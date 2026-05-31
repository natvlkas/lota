/* SPDX-License-Identifier: MIT */
/*
 * LOTA attestation-CA enrollment client - orchestrator.
 *
 * Runs the agent side of the credential-activation ceremony over TLS:
 * present the EK certificate and AIK template, activate the credential
 * the CA wraps to the TPM, and persist the issued AIK certificate.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"
#include "enroll.h"
#include "net.h"
#include "tpm.h"

/* Outer frame: u32 big-endian body length followed by the body. */
static int send_frame(struct net_context *net, const uint8_t *body, size_t len)
{
	uint8_t hdr[4];
	int ret;

	if (len > LOTA_ENROLL_MAX_FRAME)
		return -EMSGSIZE;
	hdr[0] = (uint8_t)(len >> 24);
	hdr[1] = (uint8_t)(len >> 16);
	hdr[2] = (uint8_t)(len >> 8);
	hdr[3] = (uint8_t)len;

	ret = net_write_all(net, hdr, sizeof(hdr));
	if (ret < 0)
		return ret;
	return net_write_all(net, body, len);
}

static int recv_frame(struct net_context *net, uint8_t *buf, size_t buf_max,
		      size_t *out_len)
{
	uint8_t hdr[4];
	uint32_t n;
	int ret;

	ret = net_read_full(net, hdr, sizeof(hdr));
	if (ret < 0)
		return ret;
	n = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
	    (uint32_t)hdr[2] << 8 | (uint32_t)hdr[3];
	if (n > LOTA_ENROLL_MAX_FRAME || n > buf_max)
		return -EMSGSIZE;
	ret = net_read_full(net, buf, n);
	if (ret < 0)
		return ret;
	*out_len = n;
	return 0;
}

/* Persist the DER certificate atomically: write a temp file, then rename. */
static int store_cert(const char *path, const uint8_t *der, size_t len)
{
	char tmp[PATH_MAX];
	size_t off = 0;
	int fd, ret;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -ENAMETOOLONG;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;

	while (off < len) {
		ssize_t w = write(fd, der + off, len - off);
		if (w < 0) {
			ret = -errno;
			close(fd);
			unlink(tmp);
			return ret;
		}
		off += (size_t)w;
	}

	if (fsync(fd) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}
	if (close(fd) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	if (rename(tmp, path) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	return 0;
}

int enroll_to_ca(struct tpm_context *tpm, const char *server, int port,
		 const char *ca_cert, int skip_verify, const uint8_t *pin,
		 const char *out_cert_path)
{
	struct net_context net;
	int net_inited = 0;
	uint8_t ek_cert[LOTA_ENROLL_MAX_EK_CERT];
	size_t ek_len = 0;
	uint8_t aik_pub[LOTA_ENROLL_MAX_AIK_PUBLIC];
	size_t aik_len = 0;
	uint8_t body[LOTA_ENROLL_MAX_FRAME];
	uint8_t rbuf[LOTA_ENROLL_MAX_FRAME];
	uint8_t secret[LOTA_ENROLL_MAX_SECRET];
	size_t secret_len = 0;
	size_t rlen = 0;
	struct enroll_challenge ch;
	struct enroll_result res;
	ssize_t blen;
	int ret;

	if (!tpm || !server || !out_cert_path)
		return -EINVAL;

	memset(secret, 0, sizeof(secret));

	ret = tpm_get_ek_cert(tpm, ek_cert, sizeof(ek_cert), &ek_len);
	if (ret < 0) {
		fprintf(stderr,
			"EK certificate unavailable; the CA cannot anchor "
			"this TPM: %s\n",
			strerror(-ret));
		return ret;
	}
	ret = tpm_get_aik_tpmt_public(tpm, aik_pub, sizeof(aik_pub), &aik_len);
	if (ret < 0) {
		fprintf(stderr, "AIK public area unavailable: %s\n",
			strerror(-ret));
		return ret;
	}

	memset(&net, 0, sizeof(net));
	ret = net_context_init(&net, server, port, ca_cert, skip_verify, pin);
	if (ret < 0)
		goto out;
	net_inited = 1;
	ret = net_connect(&net);
	if (ret < 0)
		goto out;

	blen = enroll_encode_begin(body, sizeof(body), ek_cert, ek_len, aik_pub,
				   aik_len);
	if (blen < 0) {
		ret = (int)blen;
		goto out;
	}
	ret = send_frame(&net, body, (size_t)blen);
	if (ret < 0)
		goto out;

	ret = recv_frame(&net, rbuf, sizeof(rbuf), &rlen);
	if (ret < 0)
		goto out;
	ret = enroll_decode_challenge(rbuf, rlen, &ch);
	if (ret < 0)
		goto out;
	if (ch.status != LOTA_ENROLL_STATUS_OK) {
		fprintf(stderr,
			"CA refused enrollment at challenge (status %u)\n",
			ch.status);
		ret = -EACCES;
		goto out;
	}

	ret = tpm_activate_credential(tpm, ch.cred_blob, ch.cred_blob_len,
				      ch.enc_secret, ch.enc_secret_len, secret,
				      sizeof(secret), &secret_len);
	if (ret < 0) {
		fprintf(stderr, "Credential activation failed: %s\n",
			strerror(-ret));
		goto out;
	}

	blen = enroll_encode_complete(body, sizeof(body), ch.session_id, secret,
				      secret_len);
	OPENSSL_cleanse(secret, sizeof(secret));
	if (blen < 0) {
		ret = (int)blen;
		goto out;
	}
	ret = send_frame(&net, body, (size_t)blen);
	if (ret < 0)
		goto out;

	ret = recv_frame(&net, rbuf, sizeof(rbuf), &rlen);
	if (ret < 0)
		goto out;
	ret = enroll_decode_result(rbuf, rlen, &res);
	if (ret < 0)
		goto out;
	if (res.status != LOTA_ENROLL_STATUS_OK) {
		fprintf(stderr,
			"CA refused enrollment at completion (status %u)\n",
			res.status);
		ret = -EACCES;
		goto out;
	}

	ret = store_cert(out_cert_path, res.aik_cert, res.aik_cert_len);
	if (ret < 0) {
		fprintf(stderr, "Failed to store AIK certificate: %s\n",
			strerror(-ret));
		goto out;
	}

	printf("Enrolled. Device ID: %s\n", res.device_id);
	printf("AIK certificate stored at %s (%zu bytes)\n", out_cert_path,
	       res.aik_cert_len);
	ret = 0;

out:
	OPENSSL_cleanse(secret, sizeof(secret));
	if (net_inited)
		net_context_cleanup(&net);
	return ret;
}

int do_enroll(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin)
{
	int ret;

	printf("=== Attestation CA Enrollment ===\n\n");

	ret = net_init();
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize network: %s\n",
			strerror(-ret));
		return ret;
	}

	printf("Initializing TPM...\n");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		net_cleanup();
		return ret;
	}

	printf("Checking AIK...\n");
	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to provision AIK: %s\n",
			tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return ret;
	}

	ret = enroll_to_ca(&g_agent.tpm_ctx, server, port, ca_cert, skip_verify,
			   pin, LOTA_AIK_CERT_PATH);

	printf("\n=== Enrollment %s ===\n", ret == 0 ? "Successful" : "Failed");

	tpm_cleanup(&g_agent.tpm_ctx);
	net_cleanup();
	return ret;
}
