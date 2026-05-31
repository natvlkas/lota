/* SPDX-License-Identifier: MIT */
/*
 * LOTA attestation-CA enrollment client.
 *
 * Drives the agent side of the credential-activation ceremony: send the
 * EK certificate and AIK template, activate the returned credential in
 * the TPM, and persist the issued AIK certificate.
 */

#ifndef LOTA_AGENT_ENROLL_H
#define LOTA_AGENT_ENROLL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "../../include/lota_enroll.h"

struct tpm_context;

/* On-disk location of the CA-issued AIK certificate (DER). */
#define LOTA_AIK_CERT_PATH "/var/lib/lota/aik_cert.der"

struct enroll_challenge {
	uint16_t status;
	char session_id[LOTA_ENROLL_MAX_SESSION_ID + 1];
	uint8_t cred_blob[LOTA_ENROLL_MAX_CRED_BLOB];
	size_t cred_blob_len;
	uint8_t enc_secret[LOTA_ENROLL_MAX_ENC_SECRET];
	size_t enc_secret_len;
};

struct enroll_result {
	uint16_t status;
	uint8_t aik_cert[LOTA_ENROLL_MAX_AIK_CERT];
	size_t aik_cert_len;
	char device_id[LOTA_ENROLL_MAX_DEVICE_ID + 1];
};

/*
 * Wire codec. Encoders return the body length written or negative errno;
 * decoders return 0 or negative errno. The encoded body excludes the
 * outer u32 frame length, which the transport adds.
 */
ssize_t enroll_encode_begin(uint8_t *out, size_t out_max,
			    const uint8_t *ek_cert, size_t ek_cert_len,
			    const uint8_t *aik_public, size_t aik_public_len);
ssize_t enroll_encode_complete(uint8_t *out, size_t out_max,
			       const char *session_id, const uint8_t *secret,
			       size_t secret_len);
int enroll_decode_challenge(const uint8_t *body, size_t len,
			    struct enroll_challenge *out);
int enroll_decode_result(const uint8_t *body, size_t len,
			 struct enroll_result *out);

/*
 * Run one enrollment against the CA at server:port and write the issued
 * AIK certificate to out_cert_path. The TPM context must already have a
 * provisioned AIK. Returns 0 on success, negative errno on failure.
 */
int enroll_to_ca(struct tpm_context *tpm, const char *server, int port,
		 const char *ca_cert, int skip_verify, const uint8_t *pin,
		 const char *out_cert_path);

#endif /* LOTA_AGENT_ENROLL_H */
