/* SPDX-License-Identifier: MIT */
/*
 * LOTA EXT-2 runtime re-measurement demonstrator.
 *
 * A standalone, TPM-free reference for the runtime measurement that the
 * anti-cheat heartbeat binds into every beat. It needs no agent, no
 * verifier and no TPM, so it runs unmodified inside a plain VM.
 *
 * It shows three things:
 *
 *   1. The live measurement of the running image (the bytes mapped into
 *      this process) equals the measurement derived from the on-disk ELF.
 *      This is the invariant a verifier relies on: it can precompute the
 *      expected value from the binary and still recognise an honest
 *      producer's live measurement.
 *
 *   2. A one-byte change inside an executable segment flips the digest
 *      (--patch-demo). That is exactly the on-disk-vs-live drift EXT-2
 *      closes: a runtime patch the session-start file hash never saw.
 *
 *   3. Re-measuring a steady process repeatedly yields a stable digest
 *      (--watch), which is what the heartbeat does on every interval.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lota_anticheat.h"

static void print_digest(const char *label,
			 const uint8_t d[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	printf("%-22s ", label);
	for (int i = 0; i < LOTA_AC_RUNTIME_MEASURE_SIZE; i++)
		printf("%02x", d[i]);
	printf("\n");
}

/* Sleep helper that tolerates signal interruption. */
static void sleep_seconds(unsigned seconds)
{
	struct timespec ts = {.tv_sec = (time_t)seconds, .tv_nsec = 0};
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

/*
 * File offset of the last byte of the first executable (PF_X) PT_LOAD
 * segment, or (off_t)-1 on failure. The last byte is always code and
 * never overlaps the ELF header, so patching it exercises detection
 * instead of corrupting the parse.
 */
static off_t first_exec_seg_last_byte(const char *path)
{
	Elf64_Ehdr ehdr;
	Elf64_Phdr ph;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	off_t ret = (off_t)-1;

	if (fd < 0)
		return ret;
	if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr))
		goto done;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		goto done;

	for (size_t i = 0; i < ehdr.e_phnum; i++) {
		off_t off = (off_t)ehdr.e_phoff + (off_t)(i * ehdr.e_phentsize);
		if (pread(fd, &ph, sizeof(ph), off) != (ssize_t)sizeof(ph))
			goto done;
		if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X) &&
		    ph.p_filesz > 0) {
			ret = (off_t)(ph.p_offset + ph.p_filesz - 1);
			goto done;
		}
	}

done:
	close(fd);
	return ret;
}

static int copy_file(const char *src, const char *dst)
{
	uint8_t buf[8192];
	int in = open(src, O_RDONLY | O_CLOEXEC);
	int out = -1;
	int ret = -1;

	if (in < 0)
		return -1;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
	if (out < 0)
		goto done;

	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			goto done;
		}
		if (n == 0)
			break;
		if (write(out, buf, (size_t)n) != n)
			goto done;
	}
	ret = 0;

done:
	if (in >= 0)
		close(in);
	if (out >= 0)
		close(out);
	return ret;
}

/* Default mode: prove live measurement == on-disk measurement. */
static int run_default(const char *exe_path)
{
	uint8_t live[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t file[LOTA_AC_RUNTIME_MEASURE_SIZE];
	int rc;

	rc = lota_ac_compute_runtime_measure(live);
	if (rc < 0) {
		fprintf(stderr, "live measurement failed: %s\n", strerror(-rc));
		return 1;
	}
	rc = lota_ac_compute_expected_runtime_measure(exe_path, file);
	if (rc < 0) {
		fprintf(stderr, "file measurement of %s failed: %s\n", exe_path,
			strerror(-rc));
		return 1;
	}

	print_digest("live (mapped image):", live);
	print_digest("file (on-disk ELF):", file);

	if (memcmp(live, file, sizeof(live)) != 0) {
		printf("RESULT: MISMATCH - live image differs from %s\n",
		       exe_path);
		return 1;
	}
	printf("RESULT: MATCH - live image matches %s\n", exe_path);
	return 0;
}

/* --compare: report whether another binary measures the same as self. */
static int run_compare(const char *other)
{
	uint8_t self_live[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t other_file[LOTA_AC_RUNTIME_MEASURE_SIZE];
	int rc;

	rc = lota_ac_compute_runtime_measure(self_live);
	if (rc < 0) {
		fprintf(stderr, "live measurement failed: %s\n", strerror(-rc));
		return 1;
	}
	rc = lota_ac_compute_expected_runtime_measure(other, other_file);
	if (rc < 0) {
		fprintf(stderr, "file measurement of %s failed: %s\n", other,
			strerror(-rc));
		return 1;
	}

	print_digest("self (mapped image):", self_live);
	print_digest("other (on-disk ELF):", other_file);

	if (memcmp(self_live, other_file, sizeof(self_live)) != 0) {
		printf("RESULT: DIFFERENT - %s is not this image\n", other);
		return 0;
	}
	printf("RESULT: SAME - %s measures identically to this image\n", other);
	return 0;
}

/* --patch-demo: a one-byte code patch must flip the digest. */
static int run_patch_demo(const char *exe_path)
{
	char tmp[] = "/tmp/lota_remeasure_XXXXXX";
	uint8_t before[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t after[LOTA_AC_RUNTIME_MEASURE_SIZE];
	off_t off;
	uint8_t byte;
	int fd;
	int ret = 1;

	fd = mkstemp(tmp);
	if (fd < 0) {
		perror("mkstemp");
		return 1;
	}
	close(fd);

	if (copy_file(exe_path, tmp) != 0) {
		fprintf(stderr, "copy %s -> %s failed\n", exe_path, tmp);
		goto done;
	}
	if (lota_ac_compute_expected_runtime_measure(tmp, before) < 0) {
		fprintf(stderr, "measure before failed\n");
		goto done;
	}

	off = first_exec_seg_last_byte(tmp);
	if (off < 0) {
		fprintf(stderr, "could not locate an executable segment\n");
		goto done;
	}

	fd = open(tmp, O_RDWR | O_CLOEXEC);
	if (fd < 0 || pread(fd, &byte, 1, off) != 1) {
		perror("open/read patch site");
		if (fd >= 0)
			close(fd);
		goto done;
	}
	byte ^= 0xFF;
	if (pwrite(fd, &byte, 1, off) != 1) {
		perror("write patch");
		close(fd);
		goto done;
	}
	close(fd);

	if (lota_ac_compute_expected_runtime_measure(tmp, after) < 0) {
		fprintf(stderr, "measure after failed\n");
		goto done;
	}

	print_digest("before patch:", before);
	print_digest("after 1-byte patch:", after);

	if (memcmp(before, after, sizeof(before)) == 0) {
		printf("RESULT: UNDETECTED - patch did not change the digest\n");
		goto done;
	}
	printf("RESULT: DETECTED - code patch flipped the runtime digest\n");
	ret = 0;

done:
	unlink(tmp);
	return ret;
}

/* --watch: re-measure repeatedly; a steady process stays stable. */
static int run_watch(unsigned interval, unsigned count)
{
	uint8_t baseline[LOTA_AC_RUNTIME_MEASURE_SIZE];
	int rc = lota_ac_compute_runtime_measure(baseline);

	if (rc < 0) {
		fprintf(stderr, "live measurement failed: %s\n", strerror(-rc));
		return 1;
	}
	print_digest("baseline:", baseline);

	for (unsigned i = 1; i <= count; i++) {
		uint8_t now[LOTA_AC_RUNTIME_MEASURE_SIZE];

		sleep_seconds(interval);
		rc = lota_ac_compute_runtime_measure(now);
		if (rc < 0) {
			fprintf(stderr, "live measurement failed: %s\n",
				strerror(-rc));
			return 1;
		}
		if (memcmp(now, baseline, sizeof(now)) != 0) {
			printf("tick %u: CHANGED - live code pages drifted\n",
			       i);
			print_digest("  now:", now);
			return 1;
		}
		printf("tick %u: stable\n", i);
	}
	printf("RESULT: STABLE - %u re-measurements matched the baseline\n",
	       count);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--compare PATH | --patch-demo | --watch SEC]\n"
		"           [--count N] [--exe PATH]\n"
		"\n"
		"  (no flags)       prove the live image matches its ELF file\n"
		"  --compare PATH   compare this image to another ELF\n"
		"  --patch-demo     show a 1-byte code patch flips the digest\n"
		"  --watch SEC      re-measure this image every SEC seconds\n"
		"  --count N        number of --watch ticks (default 5)\n"
		"  --exe PATH       ELF used for the file side (default "
		"/proc/self/exe)\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *exe_path = "/proc/self/exe";
	const char *compare = NULL;
	int patch_demo = 0;
	long watch = -1;
	unsigned count = 5;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--compare") == 0 && i + 1 < argc) {
			compare = argv[++i];
		} else if (strcmp(argv[i], "--patch-demo") == 0) {
			patch_demo = 1;
		} else if (strcmp(argv[i], "--watch") == 0 && i + 1 < argc) {
			watch = strtol(argv[++i], NULL, 10);
			if (watch < 0) {
				usage(argv[0]);
				return 2;
			}
		} else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
			long c = strtol(argv[++i], NULL, 10);
			if (c <= 0) {
				usage(argv[0]);
				return 2;
			}
			count = (unsigned)c;
		} else if (strcmp(argv[i], "--exe") == 0 && i + 1 < argc) {
			exe_path = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (compare)
		return run_compare(compare);
	if (patch_demo)
		return run_patch_demo(exe_path);
	if (watch >= 0)
		return run_watch((unsigned)watch, count);
	return run_default(exe_path);
}
