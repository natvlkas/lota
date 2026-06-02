/* SPDX-License-Identifier: MIT */
/*
 * LOTA runtime re-measurement - Unit Tests
 *
 * Exercises lota_ac_compute_runtime_measure() (live mapping) and
 * lota_ac_compute_expected_runtime_measure() (ELF file). The central
 * invariant is that, for the same position-independent x86-64 binary,
 * the live measurement equals the file-derived measurement: that is what
 * lets a verifier precompute the value an honest producer must report.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lota_anticheat.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-55s", tests_run, name);                      \
	} while (0)

#define PASS()                                                                 \
	do {                                                                   \
		tests_passed++;                                                \
		printf("PASS\n");                                              \
	} while (0)

#define FAIL(reason)                                                           \
	do {                                                                   \
		printf("FAIL (%s)\n", reason);                                 \
	} while (0)

static char tmp_path[256];

/*
 * Copy /proc/self/exe to a writable temp file
 * Returns 0 on success
 */
static int copy_self_exe(char *out_path, size_t out_len)
{
	uint8_t buf[8192];
	int in = -1;
	int out = -1;
	int ret = -1;

	snprintf(out_path, out_len, "/tmp/lota_rm_XXXXXX");
	out = mkstemp(out_path);
	if (out < 0)
		return -1;

	in = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (in < 0)
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

/*
 * Return the file offset of the last byte of the first executable (PF_X)
 * PT_LOAD segment of an ELF file, or (off_t)-1 on failure.
 *
 * The last byte is always inside the measured region and never overlaps the ELF
 * header (which would corrupt parsing instead of testing tamper detection)
 */
static off_t first_exec_seg_offset(const char *path)
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

static void test_live_self_measure(void)
{
	uint8_t a[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t b[LOTA_AC_RUNTIME_MEASURE_SIZE];

	TEST("live self-measure succeeds and is deterministic");
	if (lota_ac_compute_runtime_measure(a) != 0) {
		FAIL("first call");
		return;
	}
	if (lota_ac_compute_runtime_measure(b) != 0) {
		FAIL("second call");
		return;
	}
	if (memcmp(a, b, sizeof(a)) != 0) {
		FAIL("not deterministic");
		return;
	}
	PASS();
}

static void test_file_measure_matches_live(void)
{
	uint8_t live[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t file[LOTA_AC_RUNTIME_MEASURE_SIZE];

	TEST("file measure of /proc/self/exe equals live measure");
	if (lota_ac_compute_runtime_measure(live) != 0) {
		FAIL("live");
		return;
	}
	if (lota_ac_compute_expected_runtime_measure("/proc/self/exe", file) !=
	    0) {
		FAIL("file");
		return;
	}
	if (memcmp(live, file, sizeof(live)) != 0) {
		FAIL("live != file");
		return;
	}
	PASS();
}

static void test_file_measure_copy_matches(void)
{
	uint8_t orig[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t copy[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];

	TEST("file measure is stable across an identical copy");
	if (copy_self_exe(path, sizeof(path)) != 0) {
		FAIL("copy");
		return;
	}
	int ok = lota_ac_compute_expected_runtime_measure("/proc/self/exe",
							  orig) == 0 &&
		 lota_ac_compute_expected_runtime_measure(path, copy) == 0;
	unlink(path);
	if (!ok) {
		FAIL("measure");
		return;
	}
	if (memcmp(orig, copy, sizeof(orig)) != 0) {
		FAIL("copy differs");
		return;
	}
	PASS();
}

static void test_tamper_in_exec_segment_detected(void)
{
	uint8_t before[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t after[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	off_t off;
	uint8_t byte;
	int fd;

	TEST("a one-byte patch inside an exec segment changes the digest");
	if (copy_self_exe(path, sizeof(path)) != 0) {
		FAIL("copy");
		return;
	}
	if (lota_ac_compute_expected_runtime_measure(path, before) != 0) {
		unlink(path);
		FAIL("measure before");
		return;
	}

	off = first_exec_seg_offset(path);
	if (off < 0) {
		unlink(path);
		FAIL("locate exec segment");
		return;
	}

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0 || pread(fd, &byte, 1, off) != 1) {
		if (fd >= 0)
			close(fd);
		unlink(path);
		FAIL("open/read patch site");
		return;
	}
	byte ^= 0xFF;
	if (pwrite(fd, &byte, 1, off) != 1) {
		close(fd);
		unlink(path);
		FAIL("write patch");
		return;
	}
	close(fd);

	int ok = lota_ac_compute_expected_runtime_measure(path, after) == 0;
	unlink(path);
	if (!ok) {
		FAIL("measure after");
		return;
	}
	if (memcmp(before, after, sizeof(before)) == 0) {
		FAIL("patch not detected");
		return;
	}
	PASS();
}

static void test_invalid_args(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];

	TEST("NULL output and path are rejected");
	if (lota_ac_compute_runtime_measure(NULL) != -EINVAL) {
		FAIL("live NULL");
		return;
	}
	if (lota_ac_compute_expected_runtime_measure(NULL, out) != -EINVAL) {
		FAIL("file NULL path");
		return;
	}
	if (lota_ac_compute_expected_runtime_measure("/proc/self/exe", NULL) !=
	    -EINVAL) {
		FAIL("file NULL out");
		return;
	}
	PASS();
}

static void test_missing_file(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];

	TEST("a missing ELF path returns a negative error");
	if (lota_ac_compute_expected_runtime_measure("/nonexistent/lota/xyz",
						     out) >= 0) {
		FAIL("expected error");
		return;
	}
	PASS();
}

static void test_non_elf_rejected(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	int fd;
	const char junk[] = "this is not an ELF file at all, just text\n";

	TEST("a non-ELF file is rejected");
	snprintf(tmp_path, sizeof(tmp_path), "/tmp/lota_rm_junk_XXXXXX");
	fd = mkstemp(tmp_path);
	if (fd < 0) {
		FAIL("mkstemp");
		return;
	}
	if (write(fd, junk, sizeof(junk)) != (ssize_t)sizeof(junk)) {
		close(fd);
		unlink(tmp_path);
		FAIL("write");
		return;
	}
	close(fd);

	int rc = lota_ac_compute_expected_runtime_measure(tmp_path, out);
	unlink(tmp_path);
	if (rc >= 0) {
		FAIL("accepted junk");
		return;
	}
	PASS();
}

int main(void)
{
	printf("=== LOTA runtime re-measurement tests === \n\n");

	test_live_self_measure();
	test_file_measure_matches_live();
	test_file_measure_copy_matches();
	test_tamper_in_exec_segment_detected();
	test_invalid_args();
	test_missing_file();
	test_non_elf_rejected();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
