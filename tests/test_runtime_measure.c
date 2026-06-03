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

/*
 * Synthetic ELF builder for parser-robustness tests.
 *
 * Verifier-side measurement parses an ELF file that, in a real
 * deployment, an operator points at. A malformed or hostile file must
 * fail with a clean negative error and never read out of bounds.
 * The builder lays out a minimal but valid-enough ELF64:
 *
 *   [Elf64_Ehdr][phdr table][segment bytes...]
 *
 * and exposes knobs to corrupt individual fields. Only the fields the
 * parser inspects are populated; e_type / e_machine / entry are left
 * zero on purpose.
 */
struct seg_spec {
	uint32_t type;	 /* p_type */
	uint32_t flags;	 /* p_flags */
	uint64_t vaddr;	 /* p_vaddr */
	uint64_t filesz; /* declared p_filesz */
	uint8_t fill;	 /* byte the segment body is filled with */
};

struct elf_spec {
	int ei_class;	/* default ELFCLASS64 */
	int ei_data;	/* default ELFDATA2LSB */
	int phentsize;	/* default sizeof(Elf64_Phdr) */
	int phnum_set;	/* override e_phnum when non-zero */
	uint16_t phnum; /* value used when phnum_set */
	int phoff_set;	/* override e_phoff when non-zero */
	uint64_t phoff; /* value used when phoff_set */
	const struct seg_spec *segs;
	size_t nseg;
	long drop_tail; /* chop this many bytes off the end of the file */
};

/*
 * Build the ELF described by spec into path.
 * Returns 0 on success.
 */
static int build_elf(const char *path, const struct elf_spec *spec)
{
	Elf64_Ehdr eh;
	size_t phoff = sizeof(Elf64_Ehdr);
	size_t table = spec->nseg * sizeof(Elf64_Phdr);
	size_t body = 0;
	for (size_t i = 0; i < spec->nseg; i++)
		body += spec->segs[i].filesz;

	size_t total = phoff + table + body;
	uint8_t *buf = calloc(1, total ? total : 1);
	if (!buf)
		return -1;

	memset(&eh, 0, sizeof(eh));
	memcpy(eh.e_ident, ELFMAG, SELFMAG);
	eh.e_ident[EI_CLASS] = spec->ei_class ? spec->ei_class : ELFCLASS64;
	eh.e_ident[EI_DATA] = spec->ei_data ? spec->ei_data : ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_phoff = spec->phoff_set ? spec->phoff : phoff;
	eh.e_phentsize = (uint16_t)(spec->phentsize ? spec->phentsize
						    : (int)sizeof(Elf64_Phdr));
	eh.e_phnum = spec->phnum_set ? spec->phnum : (uint16_t)spec->nseg;
	memcpy(buf, &eh, sizeof(eh));

	size_t seg_off = phoff + table;
	for (size_t i = 0; i < spec->nseg; i++) {
		Elf64_Phdr ph;
		memset(&ph, 0, sizeof(ph));
		ph.p_type = spec->segs[i].type;
		ph.p_flags = spec->segs[i].flags;
		ph.p_vaddr = spec->segs[i].vaddr;
		ph.p_offset = seg_off;
		ph.p_filesz = spec->segs[i].filesz;
		ph.p_memsz = spec->segs[i].filesz;
		memcpy(buf + phoff + i * sizeof(Elf64_Phdr), &ph, sizeof(ph));
		memset(buf + seg_off, spec->segs[i].fill, spec->segs[i].filesz);
		seg_off += spec->segs[i].filesz;
	}

	long write_len = (long)total - spec->drop_tail;
	if (write_len < 0)
		write_len = 0;

	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		free(buf);
		return -1;
	}
	ssize_t n = write(fd, buf, (size_t)write_len);
	close(fd);
	free(buf);
	return (n == write_len) ? 0 : -1;
}

/*
 * Build spec into a fresh temp file
 * out_path must hold >= 64 bytes.
 */
static int build_elf_tmp(const struct elf_spec *spec, char *out_path,
			 size_t out_len)
{
	int fd;
	snprintf(out_path, out_len, "/tmp/lota_rm_elf_XXXXXX");
	fd = mkstemp(out_path);
	if (fd < 0)
		return -1;
	close(fd);
	return build_elf(out_path, spec);
}

static void test_rejects_elfclass32(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	const struct seg_spec seg = {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xCC};
	struct elf_spec spec = {
	    .ei_class = ELFCLASS32, .segs = &seg, .nseg = 1};

	TEST("32-bit ELF class is rejected (-ENOTSUP)");
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc != -ENOTSUP) {
		FAIL("expected -ENOTSUP");
		return;
	}
	PASS();
}

static void test_rejects_big_endian(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	const struct seg_spec seg = {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xCC};
	struct elf_spec spec = {
	    .ei_data = ELFDATA2MSB, .segs = &seg, .nseg = 1};

	TEST("big-endian ELF data is rejected (-ENOTSUP)");
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc != -ENOTSUP) {
		FAIL("expected -ENOTSUP");
		return;
	}
	PASS();
}

static void test_rejects_bad_phentsize(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	const struct seg_spec seg = {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xCC};
	struct elf_spec spec = {.phentsize = 32, .segs = &seg, .nseg = 1};

	TEST("wrong e_phentsize is rejected (-EINVAL)");
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

static void test_rejects_zero_phnum(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	const struct seg_spec seg = {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xCC};
	struct elf_spec spec = {
	    .phnum_set = 1, .phnum = 0, .segs = &seg, .nseg = 1};

	TEST("e_phnum == 0 is rejected (-EINVAL)");
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

static void test_rejects_phoff_past_eof(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	const struct seg_spec seg = {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xCC};
	struct elf_spec spec = {
	    .phoff_set = 1, .phoff = 1u << 20, .segs = &seg, .nseg = 1};

	TEST("e_phoff past EOF is rejected (truncated read)");
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc >= 0) {
		FAIL("accepted phoff past EOF");
		return;
	}
	PASS();
}

static void test_rejects_segment_past_eof(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	/* declare 4096 bytes of code but chop the body off the file */
	const struct seg_spec seg = {PT_LOAD, PF_R | PF_X, 0x1000, 4096, 0xCC};
	struct elf_spec spec = {.segs = &seg, .nseg = 1, .drop_tail = 4096};

	TEST("segment filesz past EOF is rejected (-EIO)");
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc != -EIO) {
		FAIL("expected -EIO");
		return;
	}
	PASS();
}

static void test_rejects_no_exec_segment(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	/* only readable/writable PT_LOAD, nothing executable */
	const struct seg_spec segs[] = {
	    {PT_LOAD, PF_R, 0x1000, 16, 0x11},
	    {PT_LOAD, PF_R | PF_W, 0x2000, 16, 0x22},
	};
	struct elf_spec spec = {.segs = segs, .nseg = 2};

	TEST("no executable PT_LOAD is rejected (-ENOENT)");
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc != -ENOENT) {
		FAIL("expected -ENOENT");
		return;
	}
	PASS();
}

static void test_rejects_too_many_exec_segments(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[256];
	struct seg_spec segs[17];
	struct elf_spec spec = {.segs = segs, .nseg = 17};

	TEST("more than 16 exec segments are rejected (-E2BIG)");
	for (int i = 0; i < 17; i++) {
		segs[i].type = PT_LOAD;
		segs[i].flags = PF_R | PF_X;
		segs[i].vaddr = 0x1000 + (uint64_t)i * 0x1000;
		segs[i].filesz = 8;
		segs[i].fill = (uint8_t)i;
	}
	if (build_elf_tmp(&spec, path, sizeof(path)) != 0) {
		FAIL("build");
		return;
	}
	int rc = lota_ac_compute_expected_runtime_measure(path, out);
	unlink(path);
	if (rc != -E2BIG) {
		FAIL("expected -E2BIG");
		return;
	}
	PASS();
}

static void test_second_segment_fields_bound(void)
{
	uint8_t base[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t single[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t diff_bytes[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t diff_vaddr[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char p_base[256], p_single[256], p_bytes[256], p_vaddr[256];

	const struct seg_spec base_segs[] = {
	    {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xA1},
	    {PT_LOAD, PF_R | PF_X, 0x2000, 16, 0xB2},
	};
	const struct seg_spec one_seg[] = {
	    {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xA1},
	};
	/* second segment: body bytes differ */
	const struct seg_spec bytes_segs[] = {
	    {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xA1},
	    {PT_LOAD, PF_R | PF_X, 0x2000, 16, 0xCC},
	};
	/* second segment: vaddr differs (bytes/offset identical) */
	const struct seg_spec vaddr_segs[] = {
	    {PT_LOAD, PF_R | PF_X, 0x1000, 16, 0xA1},
	    {PT_LOAD, PF_R | PF_X, 0x3000, 16, 0xB2},
	};
	struct elf_spec b = {.segs = base_segs, .nseg = 2};
	struct elf_spec s = {.segs = one_seg, .nseg = 1};
	struct elf_spec yb = {.segs = bytes_segs, .nseg = 2};
	struct elf_spec yv = {.segs = vaddr_segs, .nseg = 2};

	TEST("second exec segment's bytes and vaddr are bound");
	if (build_elf_tmp(&b, p_base, sizeof(p_base)) != 0 ||
	    build_elf_tmp(&s, p_single, sizeof(p_single)) != 0 ||
	    build_elf_tmp(&yb, p_bytes, sizeof(p_bytes)) != 0 ||
	    build_elf_tmp(&yv, p_vaddr, sizeof(p_vaddr)) != 0) {
		FAIL("build");
		return;
	}

	int ok =
	    lota_ac_compute_expected_runtime_measure(p_base, base) == 0 &&
	    lota_ac_compute_expected_runtime_measure(p_single, single) == 0 &&
	    lota_ac_compute_expected_runtime_measure(p_bytes, diff_bytes) ==
		0 &&
	    lota_ac_compute_expected_runtime_measure(p_vaddr, diff_vaddr) == 0;
	unlink(p_base);
	unlink(p_single);
	unlink(p_bytes);
	unlink(p_vaddr);
	if (!ok) {
		FAIL("measure");
		return;
	}
	/* dropping the second segment changes the digest (count + content) */
	if (memcmp(base, single, sizeof(base)) == 0) {
		FAIL("second segment ignored");
		return;
	}
	/* a one-byte body change in the second segment is detected */
	if (memcmp(base, diff_bytes, sizeof(base)) == 0) {
		FAIL("second segment bytes not bound");
		return;
	}
	/* moving the second segment's vaddr is detected */
	if (memcmp(base, diff_vaddr, sizeof(base)) == 0) {
		FAIL("second segment vaddr not bound");
		return;
	}
	PASS();
}

static void test_synthetic_two_segments_stable(void)
{
	uint8_t first[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t second[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char p1[256], p2[256];
	const struct seg_spec segs[] = {
	    {PT_LOAD, PF_R | PF_X, 0x1000, 64, 0x5A},
	    {PT_LOAD, PF_R | PF_X, 0x4000, 128, 0xA5},
	};
	struct elf_spec spec = {.segs = segs, .nseg = 2};

	TEST("identical synthetic ELFs measure identically");
	if (build_elf_tmp(&spec, p1, sizeof(p1)) != 0 ||
	    build_elf_tmp(&spec, p2, sizeof(p2)) != 0) {
		FAIL("build");
		return;
	}
	int ok = lota_ac_compute_expected_runtime_measure(p1, first) == 0 &&
		 lota_ac_compute_expected_runtime_measure(p2, second) == 0;
	unlink(p1);
	unlink(p2);
	if (!ok) {
		FAIL("measure");
		return;
	}
	if (memcmp(first, second, sizeof(first)) != 0) {
		FAIL("identical inputs diverged");
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

	/* parser robustness against malformed / hostile ELF input */
	test_rejects_elfclass32();
	test_rejects_big_endian();
	test_rejects_bad_phentsize();
	test_rejects_zero_phnum();
	test_rejects_phoff_past_eof();
	test_rejects_segment_past_eof();
	test_rejects_no_exec_segment();
	test_rejects_too_many_exec_segments();
	test_second_segment_fields_bound();
	test_synthetic_two_segments_stable();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
