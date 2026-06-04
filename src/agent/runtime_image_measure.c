/* SPDX-License-Identifier: MIT */
/*
 * Kernel-anchored runtime image measurement of a live process.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runtime_image_measure.h"

static const char *rt_basename(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

/* drop the kernel's " (deleted)" suffix from a mapped pathname in place */
static void rt_strip_deleted_suffix(char *path)
{
	static const char suffix[] = " (deleted)";
	size_t len = strlen(path);
	size_t slen = sizeof(suffix) - 1;

	if (len >= slen && strcmp(path + len - slen, suffix) == 0)
		path[len - slen] = '\0';
}

int lota_rt_parse_maps_line(const char *line, struct lota_rt_map_entry *out)
{
	unsigned long start, end, off;
	unsigned int maj, min;
	unsigned long long ino;
	char perms[5] = {0};
	char path[LOTA_RUNTIME_IMAGE_SONAME_MAX + 64];
	const char *p;
	const char *soname;
	int pos = 0;
	int n;

	if (!line || !out)
		return -EINVAL;

	n = sscanf(line, "%lx-%lx %4s %lx %x:%x %llu %n", &start, &end, perms,
		   &off, &maj, &min, &ino, &pos);
	if (n < 7 || pos <= 0)
		return -EINVAL;
	if (strlen(perms) != 4)
		return -EINVAL;

	/* only file-backed executable mappings are measured */
	if (perms[2] != 'x' || ino == 0)
		return 0;

	p = line + pos;
	if (*p == '\0' || *p == '\n')
		return 0; /* anonymous executable mapping */
	if (*p == '[')
		return 0; /* special region: [vdso], [stack], ... */

	if (strlen(p) >= sizeof(path))
		return -ENAMETOOLONG;
	snprintf(path, sizeof(path), "%s", p);
	path[strcspn(path, "\n")] = '\0';
	rt_strip_deleted_suffix(path);

	soname = rt_basename(path);
	if (soname[0] == '\0' ||
	    strlen(soname) >= LOTA_RUNTIME_IMAGE_SONAME_MAX)
		return -ENAMETOOLONG;

	memset(out, 0, sizeof(*out));
	out->start = start;
	out->end = end;
	out->dev_major = maj;
	out->dev_minor = min;
	out->ino = ino;
	snprintf(out->soname, sizeof(out->soname), "%s", soname);
	return 1;
}

static int rt_entry_seen(const struct lota_rt_map_entry *entries, size_t n,
			 const struct lota_rt_map_entry *cand)
{
	for (size_t i = 0; i < n; i++) {
		if (entries[i].dev_major == cand->dev_major &&
		    entries[i].dev_minor == cand->dev_minor &&
		    entries[i].ino == cand->ino)
			return 1;
	}
	return 0;
}

int lota_rt_collect_exec_maps(pid_t pid, struct lota_rt_map_entry *entries,
			      size_t max, size_t *n_out)
{
	char maps_path[64];
	char *line = NULL;
	size_t line_cap = 0;
	size_t count = 0;
	ssize_t nread;
	FILE *f;
	int ret = 0;

	if (!entries || !n_out || max == 0)
		return -EINVAL;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
	f = fopen(maps_path, "re");
	if (!f)
		return -errno;

	while ((nread = getline(&line, &line_cap, f)) != -1) {
		struct lota_rt_map_entry e;
		int rc = lota_rt_parse_maps_line(line, &e);

		if (rc < 0) {
			ret = rc;
			goto out;
		}
		if (rc == 0)
			continue;
		if (rt_entry_seen(entries, count, &e))
			continue;
		if (count >= max) {
			ret = -E2BIG;
			goto out;
		}
		entries[count++] = e;
	}

	*n_out = count;
out:
	free(line);
	fclose(f);
	return ret;
}
