/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Path resolution: normalize "." / ".." / duplicate slashes, resolve a user path
 * against the process cwd to an absolute path, and look a path up in the read-only
 * cpio rootfs. Pure string + rootfs-table work — the dispatcher calls resolve_path()
 * and fs_lookup() (see fs/lxp_path.h).
 */
#include "fs/lxp_path.h"

#include "lxp/lxp_syscall.h"
#include "lxp_internal.h" /* user_strnlen, file_mode */

#include <string.h>

/*
 * Collapse ".", "..", and duplicate/trailing slashes in absolute path `in` into
 * out[outlen]. Returns 0, or -ENAMETOOLONG on overflow.
 */
static long normalize_abs(const char *in, char *out, size_t outlen)
{
	size_t ol = 0;
	out[0] = '\0';
	const char *s = in;
	while (*s) {
		while (*s == '/')
			s++;
		if (!*s)
			break;
		const char *seg = s;
		while (*s && *s != '/')
			s++;
		size_t seglen = (size_t)(s - seg);
		if (seglen == 1 && seg[0] == '.') {
			continue; /* "." → current dir */
		}
		if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
			while (ol > 0 && out[ol - 1] != '/') /* drop last component */
				ol--;
			if (ol > 0)
				ol--; /* drop the separating '/' */
			out[ol] = '\0';
			continue;
		}
		if (ol + 1 + seglen >= outlen)
			return -LXP_ENAMETOOLONG;
		out[ol++] = '/';
		memcpy(out + ol, seg, seglen);
		ol += seglen;
		out[ol] = '\0';
	}
	if (ol == 0) { /* everything collapsed away → root */
		out[0] = '/';
		out[1] = '\0';
	}
	return 0;
}

/*
 * Resolve `in` (absolute, or relative to the process cwd) into a normalized
 * absolute path in out[outlen]. Returns 0, or -ENAMETOOLONG on overflow.
 */
long resolve_path(const lxp_proc_t *p, const char *in, char *out, size_t outlen)
{
	/* Every path syscall funnels through here, so one check guards them all: reject a path pointer
	 * that isn't a NUL-terminated string wholly inside the program's memory (-EFAULT) before any
	 * deref — else a bad `in` faults the kernel or walks a strlen off the region. */
	if (user_strnlen(p, in, LXP_PATH_MAX) < 0)
		return -LXP_EFAULT;
	char joined[LXP_PATH_MAX];
	size_t jl = 0;
	if (in[0] != '/') { /* prefix the cwd (which is absolute + normalized) */
		for (const char *c = p->cwd; *c; c++) {
			if (jl + 2 >= sizeof(joined))
				return -LXP_ENAMETOOLONG;
			joined[jl++] = *c;
		}
		joined[jl++] = '/';
	}
	for (const char *c = in; *c; c++) {
		if (jl + 1 >= sizeof(joined))
			return -LXP_ENAMETOOLONG;
		joined[jl++] = *c;
	}
	joined[jl] = '\0';
	return normalize_abs(joined, out, outlen);
}

/* Find the rootfs index for an absolute path in (fs,count), or -1. */
static int fsx_lookup(const lxp_file_t *fs, int count, const char *abspath)
{
	for (int i = 0; i < count; i++)
		if (strcmp(fs[i].path, abspath) == 0)
			return i;
	return -1;
}

/*
 * Follow symlinks from rootfs index `idx` (up to 8 hops), normalizing each
 * target against the link's own directory (so e.g. /sbin/init -> ../bin/busybox
 * resolves to /bin/busybox). Returns the final non-symlink index, or -1.
 */
static int fsx_follow(const lxp_file_t *fs, int count, int idx)
{
	for (int hop = 0; hop < 8 && idx >= 0; hop++) {
		const lxp_file_t *lnk = &fs[idx];
		if ((file_mode(lnk) & LXP_S_IFMT) != LXP_S_IFLNK)
			return idx;
		const char *tgt = (const char *)lnk->data;
		size_t tl = lnk->size;
		if (!tgt || tl == 0)
			return -1;
		char raw[LXP_PATH_MAX], abs[LXP_PATH_MAX];
		size_t rl = 0;
		if (tgt[0] != '/') { /* relative to the link's own directory */
			const char *base = strrchr(lnk->path, '/');
			rl = base ? (size_t)(base - lnk->path + 1) : 0;
			if (rl >= sizeof(raw))
				return -1;
			memcpy(raw, lnk->path, rl);
		}
		if (rl + tl >= sizeof(raw))
			return -1;
		memcpy(raw + rl, tgt, tl);
		raw[rl + tl] = '\0';
		if (normalize_abs(raw, abs, sizeof(abs)) < 0)
			return -1;
		idx = fsx_lookup(fs, count, abs);
	}
	return idx;
}

/* Find the rootfs index for an absolute path, or -1. */
int fs_lookup(const lxp_proc_t *p, const char *abspath)
{
	return fsx_lookup(p->fs, p->fs_count, abspath);
}

int fs_follow(const lxp_proc_t *p, int idx)
{
	return fsx_follow(p->fs, p->fs_count, idx);
}

/*
 * Resolve an absolute path through (fs,count), following symlinks, to its target file's
 * bytes. Public so the run loop can locate the FDPIC interpreter (ld.so) at launch, before
 * a proc (and its fd table) exists. Returns 0 + sets data/len, or -ENOENT.
 */
long lxp_rootfs_resolve(const lxp_file_t *fs, int count, const char *abspath,
			    const uint8_t **data, size_t *len)
{
	int idx = fsx_follow(fs, count, fsx_lookup(fs, count, abspath));
	if (idx < 0)
		return -LXP_ENOENT;
	if (data)
		*data = fs[idx].data;
	if (len)
		*len = fs[idx].size;
	return 0;
}
