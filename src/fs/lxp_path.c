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

#include "fs/lxp_vfs.h"
#include "lxp_internal.h" /* lxp_guest_strnlen, file_mode */
#include "lxp_linux_uapi.h"
#include "proc/lxp_proc.h"

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

/* Join a relative @p in onto the absolute @p base (an absolute @p in ignores it) and
 * normalize into out[outlen]. */
static long resolve_from(const char *base, const char *in, char *out, size_t outlen)
{
	char joined[LXP_PATH_MAX];
	size_t jl = 0;
	if (in[0] != '/') { /* prefix the base (which is absolute + normalized) */
		for (const char *c = base; *c; c++) {
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

/*
 * Resolve `in` (absolute, or relative to the process cwd) into a normalized
 * absolute path in out[outlen]. Returns 0, or -ENAMETOOLONG on overflow.
 */
long resolve_path(const lxp_proc_t *p, const char *in, char *out, size_t outlen)
{
	/* Every path syscall funnels through here, so one check guards them all: reject a
	 * path pointer that isn't a NUL-terminated string wholly inside the program's memory
	 * (-EFAULT) before any deref — else a bad `in` faults the kernel or walks a strlen
	 * off the region. */
	if (lxp_guest_strnlen(p, in, LXP_PATH_MAX) < 0)
		return -LXP_EFAULT;
	return resolve_from(p->fs_context->cwd, in, out, outlen);
}

long resolve_path_at(lxp_proc_t *p, int dirfd, const char *in, char *out, size_t outlen)
{
	if (dirfd == LXP_AT_FDCWD)
		return resolve_path(p, in, out, outlen);
	if (lxp_guest_strnlen(p, in, LXP_PATH_MAX) < 0)
		return -LXP_EFAULT;
	if (in[0] == '/') /* an absolute path ignores dirfd */
		return resolve_from("/", in, out, outlen);
	char base[LXP_PATH_MAX];
	long rc = lxp_vfs_dir_path(p, dirfd, base, sizeof(base));
	return rc < 0 ? rc : resolve_from(base, in, out, outlen);
}

long resolve_path_trusted(const char *in, char *out, size_t outlen)
{
	/* No lxp_guest_strnlen() here, and that is the point: `in` is a string the kernel
	 * copied out of a file's own bytes, so it does not live in the guest's
	 * region and resolve_path()'s pointer guard rejects it with -EFAULT — which
	 * the #! path reported as ENOENT, making every interpreter script
	 * unrunnable on target. There is no pointer to validate here, only content. */
	if (!in || in[0] != '/')
		return -LXP_EINVAL;
	return normalize_abs(in, out, outlen);
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
	int idx = lxp_rootfs_resolve_index(fs, count, abspath);
	if (idx < 0)
		return -LXP_ENOENT;
	if (data)
		*data = fs[idx].data;
	if (len)
		*len = fs[idx].size;
	return 0;
}

int lxp_rootfs_resolve_index(const lxp_file_t *fs, int count, const char *abspath)
{
	if (!fs || count < 0 || !abspath)
		return -1;
	return fsx_follow(fs, count, fsx_lookup(fs, count, abspath));
}

size_t lxp_path_under(const char *path, const char *prefix)
{
	size_t n = strlen(prefix);
	if (n == 1 && prefix[0] == '/')
		return path[0] == '/' ? 1u : 0u;
	if (n == 0 || strncmp(path, prefix, n) != 0)
		return 0;
	return path[n] == '\0' || path[n] == '/' ? n : 0u;
}

const char *lxp_path_child_name(const char *dir, const char *path)
{
	if (dir[0] == '/' && dir[1] == 0) { /* root */
		if (path[0] != '/' || path[1] == 0)
			return NULL;
		return strchr(path + 1, '/') ? NULL : path + 1;
	}
	size_t dl = strlen(dir);
	if (strncmp(path, dir, dl) != 0 || path[dl] != '/')
		return NULL;
	const char *name = path + dl + 1;
	return (*name && !strchr(name, '/')) ? name : NULL;
}

uint32_t lxp_path_hash(uint32_t hash, const char *text)
{
	for (const unsigned char *c = (const unsigned char *)text; *c; c++) {
		hash ^= *c;
		hash *= 16777619u;
	}
	return hash;
}
