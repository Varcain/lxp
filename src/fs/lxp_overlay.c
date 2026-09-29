/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The root mount: the writable tmpfs overlay over the read-only rootfs. A tmpfs node
 * shadows the rootfs entry of the same name and new names are created in tmpfs, but a
 * name the rootfs image holds is never written (EROFS).
 */
#include "fs/lxp_mount.h"

#include "fs/lxp_path.h"
#include "fs/lxp_tmpfs.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"
#include "sys/lxp_sys.h"

#include <string.h>

static int is_dir(uint32_t mode)
{
	return (mode & LXP_S_IFMT) == LXP_S_IFDIR;
}

static long overlay_open(lxp_proc_t *p, const char *path, int flags)
{
	int wi = wfs_find(path);
	if ((flags & LXP_O_ACCMODE) != LXP_O_RDONLY || (flags & LXP_O_CREAT)) {
		if (wi < 0) {
			int fi = fs_lookup(p, path);
			if (fi >= 0) {
				/* A rootfs name, followed to what a write would reach. */
				fi = fs_follow(p, fi);
				return fi >= 0 && is_dir(file_mode(&p->fs[fi])) ? -LXP_EISDIR
										: -LXP_EROFS;
			}
			if (!(flags & LXP_O_CREAT))
				return -LXP_ENOENT;
			wi = wfs_create(path, LXP_S_IFREG | 0644u);
			if (wi < 0)
				return -LXP_EMFILE;
		} else {
			if (is_dir(wnode_at(wi)->mode))
				return -LXP_EISDIR;
			if (flags & LXP_O_TRUNC)
				wnode_at(wi)->size = 0;
		}
		return lxp_sys_fd_alloc(p, LXP_FD_TMPFS, wi,
					(flags & LXP_O_APPEND) ? wnode_at(wi)->size : 0, flags);
	}
	if (wi >= 0)
		return lxp_sys_fd_alloc(p, LXP_FD_TMPFS, wi, 0, flags);
	/* Follow symlinks so a read open of e.g. /lib/libc.so.0 -> libuClibc.so returns the
	 * target ELF (ld.so opens its .so deps by their symlinked SONAMEs). */
	int fi = fs_follow(p, fs_lookup(p, path));
	if (fi >= 0)
		return lxp_sys_fd_alloc(p, LXP_FD_FILE, fi, 0, flags);
	return -LXP_ENOENT;
}

static long overlay_stat(lxp_proc_t *p, const char *path, int follow, struct lxp_stat *st)
{
	int wi = wfs_find(path);
	if (wi >= 0) {
		lxp_stat_init(st, LXP_INO_TMPFS + (uint32_t)wi, wnode_at(wi)->mode,
			      wnode_at(wi)->size);
		return 0;
	}
	int fi = fs_lookup(p, path);
	if (fi >= 0 && follow)
		fi = fs_follow(p, fi);
	if (fi >= 0) {
		lxp_stat_init(st, LXP_INO_ROOTFS + (uint32_t)fi, file_mode(&p->fs[fi]),
			      p->fs[fi].size);
		return 0;
	}
	if (path[0] == '/' && path[1] == '\0') {
		/* An image without a "." entry: the root, numbered after the rootfs entries. */
		lxp_stat_init(st, LXP_INO_ROOTFS + (uint32_t)p->fs_count, LXP_S_IFDIR | 0755u, 0);
		return 0;
	}
	return -LXP_ENOENT;
}

static int overlay_exists(lxp_proc_t *p, const char *path)
{
	struct lxp_stat st;
	return overlay_stat(p, path, 0, &st) == 0;
}

static long overlay_mkdir(lxp_proc_t *p, const char *path, uint32_t mode)
{
	if (overlay_exists(p, path))
		return -LXP_EEXIST;
	return wfs_create(path, LXP_S_IFDIR | (mode & 0777u)) < 0 ? -LXP_ENOSPC : 0;
}

/* unlink (dir = 0) or rmdir (dir = 1) of a tmpfs node; rootfs entries stay. */
static long overlay_remove(lxp_proc_t *p, const char *path, int dir)
{
	int wi = wfs_find(path);
	if (wi < 0)
		return fs_lookup(p, path) >= 0 ? -LXP_EROFS : -LXP_ENOENT;
	int node_is_dir = is_dir(wnode_at(wi)->mode);
	if (dir && !node_is_dir)
		return -LXP_ENOTDIR;
	if (!dir && node_is_dir)
		return -LXP_EISDIR;
	for (int j = 0; node_is_dir && j < LXP_NWNODE; j++)
		if (wnode_at(j)->used && lxp_path_child_name(path, wnode_at(j)->path))
			return -LXP_ENOTEMPTY;
	wfs_free(wi); /* reclaim the node and its pool bytes */
	return 0;
}

static long overlay_symlink(lxp_proc_t *p, const char *target, size_t target_len,
			    const char *path)
{
	if (overlay_exists(p, path))
		return -LXP_EEXIST;
	int wi = wfs_create(path, LXP_S_IFLNK | 0777u);
	if (wi < 0)
		return -LXP_ENOSPC;
	if (wfs_reserve(wi, target_len) < 0) {
		wfs_free(wi); /* roll back the just-created node (its data is still NULL) */
		return -LXP_ENOSPC;
	}
	memcpy(wnode_at(wi)->data, target, target_len);
	wnode_at(wi)->size = target_len;
	return 0;
}

/*
 * link(from, to): tmpfs has no shared-inode / link-count model (st_nlink is always 1), so
 * a true hard link is not representable. The call makes @p to an independent copy of
 * @p from's current bytes -- enough for `ln a b` and the write-temp / link / unlink-temp
 * idiom (dropbear host keys, mkstemp-based writers, editors). @p from may be a rootfs or
 * tmpfs file; a directory is EPERM, as on Linux, and a trailing symlink is not followed.
 */
static long overlay_link(lxp_proc_t *p, const char *from, const char *to)
{
	if (overlay_exists(p, to))
		return -LXP_EEXIST;
	const uint8_t *src;
	size_t len;
	uint32_t mode;
	int wi = wfs_find(from);
	if (wi >= 0) {
		src = wnode_at(wi)->data;
		len = wnode_at(wi)->size;
		mode = wnode_at(wi)->mode;
	} else {
		int fi = fs_lookup(p, from);
		if (fi < 0)
			return -LXP_ENOENT;
		src = p->fs[fi].data;
		len = p->fs[fi].size;
		mode = file_mode(&p->fs[fi]);
	}
	if (is_dir(mode))
		return -LXP_EPERM;
	int ni = wfs_create(to, LXP_S_IFREG | (mode & 0777u));
	if (ni < 0)
		return -LXP_ENOSPC;
	if (len > 0) {
		if (wfs_reserve(ni, len) < 0) {
			wfs_free(ni);
			return -LXP_ENOSPC;
		}
		memcpy(wnode_at(ni)->data, src, len); /* the arena never moves the source block */
		wnode_at(ni)->size = len;
	}
	return 0;
}

static long overlay_rename(lxp_proc_t *p, const char *from, const char *to)
{
	int wi = wfs_find(from);
	if (wi < 0)
		return fs_lookup(p, from) >= 0 ? -LXP_EROFS : -LXP_ENOENT;
	if (wfs_find(to) < 0 && fs_lookup(p, to) >= 0)
		return -LXP_EROFS; /* it would replace a name the rootfs holds */
	return wfs_rename(wi, to);
}

/* Permission bits stick on a tmpfs node and are accepted, inert, on a rootfs entry. */
static long overlay_chmod(lxp_proc_t *p, const char *path, uint32_t mode)
{
	int wi = wfs_find(path);
	if (wi >= 0) {
		wnode_at(wi)->mode = (wnode_at(wi)->mode & LXP_S_IFMT) | (mode & 0777u);
		return 0;
	}
	return overlay_exists(p, path) ? 0 : -LXP_ENOENT;
}

/* Times are not tracked, but the existence check must be honest: `touch` probes with
 * utimensat first and only creates the file on ENOENT. */
static long overlay_utimens(lxp_proc_t *p, const char *path)
{
	return overlay_exists(p, path) ? 0 : -LXP_ENOENT;
}

/* The target of a tmpfs or rootfs symlink. */
static long overlay_readlink(lxp_proc_t *p, const char *path, char *out, size_t cap)
{
	uint32_t mode;
	const uint8_t *data;
	size_t size;
	int wi = wfs_find(path);
	if (wi >= 0) {
		mode = wnode_at(wi)->mode;
		data = wnode_at(wi)->data;
		size = wnode_at(wi)->size;
	} else {
		int fi = fs_lookup(p, path);
		if (fi < 0)
			return overlay_exists(p, path) ? -LXP_EINVAL : -LXP_ENOENT;
		mode = file_mode(&p->fs[fi]);
		data = p->fs[fi].data;
		size = p->fs[fi].size;
	}
	if ((mode & LXP_S_IFMT) != LXP_S_IFLNK || !data)
		return -LXP_EINVAL;
	size_t n = size < cap ? size : cap;
	memcpy(out, data, n);
	return (long)n;
}

/* A rootfs file cannot be written, but a directory can take new names. */
static long overlay_access(lxp_proc_t *p, const char *path, int mode)
{
	struct lxp_stat st;
	long rc = overlay_stat(p, path, 0, &st);
	if (rc < 0)
		return rc;
	if ((mode & 2) && wfs_find(path) < 0 && !is_dir(st.mode))
		return -LXP_EROFS;
	return 0;
}

/* A rootfs symlink is followed, and the cwd names the directory it leads to: paths do
 * not resolve symlinks in their leading components, so the link's own name would not
 * work as a base for relative paths. */
static long overlay_chdir(lxp_proc_t *p, const char *path)
{
	struct lxp_stat st;
	long rc = overlay_stat(p, path, 1, &st);
	if (rc < 0)
		return rc;
	if (!is_dir(st.mode))
		return -LXP_ENOTDIR;
	const char *dir = path;
	if (wfs_find(path) < 0) {
		int fi = fs_follow(p, fs_lookup(p, path));
		if (fi >= 0)
			dir = p->fs[fi].path;
	}
	if (strlen(dir) >= sizeof(p->fs_context->cwd))
		return -LXP_ENAMETOOLONG;
	strcpy(p->fs_context->cwd, dir);
	return 0;
}

/* A rootfs program is loaded in place; a tmpfs one is copied out first. */
static long overlay_exec(lxp_proc_t *p, const char *path, const uint8_t **data, size_t *size,
			 int *rootfs_index)
{
	int wi = wfs_find(path);
	if (wi >= 0) {
		if (is_dir(wnode_at(wi)->mode))
			return -LXP_EACCES;
		*data = wnode_at(wi)->data;
		*size = wnode_at(wi)->size;
		*rootfs_index = -1;
		return 0;
	}
	/* Follow symlinks, e.g. /bin/echo -> busybox (Buildroot installs applets as symlinks). */
	int fi = fs_follow(p, fs_lookup(p, path));
	if (fi < 0)
		return -LXP_ENOENT;
	if (is_dir(file_mode(&p->fs[fi])))
		return -LXP_EACCES;
	*data = p->fs[fi].data;
	*size = p->fs[fi].size;
	*rootfs_index = fi;
	return 0;
}

const lxp_mount_ops_t lxp_overlay_mount_ops = {
	.open = overlay_open,
	.stat = overlay_stat,
	.mkdir = overlay_mkdir,
	.remove = overlay_remove,
	.symlink = overlay_symlink,
	.link = overlay_link,
	.rename = overlay_rename,
	.chmod = overlay_chmod,
	.utimens = overlay_utimens,
	.readlink = overlay_readlink,
	.access = overlay_access,
	.chdir = overlay_chdir,
	.exec = overlay_exec,
	.magic = LXP_TMPFS_MAGIC,
	.name_errno = LXP_EROFS,
};
