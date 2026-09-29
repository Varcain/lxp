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
	if (fi < 0)
		return -LXP_ENOENT;
	lxp_stat_init(st, LXP_INO_ROOTFS + (uint32_t)fi, file_mode(&p->fs[fi]), p->fs[fi].size);
	return 0;
}

const lxp_mount_ops_t lxp_overlay_mount_ops = {
	.open = overlay_open,
	.stat = overlay_stat,
};
