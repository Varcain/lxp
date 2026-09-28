/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Read-only rootfs file operations (FD_FILE): file_idx indexes the process's
 * parsed rootfs table, whose entries point at the image in place.
 */
#include "fs/lxp_vfs.h"

#include "fs/lxp_stat.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"

/* Effective st_mode for a rootfs node (0 in the table means a regular file). */
uint32_t file_mode(const lxp_file_t *f)
{
	return f->mode ? f->mode : (LXP_S_IFREG | 0644u);
}

/* Read from a read-only rootfs file at @p off; the image is mapped in place. */
static long fop_pread_rootfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len, uint64_t off)
{
	const lxp_file_t *f = &p->fs[s->file_idx];
	if ((file_mode(f) & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EISDIR;
	return lxp_vfs_read_mem(p, f->data, f->size, buf, len, off);
}

static long fop_read_rootfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	long n = fop_pread_rootfs(p, s, buf, len, s->offset);
	if (n > 0)
		s->offset += (size_t)n;
	return n;
}

static long fop_lseek_rootfs(lxp_proc_t *p, lxp_ofd_t *s, long off, int whence)
{
	return lxp_vfs_seek(s, (long)p->fs[s->file_idx].size, off, whence);
}

static long fop_fstat_rootfs(lxp_proc_t *p, lxp_ofd_t *s, void *statbuf)
{
	lxp_fill_kstat64(statbuf, 1u + (uint32_t)s->file_idx, file_mode(&p->fs[s->file_idx]),
			 p->fs[s->file_idx].size);
	return 0;
}

/* Read-only: a NULL write makes write(2) return -EBADF and pwrite64(2) -ESPIPE. */
const lxp_file_ops_t lxp_rootfs_fops = {
	.read = fop_read_rootfs,
	.pread = fop_pread_rootfs,
	.lseek = fop_lseek_rootfs,
	.fstat = fop_fstat_rootfs,
};
