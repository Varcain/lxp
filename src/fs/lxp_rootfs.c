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

/* Read from a read-only rootfs file at the current offset. */
static long fop_read_rootfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	const lxp_file_t *f = &p->fs[s->file_idx];
	if ((file_mode(f) & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EISDIR;
	if (s->offset >= f->size)
		return 0; /* EOF */
	size_t n = f->size - s->offset;
	if (n > len)
		n = len;
	if (lxp_copy_to_guest(p, (uintptr_t)buf, f->data + s->offset, n) != 0)
		return -LXP_EFAULT;
	s->offset += n;
	return (long)n;
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

/* Read-only: a NULL write makes the syscall return -EBADF. */
const lxp_file_ops_t lxp_rootfs_fops = {
	.read = fop_read_rootfs,
	.lseek = fop_lseek_rootfs,
	.fstat = fop_fstat_rootfs,
};
