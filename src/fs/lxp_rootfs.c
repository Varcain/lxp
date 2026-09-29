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

#include "fs/lxp_dir.h"
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

static int64_t fop_lseek_rootfs(lxp_proc_t *p, lxp_ofd_t *s, int64_t off, int whence)
{
	return lxp_vfs_seek(s, (int64_t)p->fs[s->file_idx].size, off, whence);
}

/* Text sharing: a read-only map of a range within the file is the rootfs image in
 * place (zero-copy). FDPIC text is pure PIC — its relocations land in the per-process
 * GOT/data, never the shared text — so every dynamic process shares ONE libc.so text
 * copy (the cpio bytes) instead of its own ~358K arena copy. Every engine exposes the
 * backing span to its unprivileged guest as RO+X: a static or per-task window on
 * FreeRTOS, Zephyr's user-RX text/QSPI region, or the NuttX port's raw MPU region. */
static long fop_mmap_rootfs(lxp_proc_t *p, lxp_ofd_t *s, size_t len, int prot, uint32_t pgoff)
{
	const lxp_file_t *f = &p->fs[s->file_idx];
	size_t foff = (size_t)pgoff * 4096u; /* guard the *4096 and +len wraps (32-bit) */
	if ((prot & LXP_PROT_WRITE) || foff / 4096u != (size_t)pgoff || foff > f->size ||
	    f->size - foff < len)
		return -LXP_ENODEV; /* a private copy */
	return (long)(uintptr_t)(f->data + foff);
}

static long fop_getdents_rootfs(lxp_proc_t *p, lxp_ofd_t *s, lxp_dirent_sink_t *sink)
{
	const lxp_file_t *f = &p->fs[s->file_idx];
	if ((file_mode(f) & LXP_S_IFMT) != LXP_S_IFDIR)
		return -LXP_ENOTDIR;
	return lxp_dir_list(p, s, f->path, sink);
}

static long fop_fstat_rootfs(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	lxp_stat_init(st, LXP_INO_ROOTFS + (uint32_t)s->file_idx, file_mode(&p->fs[s->file_idx]),
		      p->fs[s->file_idx].size);
	return 0;
}

/* Read-only: a NULL write makes write(2) return -EBADF and pwrite64(2) -ESPIPE. */
const lxp_file_ops_t lxp_rootfs_fops = {
	.read = fop_read_rootfs,
	.pread = fop_pread_rootfs,
	.lseek = fop_lseek_rootfs,
	.getdents = fop_getdents_rootfs,
	.mmap = fop_mmap_rootfs,
	.fstat = fop_fstat_rootfs,
};
