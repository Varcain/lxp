/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */
#include "fs/lxp_stat.h"

#include "lxp_guest.h"
#include "lxp_linux_uapi.h"

#include <string.h>

void lxp_stat_init(struct lxp_stat *st, uint32_t ino, uint32_t mode, uint64_t size)
{
	memset(st, 0, sizeof(*st));
	st->ino = ino;
	st->mode = mode;
	st->nlink = 1;
	st->size = size;
}

static void fill_kstat64(struct lxp_kstat64 *k, const struct lxp_stat *st)
{
	memset(k, 0, sizeof(*k));
	k->st_dev = ((uint64_t)st->dev_major << 8) | st->dev_minor;
	k->st_nlink = st->nlink;
	/* A UNIQUE, non-zero inode per node: ld.so dedups loaded objects by (st_dev, st_ino),
	 * so a zero inode makes every .so look already-loaded — libc.so would be skipped and
	 * its symbols never resolve. */
	k->__st_ino = st->ino;
	k->st_ino = st->ino;
	k->st_mode = st->mode;
	k->st_rdev = st->rdev;
	k->st_size = (int64_t)st->size;
	/* A character device blksize makes uClibc block-buffer stdio. */
	k->st_blksize = ((st->mode & LXP_S_IFMT) == LXP_S_IFCHR) ? 1024u : 512u;
	k->st_blocks = (uint64_t)((st->size + 511u) / 512u);
	k->st_mtime = (uint32_t)st->mtime;
}

static void fill_statx(struct lxp_statx *x, const struct lxp_stat *st)
{
	memset(x, 0, sizeof(*x));
	x->stx_mask = LXP_STATX_BASIC_STATS;
	x->stx_blksize = 512;
	x->stx_nlink = st->nlink;
	x->stx_mode = (uint16_t)st->mode;
	x->stx_ino = st->ino;
	x->stx_size = st->size;
	x->stx_blocks = (st->size + 511u) / 512u;
	memcpy(x->__times + 48, &st->mtime, sizeof(st->mtime)); /* stx_mtime.tv_sec */
	x->stx_rdev_major = (uint32_t)(st->rdev >> 8);
	x->stx_rdev_minor = (uint32_t)(st->rdev & 0xffu);
	x->stx_dev_major = st->dev_major;
	x->stx_dev_minor = st->dev_minor;
}

long lxp_stat_copyout(lxp_proc_t *p, uintptr_t ubuf, int statx, const struct lxp_stat *st)
{
	if (statx) {
		struct lxp_statx x;
		fill_statx(&x, st);
		return lxp_copy_to_guest(p, ubuf, &x, sizeof(x));
	}
	struct lxp_kstat64 k;
	fill_kstat64(&k, st);
	return lxp_copy_to_guest(p, ubuf, &k, sizeof(k));
}
