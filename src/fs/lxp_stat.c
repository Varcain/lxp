/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */
#include "fs/lxp_stat.h"

#include "lxp_linux_uapi.h"

#include <string.h>

void lxp_fill_kstat64(struct lxp_kstat64 *st, uint32_t ino, uint32_t mode, uint64_t size)
{
	memset(st, 0, sizeof(*st));
	st->st_nlink = 1;
	/* A UNIQUE, non-zero inode per node: ld.so dedups loaded objects by (st_dev, st_ino),
	 * so a zero inode makes every .so look already-loaded — libc.so would be skipped and
	 * its symbols never resolve. */
	st->__st_ino = ino;
	st->st_ino = ino;
	st->st_mode = mode;
	st->st_size = (int64_t)size;
	/* A character device blksize makes uClibc block-buffer stdio. */
	st->st_blksize = ((mode & LXP_S_IFMT) == LXP_S_IFCHR) ? 1024u : 512u;
	st->st_blocks = (uint64_t)((size + 511u) / 512u);
}
