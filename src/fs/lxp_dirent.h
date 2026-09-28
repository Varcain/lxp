/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Directory-record output for getdents(2) and getdents64(2).
 */
#ifndef LXP_FS_DIRENT_H
#define LXP_FS_DIRENT_H

#include <stddef.h>
#include <stdint.h>

#include "proc/lxp_proc_fwd.h"

/* A guest buffer being filled with linux_dirent64 (is64) or 32-bit linux_dirent
 * records. A failed copy to the guest is sticky in @c error; later records are
 * then dropped. */
typedef struct lxp_dirent_sink {
	lxp_proc_t *proc;
	uintptr_t ubuf;
	size_t cap;
	size_t filled;
	long error;
	int is64;
} lxp_dirent_sink_t;

/* Append one record with inode @p ino, resume cookie @p off and d_type @p type.
 * Returns 1 when written, 0 when it does not fit or the sink has failed. */
int lxp_dirent_put(lxp_dirent_sink_t *sink, uint64_t ino, uint64_t off, uint8_t type,
		   const char *name, size_t namelen);

/* The d_type for stat mode @p mode. */
uint8_t lxp_dirent_type(uint32_t mode);

#endif /* LXP_FS_DIRENT_H */
