/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */
#include "fs/lxp_dirent.h"

#include "lxp/lxp_config.h"
#include "lxp/lxp_types.h"
#include "lxp_guest.h"
#include "lxp_linux_uapi.h"
#include "proc/lxp_proc.h" /* LXP_PATH_MAX */

#include <string.h>

/* getdents64 record: fixed 19-byte head (d_ino..d_type) then a NUL-terminated name. */
struct lxp_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	uint16_t d_reclen;
	uint8_t d_type;
	char d_name[];
};
LXP_STATIC_ASSERT(offsetof(struct lxp_dirent64, d_name) == 19, "dirent64 head size drifted");

/* The 32-bit linux_dirent head: d_ino[4] d_off[4] d_reclen[2]; d_type is the last byte. */
#define LXP_DIRENT32_HEAD 10u

int lxp_dirent_put(lxp_dirent_sink_t *sink, uint64_t ino, uint64_t off, uint8_t type,
		   const char *name, size_t namelen)
{
	if (sink->error)
		return 0;
	size_t head = sink->is64 ? offsetof(struct lxp_dirent64, d_name) : LXP_DIRENT32_HEAD;
	size_t reclen = (head + namelen + 1u + (sink->is64 ? 0u : 1u) + 7u) & ~(size_t)7u;
	uint8_t record[LXP_PATH_MAX + 32];
	if (sink->filled + reclen > sink->cap || reclen > sizeof(record))
		return 0;
	size_t p = 0;
	int inobytes = sink->is64 ? 8 : 4;
	for (int i = 0; i < inobytes; i++)
		record[p++] = (uint8_t)(ino >> (8 * i));
	for (int i = 0; i < inobytes; i++)
		record[p++] = (uint8_t)(off >> (8 * i));
	record[p++] = (uint8_t)reclen;
	record[p++] = (uint8_t)(reclen >> 8);
	if (sink->is64)
		record[p++] = type;
	memcpy(record + p, name, namelen);
	p += namelen;
	while (p < reclen)
		record[p++] = 0;
	if (!sink->is64)
		record[reclen - 1] = type; /* the 32-bit layout carries d_type in its last byte */
	if (lxp_copy_to_guest(sink->proc, sink->ubuf + sink->filled, record, reclen) != 0) {
		sink->error = -LXP_EFAULT;
		return 0;
	}
	sink->filled += reclen;
	return 1;
}

uint8_t lxp_dirent_type(uint32_t mode)
{
	switch (mode & LXP_S_IFMT) {
	case LXP_S_IFDIR:
		return LXP_DT_DIR;
	case LXP_S_IFCHR:
		return LXP_DT_CHR;
	case LXP_S_IFBLK:
		return LXP_DT_BLK;
	case LXP_S_IFLNK:
		return LXP_DT_LNK;
	case LXP_S_IFIFO:
		return LXP_DT_FIFO;
	case LXP_S_IFSOCK:
		return LXP_DT_SOCK;
	default:
		return LXP_DT_REG;
	}
}
