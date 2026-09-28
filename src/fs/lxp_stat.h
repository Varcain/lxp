/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The ARM kernel struct stat64 record every fstat/stat path fills.
 */
#ifndef LXP_FS_STAT_H
#define LXP_FS_STAT_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_types.h"

/*
 * ARM kernel struct stat64. Spelled with fixed-width types (the kernel's
 * `unsigned long` is 32-bit on ARM but 64-bit on the x86-64 host) so the binary
 * layout is identical on target and in host tests.
 */
struct lxp_kstat64 {
	uint64_t st_dev;
	uint8_t __pad0[4];
	uint32_t __st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint64_t st_rdev;
	uint8_t __pad3[4];
	int64_t st_size;
	uint32_t st_blksize;
	uint64_t st_blocks;
	uint32_t st_atime;
	uint32_t st_atime_nsec;
	uint32_t st_mtime;
	uint32_t st_mtime_nsec;
	uint32_t st_ctime;
	uint32_t st_ctime_nsec;
	uint64_t st_ino;
};
/* ABI pins: the ARM-EABI struct stat64 layout uClibc-ng expects. A field-order or
 * type drift (which would silently corrupt every stat/fstat) fails the build. The
 * struct uses fixed-width fields, so these hold on the 32-bit target and the 64-bit
 * host test build alike. */
LXP_STATIC_ASSERT(sizeof(struct lxp_kstat64) == 104, "stat64 ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_mode) == 16, "stat64 st_mode offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_rdev) == 32, "stat64 st_rdev offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_size) == 48, "stat64 st_size offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_blocks) == 64, "stat64 st_blocks offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_ino) == 96, "stat64 st_ino offset drifted");

/* Fill an ARM kstat64 from a node's inode + mode + size. */
void lxp_fill_kstat64(struct lxp_kstat64 *st, uint32_t ino, uint32_t mode, uint64_t size);

#endif /* LXP_FS_STAT_H */
