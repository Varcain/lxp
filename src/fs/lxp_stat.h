/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The stat record each descriptor kind and path namespace fills, and the ARM-EABI
 * struct stat64, statx and statfs64 layouts it is formatted into.
 */
#ifndef LXP_FS_STAT_H
#define LXP_FS_STAT_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_types.h"
#include "proc/lxp_proc_fwd.h"

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

/* ARM-EABI statfs64. Mounted host volumes use provider allocation data; the
 * in-memory personality namespaces retain bounded synthetic values. */
struct lxp_statfs64 {
	uint32_t f_type, f_bsize;
	uint64_t f_blocks, f_bfree, f_bavail, f_files, f_ffree;
	uint32_t f_fsid[2], f_namelen, f_frsize, f_flags, f_spare[4];
};
LXP_STATIC_ASSERT(sizeof(struct lxp_statfs64) == 88, "statfs64 ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statfs64, f_blocks) == 8, "statfs64 f_blocks offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statfs64, f_namelen) == 56,
		  "statfs64 f_namelen offset drifted");

#define LXP_TMPFS_MAGIC 0x01021994u
#define LXP_MSDOS_SUPER_MAGIC 0x00004d44u
#define LXP_ST_RDONLY 0x0001u
#define LXP_ST_NOSUID 0x0002u
#define LXP_ST_NODEV 0x0004u
#define LXP_ST_NOEXEC 0x0008u

/* Modern struct statx (256 bytes); fixed-width so host tests match the target. */
struct lxp_statx {
	uint32_t stx_mask;
	uint32_t stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink;
	uint32_t stx_uid;
	uint32_t stx_gid;
	uint16_t stx_mode;
	uint16_t __spare0;
	uint64_t stx_ino;
	uint64_t stx_size;
	uint64_t stx_blocks;
	uint64_t stx_attributes_mask;
	uint8_t __times[64];	 /* atime/btime/ctime/mtime (4 x 16B) — offsets 64..128 */
	uint32_t stx_rdev_major; /* offset 128 */
	uint32_t stx_rdev_minor; /* offset 132 */
	uint32_t stx_dev_major;
	uint32_t stx_dev_minor;
	uint8_t __rest[256 - 144];
};
LXP_STATIC_ASSERT(sizeof(struct lxp_statx) == 256, "statx ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statx, stx_mode) == 28, "statx stx_mode offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statx, stx_ino) == 32, "statx stx_ino offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statx, stx_rdev_major) == 128,
		  "statx stx_rdev offset drifted");

/* Inode ranges. Each namespace numbers its objects from its own base so that
 * (st_dev, st_ino) stays unique: ld.so dedups loaded objects by that pair, so a
 * collision makes a library look already loaded. A named object gets the same
 * inode from stat, fstat and readdir. */
enum lxp_ino_base {
	LXP_INO_ROOTFS = 0x000001u,   /* + rootfs index */
	LXP_INO_TMPFS = 0x100000u,    /* + writable node index */
	LXP_INO_PROC = 0x200000u,     /* + 20-bit path hash (lxp_procfs_inode) */
	LXP_INO_DEV = 0x300000u,      /* + registry index; streams: + object index */
	LXP_INO_DEVFS = 0x300100u,    /* + built-in /dev node (console, null, random, ptmx) */
	LXP_INO_SOCKET = 0x400000u,   /* + socket index */
	LXP_INO_PTY = 0x500000u,      /* + pty index */
	LXP_INO_NETFS = 0x600000u,    /* + 9P qid path */
	LXP_INO_HOSTFS = 0x70000000u, /* + 28-bit path hash (lxp_hostfs_path_inode) */
};

/* The attributes every stat path reports, before formatting for the guest. */
struct lxp_stat {
	uint32_t mode;
	uint32_t ino;
	uint32_t nlink;
	uint32_t dev_major;
	uint32_t dev_minor;
	uint64_t rdev; /* major << 8 | minor */
	uint64_t size;
	int64_t mtime; /* seconds; 0 when the backend has none */
};

/* A single-link object with no device or time attributes. */
void lxp_stat_init(struct lxp_stat *st, uint32_t ino, uint32_t mode, uint64_t size);

/* Write @p st to guest @p ubuf as a struct stat64, or as a struct statx when
 * @p statx is nonzero: 0 or -EFAULT. */
long lxp_stat_copyout(lxp_proc_t *p, uintptr_t ubuf, int statx, const struct lxp_stat *st);

#endif /* LXP_FS_STAT_H */
