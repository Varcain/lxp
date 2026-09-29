/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Field views of the guest stat64 and statx buffers, read at their ARM-EABI byte
 * offsets so the tests pin the ABI independently of the module's own structs.
 */
#ifndef LXP_STAT_VIEW_H
#define LXP_STAT_VIEW_H

#include <stdint.h>
#include <string.h>

typedef struct lxp_stat_view {
	uint32_t mode;
	uint32_t nlink;
	uint64_t ino;
	uint64_t size;
	uint64_t dev;  /* major << 8 | minor */
	uint64_t rdev; /* major << 8 | minor */
	int64_t mtime;
} lxp_stat_view_t;

static inline uint64_t lxp_view_u64(const uint8_t *b, size_t off)
{
	uint64_t v;
	memcpy(&v, b + off, sizeof(v));
	return v;
}

static inline uint32_t lxp_view_u32(const uint8_t *b, size_t off)
{
	uint32_t v;
	memcpy(&v, b + off, sizeof(v));
	return v;
}

/* struct stat64: st_dev@0 st_mode@16 st_nlink@20 st_rdev@32 st_size@48 st_mtime@80
 * st_ino@96. */
static inline lxp_stat_view_t lxp_view_kstat64(const uint8_t *b)
{
	lxp_stat_view_t v = {
		.mode = lxp_view_u32(b, 16),
		.nlink = lxp_view_u32(b, 20),
		.ino = lxp_view_u64(b, 96),
		.size = lxp_view_u64(b, 48),
		.dev = lxp_view_u64(b, 0),
		.rdev = lxp_view_u64(b, 32),
		.mtime = (int64_t)lxp_view_u32(b, 80),
	};
	return v;
}

/* struct statx: stx_nlink@16 stx_mode@28 stx_ino@32 stx_size@40 stx_mtime.tv_sec@112
 * stx_rdev_major@128 stx_rdev_minor@132 stx_dev_major@136 stx_dev_minor@140. */
static inline lxp_stat_view_t lxp_view_statx(const uint8_t *b)
{
	uint16_t mode;
	memcpy(&mode, b + 28, sizeof(mode));
	lxp_stat_view_t v = {
		.mode = mode,
		.nlink = lxp_view_u32(b, 16),
		.ino = lxp_view_u64(b, 32),
		.size = lxp_view_u64(b, 40),
		.dev = ((uint64_t)lxp_view_u32(b, 136) << 8) | lxp_view_u32(b, 140),
		.rdev = ((uint64_t)lxp_view_u32(b, 128) << 8) | lxp_view_u32(b, 132),
		.mtime = (int64_t)lxp_view_u64(b, 112),
	};
	return v;
}

#endif /* LXP_STAT_VIEW_H */
