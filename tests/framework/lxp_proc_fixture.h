/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Shared fixture for the syscall golden-conformance suite: a proc backed by a bounded
 * LOW-4 GiB region so the host tests run as close to the 32-bit target as a host can.
 *   - region_lo/hi bound user_ok() to a REAL window, so a bad guest pointer is genuinely
 *     -EFAULT (unlike the all-permitting setup in test_linux_syscall.c) and ASan faults
 *     on any user_ok bypass.
 *   - brk / mmap addresses come from an arena inside the low region, so they fit a 32-bit
 *     r0 exactly and round-trip as they do on the Cortex-M target.
 * Reuses fuzz_lowbuf (MAP_32BIT + PROT_NONE guard page) from fuzz/fuzz_common.h, so the
 * low-region logic has a single source of truth (build adds -I fuzz).
 *
 * MAP_32BIT is best-effort: if the low 4 GiB is exhausted (or unavailable) the mapping
 * falls back above 4 GiB. Value/errno/struct assertions are address-width-independent and
 * still run; only the "address fits 32 bits" round-trip checks must be gated on
 * lxp_conf_is_32bit(). Because every guest pointer the suite hands a syscall is carved from
 * this region, the pointers are valid regardless of where the region landed.
 *
 * Header-only (no new TU). The prior mapping is released on each lxp_conf_begin(), so a
 * cmocka assert longjmp'ing out of a test never leaks the low region into the next one.
 */
#ifndef LXP_PROC_FIXTURE_H
#define LXP_PROC_FIXTURE_H

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fuzz_common.h" /* fuzz_lowbuf_map / fuzz_lowbuf_t — via -I fuzz */

#include "lxp/lxp_arena.h"
#include "lxp/lxp_syscall.h"

#define LXP_CONF_SCRATCH (64u * 1024u)	/* guest buffers + path strings the suite hands to syscalls */
#define LXP_CONF_ARENA (512u * 1024u)	/* backs brk + anonymous mmap */
#define LXP_CONF_BRK (64u * 1024u)	/* initial brk reservation */

typedef struct lxp_conf {
	fuzz_lowbuf_t low; /* the whole low-region mapping: [scratch | arena] */
	lxp_arena_t arena;
	uint8_t *scratch;     /* bump cursor within the scratch sub-region */
	uint8_t *scratch_end;
} lxp_conf_t;

/* Captured fd 1/2 output, so write()/writev() can be asserted by value. */
static char g_conf_cap[256];
static size_t g_conf_cap_len;

static long lxp_conf_cap_write(void *ctx, int fd, const void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (g_conf_cap_len + len > sizeof(g_conf_cap))
		len = sizeof(g_conf_cap) - g_conf_cap_len;
	memcpy(g_conf_cap + g_conf_cap_len, buf, len);
	g_conf_cap_len += len;
	return (long)len;
}

/* The single live fixture; released + remapped on each begin so a test that aborts via a
 * cmocka assert cannot leak its low-region mapping into the next test. */
static lxp_conf_t g_conf;

static inline void lxp_conf_release(lxp_conf_t *fx)
{
	if (fx->low.base) {
		long pg = sysconf(_SC_PAGESIZE);
		if (pg <= 0)
			pg = 4096;
		munmap(fx->low.base, fx->low.cap + (size_t)pg); /* usable + guard page */
		fx->low.base = NULL;
		fx->low.cap = 0;
	}
}

/* True when the region genuinely landed in the low 4 GiB (MAP_32BIT succeeded), so the
 * address-width round-trip assertions are meaningful. */
static inline int lxp_conf_is_32bit(const lxp_conf_t *fx)
{
	return ((uintptr_t)fx->low.base + fx->low.cap) <= 0xFFFFFFFFu;
}

/* Start a fresh conformance proc over a newly mapped low region. Returns the fixture, or
 * NULL if the mapping failed (the caller should skip()). @p rootfs may be NULL. */
static inline lxp_conf_t *lxp_conf_begin(lxp_proc_t *p, const lxp_file_t *rootfs, int rootfs_n)
{
	lxp_conf_release(&g_conf);
	g_conf.low = fuzz_lowbuf_map(LXP_CONF_SCRATCH + LXP_CONF_ARENA);
	if (!g_conf.low.base)
		return NULL;
	g_conf.scratch = g_conf.low.base;
	g_conf.scratch_end = g_conf.low.base + LXP_CONF_SCRATCH;
	if (lxp_arena_init(&g_conf.arena, g_conf.low.base + LXP_CONF_SCRATCH, LXP_CONF_ARENA) != LXP_OK) {
		lxp_conf_release(&g_conf);
		return NULL;
	}
	if (lxp_proc_init(p, &g_conf.arena, LXP_CONF_BRK) != LXP_OK) {
		lxp_conf_release(&g_conf);
		return NULL;
	}
	/* Bound user_ok to the whole low region; a static proc's pool == its region. */
	p->region_lo = (uintptr_t)g_conf.low.base;
	p->region_hi = (uintptr_t)g_conf.low.base + g_conf.low.cap;
	p->pool_lo = p->region_lo;
	p->pool_hi = p->region_hi;
	p->write_fn = lxp_conf_cap_write;
	g_conf_cap_len = 0;
	if (rootfs)
		lxp_proc_set_rootfs(p, rootfs, rootfs_n);
	return &g_conf;
}

/* Carve @p n zeroed bytes of in-region guest memory (8-aligned). Aborts the test if the
 * scratch sub-region is exhausted (a fixture-sizing bug, not a syscall result). */
static inline void *lxp_conf_alloc(lxp_conf_t *fx, size_t n)
{
	uint8_t *q = (uint8_t *)(((uintptr_t)fx->scratch + 7u) & ~(uintptr_t)7u);
	if (q + n > fx->scratch_end)
		return NULL;
	fx->scratch = q + n;
	memset(q, 0, n);
	return q;
}

/* Copy a C string into in-region guest memory; returns the in-region pointer (for path
 * args, which the syscall validates through user_strnlen against region_lo/hi). */
static inline char *lxp_conf_str(lxp_conf_t *fx, const char *s)
{
	size_t n = strlen(s) + 1;
	char *d = (char *)lxp_conf_alloc(fx, n);
	if (d)
		memcpy(d, s, n);
	return d;
}

/* A guaranteed-invalid guest pointer (just past the region's upper bound), for -EFAULT
 * assertions. A read/write of it must fail user_ok. */
static inline void *lxp_conf_bad_ptr(const lxp_conf_t *fx)
{
	return (void *)((uintptr_t)fx->low.base + fx->low.cap);
}

/* Search a getdents64 buffer for an entry by name; returns its d_type, or -1. Mirrors the
 * ARM linux_dirent64 layout (d_name at offset 19, d_reclen at 16). */
static inline int lxp_conf_dirent_type(const uint8_t *buf, long len, const char *name)
{
	long off = 0;
	while (off + 19 <= len) {
		uint16_t reclen;
		memcpy(&reclen, buf + off + 16, sizeof(reclen));
		if (reclen == 0)
			break;
		if (strcmp((const char *)(buf + off + 19), name) == 0)
			return buf[off + 18];
		off += reclen;
	}
	return -1;
}

#endif /* LXP_PROC_FIXTURE_H */
