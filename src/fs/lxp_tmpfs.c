/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Writable VFS (tmpfs) node storage + pool. See fs/lxp_tmpfs.h for the model; the
 * syscall dispatcher owns the FD_TMPFS operation handlers and reaches nodes via
 * wnode_at() / wfs_find() / wfs_create() / wfs_reserve() / wfs_free().
 *
 * File bytes come from a fixed pool managed by the module's arena allocator
 * (first-fit + boundary coalescing), so a node's block is reclaimed when the file
 * grows (the old block is freed) or is removed (wfs_free).
 */
#include "fs/lxp_tmpfs.h"

#include <string.h>

#include "lxp/lxp_arena.h"

/* Board-relocatable BSS section (default: normal .bss). A consumer whose on-chip SRAM is tight can
 * point this at a far region (STM32 Zephyr: SDRAM1) so the tmpfs pool — and thus a large /tmp file
 * a program mmap()s (e.g. iperf3's per-stream buffer, created mkstemp+ftruncate+mmap) — need not
 * fit the SRAM. Same knob the pipe pool uses. */
#ifndef LXP_FAR_BSS
#define LXP_FAR_BSS
#endif

static lxp_wnode_t g_wnodes[LXP_NWNODE];
#if defined(LXP_WFS_POOL_BASE)
_Static_assert(((uintptr_t)LXP_WFS_POOL_BASE & (LXP_ARENA_ALIGN - 1u)) == 0u,
	       "LXP_WFS_POOL_BASE must satisfy arena alignment");
static uint8_t *const g_wfs_pool = (uint8_t *)(uintptr_t)LXP_WFS_POOL_BASE;
#else
static uint8_t g_wfs_pool[LXP_WFS_POOL] LXP_FAR_BSS __attribute__((aligned(LXP_ARENA_ALIGN)));
#endif
static lxp_arena_t g_wfs_arena;
static int g_wfs_ready; /* the arena is initialised lazily on first allocation. */

lxp_wnode_t *wnode_at(int i)
{
	return &g_wnodes[i];
}

int wfs_find(const char *abspath)
{
	for (int i = 0; i < LXP_NWNODE; i++)
		if (g_wnodes[i].used && g_wnodes[i].linked &&
		    strcmp(g_wnodes[i].path, abspath) == 0)
			return i;
	return -1;
}

int wfs_create(const char *abspath, uint32_t mode)
{
	if (strlen(abspath) >= LXP_PATH_MAX)
		return -1;
	for (int i = 0; i < LXP_NWNODE; i++)
		if (!g_wnodes[i].used) {
			strcpy(g_wnodes[i].path, abspath);
			g_wnodes[i].mode = mode;
			g_wnodes[i].data = NULL;
			g_wnodes[i].size = 0;
			g_wnodes[i].cap = 0;
			g_wnodes[i].used = 1;
			g_wnodes[i].linked = 1;
			g_wnodes[i].open_refs = 0;
			return i;
		}
	return -1;
}

int wfs_reserve(int i, size_t need)
{
	lxp_wnode_t *w = &g_wnodes[i];
	if (need <= w->cap)
		return 0;
	/*
	 * One aligned allocator header lives inside the pool. Reject before the
	 * 256-round wraps size_t and keep the advertised file capacity honest.
	 */
	const size_t max_payload = LXP_WFS_POOL - LXP_ARENA_ALIGN;
	if (need > max_payload)
		return -1;
	if (need > SIZE_MAX - 255u)
		return -1;
	size_t mincap = (need + 255u) & ~(size_t)255u;
	size_t ncap = mincap;
	if (w->cap > max_payload / 2u)
		ncap = max_payload;
	else if (w->cap * 2u > ncap) /* geometric growth: O(n), not O(n^2) */
		ncap = w->cap * 2;
	if (ncap > max_payload)
		ncap = max_payload;
	if (!g_wfs_ready) {
		lxp_arena_init(&g_wfs_arena, g_wfs_pool, LXP_WFS_POOL);
		g_wfs_ready = 1;
	}
	uint8_t *nd = lxp_arena_realloc(&g_wfs_arena, w->data, ncap);
	if (!nd && ncap != mincap)
		nd = lxp_arena_realloc(&g_wfs_arena, w->data, mincap);
	if (!nd)
		return -1;
	w->data = nd;
	w->cap = ncap;
	return 0;
}

static void wfs_reclaim(int i)
{
	lxp_wnode_t *w = &g_wnodes[i];
	if (w->data)
		lxp_arena_free(&g_wfs_arena, w->data); /* reclaim the node's pool bytes */
	memset(w, 0, sizeof(*w));
}

int wfs_open(int i)
{
	if (i < 0 || i >= LXP_NWNODE || !g_wnodes[i].used ||
	    g_wnodes[i].open_refs == UINT16_MAX)
		return -1;
	g_wnodes[i].open_refs++;
	return 0;
}

void wfs_close(int i)
{
	if (i < 0 || i >= LXP_NWNODE || !g_wnodes[i].used ||
	    g_wnodes[i].open_refs == 0)
		return;
	if (--g_wnodes[i].open_refs == 0 && !g_wnodes[i].linked)
		wfs_reclaim(i);
}

void wfs_free(int i)
{
	if (i < 0 || i >= LXP_NWNODE || !g_wnodes[i].used)
		return;
	/*
	 * unlink(2) removes the directory entry, not an already-open file
	 * description. SQLite relies on this for anonymous temporary databases:
	 * it opens a file, unlinks the name, then continues using the descriptor.
	 */
	g_wnodes[i].linked = 0;
	g_wnodes[i].path[0] = '\0';
	if (g_wnodes[i].open_refs == 0)
		wfs_reclaim(i);
}
