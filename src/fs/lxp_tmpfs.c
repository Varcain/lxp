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
 * grows (the old block is freed) or is removed (wfs_free) — no leak, unlike the
 * former pure-bump pool.
 */
#include "fs/lxp_tmpfs.h"

#include <string.h>

#include "lxp/lxp_arena.h"

#define LXP_WFS_POOL (64u * 1024u)

static lxp_wnode_t g_wnodes[LXP_NWNODE];
static uint8_t g_wfs_pool[LXP_WFS_POOL] __attribute__((aligned(LXP_ARENA_ALIGN)));
static lxp_arena_t g_wfs_arena;
static int g_wfs_ready; /* the arena is initialised lazily on first allocation. */

lxp_wnode_t *wnode_at(int i)
{
	return &g_wnodes[i];
}

static uint8_t *wfs_alloc(size_t n)
{
	if (!g_wfs_ready) {
		lxp_arena_init(&g_wfs_arena, g_wfs_pool, sizeof(g_wfs_pool));
		g_wfs_ready = 1;
	}
	return (uint8_t *)lxp_arena_alloc(&g_wfs_arena, n); /* the arena aligns internally */
}

int wfs_find(const char *abspath)
{
	for (int i = 0; i < LXP_NWNODE; i++)
		if (g_wnodes[i].used && strcmp(g_wnodes[i].path, abspath) == 0)
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
			return i;
		}
	return -1;
}

int wfs_reserve(int i, size_t need)
{
	lxp_wnode_t *w = &g_wnodes[i];
	if (need <= w->cap)
		return 0;
	if (need > LXP_WFS_POOL) /* reject before the 256-round wraps a 32-bit size_t → tiny alloc */
		return -1;
	size_t ncap = (need + 255u) & ~(size_t)255u;
	uint8_t *nd = wfs_alloc(ncap);
	if (!nd)
		return -1;
	if (w->data && w->size)
		memcpy(nd, w->data, w->size);
	if (w->data)
		lxp_arena_free(&g_wfs_arena, w->data); /* reclaim the old (smaller) block */
	w->data = nd;
	w->cap = ncap;
	return 0;
}

void wfs_free(int i)
{
	lxp_wnode_t *w = &g_wnodes[i];
	if (w->data)
		lxp_arena_free(&g_wfs_arena, w->data); /* reclaim the node's pool bytes */
	w->data = NULL;
	w->size = 0;
	w->cap = 0;
	w->used = 0;
}
