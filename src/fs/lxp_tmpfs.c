/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Writable VFS (tmpfs) node storage + pool. See fs/lxp_tmpfs.h for the model; the
 * syscall dispatcher owns the FD_TMPFS operation handlers and reaches nodes via
 * wnode_at() / wfs_find() / wfs_create() / wfs_reserve().
 */
#include "fs/lxp_tmpfs.h"

#include <string.h>

#define LXP_WFS_POOL (64u * 1024u)

static lxp_wnode_t g_wnodes[LXP_NWNODE];
static uint8_t g_wfs_pool[LXP_WFS_POOL];
static size_t g_wfs_off;

lxp_wnode_t *wnode_at(int i)
{
	return &g_wnodes[i];
}

static uint8_t *wfs_alloc(size_t n)
{
	n = (n + 7u) & ~(size_t)7u;
	if (g_wfs_off + n > sizeof(g_wfs_pool))
		return NULL;
	uint8_t *p = g_wfs_pool + g_wfs_off;
	g_wfs_off += n;
	return p;
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
	size_t ncap = (need + 255u) & ~(size_t)255u;
	uint8_t *nd = wfs_alloc(ncap);
	if (!nd)
		return -1;
	if (w->data && w->size)
		memcpy(nd, w->data, w->size);
	w->data = nd;
	w->cap = ncap;
	return 0;
}
