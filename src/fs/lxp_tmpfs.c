/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Writable VFS (tmpfs) node storage + pool and the FD_TMPFS file operations. See
 * fs/lxp_tmpfs.h for the model; the path syscalls reach nodes via lxp_wnode_at() /
 * lxp_wfs_find() / lxp_wfs_create() / lxp_wfs_reserve() / lxp_wfs_free().
 *
 * File bytes come from a fixed pool managed by the module's arena allocator
 * (first-fit + boundary coalescing), so a node's block is reclaimed when the file
 * grows (the old block is freed) or is removed (lxp_wfs_free).
 */
#include "fs/lxp_tmpfs.h"

#include <stdint.h>
#include <string.h>

#include "fs/lxp_dir.h"
#include "fs/lxp_path.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_vfs.h"
#include "lxp_arena.h"
#include "lxp_guest.h"
#include "lxp_linux_uapi.h"

/* The tmpfs pool goes through LXP_FAR_BSS (lxp_config.h), like the pipe pool, so a
 * consumer whose on-chip SRAM is tight can place it in external RAM (STM32 Zephyr: SDRAM1)
 * and a large /tmp file a program mmap()s need not fit the SRAM. */

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

lxp_wnode_t *lxp_wnode_at(int i)
{
	return &g_wnodes[i];
}

int lxp_wfs_find(const char *abspath)
{
	for (int i = 0; i < LXP_NWNODE; i++)
		if (g_wnodes[i].used && g_wnodes[i].linked &&
		    strcmp(g_wnodes[i].path, abspath) == 0)
			return i;
	return -1;
}

int lxp_wfs_create(const char *abspath, uint32_t mode)
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

int lxp_wfs_reserve(int i, size_t need)
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

int lxp_wfs_open(int i)
{
	if (i < 0 || i >= LXP_NWNODE || !g_wnodes[i].used ||
	    g_wnodes[i].open_refs == UINT16_MAX)
		return -1;
	g_wnodes[i].open_refs++;
	return 0;
}

void lxp_wfs_close(int i)
{
	if (i < 0 || i >= LXP_NWNODE || !g_wnodes[i].used ||
	    g_wnodes[i].open_refs == 0)
		return;
	if (--g_wnodes[i].open_refs == 0 && !g_wnodes[i].linked)
		wfs_reclaim(i);
}

/* Whether a linked node lies strictly below directory path @p dir. */
static int wfs_has_descendant(const char *dir)
{
	for (int j = 0; j < LXP_NWNODE; j++)
		if (g_wnodes[j].used && g_wnodes[j].linked && strcmp(g_wnodes[j].path, dir) != 0 &&
		    lxp_path_under(g_wnodes[j].path, dir))
			return 1;
	return 0;
}

int lxp_wfs_rename(int i, const char *newabs)
{
	lxp_wnode_t *node = &g_wnodes[i];
	size_t old_len = strlen(node->path);
	size_t new_len = strlen(newabs);
	if (strcmp(node->path, newabs) == 0)
		return 0;
	if (new_len >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	int is_dir = (node->mode & LXP_S_IFMT) == LXP_S_IFDIR;
	if (is_dir && lxp_path_under(newabs, node->path))
		return -LXP_EINVAL;
	int di = lxp_wfs_find(newabs);
	if (di >= 0 && wfs_has_descendant(newabs))
		return -LXP_ENOTEMPTY;
	/* Each descendant keeps its place below the new name: check they all fit first. */
	for (int j = 0; is_dir && j < LXP_NWNODE; j++)
		if (j != i && g_wnodes[j].used && g_wnodes[j].linked &&
		    lxp_path_under(g_wnodes[j].path, node->path) &&
		    strlen(g_wnodes[j].path) - old_len + new_len >= LXP_PATH_MAX)
			return -LXP_ENAMETOOLONG;
	if (di >= 0)
		lxp_wfs_free(di);
	for (int j = 0; is_dir && j < LXP_NWNODE; j++) {
		if (j == i || !g_wnodes[j].used || !g_wnodes[j].linked ||
		    !lxp_path_under(g_wnodes[j].path, node->path))
			continue;
		char moved[LXP_PATH_MAX];
		memcpy(moved, newabs, new_len);
		strcpy(moved + new_len, g_wnodes[j].path + old_len);
		strcpy(g_wnodes[j].path, moved);
	}
	strcpy(node->path, newabs);
	return 0;
}

void lxp_wfs_free(int i)
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

/* A writable-node file read returns bytes from its buffer at @p off. */
static long fop_pread_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len, uint64_t off)
{
	lxp_wnode_t *t = lxp_wnode_at(s->file_idx);
	if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EISDIR;
	return lxp_vfs_read_mem(p, t->data, t->size, buf, len, off);
}

static long fop_read_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	long n = fop_pread_tmpfs(p, s, buf, len, s->offset);
	if (n > 0)
		s->offset += (size_t)n;
	return n;
}

/* A writable-node file write copies into its (growable) buffer at @p off. */
static long fop_pwrite_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len,
			     uint64_t off)
{
	if (off > SIZE_MAX)
		return -LXP_EFBIG;
	size_t local_off = (size_t)off;
	lxp_wnode_t *t = lxp_wnode_at(s->file_idx);
	if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EBADF;
	if (local_off + len < len) /* off+len wrapped a 32-bit size_t → tiny reserve, OOB write */
		return -LXP_EINVAL;
	if (lxp_wfs_reserve(s->file_idx, local_off + len) != 0)
		return -LXP_EFBIG; /* writable-fs pool exhausted */
	if (local_off > t->size) /* zero the sparse hole (else it leaks stale pool bytes) */
		memset(t->data + t->size, 0, local_off - t->size);
	if (lxp_copy_from_guest(p, t->data + local_off, (uintptr_t)buf, len) != 0)
		return -LXP_EFAULT;
	if (local_off + len > t->size)
		t->size = local_off + len;
	return (long)len;
}

static long fop_write_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	long n = fop_pwrite_tmpfs(p, s, buf, len, s->offset);
	if (n > 0)
		s->offset += (size_t)n;
	return n;
}

static int64_t fop_lseek_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, int64_t off, int whence)
{
	(void)p;
	return lxp_vfs_seek(s, (int64_t)lxp_wnode_at(s->file_idx)->size, off, whence);
}

static long fop_getdents_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, lxp_dirent_sink_t *sink)
{
	lxp_wnode_t *t = lxp_wnode_at(s->file_idx);
	if ((t->mode & LXP_S_IFMT) != LXP_S_IFDIR)
		return -LXP_ENOTDIR;
	return lxp_dir_list(p, s, t->path, sink);
}

static long fop_fstat_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	(void)p;
	lxp_wnode_t *node = lxp_wnode_at(s->file_idx);
	lxp_stat_init(st, LXP_INO_TMPFS + (uint32_t)s->file_idx, node->mode, node->size);
	if (!node->linked)
		st->nlink = 0;
	return 0;
}

/* ftruncate64(fd, length) on a writable-VFS file: set its logical size, growing
 * with zeros if needed. vi's :w writes the new content then truncates to the exact
 * length, so editing an existing file shorter drops the old trailing bytes. */
static long fop_ftruncate_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, uint64_t length)
{
	(void)p;
	lxp_wnode_t *t = lxp_wnode_at(s->file_idx);
	if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EISDIR;
	if (length > SIZE_MAX)
		return -LXP_EFBIG;
	size_t newlen = (size_t)length;
	if (newlen > t->size) {
		if (lxp_wfs_reserve(s->file_idx, newlen) != 0)
			return -LXP_EFBIG;
		memset(t->data + t->size, 0, newlen - t->size);
	}
	t->size = newlen;
	return 0;
}

static void fop_close_tmpfs(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_wfs_close(s->file_idx);
}

/* An unlinked directory no longer has a name to resolve against. */
static long fop_dir_path_tmpfs(lxp_proc_t *p, lxp_ofd_t *s, char *out, size_t cap)
{
	(void)p;
	const lxp_wnode_t *w = lxp_wnode_at(s->file_idx);
	if ((w->mode & LXP_S_IFMT) != LXP_S_IFDIR)
		return -LXP_ENOTDIR;
	if (!w->linked)
		return -LXP_ENOENT;
	return lxp_vfs_copy_path(w->path, out, cap);
}

const lxp_file_ops_t lxp_tmpfs_fops = {
	.read = fop_read_tmpfs,
	.write = fop_write_tmpfs,
	.pread = fop_pread_tmpfs,
	.pwrite = fop_pwrite_tmpfs,
	.lseek = fop_lseek_tmpfs,
	.getdents = fop_getdents_tmpfs,
	.dir_path = fop_dir_path_tmpfs,
	.fstat = fop_fstat_tmpfs,
	.ftruncate = fop_ftruncate_tmpfs,
	.close = fop_close_tmpfs,
};
