/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Writable VFS (tmpfs) overlaid on the read-only cpio rootfs: regular files,
 * directories (mkdir), and symlinks (ln -s) created at runtime live here (e.g.
 * `mkdir /tmp/d`, `echo x > /tmp/f`). Nodes are global kernel state (shared across
 * processes, like pipes), keyed by absolute path; file bytes come from a fixed pool
 * managed by the arena allocator, so a node's block is reclaimed on growth and on
 * removal (ENOSPC only when the live set truly exhausts the pool).
 *
 * The node objects, pool and FD_TMPFS file operations live in src/fs/lxp_tmpfs.c; the
 * path syscalls and getdents reach a node via lxp_wnode_at().
 */
#ifndef LXP_FS_TMPFS_H
#define LXP_FS_TMPFS_H

#include <stddef.h>
#include <stdint.h>

#include "proc/lxp_proc.h" /* LXP_PATH_MAX */

#define LXP_NWNODE 32

typedef struct {
	char path[LXP_PATH_MAX]; /* absolute, normalized */
	uint32_t mode;		 /* S_IFREG|perms, S_IFDIR|perms, or S_IFLNK */
	uint8_t *data;		 /* file/symlink bytes (pool); NULL when empty */
	size_t size;
	size_t cap;
	int used;
	uint16_t open_refs;
	uint8_t linked;
} lxp_wnode_t;

/* The i-th node (0 <= i < LXP_NWNODE). The pool is otherwise private to lxp_tmpfs.c. */
lxp_wnode_t *lxp_wnode_at(int i);

/* Find a writable node by absolute path (any type), or -1. */
int lxp_wfs_find(const char *abspath);

/* Allocate a node for abspath with mode; -1 if the table is full / path too long. */
int lxp_wfs_create(const char *abspath, uint32_t mode);

/* Ensure node i can hold `need` bytes (grows from the pool, reclaiming the old
 * block). 0 on success, -1 if the pool is exhausted. */
int lxp_wfs_reserve(int i, size_t need);

/* Retain/release one open-file description for node i. dup/fork aliases share
 * that description and therefore do not add another node reference. */
int lxp_wfs_open(int i);
void lxp_wfs_close(int i);

/* Rename node i to newabs, replacing an existing node there; a directory carries its
 * descendants along. 0, or -ENAMETOOLONG, -EINVAL (a directory into its own subtree)
 * or -ENOTEMPTY (replacing a directory that has entries). */
int lxp_wfs_rename(int i, const char *newabs);

/* Remove node i's directory entry (unlink/rmdir, or rename replacing an
 * existing destination). Its bytes remain accessible to existing open-file
 * descriptions and are reclaimed after the final close. Nodes without open
 * descriptions are reclaimed immediately. */
void lxp_wfs_free(int i);

#endif /* LXP_FS_TMPFS_H */
