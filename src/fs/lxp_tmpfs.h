/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Writable VFS (tmpfs) overlaid on the read-only cpio rootfs: regular files,
 * directories (mkdir), and symlinks (ln -s) created at runtime live here (e.g.
 * `mkdir /tmp/d`, `echo x > /tmp/f`). Nodes are global kernel state (shared across
 * processes, like pipes), keyed by absolute path; file bytes come from a bump pool
 * (growth re-allocates, the old block leaks — bounded, ENOSPC when exhausted).
 *
 * The node objects + pool live in src/fs/lxp_tmpfs.c; the syscall dispatcher owns the
 * FD_TMPFS read/write/stat/getdents integration and reaches a node via wnode_at().
 */
#ifndef LXP_FS_TMPFS_H
#define LXP_FS_TMPFS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_syscall.h" /* LXP_PATH_MAX */

#define LXP_NWNODE 32

typedef struct {
	char path[LXP_PATH_MAX]; /* absolute, normalized */
	uint32_t mode;		 /* S_IFREG|perms, S_IFDIR|perms, or S_IFLNK */
	uint8_t *data;		 /* file/symlink bytes (pool); NULL when empty */
	size_t size;
	size_t cap;
	int used;
} lxp_wnode_t;

/* The i-th node (0 <= i < LXP_NWNODE). The pool is otherwise private to lxp_tmpfs.c. */
lxp_wnode_t *wnode_at(int i);

/* Find a writable node by absolute path (any type), or -1. */
int wfs_find(const char *abspath);

/* Allocate a node for abspath with mode; -1 if the table is full / path too long. */
int wfs_create(const char *abspath, uint32_t mode);

/* Ensure node i can hold `need` bytes (grows from the pool; old block leaks). 0 / -1. */
int wfs_reserve(int i, size_t need);

#endif /* LXP_FS_TMPFS_H */
