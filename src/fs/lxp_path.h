/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Path resolution used by the syscall dispatcher (src/fs/lxp_path.c). The rootfs
 * resolver lxp_rootfs_resolve() is public in lxp_proc.h (the run loop uses it to
 * locate ld.so before a proc exists).
 */
#ifndef LXP_FS_PATH_H
#define LXP_FS_PATH_H

#include <stddef.h>

#include "proc/lxp_proc.h"

/* Resolve user path `in` against p->fs_context->cwd into out[outlen] as a normalized absolute
 * path. Returns 0, or a negative errno (-EFAULT / -ENAMETOOLONG).
 *
 * `in` MUST be a guest pointer: this rejects anything not wholly inside the
 * program's memory, which is what guards every path syscall. Do not hand it a
 * string the kernel owns — see lxp_resolve_path_trusted(). */
long lxp_resolve_path(const lxp_proc_t *p, const char *in, char *out, size_t outlen);

/* lxp_resolve_path() for the *at() calls: a relative `in` resolves against the directory
 * open on @p dirfd (LXP_AT_FDCWD: the cwd). -EBADF, -ENOTDIR, or -EOPNOTSUPP for a
 * directory whose kind cannot name it (hostfs, netfs). */
long lxp_resolve_path_at(lxp_proc_t *p, int dirfd, const char *in, char *out, size_t outlen);

/* Normalize an ABSOLUTE path the kernel itself owns — one copied out of a file's
 * bytes rather than handed over by the guest, so there is no user pointer to
 * validate and lxp_resolve_path()'s -EFAULT guard would reject it outright.
 *
 * Only for kernel-owned input. Requires `in` to be absolute: the sole caller is
 * the #! interpreter, and Linux does not PATH-search one either. Returns 0, or a
 * negative errno (-EINVAL if relative, -ENAMETOOLONG). */
long lxp_resolve_path_trusted(const char *in, char *out, size_t outlen);

/* Look `abspath` up in p's read-only rootfs; returns the file index, or -1. */
int lxp_fs_lookup(const lxp_proc_t *p, const char *abspath);

/* Follow symlinks from rootfs index `idx` to the final target index, or -1. */
int lxp_fs_follow(const lxp_proc_t *p, int idx);

/* Resolve a trusted absolute rootfs path to its final non-symlink index. */
int lxp_rootfs_resolve_index(const lxp_file_t *fs, int count, const char *abspath);

/* The length of @p prefix when @p path is @p prefix or lies below it at a component
 * boundary (so /data covers /data/x but not /database), else 0. Everything lies below "/". */
size_t lxp_path_under(const char *path, const char *prefix);

/* If @p path names an entry exactly one component below directory @p dir, return
 * that child's name; otherwise NULL. */
const char *lxp_path_child_name(const char *dir, const char *path);

/* FNV-1a over path text. Start from LXP_PATH_HASH_INIT; chaining calls hashes the
 * concatenation, so hash("/dir") then "/" then "name" equals hash("/dir/name"). */
#define LXP_PATH_HASH_INIT 2166136261u
uint32_t lxp_path_hash(uint32_t hash, const char *text);

#endif /* LXP_FS_PATH_H */
