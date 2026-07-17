/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Path resolution used by the syscall dispatcher (src/fs/lxp_path.c). The rootfs
 * resolver lxp_rootfs_resolve() is public in lxp_syscall.h (the run loop uses it to
 * locate ld.so before a proc exists).
 */
#ifndef LXP_FS_PATH_H
#define LXP_FS_PATH_H

#include <stddef.h>

#include "lxp/lxp_syscall.h" /* lxp_proc_t */

/* Resolve user path `in` against p->cwd into out[outlen] as a normalized absolute
 * path. Returns 0, or a negative errno (-EFAULT / -ENAMETOOLONG).
 *
 * `in` MUST be a guest pointer: this rejects anything not wholly inside the
 * program's memory, which is what guards every path syscall. Do not hand it a
 * string the kernel owns — see resolve_path_trusted(). */
long resolve_path(const lxp_proc_t *p, const char *in, char *out, size_t outlen);

/* Normalize an ABSOLUTE path the kernel itself owns — one copied out of a file's
 * bytes rather than handed over by the guest, so there is no user pointer to
 * validate and resolve_path()'s -EFAULT guard would reject it outright.
 *
 * Only for kernel-owned input. Requires `in` to be absolute: the sole caller is
 * the #! interpreter, and Linux does not PATH-search one either. Returns 0, or a
 * negative errno (-EINVAL if relative, -ENAMETOOLONG). */
long resolve_path_trusted(const char *in, char *out, size_t outlen);

/* Look `abspath` up in p's read-only rootfs; returns the file index, or -1. */
int fs_lookup(const lxp_proc_t *p, const char *abspath);

/* Follow symlinks from rootfs index `idx` to the final target index, or -1. */
int fs_follow(const lxp_proc_t *p, int idx);

#endif /* LXP_FS_PATH_H */
