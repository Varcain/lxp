/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Cross-TU private internals of the syscall core: user-pointer validation + a couple
 * of rootfs helpers the extracted subsystem TUs (fs/proc/...) share with the
 * dispatcher. Defined in src/lxp_syscall.c; NOT part of the public include/ API.
 */
#ifndef LXP_INTERNAL_H
#define LXP_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_syscall.h" /* lxp_proc_t, lxp_file_t */

/* True iff [ptr, ptr+len) is wholly readable (write==0) or writable (write==1) by
 * program `p` — the access_ok guard every user-pointer deref must pass first. */
int user_ok(const lxp_proc_t *p, const void *ptr, size_t len, int write);

/* strlen of a user string, or -EFAULT if not NUL-terminated within a valid readable
 * range (bounded by `max`). */
long user_strnlen(const lxp_proc_t *p, const char *s, size_t max);

/* The stat mode (S_IF* | perms) of a rootfs file entry. */
uint32_t file_mode(const lxp_file_t *f);

#endif /* LXP_INTERNAL_H */
