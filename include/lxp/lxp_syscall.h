/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_SYSCALL_H
#define LXP_SYSCALL_H

/**
 * @file lxp_syscall.h
 * @brief Compatibility entry point for Linux syscall dispatch.
 *
 * New subsystem interfaces should include the narrow type contract they use.
 * The complete process model lives in @c lxp_proc.h; this header intentionally
 * preserves the original source-level API for applications and tests which
 * drive @c lxp_syscall() directly.
 */

#include "lxp/lxp_linux_uapi.h"
#include "lxp/lxp_proc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dispatch one Linux syscall against @p proc. Results use the Linux ABI:
 * non-negative success or a negated @c LXP_E* value.
 */
long lxp_syscall(lxp_proc_t *proc, long nr, long a0, long a1, long a2, long a3,
		 long a4, long a5);

#ifdef __cplusplus
}
#endif

#endif /* LXP_SYSCALL_H */
