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

#include "lxp_linux_uapi.h"
#include "proc/lxp_proc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dispatch one Linux syscall against @p proc. Results use the Linux ABI:
 * non-negative success or a negated @c LXP_E* value.
 */
long lxp_syscall(lxp_proc_t *proc, long nr, long a0, long a1, long a2, long a3,
		 long a4, long a5);

/* Syscall-table flags. A clamp caps a guest-controlled byte count before the handler
 * runs: each interface permits a short result, and the finite quantum keeps one
 * deferred request preemptible and bounded. */
#define LXP_SYS_CLAMP_A1 0x01u	    /**< a[1] to LXP_SYSCALL_QUANTUM_BYTES */
#define LXP_SYS_CLAMP_A2 0x02u	    /**< a[2] to LXP_SYSCALL_QUANTUM_BYTES */
#define LXP_SYS_CLAMP_A2_FILE 0x04u /**< a[2] to LXP_SYSCALL_FILE_QUANTUM_BYTES */
/** Constant-time and pointer-free: may run in the trap's top half. Every other
 *  syscall is deferred to the coordinator, so a new one never inherits handler-mode
 *  execution by accident. */
#define LXP_SYS_FAST 0x08u
/** An ENOSYS the guest probes for and falls back from (socket() without
 *  networking): not reported through the host's on_enosys hook. */
#define LXP_SYS_QUIET_ENOSYS 0x10u

/** The table flags of syscall @p nr (0 for a number with no row). */
unsigned lxp_syscall_flags(long nr);

#ifdef __cplusplus
}
#endif

#endif /* LXP_SYSCALL_H */
