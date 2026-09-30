/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Per-process signal policy (src/signal/lxp_signal_policy.c).
 */
#ifndef LXP_SIGNAL_POLICY_H
#define LXP_SIGNAL_POLICY_H

#include <stdint.h>

#include "proc/lxp_proc.h"

/* The lowest-numbered pending signal @p proc does not block, or 0; pending_take() also
 * clears it. */
int pending_deliverable(const lxp_proc_t *proc);
int pending_take(lxp_proc_t *proc);

/* SIG_DFL of @p sig never terminates (SIGCHLD, SIGCONT, SIGURG, SIGWINCH). */
int sig_default_ignore(int sig);
/* @p sig is ignored by @p proc: SIG_IGN, or SIG_DFL of a default-ignore signal. */
int sig_swallowed(const lxp_proc_t *proc, int sig);
/* A job-control stop signal (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU). */
int sig_is_stop(int sig);
/* Delivering @p sig would stop @p proc rather than run a handler or be ignored. */
int sig_stops_proc(const lxp_proc_t *proc, int sig);

/* Mark @p sig pending on @p proc, keeping the last of SIGCONT and a stop signal. */
void lxp_signal_latch(lxp_proc_t *proc, int sig);
/* End @p proc by @p sig: ask for its exit and record status 128+sig with @p reason and,
 * for a fault, the port's @p detail and @p address. */
void lxp_signal_terminate(lxp_proc_t *proc, int sig, uint8_t reason, uint32_t detail,
			  uintptr_t address);

#endif /* LXP_SIGNAL_POLICY_H */
