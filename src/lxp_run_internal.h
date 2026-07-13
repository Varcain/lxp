/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Private coordinator internals shared between the run loop (src/lxp_run.c) and the
 * signal-delivery TU (src/lxp_signal.c): a couple of coordinator primitives + the
 * per-slot signal-save state. NOT part of the public include/ API.
 */
#ifndef LXP_RUN_INTERNAL_H
#define LXP_RUN_INTERNAL_H

#include <stdint.h>

#include "lxp/lxp_seam.h"    /* struct lxp_frame, lxp_proc_t, LXP_NSLOT */
#include "lxp/lxp_syscall.h" /* lxp_proc_t, LXP_SIG_* */

/* Per-slot context saved at signal delivery, restored at rt_sigreturn. One per slot:
 * a program (via clone) may run several threads, each needing its own saved frame. */
struct sig_save_s {
	uint32_t r0, r1, r2, r3, r9, r12, lr, pc, xpsr;
	uint64_t saved_mask; /* proc->sig_blocked to restore at rt_sigreturn (handler self-block) */
	int active;
};
extern struct sig_save_s g_sig_save[LXP_NSLOT];

/* On handler entry: save the current signal mask into @p sv and block the delivered signal
 * for the handler's duration (POSIX: a handler does not re-enter on its own signal). Restored
 * from @c sv->saved_mask at rt_sigreturn (sig_restore). Shared by deliver_signal (running
 * frame) and deliver_signal_parked (parked proc). */
static inline void sig_block_for_handler(struct sig_save_s *sv, lxp_proc_t *proc, int sig)
{
	sv->saved_mask = proc->sig_blocked;
	proc->sig_blocked |= lxp_sig_bit(sig);
}

/* ---- coordinator primitives (lxp_run.c) ------------------------------------ */
int slot_of(const lxp_proc_t *p);	/* slot index of proc (proc - g_lxp_proc) */
void park_frame(struct lxp_frame *f);	/* park the frame at the spin loop + wake the coordinator */

/* ---- signal delivery (lxp_signal.c) ---------------------------------------- */
void resolve_handler(const lxp_proc_t *proc, int sig, uintptr_t *entry, uint32_t *got,
		     uintptr_t *restorer);
int sig_swallowed(const lxp_proc_t *proc, int sig);
void deliver_signal(struct lxp_frame *f, lxp_proc_t *proc, int sig, long ret);
void sig_restore(struct lxp_frame *f, lxp_proc_t *proc);

#endif /* LXP_RUN_INTERNAL_H */
