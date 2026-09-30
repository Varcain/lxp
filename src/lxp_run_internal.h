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

#include "lxp/lxp_seam.h" /* struct lxp_frame, LXP_NSLOT */
#include "proc/lxp_proc.h" /* lxp_proc_t, LXP_SIG_* */
#include "signal/lxp_signal_policy.h"

/* Context saved at signal delivery and restored at rt_sigreturn. */
struct sig_save_s {
	uint32_t r0, r1, r2, r3, r9, r12, lr, pc, xpsr;
	uint64_t saved_mask; /* mask restored when this specific handler returns */
#if LXP_ENABLE_FPU_CONTEXT
	/* A signal handler may freely use VFP registers. Preserve the interrupted
	 * state separately so rt_sigreturn can restore it exactly. */
	struct lxp_fp_context fp;
#endif
};

/* Each guest slot owns a bounded LIFO. A process may have several slots through
 * clone(), and each thread can receive a different signal while a handler is
 * active. Keeping the stack in host memory prevents guest stack corruption from
 * altering a future rt_sigreturn. */
struct sig_save_stack_s {
	struct sig_save_s frame[LXP_SIGNAL_NEST_MAX];
	uint8_t depth;
};
extern struct sig_save_stack_s g_lxp_sig_save[LXP_NSLOT];

enum lxp_signal_action {
	LXP_SIGNAL_INVALID,
	LXP_SIGNAL_IGNORE,
	LXP_SIGNAL_STOP,
	LXP_SIGNAL_TERMINATE,
	LXP_SIGNAL_HANDLER,
};

struct lxp_signal_delivery {
	uintptr_t entry;
	uintptr_t restorer;
	uint32_t got;
	struct sig_save_s *save;
};

/* ---- coordinator primitives (lxp_run.c) ------------------------------------ */
int lxp_slot_of(const lxp_proc_t *p); /* slot index of proc in the private runtime table */
void lxp_park_frame(struct lxp_frame *f,
		lxp_proc_t *proc); /* park + publish this slot to the coordinator */

/* ---- signal delivery (lxp_signal.c) ---------------------------------------- */
int lxp_resolve_handler(const lxp_proc_t *proc, int sig, uintptr_t *entry, uint32_t *got,
		    uintptr_t *restorer);
struct sig_save_s *lxp_sig_save_push(lxp_proc_t *proc, int sig);
enum lxp_signal_action lxp_signal_prepare(lxp_proc_t *proc, int sig,
					  struct lxp_signal_delivery *delivery);
void lxp_deliver_signal(struct lxp_frame *f, lxp_proc_t *proc, int sig, long ret);
void lxp_sig_restore(struct lxp_frame *f, lxp_proc_t *proc);

#endif /* LXP_RUN_INTERNAL_H */
