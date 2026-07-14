/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Signal delivery over the uniform svc frame: resolve an FDPIC handler descriptor,
 * push a handler frame (saving the interrupted context per slot), and restore it at
 * rt_sigreturn. Driven by the run loop's dispatch + event loop (lxp_run.c) via the
 * coordinator primitives in lxp_run_internal.h; deliver_signal_parked (the parked-proc
 * variant, which resumes via the engine) stays with the coordinator in lxp_run.c.
 */
#include "lxp_run_internal.h"

#include "lxp/lxp_seam.h"
#include "lxp/lxp_syscall.h"

/* ---- signal delivery (over the uniform frame) ------------------------------ */
/* Resolve a handler + restorer for delivery. FDPIC: sa_handler/sa_restorer are function DESCRIPTORS
 * {entry, GOT} — deref, since the handler may live in a different module (e.g. libpthread) than the
 * interrupted code and needs its own r9=GOT. Non-FDPIC (e.g. the posix host test): raw entries, no
 * GOT change. */
void resolve_handler(const lxp_proc_t *proc, int sig, uintptr_t *entry, uint32_t *got,
			    uintptr_t *restorer)
{
	uintptr_t h = proc->sig_handler[sig];
	uintptr_t r = proc->sig_restorer;
	if (proc->is_fdpic) {
		*entry = ((const uint32_t *)h)[0];
		*got = ((const uint32_t *)h)[1];
		*restorer = ((const uint32_t *)r)[0];
	} else {
		*entry = h;
		*got = 0;
		*restorer = r;
	}
}

/* Is signal `sig` effectively ignored for `proc`? True for SIG_IGN, or SIG_DFL of a
 * signal whose default action is "ignore" (SIGCHLD). Such a signal is swallowed by the
 * coordinator: it neither runs a handler nor terminates a parked proc — a parent must
 * not die because a child exited. */
int sig_swallowed(const lxp_proc_t *proc, int sig)
{
	uintptr_t h = proc->sig_handler[sig];
	if (h == LXP_SIG_IGN)
		return 1;
	if (h == LXP_SIG_DFL && sig == LXP_SIGCHLD)
		return 1;
	return 0;
}

/* Deliver signal `sig` to `proc`; `ret` is the interrupted syscall's result
 * (0 for a kill/tkill, -EINTR for a console-interrupted read). */
void deliver_signal(struct lxp_frame *f, lxp_proc_t *proc, int sig, long ret)
{
	if (sig < 1 || sig >= LXP_NSIG) {
		f->r[0] = (uint32_t)-LXP_EINVAL;
		return;
	}
	uintptr_t h = proc->sig_handler[sig];
	if (h == LXP_SIG_IGN || (h == LXP_SIG_DFL && sig == LXP_SIGCHLD)) {
		f->r[0] = (uint32_t)ret; /* SIG_IGN, or a default-ignore signal (SIGCHLD) */
		return;
	}
	if (h == LXP_SIG_DFL) {
		proc->exited = 1;
		proc->exit_status = 128 + sig;
		park_frame(f); /* the coordinator reaps it */
		return;
	}
	struct sig_save_s *sv = &g_sig_save[slot_of(proc)];
	sv->r0 = (uint32_t)ret;
	sv->r1 = f->r[1];
	sv->r2 = f->r[2];
	sv->r3 = f->r[3];
	sv->r9 = f->r[9]; /* FDPIC GOT of the interrupted code — clobbered below, restored at sigreturn */
	sv->r12 = f->r[12];
	sv->lr = f->r[14];
	sv->pc = f->r[15];
	sv->xpsr = f->xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	if (f->fp)
		sv->fp = *f->fp;
	else
		sv->fp.active = 0;
#endif
	sig_block_for_handler(sv, proc, sig); /* self-block the signal; restored at rt_sigreturn */
	sv->active = 1;
	uintptr_t entry, restorer;
	uint32_t got;
	resolve_handler(proc, sig, &entry, &got, &restorer);
	if (proc->is_fdpic)
		f->r[9] = got;			 /* FDPIC: r9 = the handler's own GOT */
	f->r[15] = entry & ~1u;			 /* pc -> handler entry (Thumb via xPSR.T) */
	f->r[0] = (uint32_t)sig;		 /* r0 = signo */
	f->r[14] = restorer | 1u;		 /* lr -> sa_restorer */
	f->xpsr |= (1u << 24);
}

/* rt_sigreturn: restore the context saved at delivery. */
void sig_restore(struct lxp_frame *f, lxp_proc_t *proc)
{
	struct sig_save_s *sv = &g_sig_save[slot_of(proc)];
	if (!sv->active)
		return;
	proc->sig_blocked = sv->saved_mask; /* undo the handler self-block (+ any handler-local mask) */
	f->r[0] = sv->r0;
	f->r[1] = sv->r1;
	f->r[2] = sv->r2;
	f->r[3] = sv->r3;
	f->r[9] = sv->r9; /* FDPIC GOT: the handler ran with its own r9; restore the interrupted code's */
	f->r[12] = sv->r12;
	f->r[14] = sv->lr;
	f->r[15] = sv->pc & ~1u;
	f->xpsr = sv->xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	if (f->fp)
		*f->fp = sv->fp;
#endif
	sv->active = 0;
}
