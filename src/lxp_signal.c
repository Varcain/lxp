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

#include "lxp_guest.h"
#include "proc/lxp_proc.h"
#include "lxp/lxp_seam.h"

/* ---- signal delivery (over the uniform frame) ------------------------------ */
/* Resolve a handler + restorer for delivery. FDPIC: sa_handler/sa_restorer are function DESCRIPTORS
 * {entry, GOT} — deref, since the handler may live in a different module (e.g. libpthread) than the
 * interrupted code and needs its own r9=GOT. Non-FDPIC (e.g. the posix host test): raw entries, no
 * GOT change. */
int resolve_handler(const lxp_proc_t *proc, int sig, uintptr_t *entry, uint32_t *got,
		    uintptr_t *restorer)
{
	uintptr_t h = lxp_sig_handler_get(proc, sig);
	uintptr_t r = lxp_sig_restorer_get(proc);
	if (proc->is_fdpic) {
		uint32_t descriptor[2];
		uint32_t restore_entry;
		if (lxp_copy_from_guest(proc, descriptor, h, sizeof(descriptor)) != 0 ||
		    lxp_guest_get_u32(proc, r, &restore_entry) != 0)
			return -LXP_EFAULT;
		*entry = descriptor[0];
		*got = descriptor[1];
		*restorer = restore_entry;
	} else {
		*entry = h;
		*got = 0;
		*restorer = r;
	}
	return 0;
}

/* Signals whose POSIX default action never terminates the process: SIGCHLD (ignore),
 * SIGCONT (consumed by the coordinator for a stopped process; a no-op while running),
 * SIGURG + SIGWINCH (ignore). A SIG_DFL of one of these must be SWALLOWED, not turned
 * into a 128+signo termination — else a shell's `fg`, which sends kill(-pgid, SIGCONT)
 * to resume a job, kills the very job (and every proc in range). */
int sig_default_ignore(int sig)
{
	return sig == LXP_SIGCHLD || sig == LXP_SIGCONT || sig == LXP_SIGURG || sig == LXP_SIGWINCH;
}

/* Is signal `sig` effectively ignored for `proc`? True for SIG_IGN, or SIG_DFL of a
 * signal whose default action is "ignore" (SIGCHLD/SIGCONT/SIGURG/SIGWINCH). Such a
 * signal is swallowed by the coordinator: it neither runs a handler nor terminates a
 * parked proc — a parent must not die because a child exited or a job was resumed. */
int sig_swallowed(const lxp_proc_t *proc, int sig)
{
	uintptr_t h = lxp_sig_handler_get(proc, sig);
	if (h == LXP_SIG_IGN)
		return 1;
	if (h == LXP_SIG_DFL && sig_default_ignore(sig))
		return 1;
	return 0;
}

/* The job-control stop signals: their default action suspends the process. */
int sig_is_stop(int sig)
{
	return sig == LXP_SIGSTOP || sig == LXP_SIGTSTP || sig == LXP_SIGTTIN || sig == LXP_SIGTTOU;
}

/* Would delivering `sig` to `proc` actually STOP it (rather than run a handler or be
 * ignored)? SIGSTOP always stops (it can be neither caught nor ignored); SIGTSTP/TTIN/
 * TTOU stop only at their default disposition — a caught one runs the handler, an
 * ignored one is dropped. */
int sig_stops_proc(const lxp_proc_t *proc, int sig)
{
	if (!sig_is_stop(sig))
		return 0;
	if (sig == LXP_SIGSTOP)
		return 1;
	return lxp_sig_handler_get(proc, sig) == LXP_SIG_DFL;
}

/* Publish one pending signal while preserving the ordering rule that a bitset
 * cannot represent by itself. Generating SIGCONT discards pending job-control
 * stops; generating a stop signal discards pending SIGCONT. All signal producers
 * use this owner so the last generated action wins. */
void lxp_signal_latch(lxp_proc_t *proc, int sig)
{
	if (!proc || sig <= 0 || sig >= LXP_NSIG)
		return;
	uint64_t pending = proc->pending_sigs;
	const uint64_t stop_mask = lxp_sig_bit(LXP_SIGSTOP) | lxp_sig_bit(LXP_SIGTSTP) |
				   lxp_sig_bit(LXP_SIGTTIN) | lxp_sig_bit(LXP_SIGTTOU);
	if (sig == LXP_SIGCONT)
		pending &= ~stop_mask;
	else if (sig_is_stop(sig))
		pending &= ~lxp_sig_bit(LXP_SIGCONT);
	proc->pending_sigs = pending | lxp_sig_bit(sig);
}

/* Reserve the next host-owned signal frame and install the handler mask. For a
 * signal that wakes rt_sigsuspend, the frame must restore the mask from before
 * the suspend, not the temporary wait mask. Consume that association here so a
 * signal nested inside the handler restores only its own entry mask. */
struct sig_save_s *sig_save_push(lxp_proc_t *proc, int sig)
{
	int slot = slot_of(proc);
	if (slot < 0 || slot >= LXP_NSLOT)
		return NULL;
	struct sig_save_stack_s *stack = &g_sig_save[slot];
	if (stack->depth >= LXP_SIGNAL_NEST_MAX)
		return NULL;

	struct sig_save_s *sv = &stack->frame[stack->depth++];
	if (proc->sigsuspend_active) {
		sv->saved_mask = proc->sigsuspend_saved_mask;
		proc->sigsuspend_active = 0;
	} else {
		sv->saved_mask = proc->sig_blocked;
	}
	/* POSIX blocks the delivered signal while its handler runs. Other
	 * unblocked signals remain eligible and therefore may occupy the next frame. */
	proc->sig_blocked |= lxp_sig_bit(sig);
	return sv;
}

void lxp_signal_terminate(lxp_proc_t *proc, int sig, uint8_t reason, uintptr_t address)
{
	(void)lxp_intent_exit(proc, 0);
	proc->exit_status = 128 + sig;
	proc->exit_reason = reason;
	proc->exit_signal = (uint8_t)sig;
	proc->exit_detail = 0;
	proc->exit_address = address;
}

/* Resolve one disposition before choosing the live-frame or parked-frame
 * delivery mechanism. This is the sole owner of ignore/default/handler-fault
 * semantics; callers retain only their different host-context transitions. */
enum lxp_signal_action lxp_signal_prepare(lxp_proc_t *proc, int sig,
					  struct lxp_signal_delivery *delivery)
{
	if (!proc || !delivery || sig < 1 || sig >= LXP_NSIG)
		return LXP_SIGNAL_INVALID;
	if (sig_stops_proc(proc, sig))
		return LXP_SIGNAL_STOP;
	if (sig_swallowed(proc, sig))
		return LXP_SIGNAL_IGNORE;

	uintptr_t handler = lxp_sig_handler_get(proc, sig);
	if (handler == LXP_SIG_DFL) {
		lxp_signal_terminate(proc, sig, LXP_EXIT_REASON_SIGNAL, 0);
		return LXP_SIGNAL_TERMINATE;
	}
	if (resolve_handler(proc, sig, &delivery->entry, &delivery->got, &delivery->restorer) !=
	    0) {
		lxp_signal_terminate(proc, LXP_SIGSEGV, LXP_EXIT_REASON_MEMORY_FAULT, handler);
		return LXP_SIGNAL_TERMINATE;
	}
	delivery->save = sig_save_push(proc, sig);
	if (!delivery->save) {
		lxp_signal_terminate(proc, LXP_SIGSEGV, LXP_EXIT_REASON_SIGNAL_DEPTH, 0);
		return LXP_SIGNAL_TERMINATE;
	}
	return LXP_SIGNAL_HANDLER;
}

/* Deliver signal `sig` to `proc`; `ret` is the interrupted syscall's result
 * (0 for a kill/tkill, -EINTR for a console-interrupted read). */
void deliver_signal(struct lxp_frame *f, lxp_proc_t *proc, int sig, long ret)
{
	if (!proc || sig < 1 || sig >= LXP_NSIG) {
		f->r[0] = (uint32_t)-LXP_EINVAL;
		return;
	}
	/* A handler automatically blocks its own signal unless userspace requested
	 * re-entry. The personality does not model SA_NODEFER, so a self-kill from
	 * inside that handler must remain pending rather than recursively deliver. */
	if (lxp_sig_blocked(proc, sig)) {
		lxp_signal_latch(proc, sig);
		f->r[0] = (uint32_t)ret;
		return;
	}
	struct lxp_signal_delivery delivery;
	enum lxp_signal_action action = lxp_signal_prepare(proc, sig, &delivery);
	/* Job-control stop taken by a running proc at a syscall boundary. Save the
	 * completed syscall result, redirect this frame to the persistent park entry,
	 * and publish a typed stop event; the coordinator owns the native suspend and
	 * later resumes this exact context on SIGCONT. */
	if (action == LXP_SIGNAL_STOP) {
		proc->stopped = 1;
		proc->stop_kind = LXP_STOP_READY;
		proc->stop_sig = (uint8_t)sig;
		proc->stop_r0 = ret;
		park_frame(f, proc);
		return;
	}
	if (action == LXP_SIGNAL_IGNORE) {
		f->r[0] = (uint32_t)
			ret; /* SIG_IGN, or a default-ignore signal (SIGCHLD/SIGCONT/...) */
		return;
	}
	if (action == LXP_SIGNAL_TERMINATE) {
		park_frame(f, proc); /* the coordinator reaps it */
		return;
	}
	if (action != LXP_SIGNAL_HANDLER) {
		f->r[0] = (uint32_t)-LXP_EINVAL;
		return;
	}
	struct sig_save_s *sv = delivery.save;
	sv->r0 = (uint32_t)ret;
	sv->r1 = f->r[1];
	sv->r2 = f->r[2];
	sv->r3 = f->r[3];
	sv->r9 =
		f->r[9]; /* FDPIC GOT of the interrupted code — clobbered below, restored at sigreturn */
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
	if (proc->is_fdpic)
		f->r[9] = delivery.got;	   /* FDPIC: r9 = the handler's own GOT */
	f->r[15] = delivery.entry & ~1u;   /* pc -> handler entry (Thumb via xPSR.T) */
	f->r[0] = (uint32_t)sig;	   /* r0 = signo */
	f->r[14] = delivery.restorer | 1u; /* lr -> sa_restorer */
	f->xpsr |= (1u << 24);
}

/* rt_sigreturn: restore the context saved at delivery. */
void sig_restore(struct lxp_frame *f, lxp_proc_t *proc)
{
	int slot = slot_of(proc);
	if (slot < 0 || slot >= LXP_NSLOT)
		return;
	struct sig_save_stack_s *stack = &g_sig_save[slot];
	if (stack->depth == 0)
		return;
	struct sig_save_s *sv = &stack->frame[stack->depth - 1u];
	proc->sig_blocked =
		sv->saved_mask; /* undo the handler self-block (+ any handler-local mask) */
	f->r[0] = sv->r0;
	f->r[1] = sv->r1;
	f->r[2] = sv->r2;
	f->r[3] = sv->r3;
	f->r[9] =
		sv->r9; /* FDPIC GOT: the handler ran with its own r9; restore the interrupted code's */
	f->r[12] = sv->r12;
	f->r[14] = sv->lr;
	f->r[15] = sv->pc & ~1u;
	f->xpsr = sv->xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	if (f->fp)
		*f->fp = sv->fp;
#endif
	stack->depth--;
}
