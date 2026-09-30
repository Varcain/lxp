/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Where a signal goes: latching it on the processes a kill(2) or a terminal names, and
 * delivering one to a process parked in the coordinator (the LinuxThreads restart).
 */
#include "lxp_internal.h"
#include "lxp_run_internal.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_runtime_store.h"

int lxp_signal_send(const lxp_proc_t *skip, int pid, int pgid, int sig)
{
	int recipients = 0;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
		if (!p->alive || p == skip || p->pid <= 1)
			continue;
		if (pid > 0 ? p->pid != pid : pgid > 0 && (!p->group || p->group->pgid != pgid))
			continue;
		lxp_signal_latch(p, sig);
		recipients++;
	}
	/* Wake the coordinator now so it delivers the signal at once (the LinuxThreads
	 * restart) instead of at its next poll: otherwise every thread wakeup costs up to one
	 * event_wait timeout. */
	if (recipients && g_lxp_os_ops && g_lxp_os_ops->event_post)
		g_lxp_os_ops->event_post();
	return recipients;
}

int lxp_signal_process_group(int pgid, int sig)
{
	if (pgid <= 0 || sig <= 0 || sig >= LXP_NSIG)
		return 0;
	return lxp_signal_send(NULL, 0, pgid, sig);
}

/* Deliver `sig` to a proc PARKED in rt_sigsuspend (the LinuxThreads restart). There is no live
 * frame — the interrupted context is the slot's captured resume context. Save that as the
 * slot's sigreturn frame (to resume with `ret` = -EINTR), then resume the proc INTO its
 * handler; the handler's sa_restorer -> rt_sigreturn restores the saved frame and the syscall
 * returns -EINTR. SIG_IGN just resumes with `ret`; SIG_DFL terminates (the LXP_EV_EXIT pass
 * reaps it). */
void deliver_signal_parked(int slot, lxp_proc_t *proc, int sig, long ret)
{
	struct lxp_signal_delivery delivery;
	enum lxp_signal_action action = lxp_signal_prepare(proc, sig, &delivery);
	if (action == LXP_SIGNAL_IGNORE) {
		(void)coordinator_complete_slot(
			slot_ref_at(slot),
			ret); /* IGN or default-ignore (SIGCHLD/SIGCONT/...) */
		return;
	}
	/* A deferred completion is itself a signal-delivery boundary and the native
	 * task is already parked. Retain its result and let SIGCONT resume it. */
	if (action == LXP_SIGNAL_STOP) {
		proc->stopped = 1;
		proc->stop_kind = LXP_STOP_PARKED;
		proc->stop_sig = (uint8_t)sig;
		proc->stop_r0 = 0;
		(void)coordinator_complete_slot(slot_ref_at(slot), ret);
		notify_parent_stopped(proc->group->ppid, proc->pid, sig);
		return;
	}
	if (action == LXP_SIGNAL_TERMINATE) {
		primary_slot_mark(slot);
		return;
	}
	if (action != LXP_SIGNAL_HANDLER)
		return;
	struct lxp_resume_ctx *resume = &g_lxp_rt.slots[slot].resume;
	struct sig_save_s *sv = delivery.save;
	sv->r0 = (uint32_t)ret;
	sv->r1 = resume->r1;
	sv->r2 = resume->r2;
	sv->r3 = resume->r3;
	sv->r9 = resume->r4_11[5]; /* the parked code's FDPIC GOT; overwritten below (r9) */
	sv->r12 = resume->r12;
	sv->lr = resume->lr;
	sv->pc = resume->pc;		      /* the rt_sigsuspend resume point */
	sv->xpsr = resume->xpsr | (1u << 24); /* preserve APSR flags + Thumb */
#if LXP_ENABLE_FPU_CONTEXT
	sv->fp = resume->fp;
#endif
	/* Reuse the slot ctx as the handler-entry frame; sp + r4-r11 stay = the thread's, except r9
	 * (the handler's own GOT for FDPIC — resolve_handler derefs the {entry,GOT} funcdescs; the
	 * restart handler lives in libpthread, a different module than the interrupted libc). */
	if (proc->is_fdpic)
		resume->r4_11[5] = delivery.got;      /* r9 = handler's GOT */
	resume->lr = delivery.restorer | 1u;	      /* return -> sa_restorer entry -> sigreturn */
	resume->pc = delivery.entry | 1u;	      /* enter the handler (Thumb) */
	coordinator_resume_slot(slot, proc->mm->region.index, resume, sig); /* r0 = signo */
}
