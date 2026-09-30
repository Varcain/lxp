/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The trap top half: what runs on a guest's svc. It answers the fast syscalls inline,
 * handles the calls that act across slots (kill, priorities, fork, futex, sigreturn),
 * and otherwise captures the guest's resume context and parks it for the coordinator.
 */
#include <string.h>

#include "lxp_internal.h"
#include "lxp_linux_uapi.h"
#include "lxp_provider.h"
#include "lxp_run_internal.h"
#include "lxp_syscall.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_runtime_store.h"
#include "signal/lxp_signal_policy.h"

/* Capture the post-svc context of frame f into slot s's resume ctx. */
static void capture_ctx(int s, const struct lxp_frame *f)
{
	for (int i = 0; i < 8; i++)
		g_lxp_rt.slots[s].resume.r4_11[i] = f->r[4 + i];
	g_lxp_rt.slots[s].resume.r12 = f->r[12];
	g_lxp_rt.slots[s].resume.lr = f->r[14];
	g_lxp_rt.slots[s].resume.sp = f->r[13];	  /* the seam set r[13] = the pre-svc SP */
	g_lxp_rt.slots[s].resume.pc = f->r[15] | 1u; /* resume after the svc (Thumb) */
	/* Preserve r1-r3 across the parking syscall (Linux preserves r1-r14; only r0 is
	 * the return, supplied by the resume). A guest may reuse an arg register after a
	 * syscall — so leaving these garbage on resume corrupts it (e.g. wait4's options). */
	g_lxp_rt.slots[s].resume.r1 = f->r[1];
	g_lxp_rt.slots[s].resume.r2 = f->r[2];
	g_lxp_rt.slots[s].resume.r3 = f->r[3];
	g_lxp_rt.slots[s].resume.xpsr = f->xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	if (f->fp)
		g_lxp_rt.slots[s].resume.fp = *f->fp;
	else
		memset(&g_lxp_rt.slots[s].resume.fp, 0, sizeof(g_lxp_rt.slots[s].resume.fp));
#endif
}

/* Snapshot a normal syscall and park its guest. A second request for the same
 * slot is impossible while the first task is parked, but the CAS makes that
 * invariant fail closed instead of overwriting an in-flight mailbox. */
static void defer_syscall(struct lxp_frame *f, lxp_proc_t *proc)
{
	int slot = slot_of(proc);
	uint8_t expected = DEFER_IDLE;
	if (slot < 0 || slot >= LXP_NSLOT ||
	    !__atomic_compare_exchange_n(&g_lxp_rt.slots[slot].deferred.state, &expected,
					 DEFER_FILLING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		f->r[0] = (uint32_t)-LXP_EAGAIN;
		return;
	}
	if (lxp_intent_begin(proc, &(lxp_intent_t){
					   .kind = LXP_INTENT_DEFERRED_SYSCALL,
				   }) != 0) {
		deferred_state_store(slot, DEFER_IDLE);
		f->r[0] = (uint32_t)-LXP_EAGAIN;
		return;
	}
	g_lxp_rt.slots[slot].deferred.a0 = f->r[0];
	g_lxp_rt.slots[slot].deferred.owner = (lxp_slot_ref_t){
		.index = (int16_t)slot,
		.generation = slot_generation(slot),
	};
#if LXP_ENABLE_LATENCY
	{ /* the only timer call on the svc top half, and only when instrumented */
		uint64_t t = 0;
		lxp_time_ns(&t);
		g_lxp_rt.slots[slot].deferred.pub_ns = t;
	}
#endif
	deferred_state_store(slot, DEFER_READY);
	park_frame(f, proc);
}

/* Park the program frame until the coordinator reaps the event, and wake the
 * coordinator (it blocks in event_wait rather than busy-polling). Persistent
 * ports prepare a guest-readable resume token while the original svc frame is
 * still live; ports with a native saved-frame restore return NULL. */
void park_frame(struct lxp_frame *f, lxp_proc_t *proc)
{
	int slot = slot_of(proc);
	capture_ctx(slot, f);
	void *token = lxp_lifecycle_prepare_park(slot, &g_lxp_rt.slots[slot].resume);
	f->r[0] = (uint32_t)(uintptr_t)token;
	f->r[15] = (uint32_t)((uintptr_t)g_lxp_os_ops->park_entry & ~(uintptr_t)1u);
	f->xpsr |= (1u << 24);
	lxp_event_post_slot(slot);
}

/* halt, poweroff and reboot ask init (pid 1) to shut down with SIGUSR1, SIGUSR2 and
 * SIGTERM respectively. */
static int init_shutdown_signal(int sig)
{
	return sig == LXP_SIGUSR1 || sig == LXP_SIGUSR2 || sig == LXP_SIGTERM;
}

void lxp_trap_dispatch(struct lxp_frame *f, lxp_proc_t *proc)
{
	long nr = (long)(int32_t)f->r[7];
	if (nr == LXP_NR_getpriority || nr == LXP_NR_setpriority) {
		enum { PRIO_PROCESS = 0, PRIO_PGRP = 1, PRIO_USER = 2 };
		int which = (int)f->r[0];
		int who = (int)f->r[1];
		int caller_pgid = proc->group ? proc->group->pgid : proc->pid;
		int found = 0;
		int best = 19;
		int requested = (int)f->r[2];
		if (which < PRIO_PROCESS || which > PRIO_USER || who < 0) {
			f->r[0] = -LXP_EINVAL;
			return;
		}
		if (requested < -20)
			requested = -20;
		else if (requested > 19)
			requested = 19;
		for (int s = 0; s < LXP_NSLOT; s++) {
			lxp_proc_t *target = &g_lxp_rt.slots[s].proc;
			if (!target->alive)
				continue;
			int match =
				(which == PRIO_PROCESS)
					? (who == 0 ? target == proc : target->pid == who)
				: (which == PRIO_PGRP)
					? (target->group &&
					   target->group->pgid == (who == 0 ? caller_pgid : who))
					: (who == 0); /* every guest has uid 0 */
			if (!match)
				continue;
			found = 1;
			if (nr == LXP_NR_setpriority)
				lxp_proc_nice_set(target, requested);
			else {
				int nice = lxp_proc_nice_get(target);
				if (nice < best)
					best = nice;
			}
		}
		if (!found) {
			f->r[0] = -LXP_ESRCH;
			return;
		}
		/* The raw syscall returns 40..1; libc translates that to nice -20..19. */
		f->r[0] = nr == LXP_NR_getpriority ? (uint32_t)(20 - best) : 0u;
		return;
	}
	if (nr == LXP_NR_kill || nr == LXP_NR_tkill || nr == LXP_NR_tgkill) {
		int sig = (nr == LXP_NR_tgkill) ? (int)f->r[2] : (int)f->r[1];
		int target = (int)f->r[0];
		/* Process-group target for a kill(pid<=0): pid==0 = the caller's group,
		 * pid<-1 = group |pid|. */
		int want_pgid = (target == 0) ? proc->group->pgid : (target < -1 ? -target : 0);
		if (sig < 0 ||
		    sig >= LXP_NSIG) { /* sig indexes sig_handler[]/pending_sig — reject OOB */
			f->r[0] = -LXP_EINVAL;
			return;
		}
		/* init is parked and can't receive its shutdown signal, so honor one sent to
		 * pid 1 directly as a system halt. */
		if (nr == LXP_NR_kill && target == 1 && init_shutdown_signal(sig)) {
			lxp_request_halt();
			f->r[0] = 0; /* kill() succeeds; the run loop stops next iteration */
			return;
		}
		/* Self-signal (tkill/tgkill, or kill to own pid) is delivered inline. */
		if (nr != LXP_NR_kill || target == proc->pid) {
			deliver_signal(f, proc, sig, 0);
			return;
		}
		/* Latch a cross-process signal on the target proc(s); it is
		 * delivered at the target's next syscall boundary (running) or by the coordinator
		 * (parked in sleep/wait/pipe). Real Linux targeting: pid>0 = that process; pid==0 =
		 * the caller's process group; pid<-1 = process group |pid|; pid==-1 = broadcast to
		 * all (but init). Skips the sender + init; an explicit self-signal took the inline
		 * path above. */
		int recipients = lxp_signal_send(proc, target > 0 ? target : 0, want_pgid, sig);
		f->r[0] = recipients ? 0 : -LXP_ESRCH;
		return;
	}
	if (nr == LXP_NR_rt_sigreturn || nr == LXP_NR_sigreturn) {
		sig_restore(f, proc);
		return;
	}
	/* fork/vfork/clone: capture the parent's resume context and ask the coordinator
	 * to spawn a child. The parent's host task stays parked through the vfork window
	 * (NOMMU shares the image) until the child execs into its own region or exits. */
	if (nr == LXP_NR_vfork || nr == LXP_NR_fork || nr == LXP_NR_clone) {
		/* CLONE_VM shares the address space for life and therefore co-runs on
		 * the supplied child stack. CLONE_THREAD additionally joins the
		 * caller's thread group; legacy LinuxThreads-style CLONE_VM children
		 * remain distinct, waitable processes. */
		uint32_t clone_flags = nr == LXP_NR_clone ? (uint32_t)f->r[0] : 0;
		if (((clone_flags & LXP_CLONE_SIGHAND) && !(clone_flags & LXP_CLONE_VM)) ||
		    ((clone_flags & LXP_CLONE_THREAD) &&
		     (clone_flags & (LXP_CLONE_VM | LXP_CLONE_SIGHAND)) !=
			     (LXP_CLONE_VM | LXP_CLONE_SIGHAND))) {
			f->r[0] = -LXP_EINVAL;
			return;
		}
		lxp_intent_t intent = {
			.kind = LXP_INTENT_FORK,
			.data.fork.flags = clone_flags,
			.data.fork.child_stack = (clone_flags & LXP_CLONE_VM) ? f->r[1] : 0,
		};
		if (lxp_intent_begin(proc, &intent) != 0) {
			f->r[0] = -LXP_EAGAIN;
			return;
		}
		park_frame(f, proc);
		return;
	}
	/* futex: a co-running thread's WAIT parks here / WAKE resumes peers (needs the proc
	 * table + event_post, so it is coordinator-handled, not a plain dispatch case). */
	if (nr == LXP_NR_futex || nr == LXP_NR_futex_time64) {
		lxp_futex(f, proc, nr == LXP_NR_futex_time64);
		return;
	}
	if (!(lxp_syscall_flags(nr) & LXP_SYS_FAST)) {
		defer_syscall(f, proc);
		return;
	}

	long r = lxp_syscall(proc, nr, (int32_t)f->r[0], (int32_t)f->r[1], (int32_t)f->r[2],
			     (int32_t)f->r[3], (int32_t)f->r[4], (int32_t)f->r[5]);
	coordinator_report_enosys(nr, r);
	/* A blocking syscall published a typed wait; capture the
	 * post-svc context (resume the SAME image after the svc) and park. The
	 * coordinator delays/wakes and resumes it through the explicit parked-resume
	 * port action. */
	if (proc->wait.kind != LXP_WAIT_NONE) {
		park_frame(f, proc);
		return;
	}
	if (proc->intent.kind != LXP_INTENT_NONE) {
		park_frame(f, proc);
		return;
	}
	/* Another proc's kill() latched a signal on us; deliver it at this syscall
	 * boundary (Linux at-the-boundary async delivery) unless the
	 * proc has blocked it (rt_sigprocmask) — a blocked signal stays latched and is delivered
	 * at a later boundary once unblocked. */
	int psig = pending_take(proc);
	if (psig) {
		deliver_signal(f, proc, psig, r);
		return;
	}
	f->r[0] = (uint32_t)r;
}

int lxp_dispatch_slot(lxp_slot_ref_t ref, struct lxp_frame *frame)
{
	if (!frame || !lxp_slot_ref_is_runnable(ref))
		return -LXP_ESRCH;
	lxp_guest_view_t view;
	int rc = lxp_guest_view_begin(&g_lxp_rt.slots[ref.index].proc, ref,
				      &g_lxp_rt.slots[ref.index].generation, LXP_GUEST_READ_WRITE,
				      &view);
	if (rc != LXP_OK)
		return rc;
	lxp_trap_dispatch(frame, &g_lxp_rt.slots[ref.index].proc);
	lxp_guest_view_end(&view);
	return LXP_OK;
}
