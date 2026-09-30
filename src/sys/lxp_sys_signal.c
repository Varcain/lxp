/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Signal syscalls: dispositions, the blocked mask, sigsuspend and the polling
 * sigtimedwait. Delivery itself is the coordinator's (src/lxp_signal.c).
 */
#include "sys/lxp_sys.h"
#include "lxp_guest.h"
#include "lxp_linux_uapi.h"
#include "signal/lxp_signal_policy.h"

long lxp_sys_rt_sigaction(lxp_proc_t *proc, const long a[6])
{
	/* Record the per-signal disposition; the engine seam delivers it.
	 * struct sigaction: sa_handler@0, sa_flags@4, sa_restorer@8. */
	int sig = (int)a[0];
	if (sig < 1 || sig >= LXP_NSIG)
		return -LXP_EINVAL;
	uintptr_t uact = (uintptr_t)a[1], uoact = (uintptr_t)a[2];
	/* Read the new action before writing the old one: the guest may pass one struct
	 * as both. */
	uint32_t act[3];
	if (uact && lxp_copy_from_guest(proc, act, uact, sizeof(act)) != 0)
		return -LXP_EFAULT;
	if (uoact && !lxp_guest_access_ok(proc, (void *)uoact, sizeof(act), 1))
		return -LXP_EFAULT;
	if (uoact &&
	    (lxp_guest_put_u32(proc, uoact, (uint32_t)lxp_sig_handler_get(proc, sig)) != 0 ||
	     lxp_guest_put_u32(proc, uoact + 8, (uint32_t)lxp_sig_restorer_get(proc)) != 0))
		return -LXP_EFAULT;
	if (uact) {
		proc->sighand->handler[sig] = act[0];
		proc->sighand->restorer = act[2];
	}
	return 0;
}

/* (how, set, oldset, sigsetsize) */
long lxp_sys_rt_sigprocmask(lxp_proc_t *proc, const long a[6])
{
	int how = (int)a[0];
	uintptr_t uset = (uintptr_t)a[1];
	uintptr_t uold = (uintptr_t)a[2];
	size_t sz = (size_t)a[3]; /* bytes of the guest sigset_t (8 for the 64-bit mask) */
	if (sz > 8)
		return -LXP_EINVAL;
	if (uset && !lxp_guest_access_ok(proc, (void *)uset, sz, 0))
		return -LXP_EFAULT;
	if (uold && !lxp_guest_access_ok(proc, (void *)uold, sz, 1))
		return -LXP_EFAULT;
	/* Read the new set BEFORE writing oldset — the guest may alias them, the legal
	 * sigprocmask(SIG_SETMASK, &m, &m) swap — and validate `how` up front so an invalid
	 * value has no side effects. */
	uint64_t nv = 0;
	if (uset) {
		if (how != LXP_SIG_BLOCK && how != LXP_SIG_UNBLOCK &&
		    how != LXP_SIG_SETMASK)
			return -LXP_EINVAL;
		uint32_t w[2] = {0, 0};
		if (lxp_copy_from_guest(proc, w, uset, sz) != 0)
			return -LXP_EFAULT;
		if (sz >= 4)
			nv |= (uint64_t)w[0];
		if (sz >= 8)
			nv |= (uint64_t)w[1] << 32;
	}
	uint64_t old = proc->sig_blocked;
	if (uold) { /* report the previous mask, low word then high, within sigsetsize */
		const uint32_t ow[2] = {(uint32_t)old, (uint32_t)(old >> 32)};
		size_t n = sz >= 8 ? 8u : sz >= 4 ? 4u : 0u;
		if (n && lxp_copy_to_guest(proc, uold, ow, n) != 0)
			return -LXP_EFAULT;
	}
	if (uset) {
		proc->sig_blocked = how == LXP_SIG_BLOCK     ? old | nv
				    : how == LXP_SIG_UNBLOCK ? old & ~nv
							     : nv; /* LXP_SIG_SETMASK */
		/* SIGKILL and SIGSTOP can never be blocked. */
		proc->sig_blocked &= ~(lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGSTOP));
	}
	return 0;
}

/* (unewset, sigsetsize) */
long lxp_sys_rt_sigsuspend(lxp_proc_t *proc, const long a[6])
{
	/* LinuxThreads suspend(): block until a signal (the restart) is delivered. If one is
	 * already pending (a restart that beat us here), fall through so the dispatch delivers
	 * it now; otherwise ask the run loop to park us — the coordinator runs the handler on
	 * the restart kill() and resumes us. sigsuspend always "returns" -EINTR.
	 *
	 * INSTALL the mask arg (POSIX: atomically set the signal mask for the wait): the whole
	 * point of the restart protocol is that the caller BLOCKS the restart signal normally and
	 * sigsuspend UNBLOCKS it only while waiting. If we ignore the mask, the restart stays
	 * blocked, pending_deliverable() skips it, and the parked thread is never
	 * woken (deadlock — curl's LinuxThreads resolver: manager, main, and a sigwait thread all
	 * stuck). The prior mask is restored when the delivered handler returns (sig_restore). */
	uintptr_t uset = (uintptr_t)a[0];
	size_t sz = (size_t)a[1];
	if (sz != 8)
		return -LXP_EINVAL; /* Linux: sigsetsize must equal sizeof(kernel sigset_t) */
	uint32_t w[2];
	if (!uset || lxp_copy_from_guest(proc, w, uset, sizeof(w)) != 0)
		return -LXP_EFAULT; /* the whole 8-byte mask, or nothing */
	uint64_t m = (uint64_t)w[0] | ((uint64_t)w[1] << 32);
	m &= ~(lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGSTOP)); /* never blockable */
	proc->sigsuspend_saved_mask = proc->sig_blocked;
	proc->sig_blocked = m;
	proc->sigsuspend_active = 1;
	/* Park unless a signal that is deliverable UNDER THE NEW MASK is already pending — then
	 * fall through so the dispatch delivers it now. A signal pending but blocked by the new
	 * mask must NOT keep us running (it stays pending until the mask is restored). */
	if (!pending_deliverable(proc)) {
		lxp_wait_t wait = {.kind = LXP_WAIT_SIGSUSPEND};
		if (lxp_wait_begin(proc, &wait) != 0)
			return -LXP_EAGAIN;
	}
	return -LXP_EINTR;
}

/* (set, info, timeout, sigsetsize) */
long lxp_sys_rt_sigtimedwait_time64(lxp_proc_t *proc, const long a[6])
{
	/* Poll variant: return a pending signal that is in `set` (dequeuing it), else report
	 * a timeout. Blocking for the timeout is not modeled — this is enough for libc/shell
	 * startup, which drains pending signals with sigtimedwait and must see -EAGAIN (not
	 * -ENOSYS) to finish and continue to the interactive read. */
	uintptr_t uset = (uintptr_t)a[0];
	size_t sz = (size_t)a[3];
	if (sz > 8)
		return -LXP_EINVAL;
	uint64_t set = 0;
	if (uset) {
		uint32_t w[2] = {0, 0};
		if (lxp_copy_from_guest(proc, w, uset, sz) != 0)
			return -LXP_EFAULT;
		if (sz >= 4)
			set |= (uint64_t)w[0];
		if (sz >= 8)
			set |= (uint64_t)w[1] << 32;
	}
	uint64_t ready = proc->pending_sigs & set;
	if (ready) {
		int sig = __builtin_ctzll(ready) + 1; /* lowest pending signal in the set */
		proc->pending_sigs &= ~lxp_sig_bit(sig);
		(void)a[1]; /* siginfo output omitted; the return value carries the signo */
		return sig;
	}
	return -LXP_EAGAIN;
}
