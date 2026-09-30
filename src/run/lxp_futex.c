/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * futex(2) for co-running CLONE_VM threads: waits park in the coordinator and wakes mark
 * the matching waiters for it to resume.
 */
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_provider.h"
#include "lxp_run_internal.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_runtime_store.h"

/* Another live thread shares this proc's address space (a co-running CLONE_VM thread or its
 * creator) — the only case where a parked FUTEX_WAIT could ever be woken. Without one, the
 * wait would deadlock, so the futex handler returns -EAGAIN instead of parking. */
int lxp_futex_has_corunner(const lxp_proc_t *proc)
{
	if (!proc || !proc->mm)
		return 0;
	/* A suspended vfork parent shares our region but is frozen until we exec/exit, so it can
	 * never FUTEX_WAKE us — exclude it (proc->vfork_parent.index), or a vfork child's libc
	 * futex would park forever instead of failing with -EAGAIN and making progress. */
	int vp = proc->vfork_parent.index;
	for (int s = 0; s < LXP_NSLOT; s++) {
		const lxp_proc_t *q = &g_lxp_rt.slots[s].proc;
		if (q != proc && q->alive && q->mm == proc->mm && s != vp)
			return 1;
	}
	return 0;
}

/* futex(2): a uaddr-keyed wait/wake over the shared region of co-running threads. FUTEX_WAIT
 * parks the caller when *uaddr still equals the expected value AND a co-runner exists to wake
 * it (else -EAGAIN); FUTEX_WAKE marks up to `val` matching waiters and asks the coordinator to
 * resume them (with 0). Other ops are accepted inert. Intercepted here (not in the dispatch
 * switch) because the wake path needs the coordinator's proc table + event_post. */
void lxp_futex(struct lxp_frame *f, lxp_proc_t *proc, int is_time64)
{
	uintptr_t uaddr = (uintptr_t)f->r[0];
	int op = (int)f->r[1] & 0x7f; /* mask FUTEX_PRIVATE_FLAG / FUTEX_CLOCK_REALTIME */
	uint32_t val = (uint32_t)f->r[2];

	if (op == 0 || op == 9) { /* FUTEX_WAIT / FUTEX_WAIT_BITSET */
		uint32_t observed;
		if (lxp_guest_get_u32(proc, uaddr, &observed) != 0) {
			f->r[0] = (uint32_t)-LXP_EFAULT;
			return;
		}
		if (observed != val) {
			f->r[0] = (uint32_t)-LXP_EAGAIN; /* value already moved: do not sleep */
			return;
		}
		if (!lxp_futex_has_corunner(proc)) {
			/* single-threaded: retry the userspace lock */
			f->r[0] = (uint32_t)-LXP_EAGAIN;
			return;
		}
		/* Optional timeout (arg4): FUTEX_WAIT is relative, FUTEX_WAIT_BITSET absolute
		 * (against our monotonic clock; a CLOCK_REALTIME absolute is approximated).
		 * Without it the wait is infinite. The coordinator resumes with -ETIMEDOUT once
		 * the deadline passes. */
		uint64_t deadline = 0;
		uintptr_t utimeout = (uintptr_t)f->r[3];
		if (utimeout) {
			uint64_t sec, nsec;
			if (is_time64) {
				int64_t t[2];
				if (lxp_copy_from_guest(proc, t, utimeout, sizeof(t)) != 0) {
					f->r[0] = (uint32_t)-LXP_EFAULT;
					return;
				}
				sec = (uint64_t)t[0];
				nsec = (uint64_t)t[1];
			} else {
				int32_t t[2];
				if (lxp_copy_from_guest(proc, t, utimeout, sizeof(t)) != 0) {
					f->r[0] = (uint32_t)-LXP_EFAULT;
					return;
				}
				sec = (uint64_t)(uint32_t)t[0];
				nsec = (uint64_t)(uint32_t)t[1];
			}
			uint64_t ts_us = sec * 1000000ull + nsec / 1000ull, now = 0;
			lxp_time_us(&now);
			deadline = (op == 0) ? now + ts_us : ts_us;
			if (!deadline)
				deadline = 1; /* 0 encodes "no timeout"; keep a nonzero deadline */
		}
		lxp_wait_t wait = {
			.kind = LXP_WAIT_FUTEX,
			.data.futex.uaddr = uaddr,
			.data.futex.deadline_us = deadline,
		};
		if (lxp_wait_begin(proc, &wait) != 0) {
			f->r[0] = (uint32_t)-LXP_EAGAIN;
			return;
		}
		/* the coordinator parks us; FUTEX_WAKE / timeout resumes us */
		lxp_park_frame(f, proc);
		return;
	}
	if (op == 1 || op == 10) { /* FUTEX_WAKE / FUTEX_WAKE_BITSET */
		uint32_t woken = 0;
		for (int s = 0; s < LXP_NSLOT && woken < val; s++) {
			lxp_proc_t *q = &g_lxp_rt.slots[s].proc;
			/* !woken: a waiter already marked by an earlier WAKE (not yet resumed by
			 * the coordinator) must not be woken — or counted — twice. */
			if (q->alive && q->wait.kind == LXP_WAIT_FUTEX &&
			    !q->wait.data.futex.woken && q->wait.data.futex.uaddr == uaddr) {
				q->wait.data.futex.woken = 1;
				woken++;
			}
		}
		if (woken && g_lxp_os_ops && g_lxp_os_ops->core.event_post)
			g_lxp_os_ops->core.event_post();
		f->r[0] = woken;
		return;
	}
	f->r[0] = 0; /* REQUEUE / WAKE_OP / etc.: accepted, no queued waiter affected */
}
