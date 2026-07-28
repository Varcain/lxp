/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private blocked-operation retry, timeout, and signal module.
 */

#include "run/lxp_coordinator.h"
#include "lxp_internal.h"
#include "lxp_run_internal.h"
#if LXP_ENABLE_DEV
#include "lxp/lxp_dev.h"
#endif
#if LXP_ENABLE_NET
#include "lxp/lxp_net.h"
#endif
#if LXP_ENABLE_NETFS
#include "lxp/lxp_netfs.h"
#endif
#if LXP_ENABLE_PTY
#include "lxp/lxp_pty.h"
#endif

static uint32_t lxp_blocked_wait_policy(lxp_wait_kind_t kind)
{
	switch (kind) {
	case LXP_WAIT_PIPE:
	case LXP_WAIT_DEVICE:
	case LXP_WAIT_NETFS:
	case LXP_WAIT_PTY:
	case LXP_WAIT_FUTEX:
		return LXP_BLOCKED_WAIT_POLL;
	case LXP_WAIT_CONSOLE:
		return LXP_BLOCKED_WAIT_POLL | LXP_BLOCKED_WAIT_CONSOLE;
	case LXP_WAIT_SOCKET:
		return LXP_BLOCKED_WAIT_SOCKET;
	case LXP_WAIT_NONE:
	case LXP_WAIT_TIMER:
	case LXP_WAIT_CHILD:
	case LXP_WAIT_SIGSUSPEND:
	case LXP_WAIT_COUNT:
	default:
		return 0;
	}
}

static void lxp_blocked_note_deadline(struct lxp_blocked_scan *scan, uint64_t deadline)
{
	if (deadline && deadline < scan->next_deadline_us)
		scan->next_deadline_us = deadline;
}

static int lxp_blocked_handle_stopped(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				      struct lxp_blocked_scan *scan)
{
	if (!proc->stopped)
		return 0;
	scan->any_busy = 1;
	if (proc->pending_sigs & lxp_sig_bit(LXP_SIGCONT)) {
		proc->pending_sigs &= ~lxp_sig_bit(LXP_SIGCONT);
		int boundary = proc->stop_kind == LXP_STOP_BOUNDARY;
		proc->stopped = 0;
		proc->stop_kind = LXP_STOP_NONE;
		if (boundary)
			(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
						      lxp_slot_resume_view(slot_ref_at(slot)), proc->stop_r0);
		scan->progress = 1;
		return 1;
	}

	int sig = pending_deliverable(proc);
	if (sig == LXP_SIGKILL || (sig && lxp_sig_handler_get(proc, sig) == LXP_SIG_DFL &&
				   !sig_default_ignore(sig) && !sig_is_stop(sig))) {
		proc->pending_sigs &= ~lxp_sig_bit(sig);
		proc->stopped = 0;
		proc->stop_kind = LXP_STOP_NONE;
		(void)lxp_intent_exit(proc, 0);
		proc->exit_status = 128 + sig;
		proc->exit_reason = LXP_EXIT_REASON_SIGNAL;
		proc->exit_signal = (uint8_t)sig;
		primary_slot_mark(slot);
		scan->progress = 1;
	}
	return 1;
}

static int lxp_blocked_handle_signal(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				     struct lxp_blocked_scan *scan)
{
	int sig = !slot_runnable_load(slot) ? pending_deliverable(proc) : 0;
	if (sig && sig_stops_proc(proc, sig)) {
		proc->pending_sigs &= ~lxp_sig_bit(sig);
		proc->stopped = 1;
		proc->stop_kind = LXP_STOP_PARKED;
		proc->stop_sig = (uint8_t)sig;
		notify_parent_stopped(eng, proc->group->ppid, proc->pid, sig);
		scan->progress = 1;
		return 1;
	}
	if (sig && proc->wait.kind != LXP_WAIT_NONE) {
		proc->pending_sigs &= ~lxp_sig_bit(sig);
		if (!sig_swallowed(proc, sig)) {
			lxp_wait_kind_t kind = proc->wait.kind;
#if LXP_ENABLE_NETFS
			if (kind == LXP_WAIT_NETFS)
				lxp_netfs_cancel(proc);
#endif
			(void)lxp_wait_interrupt(proc, kind);
			deliver_signal_parked(eng, slot, proc, sig, -LXP_EINTR);
			scan->progress = 1;
		}
	}
	return 0;
}

static void lxp_blocked_retry_timer(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				    uint64_t now, struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_TIMER || slot_runnable_load(slot))
		return;
	scan->any_busy = 1;
	uint64_t deadline = proc->wait.data.timer.deadline_us;
	if (now >= deadline) {
		(void)lxp_wait_timeout(proc, LXP_WAIT_TIMER);
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), 0);
		scan->progress = 1;
	} else {
		lxp_blocked_note_deadline(scan, deadline);
	}
}

static void lxp_blocked_retry_futex(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				    uint64_t now, struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_FUTEX || slot_runnable_load(slot))
		return;
	scan->any_busy = 1;
	uint64_t deadline = proc->wait.data.futex.deadline_us;
	if (proc->wait.data.futex.woken) {
		(void)lxp_wait_complete(proc, LXP_WAIT_FUTEX);
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), 0);
		scan->progress = 1;
	} else if (deadline && now >= deadline) {
		(void)lxp_wait_timeout(proc, LXP_WAIT_FUTEX);
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), -LXP_ETIMEDOUT);
		scan->progress = 1;
	} else {
		lxp_blocked_note_deadline(scan, deadline);
	}
}

static void lxp_blocked_retry_pipe(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				   struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_PIPE || slot_runnable_load(slot))
		return;
	long rc = lxp_pipe_retry(proc);
	if (rc == -LXP_EAGAIN)
		return;
	(void)lxp_wait_complete(proc, LXP_WAIT_PIPE);
	if (rc == -LXP_EPIPE && lxp_sig_handler_get(proc, LXP_SIGPIPE) != LXP_SIG_IGN) {
		(void)lxp_intent_exit(proc, 0);
		proc->exit_status = 128 + LXP_SIGPIPE;
		proc->exit_reason = LXP_EXIT_REASON_SIGNAL;
		proc->exit_signal = LXP_SIGPIPE;
		primary_slot_mark(slot);
	} else {
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), rc);
	}
	scan->progress = 1;
}

#if LXP_ENABLE_DEV
static void lxp_blocked_retry_device(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				     struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_DEVICE || slot_runnable_load(slot))
		return;
	if (proc->wait.op == LXP_DEVW_MMAP) {
		uintptr_t buffer = proc->wait.data.io.buffer;
		size_t length = proc->wait.data.io.length;
		unsigned attrs = (unsigned)proc->wait.data.io.command;
		int map = device_map_index(proc, buffer, length);
		long rc = map;
		if (map >= 0) {
			int mapped = coordinator_map_mm_range(eng, proc->mm, buffer, length, attrs);
			rc = mapped == 0 ? (long)buffer : mapped;
		}
		if (rc >= 0) {
			proc->mm->dev_map_lo[map] = buffer;
			proc->mm->dev_map_hi[map] = buffer + length;
			proc->mm->dev_map_attrs[map] = attrs;
			if (++proc->mm->device_generation == 0)
				proc->mm->device_generation = 1u;
		}
		(void)lxp_wait_complete(proc, LXP_WAIT_DEVICE);
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), rc);
		scan->progress = 1;
		return;
	}
	long rc = lxp_dev_retry(proc);
	if (rc != -LXP_EAGAIN) {
		(void)lxp_wait_complete(proc, LXP_WAIT_DEVICE);
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), rc);
		scan->progress = 1;
	}
}
#endif

#if LXP_ENABLE_NET
static void lxp_blocked_retry_socket(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				     struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_SOCKET || slot_runnable_load(slot))
		return;
	long rc = lxp_sock_retry(proc);
	if (rc != -LXP_EAGAIN) {
		(void)lxp_wait_complete(proc, LXP_WAIT_SOCKET);
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), rc);
		scan->progress = 1;
	}
}
#endif

#if LXP_ENABLE_NETFS
void lxp_blocked_complete_netfs_retry(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				      long rc, struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind == LXP_WAIT_NETFS)
		(void)lxp_wait_complete(proc, LXP_WAIT_NETFS);
	if (proc->intent.kind == LXP_INTENT_EXEC) {
		/*
		 * Unlike a normal execve, a remote exec publishes its intent from
		 * the coordinator after the 9P fetch completes. There is no
		 * returning SVC path to mark the slot, so expose the new primary
		 * event here.
		 */
		primary_slot_mark(slot);
	} else {
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), rc);
	}
	scan->progress = 1;
}

static void lxp_blocked_retry_netfs(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				    struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_NETFS || slot_runnable_load(slot))
		return;
	long rc = lxp_netfs_retry(proc);
	if (rc == -LXP_EAGAIN)
		return;
	lxp_blocked_complete_netfs_retry(eng, slot, proc, rc, scan);
}
#endif

#if LXP_ENABLE_PTY
static void lxp_blocked_retry_pty(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				  struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_PTY || slot_runnable_load(slot))
		return;
	long rc = lxp_pty_retry(proc);
	if (rc != -LXP_EAGAIN) {
		(void)lxp_wait_complete(proc, LXP_WAIT_PTY);
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      lxp_slot_resume_view(slot_ref_at(slot)), rc);
		scan->progress = 1;
	}
}
#endif

/* Returns nonzero when ^Z kept this slot in its console wait and the caller
 * must skip the rest of this slot's retry policy. */
static int lxp_blocked_retry_console(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				     struct lxp_blocked_scan *scan)
{
	if (proc->wait.kind != LXP_WAIT_CONSOLE || slot_runnable_load(slot) ||
	    !proc->console_poll || !proc->console_poll(proc->io_ctx))
		return 0;

	uintptr_t buffer = proc->wait.data.io.buffer;
	size_t length = proc->wait.data.io.length;
	long rc = proc->read_fn ? proc->read_fn(proc->io_ctx, 0, (void *)buffer, length) : 0;
	uint8_t ch = rc == 1 ? ((const volatile uint8_t *)(uintptr_t)buffer)[0] : 0;
	if (rc == 1) {
		ch = lxp_console_input_xlate(ch);
		((volatile uint8_t *)(uintptr_t)buffer)[0] = ch;
	}
	if (rc == 1 && lxp_tty_isig() && ch == 26) {
		console_signal_fg(LXP_SIGTSTP);
		scan->progress = 1;
		return 1;
	}
	if (rc == 1 && lxp_tty_isig() && ch == 3) {
		console_signal_fg(LXP_SIGINT);
		rc = -LXP_EINTR;
	}
	(void)lxp_wait_complete(proc, LXP_WAIT_CONSOLE);
	(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
				      lxp_slot_resume_view(slot_ref_at(slot)), rc);
	scan->progress = 1;
	return 0;
}

struct lxp_blocked_scan lxp_scan_blocked(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg,
					 uint64_t now)
{
	struct lxp_blocked_scan scan = {
		.next_deadline_us = UINT64_MAX,
	};

	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		lxp_proc_t *proc = lxp_slot_proc(slot);
		if (!proc->alive)
			continue;
		scan.any_alive = 1;
		lxp_guest_view_t view;
		int view_active = 0;
		if (!slot_runnable_load(slot)) {
			int rc = coordinator_guest_view_begin(slot, &view);
			if (rc != LXP_OK) {
				guest_view_failure(slot, rc);
				scan.progress = 1;
				continue;
			}
			view_active = 1;
		}
		if (lxp_blocked_handle_stopped(eng, slot, proc, &scan)) {
			if (view_active)
				lxp_guest_view_end(&view);
			continue;
		}
		if (slot_runnable_load(slot))
			scan.any_busy = 1;
		scan.wait_policy |= lxp_blocked_wait_policy(proc->wait.kind);

		if (proc->alarm_deadline_us && !slot_runnable_load(slot)) {
			if (now >= proc->alarm_deadline_us) {
				proc->pending_sigs |= lxp_sig_bit(LXP_SIGALRM);
				proc->alarm_deadline_us =
					proc->alarm_interval_us ? now + proc->alarm_interval_us : 0;
			}
			lxp_blocked_note_deadline(&scan, proc->alarm_deadline_us);
		}
		if (lxp_blocked_handle_signal(eng, slot, proc, &scan)) {
			if (view_active)
				lxp_guest_view_end(&view);
			continue;
		}
		lxp_blocked_retry_timer(eng, slot, proc, now, &scan);
		lxp_blocked_retry_futex(eng, slot, proc, now, &scan);
		lxp_blocked_retry_pipe(eng, slot, proc, &scan);
#if LXP_ENABLE_DEV
		lxp_blocked_retry_device(eng, slot, proc, &scan);
#endif
#if LXP_ENABLE_NET
		lxp_blocked_retry_socket(eng, slot, proc, &scan);
#endif
#if LXP_ENABLE_NETFS
		lxp_blocked_retry_netfs(eng, slot, proc, &scan);
#endif
#if LXP_ENABLE_PTY
		lxp_blocked_retry_pty(eng, slot, proc, &scan);
#endif
		(void)lxp_blocked_retry_console(eng, slot, proc, &scan);
		if (view_active)
			lxp_guest_view_end(&view);
	}

	/* Async ^C/^Z for a foreground program that never reads stdin. */
	if (lxp_tty_isig() && !(scan.wait_policy & LXP_BLOCKED_WAIT_CONSOLE) && cfg &&
	    cfg->console_poll &&
	    cfg->console_poll(cfg->io_ctx)) {
		uint8_t ch = 0;
		long rc = cfg->read_fn ? cfg->read_fn(cfg->io_ctx, 0, &ch, 1) : 0;
		if (rc == 1 && (ch == 3 || ch == 26)) {
			console_signal_fg(ch == 3 ? LXP_SIGINT : LXP_SIGTSTP);
			scan.progress = 1;
		}
	}
	return scan;
}
