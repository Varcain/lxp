/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator tests for signals and job control: pending-signal selection, stop and continue,
 * SIGKILL, caught SIGCONT across parked waits, process groups and stop notification.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "lxp_run_internal.h"
#include "../framework/lxp_coord_fixture.h"
#include "../framework/lxp_mock_engine.h"

static void test_stopped_wait_completion_is_retained_until_sigcont(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	int status = -1;
	make_valid_running_slot(0, 0);
	lxp_proc_t *parent = &g_lxp_rt.slots[0].proc;
	parent->pid = 1;
	parent->group->tgid = 1;
	parent->group->live_children = 1;
	set_child_wait(parent, -1, 0, &status);
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	parent->stopped = 1;
	parent->stop_kind = LXP_STOP_PARKED;
	parent->stop_sig = LXP_SIGSTOP;

	lxp_reap_to_parent(/*ppid*/ 1, /*cpid*/ 7, /*status*/ 42,
		       /*sigchld=*/1);

	assert_true(parent->stopped);
	assert_int_equal(parent->stop_kind, LXP_STOP_READY);
	assert_int_equal(parent->stop_r0, 7);
	assert_int_equal(parent->wait.kind, LXP_WAIT_NONE);
	assert_int_equal(status, 42 << 8);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);
	assert_false(g_lxp_rt.slots[0].runnable);
	assert_int_equal(g_mock.resume_calls, 0);

	lxp_signal_latch(parent, LXP_SIGCONT);
	assert_true(lxp_scan_blocked(1).progress);
	assert_false(parent->stopped);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, 7);
}

/* lxp_pending_deliverable returns the lowest-numbered UNBLOCKED pending signal and leaves blocked
 * ones set — so the mask is honored (a blocked signal is deferred, #4) and no pending signal is
 * lost to a single slot when another arrives (#5). SIGKILL/SIGSTOP are never blocked. */
static void test_pending_deliverable(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->sig_blocked = lxp_sig_bit(LXP_SIGTERM); /* SIGTERM blocked, SIGINT not */
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM) | lxp_sig_bit(LXP_SIGINT);
	assert_int_equal(lxp_pending_deliverable(p), LXP_SIGINT); /* skips the blocked SIGTERM */

	p->pending_sigs &= ~lxp_sig_bit(LXP_SIGINT); /* consume SIGINT */
	assert_int_equal(lxp_pending_deliverable(p), 0); /* SIGTERM still blocked -> nothing */
	assert_true(p->pending_sigs & lxp_sig_bit(LXP_SIGTERM)); /* ...but not lost */
	p->sig_blocked = 0;
	/* unblocked -> now deliverable */
	assert_int_equal(lxp_pending_deliverable(p), LXP_SIGTERM);

	p->sig_blocked = (uint64_t)-1; /* even a full mask cannot block SIGKILL */
	p->pending_sigs = lxp_sig_bit(LXP_SIGKILL);
	assert_int_equal(lxp_pending_deliverable(p), LXP_SIGKILL);

	p->pending_sigs = 0;
	assert_int_equal(lxp_pending_deliverable(p), 0); /* empty set */
}

static void test_deferred_completion_takes_pending_stop_without_resume(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->pid = 7;
	struct lxp_frame frame = {0};
	frame.r[7] = 999;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal(lxp_deferred_state_load(0), DEFER_READY);
	lxp_signal_latch(proc, LXP_SIGSTOP);

	lxp_execute_deferred(0);

	assert_int_equal(lxp_deferred_state_load(0), DEFER_IDLE);
	assert_true(proc->stopped);
	assert_int_equal(proc->stop_kind, LXP_STOP_READY);
	assert_int_equal(proc->stop_sig, LXP_SIGSTOP);
	assert_int_equal(proc->stop_r0, -LXP_ENOSYS);
	assert_false(proc->pending_sigs & lxp_sig_bit(LXP_SIGSTOP));
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);
	assert_false(g_lxp_rt.slots[0].runnable);
	assert_int_equal(g_mock.resume_calls, 0);

	lxp_signal_latch(proc, LXP_SIGCONT);
	assert_true(lxp_scan_blocked(1).progress);
	assert_false(proc->stopped);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, -LXP_ENOSYS);
}

/* A deliverable signal queued before resource acquisition cancels deferred work.
 * Default SIGTERM kills the guest without ever executing or resuming its syscall. */
static void test_deferred_signal_cancels_before_execute(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &f), LXP_OK);
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM);

	lxp_execute_deferred(0);

	assert_int_equal(lxp_deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_status, 128 + LXP_SIGTERM);
}

/* A signal owns cancellation of an in-flight netfs wait before the generic
 * retry pass sees it. The late transport reply is covered by the netfs suite;
 * this crossing proves the coordinator cannot resume a killed guest first. */
static void test_signal_interrupts_blocked_netfs_before_retry(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	assert_int_equal(lxp_wait_begin(p,
					&(lxp_wait_t){
						.kind = LXP_WAIT_NETFS,
						.data.io.request = -1,
					}),
			 LXP_OK);
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM);

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);

	assert_true(scan.progress);
	assert_int_equal(p->wait.kind, LXP_WAIT_NONE);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_status, 128 + LXP_SIGTERM);
	assert_true(lxp_primary_slot_pending(0));
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

/* A caught signal must not turn an already-submitted host-FS operation into an
 * at-most-once violation. Its completion result is retained in the signal
 * return frame, then the handler runs; libc resumes with that result rather
 * than retrying an operation whose native cursor may already have advanced. */
static void test_caught_signal_waits_for_hostfs_completion(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->sighand->handler[LXP_SIGALRM] = 0x1234u;
	proc->sighand->restorer = 0x5678u;
	g_lxp_rt.slots[0].resume.pc = 0x2221u;
	assert_int_equal(lxp_wait_begin(proc,
					&(lxp_wait_t){
						.kind = LXP_WAIT_HOSTFS,
						.data.hostfs.nr = 999,
					}),
			 LXP_OK);
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	lxp_signal_latch(proc, LXP_SIGALRM);

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);

	assert_true(scan.progress);
	assert_int_equal(proc->wait.kind, LXP_WAIT_NONE);
	assert_false(proc->pending_sigs & lxp_sig_bit(LXP_SIGALRM));
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, LXP_SIGALRM);
	assert_int_equal(g_lxp_rt.slots[0].resume.pc, 0x1235u);
	assert_int_equal(g_lxp_sig_save[0].depth, 1);
	assert_int_equal((int32_t)g_lxp_sig_save[0].frame[0].r0, -LXP_ENOSYS);
	assert_int_equal(g_lxp_sig_save[0].frame[0].pc, 0x2221u);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

/* kill(-pgid)/kill(0) target a PROCESS GROUP, not every proc — the fix for `kill %job` (and
 * fg's SIGCONT) no longer nuking unrelated daemons like inetd. */
static void test_kill_targets_process_group(void **state)
{
	(void)state;
	/* pid / pgid layout: init(1,1) shell(2,2) cmd1(3,3) cmd2(4,3 — cmd1's group) inetd(5,5) */
	const int pid[5] = {1, 2, 3, 4, 5};
	const int pgid[5] = {1, 2, 3, 3, 5};
	for (int i = 0; i < 5; i++) {
		g_lxp_rt.slots[i].proc.alive = 1;
		g_lxp_rt.slots[i].proc.pid = pid[i];
		g_lxp_rt.slots[i].proc.group->pgid = pgid[i];
	}
	lxp_proc_t *shell = &g_lxp_rt.slots[1].proc; /* the sender */
	const uint64_t bit = lxp_sig_bit(LXP_SIGTERM);

	/* shell: kill(-3, SIGTERM) -> process group 3 = {cmd1 pid3, cmd2 pid4} only. */
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_kill;
	f.r[0] = (uint32_t)(-3); /* target = -pgid */
	f.r[1] = LXP_SIGTERM;
	lxp_trap_dispatch(&f, shell);
	assert_int_equal((int32_t)f.r[0], 0);		      /* a target was found */
	assert_true(g_lxp_rt.slots[2].proc.pending_sigs & bit);  /* cmd1 (pgid 3) */
	assert_true(g_lxp_rt.slots[3].proc.pending_sigs & bit);  /* cmd2 (pgid 3) */
	assert_false(g_lxp_rt.slots[0].proc.pending_sigs & bit); /* init untouched */
	assert_false(g_lxp_rt.slots[1].proc.pending_sigs & bit); /* the sender itself */
	assert_false(g_lxp_rt.slots[4].proc.pending_sigs &
		     bit); /* inetd (pgid 5) — the old broadcast bug */

	/* kill(0, SIGTERM) targets the SENDER's own group (pgid 2); put inetd in it. */
	for (int i = 0; i < 5; i++)
		g_lxp_rt.slots[i].proc.pending_sigs = 0;
	g_lxp_rt.slots[4].proc.group->pgid = 2;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_kill;
	f.r[0] = 0; /* caller's process group */
	f.r[1] = LXP_SIGTERM;
	lxp_trap_dispatch(&f, shell);
	assert_true(g_lxp_rt.slots[4].proc.pending_sigs & bit);  /* the group peer */
	assert_false(g_lxp_rt.slots[2].proc.pending_sigs & bit); /* pgid 3, not in group 2 */
}

/* setpgid(0,pgid)/getpgrp track a real per-proc group; setsid makes the caller a leader. */
static void test_setpgid_getpgrp_track_group(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->alive = 1;
	p->pid = 7;
	p->group->pgid = 7;
	struct lxp_frame f;

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpgrp;
	lxp_trap_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 7); /* getpgrp -> current group */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_setpgid;
	f.r[0] = 0;  /* self */
	f.r[1] = 42; /* pgid */
	lxp_trap_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 0);
	assert_int_equal(p->group->pgid, 42); /* setpgid(0,42) joined group 42 */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpgrp;
	lxp_trap_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 42); /* getpgrp reflects it */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_setsid;
	lxp_trap_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 7); /* setsid -> new session, pgid = pid */
	assert_int_equal(p->group->pgid, 7);
}

static void test_running_stop_parks_at_boundary_and_continues(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->pid = 7;
	struct lxp_frame frame = {0};
	frame.r[7] = LXP_NR_gettid;
	proc->pending_sigs = lxp_sig_bit(LXP_SIGSTOP);

	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_true(proc->stopped);
	assert_int_equal(proc->stop_kind, LXP_STOP_READY);
	assert_int_equal(proc->stop_sig, LXP_SIGSTOP);
	assert_int_equal(proc->stop_r0, proc->pid);
	assert_int_equal(g_mock.park_prepare_calls, 1);
	assert_true(lxp_primary_slot_pending(0));

	unsigned cursor = 0;
	struct lxp_claimed_event claimed = lxp_coordinator_claim_event(&cursor);
	assert_int_equal(claimed.slot, 0);
	assert_int_equal(claimed.type, LXP_EV_STOP);
	int next_pid = 8;
	struct lxp_primary_result primary = lxp_handle_primary_event(
		claimed.slot, claimed.type, &next_pid);
	assert_int_equal(primary.flow, LXP_PRIMARY_HANDLED);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);
	assert_false(g_lxp_rt.slots[0].runnable);

	lxp_signal_latch(proc, LXP_SIGSTOP);
	lxp_signal_latch(proc, LXP_SIGTSTP);
	lxp_signal_latch(proc, LXP_SIGCONT);
	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_false(proc->stopped);
	assert_int_equal(proc->stop_kind, LXP_STOP_NONE);
	assert_int_equal(proc->stop_sig, 0);
	assert_int_equal(proc->stop_r0, 0);
	assert_int_equal(proc->pending_sigs, 0);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, proc->pid);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_RUNNING);
	assert_true(g_lxp_rt.slots[0].runnable);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_stop_continue_publication_preserves_generation_order(void **state)
{
	(void)state;
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;

	lxp_signal_latch(proc, LXP_SIGCONT);
	lxp_signal_latch(proc, LXP_SIGTSTP);
	assert_int_equal(proc->pending_sigs, lxp_sig_bit(LXP_SIGTSTP));

	proc->pending_sigs = 0;
	lxp_signal_latch(proc, LXP_SIGSTOP);
	lxp_signal_latch(proc, LXP_SIGTSTP);
	lxp_signal_latch(proc, LXP_SIGCONT);
	assert_int_equal(proc->pending_sigs, lxp_sig_bit(LXP_SIGCONT));

	proc->pending_sigs = lxp_sig_bit(LXP_SIGKILL);
	lxp_signal_latch(proc, LXP_SIGSTOP);
	lxp_signal_latch(proc, LXP_SIGCONT);
	assert_int_equal(proc->pending_sigs, lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGCONT));
}

static void test_caught_sigcont_runs_after_boundary_resume(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->pid = 7;
	proc->sighand->handler[LXP_SIGCONT] = 0x1234u;
	proc->sighand->restorer = 0x5678u;
	struct lxp_frame frame = {0};
	frame.r[7] = LXP_NR_gettid;
	frame.r[14] = 0xaaaau;
	frame.r[15] = 0x1110u;
	frame.xpsr = 1u << 24;
	lxp_signal_latch(proc, LXP_SIGSTOP);

	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	unsigned cursor = 0;
	struct lxp_claimed_event claimed = lxp_coordinator_claim_event(&cursor);
	int next_pid = 8;
	(void)lxp_handle_primary_event(claimed.slot, claimed.type, &next_pid);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);

	lxp_signal_latch(proc, LXP_SIGCONT);
	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_false(proc->stopped);
	assert_int_equal(proc->wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, LXP_SIGCONT);
	assert_int_equal(g_lxp_rt.slots[0].resume.pc, 0x1235u);
	assert_int_equal(g_lxp_rt.slots[0].resume.lr, 0x5679u);
	assert_int_equal(g_lxp_sig_save[0].depth, 1);
	assert_int_equal(g_lxp_sig_save[0].frame[0].r0, proc->pid);
	assert_int_equal(g_lxp_sig_save[0].frame[0].pc, 0x1111u);
	assert_int_equal(g_lxp_sig_save[0].frame[0].lr, 0xaaaau);
}

static void test_caught_sigcont_interrupts_parked_wait(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->sighand->handler[LXP_SIGCONT] = 0x1234u;
	proc->sighand->restorer = 0x5678u;
	g_lxp_rt.slots[0].resume.pc = 0x2221u;
	assert_int_equal(lxp_wait_begin(proc,
					&(lxp_wait_t){
						.kind = LXP_WAIT_TIMER,
						.data.timer.deadline_us = 1000,
					}),
			 LXP_OK);
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	lxp_signal_latch(proc, LXP_SIGSTOP);

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_true(proc->stopped);
	assert_int_equal(proc->stop_kind, LXP_STOP_PARKED);
	assert_int_equal(g_mock.resume_calls, 0);

	lxp_signal_latch(proc, LXP_SIGCONT);
	scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_false(proc->stopped);
	assert_int_equal(proc->wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, LXP_SIGCONT);
	assert_int_equal(g_lxp_rt.slots[0].resume.pc, 0x1235u);
	assert_int_equal(g_lxp_sig_save[0].depth, 1);
	assert_int_equal((int32_t)g_lxp_sig_save[0].frame[0].r0, -LXP_EINTR);
	assert_int_equal(g_lxp_sig_save[0].frame[0].pc, 0x2221u);
}

static void test_blocked_caught_sigcont_resumes_boundary_but_stays_pending(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->pid = 7;
	proc->sighand->handler[LXP_SIGCONT] = 0x1234u;
	proc->sighand->restorer = 0x5678u;
	proc->sig_blocked = lxp_sig_bit(LXP_SIGCONT);
	struct lxp_frame frame = {0};
	frame.r[7] = LXP_NR_gettid;
	frame.r[15] = 0x1110u;
	frame.xpsr = 1u << 24;
	lxp_signal_latch(proc, LXP_SIGSTOP);

	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	unsigned cursor = 0;
	struct lxp_claimed_event claimed = lxp_coordinator_claim_event(&cursor);
	int next_pid = 8;
	(void)lxp_handle_primary_event(claimed.slot, claimed.type, &next_pid);
	lxp_signal_latch(proc, LXP_SIGCONT);

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_false(proc->stopped);
	assert_true(proc->pending_sigs & lxp_sig_bit(LXP_SIGCONT));
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, proc->pid);
	assert_int_equal(g_lxp_rt.slots[0].resume.pc, 0x1111u);
	assert_int_equal(g_lxp_sig_save[0].depth, 0);
}

static void test_blocked_caught_sigcont_keeps_parked_wait(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->sighand->handler[LXP_SIGCONT] = 0x1234u;
	proc->sig_blocked = lxp_sig_bit(LXP_SIGCONT);
	assert_int_equal(lxp_wait_begin(proc,
					&(lxp_wait_t){
						.kind = LXP_WAIT_TIMER,
						.data.timer.deadline_us = 1000,
					}),
			 LXP_OK);
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	lxp_signal_latch(proc, LXP_SIGSTOP);
	assert_true(lxp_scan_blocked(1).progress);
	assert_true(proc->stopped);

	lxp_signal_latch(proc, LXP_SIGCONT);
	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_false(proc->stopped);
	assert_true(proc->pending_sigs & lxp_sig_bit(LXP_SIGCONT));
	assert_int_equal(proc->wait.kind, LXP_WAIT_TIMER);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_sig_save[0].depth, 0);
}

static void test_caught_sigcont_does_not_resume_vfork_owned_park(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->sighand->handler[LXP_SIGCONT] = 0x1234u;
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	assert_int_equal(proc->wait.kind, LXP_WAIT_NONE);
	proc->stopped = 1;
	proc->stop_kind = LXP_STOP_PARKED;
	proc->stop_sig = LXP_SIGSTOP;
	lxp_signal_latch(proc, LXP_SIGCONT);

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_false(proc->stopped);
	assert_true(proc->pending_sigs & lxp_sig_bit(LXP_SIGCONT));
	assert_int_equal(proc->wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);
	assert_false(g_lxp_rt.slots[0].runnable);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_sig_save[0].depth, 0);
}

static void test_stopped_vfork_parent_release_waits_for_sigcont(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	make_valid_running_slot(1, 1);
	lxp_proc_t *parent = &g_lxp_rt.slots[0].proc;
	lxp_proc_t *child = &g_lxp_rt.slots[1].proc;
	parent->pid = 1;
	parent->group->tgid = 1;
	parent->group->live_children = 1;
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	parent->stopped = 1;
	parent->stop_kind = LXP_STOP_PARKED;
	parent->stop_sig = LXP_SIGSTOP;

	child->pid = 7;
	child->group->tgid = 7;
	child->group->ppid = 1;
	child->vfork_parent = lxp_slot_ref_at(0);
	child->exit_status = 0;
	assert_int_equal(lxp_intent_exit(child, 0), LXP_OK);
	assert_int_equal(lxp_coordinator_resume_slot(0, parent->mm->region.index,
						 lxp_slot_resume_view(lxp_slot_ref_at(0)), 7),
			 -LXP_EAGAIN);
	assert_int_equal(g_mock.resume_calls, 0);

	(void)lxp_handle_exit(1);

	assert_false(child->alive);
	assert_true(parent->stopped);
	assert_int_equal(parent->stop_kind, LXP_STOP_READY);
	assert_int_equal(parent->stop_r0, 7);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);
	assert_false(g_lxp_rt.slots[0].runnable);
	assert_int_equal(g_mock.resume_calls, 0);

	lxp_signal_latch(parent, LXP_SIGCONT);
	assert_true(lxp_scan_blocked(1).progress);
	assert_false(parent->stopped);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, 7);
}

static void test_sigkill_wins_over_sigcont_for_stopped_task(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	proc->stopped = 1;
	proc->stop_kind = LXP_STOP_READY;
	proc->stop_sig = LXP_SIGSTOP;
	proc->stop_r0 = 17;
	lxp_signal_latch(proc, LXP_SIGCONT);
	lxp_signal_latch(proc, LXP_SIGKILL);

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_false(proc->stopped);
	assert_int_equal(proc->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(proc->exit_status, 128 + LXP_SIGKILL);
	assert_int_equal(proc->exit_signal, LXP_SIGKILL);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_true(lxp_primary_slot_pending(0));
}

/* The stop-signal predicate: SIGSTOP always stops (uncatchable); SIGTSTP/TTIN/TTOU stop
 * only at their default disposition (a caught one runs the handler). */
static void test_sig_stops_proc_predicate(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	static lxp_sighand_t sighand;
	memset(&sighand, 0, sizeof(sighand));
	sighand.refs = 1;
	p->sighand = &sighand;
	p->sighand->handler[LXP_SIGTSTP] = LXP_SIG_DFL;
	assert_true(lxp_sig_is_stop(LXP_SIGTSTP));
	assert_true(lxp_sig_is_stop(LXP_SIGSTOP));
	assert_false(lxp_sig_is_stop(LXP_SIGINT));
	assert_true(lxp_sig_stops_proc(p, LXP_SIGTSTP)); /* SIG_DFL → stops */
	p->sighand->handler[LXP_SIGTSTP] = 0x1000;   /* a caught handler → runs it, no stop */
	assert_false(lxp_sig_stops_proc(p, LXP_SIGTSTP));
	p->sighand->handler[LXP_SIGSTOP] = 0x1000; /* SIGSTOP is uncatchable → always stops */
	assert_true(lxp_sig_stops_proc(p, LXP_SIGSTOP));
	assert_false(lxp_sig_stops_proc(p, LXP_SIGINT)); /* not a stop signal */
}

/* A stopped child wakes a parent blocked in wait4(WUNTRACED) with a WIFSTOPPED status and,
 * unlike an exit, leaves live_children intact (the child is still alive). */
static void test_stop_notify_wakes_wuntraced_waiter(void **state)
{
	(void)state;
	int status = -1;
	lxp_deferred_slot_reassign(0);
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_rt.slots[0].proc, -1, LXP_WUNTRACED, &status);
	g_lxp_rt.slots[0].host_state = SLOT_PARKED;

	lxp_notify_parent_stopped(/*ppid*/ 1, /*cpid*/ 7, LXP_SIGTSTP);

	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, 7);
	assert_int_equal(status, ((LXP_SIGTSTP & 0xff) << 8) | 0x7f); /* WIFSTOPPED */
	assert_int_equal(g_lxp_rt.slots[0].proc.wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children,
			 1); /* NOT decremented — the child lives */
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count, 0);
}

/* A stopped child whose parent is NOT waiting (or waits without WUNTRACED) queues a STOPPED
 * notice + raises SIGCHLD, again without touching live_children. */
static void test_stop_notify_queues_without_wuntraced(void **state)
{
	(void)state;
	/* Parent blocked in wait4 but WITHOUT WUNTRACED → cannot take the stop → queue it. */
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_rt.slots[0].proc, -1, 0, NULL);

	lxp_notify_parent_stopped(/*ppid*/ 1, /*cpid*/ 7, LXP_SIGTSTP);

	assert_int_equal(g_mock.resume_calls, 0); /* the waiter is not woken */
	assert_int_equal(g_lxp_rt.slots[0].proc.wait.kind, LXP_WAIT_CHILD);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count, 1);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_pid[0], 7);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_status[0], LXP_SIGTSTP);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_kind[0], LXP_CHILD_STOPPED);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children, 1); /* NOT decremented */
	assert_true(g_lxp_rt.slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD));
}

int test_coord_signal_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_kill_targets_process_group, reset_state),
		cmocka_unit_test_setup(test_setpgid_getpgrp_track_group, reset_state),
		cmocka_unit_test_setup(test_running_stop_parks_at_boundary_and_continues,
				       reset_state),
		cmocka_unit_test_setup(test_stop_continue_publication_preserves_generation_order,
				       reset_state),
		cmocka_unit_test_setup(test_caught_sigcont_runs_after_boundary_resume, reset_state),
		cmocka_unit_test_setup(test_caught_sigcont_interrupts_parked_wait, reset_state),
		cmocka_unit_test_setup(
			test_blocked_caught_sigcont_resumes_boundary_but_stays_pending,
			reset_state),
		cmocka_unit_test_setup(test_blocked_caught_sigcont_keeps_parked_wait, reset_state),
		cmocka_unit_test_setup(test_caught_sigcont_does_not_resume_vfork_owned_park,
				       reset_state),
		cmocka_unit_test_setup(test_stopped_vfork_parent_release_waits_for_sigcont,
				       reset_state),
		cmocka_unit_test_setup(test_sigkill_wins_over_sigcont_for_stopped_task,
				       reset_state),
		cmocka_unit_test_setup(test_sig_stops_proc_predicate, reset_state),
		cmocka_unit_test_setup(test_stop_notify_wakes_wuntraced_waiter, reset_state),
		cmocka_unit_test_setup(test_stop_notify_queues_without_wuntraced, reset_state),
		cmocka_unit_test_setup(test_deferred_completion_takes_pending_stop_without_resume,
				       reset_state),
		cmocka_unit_test_setup(test_deferred_signal_cancels_before_execute, reset_state),
		cmocka_unit_test_setup(test_signal_interrupts_blocked_netfs_before_retry,
				       reset_state),
		cmocka_unit_test_setup(test_caught_signal_waits_for_hostfs_completion, reset_state),
		cmocka_unit_test_setup(test_pending_deliverable, reset_state),
		cmocka_unit_test_setup(test_stopped_wait_completion_is_retained_until_sigcont,
				       reset_state),
	};
	return cmocka_run_group_tests_name("coordinator: signals", tests, NULL, NULL);
}
