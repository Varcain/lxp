/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator tests for slot lifecycle and scheduling: typed intents and waits, the deferred-
 * syscall mailbox and trap dispatch, event claims, the blocked-slot scan and its service
 * classes, park/resume/abort failures and teardown.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "lxp_syscall.h"
#include "fs/lxp_tty.h"
#include "lxp_internal.h"
#include "../framework/lxp_coord_fixture.h"
#include "../framework/lxp_mock_engine.h"

/* The blocked-slot service selector, with the pending classes as a bit mask. */
static int service_select(uint8_t pending_mask, const uint64_t oldest[LXP_SERVICE_CLASSES],
			  uint64_t now)
{
	uint8_t pending[LXP_SERVICE_CLASSES];
	for (int cls = 0; cls < LXP_SERVICE_CLASSES; cls++)
		pending[cls] = (uint8_t)((pending_mask >> cls) & 1u);
	return lxp_blocked_service_select(pending, oldest, now);
}

static void test_priority_syscalls_update_bounded_guest_weights(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	make_valid_running_slot(1, 1);
	g_lxp_rt.slots[0].proc.group->pgid = 7;
	g_lxp_rt.slots[1].proc.group->pgid = 7;

	struct lxp_frame frame = {0};
	frame.r[7] = LXP_NR_setpriority;
	frame.r[0] = 0; /* PRIO_PROCESS */
	frame.r[1] = (uint32_t)g_lxp_rt.slots[1].proc.pid;
	frame.r[2] = (uint32_t)-10;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal((int32_t)frame.r[0], 0);
	assert_int_equal(lxp_proc_nice_get(&g_lxp_rt.slots[1].proc), -10);
	assert_int_equal(lxp_guest_sched_weight(1), 30);

	memset(&frame, 0, sizeof(frame));
	frame.r[7] = LXP_NR_getpriority;
	frame.r[0] = 1; /* PRIO_PGRP */
	frame.r[1] = 7;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal(frame.r[0], 30); /* raw 20 - best nice (-10) */

	memset(&frame, 0, sizeof(frame));
	frame.r[7] = LXP_NR_setpriority;
	frame.r[0] = 1; /* PRIO_PGRP */
	frame.r[1] = 7;
	frame.r[2] = 99; /* clamped to nice 19 */
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal(lxp_proc_nice_get(&g_lxp_rt.slots[0].proc), 19);
	assert_int_equal(lxp_proc_nice_get(&g_lxp_rt.slots[1].proc), 19);
	assert_int_equal(lxp_guest_sched_weight(0), 1);
	assert_int_equal(lxp_guest_sched_weight(1), 1);
	assert_int_equal(lxp_guest_sched_weight(2), 0); /* not runnable */

	/* The caller itself (who 0): the raw value is 20 - nice, so a negative nice
	 * cannot be mistaken for an errno by libc. */
	memset(&frame, 0, sizeof(frame));
	frame.r[7] = LXP_NR_getpriority;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal(frame.r[0], 1); /* nice 19 */

	/* No such process, and an invalid `which`. */
	memset(&frame, 0, sizeof(frame));
	frame.r[7] = LXP_NR_getpriority;
	frame.r[1] = 99;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal((int32_t)frame.r[0], -LXP_ESRCH);
	memset(&frame, 0, sizeof(frame));
	frame.r[7] = LXP_NR_setpriority;
	frame.r[0] = 3;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal((int32_t)frame.r[0], -LXP_EINVAL);
}

static void test_typed_intent_transitions_are_exclusive(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	for (int kind = LXP_INTENT_DEFERRED_SYSCALL; kind < LXP_INTENT_COUNT; kind++) {
		lxp_intent_t intent = {.kind = (lxp_intent_kind_t)kind};
		assert_int_equal(lxp_intent_begin(p, &intent), 0);
		assert_int_equal(lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}),
				 -LXP_EAGAIN);
		assert_int_equal(p->intent.kind, kind);
		assert_int_equal(lxp_intent_complete(p, (lxp_intent_kind_t)kind), 0);
		assert_int_equal(p->intent.kind, LXP_INTENT_NONE);
	}
	assert_int_equal(lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_NONE}),
			 -LXP_EINVAL);
	assert_int_equal(lxp_wait_begin(p, &(lxp_wait_t){.kind = LXP_WAIT_CHILD}), 0);
	assert_int_equal(lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}),
			 -LXP_EAGAIN);
	assert_int_equal(lxp_wait_cancel(p), 0);
	assert_int_equal(lxp_intent_exit(p, 1), 0);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_true(p->intent.data.exit.group);
}

static void test_exit_intent_supersedes_deferred_work(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->intent.kind = LXP_INTENT_DEFERRED_SYSCALL;
	g_lxp_rt.slots[0].deferred.owner = lxp_slot_ref_at(0);
	lxp_deferred_state_store(0, DEFER_READY);

	assert_int_equal(lxp_intent_exit(p, 0), 0);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(lxp_claim_slot_event(0), LXP_EV_EXIT);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_typed_wait_transitions_cover_every_kind(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	for (int kind = LXP_WAIT_TIMER; kind < LXP_WAIT_COUNT; kind++) {
		lxp_wait_t wait = {.kind = (lxp_wait_kind_t)kind};
		assert_int_equal(lxp_wait_begin(p, &wait), 0);
		assert_int_equal(lxp_wait_begin(p, &(lxp_wait_t){.kind = LXP_WAIT_CHILD}),
				 -LXP_EAGAIN);
		assert_int_equal(p->wait.kind, kind);
		assert_int_equal(lxp_wait_interrupt(p, (lxp_wait_kind_t)kind), 0);
		assert_int_equal(p->wait.kind, LXP_WAIT_NONE);

		assert_int_equal(lxp_wait_begin(p, &wait), 0);
		assert_int_equal(lxp_wait_timeout(p, (lxp_wait_kind_t)kind), 0);
		assert_int_equal(p->wait.kind, LXP_WAIT_NONE);
	}
	assert_int_equal(lxp_wait_begin(p, &(lxp_wait_t){.kind = LXP_WAIT_NONE}), -LXP_EINVAL);
}

static void test_slot_references_reject_recycled_incarnations_and_skip_zero(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	g_lxp_rt.slots[0].generation = UINT32_MAX;
	lxp_slot_ref_t stale = lxp_slot_ref_at(0);

	lxp_deferred_slot_reassign(0);
	lxp_slot_ref_t current;
	assert_int_equal(lxp_slot_ref_current(0, &current), LXP_OK);
	assert_int_equal(current.generation, 1);
	assert_false(lxp_slot_ref_is_current(stale));
	assert_true(lxp_slot_ref_is_current(current));

	struct lxp_frame frame = {0};
	frame.r[0] = 0xfeedbeefu;
	frame.r[7] = LXP_NR_getpid;
	assert_int_equal(lxp_dispatch_slot(stale, &frame), LXP_ERR_NOT_FOUND);
	assert_int_equal(frame.r[0], 0xfeedbeefu);
	assert_int_equal(lxp_dispatch_slot(current, &frame), LXP_OK);
	assert_int_equal(frame.r[0], g_lxp_rt.slots[0].proc.pid);
}

static void test_resume_context_view_rejects_recycled_slot(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	memset(&g_lxp_rt.slots[0].resume, 0x5a, sizeof(g_lxp_rt.slots[0].resume));
	lxp_slot_ref_t stale = lxp_slot_ref_at(0);

	assert_ptr_equal(lxp_slot_resume_view(stale), &g_lxp_rt.slots[0].resume);
	lxp_deferred_slot_reassign(0);
	assert_null(lxp_slot_resume_view(stale));
	assert_ptr_equal(lxp_slot_resume_view(lxp_slot_ref_at(0)), &g_lxp_rt.slots[0].resume);
}

static void test_fault_publication_rejects_stale_slot_reference(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_slot_ref_t stale = lxp_slot_ref_at(0);
	lxp_deferred_slot_reassign(0);
	lxp_slot_ref_t current = lxp_slot_ref_at(0);
	const lxp_guest_fault_t fault = {
		.detail = 0x82u,
		.address = 0x12345678u,
	};

	assert_int_equal(lxp_slot_report_memory_fault(stale, &fault), LXP_ERR_NOT_FOUND);
	assert_int_equal(g_lxp_rt.slots[0].proc.intent.kind, LXP_INTENT_NONE);
	assert_false(lxp_primary_slot_pending(0));
	assert_int_equal(lxp_slot_report_memory_fault(current, &fault), LXP_OK);
	assert_int_equal(g_lxp_rt.slots[0].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_rt.slots[0].proc.exit_reason, LXP_EXIT_REASON_MEMORY_FAULT);
	assert_int_equal(g_lxp_rt.slots[0].proc.exit_detail, fault.detail);
	assert_int_equal(g_lxp_rt.slots[0].proc.exit_address, fault.address);
	assert_true(lxp_primary_slot_pending(0));
}

static void test_coordinator_socket_wait_uses_readiness_events(void **state)
{
	(void)state;

	/* Legacy/portable ports retain the bounded polling fallback. */
	assert_int_equal(lxp_coordinator_wait_timeout(LXP_BLOCKED_WAIT_SOCKET, 0, 0), 5);
	/* An event-driven net port can sleep until its run-scoped callback (or the
	 * normal 50 ms maintenance wakeup) without quantizing readiness to 5 ms. */
	assert_int_equal(lxp_coordinator_wait_timeout(LXP_BLOCKED_WAIT_SOCKET, 1, 0), 50);
	/* A different polling wait class still requires the short timeout. */
	assert_int_equal(
		lxp_coordinator_wait_timeout(LXP_BLOCKED_WAIT_POLL | LXP_BLOCKED_WAIT_SOCKET, 1, 0),
		5);
	/* A console readiness subscription removes its independent 5 ms fallback. */
	assert_int_equal(lxp_coordinator_wait_timeout(LXP_BLOCKED_WAIT_CONSOLE, 0, 0), 5);
	assert_int_equal(lxp_coordinator_wait_timeout(LXP_BLOCKED_WAIT_CONSOLE, 0, 1), 50);
	assert_int_equal(lxp_coordinator_wait_timeout(0, 0, 0), 50);
}

static void test_coordinator_service_classes_are_weighted_and_aged(void **state)
{
	(void)state;
	const uint64_t fresh[4] = {100, 100, 100, 100};
	const int expected[] = {0, 0, 0, 0, 1, 1, 1, 2, 2, 3};
	lxp_blocked_fair_reset();
	for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++)
		assert_int_equal(service_select(0x0fu, fresh, 100), expected[i]);

	/* A low-weight class bypasses the schedule after the bounded age. */
	const uint64_t aged[4] = {20001, 20001, 1, 20001};
	lxp_blocked_fair_reset();
	assert_int_equal(service_select(0x0fu, aged, 20001), 2);

	/* Several old-but-not-ready classes must not let the single oldest class
	 * monopolize every retry. A parked socket is older than the console here;
	 * both remain aged and still advance through their weighted opportunities. */
	const uint64_t multiple_aged[4] = {20001, 1, 2, 20001};
	const int aged_expected[] = {1, 1, 1, 2, 2};
	lxp_blocked_fair_reset();
	for (size_t i = 0; i < sizeof(aged_expected) / sizeof(aged_expected[0]); i++)
		assert_int_equal(service_select(0x06u, multiple_aged, 20002),
				 aged_expected[i]);

#if LXP_ENABLE_FS
	/* A native completion is readiness, not merely another pending class.
	 * It gets the next opportunity without changing the weighted sequence
	 * used when requests are still in flight. */
	lxp_blocked_fair_reset();
	assert_int_equal(service_select(0x0fu, fresh, 100), 0);
	assert_int_equal(service_select(0x0fu, fresh, 100), 0);
	assert_int_equal(service_select(0x0fu, fresh, 100), 0);
	assert_int_equal(service_select(0x0fu, fresh, 100), 0);
	assert_int_equal(service_select(0x0fu, fresh, 100), 1);
	lxp_fs_completion_ready(&g_mock_eng);
	assert_int_equal(service_select(0x0fu, fresh, 100), 0);
#endif
}

/* The per-slot claim helper maps one typed intent/wait without consuming its
 * payload inside the engine critical section. */
static void test_claim_slot_event_priority_and_consumption(void **state)
{
	(void)state;
	const int s = 2;
	lxp_proc_t *p = &g_lxp_rt.slots[s].proc;

	assert_false(lxp_primary_slot_pending(s));
	lxp_event_post_slot(s);
	assert_true(lxp_primary_slot_pending(s));
	assert_int_equal(g_mock.event_posts, 1);
	lxp_primary_slot_clear(s);
	assert_false(lxp_primary_slot_pending(s));

	assert_int_equal(lxp_claim_slot_event(s), LXP_EV_NONE);
	p->alive = 1;
	p->intent.kind = LXP_INTENT_EXIT;
	assert_int_equal(lxp_claim_slot_event(s), LXP_EV_EXIT);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	p->intent.kind = LXP_INTENT_EXEC;
	assert_int_equal(lxp_claim_slot_event(s), LXP_EV_EXEC);
	p->intent.kind = LXP_INTENT_FORK;
	assert_int_equal(lxp_claim_slot_event(s), LXP_EV_FORK);
	assert_int_equal(p->intent.kind, LXP_INTENT_FORK);
	p->intent.kind = LXP_INTENT_NONE;
	p->wait.kind = LXP_WAIT_TIMER;
	p->wait.data.timer.deadline_us = 1;
	assert_int_equal(lxp_claim_slot_event(s), LXP_EV_NONE);
	g_lxp_rt.slots[s].runnable = 1;
	g_lxp_rt.slots[s].host_state = SLOT_RUNNING;
	p->wait.kind = LXP_WAIT_NONE;
	p->stopped = 1;
	p->stop_kind = LXP_STOP_READY;
	assert_int_equal(lxp_claim_slot_event(s), LXP_EV_STOP);
	p->stopped = 0;
	p->stop_kind = LXP_STOP_NONE;
	static const struct {
		lxp_wait_kind_t kind;
		int event;
	} cases[] = {
		{LXP_WAIT_TIMER, LXP_EV_SLEEP},		  {LXP_WAIT_CHILD, LXP_EV_WAITPARK},
		{LXP_WAIT_FUTEX, LXP_EV_FUTEXWAIT},	  {LXP_WAIT_PIPE, LXP_EV_PIPE},
		{LXP_WAIT_CONSOLE, LXP_EV_CONSOLEWAIT},	  {LXP_WAIT_DEVICE, LXP_EV_DEVWAIT},
		{LXP_WAIT_SOCKET, LXP_EV_SOCKWAIT},	  {LXP_WAIT_POLL, LXP_EV_SOCKWAIT},
#if LXP_ENABLE_NETFS
		{LXP_WAIT_NETFS, LXP_EV_NETFSWAIT},
#endif
#if LXP_ENABLE_PTY
		{LXP_WAIT_PTY, LXP_EV_PTYWAIT},
#endif
		{LXP_WAIT_SIGSUSPEND, LXP_EV_SIGSUSPEND},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		p->wait.kind = cases[i].kind;
		assert_int_equal(lxp_claim_slot_event(s), cases[i].event);
		assert_int_equal(p->wait.kind, cases[i].kind);
	}
}

static void test_coordinator_claim_rotates_fairly_and_discards_stale_hints(void **state)
{
	(void)state;
	make_valid_running_slot(2, 2);
	make_valid_running_slot(4, 4);
	g_lxp_rt.slots[2].proc.wait.kind = LXP_WAIT_TIMER;
	g_lxp_rt.slots[4].proc.wait.kind = LXP_WAIT_TIMER;
	lxp_primary_slot_mark(2);
	lxp_primary_slot_mark(4);

	unsigned cursor = 0;
	struct lxp_claimed_event claimed = lxp_coordinator_claim_event(&cursor);
	assert_int_equal(claimed.slot, 2);
	assert_int_equal(claimed.type, LXP_EV_SLEEP);
	assert_int_equal(cursor, 3);

	/* Re-publishing slot 2 cannot starve the later pending slot. */
	lxp_primary_slot_mark(2);
	claimed = lxp_coordinator_claim_event(&cursor);
	assert_int_equal(claimed.slot, 4);
	assert_int_equal(cursor, 5);
	claimed = lxp_coordinator_claim_event(&cursor);
	assert_int_equal(claimed.slot, 2);
	assert_int_equal(cursor, 3);

	/* A stale bitmap hint is consumed without inventing an event. */
	lxp_primary_slot_mark(1);
	claimed = lxp_coordinator_claim_event(&cursor);
	assert_int_equal(claimed.slot, -1);
	assert_int_equal(claimed.type, LXP_EV_NONE);
	assert_false(lxp_primary_slot_pending(1));
	assert_int_equal(g_mock.critical_enter_calls, 4);
	assert_int_equal(g_mock.critical_exit_calls, 4);
	assert_int_equal(g_mock.critical_exit_token, (lxp_critical_token_t)0xa5a5u);
}

static void test_primary_wait_handler_applies_park_outcome(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	const int slot = 2;
	make_valid_running_slot(slot, 2);
	g_lxp_rt.slots[slot].proc.wait.kind = LXP_WAIT_TIMER;
	int next_pid = 10;

	struct lxp_primary_result result =
		lxp_handle_primary_event(slot, LXP_EV_SLEEP, &next_pid);
	assert_int_equal(result.flow, LXP_PRIMARY_HANDLED);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.park_sidx, slot);
	assert_int_equal(g_lxp_rt.slots[slot].host_state, SLOT_PARKED);
	assert_false(g_lxp_rt.slots[slot].runnable);
	assert_int_equal(next_pid, 10);
}

static void test_primary_handler_rejects_out_of_range_slot(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	int next_pid = 10;

	struct lxp_primary_result result = lxp_handle_primary_event(
		LXP_NSLOT, LXP_EV_EXIT, &next_pid);
	assert_int_equal(result.flow, LXP_PRIMARY_SCAN_BLOCKED);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(next_pid, 10);
}

static void test_blocked_timer_handler_resumes_expired_wait(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	const int slot = 3;
	make_valid_running_slot(slot, 3);
	assert_int_equal(lxp_coordinator_park_slot(slot), LXP_OK);
	assert_int_equal(lxp_wait_begin(&g_lxp_rt.slots[slot].proc,
					&(lxp_wait_t){
						.kind = LXP_WAIT_TIMER,
						.data.timer.deadline_us = 50,
					}),
			 LXP_OK);

	struct lxp_blocked_scan scan = lxp_scan_blocked(50);
	assert_true(scan.any_alive);
	assert_true(scan.any_busy);
	assert_true(scan.progress);
	assert_int_equal(scan.next_deadline_us, UINT64_MAX);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, slot);
	assert_int_equal(g_mock.resume_r0, 0);
	assert_int_equal(g_lxp_rt.slots[slot].proc.wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_lxp_rt.slots[slot].host_state, SLOT_RUNNING);
	assert_true(g_lxp_rt.slots[slot].runnable);
}

static void test_teardown_releases_every_slot_resource(void **state)
{
	(void)state;
	const int s = 2;
	lxp_deferred_slot_reassign(s);
	lxp_slot_ref_t owner = lxp_slot_ref_at(s);
	lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
	p->alive = 1;
	p->mm->region = lxp_region_reserve(1, owner);
	p->snapshot = lxp_region_reserve(2, owner);
	g_lxp_rt.slots[s].runnable = 1;
	g_lxp_rt.slots[s].host_state = SLOT_RUNNING;
	assert_non_null(lxp_fd_description(p, 0));

	lxp_coordinator_teardown_all();

	assert_int_equal(g_mock.abort_calls, LXP_NSLOT);
	assert_false(p->alive);
	assert_false(g_lxp_rt.slots[s].runnable);
	assert_null(lxp_fd_description(p, 0));
	for (int r = 0; r < LXP_NREG; r++) {
		assert_int_equal(g_lxp_rt.regions[r].lease_owner.index, -1);
		assert_int_equal(g_lxp_rt.regions[r].refs, 0);
	}
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_teardown_quiesces_before_releasing_resources(void **state)
{
	(void)state;
	const int s = 2;
	lxp_deferred_slot_reassign(s);
	lxp_slot_ref_t owner = lxp_slot_ref_at(s);
	lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
	p->alive = 1;
	p->mm->region = lxp_region_reserve(1, owner);
	g_lxp_rt.slots[s].runnable = 1;
	g_lxp_rt.slots[s].host_state = SLOT_RUNNING;
	g_mock.abort_failures = 1;
	g_mock.abort_fail_slot = s;
	g_mock.observe_wait_slot = s;
	lxp_trap_publish(1);

	lxp_coordinator_teardown_all();

	assert_int_equal(g_mock.abort_calls, LXP_NSLOT + 1);
	assert_int_equal(g_mock.event_wait_calls, 1);
	assert_true(g_mock.wait_observed_alive);
	assert_int_equal(g_mock.wait_observed_region_refs, 1);
	assert_true(g_mock.wait_observed_trap_active);
	assert_false(lxp_trap_active());
	assert_false(p->alive);
	assert_int_equal(g_lxp_rt.regions[1].refs, 0);
}

static void test_spawn_callbacks_receive_explicit_mode_and_published_slot(void **state)
{
	(void)state;
	struct lxp_resume_ctx ctx;
	lxp_guest_launch_t launch;
	memset(&ctx, 0, sizeof(ctx));
	memset(&launch, 0, sizeof(launch));
	for (unsigned i = 0; i < 16; i++)
		launch.r[i] = 0x100u + i;
	launch.xpsr = 1u << 24;
	launch.copied_text_base = 0x20000000u;
	launch.copied_text_size = 0x1000u;
	struct lxp_resume_ctx translated;
	lxp_resume_ctx_from_launch(&translated, &launch);
	for (unsigned i = 0; i < 8; i++)
		assert_int_equal(translated.r4_11[i], launch.r[4u + i]);
	assert_int_equal(translated.r12, launch.r[12]);
	assert_int_equal(translated.sp, launch.r[13]);
	assert_int_equal(translated.lr, launch.r[14]);
	assert_int_equal(translated.pc, launch.r[15]);
	assert_int_equal(translated.r1, launch.r[1]);
	assert_int_equal(translated.r2, launch.r[2]);
	assert_int_equal(translated.r3, launch.r[3]);
	assert_int_equal(translated.xpsr, launch.xpsr);

	/* A fresh image launch observes its dispatch capability before the mock
	 * engine can make a native task runnable. */
	const int launch_slot = 1;
	lxp_deferred_slot_reassign(launch_slot);
	g_lxp_rt.slots[launch_slot].proc.alive = 1;
	uint32_t launch_generation = lxp_slot_generation(launch_slot);
	assert_int_equal(lxp_coordinator_launch_slot(launch_slot, 0, &launch), LXP_OK);
	assert_int_equal(g_mock.launch_calls, 1);
	assert_int_equal(g_mock.launch_sidx, launch_slot);
	assert_int_equal(g_mock.launch_generation, launch_generation);
	assert_true(g_mock.launch_observed_runnable);
	assert_int_equal(g_mock.launch_observed_host_state, SLOT_STARTING);
	assert_memory_equal(&g_mock.launch, &launch, sizeof(launch));
	assert_int_equal(g_lxp_rt.slots[launch_slot].host_state, SLOT_RUNNING);

	/* A captured fork child has no native task yet and is explicitly START,
	 * rather than being inferred from the absence of a handle. */
	const int start_slot = 2;
	lxp_deferred_slot_reassign(start_slot);
	g_lxp_rt.slots[start_slot].proc.alive = 1;
	uint32_t start_generation = lxp_slot_generation(start_slot);
	assert_int_equal(lxp_coordinator_resume_slot(start_slot, 0, &ctx, 7), LXP_OK);
	assert_int_equal(g_mock.resume_mode, LXP_SPAWN_RESUME_START);
	assert_int_equal(g_mock.resume_generation, start_generation);
	assert_true(g_mock.resume_observed_runnable);
	assert_int_equal(g_mock.resume_observed_host_state, SLOT_STARTING);
	assert_int_equal(g_lxp_rt.slots[start_slot].host_state, SLOT_RUNNING);

	/* A task suspended by park_slot is explicitly PARKED and sees the same
	 * pre-published dispatch capability before the engine wakes it. */
	const int parked_slot = 3;
	make_valid_running_slot(parked_slot, 3);
	assert_int_equal(lxp_coordinator_park_slot(parked_slot), LXP_OK);
	uint32_t parked_generation = lxp_slot_generation(parked_slot);
	assert_int_equal(lxp_coordinator_resume_slot(parked_slot, 3, &ctx, 9), LXP_OK);
	assert_int_equal(g_mock.resume_mode, LXP_SPAWN_RESUME_PARKED);
	assert_int_equal(g_mock.resume_generation, parked_generation);
	assert_true(g_mock.resume_observed_runnable);
	assert_int_equal(g_mock.resume_observed_host_state, SLOT_RESUMING);
	assert_int_equal(g_lxp_rt.slots[parked_slot].host_state, SLOT_RUNNING);
}

static void test_completion_owner_requires_parked_slot(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_slot_ref_t ref = lxp_slot_ref_at(0);

	assert_int_equal(lxp_coordinator_complete_slot(ref, 7), -LXP_EAGAIN);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_RUNNING);

	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
	assert_int_equal(lxp_coordinator_complete_slot(ref, 7), LXP_OK);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, 7);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_RUNNING);
}

static void test_park_failure_aborts_and_kills_slot(void **state)
{
	(void)state;
	const int s = 2;
	lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
	p->alive = 1;
	g_lxp_rt.slots[s].runnable = 1;
	g_lxp_rt.slots[s].host_state = SLOT_RUNNING;
	lxp_deferred_slot_reassign(s);
	uint32_t generation = g_lxp_rt.slots[s].generation;
	g_mock.park_failures = 1;

	assert_int_equal(lxp_coordinator_park_slot(s), -LXP_EIO);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.park_generation, generation);
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_mock.abort_generation, generation);
	assert_int_equal(g_lxp_rt.slots[s].host_state, SLOT_DEAD);
	assert_false(g_lxp_rt.slots[s].runnable);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_reason, LXP_EXIT_REASON_HOST_TRANSITION);
	assert_true(lxp_primary_slot_pending(s));
}

static void test_resume_failure_aborts_parked_slot(void **state)
{
	(void)state;
	const int s = 3;
	lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
	p->alive = 1;
	g_lxp_rt.slots[s].host_state = SLOT_PARKED;
	lxp_deferred_slot_reassign(s);
	uint32_t generation = g_lxp_rt.slots[s].generation;
	g_mock.resume_failures = 1;

	assert_int_equal(lxp_coordinator_resume_slot(s, 0, &g_lxp_rt.slots[s].resume, 42),
			 -LXP_EIO);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_generation, generation);
	assert_int_equal(g_mock.resume_mode, LXP_SPAWN_RESUME_PARKED);
	assert_true(g_mock.resume_observed_runnable);
	assert_int_equal(g_mock.resume_observed_host_state, SLOT_RESUMING);
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_mock.abort_generation, generation);
	assert_int_equal(g_lxp_rt.slots[s].host_state, SLOT_DEAD);
	assert_false(g_lxp_rt.slots[s].runnable);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_reason, LXP_EXIT_REASON_HOST_TRANSITION);
}

static void test_abort_failure_retains_slot_until_retry(void **state)
{
	(void)state;
	const int s = 4;
	lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
	p->alive = 1;
	g_lxp_rt.slots[s].runnable = 1;
	g_lxp_rt.slots[s].host_state = SLOT_RUNNING;
	lxp_deferred_slot_reassign(s);
	uint32_t generation = g_lxp_rt.slots[s].generation;
	g_mock.abort_failures = 1;

	assert_int_equal(lxp_coordinator_abort_slot(s), -LXP_EIO);
	assert_int_equal(g_lxp_rt.slots[s].host_state, SLOT_FAILED);
	assert_true(g_lxp_rt.slots[s].runnable);
	assert_true(p->alive);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_reason, LXP_EXIT_REASON_HOST_TRANSITION);
	assert_int_equal(g_mock.abort_generation, generation);

	assert_int_equal(lxp_coordinator_abort_slot(s), LXP_OK);
	assert_int_equal(g_lxp_rt.slots[s].host_state, SLOT_DEAD);
	assert_false(g_lxp_rt.slots[s].runnable);
	assert_true(p->alive); /* Linux ownership is released only by EV_EXIT. */
}

/* lxp_trap_dispatch used to read TCSETS' arg before lxp_syscall reached the console handler.
 * Because dispatch runs privileged, a guest could point it at host memory or MMIO and fault the
 * RTOS even if the handler itself performed access_ok. Keep this at the trap-dispatch level, not
 * merely in the direct-syscall conformance suite. */
static void test_dispatch_rejects_bad_tcsets_pointer(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->mm->region_lo = 0x1000u;
	proc->mm->region_hi = 0x2000u;
	proc->mm->pool_lo = proc->mm->pool_hi = 0;

	const uint32_t cmds[] = {LXP_TCSETS, LXP_TCSETSW, LXP_TCSETSF};
	const lxp_tty_t defaults = LXP_TTY_DEFAULTS;
	for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
		struct lxp_frame f;
		memset(&f, 0, sizeof(f));
		f.r[0] = 0; /* stdin is a console fd */
		f.r[1] = cmds[i];
		f.r[2] = 0x20000000u; /* mapped host SRAM on target; outside this guest */
		f.r[7] = LXP_NR_ioctl;
		lxp_console_reset();
		g_lxp_rt.slots[0].runnable = 1;
		g_lxp_rt.slots[0].host_state = SLOT_RUNNING;

		assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &f), LXP_OK);

		assert_int_equal(lxp_deferred_state_load(0), DEFER_READY);
		assert_int_equal(g_mock.event_posts, (int)i + 1);
		lxp_execute_deferred(0);
		assert_int_equal(g_mock.resume_r0, -LXP_EFAULT);
		/* invalid input cannot alter console state */
		assert_memory_equal(&lxp_console_tty()->termios, &defaults.termios,
				    sizeof(defaults.termios));
	}
}

/* Pointer-free identity calls stay in the bounded top half; unknown/new calls
 * default to the deferred mailbox and therefore cannot accidentally run in SVC. */
static void test_dispatch_class_defaults_deferred(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->pid = 42;
	p->group->tgid = 42;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpid;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &f), LXP_OK);
	assert_int_equal(f.r[0], 42);
	assert_int_equal(g_mock.event_posts, 0);
	assert_int_equal(lxp_deferred_state_load(0), DEFER_IDLE);

	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	f.xpsr = 0xa8000000u | (1u << 24); /* NZCV + Thumb survive park/resume */
	struct lxp_fp_context fp;
	memset(&fp, 0, sizeof(fp));
	for (int i = 0; i < 32; i++)
		fp.s[i] = 0x3f000000u + (uint32_t)i;
	fp.fpscr = 0x01c00000u;
	fp.active = 1;
	f.fp = &fp;
	g_lxp_rt.slots[0].runnable = 1;
	g_lxp_rt.slots[0].host_state = SLOT_RUNNING;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &f), LXP_OK);
	assert_int_equal(lxp_deferred_state_load(0), DEFER_READY);
	assert_int_equal(g_mock.event_posts, 1);
	lxp_execute_deferred(0);
	assert_int_equal(g_mock.resume_r0, -LXP_ENOSYS);
	assert_int_equal(g_mock.coord_map_calls, 1);
	assert_int_equal(g_mock.coord_map_region, 0);
	assert_null(p->guest_view);
	assert_int_equal(g_mock.resume_xpsr, f.xpsr);
	assert_memory_equal(&g_mock.resume_fp, &fp, sizeof(fp));
}

/* Distinct slots have distinct fixed mailboxes. Both may queue while neither
 * bottom half has completed; servicing one cannot overwrite or lose the other. */
static void test_deferred_requests_are_per_slot(void **state)
{
	(void)state;
	for (int s = 0; s < 2; s++) {
		make_valid_running_slot(s, s);
		g_lxp_rt.slots[s].proc.pid = s + 1;
		struct lxp_frame f;
		memset(&f, 0, sizeof(f));
		f.r[7] = 900u + (uint32_t)s;
		assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(s), &f), LXP_OK);
	}
	assert_int_equal(g_mock.event_posts, 2);
	assert_int_equal(lxp_deferred_state_load(0), DEFER_READY);
	assert_int_equal(lxp_deferred_state_load(1), DEFER_READY);

	lxp_execute_deferred(1);
	assert_int_equal(lxp_deferred_state_load(0), DEFER_READY);
	assert_int_equal(lxp_deferred_state_load(1), DEFER_IDLE);
	lxp_execute_deferred(0);
	assert_int_equal(g_mock.resume_calls, 2);
	assert_int_equal(g_mock.resume_order[0], 1);
	assert_int_equal(g_mock.resume_order[1], 0);
}

/* A stale event from an old slot generation is discarded without aborting or
 * resuming the new occupant of that slot. */
static void test_deferred_generation_rejects_stale_work(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	lxp_trap_dispatch(&f, p);
	lxp_slot_ref_t old_owner = g_lxp_rt.slots[0].deferred.owner;
	lxp_deferred_slot_reassign(0);
	g_lxp_rt.slots[0].deferred.owner = old_owner;
	lxp_deferred_state_store(0, DEFER_READY); /* delayed event from the prior occupant */
	g_lxp_rt.slots[0].runnable = 1;
	g_lxp_rt.slots[0].host_state = SLOT_RUNNING;

	lxp_execute_deferred(0);

	assert_int_equal(lxp_deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].runnable, 1); /* the replacement task was untouched */
}

/* One slot cannot overwrite its outstanding request, even if a broken seam
 * attempts to dispatch that slot again before the bottom half claims it. */
static void test_deferred_same_slot_rejects_overwrite(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->alive = 1;
	lxp_deferred_slot_reassign(0);
	struct lxp_frame first, second;
	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	first.r[7] = 998;
	second.r[7] = 999;
	lxp_trap_dispatch(&first, p);
	lxp_trap_dispatch(&second, p);
	assert_int_equal((int32_t)second.r[0], -LXP_EAGAIN);
	assert_int_equal(g_mock.event_posts, 1);
	assert_int_equal((int32_t)g_lxp_rt.slots[0].resume.r4_11[3], 998);
}

/* Reaping and then reusing a slot is a stronger boundary than merely advancing
 * its mailbox generation: no late completion may touch the new process. */
static void test_reused_slot_ignores_late_completion_from_dead_generation(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	struct lxp_frame frame;
	memset(&frame, 0, sizeof(frame));
	frame.r[7] = 999;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	lxp_slot_ref_t stale_owner = g_lxp_rt.slots[0].deferred.owner;

	lxp_proc_t *old = &g_lxp_rt.slots[0].proc;
	assert_int_equal(lxp_intent_exit(old, 0), LXP_OK);
	old->exit_status = 0;
	lxp_primary_slot_clear(0);
	(void)lxp_handle_exit(0);
	assert_false(old->alive);
	assert_int_equal(g_lxp_rt.regions[0].refs, 0);

	assert_int_equal(lxp_proc_init(old, &g_mock_arenas[0], 0), 0);
	make_valid_running_slot(0, 0);
	lxp_slot_ref_t replacement = lxp_slot_ref_at(0);
	assert_false(lxp_slot_ref_equal(stale_owner, replacement));
	int resumes = g_mock.resume_calls;
	int aborts = g_mock.abort_calls;

	g_lxp_rt.slots[0].deferred.owner = stale_owner;
	lxp_deferred_state_store(0, DEFER_READY);
	lxp_execute_deferred(0);

	assert_int_equal(lxp_deferred_state_load(0), DEFER_IDLE);
	assert_true(lxp_slot_ref_equal(replacement, lxp_slot_ref_at(0)));
	assert_true(g_lxp_rt.slots[0].proc.alive);
	assert_true(g_lxp_rt.slots[0].runnable);
	assert_int_equal(g_mock.resume_calls, resumes);
	assert_int_equal(g_mock.abort_calls, aborts);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

enum protocol_command {
	PROTOCOL_PARK_TIMER,
	PROTOCOL_TIMEOUT,
	PROTOCOL_SIGNAL_TERM,
	PROTOCOL_EXIT_COMMIT,
	PROTOCOL_REUSE_SLOT,
	PROTOCOL_STALE_COMPLETION,
	PROTOCOL_COMMAND_COUNT,
};

enum protocol_phase {
	PROTOCOL_RUNNING,
	PROTOCOL_PARKED,
	PROTOCOL_EXIT_PENDING,
	PROTOCOL_DEAD,
	PROTOCOL_REUSED,
};

struct protocol_model {
	enum protocol_phase phase;
	lxp_slot_ref_t first_owner;
};

static int protocol_apply(struct protocol_model *model, enum protocol_command command)
{
	g_lxp_rt.cfg = &g_mock_cfg;
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;

	switch (command) {
	case PROTOCOL_PARK_TIMER:
		if (model->phase != PROTOCOL_RUNNING)
			return 0;
		assert_int_equal(lxp_wait_begin(proc,
						&(lxp_wait_t){
							.kind = LXP_WAIT_TIMER,
							.data.timer.deadline_us = 10,
						}),
				 LXP_OK);
		assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);
		model->phase = PROTOCOL_PARKED;
		break;
	case PROTOCOL_TIMEOUT:
		if (model->phase != PROTOCOL_PARKED)
			return 0;
		assert_int_equal(lxp_wait_timeout(proc, LXP_WAIT_TIMER), LXP_OK);
		assert_int_equal(
			lxp_coordinator_resume_slot(0, 0, &g_lxp_rt.slots[0].resume, 0),
			LXP_OK);
		model->phase = PROTOCOL_RUNNING;
		break;
	case PROTOCOL_SIGNAL_TERM:
		if (model->phase != PROTOCOL_PARKED)
			return 0;
		proc->pending_sigs = lxp_sig_bit(LXP_SIGTERM);
		assert_true(lxp_scan_blocked(1).progress);
		assert_int_equal(proc->wait.kind, LXP_WAIT_NONE);
		assert_int_equal(proc->intent.kind, LXP_INTENT_EXIT);
		model->phase = PROTOCOL_EXIT_PENDING;
		break;
	case PROTOCOL_EXIT_COMMIT:
		if (model->phase != PROTOCOL_EXIT_PENDING)
			return 0;
		lxp_primary_slot_clear(0);
		(void)lxp_handle_exit(0);
		assert_false(proc->alive);
		model->phase = PROTOCOL_DEAD;
		break;
	case PROTOCOL_REUSE_SLOT:
		if (model->phase != PROTOCOL_DEAD)
			return 0;
		assert_int_equal(lxp_proc_init(proc, &g_mock_arenas[0], 0), 0);
		make_valid_running_slot(0, 0);
		model->phase = PROTOCOL_REUSED;
		break;
	case PROTOCOL_STALE_COMPLETION:
		if (model->phase != PROTOCOL_REUSED)
			return 0;
		g_lxp_rt.slots[0].deferred.owner = model->first_owner;
		lxp_deferred_state_store(0, DEFER_READY);
		lxp_execute_deferred(0);
		assert_int_equal(lxp_deferred_state_load(0), DEFER_IDLE);
		assert_true(g_lxp_rt.slots[0].runnable);
		break;
	default:
		fail_msg("invalid protocol command %d", command);
	}
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
	return 1;
}

/* Enumerate every five-command word over the lifecycle alphabet. Illegal
 * transitions stop that word; every transition which is applied is checked
 * against the independent world validator immediately. */
static void test_generated_protocol_sequences_preserve_world(void **state)
{
	(void)state;
	enum { PROTOCOL_DEPTH = 5 };
	unsigned coverage = 0;
	unsigned words = 1;
	for (int i = 0; i < PROTOCOL_DEPTH; i++)
		words *= PROTOCOL_COMMAND_COUNT;

	for (unsigned word = 0; word < words; word++) {
		assert_int_equal(reset_state(NULL), 0);
		make_valid_running_slot(0, 0);
		assert_int_equal(lxp_validate_world(NULL), LXP_OK);
		struct protocol_model model = {
			.phase = PROTOCOL_RUNNING,
			.first_owner = lxp_slot_ref_at(0),
		};
		unsigned encoded = word;
		for (int step = 0; step < PROTOCOL_DEPTH; step++) {
			enum protocol_command command = encoded % PROTOCOL_COMMAND_COUNT;
			encoded /= PROTOCOL_COMMAND_COUNT;
			if (!protocol_apply(&model, command))
				break;
			coverage |= 1u << command;
		}
	}
	assert_int_equal(coverage, (1u << PROTOCOL_COMMAND_COUNT) - 1u);
}

static int console_not_ready(void *ctx)
{
	(void)ctx;
	return 0;
}

static void test_blocked_scan_reports_wait_policy(void **state)
{
	(void)state;
	g_lxp_rt.cfg = &g_mock_cfg;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->console_poll = console_not_ready;
	assert_int_equal(lxp_wait_begin(proc,
					&(lxp_wait_t){
						.kind = LXP_WAIT_CONSOLE,
						.data.io.buffer = (uintptr_t)g_mock_regions[0],
						.data.io.length = 1,
					}),
			 LXP_OK);
	assert_int_equal(lxp_coordinator_park_slot(0), LXP_OK);

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	/* The coordinator decides whether this class needs polling from the
	 * run-scoped subscription; the scan reports the class without conflating it
	 * with generic poll-only waits. */
	assert_int_equal(scan.wait_policy, LXP_BLOCKED_WAIT_CONSOLE);
	assert_false(scan.progress);
}

/* A process outside the slot table, the way a stale record looks to teardown: nothing
 * closes its descriptors, so only the pool reset can free what they hold. */
static void orphan_proc_init(lxp_proc_t *p, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_mock_regions[1], sizeof(g_mock_regions[1])),
			 LXP_OK);
	assert_int_equal(lxp_proc_init(p, arena, 0), 0);
	p->mm->region_lo = 1;
	p->mm->region_hi = UINTPTR_MAX;
}

static long orphan_eventfd(lxp_proc_t *p)
{
	return lxp_syscall(p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0);
}

static long orphan_proc_open(lxp_proc_t *p)
{
	return lxp_syscall(p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t) "/proc/uptime", 0, 0,
			   0, 0);
}

/* Teardown frees every pool a descriptor references, so bookkeeping a run leaves
 * behind (descriptions nobody closed) cannot exhaust the next run's eventfd counters or
 * /proc contents. */
static void test_teardown_resets_descriptor_pools(void **state)
{
	(void)state;
	long (*const opens[])(lxp_proc_t *) = {orphan_eventfd, orphan_proc_open};
	for (size_t k = 0; k < sizeof(opens) / sizeof(opens[0]); k++) {
		lxp_arena_t arena;
		lxp_proc_t holder, probe;
		orphan_proc_init(&holder, &arena);
		int held = 0;
		while (held < LXP_MAX_FDS && opens[k](&holder) >= 0)
			held++;
		/* the pool ran out, not the table */
		assert_true(held > 0 && held < LXP_MAX_FDS - 3);
		orphan_proc_init(&probe, &arena);
		assert_int_equal(opens[k](&probe), -LXP_EMFILE);

		lxp_coordinator_teardown_all();

		orphan_proc_init(&probe, &arena);
		assert_true(opens[k](&probe) >= 0);
		lxp_coordinator_teardown_all();
	}
}

/* Blocking handlers hand ownership to the existing wait state machine. The
 * coordinator suspends the existing task before executing the host syscall and
 * leaves it parked when the syscall establishes a wait condition. */
static void test_deferred_blocking_handoff_keeps_parked_task(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->console_poll = console_not_ready;

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[0] = 0; /* no pollfd array: this is a pure timeout sleep */
	f.r[1] = 0;
	f.r[2] = 1000;
	f.r[7] = LXP_NR_poll;
	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &f), LXP_OK);
	lxp_execute_deferred(0);

	assert_int_equal(lxp_deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(p->wait.kind, LXP_WAIT_TIMER);
	assert_true(lxp_primary_slot_pending(0));
	assert_int_equal(g_lxp_rt.slots[0].runnable, 0);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
}

int test_coord_lifecycle_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_typed_intent_transitions_are_exclusive, reset_state),
		cmocka_unit_test_setup(test_exit_intent_supersedes_deferred_work, reset_state),
		cmocka_unit_test_setup(test_typed_wait_transitions_cover_every_kind, reset_state),
		cmocka_unit_test_setup(
			test_slot_references_reject_recycled_incarnations_and_skip_zero,
			reset_state),
		cmocka_unit_test_setup(test_resume_context_view_rejects_recycled_slot, reset_state),
		cmocka_unit_test_setup(test_fault_publication_rejects_stale_slot_reference,
				       reset_state),
		cmocka_unit_test_setup(test_priority_syscalls_update_bounded_guest_weights,
				       reset_state),
		cmocka_unit_test_setup(test_coordinator_socket_wait_uses_readiness_events,
				       reset_state),
		cmocka_unit_test_setup(test_coordinator_service_classes_are_weighted_and_aged,
				       reset_state),
		cmocka_unit_test_setup(test_claim_slot_event_priority_and_consumption, reset_state),
		cmocka_unit_test_setup(
			test_coordinator_claim_rotates_fairly_and_discards_stale_hints,
			reset_state),
		cmocka_unit_test_setup(test_primary_wait_handler_applies_park_outcome, reset_state),
		cmocka_unit_test_setup(test_primary_handler_rejects_out_of_range_slot, reset_state),
		cmocka_unit_test_setup(test_blocked_timer_handler_resumes_expired_wait,
				       reset_state),
		cmocka_unit_test_setup(test_dispatch_rejects_bad_tcsets_pointer, reset_state),
		cmocka_unit_test_setup(test_teardown_resets_descriptor_pools, reset_state),
		cmocka_unit_test_setup(test_dispatch_class_defaults_deferred, reset_state),
		cmocka_unit_test_setup(test_deferred_requests_are_per_slot, reset_state),
		cmocka_unit_test_setup(test_deferred_generation_rejects_stale_work, reset_state),
		cmocka_unit_test_setup(test_deferred_same_slot_rejects_overwrite, reset_state),
		cmocka_unit_test_setup(
			test_reused_slot_ignores_late_completion_from_dead_generation, reset_state),
		cmocka_unit_test_setup(test_generated_protocol_sequences_preserve_world,
				       reset_state),
		cmocka_unit_test_setup(test_blocked_scan_reports_wait_policy, reset_state),
		cmocka_unit_test_setup(test_deferred_blocking_handoff_keeps_parked_task,
				       reset_state),
		cmocka_unit_test_setup(test_teardown_releases_every_slot_resource, reset_state),
		cmocka_unit_test_setup(test_teardown_quiesces_before_releasing_resources,
				       reset_state),
		cmocka_unit_test_setup(
			test_spawn_callbacks_receive_explicit_mode_and_published_slot, reset_state),
		cmocka_unit_test_setup(test_completion_owner_requires_parked_slot, reset_state),
		cmocka_unit_test_setup(test_park_failure_aborts_and_kills_slot, reset_state),
		cmocka_unit_test_setup(test_resume_failure_aborts_parked_slot, reset_state),
		cmocka_unit_test_setup(test_abort_failure_retains_slot_until_retry, reset_state),
	};
	return cmocka_run_group_tests_name("coordinator: lifecycle", tests, NULL, NULL);
}
