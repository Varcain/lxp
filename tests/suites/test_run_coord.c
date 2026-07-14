/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Host unit tests for the run-loop coordinator (src/lxp_run.c). The coordinator is
 * excluded from the main test binary — its 32-bit-target pointer casts warn on a
 * 64-bit host, and its OS-service symbols would clash with tests/stub_lnx_run.c — so
 * it has only ever been exercised end-to-end on QEMU (M1..M4). That leaves its
 * process-bookkeeping state machine (zombie reaping, wait-status encoding, region
 * liveness) untested at the unit level.
 *
 * This dedicated binary #includes the coordinator TU whole to reach its static
 * helpers, and drives them against a mock engine (lxp_os_ops_t) with NO guest
 * threads: the tests set up g_lxp_proc[] by hand, call the helper, and assert on the
 * recorded engine calls and the resulting process state.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

/* Pull in the coordinator: this defines g_lxp_proc / g_lxp_used / g_ctx and the
 * OS-service symbols, and exposes the static helpers (reap_to_parent, region_free). */
#include "lxp_run.c"

/* ---- mock engine ------------------------------------------------------------ */
static struct {
	int resume_calls;
	int resume_sidx;
	long resume_r0;
	uint32_t resume_xpsr;
	int resume_order[LXP_NSLOT];
	long resume_results[LXP_NSLOT];
	int abort_calls;
	int abort_sidx;
	int event_posts;
} g_mock;

static uint8_t *mock_region(int ridx)
{
	(void)ridx;
	return NULL;
}
static void mock_spawn_resume(int sidx, int ridx, const struct lxp_resume_ctx *c, long r0)
{
	(void)ridx;
	(void)c;
	g_mock.resume_calls++;
	g_mock.resume_sidx = sidx;
	g_mock.resume_r0 = r0;
	g_mock.resume_xpsr = c->xpsr;
	if (g_mock.resume_calls <= LXP_NSLOT) {
		g_mock.resume_order[g_mock.resume_calls - 1] = sidx;
		g_mock.resume_results[g_mock.resume_calls - 1] = r0;
	}
	g_lxp_used[sidx] = 1;
}
static void mock_abort_slot(int sidx)
{
	g_mock.abort_calls++;
	g_mock.abort_sidx = sidx;
	g_lxp_used[sidx] = 0;
}
static void mock_event_post(void)
{
	g_mock.event_posts++;
}

static const lxp_os_ops_t g_mock_eng = {
	.region = mock_region,
	.spawn_resume = mock_spawn_resume,
	.abort_slot = mock_abort_slot,
	.event_post = mock_event_post,
};

static int reset_state(void **state)
{
	(void)state;
	memset(g_lxp_proc, 0, sizeof(g_lxp_proc));
	memset(g_lxp_used, 0, sizeof(g_lxp_used));
	memset(g_deferred, 0, sizeof(g_deferred));
	memset(g_slot_generation, 0, sizeof(g_slot_generation));
	memset(&g_mock, 0, sizeof(g_mock));
	g_eng = &g_mock_eng;
	g_cfg = NULL;
	g_pending_sig = 0;
	g_tty_isig = 1;
	return 0;
}

/* ---- wait-status encoding --------------------------------------------------- */
static void test_encode_wstatus(void **state)
{
	(void)state;
	/* Normal exit: WIFEXITED, code in bits 8-15. */
	assert_int_equal(lxp_encode_wstatus(0), 0);
	assert_int_equal(lxp_encode_wstatus(42), 42 << 8);
	assert_int_equal(lxp_encode_wstatus(255), 255 << 8);
	/* Our "128 + signal" kill convention: WIFSIGNALED, signal in the low 7 bits. */
	assert_int_equal(lxp_encode_wstatus(128 + 9), 9);   /* SIGKILL */
	assert_int_equal(lxp_encode_wstatus(128 + 15), 15); /* SIGTERM */
	assert_int_equal(lxp_encode_wstatus(128 + 31), 31); /* highest signal delivered */
	/* Boundaries: 128 itself and >128+31 are ordinary exit codes, not signals. */
	assert_int_equal(lxp_encode_wstatus(128), 128 << 8);
	assert_int_equal(lxp_encode_wstatus(160), 160 << 8);
}

/* ---- reap_to_parent: parent blocked in wait4 -------------------------------- */
static void test_reap_wakes_blocking_parent(void **state)
{
	(void)state;
	int status = -1;
	/* slot 0 = parent pid 1, blocked in wait4 for any child, with one live child. */
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = 1;
	g_lxp_proc[0].wait_pending = 1;
	g_lxp_proc[0].wait_pid = -1; /* any child */
	g_lxp_proc[0].wait_status_p = (uintptr_t)&status;

	reap_to_parent(&g_mock_eng, /*ppid*/ 1, /*cpid*/ 7, /*status*/ 42);

	/* Resumed once, returning the reaped pid; *status = WIFEXITED(42); child accounted. */
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, 0);
	assert_int_equal(g_mock.resume_r0, 7);
	assert_int_equal(status, 42 << 8);
	assert_int_equal(g_lxp_proc[0].wait_pending, 0);
	assert_int_equal(g_lxp_proc[0].live_children, 0);
	assert_int_equal(g_lxp_proc[0].child_count, 0); /* woken, not queued */
	assert_int_equal(g_mock.abort_calls, 0);	/* g_lxp_used[0]==0: no spin thread */
}

/* A signal-killed child (128 + signo) wakes the waiter as WIFSIGNALED. */
static void test_reap_signaled_child_status(void **state)
{
	(void)state;
	int status = -1;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = 1;
	g_lxp_proc[0].wait_pending = 1;
	g_lxp_proc[0].wait_pid = -1;
	g_lxp_proc[0].wait_status_p = (uintptr_t)&status;
	g_lxp_used[0] = 1; /* a parked-waiter spin thread must be aborted before resume */

	reap_to_parent(&g_mock_eng, 1, 7, 128 + 15 /* SIGTERM */);

	assert_int_equal(status, 15); /* low 7 bits = the signal */
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_mock.abort_sidx, 0);
	assert_int_equal(g_mock.resume_calls, 1);
}

/* A wait4 targeting a specific other pid is NOT woken by an unrelated child. */
static void test_reap_specific_pid_not_woken(void **state)
{
	(void)state;
	int status = -1;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = 2;
	g_lxp_proc[0].wait_pending = 1;
	g_lxp_proc[0].wait_pid = 9; /* waiting specifically for pid 9 */
	g_lxp_proc[0].wait_status_p = (uintptr_t)&status;

	reap_to_parent(&g_mock_eng, 1, 7, 0); /* pid 7 exits, not 9 */

	/* Not resumed; the zombie is queued and SIGCHLD raised; still one live child left. */
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_proc[0].wait_pending, 1);
	assert_int_equal(g_lxp_proc[0].child_count, 1);
	assert_int_equal(g_lxp_proc[0].child_pid[0], 7);
	assert_int_equal(g_lxp_proc[0].live_children, 1);
	assert_true((g_lxp_proc[0].pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) != 0);
}

/* ---- reap_to_parent: parent not waiting → zombie queued + SIGCHLD ----------- */
static void test_reap_queues_zombie(void **state)
{
	(void)state;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = 1;
	/* wait_pending == 0: the parent is off in select()/poll(), not blocking in wait4. */

	reap_to_parent(&g_mock_eng, 1, 7, 3);

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_proc[0].child_count, 1);
	assert_int_equal(g_lxp_proc[0].child_pid[0], 7);
	assert_int_equal(g_lxp_proc[0].child_status[0], 3); /* raw code; wait4 encodes on reap */
	assert_int_equal(g_lxp_proc[0].live_children, 0);
	assert_true((g_lxp_proc[0].pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) != 0);
}

/* The zombie queue is bounded (LXP_MAX_CHILD): an overflow is dropped, not overrun. */
static void test_reap_zombie_queue_full(void **state)
{
	(void)state;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = LXP_MAX_CHILD + 1;
	g_lxp_proc[0].child_count = LXP_MAX_CHILD; /* already full */

	reap_to_parent(&g_mock_eng, 1, 99, 0);

	assert_int_equal(g_lxp_proc[0].child_count, LXP_MAX_CHILD); /* clamped, no overrun */
	assert_int_equal(g_lxp_proc[0].live_children, LXP_MAX_CHILD); /* still decremented */
}

/* An exit reported for a parent that no longer exists is a safe no-op. */
static void test_reap_unknown_parent(void **state)
{
	(void)state;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;

	reap_to_parent(&g_mock_eng, /*ppid*/ 42, 7, 0); /* no proc has pid 42 */

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_lxp_proc[0].child_count, 0);
}

/* ---- region_free: owner table AND liveness both gate reuse ------------------ */
static void test_region_free(void **state)
{
	(void)state;
	int rowner[LXP_NREG];
	for (int r = 0; r < LXP_NREG; r++)
		rowner[r] = -1;

	/* All regions unowned and no live proc → every region is free. */
	assert_true(region_free(0, rowner));
	assert_true(region_free(1, rowner));

	/* An owned region is not free. */
	rowner[1] = 3;
	assert_false(region_free(1, rowner));

	/* Owner table says free (rowner<0), but a live proc still runs there → NOT free.
	 * This is the anti-trample guard against vfork accounting drift. */
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].region = 2;
	assert_false(region_free(2, rowner));

	/* A dead proc's stale region entry does not hold the region. */
	g_lxp_proc[0].alive = 0;
	assert_true(region_free(2, rowner));
}

/* ---- futex: co-runner gate + FUTEX_WAKE bookkeeping ------------------------- */
/* futex_has_corunner: a FUTEX_WAIT only parks when another live thread shares the region
 * (else nobody could ever wake it). */
static void test_futex_has_corunner(void **state)
{
	(void)state;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].region = 2;
	assert_false(futex_has_corunner(&g_lxp_proc[0])); /* alone in region 2 */

	g_lxp_proc[1].alive = 1;
	g_lxp_proc[1].region = 3;
	assert_false(futex_has_corunner(&g_lxp_proc[0])); /* a live proc, but a different region */

	g_lxp_proc[2].alive = 1;
	g_lxp_proc[2].region = 2;
	assert_true(futex_has_corunner(&g_lxp_proc[0])); /* a co-runner shares region 2 */

	g_lxp_proc[2].alive = 0;
	assert_false(futex_has_corunner(&g_lxp_proc[0])); /* it exited -> no longer a co-runner */
}

/* FUTEX_WAKE marks up to `val` waiters queued on the same uaddr (and no others). The
 * addresses here are only compared, never dereferenced, so plain integers stand in for the
 * 32-bit guest pointers (the deref path is covered on-target by the M5 QEMU guest). */
static void test_futex_wake_marks_waiters(void **state)
{
	(void)state;
	const uint32_t uaddr = 0x2000, other = 0x3000;
	g_lxp_proc[1].alive = 1;
	g_lxp_proc[1].futex_wait = 1;
	g_lxp_proc[1].futex_uaddr = uaddr;
	g_lxp_proc[2].alive = 1;
	g_lxp_proc[2].futex_wait = 1;
	g_lxp_proc[2].futex_uaddr = uaddr;
	g_lxp_proc[3].alive = 1;
	g_lxp_proc[3].futex_wait = 1;
	g_lxp_proc[3].futex_uaddr = other; /* a different futex; must be untouched */

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[0] = uaddr;
	f.r[1] = 1; /* FUTEX_WAKE */
	f.r[2] = 1; /* wake at most one */
	lxp_futex(&f, &g_lxp_proc[0], 0);

	assert_int_equal(f.r[0], 1); /* reported one woken */
	assert_int_equal(g_lxp_proc[1].futex_woken + g_lxp_proc[2].futex_woken, 1); /* exactly one */
	assert_int_equal(g_lxp_proc[3].futex_woken, 0); /* other uaddr not disturbed */

	/* A second WAKE(all) picks up the remaining waiter on uaddr, still not the other. */
	memset(&f, 0, sizeof(f));
	f.r[0] = uaddr;
	f.r[1] = 1;
	f.r[2] = 0x7fffffff;
	lxp_futex(&f, &g_lxp_proc[0], 0);
	assert_int_equal(f.r[0], 1); /* the one still-parked waiter */
	assert_int_equal(g_lxp_proc[1].futex_woken, 1);
	assert_int_equal(g_lxp_proc[2].futex_woken, 1);
	assert_int_equal(g_lxp_proc[3].futex_woken, 0);
}

/* pending_deliverable returns the lowest-numbered UNBLOCKED pending signal and leaves blocked
 * ones set — so the mask is honored (a blocked signal is deferred, #4) and no pending signal is
 * lost to a single slot when another arrives (#5). SIGKILL/SIGSTOP are never blocked. */
static void test_pending_deliverable(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->sig_blocked = lxp_sig_bit(LXP_SIGTERM); /* SIGTERM blocked, SIGINT not */
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM) | lxp_sig_bit(LXP_SIGINT);
	assert_int_equal(pending_deliverable(p), LXP_SIGINT); /* skips the blocked SIGTERM */

	p->pending_sigs &= ~lxp_sig_bit(LXP_SIGINT);	 /* consume SIGINT */
	assert_int_equal(pending_deliverable(p), 0);	 /* SIGTERM still blocked -> nothing */
	assert_true(p->pending_sigs & lxp_sig_bit(LXP_SIGTERM)); /* ...but not lost */
	p->sig_blocked = 0;
	assert_int_equal(pending_deliverable(p), LXP_SIGTERM); /* unblocked -> now deliverable */

	p->sig_blocked = (uint64_t)-1; /* even a full mask cannot block SIGKILL */
	p->pending_sigs = lxp_sig_bit(LXP_SIGKILL);
	assert_int_equal(pending_deliverable(p), LXP_SIGKILL);

	p->pending_sigs = 0;
	assert_int_equal(pending_deliverable(p), 0); /* empty set */
}

/* lxp_dispatch used to read TCSETS' arg before lxp_syscall reached the console handler. Because
 * dispatch runs privileged, a guest could point it at host memory or MMIO and fault the RTOS even
 * if the handler itself performed access_ok. Keep this at the trap-dispatch level, not merely in
 * the direct-syscall conformance suite. */
static void test_dispatch_rejects_bad_tcsets_pointer(void **state)
{
	(void)state;
	uint8_t arena_mem[256] __attribute__((aligned(16)));
	lxp_arena_t arena;
	assert_int_equal(lxp_arena_init(&arena, arena_mem, sizeof(arena_mem)), LXP_OK);
	lxp_proc_t *proc = &g_lxp_proc[0];
	assert_int_equal(lxp_proc_init(proc, &arena, 0), LXP_OK);
	proc->alive = 1;
	proc->region_lo = 0x1000u;
	proc->region_hi = 0x2000u;
	proc->pool_lo = proc->pool_hi = 0;
	deferred_slot_reassign(0);

	const uint32_t cmds[] = {LXP_TCSETS, LXP_TCSETSW, LXP_TCSETSF};
	for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
		struct lxp_frame f;
		memset(&f, 0, sizeof(f));
		f.r[0] = 0; /* stdin is a console fd */
		f.r[1] = cmds[i];
		f.r[2] = 0x20000000u; /* mapped host SRAM on target; outside this guest */
		f.r[7] = LXP_NR_ioctl;
		g_tty_isig = 1;
		g_lxp_used[0] = 1;

		lxp_dispatch(&f, proc);

		assert_int_equal(deferred_state_load(0), DEFER_READY);
		assert_int_equal(g_mock.event_posts, (int)i + 1);
		execute_deferred(&g_mock_eng, 0);
		assert_int_equal(g_mock.resume_r0, -LXP_EFAULT);
		assert_int_equal(g_tty_isig, 1); /* invalid input cannot alter console state */
	}
}

/* Pointer-free identity calls stay in the bounded top half; unknown/new calls
 * default to the deferred mailbox and therefore cannot accidentally run in SVC. */
static void test_dispatch_class_defaults_deferred(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->pid = 42;
	deferred_slot_reassign(0);
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpid;
	lxp_dispatch(&f, p);
	assert_int_equal(f.r[0], 42);
	assert_int_equal(g_mock.event_posts, 0);
	assert_int_equal(deferred_state_load(0), DEFER_IDLE);

	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	f.xpsr = 0xa8000000u | (1u << 24); /* NZCV + Thumb survive task recreation */
	g_lxp_used[0] = 1;
	lxp_dispatch(&f, p);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	assert_int_equal(g_mock.event_posts, 1);
	execute_deferred(&g_mock_eng, 0);
	assert_int_equal(g_mock.resume_r0, -LXP_ENOSYS);
	assert_int_equal(g_mock.resume_xpsr, f.xpsr);
}

/* Distinct slots have distinct fixed mailboxes. Both may queue while neither
 * bottom half has completed; servicing one cannot overwrite or lose the other. */
static void test_deferred_requests_are_per_slot(void **state)
{
	(void)state;
	for (int s = 0; s < 2; s++) {
		g_lxp_proc[s].alive = 1;
		g_lxp_proc[s].pid = s + 1;
		deferred_slot_reassign(s);
		g_lxp_used[s] = 1;
		struct lxp_frame f;
		memset(&f, 0, sizeof(f));
		f.r[7] = 900u + (uint32_t)s;
		lxp_dispatch(&f, &g_lxp_proc[s]);
	}
	assert_int_equal(g_mock.event_posts, 2);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	assert_int_equal(deferred_state_load(1), DEFER_READY);

	execute_deferred(&g_mock_eng, 1);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	assert_int_equal(deferred_state_load(1), DEFER_IDLE);
	execute_deferred(&g_mock_eng, 0);
	assert_int_equal(g_mock.resume_calls, 2);
	assert_int_equal(g_mock.resume_order[0], 1);
	assert_int_equal(g_mock.resume_order[1], 0);
}

/* A stale event from an old slot generation is discarded without aborting or
 * resuming the new occupant of that slot. */
static void test_deferred_generation_rejects_stale_work(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	deferred_slot_reassign(0);
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	lxp_dispatch(&f, p);
	uint32_t old_generation = g_deferred[0].generation;
	deferred_slot_reassign(0);
	g_deferred[0].generation = old_generation;
	deferred_state_store(0, DEFER_READY); /* delayed event from the prior occupant */
	g_lxp_used[0] = 1;

	execute_deferred(&g_mock_eng, 0);

	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_used[0], 1); /* the replacement task was untouched */
}

/* One slot cannot overwrite its outstanding request, even if a broken seam
 * attempts to dispatch that slot again before the bottom half claims it. */
static void test_deferred_same_slot_rejects_overwrite(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	deferred_slot_reassign(0);
	struct lxp_frame first, second;
	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	first.r[7] = 998;
	second.r[7] = 999;
	lxp_dispatch(&first, p);
	lxp_dispatch(&second, p);
	assert_int_equal((int32_t)second.r[0], -LXP_EAGAIN);
	assert_int_equal(g_mock.event_posts, 1);
	assert_int_equal((int32_t)g_ctx[0].r4_11[3], 998);
}

/* A deliverable signal queued before resource acquisition cancels deferred work.
 * Default SIGTERM kills the guest without ever executing or resuming its syscall. */
static void test_deferred_signal_cancels_before_execute(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	deferred_slot_reassign(0);
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	g_lxp_used[0] = 1;
	lxp_dispatch(&f, p);
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM);

	execute_deferred(&g_mock_eng, 0);

	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(p->exited, 1);
	assert_int_equal(p->exit_status, 128 + LXP_SIGTERM);
}

static int console_not_ready(void *ctx)
{
	(void)ctx;
	return 0;
}

/* Blocking handlers hand ownership to the existing wait state machine. The
 * parked task must remain present until that event claims and aborts it; deleting
 * it in the generic bottom half makes the wait predicate permanently false. */
static void test_deferred_blocking_handoff_keeps_parked_task(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->console_poll = console_not_ready;
	deferred_slot_reassign(0);
	g_lxp_used[0] = 1;

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[0] = 0; /* no pollfd array: this is a pure timeout sleep */
	f.r[1] = 0;
	f.r[2] = 1000;
	f.r[7] = LXP_NR_poll;
	lxp_dispatch(&f, p);
	execute_deferred(&g_mock_eng, 0);

	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(p->sleep_pending, 1);
	assert_int_equal(g_lxp_used[0], 1);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_encode_wstatus, reset_state),
		cmocka_unit_test_setup(test_dispatch_rejects_bad_tcsets_pointer, reset_state),
		cmocka_unit_test_setup(test_dispatch_class_defaults_deferred, reset_state),
		cmocka_unit_test_setup(test_deferred_requests_are_per_slot, reset_state),
		cmocka_unit_test_setup(test_deferred_generation_rejects_stale_work, reset_state),
		cmocka_unit_test_setup(test_deferred_same_slot_rejects_overwrite, reset_state),
		cmocka_unit_test_setup(test_deferred_signal_cancels_before_execute, reset_state),
		cmocka_unit_test_setup(test_deferred_blocking_handoff_keeps_parked_task,
				       reset_state),
		cmocka_unit_test_setup(test_pending_deliverable, reset_state),
		cmocka_unit_test_setup(test_futex_has_corunner, reset_state),
		cmocka_unit_test_setup(test_futex_wake_marks_waiters, reset_state),
		cmocka_unit_test_setup(test_reap_wakes_blocking_parent, reset_state),
		cmocka_unit_test_setup(test_reap_signaled_child_status, reset_state),
		cmocka_unit_test_setup(test_reap_specific_pid_not_woken, reset_state),
		cmocka_unit_test_setup(test_reap_queues_zombie, reset_state),
		cmocka_unit_test_setup(test_reap_zombie_queue_full, reset_state),
		cmocka_unit_test_setup(test_reap_unknown_parent, reset_state),
		cmocka_unit_test_setup(test_region_free, reset_state),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
