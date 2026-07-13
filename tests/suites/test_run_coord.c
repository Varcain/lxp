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
	int abort_calls;
	int abort_sidx;
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
}
static void mock_abort_slot(int sidx)
{
	g_mock.abort_calls++;
	g_mock.abort_sidx = sidx;
}

static const lxp_os_ops_t g_mock_eng = {
	.region = mock_region,
	.spawn_resume = mock_spawn_resume,
	.abort_slot = mock_abort_slot,
};

static int reset_state(void **state)
{
	(void)state;
	memset(g_lxp_proc, 0, sizeof(g_lxp_proc));
	memset(g_lxp_used, 0, sizeof(g_lxp_used));
	memset(&g_mock, 0, sizeof(g_mock));
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
	assert_int_equal(g_lxp_proc[0].pending_sig, LXP_SIGCHLD);
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
	assert_int_equal(g_lxp_proc[0].pending_sig, LXP_SIGCHLD);
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

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_encode_wstatus, reset_state),
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
