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
	struct lxp_fp_context resume_fp;
	int resume_order[LXP_NSLOT];
	long resume_results[LXP_NSLOT];
	int abort_calls;
	int abort_sidx;
	int event_posts;
	int cache_clean_calls;
	const void *cache_clean_base[8];
	size_t cache_clean_len[8];
	int cache_invalidate_calls;
	const void *cache_invalidate_base[8];
	size_t cache_invalidate_len[8];
	int exit_notify_calls;
	lxp_guest_exit_info_t exit_info;
} g_mock;

static uint8_t g_mock_regions[LXP_NREG][256];
static uint8_t g_mock_dyn_pools[LXP_NREG][64];
static lxp_exec_capture_t g_mock_exec_captures[LXP_NSLOT];

static uint8_t *mock_region(int ridx)
{
	return g_mock_regions[ridx];
}
static uint8_t *mock_dyn_pool(int ridx, size_t *size)
{
	if (size)
		*size = sizeof(g_mock_dyn_pools[ridx]);
	return g_mock_dyn_pools[ridx];
}
static lxp_exec_capture_t *mock_exec_capture(int sidx)
{
	return (sidx >= 0 && sidx < LXP_NSLOT) ? &g_mock_exec_captures[sidx] : NULL;
}
static void mock_cache_clean(const void *base, size_t len)
{
	int i = g_mock.cache_clean_calls++;
	if (i < 8) {
		g_mock.cache_clean_base[i] = base;
		g_mock.cache_clean_len[i] = len;
	}
}
static void mock_cache_invalidate(const void *base, size_t len)
{
	int i = g_mock.cache_invalidate_calls++;
	if (i < 8) {
		g_mock.cache_invalidate_base[i] = base;
		g_mock.cache_invalidate_len[i] = len;
	}
}
static void mock_spawn_resume(int sidx, int ridx, const struct lxp_resume_ctx *c, long r0)
{
	(void)ridx;
	(void)c;
	g_mock.resume_calls++;
	g_mock.resume_sidx = sidx;
	g_mock.resume_r0 = r0;
	g_mock.resume_xpsr = c->xpsr;
	g_mock.resume_fp = c->fp;
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
static const char *mock_system_version(void)
{
	return "MockRTOS 9.8.7 ove-fedcba9 lxp-7654321";
}

static const lxp_os_ops_t g_mock_eng = {
	.region = mock_region,
	.dyn_pool = mock_dyn_pool,
	.exec_capture = mock_exec_capture,
	.spawn_resume = mock_spawn_resume,
	.abort_slot = mock_abort_slot,
	.event_post = mock_event_post,
	.cache_clean = mock_cache_clean,
	.cache_invalidate = mock_cache_invalidate,
	.system_version = mock_system_version,
};

static void mock_on_guest_exit(const lxp_guest_exit_info_t *info)
{
	g_mock.exit_notify_calls++;
	g_mock.exit_info = *info;
}

static const lxp_run_config_t g_mock_cfg = {
	.on_guest_exit = mock_on_guest_exit,
};

static int reset_state(void **state)
{
	(void)state;
	memset(g_lxp_proc, 0, sizeof(g_lxp_proc));
	memset(g_lxp_used, 0, sizeof(g_lxp_used));
	memset(g_deferred, 0, sizeof(g_deferred));
	memset(g_primary_pending, 0, sizeof(g_primary_pending));
	memset(g_slot_generation, 0, sizeof(g_slot_generation));
	memset(g_region_generation, 0, sizeof(g_region_generation));
	memset(g_vfork_guard, 0, sizeof(g_vfork_guard));
	memset(g_ctx, 0, sizeof(g_ctx));
	memset(g_sig_save, 0, sizeof(g_sig_save));
	memset(g_mock_regions, 0, sizeof(g_mock_regions));
	memset(g_mock_dyn_pools, 0, sizeof(g_mock_dyn_pools));
	memset(&g_mock, 0, sizeof(g_mock));
	for (int r = 0; r < LXP_NREG; r++)
		g_region_owner[r] = -1;
	for (int s = 0; s < LXP_NSLOT; s++)
		g_vfork_guard[s].parent_slot = g_vfork_guard[s].parent_region =
			g_vfork_guard[s].snapshot_region = -1;
	lxp_console_set_fg_pgrp(0);
	g_eng = &g_mock_eng;
	g_cfg = NULL;
	g_lxp_active = 0;
	g_pending_sig = 0;
	g_tty_isig = 1;
	g_tty_icrnl = 1;
	return 0;
}

static void test_system_version_routes_to_engine(void **state)
{
	(void)state;
	assert_string_equal(lxp_system_version(),
			    "MockRTOS 9.8.7 ove-fedcba9 lxp-7654321");
	g_eng = NULL;
	assert_string_equal(lxp_system_version(), "lxp");
}

static void test_resource_stats_track_slots_and_reserved_regions(void **state)
{
	(void)state;
	g_lxp_active = 1;
	g_region_owner[0] = 0; /* live init region */
	g_region_owner[2] = 1; /* reserved vfork snapshot/exec region */
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].region = 0;
	g_lxp_proc[1].alive = 1;
	g_lxp_proc[1].region = 0; /* thread shares region 0 but consumes a slot */

	struct lxp_resource_stats resources;
	lxp_get_resource_stats(&resources);
	assert_int_equal(resources.slots_total, LXP_NSLOT);
	assert_int_equal(resources.slots_free, LXP_NSLOT - 2);
	assert_int_equal(resources.regions_total, LXP_NREG);
	assert_int_equal(resources.regions_free, LXP_NREG - 2);
	assert_int_equal(resources.program_region_bytes, LXP_PROG_REGION_SIZE);
	assert_int_equal(resources.dynamic_pool_bytes, sizeof(g_mock_dyn_pools[0]));
	uint64_t region_bytes = LXP_PROG_REGION_SIZE + sizeof(g_mock_dyn_pools[0]);
	assert_int_equal(resources.total_bytes, region_bytes * LXP_NREG);
	assert_int_equal(resources.free_bytes, region_bytes * (LXP_NREG - 2));
	assert_int_equal(resources.available_bytes, region_bytes * (LXP_NREG - 2));

	/* Clone-style processes can share a region but still exhaust process slots. */
	for (int s = 2; s < LXP_NSLOT; s++) {
		g_lxp_proc[s].alive = 1;
		g_lxp_proc[s].region = 0;
	}
	lxp_get_resource_stats(&resources);
	assert_int_equal(resources.slots_free, 0);
	assert_int_equal(resources.regions_free, LXP_NREG - 2);
	assert_int_equal(resources.available_bytes, 0);
}

/* The per-slot claim helper keeps the original event ordering while consuming
 * only the two edge-style latches (fork and sleep). Level-style state remains
 * set for the handler that runs after the critical section. */
static void test_claim_slot_event_priority_and_consumption(void **state)
{
	(void)state;
	const int s = 2;
	lxp_proc_t *p = &g_lxp_proc[s];

	assert_false(primary_slot_pending(s));
	lxp_event_post_slot(s);
	assert_true(primary_slot_pending(s));
	assert_int_equal(g_mock.event_posts, 1);
	primary_slot_clear(s);
	assert_false(primary_slot_pending(s));

	assert_int_equal(claim_slot_event(s), LXP_EV_NONE);
	p->alive = 1;
	p->exited = 1;
	p->exec_pending = 1;
	p->fork_pending = 1;
	p->sleep_pending = 1;
	assert_int_equal(claim_slot_event(s), LXP_EV_EXIT);
	assert_int_equal(p->fork_pending, 1);
	assert_int_equal(p->sleep_pending, 1);

	p->exited = 0;
	assert_int_equal(claim_slot_event(s), LXP_EV_EXEC);
	p->exec_pending = 0;
	assert_int_equal(claim_slot_event(s), LXP_EV_FORK);
	assert_int_equal(p->fork_pending, 0);
	assert_int_equal(claim_slot_event(s), LXP_EV_SLEEP);
	assert_int_equal(p->sleep_pending, 0);

	p->console_wait = 1;
	assert_int_equal(claim_slot_event(s), LXP_EV_NONE);
	g_lxp_used[s] = 1;
	assert_int_equal(claim_slot_event(s), LXP_EV_CONSOLEWAIT);
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

	reap_to_parent(&g_mock_eng, /*ppid*/ 1, /*cpid*/ 7, /*status*/ 42, /*sigchld=*/1);

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

	reap_to_parent(&g_mock_eng, 1, 7, 128 + 15 /* SIGTERM */, /*sigchld=*/1);

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

	reap_to_parent(&g_mock_eng, 1, 7, 0, /*sigchld=*/1); /* pid 7 exits, not 9 */

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

	reap_to_parent(&g_mock_eng, 1, 7, 3, /*sigchld=*/1);

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_proc[0].child_count, 1);
	assert_int_equal(g_lxp_proc[0].child_pid[0], 7);
	assert_int_equal(g_lxp_proc[0].child_status[0], 3); /* raw code; wait4 encodes on reap */
	assert_int_equal(g_lxp_proc[0].live_children, 0);
	assert_true((g_lxp_proc[0].pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) != 0);
}

/* ---- reap_to_parent: a vfork parent (already resumed) reaps WITHOUT SIGCHLD --- */
/* Regression: a vfork parent resumed at its child's exit is not yet wait_pending, so the
 * zombie takes the else branch — but the parent will wait4() it immediately. Raising
 * SIGCHLD (sigchld != 0) here would -EINTR that wait4 before it reaps (the shell then
 * prints "waitpid: Interrupted" and loses the 127 exit code), so the vfork callers pass
 * sigchld=0: queue the zombie, do NOT signal. */
static void test_reap_vfork_parent_suppresses_sigchld(void **state)
{
	(void)state;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = 1;
	/* wait_pending == 0: just resumed from vfork, about to wait4() the child. */

	reap_to_parent(&g_mock_eng, 1, 7, 127, /*sigchld=*/0);

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_proc[0].child_count, 1);	   /* queued for the imminent wait4 */
	assert_int_equal(g_lxp_proc[0].child_pid[0], 7);
	assert_int_equal(g_lxp_proc[0].child_status[0], 127); /* exit code preserved */
	assert_int_equal(g_lxp_proc[0].live_children, 0);
	assert_true((g_lxp_proc[0].pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) == 0); /* NOT signalled */
}

/* The zombie queue is bounded (LXP_MAX_CHILD): an overflow is dropped, not overrun. */
static void test_reap_zombie_queue_full(void **state)
{
	(void)state;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = LXP_MAX_CHILD + 1;
	g_lxp_proc[0].child_count = LXP_MAX_CHILD; /* already full */

	reap_to_parent(&g_mock_eng, 1, 99, 0, /*sigchld=*/1);

	assert_int_equal(g_lxp_proc[0].child_count, LXP_MAX_CHILD); /* clamped, no overrun */
	assert_int_equal(g_lxp_proc[0].live_children, LXP_MAX_CHILD); /* still decremented */
}

/* An exit reported for a parent that no longer exists is a safe no-op. */
static void test_reap_unknown_parent(void **state)
{
	(void)state;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;

	reap_to_parent(&g_mock_eng, /*ppid*/ 42, 7, 0, /*sigchld=*/1); /* no proc has pid 42 */

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_lxp_proc[0].child_count, 0);
}

static void test_notify_guest_exit_preserves_attribution(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[3];
	p->pid = 27;
	p->ppid = 7;
	p->exit_status = 139;
	p->exit_reason = LXP_EXIT_REASON_MEMORY_FAULT;
	p->exit_signal = LXP_SIGSEGV;
	p->exit_detail = 0x92;
	p->exit_address = 0x4c;
	memcpy(p->comm, "sigctx", 7);
	g_cfg = &g_mock_cfg;

	notify_guest_exit(3, p);

	assert_int_equal(g_mock.exit_notify_calls, 1);
	assert_int_equal(g_mock.exit_info.slot, 3);
	assert_int_equal(g_mock.exit_info.pid, 27);
	assert_int_equal(g_mock.exit_info.ppid, 7);
	assert_int_equal(g_mock.exit_info.status, 139);
	assert_int_equal(g_mock.exit_info.reason, LXP_EXIT_REASON_MEMORY_FAULT);
	assert_int_equal(g_mock.exit_info.signal, LXP_SIGSEGV);
	assert_int_equal(g_mock.exit_info.detail, 0x92);
	assert_int_equal(g_mock.exit_info.address, 0x4c);
	assert_string_equal(g_mock.exit_info.comm, "sigctx");
}

static void test_fork_capacity_accounts_live_and_zombie_children(void **state)
{
	(void)state;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	assert_true(fork_capacity_available(&p));
	p.child_count = LXP_MAX_CHILD - 1;
	assert_true(fork_capacity_available(&p));
	p.live_children = 1;
	assert_false(fork_capacity_available(&p));
	p.child_count = 0;
	p.live_children = LXP_MAX_CHILD;
	assert_false(fork_capacity_available(&p));
	p.live_children = -1;
	assert_false(fork_capacity_available(&p));
}

static void test_vfork_snapshot_publishes_cacheable_destination(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->region = 0;
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	p->is_dynamic = 1;
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	for (size_t i = 0; i < 128u; i++)
		g_mock_regions[0][i] = (uint8_t)(i ^ 0x5au);
	memset(&g_mock_regions[0][128], 0xee, 64u); /* unused stack reservation: not copied */
	for (size_t i = 192u; i < sizeof(g_mock_regions[0]); i++)
		g_mock_regions[0][i] = (uint8_t)(i ^ 0x3cu);
	for (size_t i = 0; i < sizeof(g_mock_dyn_pools[0]); i++)
		g_mock_dyn_pools[0][i] = (uint8_t)(i ^ 0xa5u);
	(void)region_reserve(0, 0);

	assert_int_equal(vfork_snapshot(&g_mock_eng, p, 1, sp), 1);
	assert_memory_equal(g_mock_regions[1], g_mock_regions[0], 128u);
	assert_memory_equal(&g_mock_regions[1][192], &g_mock_regions[0][192], 64u);
	for (size_t i = 128u; i < 192u; i++)
		assert_int_equal(g_mock_regions[1][i], 0); /* inactive stack was not copied */
	assert_memory_equal(g_mock_dyn_pools[1], g_mock_dyn_pools[0],
			    sizeof(g_mock_dyn_pools[0]));
	assert_int_equal(g_mock.cache_clean_calls, 6);
	assert_ptr_equal(g_mock.cache_clean_base[0], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_clean_base[1], g_mock_regions[1]);
	assert_ptr_equal(g_mock.cache_clean_base[2], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_clean_base[3], &g_mock_regions[1][192]);
	assert_ptr_equal(g_mock.cache_clean_base[4], g_mock_dyn_pools[0]);
	assert_ptr_equal(g_mock.cache_clean_base[5], g_mock_dyn_pools[1]);
	assert_int_equal(g_mock.cache_clean_len[0], 128u);
	assert_int_equal(g_mock.cache_clean_len[1], 128u);
	assert_int_equal(g_mock.cache_clean_len[2], 64u);
	assert_int_equal(g_mock.cache_clean_len[3], 64u);
	assert_int_equal(g_mock.cache_clean_len[4], sizeof(g_mock_dyn_pools[0]));
	assert_int_equal(g_mock.cache_clean_len[5], sizeof(g_mock_dyn_pools[1]));
	assert_int_equal(g_mock.cache_invalidate_calls, 3);
	assert_ptr_equal(g_mock.cache_invalidate_base[0], g_mock_regions[1]);
	assert_ptr_equal(g_mock.cache_invalidate_base[1], &g_mock_regions[1][192]);
	assert_ptr_equal(g_mock.cache_invalidate_base[2], g_mock_dyn_pools[1]);
	assert_int_equal(g_mock.cache_invalidate_len[0], 128u);
	assert_int_equal(g_mock.cache_invalidate_len[1], 64u);
	assert_int_equal(g_mock.cache_invalidate_len[2], sizeof(g_mock_dyn_pools[1]));
}

static void test_vfork_restore_publishes_cacheable_parent(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->region = 0;
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	p->is_dynamic = 1;
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	for (size_t i = 0; i < 128u; i++)
		g_mock_regions[1][i] = (uint8_t)(i ^ 0x5au);
	for (size_t i = 192u; i < sizeof(g_mock_regions[1]); i++)
		g_mock_regions[1][i] = (uint8_t)(i ^ 0x3cu);
	for (size_t i = 0; i < sizeof(g_mock_dyn_pools[1]); i++)
		g_mock_dyn_pools[1][i] = (uint8_t)(i ^ 0xa5u);
	memset(g_mock_regions[0], 0xcc, 128u);
	memset(&g_mock_regions[0][192], 0xbb, 64u);
	memset(g_mock_dyn_pools[0], 0xdd, sizeof(g_mock_dyn_pools[0]));

	(void)region_reserve(0, 0);
	(void)region_reserve(1, 1);
	g_vfork_guard[1].parent_slot = 0;
	g_vfork_guard[1].parent_slot_generation = g_slot_generation[0];
	g_vfork_guard[1].parent_region = 0;
	g_vfork_guard[1].parent_region_generation = g_region_generation[0];
	g_vfork_guard[1].snapshot_region = 1;
	g_vfork_guard[1].snapshot_region_generation = g_region_generation[1];
	assert_int_equal(vfork_restore(&g_mock_eng, p, 1, 1, sp), 0);

	assert_memory_equal(g_mock_regions[0], g_mock_regions[1], 128u);
	assert_memory_equal(&g_mock_regions[0][192], &g_mock_regions[1][192], 64u);
	assert_memory_equal(g_mock_dyn_pools[0], g_mock_dyn_pools[1],
			    sizeof(g_mock_dyn_pools[0]));
	assert_int_equal(g_mock.cache_clean_calls, 3);
	assert_ptr_equal(g_mock.cache_clean_base[0], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_clean_base[1], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_clean_base[2], g_mock_dyn_pools[0]);
	assert_int_equal(g_mock.cache_invalidate_calls, 6);
	assert_ptr_equal(g_mock.cache_invalidate_base[0], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_invalidate_base[1], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_invalidate_base[2], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_invalidate_base[3], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_invalidate_base[4], g_mock_dyn_pools[0]);
	assert_ptr_equal(g_mock.cache_invalidate_base[5], g_mock_dyn_pools[0]);
}

static void test_vfork_snapshot_refuses_no_spare_region(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->region = 0;
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	for (int r = 0; r < LXP_NREG; r++)
		(void)region_reserve(r, r);

	assert_int_equal(vfork_snapshot(&g_mock_eng, p, 1,
					 (uintptr_t)g_mock_regions[0] + 192u), -1);
	assert_int_equal(g_mock.cache_clean_calls, 0);
	assert_int_equal(g_vfork_guard[1].snapshot_region, -1);
}

static void test_vfork_restore_rejects_recycled_snapshot(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->region = 0;
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	(void)region_reserve(0, 0);
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	assert_int_equal(vfork_snapshot(&g_mock_eng, p, 1, sp), 1);
	memset(g_mock_regions[0], 0x5a, sizeof(g_mock_regions[0]));
	region_release_if_owned(1, 1);
	(void)region_reserve(1, 2); /* same index, different reservation incarnation */

	assert_int_equal(vfork_restore(&g_mock_eng, p, 1, 1, sp), -1);
	for (size_t i = 0; i < sizeof(g_mock_regions[0]); i++)
		assert_int_equal(g_mock_regions[0][i], 0x5a);
}

static void test_vfork_restore_rejects_recycled_parent(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->region = 0;
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	(void)region_reserve(0, 0);
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	assert_int_equal(vfork_snapshot(&g_mock_eng, p, 1, sp), 1);
	memset(g_mock_regions[0], 0xa5, sizeof(g_mock_regions[0]));
	deferred_slot_reassign(0); /* same slot, different process incarnation */

	assert_int_equal(vfork_restore(&g_mock_eng, p, 1, 1, sp), -1);
	for (size_t i = 0; i < sizeof(g_mock_regions[0]); i++)
		assert_int_equal(g_mock_regions[0][i], 0xa5);
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
		g_tty_icrnl = 1;
		g_lxp_used[0] = 1;

		lxp_dispatch(&f, proc);

		assert_int_equal(deferred_state_load(0), DEFER_READY);
		assert_int_equal(g_mock.event_posts, (int)i + 1);
		execute_deferred(&g_mock_eng, 0);
		assert_int_equal(g_mock.resume_r0, -LXP_EFAULT);
		assert_int_equal(g_tty_isig, 1); /* invalid input cannot alter console state */
		assert_int_equal(g_tty_icrnl, 1);
	}
}

/* The board transport supplies CR for Enter because BusyBox's raw shell editor expects
 * it.  A cooked tty advertising ICRNL must instead give applications LF: login's retry
 * path uses fgets(), which otherwise consumes the second username forever waiting for
 * a newline.  When a guest clears ICRNL, the transport byte must be preserved. */
static void test_console_icrnl_translation(void **state)
{
	(void)state;
	g_tty_icrnl = 1;
	assert_int_equal(lxp_console_input_xlate('\r'), '\n');
	assert_int_equal(lxp_console_input_xlate('x'), 'x');
	assert_int_equal(lxp_console_input_xlate('\n'), '\n');

	g_tty_icrnl = 0;
	assert_int_equal(lxp_console_input_xlate('\r'), '\r');
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
	struct lxp_fp_context fp;
	memset(&fp, 0, sizeof(fp));
	for (int i = 0; i < 32; i++)
		fp.s[i] = 0x3f000000u + (uint32_t)i;
	fp.fpscr = 0x01c00000u;
	fp.active = 1;
	f.fp = &fp;
	g_lxp_used[0] = 1;
	lxp_dispatch(&f, p);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	assert_int_equal(g_mock.event_posts, 1);
	execute_deferred(&g_mock_eng, 0);
	assert_int_equal(g_mock.resume_r0, -LXP_ENOSYS);
	assert_int_equal(g_mock.resume_xpsr, f.xpsr);
	assert_memory_equal(&g_mock.resume_fp, &fp, sizeof(fp));
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

static int console_ready(void *ctx)
{
	(void)ctx;
	return 1;
}

static long console_read_cr(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (!len)
		return 0;
	((uint8_t *)buf)[0] = '\r';
	return 1;
}

/* A byte may already be ready when read(2) enters, bypassing console_wait entirely.
 * That fast path must use the same ICRNL discipline as a coordinator-resumed read. */
static void test_console_icrnl_immediate_read(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	assert_int_equal(lxp_arena_init(&arena, g_mock_regions[0], sizeof(g_mock_regions[0])),
			 LXP_OK);
	assert_int_equal(lxp_proc_init(&p, &arena, 0), LXP_OK);
	p.region_lo = 1;
	p.region_hi = UINTPTR_MAX;
	p.read_fn = console_read_cr;
	p.console_poll = console_ready;

	uint8_t ch = 0;
	g_tty_icrnl = 1;
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, 0, (long)(uintptr_t)&ch, 1, 0, 0, 0), 1);
	assert_int_equal(ch, '\n');

	g_tty_icrnl = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, 0, (long)(uintptr_t)&ch, 1, 0, 0, 0), 1);
	assert_int_equal(ch, '\r');
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
	assert_true(primary_slot_pending(0));
	assert_int_equal(g_lxp_used[0], 1);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
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
		g_lxp_proc[i].alive = 1;
		g_lxp_proc[i].pid = pid[i];
		g_lxp_proc[i].pgid = pgid[i];
	}
	lxp_proc_t *shell = &g_lxp_proc[1]; /* the sender */
	const uint64_t bit = lxp_sig_bit(LXP_SIGTERM);

	/* shell: kill(-3, SIGTERM) -> process group 3 = {cmd1 pid3, cmd2 pid4} only. */
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_kill;
	f.r[0] = (uint32_t)(-3); /* target = -pgid */
	f.r[1] = LXP_SIGTERM;
	lxp_dispatch(&f, shell);
	assert_int_equal((int32_t)f.r[0], 0);		/* a target was found */
	assert_true(g_lxp_proc[2].pending_sigs & bit);	/* cmd1 (pgid 3) */
	assert_true(g_lxp_proc[3].pending_sigs & bit);	/* cmd2 (pgid 3) */
	assert_false(g_lxp_proc[0].pending_sigs & bit); /* init untouched */
	assert_false(g_lxp_proc[1].pending_sigs & bit); /* the sender itself */
	assert_false(g_lxp_proc[4].pending_sigs & bit); /* inetd (pgid 5) — the old broadcast bug */

	/* kill(0, SIGTERM) targets the SENDER's own group (pgid 2); put inetd in it. */
	for (int i = 0; i < 5; i++)
		g_lxp_proc[i].pending_sigs = 0;
	g_lxp_proc[4].pgid = 2;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_kill;
	f.r[0] = 0; /* caller's process group */
	f.r[1] = LXP_SIGTERM;
	lxp_dispatch(&f, shell);
	assert_true(g_lxp_proc[4].pending_sigs & bit);	/* the group peer */
	assert_false(g_lxp_proc[2].pending_sigs & bit); /* pgid 3, not in group 2 */
}

/* setpgid(0,pgid)/getpgrp track a real per-proc group; setsid makes the caller a leader. */
static void test_setpgid_getpgrp_track_group(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->alive = 1;
	p->pid = 7;
	p->pgid = 7;
	struct lxp_frame f;

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpgrp;
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 7); /* getpgrp -> current group */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_setpgid;
	f.r[0] = 0;  /* self */
	f.r[1] = 42; /* pgid */
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 0);
	assert_int_equal(p->pgid, 42); /* setpgid(0,42) joined group 42 */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpgrp;
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 42); /* getpgrp reflects it */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_setsid;
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 7); /* setsid -> new session, pgid = pid */
	assert_int_equal(p->pgid, 7);
}

/* A console ^C raises SIGINT on the console's FOREGROUND process group only (the group
 * the shell set via tcsetpgrp/TIOCSPGRP) — the interactive shell (its own group) and any
 * background job survive. The console analog of the pty ^C: what makes a foreground
 * program interruptible from the direct console. */
static void test_console_sigint_targets_fg_group(void **state)
{
	(void)state;
	/* pid/pgid: init(1,1) shell(2,2) fg-job(3,3) fg-pipe-peer(4,3) bg-job(5,5) */
	const int pid[5] = {1, 2, 3, 4, 5};
	const int pgid[5] = {1, 2, 3, 3, 5};
	for (int i = 0; i < 5; i++) {
		g_lxp_proc[i].alive = 1;
		g_lxp_proc[i].pid = pid[i];
		g_lxp_proc[i].pgid = pgid[i];
	}
	const uint64_t bit = lxp_sig_bit(LXP_SIGINT);

	/* No foreground group yet (pre-first-tcsetpgrp): ^C signals nobody. */
	lxp_console_set_fg_pgrp(0);
	console_signal_fg(LXP_SIGINT);
	for (int i = 0; i < 5; i++)
		assert_false(g_lxp_proc[i].pending_sigs & bit);

	/* Shell put group 3 in the foreground: ^C hits that group only. */
	lxp_console_set_fg_pgrp(3);
	assert_int_equal(lxp_console_fg_pgrp(), 3);
	console_signal_fg(LXP_SIGINT);
	assert_true(g_lxp_proc[2].pending_sigs & bit);	/* fg job (pgid 3) */
	assert_true(g_lxp_proc[3].pending_sigs & bit);	/* fg pipeline peer (pgid 3) */
	assert_false(g_lxp_proc[0].pending_sigs & bit); /* init (pgid 1) */
	assert_false(g_lxp_proc[1].pending_sigs & bit); /* the shell (pgid 2) — survives to re-prompt */
	assert_false(g_lxp_proc[4].pending_sigs & bit); /* background job (pgid 5) — untouched */
}

/* Ctrl+Z (VSUSP) fans SIGTSTP out to the foreground group only — the shell and background
 * jobs are untouched — exactly like the ^C→SIGINT path. */
static void test_console_sigtstp_targets_fg_group(void **state)
{
	(void)state;
	const int pid[3] = {2, 3, 5};	/* shell(2,2) fg-job(3,3) bg-job(5,5) */
	const int pgid[3] = {2, 3, 5};
	for (int i = 0; i < 3; i++) {
		g_lxp_proc[i].alive = 1;
		g_lxp_proc[i].pid = pid[i];
		g_lxp_proc[i].pgid = pgid[i];
	}
	const uint64_t bit = lxp_sig_bit(LXP_SIGTSTP);
	lxp_console_set_fg_pgrp(3);
	console_signal_fg(LXP_SIGTSTP);
	assert_true(g_lxp_proc[1].pending_sigs & bit);	/* fg job (pgid 3) */
	assert_false(g_lxp_proc[0].pending_sigs & bit); /* the shell (pgid 2) */
	assert_false(g_lxp_proc[2].pending_sigs & bit); /* background job (pgid 5) */
}

/* The stop-signal predicate: SIGSTOP always stops (uncatchable); SIGTSTP/TTIN/TTOU stop
 * only at their default disposition (a caught one runs the handler). */
static void test_sig_stops_proc_predicate(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_proc[0];
	p->sig_handler[LXP_SIGTSTP] = LXP_SIG_DFL;
	assert_true(sig_is_stop(LXP_SIGTSTP));
	assert_true(sig_is_stop(LXP_SIGSTOP));
	assert_false(sig_is_stop(LXP_SIGINT));
	assert_true(sig_stops_proc(p, LXP_SIGTSTP)); /* SIG_DFL → stops */
	p->sig_handler[LXP_SIGTSTP] = 0x1000;	     /* a caught handler → runs it, no stop */
	assert_false(sig_stops_proc(p, LXP_SIGTSTP));
	p->sig_handler[LXP_SIGSTOP] = 0x1000;	     /* SIGSTOP is uncatchable → always stops */
	assert_true(sig_stops_proc(p, LXP_SIGSTOP));
	assert_false(sig_stops_proc(p, LXP_SIGINT)); /* not a stop signal */
}

/* A stopped child wakes a parent blocked in wait4(WUNTRACED) with a WIFSTOPPED status and,
 * unlike an exit, leaves live_children intact (the child is still alive). */
static void test_stop_notify_wakes_wuntraced_waiter(void **state)
{
	(void)state;
	int status = -1;
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = 1;
	g_lxp_proc[0].wait_pending = 1;
	g_lxp_proc[0].wait_pid = -1;
	g_lxp_proc[0].wait_options = LXP_WUNTRACED;
	g_lxp_proc[0].wait_status_p = (uintptr_t)&status;

	notify_parent_stopped(&g_mock_eng, /*ppid*/ 1, /*cpid*/ 7, LXP_SIGTSTP);

	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, 7);
	assert_int_equal(status, ((LXP_SIGTSTP & 0xff) << 8) | 0x7f); /* WIFSTOPPED */
	assert_int_equal(g_lxp_proc[0].wait_pending, 0);
	assert_int_equal(g_lxp_proc[0].live_children, 1); /* NOT decremented — the child lives */
	assert_int_equal(g_lxp_proc[0].child_count, 0);
}

/* A stopped child whose parent is NOT waiting (or waits without WUNTRACED) queues a STOPPED
 * notice + raises SIGCHLD, again without touching live_children. */
static void test_stop_notify_queues_without_wuntraced(void **state)
{
	(void)state;
	/* Parent blocked in wait4 but WITHOUT WUNTRACED → cannot take the stop → queue it. */
	g_lxp_proc[0].alive = 1;
	g_lxp_proc[0].pid = 1;
	g_lxp_proc[0].live_children = 1;
	g_lxp_proc[0].wait_pending = 1;
	g_lxp_proc[0].wait_pid = -1;
	g_lxp_proc[0].wait_options = 0;

	notify_parent_stopped(&g_mock_eng, /*ppid*/ 1, /*cpid*/ 7, LXP_SIGTSTP);

	assert_int_equal(g_mock.resume_calls, 0);	 /* the waiter is not woken */
	assert_int_equal(g_lxp_proc[0].wait_pending, 1); /* still blocked */
	assert_int_equal(g_lxp_proc[0].child_count, 1);
	assert_int_equal(g_lxp_proc[0].child_pid[0], 7);
	assert_int_equal(g_lxp_proc[0].child_status[0], LXP_SIGTSTP);
	assert_int_equal(g_lxp_proc[0].child_kind[0], LXP_CHILD_STOPPED);
	assert_int_equal(g_lxp_proc[0].live_children, 1); /* NOT decremented */
	assert_true(g_lxp_proc[0].pending_sigs & lxp_sig_bit(LXP_SIGCHLD));
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_system_version_routes_to_engine, reset_state),
		cmocka_unit_test_setup(test_resource_stats_track_slots_and_reserved_regions,
				       reset_state),
		cmocka_unit_test_setup(test_claim_slot_event_priority_and_consumption,
				       reset_state),
		cmocka_unit_test_setup(test_kill_targets_process_group, reset_state),
		cmocka_unit_test_setup(test_setpgid_getpgrp_track_group, reset_state),
		cmocka_unit_test_setup(test_console_sigint_targets_fg_group, reset_state),
		cmocka_unit_test_setup(test_console_sigtstp_targets_fg_group, reset_state),
		cmocka_unit_test_setup(test_sig_stops_proc_predicate, reset_state),
		cmocka_unit_test_setup(test_stop_notify_wakes_wuntraced_waiter, reset_state),
		cmocka_unit_test_setup(test_stop_notify_queues_without_wuntraced, reset_state),
		cmocka_unit_test_setup(test_encode_wstatus, reset_state),
		cmocka_unit_test_setup(test_dispatch_rejects_bad_tcsets_pointer, reset_state),
		cmocka_unit_test_setup(test_console_icrnl_translation, reset_state),
		cmocka_unit_test_setup(test_dispatch_class_defaults_deferred, reset_state),
		cmocka_unit_test_setup(test_deferred_requests_are_per_slot, reset_state),
		cmocka_unit_test_setup(test_deferred_generation_rejects_stale_work, reset_state),
		cmocka_unit_test_setup(test_deferred_same_slot_rejects_overwrite, reset_state),
		cmocka_unit_test_setup(test_deferred_signal_cancels_before_execute, reset_state),
		cmocka_unit_test_setup(test_console_icrnl_immediate_read, reset_state),
		cmocka_unit_test_setup(test_deferred_blocking_handoff_keeps_parked_task,
				       reset_state),
		cmocka_unit_test_setup(test_pending_deliverable, reset_state),
		cmocka_unit_test_setup(test_futex_has_corunner, reset_state),
		cmocka_unit_test_setup(test_futex_wake_marks_waiters, reset_state),
		cmocka_unit_test_setup(test_reap_wakes_blocking_parent, reset_state),
		cmocka_unit_test_setup(test_reap_signaled_child_status, reset_state),
		cmocka_unit_test_setup(test_reap_specific_pid_not_woken, reset_state),
		cmocka_unit_test_setup(test_reap_queues_zombie, reset_state),
		cmocka_unit_test_setup(test_reap_vfork_parent_suppresses_sigchld, reset_state),
		cmocka_unit_test_setup(test_reap_zombie_queue_full, reset_state),
		cmocka_unit_test_setup(test_reap_unknown_parent, reset_state),
		cmocka_unit_test_setup(test_notify_guest_exit_preserves_attribution, reset_state),
		cmocka_unit_test_setup(test_fork_capacity_accounts_live_and_zombie_children,
				       reset_state),
		cmocka_unit_test_setup(test_vfork_snapshot_publishes_cacheable_destination,
				       reset_state),
		cmocka_unit_test_setup(test_vfork_restore_publishes_cacheable_parent,
				       reset_state),
		cmocka_unit_test_setup(test_vfork_snapshot_refuses_no_spare_region,
				       reset_state),
		cmocka_unit_test_setup(test_vfork_restore_rejects_recycled_snapshot,
				       reset_state),
		cmocka_unit_test_setup(test_vfork_restore_rejects_recycled_parent,
				       reset_state),
		cmocka_unit_test_setup(test_region_free, reset_state),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
