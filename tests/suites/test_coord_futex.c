/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator tests for futex co-runner detection and FUTEX_WAKE bookkeeping.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "../framework/lxp_coord_fixture.h"
#include "../framework/lxp_mock_engine.h"

/* ---- futex: co-runner gate + FUTEX_WAKE bookkeeping ------------------------- */
/* lxp_futex_has_corunner: a FUTEX_WAIT only parks when another live thread shares the region
 * (else nobody could ever wake it). */
static void test_futex_has_corunner(void **state)
{
	(void)state;
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.mm->region.index = 2;
	assert_false(lxp_futex_has_corunner(&g_lxp_rt.slots[0].proc)); /* alone in region 2 */

	g_lxp_rt.slots[1].proc.alive = 1;
	g_lxp_rt.slots[1].proc.mm->region.index = 3;
	/* a live proc, but a different region */
	assert_false(lxp_futex_has_corunner(&g_lxp_rt.slots[0].proc));

	lxp_proc_mm_put(&g_lxp_rt.slots[2].proc);
	assert_int_equal(lxp_proc_mm_fork(&g_lxp_rt.slots[2].proc, &g_lxp_rt.slots[0].proc,
					  LXP_CLONE_VM),
			 0);
	g_lxp_rt.slots[2].proc.alive = 1;
	/* a co-runner shares the mm */
	assert_true(lxp_futex_has_corunner(&g_lxp_rt.slots[0].proc));

	g_lxp_rt.slots[2].proc.alive = 0;
	/* it exited -> no longer a co-runner */
	assert_false(lxp_futex_has_corunner(&g_lxp_rt.slots[0].proc));
}

/* FUTEX_WAKE marks up to `val` waiters queued on the same uaddr (and no others). The
 * addresses here are only compared, never dereferenced, so plain integers stand in for the
 * 32-bit guest pointers (the deref path is covered on-target by the M5 QEMU guest). */
static void test_futex_wake_marks_waiters(void **state)
{
	(void)state;
	const uint32_t uaddr = 0x2000, other = 0x3000;
	g_lxp_rt.slots[1].proc.alive = 1;
	g_lxp_rt.slots[1].proc.wait.kind = LXP_WAIT_FUTEX;
	g_lxp_rt.slots[1].proc.wait.data.futex.uaddr = uaddr;
	g_lxp_rt.slots[2].proc.alive = 1;
	g_lxp_rt.slots[2].proc.wait.kind = LXP_WAIT_FUTEX;
	g_lxp_rt.slots[2].proc.wait.data.futex.uaddr = uaddr;
	g_lxp_rt.slots[3].proc.alive = 1;
	g_lxp_rt.slots[3].proc.wait.kind = LXP_WAIT_FUTEX;
	g_lxp_rt.slots[3].proc.wait.data.futex.uaddr = other;

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[0] = uaddr;
	f.r[1] = 1; /* FUTEX_WAKE */
	f.r[2] = 1; /* wake at most one */
	lxp_futex(&f, &g_lxp_rt.slots[0].proc, 0);

	assert_int_equal(f.r[0], 1); /* reported one woken */
	assert_int_equal(g_lxp_rt.slots[1].proc.wait.data.futex.woken +
				 g_lxp_rt.slots[2].proc.wait.data.futex.woken,
			 1);
	assert_int_equal(g_lxp_rt.slots[3].proc.wait.data.futex.woken, 0);

	/* A second WAKE(all) picks up the remaining waiter on uaddr, still not the other. */
	memset(&f, 0, sizeof(f));
	f.r[0] = uaddr;
	f.r[1] = 1;
	f.r[2] = 0x7fffffff;
	lxp_futex(&f, &g_lxp_rt.slots[0].proc, 0);
	assert_int_equal(f.r[0], 1); /* the one still-parked waiter */
	assert_int_equal(g_lxp_rt.slots[1].proc.wait.data.futex.woken, 1);
	assert_int_equal(g_lxp_rt.slots[2].proc.wait.data.futex.woken, 1);
	assert_int_equal(g_lxp_rt.slots[3].proc.wait.data.futex.woken, 0);
}

int test_coord_futex_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_futex_has_corunner, reset_state),
		cmocka_unit_test_setup(test_futex_wake_marks_waiters, reset_state),
	};
	return cmocka_run_group_tests_name("coordinator: futex", tests, NULL, NULL);
}
