/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "lxp/lxp_async_gate.h"

static void test_gate_correlates_owner_and_operation(void **state)
{
	(void)state;
	lxp_async_gate_t gate;
	lxp_async_gate_init(&gate);
	assert_int_equal(lxp_async_gate_enter(&gate, 7u), LXP_ASYNC_GATE_SYNC);

	lxp_async_gate_select(&gate, UINT64_C(0x100000003));
	assert_int_equal(lxp_async_gate_enter(&gate, 7u), LXP_ASYNC_GATE_SUBMIT);
	assert_int_equal(lxp_async_gate_enter(&gate, 7u), LXP_ASYNC_GATE_BLOCK);
	assert_int_equal(lxp_async_gate_complete(&gate), LXP_ASYNC_GATE_WAKE);

	lxp_async_gate_select(&gate, UINT64_C(0x100000004));
	assert_int_equal(lxp_async_gate_enter(&gate, 7u), LXP_ASYNC_GATE_BLOCK);
	lxp_async_gate_select(&gate, UINT64_C(0x100000003));
	assert_int_equal(lxp_async_gate_enter(&gate, 8u), LXP_ASYNC_GATE_BLOCK);
	assert_int_equal(lxp_async_gate_enter(&gate, 7u), LXP_ASYNC_GATE_COLLECT);
	lxp_async_gate_collected(&gate);
	assert_int_equal(lxp_async_gate_enter(&gate, 7u), LXP_ASYNC_GATE_SUBMIT);
}

static void test_active_cancel_is_retired_by_worker(void **state)
{
	(void)state;
	lxp_async_gate_t gate;
	lxp_async_gate_init(&gate);
	lxp_async_gate_select(&gate, 42u);
	assert_int_equal(lxp_async_gate_enter(&gate, 3u), LXP_ASYNC_GATE_SUBMIT);
	assert_int_equal(lxp_async_gate_cancel(&gate, 41u), LXP_ASYNC_GATE_CANCEL_NONE);
	assert_int_equal(lxp_async_gate_cancel(&gate, 42u), LXP_ASYNC_GATE_CANCEL_ACTIVE);
	assert_int_equal(lxp_async_gate_enter(&gate, 3u), LXP_ASYNC_GATE_BLOCK);
	assert_int_equal(lxp_async_gate_complete(&gate), LXP_ASYNC_GATE_DROP);
	assert_int_equal(lxp_async_gate_enter(&gate, 3u), LXP_ASYNC_GATE_BLOCK);
	lxp_async_gate_dropped(&gate);
	assert_int_equal(lxp_async_gate_enter(&gate, 3u), LXP_ASYNC_GATE_SUBMIT);
}

static void test_completed_cancel_and_failed_submit_return_idle(void **state)
{
	(void)state;
	lxp_async_gate_t gate;
	lxp_async_gate_init(&gate);
	lxp_async_gate_select(&gate, 99u);
	assert_int_equal(lxp_async_gate_enter(&gate, 1u), LXP_ASYNC_GATE_SUBMIT);
	lxp_async_gate_abort(&gate);
	assert_int_equal(lxp_async_gate_enter(&gate, 1u), LXP_ASYNC_GATE_SUBMIT);
	assert_int_equal(lxp_async_gate_complete(&gate), LXP_ASYNC_GATE_WAKE);
	assert_int_equal(lxp_async_gate_cancel(&gate, 99u), LXP_ASYNC_GATE_CANCEL_COMPLETE);
	assert_int_equal(lxp_async_gate_enter(&gate, 1u), LXP_ASYNC_GATE_BLOCK);
	lxp_async_gate_dropped(&gate);
	assert_int_equal(lxp_async_gate_enter(&gate, 1u), LXP_ASYNC_GATE_SUBMIT);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_gate_correlates_owner_and_operation),
		cmocka_unit_test(test_active_cancel_is_retired_by_worker),
		cmocka_unit_test(test_completed_cancel_and_failed_submit_return_idle),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
