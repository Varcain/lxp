/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "../framework/lxp_test.h"
#include "lxp/lxp_linux_uapi.h"
#include "lxp/lxp_rt_metrics.h"

static void test_svc_window_and_lifetime_are_owned_by_lxp(void **state)
{
	(void)state;
	lxp_rt_svc_metrics_t window;
	lxp_rt_svc_metrics_t total;

	lxp_rt_svc_metrics_record(LXP_NR_read, 40u);
	lxp_rt_svc_metrics_record(LXP_NR_write, 20u);
	lxp_rt_svc_metrics_record(LXP_NR_clock_gettime64, 60u);
	lxp_rt_svc_metrics_take(&window, &total);

	assert_int_equal(window.calls, 3u);
	assert_int_equal(window.min_cycles, 20u);
	assert_int_equal(window.max_cycles, 60u);
	assert_int_equal(window.total_cycles, 120u);
	assert_int_equal(window.max_syscall, LXP_NR_clock_gettime64);
	assert_memory_equal(&total, &window, sizeof(total));

	lxp_rt_svc_metrics_t snapshot;
	lxp_rt_svc_metrics_snapshot(&snapshot);
	assert_memory_equal(&snapshot, &total, sizeof(snapshot));

	lxp_rt_svc_metrics_take(&window, &total);
	assert_int_equal(window.calls, 0u);
	assert_int_equal(total.calls, 3u);
}

static void test_syscall_names_remain_canonical(void **state)
{
	(void)state;
	assert_string_equal(lxp_rt_syscall_name(LXP_NR_read), "read");
	assert_string_equal(lxp_rt_syscall_name(LXP_NR_clock_gettime64), "clock_gettime64");
	assert_string_equal(lxp_rt_syscall_name(UINT32_MAX), "?");
}

int test_rt_metrics_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_svc_window_and_lifetime_are_owned_by_lxp),
		cmocka_unit_test(test_syscall_names_remain_canonical),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
