/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Host tests for the run-loop coordinator. The coordinator is excluded from the main test
 * binary because its 32-bit-target pointer casts warn on a 64-bit host and its OS-service
 * symbols clash with tests/stub_lnx_run.c. This binary links the coordinator exactly like
 * production and drives its policy modules against a mock engine with no guest threads
 * (tests/framework/lxp_mock_engine.c), one cmocka group per concern.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "framework/lxp_mock_engine.h"
#include "lxp/ports/posix.h"

#define LXP_COORD_SUITES(X) X(lifecycle) X(fork_exec) X(signal) X(futex) X(console) X(diag) X(run)

#define LXP_COORD_DECLARE(name) int test_coord_##name##_run(void);
LXP_COORD_SUITES(LXP_COORD_DECLARE)

int main(void)
{
	int failures = 0;
	g_test_net_ops = lxp_posix_net_ops();
#define LXP_COORD_RUN(name) failures += test_coord_##name##_run();
	LXP_COORD_SUITES(LXP_COORD_RUN)
	return failures != 0;
}
