/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Host unit-test entry point: runs every registered suite (see framework/suites.inc)
 * and returns non-zero if any group had failures. Each test_<suite>_run() drives its
 * own cmocka group internally.
 */
#include <stdio.h>

#include "framework/lxp_test.h"
#include "fs/lxp_pipe.h"
#include "lxp/lxp_port_posix.h"
#if LXP_ENABLE_PTY
#include "lxp/lxp_pty.h"
#endif
#include "lxp_provider.h"

#if LXP_ENABLE_DEV_FB
const lxp_display_ops_t *lxp_test_display_ops(void);
#endif

static void runtime_reset(void)
{
	lxp_proc_runtime_reset();
	lxp_fd_runtime_reset();
	lxp_pipe_runtime_reset();
#if LXP_ENABLE_PTY
	lxp_pty_runtime_reset();
#endif
}

int main(void)
{
	int failures = 0;
	const lxp_display_ops_t *display_ops = NULL;
#if LXP_ENABLE_DEV_FB
	display_ops = lxp_test_display_ops();
#endif
	lxp_providers_publish(lxp_posix_net_ops(), display_ops);
#define LXP_SUITE(name, label)                                                                     \
	printf("=== " label " ===\n");                                                             \
	runtime_reset();                                                                            \
	failures += test_##name##_run();
#include "framework/suites.inc"
	printf("\n=== Summary: %d test group(s) had failures ===\n", failures);
	return failures ? 1 : 0;
}
