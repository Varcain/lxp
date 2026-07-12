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

int main(void)
{
	int failures = 0;
#define LXP_SUITE(name, label)                                                                     \
	printf("=== " label " ===\n");                                                             \
	failures += test_##name##_run();
#include "framework/suites.inc"
	printf("\n=== Summary: %d test group(s) had failures ===\n", failures);
	return failures ? 1 : 0;
}
