/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Minimal cmocka harness for the host unit-test suites (migrated from oveRTOS).
 * Each suite builds its own CMUnitTest[] and calls cmocka_run_group_tests; the
 * dispatcher (stub_main.c) invokes every registered test_<suite>_run().
 */
#ifndef LXP_TEST_H
#define LXP_TEST_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

/* The suites assert against OVE_OK; in lxp that is LXP_OK (0). */
#include "lxp/lxp_types.h"
#ifndef OVE_OK
#define OVE_OK LXP_OK
#endif

/* Controls for tests/stub_lnx_run.c's deterministic entropy provider. */
extern int g_lxp_test_random_result;
extern size_t g_lxp_test_random_calls;
extern size_t g_lxp_test_random_len;
extern int g_lxp_test_mem_stats_result;
extern struct lxp_mem_stats g_lxp_test_mem_stats;

/* Suite entry points — one per tests/suites/test_<name>.c. */
int test_arena_run(void);
int test_loader_run(void);
int test_loader_fdpic_run(void);
int test_fs_run(void);
int test_overflow_run(void);
int test_signal_run(void);
int test_linux_syscall_run(void);
int test_syscall_conformance_run(void);
int test_linux_dev_run(void);
int test_linux_net_run(void);
int test_linux_netfs_run(void);
int test_linux_pty_run(void);

#endif /* LXP_TEST_H */
