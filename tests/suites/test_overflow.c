/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Stage-2 memory-safety regression tests. Each asserts the defensive bound/guard a
 * fix added, so a revert fails here. On the 64-bit host the 32-bit size_t WRAP the
 * fixes ultimately target cannot itself occur, but the guards are observable, and
 * under the ASan/UBSan CI build a reverted bound scans OOB past the small test
 * buffers and aborts. (The pure 32-bit wraps in pwrite/arena/tmpfs, and the kill
 * signal-range check that lives in the excluded coordinator, are covered by the
 * cross-compiled gate matrix + on-target QEMU instead.)
 */
#include "../framework/lxp_test.h"
#include "lxp/lxp_arena.h"
#include "lxp/lxp_syscall.h"

#include <stdint.h>
#include <string.h>

static uint8_t g_pool[8192] __attribute__((aligned(16)));

static void setup_proc(lxp_proc_t *p, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_pool, sizeof(g_pool)), LXP_OK);
	assert_int_equal(lxp_proc_init(p, arena, 4096), LXP_OK);
	p->region_lo = 1;
	p->region_hi = UINTPTR_MAX; /* all-permitting; a test narrows it when needed */
	p->pool_lo = p->pool_hi = 0;
}

/* 2a: poll caps nfds at LXP_MAX_FDS before the nfds*sizeof(pollfd) that can wrap a
 * 32-bit size_t. A larger nfds over the small pf[] would scan OOB (ASan) pre-fix. */
static void test_poll_nfds_bound(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	lxp_pollfd pf[4];
	memset(pf, 0, sizeof(pf));
	long r = lxp_syscall(&p, LXP_NR_poll, (long)(uintptr_t)pf, LXP_MAX_FDS + 1, 0, 0, 0, 0);
	assert_int_equal(r, -LXP_EINVAL);
}

/* 2b: writev caps iovcnt at IOV_MAX before the iovcnt*sizeof(iovec) multiply. */
static void test_writev_iovcnt_bound(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	lxp_iovec iov[2];
	memset(iov, 0, sizeof(iov));
	long r = lxp_syscall(&p, LXP_NR_writev, 1, (long)(uintptr_t)iov, 2000, 0, 0, 0);
	assert_int_equal(r, -LXP_EINVAL);
}

/* 2g: dup(2)/dup2 clear FD_CLOEXEC on the new fd (Linux ABI). */
static void test_dup_clears_cloexec(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	p.fds[0].cloexec = 1; /* mark stdin close-on-exec */
	long nf = lxp_syscall(&p, LXP_NR_dup, 0, 0, 0, 0, 0, 0);
	assert_true(nf >= 3);
	assert_int_equal(p.fds[nf].cloexec, 0);
}

/* 2g: dup3(fd, fd, ...) is EINVAL (unlike dup2, which no-ops). */
static void test_dup3_same_fd_einval(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	long r = lxp_syscall(&p, LXP_NR_dup3, 0, 0, 0, 0, 0, 0);
	assert_int_equal(r, -LXP_EINVAL);
}

/* 2e: symlink(2) validates the target pointer (it is stored verbatim, then strlen'd).
 * With the region narrowed to cover only linkp, the far target is out of range and is
 * rejected -EFAULT; pre-fix the unchecked target was strlen'd from arbitrary memory. */
static char g_far_target[] = "loop/back/target";
static void test_symlink_target_fault(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	static char lbuf[64];
	strcpy(lbuf, "/tmp/lnk");
	p.region_lo = (uintptr_t)lbuf; /* in range: linkp; out of range: the far target */
	p.region_hi = (uintptr_t)(lbuf + sizeof(lbuf));
	long r = lxp_syscall(&p, LXP_NR_symlink, (long)(uintptr_t)g_far_target,
			     (long)(uintptr_t)lbuf, 0, 0, 0, 0);
	assert_int_equal(r, -LXP_EFAULT);
}

int test_overflow_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_poll_nfds_bound),
		cmocka_unit_test(test_writev_iovcnt_bound),
		cmocka_unit_test(test_dup_clears_cloexec),
		cmocka_unit_test(test_dup3_same_fd_einval),
		cmocka_unit_test(test_symlink_target_fault),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
