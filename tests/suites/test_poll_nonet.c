/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * poll and select in a build without networking (LXP_ENABLE_NET=0, PTY on): the
 * readiness of ptys and eventfds and the ability to wait must not depend on the
 * socket layer. A standalone executable, since the main test binary builds every
 * feature in.
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <cmocka.h>

#include "framework/lxp_test.h"
#include "framework/lxp_proc_fixture.h"
#include "fs/lxp_poll.h"
#include "lxp/lxp_seam.h"
#include "lxp_run_internal.h" /* struct sig_save_stack_s, slot_of, park_frame */

#if LXP_ENABLE_NET || !LXP_ENABLE_PTY
#error "this suite checks the build with networking off and ptys on"
#endif

#define SC(...) lxp_syscall(__VA_ARGS__)

/* lxp_signal.c's coordinator symbols (lxp_run.c is not linked; see test_signal.c). */
struct sig_save_stack_s g_sig_save[LXP_NSLOT];
int slot_of(const lxp_proc_t *p)
{
	(void)p;
	return 0;
}
void park_frame(struct lxp_frame *f, lxp_proc_t *proc)
{
	(void)f;
	(void)proc;
}

static long poll_pump(lxp_proc_t *p)
{
	for (int i = 0; i < 2000; i++) {
		long rc = lxp_poll_retry(p);
		if (rc != -LXP_EAGAIN) {
			(void)lxp_wait_complete(p, LXP_WAIT_POLL);
			return rc;
		}
		struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000};
		nanosleep(&ts, NULL);
	}
	return -LXP_EAGAIN;
}

/* An idle pty master is not readable: poll waits until the slave writes. */
static void test_nonet_pty_poll_waits(void **state)
{
	(void)state;
	lxp_proc_t p;
	lxp_conf_t *fx = lxp_conf_begin(&p, NULL, 0);
	if (!fx) {
		skip();
		return;
	}
	long m = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/dev/ptmx"),
		    LXP_O_RDWR, 0, 0, 0);
	assert_true(m >= 3);
	uint32_t *ptn = lxp_conf_alloc(fx, sizeof(uint32_t));
	assert_int_equal(SC(&p, LXP_NR_ioctl, m, LXP_TIOCGPTN, (long)(uintptr_t)ptn, 0, 0, 0), 0);
	char path[16] = "/dev/pts/";
	path[9] = (char)('0' + *ptn);
	long sl = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, path),
		     LXP_O_RDWR, 0, 0, 0);
	assert_true(sl >= 3);

	lxp_pollfd *pf = lxp_conf_alloc(fx, sizeof(lxp_pollfd));
	pf->fd = (int)m;
	pf->events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 1, -1, 0, 0, 0), 0);
	assert_int_equal(p.wait.kind, LXP_WAIT_POLL);
	assert_int_equal(lxp_poll_retry(&p), -LXP_EAGAIN);
	assert_int_equal(SC(&p, LXP_NR_write, sl, (long)(uintptr_t)lxp_conf_str(fx, "x"), 1, 0, 0,
			    0),
			 1);
	assert_int_equal(poll_pump(&p), 1);
	assert_int_equal(pf->revents, LXP_POLLIN);
}

/* An eventfd is readable only once its counter is written, and select exists. */
static void test_nonet_eventfd_and_select(void **state)
{
	(void)state;
	lxp_proc_t p;
	lxp_conf_t *fx = lxp_conf_begin(&p, NULL, 0);
	if (!fx) {
		skip();
		return;
	}
	long efd = SC(&p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0);
	assert_true(efd >= 3);
	lxp_pollfd *pf = lxp_conf_alloc(fx, sizeof(lxp_pollfd));
	pf->fd = (int)efd;
	pf->events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 1, 0, 0, 0, 0), 0);

	uint32_t *rset = lxp_conf_alloc(fx, sizeof(uint32_t));
	int64_t *zero = lxp_conf_alloc(fx, 2 * sizeof(int64_t)); /* {0, 0}: do not wait */
	*rset = 1u << efd;
	assert_int_equal(SC(&p, LXP_NR_pselect6_time64, efd + 1, (long)(uintptr_t)rset, 0, 0,
			    (long)(uintptr_t)zero, 0),
			 0);
	uint64_t *ctr = lxp_conf_alloc(fx, sizeof(uint64_t));
	*ctr = 1;
	assert_int_equal(SC(&p, LXP_NR_write, efd, (long)(uintptr_t)ctr, 8, 0, 0, 0), 8);
	*rset = 1u << efd;
	assert_int_equal(SC(&p, LXP_NR_pselect6_time64, efd + 1, (long)(uintptr_t)rset, 0, 0,
			    (long)(uintptr_t)zero, 0),
			 1);
	assert_int_equal(*rset, 1u << efd);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_nonet_pty_poll_waits),
		cmocka_unit_test(test_nonet_eventfd_and_select),
	};
	return cmocka_run_group_tests_name("poll without networking", tests, NULL, NULL);
}
