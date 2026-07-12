/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Signal-delivery tests: drive src/lxp_signal.c (resolve_handler / sig_swallowed /
 * deliver_signal / sig_restore) directly over a synthetic svc frame. lxp_signal.c is
 * coupled to the coordinator only through three symbols (g_sig_save / slot_of /
 * park_frame, normally in the excluded lxp_run.c); this suite provides host stubs for
 * them, giving the signal TU its first unit coverage (before this it was reachable only
 * indirectly through QEMU).
 */
#include "../framework/lxp_test.h"
#include "lxp/lxp_seam.h"
#include "lxp/lxp_syscall.h"
#include "lxp_run_internal.h" /* struct sig_save_s + the lxp_signal.c prototypes */

#include <string.h>

/* ---- coordinator stubs (would be lxp_run.c) -------------------------------- */
struct sig_save_s g_sig_save[LXP_NSLOT];
static int g_park_calls;
int slot_of(const lxp_proc_t *p)
{
	(void)p;
	return 0; /* the tests use a single proc → slot 0 */
}
void park_frame(struct lxp_frame *f)
{
	(void)f;
	g_park_calls++;
}

#define SIG_CUSTOM 10 /* a signal with a custom handler (not SIGCHLD, in [1, NSIG)) */

static void test_sig_swallowed(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.sig_handler[SIG_CUSTOM] = LXP_SIG_IGN;
	assert_int_equal(sig_swallowed(&p, SIG_CUSTOM), 1); /* SIG_IGN */
	p.sig_handler[LXP_SIGCHLD] = LXP_SIG_DFL;
	assert_int_equal(sig_swallowed(&p, LXP_SIGCHLD), 1); /* SIG_DFL of a default-ignore signal */
	p.sig_handler[SIG_CUSTOM] = 0x4321;
	assert_int_equal(sig_swallowed(&p, SIG_CUSTOM), 0); /* a real handler is not swallowed */
}

static void test_resolve_handler_nonfdpic(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.is_fdpic = 0;
	p.sig_handler[SIG_CUSTOM] = 0xaaaa0000;
	p.sig_restorer[SIG_CUSTOM] = 0xbbbb0000;
	uintptr_t entry, restorer;
	uint32_t got;
	resolve_handler(&p, SIG_CUSTOM, &entry, &got, &restorer);
	assert_int_equal((uint32_t)entry, 0xaaaa0000); /* raw entry, no descriptor deref */
	assert_int_equal(got, 0);
	assert_int_equal((uint32_t)restorer, 0xbbbb0000);
}

static void test_resolve_handler_fdpic(void **st)
{
	(void)st;
	/* FDPIC: sa_handler/sa_restorer are {entry, GOT} descriptors — dereferenced. */
	uint32_t hdesc[2] = {0xc0de0000, 0x60700000}; /* {entry, GOT} */
	uint32_t rdesc[2] = {0x5e570000, 0};	      /* {restorer, -} */
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.is_fdpic = 1;
	p.sig_handler[SIG_CUSTOM] = (uintptr_t)hdesc;
	p.sig_restorer[SIG_CUSTOM] = (uintptr_t)rdesc;
	uintptr_t entry, restorer;
	uint32_t got;
	resolve_handler(&p, SIG_CUSTOM, &entry, &got, &restorer);
	assert_int_equal((uint32_t)entry, 0xc0de0000);
	assert_int_equal(got, 0x60700000);
	assert_int_equal((uint32_t)restorer, 0x5e570000);
}

static void test_deliver_bad_signal(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	deliver_signal(&f, &p, LXP_NSIG, 0); /* >= NSIG */
	assert_int_equal((int32_t)f.r[0], -LXP_EINVAL);
	deliver_signal(&f, &p, 0, 0); /* < 1 */
	assert_int_equal((int32_t)f.r[0], -LXP_EINVAL);
}

static void test_deliver_ignored(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.sig_handler[SIG_CUSTOM] = LXP_SIG_IGN;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[15] = 0x1000;
	g_sig_save[0].active = 0;
	deliver_signal(&f, &p, SIG_CUSTOM, 42);
	assert_int_equal((int32_t)f.r[0], 42);	 /* r0 = the interrupted result, no redirect */
	assert_int_equal(f.r[15], 0x1000);	 /* pc unchanged */
	assert_int_equal(g_sig_save[0].active, 0); /* nothing saved */
}

static void test_deliver_default_terminates(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.sig_handler[SIG_CUSTOM] = LXP_SIG_DFL;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	g_park_calls = 0;
	deliver_signal(&f, &p, SIG_CUSTOM, 0);
	assert_int_equal(p.exited, 1);
	assert_int_equal(p.exit_status, 128 + SIG_CUSTOM);
	assert_int_equal(g_park_calls, 1); /* the coordinator reaps the parked frame */
}

static void test_deliver_sigchld_swallowed(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.sig_handler[LXP_SIGCHLD] = LXP_SIG_DFL;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	deliver_signal(&f, &p, LXP_SIGCHLD, 7);
	assert_int_equal((int32_t)f.r[0], 7);
	assert_int_equal(p.exited, 0); /* SIGCHLD's default action is ignore, not terminate */
}

/* The core round-trip: push a handler frame, then rt_sigreturn restores the interrupted
 * context exactly. */
static void test_deliver_and_restore(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.is_fdpic = 0;
	p.sig_handler[SIG_CUSTOM] = 0xdead0000;	 /* handler entry */
	p.sig_restorer[SIG_CUSTOM] = 0xbeef0000; /* sa_restorer */
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[1] = 0x11;
	f.r[2] = 0x22;
	f.r[3] = 0x33;
	f.r[12] = 0xcc;
	f.r[14] = 0x2000; /* interrupted lr */
	f.r[15] = 0x1000; /* interrupted pc */
	f.xpsr = 0;
	g_sig_save[0].active = 0;

	deliver_signal(&f, &p, SIG_CUSTOM, 0);
	assert_int_equal(f.r[0], SIG_CUSTOM);		    /* r0 = signo */
	assert_int_equal(f.r[15], 0xdead0000u & ~1u);	    /* pc -> handler */
	assert_int_equal(f.r[14], 0xbeef0000u | 1u);	    /* lr -> restorer (Thumb) */
	assert_true((f.xpsr & (1u << 24)) != 0);	    /* xPSR.T set */
	assert_int_equal(g_sig_save[0].active, 1);
	assert_int_equal(g_sig_save[0].pc, 0x1000);	    /* interrupted context saved */
	assert_int_equal(g_sig_save[0].lr, 0x2000);
	assert_int_equal(g_sig_save[0].r1, 0x11);

	sig_restore(&f, &p);
	assert_int_equal(f.r[15], 0x1000u & ~1u); /* interrupted pc restored */
	assert_int_equal(f.r[14], 0x2000);
	assert_int_equal(f.r[1], 0x11);
	assert_int_equal(f.r[12], 0xcc);
	assert_int_equal(g_sig_save[0].active, 0);
}

int test_signal_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sig_swallowed),
		cmocka_unit_test(test_resolve_handler_nonfdpic),
		cmocka_unit_test(test_resolve_handler_fdpic),
		cmocka_unit_test(test_deliver_bad_signal),
		cmocka_unit_test(test_deliver_ignored),
		cmocka_unit_test(test_deliver_default_terminates),
		cmocka_unit_test(test_deliver_sigchld_swallowed),
		cmocka_unit_test(test_deliver_and_restore),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
