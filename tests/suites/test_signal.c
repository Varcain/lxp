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
struct sig_save_stack_s g_sig_save[LXP_NSLOT];
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
#define SIG_NESTED 12 /* a different catchable signal, eligible during SIG_CUSTOM */

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
	p.sig_restorer = 0xbbbb0000;
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
	p.sig_restorer = (uintptr_t)rdesc;
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
	g_sig_save[0].depth = 0;
	deliver_signal(&f, &p, SIG_CUSTOM, 42);
	assert_int_equal((int32_t)f.r[0], 42);	 /* r0 = the interrupted result, no redirect */
	assert_int_equal(f.r[15], 0x1000);	 /* pc unchanged */
	assert_int_equal(g_sig_save[0].depth, 0); /* nothing saved */
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
	p.sig_restorer = 0xbeef0000; /* sa_restorer */
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	struct lxp_fp_context fp;
	memset(&fp, 0, sizeof(fp));
	for (int i = 0; i < 32; i++)
		fp.s[i] = 0x40000000u + (uint32_t)i;
	fp.fpscr = 0x01800000u;
	fp.active = 1;
	f.fp = &fp;
	struct lxp_fp_context interrupted_fp = fp;
	f.r[1] = 0x11;
	f.r[2] = 0x22;
	f.r[3] = 0x33;
	f.r[12] = 0xcc;
	f.r[14] = 0x2000; /* interrupted lr */
	f.r[15] = 0x1000; /* interrupted pc */
	f.xpsr = 0;
	g_sig_save[0].depth = 0;

	deliver_signal(&f, &p, SIG_CUSTOM, 0);
	assert_int_equal(f.r[0], SIG_CUSTOM);		    /* r0 = signo */
	assert_int_equal(f.r[15], 0xdead0000u & ~1u);	    /* pc -> handler */
	assert_int_equal(f.r[14], 0xbeef0000u | 1u);	    /* lr -> restorer (Thumb) */
	assert_true((f.xpsr & (1u << 24)) != 0);	    /* xPSR.T set */
	assert_int_equal(g_sig_save[0].depth, 1);
	assert_int_equal(g_sig_save[0].frame[0].pc, 0x1000); /* interrupted context saved */
	assert_int_equal(g_sig_save[0].frame[0].lr, 0x2000);
	/* the full r1-r3 caller-arg triple is saved (the class of the M2 wait4 resume bug). */
	assert_int_equal(g_sig_save[0].frame[0].r1, 0x11);
	assert_int_equal(g_sig_save[0].frame[0].r2, 0x22);
	assert_int_equal(g_sig_save[0].frame[0].r3, 0x33);
	assert_memory_equal(&g_sig_save[0].frame[0].fp, &interrupted_fp,
			    sizeof(interrupted_fp));
	/* Model arbitrary floating-point work by the handler. */
	memset(&fp, 0xa5, sizeof(fp));

	sig_restore(&f, &p);
	assert_int_equal(f.r[15], 0x1000u & ~1u); /* interrupted pc restored */
	assert_int_equal(f.r[14], 0x2000);
	assert_int_equal(f.r[1], 0x11); /* r1-r3 restored exactly */
	assert_int_equal(f.r[2], 0x22);
	assert_int_equal(f.r[3], 0x33);
	assert_int_equal(f.r[12], 0xcc);
	assert_memory_equal(&fp, &interrupted_fp, sizeof(interrupted_fp));
	assert_int_equal(g_sig_save[0].depth, 0);
}

/* A spurious rt_sigreturn (no signal frame in flight) is a safe no-op — it must not corrupt
 * the interrupted context. */
static void test_sig_restore_noop(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[0] = 0x1234;
	f.r[15] = 0x5678;
	g_sig_save[0].depth = 0;
	sig_restore(&f, &p);
	assert_int_equal(f.r[0], 0x1234); /* untouched */
	assert_int_equal(f.r[15], 0x5678);
}

/* Different unblocked signals may interrupt an active handler. Their core, FDPIC
 * GOT, floating-point, and mask state must unwind in strict LIFO order. */
static void test_nested_delivery_restores_lifo(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.sig_handler[SIG_CUSTOM] = 0xdead0000;
	p.sig_handler[SIG_NESTED] = 0xcafe0000;
	p.sig_restorer = 0xbeef0000;
	p.sig_blocked = lxp_sig_bit(LXP_SIGALRM);

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	struct lxp_fp_context fp;
	memset(&fp, 0, sizeof(fp));
	for (int i = 0; i < 32; i++)
		fp.s[i] = 0x10000000u + (uint32_t)i;
	fp.fpscr = 0x01000000u;
	fp.active = 1;
	f.fp = &fp;
	struct lxp_fp_context interrupted_fp = fp;

	f.r[1] = 0x11;
	f.r[9] = 0x99;
	f.r[12] = 0xcc;
	f.r[14] = 0x2000;
	f.r[15] = 0x1000;
	f.xpsr = 0x21000000u;
	g_sig_save[0].depth = 0;

	deliver_signal(&f, &p, SIG_CUSTOM, 77);
	assert_int_equal(g_sig_save[0].depth, 1);
	assert_true(lxp_sig_blocked(&p, SIG_CUSTOM));

	/* State at a syscall boundary inside the outer handler. */
	f.r[1] = 0x1111;
	f.r[9] = 0x9999;
	f.r[12] = 0xcccc;
	f.r[14] = 0xbeef0001;
	f.r[15] = 0xdead0100;
	f.xpsr = 0x61000000u;
	for (int i = 0; i < 32; i++)
		fp.s[i] = 0x20000000u + (uint32_t)i;
	fp.fpscr = 0x02000000u;
	struct lxp_fp_context outer_handler_fp = fp;

	deliver_signal(&f, &p, SIG_NESTED, -LXP_EINTR);
	assert_int_equal(g_sig_save[0].depth, 2);
	assert_int_equal(g_sig_save[0].frame[0].pc, 0x1000);
	assert_int_equal(g_sig_save[0].frame[1].pc, 0xdead0100);
	assert_true(lxp_sig_blocked(&p, SIG_CUSTOM));
	assert_true(lxp_sig_blocked(&p, SIG_NESTED));
	memset(&fp, 0xa5, sizeof(fp)); /* arbitrary VFP work in the inner handler */

	sig_restore(&f, &p);
	assert_int_equal(g_sig_save[0].depth, 1);
	assert_int_equal((int32_t)f.r[0], -LXP_EINTR);
	assert_int_equal(f.r[1], 0x1111);
	assert_int_equal(f.r[9], 0x9999);
	assert_int_equal(f.r[15], 0xdead0100);
	assert_memory_equal(&fp, &outer_handler_fp, sizeof(fp));
	assert_true(lxp_sig_blocked(&p, SIG_CUSTOM));
	assert_false(lxp_sig_blocked(&p, SIG_NESTED));

	sig_restore(&f, &p);
	assert_int_equal(g_sig_save[0].depth, 0);
	assert_int_equal(f.r[0], 77);
	assert_int_equal(f.r[1], 0x11);
	assert_int_equal(f.r[9], 0x99);
	assert_int_equal(f.r[12], 0xcc);
	assert_int_equal(f.r[14], 0x2000);
	assert_int_equal(f.r[15], 0x1000);
	assert_memory_equal(&fp, &interrupted_fp, sizeof(fp));
	assert_false(lxp_sig_blocked(&p, SIG_CUSTOM));
	assert_true(lxp_sig_blocked(&p, LXP_SIGALRM));
}

/* The pre-sigsuspend mask belongs to the handler that woke the wait. A signal
 * nested inside that handler must first restore the outer handler's mask. */
static void test_nested_sigsuspend_mask_restore(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.sig_handler[SIG_CUSTOM] = 0xdead0000;
	p.sig_handler[SIG_NESTED] = 0xcafe0000;
	p.sig_restorer = 0xbeef0000;
	uint64_t before_suspend = lxp_sig_bit(LXP_SIGALRM);
	uint64_t wait_mask = lxp_sig_bit(LXP_SIGINT);
	p.sig_blocked = wait_mask;
	p.sigsuspend_saved_mask = before_suspend;
	p.sigsuspend_active = 1;

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	g_sig_save[0].depth = 0;
	deliver_signal(&f, &p, SIG_CUSTOM, -LXP_EINTR);
	assert_int_equal(p.sigsuspend_active, 0);
	assert_int_equal(g_sig_save[0].frame[0].saved_mask, before_suspend);
	assert_int_equal(p.sig_blocked, wait_mask | lxp_sig_bit(SIG_CUSTOM));

	deliver_signal(&f, &p, SIG_NESTED, 0);
	assert_int_equal(g_sig_save[0].frame[1].saved_mask,
			 wait_mask | lxp_sig_bit(SIG_CUSTOM));
	sig_restore(&f, &p);
	assert_int_equal(p.sig_blocked, wait_mask | lxp_sig_bit(SIG_CUSTOM));
	sig_restore(&f, &p);
	assert_int_equal(p.sig_blocked, before_suspend);
}

/* Exhausting the fixed host stack is a defined guest-local failure. The oldest
 * frame remains intact and the coordinator is asked to reap the process. */
static void test_signal_depth_overflow_is_contained(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[15] = 0x12340000;
	g_sig_save[0].depth = 0;
	g_park_calls = 0;

	p.sig_handler[SIG_CUSTOM] = 0x80000000u;
	for (unsigned i = 0; i < LXP_SIGNAL_NEST_MAX; i++) {
		/* A handler may explicitly unblock itself with rt_sigprocmask. Model
		 * that legitimate recursive-delivery path without requiring one unique
		 * signal number for every configurable stack level. */
		p.sig_blocked &= ~lxp_sig_bit(SIG_CUSTOM);
		deliver_signal(&f, &p, SIG_CUSTOM, 0);
	}
	uint32_t oldest_pc = g_sig_save[0].frame[0].pc;
	p.sig_blocked &= ~lxp_sig_bit(SIG_CUSTOM);
	deliver_signal(&f, &p, SIG_CUSTOM, 0);

	assert_int_equal(g_sig_save[0].depth, LXP_SIGNAL_NEST_MAX);
	assert_int_equal(g_sig_save[0].frame[0].pc, oldest_pc);
	assert_int_equal(p.exited, 1);
	assert_int_equal(p.exit_status, 128 + LXP_SIGSEGV);
	assert_int_equal(g_park_calls, 1);
}

/* A delivered handler blocks its own signal for its duration (no reentry), preserving any
 * previously-blocked signals; rt_sigreturn restores the prior mask. SIGKILL/SIGSTOP always
 * report deliverable, even if their mask bit is set. */
static void test_deliver_masks_signal(void **st)
{
	(void)st;
	lxp_proc_t p;
	memset(&p, 0, sizeof(p));
	p.is_fdpic = 0;
	p.sig_handler[SIG_CUSTOM] = 0xdead0000;
	p.sig_restorer = 0xbeef0000;
	p.sig_blocked = lxp_sig_bit(LXP_SIGALRM); /* a pre-existing block to preserve */
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	g_sig_save[0].depth = 0;

	deliver_signal(&f, &p, SIG_CUSTOM, 0);
	assert_true(lxp_sig_blocked(&p, SIG_CUSTOM));  /* self-blocked for the handler */
	assert_true(lxp_sig_blocked(&p, LXP_SIGALRM)); /* the prior block is preserved */
	/* A self-signal while its handler is active is deferred, not recursively
	 * delivered into a second frame. */
	deliver_signal(&f, &p, SIG_CUSTOM, 0);
	assert_int_equal(g_sig_save[0].depth, 1);
	assert_true((p.pending_sigs & lxp_sig_bit(SIG_CUSTOM)) != 0);

	sig_restore(&f, &p);
	assert_false(lxp_sig_blocked(&p, SIG_CUSTOM));  /* handler self-block undone */
	assert_true(lxp_sig_blocked(&p, LXP_SIGALRM));	/* prior mask restored */

	p.sig_blocked = (uint64_t)-1; /* everything "blocked" */
	assert_false(lxp_sig_blocked(&p, LXP_SIGKILL)); /* ...but these two never are */
	assert_false(lxp_sig_blocked(&p, LXP_SIGSTOP));
	assert_true(lxp_sig_blocked(&p, SIG_CUSTOM));
}

int test_signal_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sig_swallowed),
		cmocka_unit_test(test_deliver_masks_signal),
		cmocka_unit_test(test_resolve_handler_nonfdpic),
		cmocka_unit_test(test_resolve_handler_fdpic),
		cmocka_unit_test(test_deliver_bad_signal),
		cmocka_unit_test(test_deliver_ignored),
		cmocka_unit_test(test_deliver_default_terminates),
		cmocka_unit_test(test_deliver_sigchld_swallowed),
		cmocka_unit_test(test_deliver_and_restore),
		cmocka_unit_test(test_sig_restore_noop),
		cmocka_unit_test(test_nested_delivery_restores_lifo),
		cmocka_unit_test(test_nested_sigsuspend_mask_restore),
		cmocka_unit_test(test_signal_depth_overflow_is_contained),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
