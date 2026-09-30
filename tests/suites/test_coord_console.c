/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator tests for console input: typeahead, ICRNL, the ^C/^Z check and run-scoped console
 * readiness.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "lxp_syscall.h"
#include "fs/lxp_tty.h"
#include "lxp_internal.h"
#include "run/lxp_validate.h"
#include "../framework/lxp_coord_fixture.h"
#include "../framework/lxp_mock_engine.h"

/* A foreground guest that reads the console from a mock-region buffer. */
static lxp_proc_t *make_console_reader(int slot, uint8_t **buf)
{
	make_valid_running_slot(slot, slot);
	lxp_proc_t *p = &g_lxp_rt.slots[slot].proc;
	p->mm->region_lo = (uintptr_t)g_mock_regions[slot];
	p->mm->region_hi = (uintptr_t)g_mock_regions[slot] + sizeof(g_mock_regions[slot]);
	p->read_fn = script_console_read;
	p->console_poll = script_console_poll;
	p->group->pgid = p->pid;
	lxp_console_tty()->fg_pgrp = p->pid;
	*buf = g_mock_regions[slot];
	return p;
}

/* With ISIG on and no guest parked in a console read, the coordinator polls the
 * console for ^C/^Z. Bytes it reads that are not interrupts are typeahead: the next
 * console reads must receive them in order instead of losing them. */
static void test_console_interrupt_poll_keeps_typeahead(void **state)
{
	(void)state;
	uint8_t *buf;
	lxp_proc_t *p = make_console_reader(2, &buf);
	const lxp_run_config_t cfg = {.read_fn = script_console_read,
				      .console_poll = script_console_poll};
	g_lxp_rt.cfg = &cfg;
	console_script("ro\003t\r", 5);

	for (int i = 0; i < 5; i++)
		(void)lxp_scan_blocked(1);
	assert_int_equal(g_console_script.pos, 5);
	assert_true(p->pending_sigs & lxp_sig_bit(LXP_SIGINT));

	const char expected[] = {'r', 'o', 't', '\n'}; /* ^C consumed; ICRNL maps CR */
	for (size_t i = 0; i < sizeof(expected); i++) {
		buf[0] = 0;
		assert_int_equal(
			lxp_syscall(p, LXP_NR_read, 0, (long)(uintptr_t)buf, 1, 0, 0, 0), 1);
		assert_int_equal(buf[0], (uint8_t)expected[i]);
	}
	assert_int_equal(p->wait.kind, LXP_WAIT_NONE);
}

/* A full typeahead queue stops the interrupt poll; later bytes stay with the
 * console transport instead of being read and dropped. */
static void test_console_interrupt_poll_backpressure(void **state)
{
	(void)state;
	uint8_t *buf;
	(void)make_console_reader(2, &buf);
	const lxp_run_config_t cfg = {.read_fn = script_console_read,
				      .console_poll = script_console_poll};
	g_lxp_rt.cfg = &cfg;
	static char input[LXP_CONSOLE_TYPEAHEAD + 8];
	memset(input, 'x', sizeof(input));
	console_script(input, sizeof(input));

	for (size_t i = 0; i < sizeof(input); i++)
		(void)lxp_scan_blocked(1);
	assert_int_equal(g_console_script.pos, LXP_CONSOLE_TYPEAHEAD);
}

/* poll(2) must report a console fd readable while typeahead is queued, even when
 * the transport itself has nothing pending. */
static void test_console_poll_reports_queued_typeahead(void **state)
{
	(void)state;
	uint8_t *buf;
	lxp_proc_t *p = make_console_reader(2, &buf);
	const lxp_run_config_t cfg = {.read_fn = script_console_read,
				      .console_poll = script_console_poll};
	g_lxp_rt.cfg = &cfg;
	console_script("k", 1);
	(void)lxp_scan_blocked(1);
	assert_false(script_console_poll(NULL));

	lxp_pollfd *pfd = (lxp_pollfd *)(void *)(buf + 64);
	pfd->fd = 0;
	pfd->events = LXP_POLLIN;
	pfd->revents = 0;
	assert_int_equal(lxp_syscall(p, LXP_NR_poll, (long)(uintptr_t)pfd, 1, 0, 0, 0, 0), 1);
	assert_int_equal(pfd->revents, LXP_POLLIN);
}

static void test_console_readiness_lifecycle_is_run_scoped(void **state)
{
	(void)state;
	uint8_t image[1] = {0};
	const lxp_file_t files[] = {
		{.path = "/init", .data = image, .size = sizeof(image), .mode = LXP_S_IFREG | 0755},
	};
	lxp_run_config_t cfg = {
		.rootfs = files,
		.rootfs_count = 1,
		.rootfs_image = image,
		.rootfs_image_size = sizeof(image),
		.read_fn = mock_console_read,
		.console_poll = mock_console_poll,
		.console_subscribe = mock_console_subscribe,
		.console_unsubscribe = mock_console_unsubscribe,
	};
	const char *const argv[] = {"init", NULL};
	lxp_net_ops_t net_ops = *g_test_net_ops;
	net_ops.run_begin = mock_net_begin;
	net_ops.run_end = mock_net_end;

	/* A one-sided lifecycle or an event source without poll/read semantics is
	 * rejected before any provider or OS state is acquired. */
	cfg.console_unsubscribe = NULL;
	assert_false(lxp_run_config_valid(&cfg));
	cfg.console_unsubscribe = mock_console_unsubscribe;
	cfg.console_poll = NULL;
	assert_false(lxp_run_config_valid(&cfg));
	cfg.console_poll = mock_console_poll;
	assert_true(lxp_run_config_valid(&cfg));

	/* Subscription happens only after host preparation. Failure tears the host
	 * and earlier providers down, but does not unsubscribe an unacquired source. */
	g_mock.console_subscribe_result = LXP_ERR_NOT_SUPPORTED;
	assert_int_equal(lxp_run(&g_mock_eng, &net_ops, NULL, &g_mock_fs_ops, NULL, &cfg,
				 "/init", 1, argv),
			 LXP_RUN_ELAUNCH);
	assert_int_equal(g_mock.prepare_calls, 1);
	assert_int_equal(g_mock.console_subscribe_calls, 1);
	assert_int_equal(g_mock.console_unsubscribe_calls, 0);
	assert_int_equal(g_mock.teardown_calls, 1);
	assert_null(g_mock.console_ready);

	/* Once acquired, readiness reaches the engine directly and unsubscribe
	 * withdraws both callback and context even when image launch then fails. */
	g_mock.console_subscribe_result = LXP_OK;
	g_mock.launch_failures = 1;
	assert_int_equal(lxp_run(&g_mock_eng, &net_ops, NULL, &g_mock_fs_ops, NULL, &cfg,
				 "/init", 1, argv),
			 LXP_RUN_ELAUNCH);
	assert_int_equal(g_mock.prepare_calls, 2);
	assert_int_equal(g_mock.console_subscribe_calls, 2);
	assert_int_equal(g_mock.console_unsubscribe_calls, 1);
	assert_int_equal(g_mock.event_posts, 1);
	assert_null(g_mock.console_ready);
	assert_null(g_mock.console_ready_context);
}

/* The board transport supplies CR for Enter because BusyBox's raw shell editor expects
 * it.  A cooked tty advertising ICRNL must instead give applications LF: login's retry
 * path uses fgets(), which otherwise consumes the second username forever waiting for
 * a newline.  When a guest clears ICRNL, the transport byte must be preserved. */
static void test_console_icrnl_translation(void **state)
{
	(void)state;
	lxp_termios *tio = &lxp_console_tty()->termios;
	tio->c_iflag |= LXP_ICRNL;
	assert_int_equal(lxp_console_input_xlate('\r'), '\n');
	assert_int_equal(lxp_console_input_xlate('x'), 'x');
	assert_int_equal(lxp_console_input_xlate('\n'), '\n');

	tio->c_iflag &= ~LXP_ICRNL;
	assert_int_equal(lxp_console_input_xlate('\r'), '\r');
}

static int console_ready(void *ctx)
{
	(void)ctx;
	return 1;
}

static long console_read_cr(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (!len)
		return 0;
	((uint8_t *)buf)[0] = '\r';
	return 1;
}

static uint8_t g_console_byte;

static long console_read_byte(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (!len)
		return 0;
	((uint8_t *)buf)[0] = g_console_byte;
	return 1;
}

static long console_read_sigint(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (!len)
		return 0;
	((uint8_t *)buf)[0] = 3;
	return 1;
}

static void test_async_console_signal_is_scan_progress(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->pid = 2;
	proc->group->pgid = 2;
	lxp_console_tty()->fg_pgrp = 2;
	const lxp_run_config_t cfg = {
		.read_fn = console_read_sigint,
		.console_poll = console_ready,
	};
	g_lxp_rt.cfg = &cfg;

	struct lxp_blocked_scan scan = lxp_scan_blocked(1);
	assert_true(scan.progress);
	assert_true(proc->pending_sigs & lxp_sig_bit(LXP_SIGINT));
}

/* A byte may already be ready when read(2) enters, bypassing a console wait entirely.
 * That fast path must use the same ICRNL discipline as a coordinator-resumed read. */
static void test_console_icrnl_immediate_read(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	assert_int_equal(lxp_arena_init(&arena, g_mock_regions[0], sizeof(g_mock_regions[0])),
			 LXP_OK);
	assert_int_equal(lxp_proc_init(&p, &arena, 0), 0);
	p.mm->region_lo = 1;
	p.mm->region_hi = UINTPTR_MAX;
	p.read_fn = console_read_cr;
	p.console_poll = console_ready;

	uint8_t ch = 0;
	lxp_termios *tio = &lxp_console_tty()->termios;
	tio->c_iflag |= LXP_ICRNL;
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, 0, (long)(uintptr_t)&ch, 1, 0, 0, 0), 1);
	assert_int_equal(ch, '\n');

	tio->c_iflag &= ~LXP_ICRNL;
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, 0, (long)(uintptr_t)&ch, 1, 0, 0, 0), 1);
	assert_int_equal(ch, '\r');
}

/* A console ^C raises SIGINT on the console's FOREGROUND process group only (the group
 * the shell set via tcsetpgrp/TIOCSPGRP) — the interactive shell (its own group) and any
 * background job survive. The console analog of the pty ^C: what makes a foreground
 * program interruptible from the direct console. */
static void test_console_sigint_targets_fg_group(void **state)
{
	(void)state;
	/* pid/pgid: init(1,1) shell(2,2) fg-job(3,3) fg-pipe-peer(4,3) bg-job(5,5) */
	const int pid[5] = {1, 2, 3, 4, 5};
	const int pgid[5] = {1, 2, 3, 3, 5};
	for (int i = 0; i < 5; i++) {
		g_lxp_rt.slots[i].proc.alive = 1;
		g_lxp_rt.slots[i].proc.pid = pid[i];
		g_lxp_rt.slots[i].proc.group->pgid = pgid[i];
	}
	const uint64_t bit = lxp_sig_bit(LXP_SIGINT);

	/* No foreground group yet (pre-first-tcsetpgrp): ^C signals nobody. */
	lxp_console_tty()->fg_pgrp = 0;
	lxp_console_signal_fg(LXP_SIGINT);
	for (int i = 0; i < 5; i++)
		assert_false(g_lxp_rt.slots[i].proc.pending_sigs & bit);

	/* Shell put group 3 in the foreground: ^C hits that group only. */
	lxp_console_tty()->fg_pgrp = 3;
	lxp_console_signal_fg(LXP_SIGINT);
	assert_true(g_lxp_rt.slots[2].proc.pending_sigs & bit);  /* fg job (pgid 3) */
	assert_true(g_lxp_rt.slots[3].proc.pending_sigs & bit);  /* fg pipeline peer (pgid 3) */
	assert_false(g_lxp_rt.slots[0].proc.pending_sigs & bit); /* init (pgid 1) */
	assert_false(g_lxp_rt.slots[1].proc.pending_sigs &
		     bit); /* the shell (pgid 2) — survives to re-prompt */
	assert_false(g_lxp_rt.slots[4].proc.pending_sigs &
		     bit); /* background job (pgid 5) — untouched */
}

/* The console's signal characters are its termios c_cc entries under ISIG: ^Z raises
 * SIGTSTP only while VSUSP names it, a disabled entry makes it ordinary typeahead, and
 * with ISIG off the check leaves input for the reader. */
static void test_console_signal_chars_follow_termios(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	proc->pid = 2;
	proc->group->pgid = 2;
	lxp_tty_t *tty = lxp_console_tty();
	tty->fg_pgrp = 2;
	const lxp_run_config_t cfg = {
		.read_fn = console_read_byte,
		.console_poll = console_ready,
	};
	g_lxp_rt.cfg = &cfg;
	const uint64_t tstp = lxp_sig_bit(LXP_SIGTSTP);
	g_console_byte = 26; /* ^Z */

	assert_int_equal(lxp_console_poll_interrupts(), 1);
	assert_true(proc->pending_sigs & tstp);
	assert_false(lxp_console_input_ready(NULL)); /* the signal byte is consumed */

	proc->pending_sigs = 0;
	tty->termios.c_cc[LXP_VSUSP] = 0; /* _POSIX_VDISABLE */
	assert_int_equal(lxp_console_poll_interrupts(), 0);
	assert_false(proc->pending_sigs & tstp);
	assert_true(lxp_console_input_ready(NULL)); /* kept as typeahead */
	uint8_t ch = 0;
	proc->read_fn = NULL;
	assert_int_equal(lxp_console_read(proc, 0, &ch, 1), 1);
	assert_int_equal(ch, 26);

	tty->termios.c_cc[LXP_VSUSP] = 26;
	tty->termios.c_lflag &= ~LXP_ISIG;
	assert_int_equal(lxp_console_poll_interrupts(), 0);
	assert_false(lxp_console_input_ready(NULL)); /* nothing read on the reader's behalf */
	assert_false(proc->pending_sigs & tstp);
}

/* Ctrl+Z (VSUSP) fans SIGTSTP out to the foreground group only — the shell and background
 * jobs are untouched — exactly like the ^C→SIGINT path. */
static void test_console_sigtstp_targets_fg_group(void **state)
{
	(void)state;
	const int pid[3] = {2, 3, 5}; /* shell(2,2) fg-job(3,3) bg-job(5,5) */
	const int pgid[3] = {2, 3, 5};
	for (int i = 0; i < 3; i++) {
		g_lxp_rt.slots[i].proc.alive = 1;
		g_lxp_rt.slots[i].proc.pid = pid[i];
		g_lxp_rt.slots[i].proc.group->pgid = pgid[i];
	}
	const uint64_t bit = lxp_sig_bit(LXP_SIGTSTP);
	lxp_console_tty()->fg_pgrp = 3;
	lxp_console_signal_fg(LXP_SIGTSTP);
	assert_true(g_lxp_rt.slots[1].proc.pending_sigs & bit);  /* fg job (pgid 3) */
	assert_false(g_lxp_rt.slots[0].proc.pending_sigs & bit); /* the shell (pgid 2) */
	assert_false(g_lxp_rt.slots[2].proc.pending_sigs & bit); /* background job (pgid 5) */
}

int test_coord_console_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_console_interrupt_poll_keeps_typeahead, reset_state),
		cmocka_unit_test_setup(test_console_interrupt_poll_backpressure, reset_state),
		cmocka_unit_test_setup(test_console_poll_reports_queued_typeahead, reset_state),
		cmocka_unit_test_setup(test_console_readiness_lifecycle_is_run_scoped, reset_state),
		cmocka_unit_test_setup(test_console_sigint_targets_fg_group, reset_state),
		cmocka_unit_test_setup(test_console_sigtstp_targets_fg_group, reset_state),
		cmocka_unit_test_setup(test_console_signal_chars_follow_termios, reset_state),
		cmocka_unit_test_setup(test_console_icrnl_translation, reset_state),
		cmocka_unit_test_setup(test_console_icrnl_immediate_read, reset_state),
		cmocka_unit_test_setup(test_async_console_signal_is_scan_progress, reset_state),
	};
	return cmocka_run_group_tests_name("coordinator: console", tests, NULL, NULL);
}
