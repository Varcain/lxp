/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Linux personality pseudo-terminal tests: drive lxp_syscall() (no hardware
 * SVC, no run loop) to exercise the FD_PTY routing + the in-kernel line
 * discipline — open /dev/ptmx (master) + /dev/pts/N (slave) via TIOCGPTN,
 * canonical line delivery + echo, raw passthrough, ONLCR output mapping,
 * O_NONBLOCK EAGAIN, endpoint lifetime, foreground-group signals, winsize
 * round-trip, and the device identity ttyname(3) matches on.
 */

#include "../framework/lxp_test.h"
#include "fs/lxp_stat.h"
#include "lxp_arena.h"
#include "pty/lxp_pty.h"
#include "lxp_syscall.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint8_t g_pool[8192] __attribute__((aligned(16)));
static lxp_proc_t g_proc;
static lxp_arena_t g_arena;

#define O_RDWR_NB (LXP_O_RDWR | LXP_O_NONBLOCK)

static void pty_setup(void)
{
	lxp_proc_runtime_reset();
	lxp_fd_runtime_reset();
	lxp_pty_runtime_reset();
	assert_int_equal(lxp_arena_init(&g_arena, g_pool, sizeof(g_pool)), LXP_OK);
	assert_int_equal(lxp_proc_init(&g_proc, &g_arena, 4096), 0);
	g_proc.mm->region_lo = 1; /* all-permitting lxp_guest_access_ok except NULL */
	g_proc.mm->region_hi = UINTPTR_MAX;
	g_proc.mm->pool_lo = g_proc.mm->pool_hi = 0;
	g_proc.alive = 1;
	g_lxp_test_signal_calls = 0;
	g_lxp_test_signal_pgid = 0;
	g_lxp_test_signal_number = 0;
}

static long sc(long nr, long a0, long a1, long a2)
{
	return lxp_syscall(&g_proc, nr, a0, a1, a2, 0, 0, 0);
}

/* Open /dev/ptmx (master) + its /dev/pts/N slave; returns both fds via out params. */
static void open_pair(int *mfd, int *sfd)
{
	long m = sc(LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t) "/dev/ptmx", O_RDWR_NB);
	assert_true(m >= 0);
	unsigned ptn = 0xffff;
	assert_int_equal(sc(LXP_NR_ioctl, m, LXP_TIOCGPTN, (long)(uintptr_t)&ptn), 0);
	char path[24];
	snprintf(path, sizeof(path), "/dev/pts/%u", ptn);
	long s = sc(LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)path, O_RDWR_NB);
	assert_true(s >= 0);
	*mfd = (int)m;
	*sfd = (int)s;
}

/* /dev/ptmx mints a master, TIOCGPTN yields its number, /dev/pts/N opens the slave. */
static void test_pty_open_and_ptn(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	assert_int_not_equal(mfd, sfd);
	/* fstat → S_IFCHR so isatty() reports a terminal. */
	/* A bad pts number does not exist. */
	assert_true(sc(LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t) "/dev/pts/9", O_RDWR_NB) <
		    0);
}

/* Canonical mode (default): a line is delivered whole on newline, and echoed to the
 * master with ICRNL/ONLCR (input \n echoes as \r\n). */
static void test_pty_canonical_echo(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	char in[] = "hi\n";
	assert_int_equal(sc(LXP_NR_write, mfd, (long)(uintptr_t)in, 3), 3);
	char buf[16] = {0};
	assert_int_equal(sc(LXP_NR_read, sfd, (long)(uintptr_t)buf, sizeof(buf)), 3);
	assert_memory_equal(buf, "hi\n", 3);
	memset(buf, 0, sizeof(buf));
	assert_int_equal(sc(LXP_NR_read, mfd, (long)(uintptr_t)buf, sizeof(buf)), 4);
	assert_memory_equal(buf, "hi\r\n", 4); /* echo, newline mapped */
}

/* Raw mode (ICANON+ECHO+OPOST off): each byte passes straight to the slave, no echo. */
static void test_pty_raw_passthrough(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	lxp_termios t;
	memset(&t, 0, sizeof(t)); /* clear ICANON/ECHO/ISIG/ICRNL/OPOST */
	assert_int_equal(sc(LXP_NR_ioctl, mfd, LXP_TCSETS, (long)(uintptr_t)&t), 0);
	assert_int_equal(sc(LXP_NR_write, mfd, (long)(uintptr_t) "x", 1), 1);
	char buf[4] = {0};
	assert_int_equal(sc(LXP_NR_read, sfd, (long)(uintptr_t)buf, sizeof(buf)), 1);
	assert_int_equal(buf[0], 'x');
	/* no echo: the master ring is empty (slave still open → EAGAIN, not EOF). */
	assert_int_equal(sc(LXP_NR_read, mfd, (long)(uintptr_t)buf, sizeof(buf)),
			 -LXP_EAGAIN);
}

/* Slave output OPOST/ONLCR maps \n → \r\n on the way to the master. */
static void test_pty_onlcr_output(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	char in[] = "a\nb";
	assert_int_equal(sc(LXP_NR_write, sfd, (long)(uintptr_t)in, 3), 3);
	char buf[16] = {0};
	assert_int_equal(sc(LXP_NR_read, mfd, (long)(uintptr_t)buf, sizeof(buf)), 4);
	assert_memory_equal(buf, "a\r\nb", 4);
}

/* An empty non-blocking read returns EAGAIN while the peer end is open (not EOF). */
static void test_pty_nonblock_empty(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	char buf[4];
	assert_int_equal(sc(LXP_NR_read, sfd, (long)(uintptr_t)buf, sizeof(buf)),
			 -LXP_EAGAIN);
	assert_int_equal(sc(LXP_NR_read, mfd, (long)(uintptr_t)buf, sizeof(buf)),
			 -LXP_EAGAIN);
}

/* Dup aliases share one open description. Closing one alias must not remove the
 * endpoint; closing the final alias makes the peer observe EOF. */
static void test_pty_endpoint_lifetime(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	long mdup = sc(LXP_NR_dup, mfd, 0, 0);
	assert_true(mdup >= 0);
	assert_int_equal(sc(LXP_NR_close, mfd, 0, 0), 0);
	char buf[4];
	assert_int_equal(sc(LXP_NR_read, sfd, (long)(uintptr_t)buf, sizeof(buf)),
			 -LXP_EAGAIN);
	assert_int_equal(sc(LXP_NR_close, mdup, 0, 0), 0);
	assert_int_equal(sc(LXP_NR_read, sfd, (long)(uintptr_t)buf, sizeof(buf)), 0);
	assert_int_equal(sc(LXP_NR_close, sfd, 0, 0), 0);

	/* The pair is reusable after both final open descriptions close. */
	open_pair(&mfd, &sfd);
	assert_int_equal(sc(LXP_NR_close, mfd, 0, 0), 0);
	assert_int_equal(sc(LXP_NR_close, sfd, 0, 0), 0);
}

/* VINTR targets the foreground process group recorded by TIOCSPGRP. */
static void test_pty_foreground_signal(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	uint32_t pgid = 37;
	assert_int_equal(sc(LXP_NR_ioctl, sfd, LXP_TIOCSPGRP, (long)(uintptr_t)&pgid), 0);
	char intr = 3;
	assert_int_equal(sc(LXP_NR_write, mfd, (long)(uintptr_t)&intr, 1), 1);
	assert_int_equal(g_lxp_test_signal_calls, 1);
	assert_int_equal(g_lxp_test_signal_pgid, 37);
	assert_int_equal(g_lxp_test_signal_number, LXP_SIGINT);
}

/* VSUSP (^Z, the Linux default) raises SIGTSTP on the foreground group; with ISIG off
 * the same byte is ordinary input. */
static void test_pty_suspend_signal(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	lxp_termios t;
	assert_int_equal(sc(LXP_NR_ioctl, sfd, LXP_TCGETS, (long)(uintptr_t)&t), 0);
	assert_int_equal(t.c_cc[LXP_VSUSP], 26);
	uint32_t pgid = 41;
	assert_int_equal(sc(LXP_NR_ioctl, sfd, LXP_TIOCSPGRP, (long)(uintptr_t)&pgid), 0);
	char susp = 26;
	assert_int_equal(sc(LXP_NR_write, mfd, (long)(uintptr_t)&susp, 1), 1);
	assert_int_equal(g_lxp_test_signal_calls, 1);
	assert_int_equal(g_lxp_test_signal_pgid, 41);
	assert_int_equal(g_lxp_test_signal_number, LXP_SIGTSTP);

	t.c_lflag &= ~(LXP_ISIG | LXP_ICANON | LXP_ECHO);
	assert_int_equal(sc(LXP_NR_ioctl, mfd, LXP_TCSETS, (long)(uintptr_t)&t), 0);
	assert_int_equal(sc(LXP_NR_write, mfd, (long)(uintptr_t)&susp, 1), 1);
	assert_int_equal(g_lxp_test_signal_calls, 1);
	char buf[4] = {0};
	assert_int_equal(sc(LXP_NR_read, sfd, (long)(uintptr_t)buf, sizeof(buf)), 1);
	assert_int_equal(buf[0], 26);
}

/* TIOCSWINSZ then TIOCGWINSZ round-trips the terminal size (ssh forwards the client's). */
static void test_pty_winsize(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	lxp_winsize w = {.ws_row = 40, .ws_col = 100, .ws_xpixel = 0, .ws_ypixel = 0};
	assert_int_equal(sc(LXP_NR_ioctl, mfd, LXP_TIOCSWINSZ, (long)(uintptr_t)&w), 0);
	lxp_winsize r = {0};
	assert_int_equal(sc(LXP_NR_ioctl, sfd, LXP_TIOCGWINSZ, (long)(uintptr_t)&r), 0);
	assert_int_equal(r.ws_row, 40);
	assert_int_equal(r.ws_col, 100);
}

/* ttyname(3) finds a terminal by stat'ing /dev/pts entries for the st_rdev that fstat of
 * the fd reports (dropbear names a session's pty this way), so the two must agree. */
static void test_pty_device_identity(void **st)
{
	(void)st;
	pty_setup();
	int mfd, sfd;
	open_pair(&mfd, &sfd);
	unsigned ptn = 0xffff;
	assert_int_equal(sc(LXP_NR_ioctl, mfd, LXP_TIOCGPTN, (long)(uintptr_t)&ptn), 0);
	char path[24];
	snprintf(path, sizeof(path), "/dev/pts/%u", ptn);
	struct lxp_kstat64 node, end;
	assert_int_equal(sc(LXP_NR_stat64, (long)(uintptr_t)path, (long)(uintptr_t)&node, 0), 0);
	assert_int_equal(sc(LXP_NR_fstat64, sfd, (long)(uintptr_t)&end, 0), 0);
	assert_int_equal(node.st_mode & LXP_S_IFMT, LXP_S_IFCHR);
	assert_int_equal(end.st_mode & LXP_S_IFMT, LXP_S_IFCHR);
	assert_int_equal(node.st_rdev, (136u << 8) | ptn);
	assert_int_equal(end.st_rdev, node.st_rdev);
	assert_int_equal(end.st_ino, node.st_ino);
	/* The master reports /dev/ptmx's device, as on Linux. */
	assert_int_equal(sc(LXP_NR_fstat64, mfd, (long)(uintptr_t)&end, 0), 0);
	assert_int_equal(end.st_rdev, (5u << 8) | 2u);
}

int test_linux_pty_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_pty_open_and_ptn),
		cmocka_unit_test(test_pty_canonical_echo),
		cmocka_unit_test(test_pty_raw_passthrough),
		cmocka_unit_test(test_pty_onlcr_output),
		cmocka_unit_test(test_pty_nonblock_empty),
		cmocka_unit_test(test_pty_endpoint_lifetime),
		cmocka_unit_test(test_pty_foreground_signal),
		cmocka_unit_test(test_pty_suspend_signal),
		cmocka_unit_test(test_pty_winsize),
		cmocka_unit_test(test_pty_device_identity),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
