/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Console file operations (FD_CONSOLE): stdio on the host console transport plus
 * the stateless character devices sharing the kind, selected by file_idx —
 * 0 stdin, 1 stdout/stderr, 3 /dev/null, 4 /dev/urandom + /dev/random, 5 /dev/zero.
 * Poll readiness depends on the caller's timeout, so fs/lxp_poll.c decides it. The
 * console is one tty (fs/lxp_tty.h) whose termios the coordinator applies to input.
 */
#include "fs/lxp_tty.h"
#include "fs/lxp_vfs.h"

#include "lxp_internal.h"
#include "lxp_linux_uapi.h"

#include <string.h>

/* Coordinator-owned: tty ioctls defer to the coordinator, which also applies the
 * settings to console input (src/run/lxp_console_input.c). */
static lxp_tty_t g_console_tty = LXP_TTY_DEFAULTS;

lxp_tty_t *lxp_console_tty(void)
{
	return &g_console_tty;
}

static long fop_read_console(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	if (s->file_idx == 1) /* output consoles (stdout/stderr) are not readable */
		return -LXP_EBADF;
	if (s->file_idx == 3)	/* /dev/null */
		return 0;	/* EOF */
	if (s->file_idx == 5) { /* /dev/zero: an all-zero fill */
		memset(buf, 0, len);
		return (long)len;
	}
	if (s->file_idx == 4) /* /dev/urandom + /dev/random: host entropy */
		return lxp_random_fill_guest(buf, len, LXP_EIO);
	if (!p->read_fn)
		return 0; /* EOF */
	/* Park until a key is ready (probed via console_poll) so the syscall bottom
	 * half returns to its coordinator loop instead of pinning it in read_fn. This
	 * lets other slots and background work progress. Without a poll hook, fall
	 * back to a blocking read for host integrations that need it. */
	if (p->console_poll && !lxp_console_input_ready(p)) {
		lxp_wait_t wait = {
			.kind = LXP_WAIT_CONSOLE,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
		};
		return lxp_wait_park(p, &wait); /* parked; the coordinator resumes it when a key arrives */
	}
	return lxp_console_read(p, s->file_idx, buf, len);
}

static long fop_write_console(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	if (s->file_idx == 3 || s->file_idx == 4 || s->file_idx == 5)
		return (long)len; /* /dev/null + /dev/urandom + /dev/zero: discard writes */
	if (s->file_idx == 0 || !p->write_fn) /* stdin is not writable; no sink → EBADF */
		return -LXP_EBADF;
	return p->write_fn(p->io_ctx, s->file_idx, buf, len);
}

static long fop_ioctl_console(lxp_proc_t *p, lxp_ofd_t *s, unsigned long cmd, unsigned long arg)
{
	/* Every console fd is the one console tty, so isatty() holds and the shell goes
	 * interactive (prompt + line editing). */
	(void)s;
	return lxp_tty_ioctl(p, &g_console_tty, cmd, arg);
}

const lxp_file_ops_t lxp_console_fops = {
	.read = fop_read_console,
	.write = fop_write_console,
	.ioctl = fop_ioctl_console,
};
