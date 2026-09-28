/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Console file operations (FD_CONSOLE): stdio on the host console transport plus
 * the stateless character devices sharing the kind, selected by file_idx —
 * 0 stdin, 1 stdout/stderr, 3 /dev/null, 4 /dev/urandom + /dev/random, 5 /dev/zero.
 */
#include "fs/lxp_vfs.h"

#include "lxp_internal.h"
#include "lxp_linux_uapi.h"

#include <string.h>

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
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0; /* parked; the coordinator resumes it when a key arrives */
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
	/* Make the console fds look like a tty so the shell goes interactive
	 * (isatty → prompt + line editing). */
	(void)s;
	void *ua = (void *)(uintptr_t)arg;
	switch (cmd) {
	case LXP_TCGETS: {
		lxp_termios t = {0};
		t.c_iflag = LXP_ICRNL;
		t.c_oflag = LXP_OPOST | LXP_ONLCR;
		t.c_cflag = LXP_CS8 | LXP_CREAD;
		t.c_lflag = LXP_ICANON | LXP_ECHO | LXP_ISIG;
		t.c_cc[LXP_VINTR] = 3;	   /* ^C */
		t.c_cc[LXP_VERASE] = 0x7f; /* DEL */
		t.c_cc[LXP_VEOF] = 4;	   /* ^D */
		t.c_cc[LXP_VSUSP] = 26;	   /* ^Z */
		t.c_cc[LXP_VMIN] = 1;
		return lxp_copy_to_guest(p, (uintptr_t)ua, &t, sizeof(t));
	}
	case LXP_TCSETS:
	case LXP_TCSETSW:
	case LXP_TCSETSF:
		if (!lxp_guest_access_ok(p, ua, sizeof(lxp_termios), 0))
			return -LXP_EFAULT;
		return 0; /* accept mode changes; the console echo is the engine's job */
	case LXP_TIOCGWINSZ: {
		const lxp_winsize w = {.ws_row = 24, .ws_col = 80, .ws_xpixel = 0, .ws_ypixel = 0};
		return lxp_copy_to_guest(p, (uintptr_t)ua, &w, sizeof(w));
	}
	case LXP_TIOCSCTTY: /* getty/login: become/drop/set the tty session */
	case LXP_TIOCNOTTY:
		return 0;
	case LXP_TIOCSPGRP: {
		/* tcsetpgrp(): the shell (HUSH_JOB) records which process group is in the
		 * foreground of the console. A console ^C then raises SIGINT on exactly that
		 * group (see console_signal_fg). Runs in coordinator context (ioctl defers),
		 * so writing the shared fg-pgrp state here is safe. */
		uint32_t pgrp;
		if (lxp_guest_get_u32(p, (uintptr_t)ua, &pgrp) != 0)
			return -LXP_EFAULT;
		lxp_console_set_fg_pgrp((int)pgrp);
		return 0;
	}
	case LXP_TIOCGPGRP: {
		/* Report the tracked foreground group once set; before the shell's first
		 * tcsetpgrp, fall back to the caller's pid so tcgetpgrp() returns non-zero
		 * and the shell enables job control at startup. */
		int pgrp = lxp_console_fg_pgrp();
		if (pgrp <= 0)
			pgrp = p->pid;
		return lxp_guest_put_u32(p, (uintptr_t)ua, (uint32_t)pgrp);
	}
	default:
		return -LXP_ENOTTY;
	}
}

static unsigned fop_poll_console(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)s;
	int key = lxp_console_input_ready(p);
	return (unsigned)((p->console_poll ? (key ? LXP_POLLIN : 0) : LXP_POLLIN) | LXP_POLLOUT);
}

const lxp_file_ops_t lxp_console_fops = {
	.read = fop_read_console,
	.write = fop_write_console,
	.ioctl = fop_ioctl_console,
	.poll = fop_poll_console,
};
