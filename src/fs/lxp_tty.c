/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The terminal state and ioctls the console and the ptys share.
 */
#include "fs/lxp_tty.h"

#include "lxp_guest.h"

void lxp_tty_init(lxp_tty_t *tty)
{
	*tty = (lxp_tty_t)LXP_TTY_DEFAULTS;
}

long lxp_tty_ioctl(lxp_proc_t *p, lxp_tty_t *tty, unsigned long cmd, unsigned long arg)
{
	uintptr_t ua = (uintptr_t)arg;
	switch (cmd) {
	case LXP_TCGETS:
		return lxp_copy_to_guest(p, ua, &tty->termios, sizeof(tty->termios));
	case LXP_TCSETS:
	case LXP_TCSETSW:
	case LXP_TCSETSF: {
		lxp_termios t; /* a fault leaves the settings untouched */
		if (lxp_copy_from_guest(p, &t, ua, sizeof(t)) != 0)
			return -LXP_EFAULT;
		tty->termios = t;
		return 0;
	}
	case LXP_TIOCGWINSZ:
		return lxp_copy_to_guest(p, ua, &tty->winsize, sizeof(tty->winsize));
	case LXP_TIOCSWINSZ: {
		lxp_winsize w;
		if (lxp_copy_from_guest(p, &w, ua, sizeof(w)) != 0)
			return -LXP_EFAULT;
		tty->winsize = w;
		return 0;
	}
	case LXP_TIOCSPGRP: {
		/* tcsetpgrp(): the job-control shell names the foreground process group, which
		 * then receives the terminal's ^C and ^Z signals. */
		uint32_t pgrp;
		if (lxp_guest_get_u32(p, ua, &pgrp) != 0)
			return -LXP_EFAULT;
		tty->fg_pgrp = (int)pgrp;
		return 0;
	}
	case LXP_TIOCGPGRP:
		/* Before the shell's first tcsetpgrp, report the caller's pid so tcgetpgrp()
		 * is non-zero and the shell enables job control at startup. */
		return lxp_guest_put_u32(p, ua,
					 (uint32_t)(tty->fg_pgrp > 0 ? tty->fg_pgrp : p->pid));
	case LXP_TIOCSCTTY: /* getty/login: become/drop the controlling tty (one session) */
	case LXP_TIOCNOTTY:
		return 0;
	default:
		return -LXP_ENOTTY;
	}
}

int lxp_tty_signal_for(const lxp_tty_t *tty, uint8_t c)
{
	const lxp_termios *t = &tty->termios;
	if (!(t->c_lflag & LXP_ISIG) || c == 0) /* 0 is _POSIX_VDISABLE */
		return 0;
	if (c == t->c_cc[LXP_VINTR])
		return LXP_SIGINT;
	if (c == t->c_cc[LXP_VSUSP])
		return LXP_SIGTSTP;
	return 0;
}
