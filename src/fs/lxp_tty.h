/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * A terminal's line-discipline settings (src/fs/lxp_tty.c), shared by the console and
 * every pty: its termios, window size and foreground process group, the ioctls that read
 * and set them, and the signal an input byte raises.
 */
#ifndef LXP_FS_TTY_H
#define LXP_FS_TTY_H

#include <stdint.h>

#include "lxp_linux_uapi.h"
#include "proc/lxp_proc.h"

typedef struct lxp_tty {
	lxp_termios termios;
	lxp_winsize winsize;
	int fg_pgrp; /* the TIOCSPGRP foreground process group; 0 until one is set */
} lxp_tty_t;

/* Linux's cooked defaults: CR to NL on input, NL to CRNL on output, canonical echo with
 * ^C (VINTR) and ^Z (VSUSP) raising signals, DEL erasing and ^D ending input, 80x24. */
#define LXP_TTY_DEFAULTS                                                                           \
	{                                                                                          \
		.termios =                                                                         \
			{                                                                          \
				.c_iflag = LXP_ICRNL,                                              \
				.c_oflag = LXP_OPOST | LXP_ONLCR,                                  \
				.c_cflag = LXP_CS8 | LXP_CREAD,                                    \
				.c_lflag = LXP_ICANON | LXP_ECHO | LXP_ISIG,                       \
				.c_cc = {[LXP_VINTR] = 3,                                          \
					 [LXP_VERASE] = 0x7f,                                      \
					 [LXP_VEOF] = 4,                                           \
					 [LXP_VSUSP] = 26,                                         \
					 [LXP_VMIN] = 1},                                          \
			},                                                                         \
		.winsize = {.ws_row = 24, .ws_col = 80},                                           \
	}

/* Reset @p tty to LXP_TTY_DEFAULTS with no foreground group. */
void lxp_tty_init(lxp_tty_t *tty);

/* The ioctls every terminal answers: TCGETS/TCSETS[WF], TIOC[GS]WINSZ, TIOC[GS]PGRP and
 * TIOCSCTTY/TIOCNOTTY. The result, or -ENOTTY for any other command. */
long lxp_tty_ioctl(lxp_proc_t *p, lxp_tty_t *tty, unsigned long cmd, unsigned long arg);

/* The signal input byte @p c raises under ISIG (SIGINT for VINTR, SIGTSTP for VSUSP), or
 * 0 when it is ordinary input. */
int lxp_tty_signal_for(const lxp_tty_t *tty, uint8_t c);

/* The console's terminal (src/fs/lxp_console.c). */
lxp_tty_t *lxp_console_tty(void);

#endif /* LXP_FS_TTY_H */
