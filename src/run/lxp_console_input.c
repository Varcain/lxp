/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Console input discipline, applied by the coordinator from the console tty's termios
 * (src/fs/lxp_console.c): ICRNL on every byte a guest reads, and the ISIG signal
 * characters. While no guest reads the console the coordinator still reads input to
 * catch ^C and ^Z; the ordinary bytes it reads are kept as typeahead and delivered, in
 * order, before any further transport input. Echo and output processing stay the
 * transport's job.
 */
#include "fs/lxp_tty.h"
#include "lxp/lxp_run.h"
#include "lxp_internal.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_runtime_store.h"

void lxp_console_reset(void)
{
	lxp_tty_init(lxp_console_tty());
	g_lxp_rt.typeahead.head = 0;
	g_lxp_rt.typeahead.count = 0;
}

/* The board callback deliberately preserves CR for raw-mode line editors, so the tty's
 * ICRNL conversion happens here, after the byte enters the personality. */
uint8_t lxp_console_input_xlate(uint8_t ch)
{
	return (lxp_console_tty()->termios.c_iflag & LXP_ICRNL) && ch == '\r' ? '\n' : ch;
}

int lxp_console_input_ready(const lxp_proc_t *proc)
{
	return g_lxp_rt.typeahead.count != 0 ||
	       (proc && proc->console_poll && proc->console_poll(proc->io_ctx) > 0);
}

long lxp_console_read(lxp_proc_t *proc, int fd, void *buf, size_t len)
{
	struct lxp_console_typeahead *ta = &g_lxp_rt.typeahead;
	long rc;
	if (len != 0 && ta->count != 0) {
		((uint8_t *)buf)[0] = ta->buf[ta->head];
		ta->head = (ta->head + 1u) % LXP_CONSOLE_TYPEAHEAD;
		ta->count--;
		rc = 1;
	} else {
		rc = proc->read_fn ? proc->read_fn(proc->io_ctx, fd, buf, len) : 0;
	}
	if (rc == 1)
		((uint8_t *)buf)[0] = lxp_console_input_xlate(((const uint8_t *)buf)[0]);
	return rc;
}

int lxp_console_poll_interrupts(void)
{
	const lxp_console_t *console = g_lxp_rt.cfg ? &g_lxp_rt.cfg->launch.console : NULL;
	const lxp_tty_t *tty = lxp_console_tty();
	struct lxp_console_typeahead *ta = &g_lxp_rt.typeahead;
	if (!(tty->termios.c_lflag & LXP_ISIG) || !console || !console->read || !console->poll ||
	    ta->count == LXP_CONSOLE_TYPEAHEAD || !console->poll(console->ctx))
		return 0;
	uint8_t ch = 0;
	if (console->read(console->ctx, 0, &ch, 1) != 1)
		return 0;
	int sig = lxp_tty_signal_for(tty, ch);
	if (sig) {
		lxp_console_signal_fg(sig);
		return 1;
	}
	unsigned tail = ta->head + ta->count;
	ta->buf[tail % LXP_CONSOLE_TYPEAHEAD] = ch;
	ta->count++;
	return 0;
}

/* Raise @p sig on the console's foreground process group: every live member takes it at
 * its next syscall boundary or coordinator retry. With no foreground group yet (before
 * the shell's first tcsetpgrp) this is a no-op. */
void lxp_console_signal_fg(int sig)
{
	(void)lxp_signal_process_group(lxp_console_tty()->fg_pgrp, sig);
}
