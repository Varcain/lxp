/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Per-process signal policy: which pending signal is delivered next, what a disposition
 * means (ignore, stop, handler or terminate), publishing a pending signal, and recording a
 * signal termination. It needs only the process record, so the syscall layer, the file
 * layer and the coordinator share one implementation; delivering a signal over a trap
 * frame is src/lxp_signal.c.
 */
#include "signal/lxp_signal_policy.h"

/* Lowest-numbered pending signal for @p p that is not currently blocked (SIGKILL/SIGSTOP are
 * never blocked), or 0 if none is deliverable. It stays pending; lxp_pending_take() clears it for
 * a caller that commits to delivering it. A blocked pending signal stays set until the proc
 * unblocks it. */
int lxp_pending_deliverable(const lxp_proc_t *p)
{
	if (!p->pending_sigs)
		return 0;
	for (int sig = 1; sig < LXP_NSIG; sig++)
		if ((p->pending_sigs & lxp_sig_bit(sig)) && !lxp_sig_blocked(p, sig))
			return sig;
	return 0;
}

/* Take the signal lxp_pending_deliverable() names: clear it and return it (0 if none). */
int lxp_pending_take(lxp_proc_t *p)
{
	int sig = lxp_pending_deliverable(p);
	if (sig)
		p->pending_sigs &= ~lxp_sig_bit(sig);
	return sig;
}

/* Signals whose POSIX default action never terminates the process: SIGCHLD (ignore),
 * SIGCONT (consumed by the coordinator for a stopped process; a no-op while running),
 * SIGURG + SIGWINCH (ignore). A SIG_DFL of one of these must be SWALLOWED, not turned
 * into a 128+signo termination — else a shell's `fg`, which sends kill(-pgid, SIGCONT)
 * to resume a job, kills the very job (and every proc in range). */
int lxp_sig_default_ignore(int sig)
{
	return sig == LXP_SIGCHLD || sig == LXP_SIGCONT || sig == LXP_SIGURG || sig == LXP_SIGWINCH;
}

/* Is signal `sig` effectively ignored for `proc`? True for SIG_IGN, or SIG_DFL of a
 * signal whose default action is "ignore" (SIGCHLD/SIGCONT/SIGURG/SIGWINCH). Such a
 * signal is swallowed by the coordinator: it neither runs a handler nor terminates a
 * parked proc — a parent must not die because a child exited or a job was resumed. */
int lxp_sig_swallowed(const lxp_proc_t *proc, int sig)
{
	uintptr_t h = lxp_sig_handler_get(proc, sig);
	if (h == LXP_SIG_IGN)
		return 1;
	if (h == LXP_SIG_DFL && lxp_sig_default_ignore(sig))
		return 1;
	return 0;
}

/* The job-control stop signals: their default action suspends the process. */
int lxp_sig_is_stop(int sig)
{
	return sig == LXP_SIGSTOP || sig == LXP_SIGTSTP || sig == LXP_SIGTTIN || sig == LXP_SIGTTOU;
}

/* Would delivering `sig` to `proc` actually STOP it (rather than run a handler or be
 * ignored)? SIGSTOP always stops (it can be neither caught nor ignored); SIGTSTP/TTIN/
 * TTOU stop only at their default disposition — a caught one runs the handler, an
 * ignored one is dropped. */
int lxp_sig_stops_proc(const lxp_proc_t *proc, int sig)
{
	if (!lxp_sig_is_stop(sig))
		return 0;
	if (sig == LXP_SIGSTOP)
		return 1;
	return lxp_sig_handler_get(proc, sig) == LXP_SIG_DFL;
}

/* Publish one pending signal while preserving the ordering rule that a bitset
 * cannot represent by itself. Generating SIGCONT discards pending job-control
 * stops; generating a stop signal discards pending SIGCONT. All signal producers
 * use this owner so the last generated action wins. */
void lxp_signal_latch(lxp_proc_t *proc, int sig)
{
	if (!proc || sig <= 0 || sig >= LXP_NSIG)
		return;
	uint64_t pending = proc->pending_sigs;
	const uint64_t stop_mask = lxp_sig_bit(LXP_SIGSTOP) | lxp_sig_bit(LXP_SIGTSTP) |
				   lxp_sig_bit(LXP_SIGTTIN) | lxp_sig_bit(LXP_SIGTTOU);
	if (sig == LXP_SIGCONT)
		pending &= ~stop_mask;
	else if (lxp_sig_is_stop(sig))
		pending &= ~lxp_sig_bit(LXP_SIGCONT);
	proc->pending_sigs = pending | lxp_sig_bit(sig);
}

void lxp_signal_terminate(lxp_proc_t *proc, int sig, uint8_t reason, uint32_t detail,
			  uintptr_t address)
{
	(void)lxp_intent_exit(proc, 0);
	proc->exit_status = 128 + sig;
	proc->exit_reason = reason;
	proc->exit_signal = (uint8_t)sig;
	proc->exit_detail = detail;
	proc->exit_address = address;
}
