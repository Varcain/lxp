/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Readiness over a descriptor set, through each kind's poll file operation. A call
 * that finds nothing ready parks the task in LXP_WAIT_POLL; the coordinator re-scans
 * it on its socket tick until a descriptor is ready, the timeout expires or a
 * signal interrupts the wait.
 */
#include "fs/lxp_poll.h"

#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"

#define LXP_SEL_MAXFDS 32 /* select() handles one 32-bit fd_set word */
#define LXP_POLL_EVENTS (LXP_POLLIN | LXP_POLLOUT)

/*
 * Console readiness. There is no read-ahead, so poll(2)'s first pass answers by how
 * the caller waits (@p probe_tmo is its timeout): a blocking poll reports the console
 * ready and the caller then blocks in read() for the byte; with a console_poll hook
 * (UART console) the key readiness is real, which lets interactive top quit on `q`;
 * without one a short timeout is a read_key probe — vi/hush polling ~50 ms after ESC
 * to tell a lone ESC from an escape sequence, or vi's poll(0) "is input pending? if
 * not, repaint" — answered not ready, and a longer one ready. Every other scan
 * (select, a parked re-scan; @p probe_tmo NULL) reports the real readiness: a key
 * with a console_poll hook, else always ready.
 */
static int console_ready(lxp_proc_t *p, const long *probe_tmo)
{
	if (!probe_tmo)
		return p->console_poll ? lxp_console_input_ready(p) : 1;
	if (*probe_tmo < 0)
		return 1;
	if (p->console_poll)
		return lxp_console_input_ready(p);
	return *probe_tmo > 100;
}

/* Whether waiting can make @p s ready: a kind with a poll operation, or the console
 * when a console_poll hook reports its input. */
static int poll_waitable(lxp_proc_t *p, const lxp_ofd_t *s)
{
	if (s->kind == LXP_FD_CONSOLE)
		return p->console_poll != NULL;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	return ops && ops->poll;
}

/* Fill each entry's revents and return how many have any. A kind without a poll
 * operation (a regular file) is always ready; a descriptor that is not open is
 * POLLNVAL and a negative one is skipped. Sets *@p waitable when some entry that
 * is not ready yet could become ready. */
static int poll_scan(lxp_proc_t *p, lxp_pollfd *pf, unsigned n, const long *probe_tmo,
		     int *waitable)
{
	int ready = 0;
	for (unsigned i = 0; i < n; i++) {
		pf[i].revents = 0;
		if (pf[i].fd < 0)
			continue;
		lxp_ofd_t *s = lxp_fd_description(p, pf[i].fd);
		if (!s) {
			pf[i].revents = LXP_POLLNVAL;
			ready++;
			continue;
		}
		unsigned mask;
		if (s->kind == LXP_FD_CONSOLE) {
			mask = console_ready(p, probe_tmo) ? LXP_POLL_EVENTS : 0u;
		} else {
			const lxp_file_ops_t *ops = lxp_vfs_ops(s);
			mask = ops && ops->poll ? ops->poll(p, s) : LXP_POLL_EVENTS;
		}
		pf[i].revents = (short)(pf[i].events & mask & LXP_POLL_EVENTS);
		if (pf[i].revents)
			ready++;
		else if (waitable && poll_waitable(p, s))
			*waitable = 1;
	}
	return ready;
}

static long poll_park(lxp_proc_t *p, lxp_wait_t *wait, long tmo_ms)
{
	wait->kind = LXP_WAIT_POLL;
	wait->data.poll.deadline_us = UINT64_MAX; /* a negative timeout blocks */
	if (tmo_ms > 0) {
		uint64_t now_us = 0;
		lxp_time_us(&now_us);
		wait->data.poll.deadline_us = now_us + (uint64_t)tmo_ms * 1000ull;
	}
	if (lxp_wait_begin(p, wait) != 0)
		return -LXP_EAGAIN;
	return 0; /* parked; the coordinator resumes with the ready count or 0 */
}

static int poll_timed_out(const lxp_proc_t *p)
{
	if (p->wait.data.poll.deadline_us == UINT64_MAX)
		return 0;
	uint64_t now_us = 0;
	lxp_time_us(&now_us);
	return now_us >= p->wait.data.poll.deadline_us;
}

/* ---- poll / ppoll ---------------------------------------------------------- */

long lxp_sys_poll(lxp_proc_t *p, long nr, long a0, long a1, long a2)
{
	uintptr_t upfds = (uintptr_t)a0;
	unsigned nfds = (unsigned)a1;
	if (nfds > LXP_MAX_FDS)
		return -LXP_EINVAL;
	long tmo_ms = -1; /* ppoll(NULL): block */
	if (nr == LXP_NR_poll) {
		tmo_ms = (long)(int32_t)a2;
	} else if (a2) {
		int64_t ts[2]; /* {tv_sec, tv_nsec} */
		if (lxp_copy_from_guest(p, ts, (uintptr_t)a2, sizeof(ts)) != 0)
			return -LXP_EFAULT;
		tmo_ms = (long)(ts[0] * 1000 + ts[1] / 1000000);
	}
	lxp_pollfd pf[LXP_MAX_FDS];
	size_t bytes = (size_t)nfds * sizeof(pf[0]);
	if (nfds && lxp_copy_from_guest(p, pf, upfds, bytes) != 0)
		return -LXP_EFAULT;
	int waitable = 0;
	int ready = poll_scan(p, pf, nfds, &tmo_ms, &waitable);
	if (nfds && lxp_copy_to_guest(p, upfds, pf, bytes) != 0)
		return -LXP_EFAULT;
	if (ready > 0 || tmo_ms == 0)
		return ready;
	if (waitable) {
		lxp_wait_t wait = {
			.data.poll.pollfds = upfds,
			.data.poll.nfds = (int)nfds,
		};
		return poll_park(p, &wait, tmo_ms);
	}
	/* Nothing in the set can become ready (an empty set, or a read_key probe of a
	 * console without a console_poll hook). With the UART console sleep out the
	 * timeout; otherwise answer at once. */
	if (p->console_poll && tmo_ms > 0) {
		uint64_t now_us = 0;
		lxp_time_us(&now_us);
		lxp_wait_t wait = {
			.kind = LXP_WAIT_TIMER,
			.data.timer.deadline_us = now_us + (uint64_t)tmo_ms * 1000ull,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
	}
	return 0;
}

static long poll_retry(lxp_proc_t *p)
{
	uintptr_t upfds = p->wait.data.poll.pollfds;
	unsigned nfds = (unsigned)p->wait.data.poll.nfds;
	lxp_pollfd pf[LXP_MAX_FDS];
	size_t bytes = (size_t)nfds * sizeof(pf[0]);
	if (nfds && lxp_copy_from_guest(p, pf, upfds, bytes) != 0)
		return -LXP_EFAULT;
	int ready = poll_scan(p, pf, nfds, NULL, NULL);
	if (ready == 0 && !poll_timed_out(p))
		return -LXP_EAGAIN;
	if (nfds && lxp_copy_to_guest(p, upfds, pf, bytes) != 0)
		return -LXP_EFAULT;
	return ready;
}

/* ---- pselect6: select() over the poll scan --------------------------------- */

/* The first fd_set word of @p uset, or 0 for an absent set. */
static int sel_load(lxp_proc_t *p, uintptr_t uset, uint32_t *word)
{
	*word = 0;
	return uset ? lxp_guest_get_u32(p, uset, word) : 0;
}

/* Build pollfds from the wait's fd_sets: the count, or -EFAULT. */
static int sel_build(lxp_proc_t *p, const lxp_wait_t *wait, lxp_pollfd *pf)
{
	uint32_t r, w;
	if (sel_load(p, wait->data.poll.readfds, &r) != 0 ||
	    sel_load(p, wait->data.poll.writefds, &w) != 0)
		return -LXP_EFAULT;
	int n = 0;
	for (int fd = 0; fd < wait->data.poll.nfds; fd++) {
		short events = (short)((((r >> fd) & 1u) ? LXP_POLLIN : 0) |
				       (((w >> fd) & 1u) ? LXP_POLLOUT : 0));
		if (events) {
			pf[n].fd = fd;
			pf[n].events = events;
			pf[n].revents = 0;
			n++;
		}
	}
	return n;
}

/* Write the ready fds back into the caller's fd_sets and return select()'s count
 * (a fd ready for both read and write counts twice). exceptfds is cleared: there
 * is no out-of-band data on this tier. */
static long sel_writeback(lxp_proc_t *p, const lxp_wait_t *wait, const lxp_pollfd *pf, int n)
{
	uint32_t r = 0, w = 0;
	long ready = 0;
	for (int i = 0; i < n; i++) {
		uint32_t bit = 1u << pf[i].fd;
		if (pf[i].revents & LXP_POLLIN) {
			r |= bit;
			ready++;
		}
		if (pf[i].revents & LXP_POLLOUT) {
			w |= bit;
			ready++;
		}
	}
	if ((wait->data.poll.readfds && lxp_guest_put_u32(p, wait->data.poll.readfds, r) != 0) ||
	    (wait->data.poll.writefds && lxp_guest_put_u32(p, wait->data.poll.writefds, w) != 0) ||
	    (wait->data.poll.exceptfds && lxp_guest_put_u32(p, wait->data.poll.exceptfds, 0) != 0))
		return -LXP_EFAULT;
	return ready;
}

/* Scan a select set: the count written back, -EBADF for a set bit naming no open
 * descriptor, or -EAGAIN when nothing is ready and @p may_wait. */
static long sel_scan(lxp_proc_t *p, const lxp_wait_t *wait, int may_wait)
{
	lxp_pollfd pf[LXP_SEL_MAXFDS];
	int n = sel_build(p, wait, pf);
	if (n < 0)
		return n;
	int ready = poll_scan(p, pf, (unsigned)n, NULL, NULL);
	for (int i = 0; i < n; i++)
		if (pf[i].revents & LXP_POLLNVAL)
			return -LXP_EBADF;
	if (ready == 0 && may_wait)
		return -LXP_EAGAIN;
	return sel_writeback(p, wait, pf, n);
}

long lxp_sys_pselect6(lxp_proc_t *p, int nfds, uintptr_t urfds, uintptr_t uwfds, uintptr_t uefds,
		      uintptr_t utimeout)
{
	if (nfds < 0)
		return -LXP_EINVAL;
	if (nfds > LXP_SEL_MAXFDS)
		nfds = LXP_SEL_MAXFDS; /* one fd_set word; higher fds are not selectable here */
	long tmo_ms = -1; /* NULL timeout: block */
	if (utimeout) {
		int64_t ts[2]; /* time64: {tv_sec, tv_nsec} */
		if (lxp_copy_from_guest(p, ts, utimeout, sizeof(ts)) != 0)
			return -LXP_EFAULT;
		int64_t ms = ts[0] * 1000 + ts[1] / 1000000;
		tmo_ms = ms < 0 ? 0 : (long)ms;
	}
	lxp_wait_t wait = {
		.flags = 1, /* select: re-derive the set from the fd_sets on each scan */
		.data.poll.nfds = nfds,
		.data.poll.readfds = urfds,
		.data.poll.writefds = uwfds,
		.data.poll.exceptfds = uefds,
	};
	long rc = sel_scan(p, &wait, tmo_ms != 0);
	if (rc != -LXP_EAGAIN)
		return rc;
	return poll_park(p, &wait, tmo_ms);
}

long lxp_poll_retry(lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_POLL)
		return -LXP_EINVAL;
	if (p->wait.flags & 1u)
		return sel_scan(p, &p->wait, !poll_timed_out(p));
	return poll_retry(p);
}
