/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */
/*
 * Pseudo-terminal (Unix98 pty) layer for the Linux personality.
 *
 * A pty is two in-memory rings — m2s (master→slave, program INPUT) and s2m
 * (slave→master, program OUTPUT) — plus a minimal in-kernel line discipline. It is
 * the two-ended pipe with a transform at the boundary: master WRITE runs input
 * processing (ICRNL, ISIG ^C/^Z, canonical line editing + echo), slave WRITE runs
 * output processing (OPOST/ONLCR). Master/slave counts follow open-file-description
 * lifetime, so dup/fork aliases do not create phantom endpoints and the final close
 * drives EOF/hangup without inspecting the coordinator's process table.
 *
 * dropbear opens /dev/ptmx (master) + /dev/pts/N (slave = the login shell's ctty) and
 * shuttles bytes between the master and the SSH channel; ash reads/writes the slave.
 * Gated on LXP_ENABLE_PTY.
 */
#include "lxp/lxp_config.h" /* LXP_PTY_BUF */
#include "pty/lxp_pty.h"

#if LXP_ENABLE_PTY

#include <string.h>

#include "fs/lxp_ring.h" /* shared two-memcpy byte-ring read */
#include "fs/lxp_stat.h"
#include "fs/lxp_tty.h"
#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_internal.h" /* foreground process-group signal service */
#include "proc/lxp_proc.h"

/* Each login holds one pty pair (a master + a slave), so two pairs allow two
 * concurrent SSH logins. The rings (LXP_PTY_BUF, lxp_config.h) are small — a terminal
 * is interactive, not bulk: the s2m OUTPUT ring applies backpressure (the shell's write
 * parks) when the server is slow to drain, so a burst is paced, never dropped. */
#define LXP_NPTY 2
#define LXP_PTY_CANON 256 /* max in-progress canonical line before it must end */

typedef struct {
	uint8_t buf[LXP_PTY_BUF];
	size_t r, w, n; /* ring read/write index [0,BUF) + bytes buffered */
} pty_ring_t;

typedef struct {
	pty_ring_t m2s; /* master→slave: program input (keystrokes, post-discipline) */
	pty_ring_t s2m; /* slave→master: program output (+ canonical echo) */
	uint8_t canon[LXP_PTY_CANON]; /* in-progress canonical line (not yet readable) */
	size_t canon_n;
	lxp_tty_t tty; /* termios, window size and foreground process group */
	uint16_t masters;
	uint16_t slaves;
	int used;
	int locked;	    /* TIOCSPTLCK: slave locked until unlockpt (advisory here) */
	int m2s_eof;	    /* one-shot EOF pending on the slave (^D on an empty canonical line) */
	uint8_t m_nb, s_nb; /* O_NONBLOCK per end: an empty/full ring returns EAGAIN, not park.
			     * dropbear sets the master non-blocking and drives it with select. */
} lxp_pty_t;

static lxp_pty_t g_ptys[LXP_NPTY];

/* ── ring helpers ─────────────────────────────────────────────── */

static size_t ring_space(const pty_ring_t *r)
{
	return LXP_PTY_BUF - r->n;
}
static void ring_putc(pty_ring_t *r, uint8_t c)
{
	if (r->n < LXP_PTY_BUF) {
		r->buf[r->w] = c;
		r->w = (r->w + 1) % LXP_PTY_BUF;
		r->n++;
	}
}
static size_t ring_read(pty_ring_t *r, uint8_t *out, size_t len)
{
	return lxp_ring_read(r->buf, LXP_PTY_BUF, &r->r, &r->n, out, len);
}
/* Canonical read: up to and INCLUDING the first newline (one line per read). */
static size_t ring_read_line(pty_ring_t *r, uint8_t *out, size_t len)
{
	size_t i = 0;
	while (i < len && r->n > 0) {
		uint8_t c = r->buf[r->r];
		r->r = (r->r + 1) % LXP_PTY_BUF;
		r->n--;
		out[i++] = c;
		if (c == '\n')
			break;
	}
	return i;
}

static void pty_signal_foreground(int idx, int sig)
{
	if (g_ptys[idx].tty.fg_pgrp > 0)
		(void)lxp_signal_process_group(g_ptys[idx].tty.fg_pgrp, sig);
}

/* ── line discipline ──────────────────────────────────────────── */

/* Master WRITE → toward the slave (program input). Returns bytes consumed (>0), or
 * -EAGAIN if nothing fit (the m2s ring is full and the shell has not drained it). */
static long pty_input(int idx, const uint8_t *in, size_t len)
{
	lxp_pty_t *pt = &g_ptys[idx];
	const lxp_termios *tio = &pt->tty.termios;
	int icanon = tio->c_lflag & LXP_ICANON;
	int echo = tio->c_lflag & LXP_ECHO;
	int icrnl = tio->c_iflag & LXP_ICRNL;
	size_t consumed = 0;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = in[i];
		if (icrnl && c == '\r')
			c = '\n';
		int sig = lxp_tty_signal_for(&pt->tty, c);
		if (sig) {
			pty_signal_foreground(idx, sig);
			consumed++;
			continue;
		}
		if (!icanon) {
			/* Raw mode: the shell's own line editor reads byte-by-byte and echoes
			 * itself, so pass through untouched (echo only if the caller left it on). */
			if (ring_space(&pt->m2s) == 0)
				return consumed ? (long)consumed : -LXP_EAGAIN;
			ring_putc(&pt->m2s, c);
			if (echo)
				ring_putc(&pt->s2m, c);
			consumed++;
			continue;
		}
		/* Canonical mode: accumulate a line; deliver it whole on newline. */
		if (c == tio->c_cc[LXP_VERASE] || c == 0x08) {
			if (pt->canon_n > 0) {
				pt->canon_n--;
				if (echo) { /* erase the echoed char: back, space, back */
					ring_putc(&pt->s2m, 0x08);
					ring_putc(&pt->s2m, ' ');
					ring_putc(&pt->s2m, 0x08);
				}
			}
			consumed++;
			continue;
		}
		if (c == '\n') {
			if (ring_space(&pt->m2s) < pt->canon_n + 1)
				return consumed ? (long)consumed : -LXP_EAGAIN;
			for (size_t k = 0; k < pt->canon_n; k++)
				ring_putc(&pt->m2s, pt->canon[k]);
			ring_putc(&pt->m2s, '\n');
			pt->canon_n = 0;
			if (echo) {
				ring_putc(&pt->s2m, '\r');
				ring_putc(&pt->s2m, '\n');
			}
			consumed++;
			continue;
		}
		if (c == tio->c_cc[LXP_VEOF]) { /* ^D: flush the line; empty → EOF */
			if (ring_space(&pt->m2s) < pt->canon_n)
				return consumed ? (long)consumed : -LXP_EAGAIN;
			for (size_t k = 0; k < pt->canon_n; k++)
				ring_putc(&pt->m2s, pt->canon[k]);
			if (pt->canon_n == 0)
				pt->m2s_eof = 1; /* ^D on an empty line = end-of-file */
			pt->canon_n = 0;
			consumed++;
			continue;
		}
		if (pt->canon_n < LXP_PTY_CANON) {
			pt->canon[pt->canon_n++] = c;
			if (echo)
				ring_putc(&pt->s2m, c);
		}
		consumed++;
	}
	return (long)consumed;
}

/* Slave WRITE → toward the master (program output). ONLCR maps \n → \r\n. Returns
 * bytes consumed (>0), or -EAGAIN if the s2m ring is full (server not draining). */
static long pty_output(int idx, const uint8_t *in, size_t len)
{
	lxp_pty_t *pt = &g_ptys[idx];
	int opost = pt->tty.termios.c_oflag & LXP_OPOST;
	int onlcr = pt->tty.termios.c_oflag & LXP_ONLCR;
	size_t consumed = 0;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = in[i];
		if (opost && onlcr && c == '\n') {
			if (ring_space(&pt->s2m) < 2)
				return consumed ? (long)consumed : -LXP_EAGAIN;
			ring_putc(&pt->s2m, '\r');
			ring_putc(&pt->s2m, '\n');
		} else {
			if (ring_space(&pt->s2m) == 0)
				return consumed ? (long)consumed : -LXP_EAGAIN;
			ring_putc(&pt->s2m, c);
		}
		consumed++;
	}
	return (long)consumed;
}

/* ── public entry points ──────────────────────────────────────── */

long lxp_pty_read(lxp_proc_t *p, int idx, int is_master, void *ubuf, size_t len)
{
	(void)p;
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return -LXP_EBADF;
	lxp_pty_t *pt = &g_ptys[idx];
	if (len == 0)
		return 0;
	uint8_t *out = (uint8_t *)ubuf;
	if (is_master) { /* server reads program output from s2m */
		if (pt->s2m.n > 0)
			return (long)ring_read(&pt->s2m, out, len);
		if (pt->slaves == 0)
			return 0; /* shell exited/closed the slave → EOF, server drops the channel */
		return -LXP_EAGAIN;
	}
	/* slave: the shell reads its input from m2s */
	if (pt->m2s.n > 0)
		return (long)((pt->tty.termios.c_lflag & LXP_ICANON)
				      ? ring_read_line(&pt->m2s, out, len)
				      : ring_read(&pt->m2s, out, len));
	if (pt->masters == 0)
		return 0; /* master closed (client disconnect) → EOF/hangup → the shell exits */
	if (pt->m2s_eof) {
		pt->m2s_eof = 0;
		return 0; /* ^D */
	}
	return -LXP_EAGAIN;
}

long lxp_pty_write(lxp_proc_t *p, int idx, int is_master, const void *ubuf, size_t len)
{
	(void)p;
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return -LXP_EBADF;
	if (len == 0)
		return 0;
	const uint8_t *in = (const uint8_t *)ubuf;
	return is_master ? pty_input(idx, in, len) : pty_output(idx, in, len);
}

long lxp_pty_ioctl(lxp_proc_t *p, int idx, int is_master, unsigned long cmd, unsigned long arg)
{
	(void)is_master;
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return -LXP_EBADF;
	lxp_pty_t *pt = &g_ptys[idx];
	uintptr_t ua = (uintptr_t)arg;
	switch (cmd) {
	case LXP_TIOCGPTN:
		return lxp_guest_put_u32(p, ua, (uint32_t)idx);
	case LXP_TIOCSPTLCK: {
		uint32_t locked;
		if (lxp_guest_get_u32(p, ua, &locked) != 0)
			return -LXP_EFAULT;
		pt->locked = (int)locked;
		return 0;
	}
	default: /* both ends share the one terminal (single-session tier) */
		return lxp_tty_ioctl(p, &pt->tty, cmd, arg);
	}
}

unsigned lxp_pty_poll(int idx, int is_master)
{
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return 0;
	lxp_pty_t *pt = &g_ptys[idx];
	unsigned r = 0;
	if (is_master) {
		if (pt->s2m.n > 0 || pt->slaves == 0)
			r |= LXP_POLLIN; /* data to read, or slave gone (EOF is readable) */
		if (ring_space(&pt->m2s) > 0)
			r |= LXP_POLLOUT;
	} else {
		if (pt->m2s.n > 0 || pt->masters == 0 || pt->m2s_eof)
			r |= LXP_POLLIN;
		if (ring_space(&pt->s2m) > 0)
			r |= LXP_POLLOUT;
	}
	return r;
}

void lxp_pty_fstat(uint32_t *mode, uint64_t *size)
{
	*mode = LXP_S_IFCHR | 0620u;
	*size = 0;
}

int lxp_pty_nonblock(int idx, int is_master)
{
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return 0;
	return is_master ? g_ptys[idx].m_nb : g_ptys[idx].s_nb;
}

void lxp_pty_setfl(int idx, int is_master, int flags)
{
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return;
	uint8_t nb = (flags & LXP_O_NONBLOCK) ? 1 : 0;
	if (is_master)
		g_ptys[idx].m_nb = nb;
	else
		g_ptys[idx].s_nb = nb;
}

long lxp_pty_retry(lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_PTY)
		return -LXP_EINVAL;
	switch (p->wait.op) {
	case LXP_PTYW_SREAD:
		return lxp_pty_read(p, p->wait.data.io.object, 0, (void *)p->wait.data.io.buffer,
				    p->wait.data.io.length);
	case LXP_PTYW_MREAD:
		return lxp_pty_read(p, p->wait.data.io.object, 1, (void *)p->wait.data.io.buffer,
				    p->wait.data.io.length);
	case LXP_PTYW_SWRITE:
		return lxp_pty_write(p, p->wait.data.io.object, 0,
				     (const void *)p->wait.data.io.buffer, p->wait.data.io.length);
	case LXP_PTYW_MWRITE:
		return lxp_pty_write(p, p->wait.data.io.object, 1,
				     (const void *)p->wait.data.io.buffer, p->wait.data.io.length);
	default:
		return 0;
	}
}

/* ── open (/dev/ptmx mint, /dev/pts/N attach) ─────────────────── */

long lxp_pty_open_master(int flags)
{
	for (int i = 0; i < LXP_NPTY; i++) {
		if (g_ptys[i].used)
			continue;
		lxp_pty_t *pt = &g_ptys[i];
		memset(pt, 0, sizeof(*pt));
		pt->used = 1;
		pt->locked = 1; /* until unlockpt (TIOCSPTLCK 0) */
		pt->m_nb = (flags & LXP_O_NONBLOCK) ? 1 : 0;
		lxp_tty_init(&pt->tty); /* the console's cooked defaults */
		return i;
	}
	return -LXP_EMFILE; /* pty pool exhausted */
}

long lxp_pty_open_slave(int num, int flags)
{
	if (num < 0 || num >= LXP_NPTY || !g_ptys[num].used)
		return -LXP_ENOENT;
	g_ptys[num].s_nb = (flags & LXP_O_NONBLOCK) ? 1 : 0;
	return num; /* the pool index doubles as the pts number */
}

int lxp_pty_exists(int num)
{
	return num >= 0 && num < LXP_NPTY && g_ptys[num].used;
}

void lxp_pty_end_open(int idx, int is_master)
{
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return;
	uint16_t *ends = is_master ? &g_ptys[idx].masters : &g_ptys[idx].slaves;
	if (*ends != UINT16_MAX)
		(*ends)++;
}

void lxp_pty_end_close(int idx, int is_master)
{
	if (idx < 0 || idx >= LXP_NPTY || !g_ptys[idx].used)
		return;
	uint16_t *ends = is_master ? &g_ptys[idx].masters : &g_ptys[idx].slaves;
	if (*ends > 0)
		(*ends)--;
	if (g_ptys[idx].masters == 0 && g_ptys[idx].slaves == 0)
		memset(&g_ptys[idx], 0, sizeof(g_ptys[idx]));
}

void lxp_pty_discard(int idx)
{
	if (idx >= 0 && idx < LXP_NPTY && g_ptys[idx].masters == 0 &&
	    g_ptys[idx].slaves == 0)
		memset(&g_ptys[idx], 0, sizeof(g_ptys[idx]));
}

void lxp_pty_runtime_reset(void)
{
	memset(g_ptys, 0, sizeof(g_ptys));
}

/* ---- FD_PTY file operations ---- */
/* A pty end drains its ring (master reads program output, slave reads program input);
 * blocks while empty + the peer end is open, EOF (0) once the peer closes. */
static long fop_read_pty(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	long r = lxp_pty_read(p, s->file_idx, s->rw, buf, len);
	if (r == -LXP_EAGAIN && !lxp_pty_nonblock(s->file_idx, s->rw)) {
		lxp_wait_t wait = {
			.kind = LXP_WAIT_PTY,
			.op = s->rw ? LXP_PTYW_MREAD : LXP_PTYW_SREAD,
			.data.io.object = s->file_idx,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
		};
		return lxp_wait_park(p, &wait); /* parked; coordinator retries via lxp_pty_retry */
	}
	return r; /* bytes read, 0 (EOF), or -EAGAIN (O_NONBLOCK) */
}

/* A pty write feeds the peer's ring through the line discipline (master write runs
 * input processing toward the slave; slave write runs output/ONLCR toward the master).
 * Blocks (backpressure) when the destination ring is full and the peer is open. */
static long fop_write_pty(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	long r = lxp_pty_write(p, s->file_idx, s->rw, buf, len);
	if (r == -LXP_EAGAIN && !lxp_pty_nonblock(s->file_idx, s->rw)) {
		lxp_wait_t wait = {
			.kind = LXP_WAIT_PTY,
			.op = s->rw ? LXP_PTYW_MWRITE : LXP_PTYW_SWRITE,
			.data.io.object = s->file_idx,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
		};
		return lxp_wait_park(p, &wait); /* parked; coordinator completes via lxp_pty_retry */
	}
	return r; /* bytes consumed, or -EAGAIN (O_NONBLOCK) */
}

static long fop_fstat_pty(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	(void)p;
	uint32_t mode;
	uint64_t size;
	lxp_pty_fstat(&mode, &size); /* S_IFCHR so isatty() → interactive shell */
	lxp_stat_init(st, LXP_INO_PTY + (uint32_t)s->file_idx, mode, size);
	return 0;
}

/* F_SETFL: O_NONBLOCK gates parking on this end. */
static void fop_setfl_pty(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_pty_setfl(s->file_idx, s->rw, s->nonblock ? LXP_O_NONBLOCK : 0);
}

static void fop_close_pty(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_pty_end_close(s->file_idx, s->rw);
}

static long fop_ioctl_pty(lxp_proc_t *p, lxp_ofd_t *s, unsigned long cmd, unsigned long arg)
{
	return lxp_pty_ioctl(p, s->file_idx, s->rw, cmd, arg);
}

static unsigned fop_poll_pty(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	return (unsigned)lxp_pty_poll(s->file_idx, s->rw);
}

const lxp_file_ops_t lxp_pty_fops = {
	.read = fop_read_pty,
	.write = fop_write_pty,
	.fstat = fop_fstat_pty,
	.close = fop_close_pty,
	.ioctl = fop_ioctl_pty,
	.poll = fop_poll_pty,
	.setfl = fop_setfl_pty,
};

#endif /* LXP_ENABLE_PTY */
