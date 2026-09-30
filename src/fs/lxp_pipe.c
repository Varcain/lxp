/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Pipe objects. A pipe is shared kernel state (like a real kernel's pipe inode): a
 * bounded ring buffer with concurrent producer/consumer. A read on an empty pipe
 * blocks while any write end is open (EOF only once all writers close); a write on a
 * full pipe blocks while a reader is open (-EPIPE once all readers close). The
 * run-loop coordinator parks/wakes the blocked proc — see lxp_pipe_retry. Endpoint
 * counts follow open-file-description lifetime: dup/fork aliases share one endpoint,
 * and the final descriptor close releases it.
 */
#include "fs/lxp_pipe.h"
#include "signal/lxp_signal_policy.h"

#include "fs/lxp_ring.h" /* shared two-memcpy byte-ring read/write */
#include "fs/lxp_vfs.h"
#include "lxp/lxp_config.h"
#include "proc/lxp_proc.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint8_t buf[LXP_PIPE_BUF];
	size_t rpos;  /* ring read index [0, BUF) */
	size_t wpos;  /* ring write index [0, BUF) */
	size_t count; /* bytes currently buffered */
	uint16_t readers;
	uint16_t writers;
	uint8_t used;
} lxp_pipe_t;
static lxp_pipe_t
	g_pipes[LXP_NPIPE] LXP_FAR_BSS; /* LXP_FAR_BSS relocates the pool (STM32: .sdram_bss) */

int lxp_pipe_alloc(void)
{
	for (int i = 0; i < LXP_NPIPE; i++) {
		if (!g_pipes[i].used) {
			g_pipes[i] = (lxp_pipe_t){.used = 1};
			return i;
		}
	}
	return -1;
}

void lxp_pipe_end_open(int pi, int write_end)
{
	if (pi < 0 || pi >= LXP_NPIPE || !g_pipes[pi].used)
		return;
	uint16_t *ends = write_end ? &g_pipes[pi].writers : &g_pipes[pi].readers;
	if (*ends != UINT16_MAX)
		(*ends)++;
}

void lxp_pipe_end_close(int pi, int write_end)
{
	if (pi < 0 || pi >= LXP_NPIPE || !g_pipes[pi].used)
		return;
	uint16_t *ends = write_end ? &g_pipes[pi].writers : &g_pipes[pi].readers;
	if (*ends > 0)
		(*ends)--;
	if (g_pipes[pi].readers == 0 && g_pipes[pi].writers == 0)
		g_pipes[pi] = (lxp_pipe_t){0};
}

void lxp_pipe_discard(int pi)
{
	if (pi >= 0 && pi < LXP_NPIPE && g_pipes[pi].readers == 0 &&
	    g_pipes[pi].writers == 0)
		g_pipes[pi] = (lxp_pipe_t){0};
}

void lxp_pipe_runtime_reset(void)
{
	for (int i = 0; i < LXP_NPIPE; i++)
		g_pipes[i] = (lxp_pipe_t){0};
}

long pipe_try_read(int pi, void *buf, size_t len)
{
	lxp_pipe_t *pp = &g_pipes[pi];
	if (pp->count == 0)
		return pp->writers > 0 ? -LXP_EAGAIN : 0;
	return (long)lxp_ring_read(pp->buf, LXP_PIPE_BUF, &pp->rpos, &pp->count, buf, len);
}

long pipe_try_write(int pi, const void *buf, size_t len)
{
	lxp_pipe_t *pp = &g_pipes[pi];
	if (pp->readers == 0)
		return -LXP_EPIPE;
	if (pp->count == LXP_PIPE_BUF)
		return -LXP_EAGAIN; /* full but a reader is open */
	return (long)lxp_ring_write(pp->buf, LXP_PIPE_BUF, &pp->wpos, &pp->count, buf, len);
}

/* Retry a parked pipe read/write for the run-loop coordinator (declared in lxp_proc.h). */
long lxp_pipe_retry(lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_PIPE)
		return -LXP_EINVAL;
	if (p->wait.op == 1)
		return pipe_try_read(p->wait.data.io.object, (void *)p->wait.data.io.buffer,
				     p->wait.data.io.length);
	if (p->wait.op == 2)
		return pipe_try_write(p->wait.data.io.object, (const void *)p->wait.data.io.buffer,
				      p->wait.data.io.length);
	return 0;
}

/* poll/select readiness. Report REAL readiness (not always-ready): a read end is
 * POLLIN when it has data or all writers closed (EOF); a write end is POLLOUT when it
 * has space or all readers closed. Always-ready breaks select() on an empty self-pipe. */
unsigned pipe_poll(int pi, int rw)
{
	lxp_pipe_t *pp = &g_pipes[pi];
	if (rw == 0)
		return (pp->count > 0 || pp->writers == 0) ? LXP_POLLIN : 0u;
	return (pp->count < LXP_PIPE_BUF || pp->readers == 0) ? LXP_POLLOUT : 0u;
}

/* A pipe read end drains the shared ring; blocks while empty + a writer is open,
 * EOF (0) once all writers have closed. */
static long fop_read_pipe(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	if (s->rw != 0)
		return -LXP_EBADF;
	long r = pipe_try_read(s->file_idx, buf, len);
	if (r == -LXP_EAGAIN) { /* empty but a writer is open */
		if (s->nonblock)
			return -LXP_EAGAIN; /* O_NONBLOCK: don't park (self-pipe drain) */
		lxp_wait_t wait = {
			.kind = LXP_WAIT_PIPE,
			.op = 1,
			.data.io.object = s->file_idx,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
		};
		return lxp_wait_park(p, &wait);
	}
	return r; /* bytes read, or 0 (EOF) */
}

/* A pipe write end appends to the shared ring; blocks when full (reader open). */
static long fop_write_pipe(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	if (s->rw != 1)
		return -LXP_EBADF;
	long r = pipe_try_write(s->file_idx, buf, len);
	if (r == -LXP_EAGAIN) { /* full but a reader is open */
		if (s->nonblock)
			return -LXP_EAGAIN; /* O_NONBLOCK: don't park */
		lxp_wait_t wait = {
			.kind = LXP_WAIT_PIPE,
			.op = 2,
			.data.io.object = s->file_idx,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
		};
		return lxp_wait_park(p, &wait); /* dispatch parks; coordinator completes via lxp_pipe_retry */
	}
	if (r == -LXP_EPIPE && /* no readers: SIGPIPE — default terminates the writer */
	    lxp_sig_handler_get(p, LXP_SIGPIPE) != LXP_SIG_IGN)
		lxp_signal_terminate(p, LXP_SIGPIPE, LXP_EXIT_REASON_SIGNAL, 0, 0);
	return r; /* bytes written, or -EPIPE (no readers; writer exits unless it ignores it) */
}

static void fop_close_pipe(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_pipe_end_close(s->file_idx, s->rw);
}

static unsigned fop_poll_pipe(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	return (unsigned)pipe_poll(s->file_idx, s->rw); /* real readiness (empty self-pipe!) */
}

const lxp_file_ops_t lxp_pipe_fops = {
	.read = fop_read_pipe,
	.write = fop_write_pipe,
	.close = fop_close_pipe,
	.poll = fop_poll_pipe,
};
