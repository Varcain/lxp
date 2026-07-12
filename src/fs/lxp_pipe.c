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
 * run-loop coordinator parks/wakes the blocked proc — see lxp_pipe_retry. Open ends
 * are counted on demand across every live proc's fd table (a pipe end is open in each
 * proc that holds an fd onto it), so there is no per-fd refcount to keep in sync and a
 * slot is auto-reclaimed when both ends close or the holders exit.
 */
#include "fs/lxp_pipe.h"

#include "lxp/lxp_config.h"
#include "lxp/lxp_syscall.h"

#include <stddef.h>
#include <string.h>

typedef struct {
	uint8_t buf[LXP_PIPE_BUF];
	size_t rpos;  /* ring read index [0, BUF) */
	size_t wpos;  /* ring write index [0, BUF) */
	size_t count; /* bytes currently buffered */
	int used;
} lxp_pipe_t;
static lxp_pipe_t g_pipes[LXP_NPIPE] LXP_FAR_BSS; /* LXP_FAR_BSS relocates the pool (STM32: .sdram_bss) */

/* Count a pipe's open read/write ends across ALL live procs' fd tables. lxp_proc_table
 * / lxp_proc_nslot are weak in lxp_syscall.c (the host test links them but never drives
 * pipes); the run loop supplies the strong versions. */
static void pipe_ends(int pi, int *readers, int *writers)
{
	*readers = 0;
	*writers = 0;
	lxp_proc_t *tab = lxp_proc_table();
	int n = lxp_proc_nslot();
	if (!tab)
		return;
	for (int s = 0; s < n; s++) {
		if (!tab[s].alive)
			continue;
		for (int fd = 0; fd < LXP_MAX_FDS; fd++)
			if (tab[s].fds[fd].kind == LXP_FD_PIPE && tab[s].fds[fd].file_idx == pi)
				(tab[s].fds[fd].rw ? (*writers)++ : (*readers)++);
	}
}

int lxp_pipe_alloc(void)
{
	for (int i = 0; i < LXP_NPIPE; i++) {
		int rd, wr;
		pipe_ends(i, &rd, &wr);
		if (rd == 0 && wr == 0) {
			g_pipes[i].used = 1;
			g_pipes[i].rpos = 0;
			g_pipes[i].wpos = 0;
			g_pipes[i].count = 0;
			return i;
		}
	}
	return -1;
}

long pipe_try_read(int pi, void *buf, size_t len)
{
	lxp_pipe_t *pp = &g_pipes[pi];
	if (pp->count == 0) {
		int rd, wr;
		pipe_ends(pi, &rd, &wr);
		return wr > 0 ? -LXP_EAGAIN : 0;
	}
	if (len > pp->count)
		len = pp->count;
	uint8_t *out = (uint8_t *)buf;
	size_t n1 = LXP_PIPE_BUF - pp->rpos; /* contiguous bytes to the ring end */
	if (n1 > len)
		n1 = len;
	memcpy(out, &pp->buf[pp->rpos], n1);
	memcpy(out + n1, &pp->buf[0], len - n1); /* wrapped tail (len-n1 may be 0 = no-op) */
	pp->rpos = (pp->rpos + len) % LXP_PIPE_BUF;
	pp->count -= len;
	return (long)len;
}

long pipe_try_write(int pi, const void *buf, size_t len)
{
	lxp_pipe_t *pp = &g_pipes[pi];
	int rd, wr;
	pipe_ends(pi, &rd, &wr);
	if (rd == 0)
		return -LXP_EPIPE;
	size_t space = LXP_PIPE_BUF - pp->count;
	if (space == 0)
		return -LXP_EAGAIN;
	if (len > space)
		len = space;
	const uint8_t *in = (const uint8_t *)buf;
	size_t n1 = LXP_PIPE_BUF - pp->wpos; /* contiguous space to the ring end */
	if (n1 > len)
		n1 = len;
	memcpy(&pp->buf[pp->wpos], in, n1);
	memcpy(&pp->buf[0], in + n1, len - n1); /* wrapped tail (len-n1 may be 0 = no-op) */
	pp->wpos = (pp->wpos + len) % LXP_PIPE_BUF;
	pp->count += len;
	return (long)len;
}

/* Retry a parked pipe read/write for the run-loop coordinator (declared in lxp_syscall.h). */
long lxp_pipe_retry(lxp_proc_t *p)
{
	if (p->pipe_wait == 1)
		return pipe_try_read(p->pipe_idx, (void *)p->pipe_buf, p->pipe_len);
	if (p->pipe_wait == 2)
		return pipe_try_write(p->pipe_idx, (const void *)p->pipe_buf, p->pipe_len);
	return 0;
}

/* poll/select readiness. Report REAL readiness (not always-ready): a read end is
 * POLLIN when it has data or all writers closed (EOF); a write end is POLLOUT when it
 * has space or all readers closed. Always-ready breaks select() on an empty self-pipe. */
unsigned pipe_poll(int pi, int rw)
{
	lxp_pipe_t *pp = &g_pipes[pi];
	int rd, wr;
	pipe_ends(pi, &rd, &wr);
	if (rw == 0)
		return (pp->count > 0 || wr == 0) ? LXP_POLLIN : 0u;
	return (pp->count < LXP_PIPE_BUF || rd == 0) ? LXP_POLLOUT : 0u;
}
