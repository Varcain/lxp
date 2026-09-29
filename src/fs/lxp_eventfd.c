/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * eventfd counters. Descriptor aliases share the refcounted open-file description
 * and counter pool index.
 */
#include "fs/lxp_eventfd.h"

#include <string.h>

#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_linux_uapi.h"

#define LXP_NEVENTFD 8
static struct {
	uint64_t ctr;
	uint16_t flags;
	uint8_t used;
} g_efd[LXP_NEVENTFD];

static long efd_new(unsigned initval, int flags)
{
	for (int i = 0; i < LXP_NEVENTFD; i++)
		if (!g_efd[i].used) {
			g_efd[i].used = 1;
			g_efd[i].ctr = initval;
			g_efd[i].flags = (uint16_t)flags;
			return i;
		}
	return -LXP_EMFILE;
}

long lxp_eventfd_open(lxp_proc_t *p, unsigned initval, int flags)
{
	long ei = efd_new(initval, flags);
	if (ei < 0)
		return ei;
	/* EFD_NONBLOCK / EFD_CLOEXEC share O_NONBLOCK / O_CLOEXEC's values. */
	int fd = lxp_fd_install(p, LXP_FD_EVENTFD, (int)ei,
				LXP_O_RDWR | (flags & (LXP_O_NONBLOCK | LXP_O_CLOEXEC)));
	if (fd < 0) {
		g_efd[ei].used = 0;
		return -LXP_EMFILE;
	}
	return fd;
}

void lxp_eventfd_runtime_reset(void)
{
	memset(g_efd, 0, sizeof(g_efd));
}

/* Release an eventfd pool slot after the open-file description's last close. */
static void efd_close(int ei)
{
	if (ei >= 0 && ei < LXP_NEVENTFD)
		g_efd[ei].used = 0;
}

static int efd_readable(int ei)
{
	return (ei >= 0 && ei < LXP_NEVENTFD && g_efd[ei].ctr) ? 1 : 0;
}

/* eventfd read/write: 8-byte counter. read returns (and clears, or decrements in
 * SEMAPHORE mode) the counter, EAGAIN when zero (the caller polls first); write adds. */
static long efd_read(lxp_proc_t *p, int ei, void *buf, size_t len)
{
	if (ei < 0 || ei >= LXP_NEVENTFD || !g_efd[ei].used)
		return -LXP_EBADF;
	if (len < 8)
		return -LXP_EINVAL;
	if (g_efd[ei].ctr == 0)
		return -LXP_EAGAIN; /* counter empty; the poller re-checks on the tick */
	uint64_t v = (g_efd[ei].flags & LXP_EFD_SEMAPHORE) ? 1u : g_efd[ei].ctr;
	if (lxp_copy_to_guest(p, (uintptr_t)buf, &v, sizeof(v)) != 0)
		return -LXP_EFAULT;
	g_efd[ei].ctr -= v;
	return 8;
}

static long efd_write(lxp_proc_t *p, int ei, const void *buf, size_t len)
{
	if (ei < 0 || ei >= LXP_NEVENTFD || !g_efd[ei].used)
		return -LXP_EBADF;
	if (len < 8)
		return -LXP_EINVAL;
	uint64_t v;
	if (lxp_copy_from_guest(p, &v, (uintptr_t)buf, sizeof(v)) != 0)
		return -LXP_EFAULT;
	if (v == UINT64_MAX) /* -1 is reserved */
		return -LXP_EINVAL;
	if (UINT64_MAX - g_efd[ei].ctr - 1 < v) /* would overflow past max-1 */
		g_efd[ei].ctr = UINT64_MAX - 1;
	else
		g_efd[ei].ctr += v;
	return 8;
}

static long fop_read_eventfd(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	return efd_read(p, s->file_idx, buf, len);
}

static long fop_write_eventfd(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	return efd_write(p, s->file_idx, buf, len);
}

static void fop_close_eventfd(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	efd_close(s->file_idx); /* called only after the final descriptor alias closes */
}

static unsigned fop_poll_eventfd(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	return (unsigned)LXP_POLLOUT | (efd_readable(s->file_idx) ? (unsigned)LXP_POLLIN : 0u);
}

const lxp_file_ops_t lxp_eventfd_fops = {
	.read = fop_read_eventfd,
	.write = fop_write_eventfd,
	.close = fop_close_eventfd,
	.poll = fop_poll_eventfd,
};
