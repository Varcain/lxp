/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#include "lxp/lxp_config.h"

#if LXP_ENABLE_LINUX

#include "fs/lxp_fd_private.h"

#include "lxp_vfs.h"

#include <string.h>

/* One distinct open-file description per possible descriptor. Fork and dup
 * increase refs without allocating another object. */
#define LXP_MAX_OFD (LXP_NSLOT * LXP_MAX_FDS)
static lxp_ofd_t g_ofd[LXP_MAX_OFD];

static lxp_ofd_t *fd_lookup(lxp_proc_t *proc, int fd)
{
	if (!proc || !proc->files || fd < 0 || fd >= LXP_MAX_FDS || proc->files->fd[fd].ofd == 0 ||
	    proc->files->fd[fd].ofd > LXP_MAX_OFD)
		return NULL;
	lxp_ofd_t *ofd = &g_ofd[proc->files->fd[fd].ofd - 1u];
	return ofd->refs ? ofd : NULL;
}

lxp_ofd_t *lxp_fd_description(lxp_proc_t *proc, int fd)
{
	return fd_lookup(proc, fd);
}

uint8_t lxp_fd_kind(const lxp_proc_t *proc, int fd)
{
	const lxp_ofd_t *ofd = fd_lookup((lxp_proc_t *)proc, fd);
	return ofd ? ofd->kind : LXP_FD_FREE;
}

int lxp_fd_backing(const lxp_proc_t *proc, int fd)
{
	const lxp_ofd_t *ofd = fd_lookup((lxp_proc_t *)proc, fd);
	return ofd ? ofd->file_idx : -1;
}

int lxp_fd_open(lxp_proc_t *proc, uint8_t kind, int backing, size_t offset,
		const struct lxp_file_ops *ops)
{
	if (!proc || !proc->files)
		return -LXP_EMFILE;

	int oi = -1;
	for (int i = 0; i < LXP_MAX_OFD; i++)
		if (g_ofd[i].refs == 0) {
			oi = i;
			break;
		}
	if (oi < 0)
		return -LXP_EMFILE;

	for (int fd = 0; fd < LXP_MAX_FDS; fd++) {
		if (proc->files->fd[fd].ofd != 0)
			continue;
		g_ofd[oi].refs = 1;
		g_ofd[oi].kind = kind;
		g_ofd[oi].rw = 0;
		g_ofd[oi].nonblock = 0;
		g_ofd[oi].file_idx = backing;
		g_ofd[oi].offset = offset;
		g_ofd[oi].ops = ops;
		proc->files->fd[fd].ofd = (uint16_t)(oi + 1);
		proc->files->fd[fd].cloexec = 0;
		return fd;
	}
	return -LXP_EMFILE;
}

int lxp_fd_set_status(lxp_proc_t *proc, int fd, int direction, int nonblock)
{
	lxp_ofd_t *ofd = fd_lookup(proc, fd);
	if (!ofd)
		return -LXP_EBADF;
	ofd->rw = direction ? 1 : 0;
	ofd->nonblock = nonblock ? 1 : 0;
	return 0;
}

int lxp_fd_set_cloexec(lxp_proc_t *proc, int fd, int enabled)
{
	if (!fd_lookup(proc, fd))
		return -LXP_EBADF;
	proc->files->fd[fd].cloexec = enabled ? 1 : 0;
	return 0;
}

int lxp_fd_get_cloexec(const lxp_proc_t *proc, int fd)
{
	if (!fd_lookup((lxp_proc_t *)proc, fd))
		return -LXP_EBADF;
	return proc->files->fd[fd].cloexec ? 1 : 0;
}

int lxp_fd_free_count(const lxp_proc_t *proc)
{
	if (!proc || !proc->files)
		return 0;
	int count = 0;
	for (int fd = 0; fd < LXP_MAX_FDS; fd++)
		if (proc->files->fd[fd].ofd == 0)
			count++;
	return count;
}

int lxp_fd_close(lxp_proc_t *proc, int fd)
{
	lxp_ofd_t *ofd = fd_lookup(proc, fd);
	if (!ofd)
		return -LXP_EBADF;
	proc->files->fd[fd] = (lxp_fd_t){0};
	if (--ofd->refs == 0) {
		if (ofd->ops && ofd->ops->close)
			ofd->ops->close(proc, ofd);
		memset(ofd, 0, sizeof(*ofd));
	}
	return 0;
}

void lxp_fd_close_all(lxp_proc_t *proc)
{
	if (!proc || !proc->files)
		return;
	for (int fd = 0; fd < LXP_MAX_FDS; fd++)
		(void)lxp_fd_close(proc, fd);
}

void lxp_fd_close_on_exec(lxp_proc_t *proc)
{
	if (!proc || !proc->files)
		return;
	for (int fd = 0; fd < LXP_MAX_FDS; fd++)
		if (lxp_fd_get_cloexec(proc, fd) > 0)
			(void)lxp_fd_close(proc, fd);
}

void lxp_fd_runtime_reset(void)
{
	memset(g_ofd, 0, sizeof(g_ofd));
}

int lxp_fd_table_retain(lxp_proc_t *proc)
{
	if (!proc || !proc->files)
		return -1;
	for (int fd = 0; fd < LXP_MAX_FDS; fd++) {
		lxp_ofd_t *ofd = fd_lookup(proc, fd);
		if (ofd && ofd->refs == UINT16_MAX)
			return -1;
	}
	for (int fd = 0; fd < LXP_MAX_FDS; fd++) {
		lxp_ofd_t *ofd = fd_lookup(proc, fd);
		if (ofd)
			ofd->refs++;
	}
	return 0;
}

static int fd_retain(lxp_ofd_t *ofd)
{
	if (!ofd || ofd->refs == UINT16_MAX)
		return -1;
	ofd->refs++;
	return 0;
}

int lxp_fd_dup_to(lxp_proc_t *proc, int oldfd, int newfd, int cloexec)
{
	lxp_ofd_t *ofd = fd_lookup(proc, oldfd);
	if (!ofd)
		return -LXP_EBADF;
	if (newfd < 0 || newfd >= LXP_MAX_FDS)
		return -LXP_EBADF;
	if (oldfd == newfd)
		return newfd;

	uint16_t old_ofd = proc->files->fd[oldfd].ofd;
	if (fd_retain(ofd) != 0)
		return -LXP_EMFILE;
	if (proc->files->fd[newfd].ofd)
		(void)lxp_fd_close(proc, newfd);
	proc->files->fd[newfd].ofd = old_ofd;
	proc->files->fd[newfd].cloexec = cloexec ? 1 : 0;
	return newfd;
}

int lxp_fd_dup_min(lxp_proc_t *proc, int oldfd, int minfd, int cloexec)
{
	lxp_ofd_t *ofd = fd_lookup(proc, oldfd);
	if (!ofd)
		return -LXP_EBADF;
	if (minfd < 0 || minfd >= LXP_MAX_FDS)
		return -LXP_EMFILE;
	for (int fd = minfd; fd < LXP_MAX_FDS; fd++) {
		if (proc->files->fd[fd].ofd != 0)
			continue;
		if (fd_retain(ofd) != 0)
			return -LXP_EMFILE;
		proc->files->fd[fd].ofd = proc->files->fd[oldfd].ofd;
		proc->files->fd[fd].cloexec = cloexec ? 1 : 0;
		return fd;
	}
	return -LXP_EMFILE;
}

#endif /* LXP_ENABLE_LINUX */
