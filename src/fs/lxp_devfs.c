/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The /dev mount: the built-in console, null, zero and random nodes, the Unix98 pty
 * nodes (/dev/ptmx, /dev/pts/N) and the registered devices (/dev/fb0, ...). Any other
 * name under /dev belongs to the root, so the rootfs /dev directory still resolves.
 */
#include "fs/lxp_mount.h"

#include "fs/lxp_fd_private.h"
#include "lxp_linux_uapi.h"
#if LXP_ENABLE_DEV
#include "dev/lxp_dev.h"
#endif
#if LXP_ENABLE_PTY
#include "pty/lxp_pty.h"
#endif

#include <string.h>

/* The console nodes all open as an FD_CONSOLE whose file_idx selects the behaviour:
 * 2 = r/w console, 3 = /dev/null (EOF/discard), 4 = host entropy, 5 = /dev/zero
 * (zero-fill/discard). getty opens /dev/console and dups it to fds 0/1/2;
 * dropbear/mbedTLS open /dev/urandom for entropy. Device numbers are Linux's. */
static const struct console_node {
	const char *path;
	uint8_t idx;
	uint8_t major;
	uint8_t minor;
} g_console[] = {
	{"/dev/console", 2, 5, 1}, {"/dev/tty", 2, 5, 0},     {"/dev/tty0", 2, 4, 0},
	{"/dev/ttyS0", 2, 4, 64},  {"/dev/null", 3, 1, 3},    {"/dev/urandom", 4, 1, 9},
	{"/dev/random", 4, 1, 8},  {"/dev/zero", 5, 1, 5},
};

#define DEVFS_PTMX (sizeof(g_console) / sizeof(g_console[0])) /* its LXP_INO_DEVFS slot */

static const struct console_node *console_node(const char *path)
{
	for (size_t k = 0; k < sizeof(g_console) / sizeof(g_console[0]); k++)
		if (strcmp(path, g_console[k].path) == 0)
			return &g_console[k];
	return NULL;
}

#if LXP_ENABLE_PTY
/* The pty number N of "/dev/pts/N", or -1 for any other path. */
static int pts_number(const char *path)
{
	if (strncmp(path, "/dev/pts/", 9) != 0)
		return -1;
	const char *d = path + 9;
	if (*d < '0' || *d > '9')
		return -1;
	int num = 0;
	for (; *d >= '0' && *d <= '9'; d++)
		if (num < 100000) /* saturate: a number this large names no pty */
			num = num * 10 + (*d - '0');
	return *d == '\0' ? num : -1;
}
#endif

static int devfs_holds(const lxp_proc_t *p, const char *path)
{
	(void)p;
	if (console_node(path))
		return 1;
#if LXP_ENABLE_PTY
	if (strcmp(path, "/dev/ptmx") == 0 || pts_number(path) >= 0)
		return 1;
#endif
#if LXP_ENABLE_DEV
	if (lxp_dev_lookup(path) >= 0)
		return 1;
#endif
	return 0;
}

static long devfs_open(lxp_proc_t *p, const char *path, int flags)
{
	const struct console_node *c = console_node(path);
	if (c)
		return lxp_fd_install(p, LXP_FD_CONSOLE, c->idx, flags);
#if LXP_ENABLE_PTY
	/* Each open of /dev/ptmx mints a fresh pair and returns its master; the slave is
	 * /dev/pts/N, N being the pool index TIOCGPTN/ptsname report. */
	if (strcmp(path, "/dev/ptmx") == 0) {
		long idx = lxp_pty_open_master(flags);
		if (idx < 0)
			return idx;
		int fd = lxp_fd_install(p, LXP_FD_PTY, (int)idx, flags);
		if (fd >= 0) {
			(void)lxp_fd_set_end(p, fd, 1); /* master end */
			lxp_pty_end_open((int)idx, 1);
		} else {
			lxp_pty_discard((int)idx);
		}
		return fd;
	}
	int num = pts_number(path);
	if (num >= 0) {
		long idx = lxp_pty_open_slave(num, flags);
		if (idx < 0)
			return idx;
		int fd = lxp_fd_install(p, LXP_FD_PTY, (int)idx, flags); /* slave end */
		if (fd >= 0)
			lxp_pty_end_open((int)idx, 0);
		return fd;
	}
#endif
#if LXP_ENABLE_DEV
	/* A registered device opens as an FD_DEV whose file_idx is its open-pool index. */
	int di = lxp_dev_lookup(path);
	if (di >= 0) {
		long oi = lxp_dev_open_new(p, di, flags);
		if (oi < 0)
			return oi;
		int fd = lxp_fd_install(p, LXP_FD_DEV, (int)oi, flags);
		if (fd < 0)
			lxp_dev_close((int)oi);
		return fd;
	}
#endif
	return -LXP_ENOENT;
}

static void devfs_node(struct lxp_stat *st, uint32_t ino, uint32_t mode, uint32_t major,
		       uint32_t minor)
{
	lxp_stat_init(st, ino, LXP_S_IFCHR | mode, 0);
	st->rdev = ((uint64_t)major << 8) | minor;
}

static long devfs_stat(lxp_proc_t *p, const char *path, int follow, struct lxp_stat *st)
{
	(void)p;
	(void)follow;
	const struct console_node *c = console_node(path);
	if (c) {
		devfs_node(st, LXP_INO_DEVFS + (uint32_t)(c - g_console), 0666u, c->major, c->minor);
		return 0;
	}
#if LXP_ENABLE_PTY
	if (strcmp(path, "/dev/ptmx") == 0) {
		devfs_node(st, LXP_INO_DEVFS + (uint32_t)DEVFS_PTMX, 0666u, 5, 2);
		return 0;
	}
	int num = pts_number(path);
	if (num >= 0) {
		if (!lxp_pty_exists(num))
			return -LXP_ENOENT;
		uint64_t size;
		lxp_pty_fstat(&st->mode, &size); /* as fstat reports an open end */
		devfs_node(st, LXP_INO_PTY + (uint32_t)num, st->mode, 136, (uint32_t)num);
		return 0;
	}
#endif
#if LXP_ENABLE_DEV
	lxp_stat_init(st, 0, 0, 0);
	int di = lxp_dev_stat_path(path, &st->mode, &st->rdev);
	if (di >= 0) {
		st->ino = LXP_INO_DEV + (uint32_t)di;
		return 0;
	}
#endif
	return -LXP_ENOENT;
}

/* The nodes are fixed: they take no new names and cannot be removed or renamed. */
const lxp_mount_ops_t lxp_devfs_mount_ops = {
	.holds = devfs_holds,
	.open = devfs_open,
	.stat = devfs_stat,
	.magic = LXP_TMPFS_MAGIC, /* devtmpfs reports tmpfs */
	.name_errno = LXP_EPERM,
};
