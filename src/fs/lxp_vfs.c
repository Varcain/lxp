/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The fd-kind → file-operation table and the seek arithmetic kinds share.
 */
#include "fs/lxp_vfs.h"

#include "lxp_linux_uapi.h"

const lxp_file_ops_t *const g_lxp_file_ops[LXP_FD_KIND_COUNT] = {
	[LXP_FD_CONSOLE] = &lxp_console_fops, [LXP_FD_FILE] = &lxp_rootfs_fops,
	[LXP_FD_PIPE] = &lxp_pipe_fops,	      [LXP_FD_TMPFS] = &lxp_tmpfs_fops,
	[LXP_FD_PROC] = &lxp_procfs_fops,     [LXP_FD_EVENTFD] = &lxp_eventfd_fops,
#if LXP_ENABLE_DEV
	[LXP_FD_DEV] = &lxp_dev_fops,
#endif
#if LXP_ENABLE_NET
	[LXP_FD_SOCKET] = &lxp_socket_fops,
#endif
#if LXP_ENABLE_NETFS
	[LXP_FD_NET] = &lxp_netfs_fops,
#endif
#if LXP_ENABLE_FS
	[LXP_FD_HOSTFS] = &lxp_hostfs_fops,
#endif
#if LXP_ENABLE_PTY
	[LXP_FD_PTY] = &lxp_pty_fops,
#endif
};

long lxp_vfs_seek(lxp_ofd_t *ofd, long end, long off, int whence)
{
	long base;
	switch (whence) {
	case LXP_SEEK_SET:
		base = 0;
		break;
	case LXP_SEEK_CUR:
		base = (long)ofd->offset;
		break;
	case LXP_SEEK_END:
		base = end;
		break;
	default:
		return -LXP_EINVAL;
	}
	long pos = base + off;
	if (pos < 0)
		return -LXP_EINVAL;
	ofd->offset = (size_t)pos;
	return pos;
}
