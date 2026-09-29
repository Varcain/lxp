/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The fd-kind → file-operation table and the helpers the kinds share (in-memory
 * reads, seek arithmetic).
 */
#include "fs/lxp_vfs.h"

#include "fs/lxp_stat.h"

#include "lxp_guest.h"
#include "lxp_linux_uapi.h"

#include <string.h>

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

long lxp_vfs_read_mem(lxp_proc_t *p, const void *data, size_t size, void *buf, size_t len,
		      uint64_t off)
{
	if (off >= size)
		return 0; /* EOF */
	size_t n = size - (size_t)off;
	if (n > len)
		n = len;
	if (lxp_copy_to_guest(p, (uintptr_t)buf, (const uint8_t *)data + (size_t)off, n) != 0)
		return -LXP_EFAULT;
	return (long)n;
}

int64_t lxp_vfs_seek(lxp_ofd_t *ofd, int64_t end, int64_t off, int whence)
{
	int64_t base;
	switch (whence) {
	case LXP_SEEK_SET:
		base = 0;
		break;
	case LXP_SEEK_CUR:
		base = (int64_t)ofd->offset;
		break;
	case LXP_SEEK_END:
		base = end;
		break;
	default:
		return -LXP_EINVAL;
	}
	if (off > 0 && base > INT64_MAX - off)
		return -LXP_EOVERFLOW;
	int64_t pos = base + off;
	if (pos < 0)
		return -LXP_EINVAL;
	if ((uint64_t)pos > SIZE_MAX)
		return -LXP_EOVERFLOW;
	ofd->offset = (size_t)pos;
	return pos;
}

long lxp_vfs_copy_path(const char *path, char *out, size_t cap)
{
	size_t n = strlen(path);
	if (n >= cap)
		return -LXP_ENAMETOOLONG;
	memcpy(out, path, n + 1u);
	return 0;
}

long lxp_vfs_dir_path(lxp_proc_t *p, int fd, char *out, size_t cap)
{
	lxp_ofd_t *ofd = lxp_fd_description(p, fd);
	if (!ofd)
		return -LXP_EBADF;
	const lxp_file_ops_t *ops = lxp_vfs_ops(ofd);
	if (ops && ops->dir_path)
		return ops->dir_path(p, ofd, out, cap);
	struct lxp_stat st;
	if (ops && ops->fstat && ops->fstat(p, ofd, &st) == 0 &&
	    (st.mode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EOPNOTSUPP;
	return -LXP_ENOTDIR;
}
