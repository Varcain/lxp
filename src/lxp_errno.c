/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Provider results as the guest sees them, and errno results as a host sees them; see
 * lxp_errno.h.
 */
#include "lxp_errno.h"

#include "lxp/lxp_types.h"
#include "lxp_linux_uapi.h"

long lxp_errno_from_err(int err)
{
	switch (err) {
	case LXP_OK:
	case LXP_ERR_EOF: /* a zero-byte transfer, not an error */
		return 0;
	case LXP_ERR_WOULD_BLOCK:
	case LXP_ERR_QUEUE_FULL:
	case LXP_ERR_QUEUE_EMPTY:
		return -LXP_EAGAIN;
	case LXP_ERR_NOT_REGISTERED:
		return -LXP_ENODEV;
	case LXP_ERR_INVALID_PARAM:
	case LXP_ERR_INVAL:
		return -LXP_EINVAL;
	case LXP_ERR_BUSY:
		return -LXP_EBUSY;
	case LXP_ERR_READ_ONLY:
		return -LXP_EROFS;
	case LXP_ERR_PERMISSION:
		return -LXP_EACCES;
	case LXP_ERR_NO_MEMORY:
		return -LXP_ENOMEM;
	case LXP_ERR_TIMEOUT:
		return -LXP_ETIMEDOUT;
	case LXP_ERR_NOT_SUPPORTED:
		return -LXP_EOPNOTSUPP;
	case LXP_ERR_NOT_FOUND:
		return -LXP_ENOENT;
	case LXP_ERR_ALREADY_EXISTS:
		return -LXP_EEXIST;
	case LXP_ERR_NO_SPACE:
		return -LXP_ENOSPC;
	case LXP_ERR_NOT_DIR:
		return -LXP_ENOTDIR;
	case LXP_ERR_IS_DIR:
		return -LXP_EISDIR;
	case LXP_ERR_NOT_EMPTY:
		return -LXP_ENOTEMPTY;
	case LXP_ERR_NAME_TOO_LONG:
		return -LXP_ENAMETOOLONG;
	case LXP_ERR_BAD_HANDLE:
		return -LXP_EBADF;
	case LXP_ERR_CROSS_DEVICE:
		return -LXP_EXDEV;
	case LXP_ERR_NET_REFUSED:
		return -LXP_ECONNREFUSED;
	case LXP_ERR_NET_UNREACHABLE:
		return -LXP_ENETUNREACH;
	case LXP_ERR_NET_ADDR_IN_USE:
		return -LXP_EADDRINUSE;
	case LXP_ERR_NET_ADDR_NOT_AVAILABLE:
		return -LXP_EADDRNOTAVAIL;
	case LXP_ERR_NET_RESET:
		return -LXP_ECONNRESET;
	case LXP_ERR_NET_CLOSED:
		return -LXP_EPIPE;
	default:
		return -LXP_EIO;
	}
}

long lxp_net_errno_from_err(int err)
{
	return err == LXP_ERR_TIMEOUT ? -LXP_EAGAIN : lxp_errno_from_err(err);
}

int lxp_err_from_errno(long err)
{
	switch (err) {
	case 0:
		return LXP_OK;
	case -LXP_EAGAIN:
		return LXP_ERR_WOULD_BLOCK;
	case -LXP_ENODEV:
		return LXP_ERR_NOT_REGISTERED;
	case -LXP_EINVAL:
	case -LXP_E2BIG:
		return LXP_ERR_INVALID_PARAM;
	case -LXP_EBUSY:
		return LXP_ERR_BUSY;
	case -LXP_EROFS:
		return LXP_ERR_READ_ONLY;
	case -LXP_EACCES:
	case -LXP_EPERM:
		return LXP_ERR_PERMISSION;
	case -LXP_ENOMEM:
		return LXP_ERR_NO_MEMORY;
	case -LXP_ETIMEDOUT:
		return LXP_ERR_TIMEOUT;
	case -LXP_EOPNOTSUPP:
	case -LXP_ENOEXEC:
	case -LXP_ENOSYS:
		return LXP_ERR_NOT_SUPPORTED;
	case -LXP_ENOENT:
		return LXP_ERR_NOT_FOUND;
	case -LXP_EEXIST:
		return LXP_ERR_ALREADY_EXISTS;
	case -LXP_ENOSPC:
		return LXP_ERR_NO_SPACE;
	case -LXP_ENOTDIR:
		return LXP_ERR_NOT_DIR;
	case -LXP_EISDIR:
		return LXP_ERR_IS_DIR;
	case -LXP_ENOTEMPTY:
		return LXP_ERR_NOT_EMPTY;
	case -LXP_ENAMETOOLONG:
		return LXP_ERR_NAME_TOO_LONG;
	case -LXP_EBADF:
		return LXP_ERR_BAD_HANDLE;
	case -LXP_EXDEV:
		return LXP_ERR_CROSS_DEVICE;
	case -LXP_ECONNREFUSED:
		return LXP_ERR_NET_REFUSED;
	case -LXP_ENETUNREACH:
		return LXP_ERR_NET_UNREACHABLE;
	case -LXP_EADDRINUSE:
		return LXP_ERR_NET_ADDR_IN_USE;
	case -LXP_EADDRNOTAVAIL:
		return LXP_ERR_NET_ADDR_NOT_AVAILABLE;
	case -LXP_ECONNRESET:
		return LXP_ERR_NET_RESET;
	case -LXP_EPIPE:
		return LXP_ERR_NET_CLOSED;
	default:
		return LXP_ERR_IO;
	}
}
