/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Provider results as the guest sees them; see lxp_errno.h.
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
