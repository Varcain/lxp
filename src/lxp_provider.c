/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Core-owned active provider bindings. Host ports own immutable provider
 * tables; the personality owns which tables are active for a run.
 */
#include "lxp_provider.h"

#include "lxp_linux_uapi.h"

#if LXP_ENABLE_NET
const lxp_net_ops_t *g_lxp_net_ops;
#endif
#if LXP_ENABLE_DEV
const lxp_display_ops_t *g_lxp_display_ops;
#endif
#if LXP_ENABLE_FS
const lxp_fs_ops_t *g_lxp_fs_ops;
#endif
#if LXP_ENABLE_BLOCK
const lxp_block_ops_t *g_lxp_block_ops;
#endif

void lxp_providers_publish(const lxp_net_ops_t *net_ops, const lxp_display_ops_t *display_ops,
			   const lxp_fs_ops_t *fs_ops, const lxp_block_ops_t *block_ops)
{
#if LXP_ENABLE_NET
	g_lxp_net_ops = net_ops;
#else
	(void)net_ops;
#endif
#if LXP_ENABLE_DEV
	g_lxp_display_ops = display_ops;
#else
	(void)display_ops;
#endif
#if LXP_ENABLE_FS
	g_lxp_fs_ops = fs_ops;
#else
	(void)fs_ops;
#endif
#if LXP_ENABLE_BLOCK
	g_lxp_block_ops = block_ops;
#else
	(void)block_ops;
#endif
}

void lxp_providers_clear(void)
{
#if LXP_ENABLE_NET
	g_lxp_net_ops = NULL;
#endif
#if LXP_ENABLE_DEV
	g_lxp_display_ops = NULL;
#endif
#if LXP_ENABLE_FS
	g_lxp_fs_ops = NULL;
#endif
#if LXP_ENABLE_BLOCK
	g_lxp_block_ops = NULL;
#endif
}

long lxp_provider_error(int result)
{
	switch (result) {
	case LXP_OK:
	case LXP_ERR_EOF:
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
	default:
		return -LXP_EIO;
	}
}
