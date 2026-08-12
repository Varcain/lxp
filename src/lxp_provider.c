/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Core-owned active provider bindings. Host ports own immutable provider
 * tables; the personality owns which tables are active for a run.
 */
#include "lxp_provider.h"

#if LXP_ENABLE_NET
const lxp_net_ops_t *g_lxp_net_ops;
#endif
#if LXP_ENABLE_DEV
const lxp_display_ops_t *g_lxp_disp_ops;
#endif
#if LXP_ENABLE_FS
const lxp_fs_ops_t *g_lxp_fs_ops;
#endif
#if LXP_ENABLE_BLOCK
const lxp_block_ops_t *g_lxp_block_ops;
#endif

void lxp_providers_publish(const lxp_net_ops_t *net_ops, const lxp_display_ops_t *disp_ops,
			   const lxp_fs_ops_t *fs_ops, const lxp_block_ops_t *block_ops)
{
#if LXP_ENABLE_NET
	g_lxp_net_ops = net_ops;
#else
	(void)net_ops;
#endif
#if LXP_ENABLE_DEV
	g_lxp_disp_ops = disp_ops;
#else
	(void)disp_ops;
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
	g_lxp_disp_ops = NULL;
#endif
#if LXP_ENABLE_FS
	g_lxp_fs_ops = NULL;
#endif
#if LXP_ENABLE_BLOCK
	g_lxp_block_ops = NULL;
#endif
}
