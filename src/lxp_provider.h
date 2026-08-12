/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private active-provider bindings. The public API passes provider tables to
 * lxp_run(); only the coordinator and isolated host tests publish them here.
 */
#ifndef LXP_PROVIDER_H
#define LXP_PROVIDER_H

#include "lxp/lxp_config.h"
#include "lxp/lxp_block_ops.h"
#include "lxp/lxp_disp_ops.h"
#include "lxp/lxp_fs_ops.h"
#include "lxp/lxp_net_ops.h"

#if LXP_ENABLE_NET
extern const lxp_net_ops_t *g_lxp_net_ops;
#endif
#if LXP_ENABLE_DEV
extern const lxp_display_ops_t *g_lxp_disp_ops;
#endif
#if LXP_ENABLE_FS
extern const lxp_fs_ops_t *g_lxp_fs_ops;
#endif
#if LXP_ENABLE_BLOCK
extern const lxp_block_ops_t *g_lxp_block_ops;
#endif

void lxp_providers_publish(const lxp_net_ops_t *net_ops, const lxp_display_ops_t *disp_ops,
			   const lxp_fs_ops_t *fs_ops, const lxp_block_ops_t *block_ops);
void lxp_providers_clear(void);

#endif /* LXP_PROVIDER_H */
