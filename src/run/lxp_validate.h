/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Validation of what a host hands lxp_run() (src/run/lxp_validate.c). Each returns 1 when
 * the table or configuration is usable by this build, else 0. A table for a feature the
 * build leaves out is not inspected.
 */
#ifndef LXP_RUN_VALIDATE_H
#define LXP_RUN_VALIDATE_H

#include "lxp/lxp_block_ops.h"
#include "lxp/lxp_display_ops.h"
#include "lxp/lxp_fs_ops.h"
#include "lxp/lxp_net_ops.h"
#include "lxp/lxp_run.h"
#include "lxp/lxp_seam.h"

int lxp_os_ops_valid(const lxp_os_ops_t *ops);
int lxp_net_ops_valid(const lxp_net_ops_t *ops);
int lxp_display_ops_valid(const lxp_display_ops_t *ops);
int lxp_fs_ops_valid(const lxp_fs_ops_t *ops);
int lxp_block_ops_valid(const lxp_block_ops_t *ops);
int lxp_run_config_valid(const lxp_run_config_t *cfg);

#endif /* LXP_RUN_VALIDATE_H */
