/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_FD_PRIVATE_H
#define LXP_FD_PRIVATE_H

#include "lxp/lxp_proc.h"

/*
 * Retain every open-file description referenced by proc->files. Validation is
 * transactional: failure leaves all reference counts unchanged.
 */
int lxp_fd_table_retain(lxp_proc_t *proc);

#endif /* LXP_FD_PRIVATE_H */
