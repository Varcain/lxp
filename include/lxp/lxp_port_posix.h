/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Public entry points supplied by the optional POSIX reference port.
 */
#ifndef LXP_PORT_POSIX_H
#define LXP_PORT_POSIX_H

#include "lxp/lxp_net_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Return the immutable network provider implemented over POSIX sockets. */
const lxp_net_ops_t *lxp_posix_net_ops(void);

#ifdef __cplusplus
}
#endif

#endif /* LXP_PORT_POSIX_H */
