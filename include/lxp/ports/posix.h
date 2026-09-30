/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Public entry points supplied by the optional POSIX reference port
 * (ports/posix): a network provider over host sockets and a synthetic netif.
 */
#ifndef LXP_PORTS_POSIX_H
#define LXP_PORTS_POSIX_H

#include "lxp/lxp_net_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Return the immutable network provider implemented over POSIX sockets. */
const lxp_net_ops_t *lxp_posix_net_ops(void);

/** Return the synthetic eth0 the SIOC* ioctls act on: 127.0.0.1/8, up, with a fixed
 *  MAC. Pass it as a run configuration's netif. */
lxp_netif_t lxp_posix_netif(void);

#ifdef __cplusplus
}
#endif

#endif /* LXP_PORTS_POSIX_H */
