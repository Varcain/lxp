/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * eventfd objects (FD_EVENTFD): a 64-bit counter fd used to wake a poller from
 * another thread — curl's threaded resolver (AsynchDNS) writes it when a name
 * resolves.
 */
#ifndef LXP_FS_EVENTFD_H
#define LXP_FS_EVENTFD_H

#include "proc/lxp_proc.h"

/* eventfd2(2): claim a counter and install a descriptor for it. Returns the fd,
 * or -EMFILE when the counter pool or the descriptor table is full. */
long lxp_eventfd_open(lxp_proc_t *p, unsigned initval, int flags);
/* Free every counter (run teardown: no descriptor survives it). */
void lxp_eventfd_runtime_reset(void);

#endif /* LXP_FS_EVENTFD_H */
