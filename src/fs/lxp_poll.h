/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * poll(2), ppoll(2) and pselect6(2) over any descriptor kind (src/fs/lxp_poll.c); the
 * syscall handlers are declared in sys/lxp_sys.h.
 */
#ifndef LXP_FS_POLL_H
#define LXP_FS_POLL_H

#include <stdint.h>

#include "proc/lxp_proc.h"

/* Re-scan a task parked in LXP_WAIT_POLL (coordinator): the ready count, 0 at the
 * deadline, or -EAGAIN while nothing is ready. */
long lxp_poll_retry(lxp_proc_t *p);

#endif /* LXP_FS_POLL_H */
