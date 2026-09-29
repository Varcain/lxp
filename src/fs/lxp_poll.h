/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * poll(2), ppoll(2) and pselect6(2) over any descriptor kind (src/fs/lxp_poll.c).
 */
#ifndef LXP_FS_POLL_H
#define LXP_FS_POLL_H

#include <stdint.h>

#include "proc/lxp_proc.h"

/* poll (@p nr LXP_NR_poll: @p a2 = timeout ms) or ppoll (@p a2 = struct timespec *,
 * NULL = block) over the pollfd array @p a0 of @p a1 entries. Returns the ready
 * count, 0 at the timeout, a negated errno, or 0 after parking in LXP_WAIT_POLL. */
long lxp_sys_poll(lxp_proc_t *p, long nr, long a0, long a1, long a2);

/* pselect6 over one fd_set word (fds below 32); the signal mask is not applied. */
long lxp_sys_pselect6(lxp_proc_t *p, int nfds, uintptr_t urfds, uintptr_t uwfds, uintptr_t uefds,
		      uintptr_t utimeout);

/* Re-scan a task parked in LXP_WAIT_POLL (coordinator): the ready count, 0 at the
 * deadline, or -EAGAIN while nothing is ready. */
long lxp_poll_retry(lxp_proc_t *p);

#endif /* LXP_FS_POLL_H */
