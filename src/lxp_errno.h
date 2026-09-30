/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The one table that decides which Linux errno a guest sees for a provider's lxp_err_t
 * result (src/lxp_errno.c).
 */
#ifndef LXP_ERRNO_H
#define LXP_ERRNO_H

/* The syscall result for provider result @p err: 0 for success and for end of file (a
 * zero-byte transfer), otherwise a negated Linux errno, -EIO for a code with no closer
 * meaning. */
long lxp_errno_from_err(int err);

/* The same for socket operations. Their providers report a non-blocking operation that
 * cannot complete yet as LXP_ERR_TIMEOUT, which reads as -EAGAIN, not -ETIMEDOUT. */
long lxp_net_errno_from_err(int err);

#endif /* LXP_ERRNO_H */
