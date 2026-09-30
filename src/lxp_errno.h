/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The one table that decides which Linux errno a guest sees for a provider's lxp_err_t
 * result, and its inverse for the few errno results a host sees (src/lxp_errno.c).
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

/* The lxp_err_t that reports negated Linux errno @p err to a host: the code that
 * lxp_errno_from_err() maps back to @p err, LXP_ERR_INVALID_PARAM for -E2BIG,
 * LXP_ERR_NOT_SUPPORTED for -ENOEXEC and -ENOSYS, LXP_ERR_PERMISSION for -EPERM, and
 * LXP_ERR_IO for any other. */
int lxp_err_from_errno(long err);

#endif /* LXP_ERRNO_H */
