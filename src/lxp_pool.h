/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Refcounted open-pool primitives, shared by the three backend open pools (dev
 * g_lnx_devopen, net g_sock, netfs g_open). Each pool slot begins with {uint8_t used;
 * uint8_t refs;}; dup/fork share a slot (refs++), close drops a ref and the LAST drop
 * releases the backing object (the release action — ops->release / socket close / 9P
 * clunk — differs per pool, so it stays in the caller). Header-only static inline: the
 * caller keeps its own slot struct; these operate on its used/refs bytes + fd table.
 */
#ifndef LXP_POOL_H
#define LXP_POOL_H

#include <stdint.h>

#include "lxp/lxp_syscall.h" /* lxp_proc_t, LXP_MAX_FDS, LXP_FD_* */

/* dup/fork: take another reference on a slot (saturating at 0xff). */
static inline void lxp_pool_get(uint8_t *refs)
{
	if (*refs < 0xff)
		(*refs)++;
}

/* close: drop a reference. Returns 1 when this was the LAST reference — the caller must
 * then release the backing object and clear the slot's `used` — else 0 (still live). */
static inline int lxp_pool_put(uint8_t *refs)
{
	if (*refs > 1) {
		(*refs)--;
		return 0;
	}
	return 1;
}

/* fork: a child inherits its parent's fds, so every slot the child now holds gains a
 * reference. Scans the child's fd table for @p kind and @p get()s each held slot. */
static inline void lxp_pool_fork_inherit(lxp_proc_t *child, uint8_t kind, void (*get)(int))
{
	for (int fd = 0; fd < LXP_MAX_FDS; fd++)
		if (child->fds[fd].kind == kind)
			get(child->fds[fd].file_idx);
}

#endif /* LXP_POOL_H */
