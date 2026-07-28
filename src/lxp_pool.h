/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Refcounted open-pool primitive shared by the backend open pools. Descriptor
 * aliases are owned by the generic open-file-description layer, so these refs
 * count only distinct descriptions.
 */
#ifndef LXP_POOL_H
#define LXP_POOL_H

#include <stdint.h>

#include "lxp/lxp_proc.h" /* lxp_proc_t, LXP_MAX_FDS, LXP_FD_* */

/* close: drop a reference. Returns 1 when this was the LAST reference — the caller must
 * then release the backing object and clear the slot's `used` — else 0 (still live). */
static inline int lxp_pool_put(uint16_t *refs)
{
	if (*refs > 1) {
		(*refs)--;
		return 0;
	}
	return 1;
}

#endif /* LXP_POOL_H */
