/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Generation-qualified identities shared by the process core, guest-memory
 * boundary, and RTOS seams. This header deliberately contains no process state.
 */

#ifndef LXP_IDENTITY_H
#define LXP_IDENTITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Generation-bearing identity for a process slot. Delayed producers retain
 * and revalidate the complete reference before publishing. */
typedef struct lxp_slot_ref {
	int16_t index;
	uint16_t _pad;
	uint32_t generation;
} lxp_slot_ref_t;

/** Generation-bearing identity for one reserved program region. */
typedef struct lxp_region_ref {
	int16_t index;
	uint16_t _pad;
	uint32_t generation;
} lxp_region_ref_t;

static inline lxp_slot_ref_t lxp_slot_ref_none(void)
{
	return (lxp_slot_ref_t){.index = -1};
}

static inline lxp_region_ref_t lxp_region_ref_none(void)
{
	return (lxp_region_ref_t){.index = -1};
}

static inline int lxp_slot_ref_equal(lxp_slot_ref_t a, lxp_slot_ref_t b)
{
	return a.index == b.index && a.generation == b.generation;
}

static inline int lxp_region_ref_equal(lxp_region_ref_t a, lxp_region_ref_t b)
{
	return a.index == b.index && a.generation == b.generation;
}

#ifdef __cplusplus
}
#endif

#endif /* LXP_IDENTITY_H */
