/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Privileged access to Linux-personality guest memory.
 */
#ifndef LXP_GUEST_H
#define LXP_GUEST_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_syscall.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum lxp_guest_access {
	LXP_GUEST_READ = 1u,
	LXP_GUEST_WRITE = 2u,
	LXP_GUEST_READ_WRITE = LXP_GUEST_READ | LXP_GUEST_WRITE,
} lxp_guest_access_t;

/*
 * A view is a dispatch-local capability. It captures both the slot and address
 * space generations and is installed on exactly one lxp_proc_t until end().
 * Ordinary copy helpers revalidate the captured address space before touching
 * guest memory, so an exec/recycle cannot turn an old pointer into authority
 * over a new image.
 */
typedef struct lxp_guest_view {
	lxp_proc_t *proc;
	lxp_mm_t *mm;
	lxp_slot_ref_t slot;
	lxp_region_ref_t region;
	const uint32_t *slot_generation;
	uint8_t access;
	uint8_t active;
	uint16_t _pad;
} lxp_guest_view_t;

/** Pure range/permission validation; performs no mapping or cache operation. */
int lxp_guest_range_ok(const lxp_mm_t *mm, uintptr_t address, size_t length,
		       lxp_guest_access_t access);
/** Compatibility-shaped range validation: @p write is zero for read, nonzero for write. */
int lxp_guest_access_ok(const lxp_proc_t *proc, const void *address, size_t length, int write);

/** Bind one already-mapped SVC/coordinator dispatch to @p proc. */
int lxp_guest_view_begin(lxp_proc_t *proc, lxp_slot_ref_t slot, const uint32_t *slot_generation,
			 lxp_guest_access_t access, lxp_guest_view_t *view);

/** Revalidate the captured address-space generation and active binding. */
int lxp_guest_view_is_current(const lxp_guest_view_t *view);

/** Return the generation-bearing slot identity bound to @p proc's active view. */
int lxp_guest_view_slot(const lxp_proc_t *proc, lxp_slot_ref_t *slot);

/** Revoke a dispatch view. Safe to call more than once. */
void lxp_guest_view_end(lxp_guest_view_t *view);

/** Common privileged copy/scalar/string boundary. Return 0 or -LXP_EFAULT. */
int lxp_copy_from_guest(const lxp_proc_t *proc, void *dst, uintptr_t src, size_t length);
int lxp_copy_to_guest(const lxp_proc_t *proc, uintptr_t dst, const void *src, size_t length);
int lxp_guest_get_u32(const lxp_proc_t *proc, uintptr_t src, uint32_t *value);
int lxp_guest_put_u32(const lxp_proc_t *proc, uintptr_t dst, uint32_t value);
long lxp_guest_strnlen(const lxp_proc_t *proc, const char *src, size_t max);
int lxp_copy_string_from_guest(const lxp_proc_t *proc, char *dst, size_t capacity, uintptr_t src,
			       size_t *length);

#ifdef __cplusplus
}
#endif

#endif /* LXP_GUEST_H */
