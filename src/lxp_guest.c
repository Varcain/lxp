/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <string.h>

#include "lxp/lxp_guest.h"
#include "lxp/lxp_proc.h"

/* Supplied by the run loop. The host-only syscall tests intentionally have no
 * shared executable window. */
__attribute__((weak)) void lxp_rootfs_bounds(uintptr_t *lo, uintptr_t *hi)
{
	*lo = 0;
	*hi = 0;
}

static uintptr_t guest_range_hi(const lxp_mm_t *mm, uintptr_t address, lxp_guest_access_t access)
{
	if (!mm)
		return 0;
	if (address >= mm->region_lo && address < mm->region_hi)
		return mm->region_hi;
	if (mm->pool_hi > mm->pool_lo && address >= mm->pool_lo && address < mm->pool_hi)
		return mm->pool_hi;
#if LXP_ENABLE_DEV
	for (int i = 0; i < 2; i++)
		if (mm->dev_map_hi[i] > mm->dev_map_lo[i] && address >= mm->dev_map_lo[i] &&
		    address < mm->dev_map_hi[i])
			return mm->dev_map_hi[i];
#endif
	if (!(access & LXP_GUEST_WRITE)) {
		uintptr_t lo;
		uintptr_t hi;
		lxp_rootfs_bounds(&lo, &hi);
		if (hi > lo && address >= lo && address < hi)
			return hi;
	}
	return 0;
}

int lxp_guest_range_ok(const lxp_mm_t *mm, uintptr_t address, size_t length,
		       lxp_guest_access_t access)
{
	if ((access & ~LXP_GUEST_READ_WRITE) != 0u || access == 0)
		return 0;
	if (length == 0)
		return 1;
	uintptr_t end = address + length;
	if (end < address)
		return 0;
	uintptr_t hi = guest_range_hi(mm, address, access);
	return hi != 0 && end <= hi;
}

int lxp_guest_view_begin(lxp_proc_t *proc, lxp_slot_ref_t slot, const uint32_t *slot_generation,
			 lxp_guest_access_t access, lxp_guest_view_t *view)
{
	if (!proc || !proc->mm || !view || !slot_generation || proc->guest_view ||
	    (access & ~LXP_GUEST_READ_WRITE) != 0u || access == 0)
		return -LXP_EINVAL;
	if (__atomic_load_n(slot_generation, __ATOMIC_RELAXED) != slot.generation)
		return -LXP_ESRCH;
	lxp_region_ref_t region = proc->mm->region;
	if (region.index < 0 || region.generation == 0 || slot.index < 0 || slot.generation == 0)
		return -LXP_EFAULT;
	view->proc = proc;
	view->mm = proc->mm;
	view->slot = slot;
	view->region = region;
	view->slot_generation = slot_generation;
	view->access = (uint8_t)access;
	view->_pad = 0;
	view->active = 1;
	proc->guest_view = view;
	return LXP_OK;
}

int lxp_guest_view_is_current(const lxp_guest_view_t *view)
{
	return view && view->active && view->proc && view->proc->guest_view == view &&
	       view->slot_generation &&
	       __atomic_load_n(view->slot_generation, __ATOMIC_RELAXED) == view->slot.generation &&
	       view->proc->mm == view->mm && view->mm &&
	       lxp_region_ref_equal(view->mm->region, view->region);
}

int lxp_guest_view_slot(const lxp_proc_t *proc, lxp_slot_ref_t *slot)
{
	if (!proc || !slot || !lxp_guest_view_is_current(proc->guest_view))
		return -LXP_ESRCH;
	*slot = proc->guest_view->slot;
	return LXP_OK;
}

void lxp_guest_view_end(lxp_guest_view_t *view)
{
	if (!view || !view->active)
		return;
	/*
	 * active is the capability revocation point. The remaining fields are
	 * inert afterwards, so clearing the whole dispatch-local record only adds
	 * a memset to every SVC and coordinator dispatch.
	 */
	view->active = 0;
	if (view->proc && view->proc->guest_view == view)
		view->proc->guest_view = NULL;
	view->proc = NULL;
	view->mm = NULL;
	view->slot_generation = NULL;
}

int lxp_guest_access_ok(const lxp_proc_t *proc, const void *pointer, size_t length, int write)
{
	lxp_guest_access_t access = write ? LXP_GUEST_WRITE : LXP_GUEST_READ;
	uintptr_t address = (uintptr_t)pointer;
	if (!proc || !proc->mm)
		return 0;
	/*
	 * Host subsystem tests may exercise a handler directly. Production SVC and
	 * coordinator entry points always install a view; when present it is
	 * mandatory and narrows the access granted to this dispatch.
	 */
	if (proc->guest_view && (!lxp_guest_view_is_current(proc->guest_view) ||
				 (proc->guest_view->access & access) != access))
		return 0;
	return lxp_guest_range_ok(proc->mm, address, length, access);
}

int lxp_copy_from_guest(const lxp_proc_t *proc, void *dst, uintptr_t src, size_t length)
{
	if ((!dst && length != 0) || !lxp_guest_access_ok(proc, (const void *)src, length, 0))
		return -LXP_EFAULT;
	if (length)
		memcpy(dst, (const void *)src, length);
	return 0;
}

int lxp_copy_to_guest(const lxp_proc_t *proc, uintptr_t dst, const void *src, size_t length)
{
	if ((!src && length != 0) || !lxp_guest_access_ok(proc, (const void *)dst, length, 1))
		return -LXP_EFAULT;
	if (length)
		memcpy((void *)dst, src, length);
	return 0;
}

int lxp_guest_get_u32(const lxp_proc_t *proc, uintptr_t src, uint32_t *value)
{
	return lxp_copy_from_guest(proc, value, src, sizeof(*value));
}

int lxp_guest_put_u32(const lxp_proc_t *proc, uintptr_t dst, uint32_t value)
{
	return lxp_copy_to_guest(proc, dst, &value, sizeof(value));
}

long lxp_guest_strnlen(const lxp_proc_t *proc, const char *string, size_t max)
{
	uintptr_t src = (uintptr_t)string;
	if (!proc || !proc->mm)
		return -LXP_EFAULT;
	if (proc->guest_view && (!lxp_guest_view_is_current(proc->guest_view) ||
				 (proc->guest_view->access & LXP_GUEST_READ) == 0))
		return -LXP_EFAULT;
	uintptr_t hi = guest_range_hi(proc->mm, src, LXP_GUEST_READ);
	if (!hi)
		return -LXP_EFAULT;
	size_t available = (size_t)(hi - src);
	size_t limit = available < max ? available : max;
	for (size_t i = 0; i < limit; i++)
		if (string[i] == '\0')
			return (long)i;
	return -LXP_EFAULT;
}

int lxp_copy_string_from_guest(const lxp_proc_t *proc, char *dst, size_t capacity, uintptr_t src,
			       size_t *length)
{
	if (!dst || capacity == 0)
		return -LXP_E2BIG;
	for (size_t i = 0; i < capacity; i++) {
		unsigned char byte;
		int rc = lxp_copy_from_guest(proc, &byte, src + i, 1);
		if (rc != 0)
			return rc;
		dst[i] = (char)byte;
		if (byte == 0) {
			if (length)
				*length = i;
			return 0;
		}
	}
	return -LXP_E2BIG;
}
