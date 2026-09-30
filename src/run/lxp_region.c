/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Program regions: their generation-qualified leases and references, and the vfork
 * snapshots that keep a NOMMU parent's writable data intact while its child shares it.
 *
 * A region may be reused as vfork snapshot scratch (which then becomes the child's exec
 * image) or as a fresh exec region only after its generated capability reaches zero
 * references. A temporary lease also keeps prepared but unpublished state unavailable.
 * The live-mm scan is deliberate fail-closed redundancy: corrupted accounting causes
 * -ENOMEM rather than copying over a live daemon's libc state.
 */
#include <string.h>

#include "lxp_internal.h"
#include "lxp_run_internal.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_runtime_store.h"

lxp_arena_t *lxp_region_arena(int region)
{
	return region >= 0 && region < LXP_NREG ? &g_lxp_rt.arenas[region] : NULL;
}

unsigned lxp_region_live_users(int r)
{
	unsigned users = 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (g_lxp_rt.slots[s].proc.alive && g_lxp_rt.slots[s].proc.mm &&
		    g_lxp_rt.slots[s].proc.mm->region.index == r)
			users++;
	return users;
}

int region_free(int r)
{
	if (r < 0 || r >= LXP_NREG || g_lxp_rt.regions[r].lease_owner.index >= 0 ||
	    g_lxp_rt.regions[r].refs != 0)
		return 0;
	return lxp_region_live_users(r) == 0; /* live use despite zero refs — do not trample it */
}

static uint32_t region_generation_next(int r)
{
	uint32_t next = ++g_lxp_rt.regions[r].generation;
	if (next == 0) /* reserve zero for never-assigned test/startup state */
		next = ++g_lxp_rt.regions[r].generation;
	return next;
}

lxp_region_ref_t region_ref_at(int r)
{
	return (r >= 0 && r < LXP_NREG && g_lxp_rt.regions[r].refs != 0)
		       ? (lxp_region_ref_t){
				 .index = (int16_t)r,
				 .generation = g_lxp_rt.regions[r].generation,
			 }
		       : lxp_region_ref_none();
}

lxp_region_ref_t region_reserve(int r, lxp_slot_ref_t owner)
{
	if (r < 0 || r >= LXP_NREG || owner.index < 0 || owner.index >= LXP_NSLOT ||
	    owner.generation == 0 || !lxp_slot_ref_equal(owner, slot_ref_at(owner.index)) ||
	    g_lxp_rt.regions[r].refs != 0)
		return lxp_region_ref_none();
	g_lxp_rt.regions[r].lease_owner = owner;
	g_lxp_rt.regions[r].refs = 1;
	return (lxp_region_ref_t){
		.index = (int16_t)r,
		.generation = region_generation_next(r),
	};
}

/* Transfer an unpublished reservation to the address space that now carries
 * the same region capability. From this point onward the mm reference, not an
 * arbitrary task slot, is the ownership authority. */
int lxp_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t lease_owner)
{
	int r = ref.index;
	if (r < 0 || r >= LXP_NREG || ref.generation == 0 ||
	    g_lxp_rt.regions[r].generation != ref.generation || g_lxp_rt.regions[r].refs == 0 ||
	    !lxp_slot_ref_equal(g_lxp_rt.regions[r].lease_owner, lease_owner))
		return -1;
	g_lxp_rt.regions[r].lease_owner = lxp_slot_ref_none();
	return 0;
}

int region_get(lxp_region_ref_t ref)
{
	int r = ref.index;
	if (r < 0 || r >= LXP_NREG || ref.generation == 0 ||
	    g_lxp_rt.regions[r].generation != ref.generation ||
	    g_lxp_rt.regions[r].lease_owner.index >= 0 || g_lxp_rt.regions[r].refs == 0 ||
	    g_lxp_rt.regions[r].refs >= LXP_NSLOT)
		return -1;
	g_lxp_rt.regions[r].refs++;
	return 0;
}

int region_put(lxp_region_ref_t ref)
{
	int r = ref.index;
	if (r < 0 || r >= LXP_NREG || ref.generation == 0 ||
	    g_lxp_rt.regions[r].generation != ref.generation || g_lxp_rt.regions[r].refs == 0)
		return -1;
	if (--g_lxp_rt.regions[r].refs == 0) {
		g_lxp_rt.regions[r].lease_owner = lxp_slot_ref_none();
		(void)region_generation_next(r);
	}
	return 0;
}

void proc_mm_put(lxp_proc_t *p)
{
	if (!p || !p->mm)
		return;
	(void)region_put(p->mm->region);
	lxp_proc_mm_put(p);
}

int region_release_if_owned(lxp_region_ref_t region, lxp_slot_ref_t owner)
{
	int r = region.index;
	if (r < 0 || r >= LXP_NREG || !lxp_slot_ref_equal(g_lxp_rt.regions[r].lease_owner, owner) ||
	    g_lxp_rt.regions[r].refs != 1 || g_lxp_rt.regions[r].generation != region.generation)
		return -1;
	return region_put(region);
}

int lxp_region_lease_matches(lxp_region_ref_t region, lxp_slot_ref_t owner, unsigned refs)
{
	return region.index >= 0 && region.index < LXP_NREG && region.generation != 0 &&
	       g_lxp_rt.regions[region.index].generation == region.generation &&
	       g_lxp_rt.regions[region.index].refs == refs &&
	       lxp_slot_ref_equal(g_lxp_rt.regions[region.index].lease_owner, owner);
}

int lxp_region_lease_reassign(lxp_region_ref_t region, lxp_slot_ref_t old_owner,
			      lxp_slot_ref_t new_owner)
{
	if (!lxp_region_lease_matches(region, old_owner, 1))
		return -LXP_EINVAL;
	g_lxp_rt.regions[region.index].lease_owner = new_owner;
	return LXP_OK;
}

/* Clear a slot's generation-qualified snapshot guard (before the slot is reused, or once
 * its snapshot is restored or contained). */
void lxp_vfork_guard_reset(int slot)
{
	struct vfork_snapshot_guard *guard = &g_lxp_rt.vfork_guard[slot];
	memset(guard, 0, sizeof(*guard));
	guard->parent = lxp_slot_ref_none();
	guard->parent_region = lxp_region_ref_none();
	guard->snapshot = lxp_region_ref_none();
}

void lxp_region_runtime_reset(void)
{
	for (int r = 0; r < LXP_NREG; r++) {
		g_lxp_rt.regions[r].refs = 0;
		g_lxp_rt.regions[r].lease_owner = lxp_slot_ref_none();
	}
	for (int s = 0; s < LXP_NSLOT; s++)
		lxp_vfork_guard_reset(s);
}

/* Copy into storage that may retain cache lines from an earlier tenant. The
 * explicit pre-invalidate prevents a later clean from writing that tenant back
 * over an uncached copy; the final clean publishes cacheable coordinator writes. */
static void snapshot_copy_span(void *dst, const void *src, size_t len)
{
	lxp_cache_clean(src, len);
	lxp_cache_invalidate(dst, len);
	memcpy(dst, src, len);
	lxp_cache_clean(dst, len);
}

/* Restore into a region that the vfork child has modified. Preserve the copy
 * across both cacheable and uncached coordinator MPU views, then discard the
 * coordinator's view so the resumed parent refills the restored bytes. */
static void restore_copy_span(void *dst, const void *src, size_t len)
{
	lxp_cache_invalidate(dst, len);
	memcpy(dst, src, len);
	lxp_cache_clean(dst, len);
	lxp_cache_invalidate(dst, len);
}

/* NOMMU has no copy-on-write, so a vfork child SHARES the parent's region + dyn_pool. Correct
 * vfork usage restricts the child to exec/_exit, but real programs write shared data before exec
 * (e.g. dropbear's session child resets SIGCHLD to SIG_DFL, which uClibc-LinuxThreads records in a
 * table in the shared libc data) — corrupting the suspended parent. So we snapshot the parent's
 * writable data into a SPARE region at fork and restore it before the parent resumes. Storage is
 * free: the spare region's own region+dyn_pool exactly mirror the parent's (both LXP_PROG_*), and
 * the child needs that region for its eventual exec anyway. The writable image data [region,
 * stack_lo), active stack [captured_sp, region_hi), and dyn_pool are copied; g_lxp_rt.arenas[]
 * allocator metadata is saved separately. Copying only the active stack bounds the work to live
 * state rather than the full reserved stack, while preserving NOMMU shell re-exec paths that
 * modify vfork caller frames. Returns the reserved scratch-region capability, or an invalid
 * reference if the parent cannot be isolated. */
lxp_region_ref_t vfork_snapshot(lxp_proc_t *par, lxp_slot_ref_t child, uintptr_t sp)
{
	int parent_slot = slot_of(par);
	if (parent_slot < 0 || child.index < 0 || child.index >= LXP_NSLOT ||
	    child.generation == 0 || !par->alive || !par->mm || par->mm->region.index < 0 ||
	    par->mm->region.index >= LXP_NREG)
		return lxp_region_ref_none();
	int rsnap = -1;
	for (int r = 0; r < LXP_NREG; r++)
		if (region_free(r)) {
			rsnap = r;
			break;
		}
	if (rsnap < 0)
		return lxp_region_ref_none();
	uint8_t *pr = g_lxp_os_ops->region(par->mm->region.index);
	size_t dlen = par->stack_lo - (uintptr_t)pr; /* in-region writable data, below the stack */
	uint8_t *sr = g_lxp_os_ops->region(rsnap);
	if (sp < par->stack_lo || sp > par->mm->region_hi)
		return lxp_region_ref_none();
	lxp_region_ref_t snapshot = region_reserve(rsnap, child);
	if (snapshot.index < 0)
		return snapshot;
	snapshot_copy_span(sr, pr, dlen);
	size_t slen = par->mm->region_hi - sp;
	snapshot_copy_span(sr + (sp - (uintptr_t)pr), (const void *)sp, slen);
	if (par->mm->is_dynamic && g_lxp_os_ops->dyn_pool) {
		size_t ds = 0;
		uint8_t *pdp = g_lxp_os_ops->dyn_pool(par->mm->region.index, &ds);
		uint8_t *sdp = g_lxp_os_ops->dyn_pool(rsnap, NULL);
		snapshot_copy_span(sdp, pdp, ds);
	}
	g_lxp_rt.arenas[rsnap] =
		g_lxp_rt.arenas[par->mm->region.index]; /* allocator metadata (coordinator memory) */
	struct vfork_snapshot_guard *guard = &g_lxp_rt.vfork_guard[child.index];
	guard->parent = slot_ref_at(parent_slot);
	guard->parent_region = par->mm->region;
	guard->snapshot = snapshot;
	return snapshot;
}

/* Undo a vfork child's writes to the shared region before the parent resumes: copy the snapshot
 * back over the parent's region + dyn_pool and restore its arena metadata. Every identity is
 * checked before the first write; failure leaves memory untouched so the caller can contain both
 * processes. */
int vfork_restore(lxp_proc_t *par, lxp_region_ref_t snapshot, lxp_slot_ref_t child, uintptr_t sp)
{
	if (!lxp_slot_ref_is_current(child))
		return -1;
	struct vfork_snapshot_guard *guard = &g_lxp_rt.vfork_guard[child.index];
	int parent_slot = slot_of(par);
	int rsnap = snapshot.index;
	if (parent_slot < 0 || !par->alive || !par->mm ||
	    !lxp_slot_ref_equal(slot_ref_at(parent_slot), guard->parent) ||
	    !lxp_region_ref_equal(par->mm->region, guard->parent_region) ||
	    !lxp_region_ref_equal(snapshot, guard->snapshot) || rsnap < 0 || rsnap >= LXP_NREG ||
	    !lxp_slot_ref_equal(g_lxp_rt.regions[rsnap].lease_owner, child) ||
	    g_lxp_rt.regions[rsnap].refs != 1 ||
	    g_lxp_rt.regions[rsnap].generation != snapshot.generation)
		return -1;
	uint8_t *pr = g_lxp_os_ops->region(par->mm->region.index);
	size_t dlen = par->stack_lo - (uintptr_t)pr;
	uint8_t *sr = g_lxp_os_ops->region(rsnap);
	restore_copy_span(pr, sr, dlen);
	if (sp >= par->stack_lo && sp <= par->mm->region_hi) {
		size_t slen = par->mm->region_hi - sp;
		restore_copy_span((void *)sp, sr + (sp - (uintptr_t)pr), slen);
	}
	if (par->mm->is_dynamic && g_lxp_os_ops->dyn_pool) {
		size_t ds = 0;
		uint8_t *pdp = g_lxp_os_ops->dyn_pool(par->mm->region.index, &ds);
		restore_copy_span(pdp, g_lxp_os_ops->dyn_pool(rsnap, NULL), ds);
	}
	g_lxp_rt.arenas[par->mm->region.index] = g_lxp_rt.arenas[rsnap];
	lxp_vfork_guard_reset(child.index);
	return 0;
}

static int vfork_parent_is_current(lxp_slot_ref_t child)
{
	if (!lxp_slot_ref_is_current(child))
		return 0;
	const struct vfork_snapshot_guard *guard = &g_lxp_rt.vfork_guard[child.index];
	int ps = guard->parent.index;
	return lxp_slot_ref_is_current(guard->parent) && g_lxp_rt.slots[ps].proc.mm &&
	       lxp_region_ref_equal(g_lxp_rt.slots[ps].proc.mm->region, guard->parent_region);
}

/* A stale snapshot is an internal ownership violation, not a recoverable guest
 * error. Never copy it. Terminate a still-current suspended parent (its shared
 * image may already be dirty), fail the child, and release only a reservation
 * that is still demonstrably ours. */
void vfork_contain_stale(lxp_slot_ref_t child_ref, lxp_proc_t *child)
{
	struct vfork_snapshot_guard *guard = &g_lxp_rt.vfork_guard[child_ref.index];
	if (vfork_parent_is_current(child_ref)) {
		coordinator_exit_slot(guard->parent.index, 0, 127, LXP_EXIT_REASON_STATE_CORRUPTION,
				      0);
	}
	if (guard->snapshot.index >= 0)
		(void)region_release_if_owned(guard->snapshot, child_ref);
	lxp_vfork_guard_reset(child_ref.index);
	child->vfork_parent = lxp_slot_ref_none();
	child->snapshot = lxp_region_ref_none();
	if (child->intent.kind == LXP_INTENT_EXEC)
		(void)lxp_intent_complete(child, LXP_INTENT_EXEC);
	coordinator_exit_slot(child_ref.index, 0, 127, LXP_EXIT_REASON_STATE_CORRUPTION, 0);
}
