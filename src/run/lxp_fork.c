/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator fork/clone/vfork handler.
 */

#include <string.h>

#include "lxp_run_internal.h"
#include "run/lxp_fork_private.h"

/*
 * Fork construction owns one region reference plus the not-yet-published child
 * objects, native map, child accounting, and optional vfork snapshot. No
 * acquisition escapes until fork_txn_commit(); abort is deliberately
 * idempotent so every failed phase converges on the same cleanup.
 */
LXP_FORK_TXN_LINKAGE int fork_txn_prepare(struct fork_txn *tx, const lxp_os_ops_t *eng,
					  int parent_slot, int child_slot,
					  uint32_t clone_flags, int child_pid)
{
	memset(tx, 0, sizeof(*tx));
	tx->phase = FORK_TXN_PREPARING;
	tx->parent = lxp_slot_proc(parent_slot);
	tx->child = lxp_slot_proc(child_slot);
	tx->parent_ref = slot_ref_at(parent_slot);

	deferred_slot_reassign(child_slot);
	tx->child_ref = slot_ref_at(child_slot);
	tx->parent_region = tx->parent->mm->region;
	lxp_vfork_guard_reset(child_slot);
	if (region_get(tx->parent_region) != 0)
		return -LXP_EAGAIN;
	tx->region_acquired = 1;
	if (lifecycle_failpoint(LXP_FAIL_FORK_REGION_ACQUIRED))
		return -LXP_ENOMEM;

	int rc;
	if (clone_flags & LXP_CLONE_THREAD)
		rc = lxp_proc_init_thread_child(tx->child, tx->parent, clone_flags, child_pid);
	else
		rc = lxp_proc_init_process_child(tx->child, tx->parent, clone_flags, child_pid);
	if (rc != LXP_OK)
		return -LXP_EAGAIN;
	tx->child_constructed = 1;
	if (lifecycle_failpoint(LXP_FAIL_FORK_CHILD_PREPARED))
		return -LXP_ENOMEM;

	/* Every slot owns its cold exec capture and active signal return chain even
	 * when its process-wide objects are shared. */
	lxp_proc_bind_exec_capture(tx->child, eng->exec_capture(tx->child_ref.index));
	lxp_slot_signal_clone(tx->child_ref.index, tx->parent_ref.index);

	/* Hardware mappings are installed while the record is still unpublished.
	 * A later failure clears them through the same transaction abort. */
	tx->maps_touched = 1;
	if (coordinator_restore_mm_maps(eng, tx->child_ref.index, tx->child->mm) != 0)
		return -LXP_ENOMEM;
	if (lifecycle_failpoint(LXP_FAIL_FORK_MAPS_PREPARED))
		return -LXP_ENOMEM;
	tx->phase = FORK_TXN_PREPARED;
	return LXP_OK;
}

LXP_FORK_TXN_LINKAGE int fork_txn_count_child(struct fork_txn *tx)
{
	if (tx->phase != FORK_TXN_PREPARED || tx->child_counted)
		return -LXP_EINVAL;
	tx->parent->group->live_children++;
	tx->child_counted = 1;
	return lifecycle_failpoint(LXP_FAIL_FORK_CHILD_COUNTED) ? -LXP_ENOMEM : LXP_OK;
}

LXP_FORK_TXN_LINKAGE int fork_txn_snapshot(struct fork_txn *tx, const lxp_os_ops_t *eng,
					   uintptr_t parent_sp)
{
	if (tx->phase != FORK_TXN_PREPARED || !tx->child_constructed)
		return -LXP_EINVAL;
	tx->child->snapshot = vfork_snapshot(eng, tx->parent, tx->child_ref, parent_sp);
	if (tx->child->snapshot.index < 0)
		return -LXP_ENOMEM;
	return lifecycle_failpoint(LXP_FAIL_FORK_SNAPSHOT_ACQUIRED) ? -LXP_ENOMEM : LXP_OK;
}

static int fork_txn_validate(const struct fork_txn *tx)
{
	if (!tx || tx->phase != FORK_TXN_PREPARED || !tx->region_acquired ||
	    !tx->child_constructed || tx->child->alive || !tx->child->mm ||
	    !tx->child->files || !tx->child->fs_context || !tx->child->sighand ||
	    !tx->child->group || !lxp_slot_ref_is_current(tx->parent_ref) ||
	    !lxp_region_ref_equal(tx->child->mm->region, tx->parent_region))
		return -LXP_EINVAL;
	return LXP_OK;
}

LXP_FORK_TXN_LINKAGE int fork_txn_publish(struct fork_txn *tx)
{
	if (fork_txn_validate(tx) != LXP_OK)
		return -LXP_EINVAL;
	tx->child->alive = 1;
	tx->phase = FORK_TXN_PUBLISHED;
	return lifecycle_failpoint(LXP_FAIL_FORK_PUBLISHED) ? -LXP_ENOMEM : LXP_OK;
}

LXP_FORK_TXN_LINKAGE void fork_txn_abort(struct fork_txn *tx, const lxp_os_ops_t *eng)
{
	if (!tx || tx->phase == FORK_TXN_ABORTED || tx->phase == FORK_TXN_COMMITTED ||
	    tx->phase == FORK_TXN_EMPTY)
		return;
	if (tx->child_counted && tx->parent->group->live_children > 0)
		tx->parent->group->live_children--;
	if (tx->child_constructed && tx->child->snapshot.index >= 0)
		(void)region_release_if_owned(tx->child->snapshot, tx->child_ref);
	if (tx->maps_touched && eng->map_device)
		(void)eng->map_device(tx->child_ref.index, 0, 0, 0);
	if (tx->region_acquired)
		(void)region_put(tx->parent_region);
	if (tx->child_constructed)
		lxp_proc_child_discard(tx->child);
	lxp_slot_signal_reset(tx->child_ref.index);
	slot_runnable_store(tx->child_ref.index, 0);
	primary_slot_clear(tx->child_ref.index);
	lxp_vfork_guard_reset(tx->child_ref.index);
	tx->region_acquired = 0;
	tx->child_constructed = 0;
	tx->maps_touched = 0;
	tx->child_counted = 0;
	tx->phase = FORK_TXN_ABORTED;
}

LXP_FORK_TXN_LINKAGE int fork_txn_commit(struct fork_txn *tx)
{
	if (!tx || tx->phase != FORK_TXN_PUBLISHED)
		return -LXP_EINVAL;
	tx->region_acquired = 0;
	tx->child_constructed = 0;
	tx->maps_touched = 0;
	tx->child_counted = 0;
	tx->phase = FORK_TXN_COMMITTED;
	return LXP_OK;
}

static void fork_parent_resume_error(const lxp_os_ops_t *eng, int parent_slot, long error)
{
	(void)coordinator_park_slot(eng, parent_slot);
	(void)coordinator_complete_slot(eng, slot_ref_at(parent_slot), error);
}

void lxp_handle_fork(const lxp_os_ops_t *eng, int parent_slot, int *next_pid)
{
	lxp_proc_t *parent = lxp_slot_proc(parent_slot);
	uint32_t clone_flags = parent->intent.data.fork.flags;
	uintptr_t child_stack = parent->intent.data.fork.child_stack;
	(void)lxp_intent_complete(parent, LXP_INTENT_FORK);

	/* The zombie queue is bounded. Count live children and queued zombies so a
	 * parent that does not reap cannot make a later status disappear. */
	if (!(clone_flags & LXP_CLONE_THREAD) && !fork_capacity_available(parent)) {
		fork_parent_resume_error(eng, parent_slot, -LXP_EAGAIN);
		return;
	}

	int child_slot = -1;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (!lxp_slot_proc(s)->alive) {
			child_slot = s;
			break;
		}
	if (child_slot < 0) {
		fork_parent_resume_error(eng, parent_slot, -LXP_EAGAIN);
		return;
	}

	struct fork_txn tx;
	int child_pid = *next_pid;
	int rc = fork_txn_prepare(&tx, eng, parent_slot, child_slot, clone_flags, child_pid);
	if (rc != LXP_OK) {
		fork_txn_abort(&tx, eng);
		fork_parent_resume_error(eng, parent_slot, rc);
		return;
	}

	lxp_proc_t *child = tx.child;
	if (clone_flags & LXP_CLONE_VM) {
		/* A shared-mm clone runs on its own stack while the parent co-runs.
		 * CLONE_THREAD controls group membership; CLONE_VM alone remains a
		 * distinct waitable process. */
		if (!(clone_flags & LXP_CLONE_THREAD))
			rc = fork_txn_count_child(&tx);
		if (rc == LXP_OK)
			rc = lxp_slot_resume_clone_for_fork(tx.child_ref, tx.parent_ref,
							    child_stack);
		if (rc == LXP_OK)
			rc = fork_txn_publish(&tx);
		if (rc == LXP_OK)
			rc = fork_txn_commit(&tx);
		if (rc != LXP_OK) {
			fork_txn_abort(&tx, eng);
			fork_parent_resume_error(eng, parent_slot, rc);
			return;
		}
		(*next_pid)++;
		(void)coordinator_park_slot(eng, parent_slot);
		(void)coordinator_complete_slot(eng, tx.parent_ref, child->pid);
		(void)coordinator_resume_slot(eng, child_slot, child->mm->region.index,
					      lxp_slot_resume_view(tx.child_ref), 0);
		return;
	}

	rc = fork_txn_count_child(&tx);
	child->vfork_parent = slot_ref_at(parent_slot);
	const struct lxp_resume_ctx *parent_resume = lxp_slot_resume_view(tx.parent_ref);
	if (rc == LXP_OK && !parent_resume)
		rc = -LXP_ESRCH;
	if (rc == LXP_OK)
		rc = fork_txn_snapshot(&tx, eng, parent_resume->sp);
	if (rc != LXP_OK) {
		/* Refuse a deep vfork if no spare region can isolate the child's
		 * pre-exec writes from its suspended parent. */
		fork_txn_abort(&tx, eng);
		fork_parent_resume_error(eng, parent_slot, rc);
		return;
	}
	rc = fork_txn_publish(&tx);
	if (rc == LXP_OK)
		rc = fork_txn_commit(&tx);
	if (rc != LXP_OK) {
		fork_txn_abort(&tx, eng);
		fork_parent_resume_error(eng, parent_slot, rc);
		return;
	}
	(*next_pid)++;
	(void)coordinator_park_slot(eng, parent_slot);
	(void)coordinator_resume_slot(eng, child_slot, child->mm->region.index,
				      lxp_slot_resume_view(tx.parent_ref), 0);
}
