/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator fork/clone/vfork handler. Unity-included by lxp_run.c.
 */

static void lxp_handle_fork(const lxp_os_ops_t *eng, int parent_slot, int *next_pid)
{
	lxp_proc_t *parent = &g_lxp_slots[parent_slot].proc;
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
		if (!g_lxp_slots[s].proc.alive) {
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
		g_lxp_slots[child_slot].resume = g_lxp_slots[parent_slot].resume;
		g_lxp_slots[child_slot].resume.sp = child_stack;
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
		(void)coordinator_resume_slot(eng, parent_slot, parent->mm->region.index,
					      &g_lxp_slots[parent_slot].resume, child->pid);
		(void)coordinator_resume_slot(eng, child_slot, child->mm->region.index,
					      &g_lxp_slots[child_slot].resume, 0);
		return;
	}

	rc = fork_txn_count_child(&tx);
	child->vfork_parent = slot_ref_at(parent_slot);
	if (rc == LXP_OK)
		rc = fork_txn_snapshot(&tx, eng, g_lxp_slots[parent_slot].resume.sp);
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
				      &g_lxp_slots[parent_slot].resume, 0);
}
