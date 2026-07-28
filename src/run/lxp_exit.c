/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator exit/reap handler.
 */

#include "run/lxp_coordinator.h"
#include "lxp_run_internal.h"

struct lxp_exit_result lxp_handle_exit(const lxp_os_ops_t *eng, int slot)
{
	struct lxp_exit_result result = {0};
	lxp_proc_t *proc = lxp_proc_at(slot);
	lxp_slot_ref_t exiting_ref = slot_ref_at(slot);
	if (proc->intent.data.exit.group)
		thread_group_request_exit(slot, proc->exit_status);

	/* Host termination is the commit point. Keep every Linux reference intact
	 * and retry the exit event if the RTOS did not stop the task. */
	if (coordinator_abort_slot(eng, slot) != LXP_OK) {
		primary_slot_mark(slot);
		return result;
	}

	lxp_thread_group_t *group = proc->group;
	int pid = proc->pid;
	int tgid = group->tgid;
	int status = proc->exit_status;
	int ppid = group->ppid;
	lxp_slot_ref_t parent_ref = proc->vfork_parent;
	int parent_slot = parent_ref.index;
	lxp_proc_resources_put(proc);
	if (eng->map_device)
		(void)eng->map_device(slot, 0, 0, 0);
	g_sig_save[slot].depth = 0;

	if (lxp_slot_ref_is_current(parent_ref) && proc->snapshot.index >= 0) {
		/* A vfork child died before exec: undo its writes to the shared
		 * address space before resuming the parent. */
		if (vfork_restore(eng, lxp_proc_at(parent_slot), proc->snapshot, exiting_ref,
				  lxp_slot_resume(parent_slot)->sp) != 0) {
			vfork_contain_stale(exiting_ref, proc);
			parent_slot = -1;
			status = proc->exit_status;
		} else {
			(void)region_release_if_owned(proc->snapshot, exiting_ref);
		}
	}

	notify_guest_exit(slot, proc);
	proc_mm_put(proc);
	proc->alive = 0;
	slot_runnable_store(slot, 0);
	deferred_slot_reassign(slot);
	int group_is_dead = thread_group_live_count(group) == 0;
	if (tgid == 1 && group_is_dead) {
		lxp_proc_group_put(proc);
		result.stop_coordinator = 1;
		result.status = status;
		return result;
	}

	if (parent_slot >= 0 && lxp_slot_ref_is_current(parent_ref))
		(void)coordinator_resume_slot(eng, parent_slot,
					      lxp_proc_at(parent_slot)->mm->region.index,
					      lxp_slot_resume(parent_slot), pid);
	if (group_is_dead)
		reap_to_parent(eng, ppid, tgid, status,
			       /*sigchld=*/!lxp_slot_ref_is_current(parent_ref));
	lxp_proc_group_put(proc);
	return result;
}
