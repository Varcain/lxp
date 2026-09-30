/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator exit/reap handler.
 */

#include "run/lxp_coordinator.h"
#include "lxp_run_internal.h"

void lxp_coordinator_exit_slot(int slot, int group, int status, uint8_t reason, uint32_t detail)
{
	lxp_proc_t *proc = lxp_slot_proc(slot);
	proc->exit_status = status;
	proc->exit_reason = reason;
	proc->exit_signal = 0;
	proc->exit_detail = detail;
	proc->exit_address = 0;
	(void)lxp_intent_exit(proc, group);
	lxp_primary_slot_mark(slot);
}

struct lxp_exit_result lxp_handle_exit(int slot)
{
	struct lxp_exit_result result = {0};
	lxp_proc_t *proc = lxp_slot_proc(slot);
	lxp_slot_ref_t exiting_ref = lxp_slot_ref_at(slot);
	if (proc->intent.data.exit.group)
		lxp_thread_group_request_exit(slot, proc->exit_status);

	/* Host termination is the commit point. Keep every Linux reference intact
	 * and retry the exit event if the RTOS did not stop the task. */
	if (lxp_coordinator_abort_slot(slot) != LXP_OK) {
		lxp_primary_slot_mark(slot);
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
	if (g_lxp_os_ops->memory.map_device)
		(void)g_lxp_os_ops->memory.map_device(slot, 0, 0, 0);
	g_lxp_sig_save[slot].depth = 0;

	if (lxp_slot_ref_is_current(parent_ref) && proc->snapshot.index >= 0) {
		/* A vfork child died before exec: undo its writes to the shared
		 * address space before resuming the parent. */
		if (lxp_vfork_restore(lxp_slot_proc(parent_slot), proc->snapshot, exiting_ref,
				  lxp_slot_resume_view(parent_ref)->sp) != 0) {
			lxp_vfork_contain_stale(exiting_ref, proc);
			parent_slot = -1;
			status = proc->exit_status;
		} else {
			(void)lxp_region_release_if_owned(proc->snapshot, exiting_ref);
		}
	}

	lxp_notify_guest_exit(slot, proc);
	lxp_region_mm_put(proc);
	proc->alive = 0;
	lxp_slot_debug_clear(slot);
	lxp_slot_runnable_store(slot, 0);
	lxp_deferred_slot_reassign(slot);
	int group_is_dead = lxp_thread_group_live_count(group) == 0;
	if (tgid == 1 && group_is_dead) {
		lxp_proc_group_put(proc);
		result.stop_coordinator = 1;
		result.status = status;
		return result;
	}

	if (parent_slot >= 0 && lxp_slot_ref_is_current(parent_ref))
		(void)lxp_coordinator_complete_slot(parent_ref, pid);
	if (group_is_dead)
		lxp_reap_to_parent(ppid, tgid, status,
			       /*sigchld=*/!lxp_slot_ref_is_current(parent_ref));
	lxp_proc_group_put(proc);
	return result;
}
