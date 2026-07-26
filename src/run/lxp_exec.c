/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator exec handler. Unity-included by lxp_run.c.
 */

static void lxp_handle_exec(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg, int slot)
{
	lxp_proc_t *proc = &g_lxp_slots[slot].proc;

	/* Freeze the old image before inspecting or transferring its resources. */
	if (coordinator_park_slot(eng, slot) != LXP_OK)
		return;
	(void)lxp_intent_complete(proc, LXP_INTENT_EXEC);
	lxp_exec_capture_t *capture = proc->exec_capture;
	if (!capture) {
		proc->exit_status = 127;
		(void)lxp_intent_exit(proc, 0);
		primary_slot_mark(slot);
		return;
	}

	int image_index = proc->exec_file_idx;
	int argc = capture->argc;
	int envc = capture->envc;
	/* launch() reinitializes the slot, so copy the captured vectors first. */
	static char args[LXP_EXEC_ARGBUF];
	static const char *argv[LXP_EXEC_MAXARGS + 1];
	static char envs[LXP_EXEC_ENVBUF];
	static const char *envp[LXP_EXEC_MAXENVS + 1];
	flatten_vec(args, argv, capture->argv_buf, capture->argv, argc);
	flatten_vec(envs, envp, capture->env_buf, capture->env, envc);

	lxp_slot_ref_t exec_ref = slot_ref_at(slot);
	lxp_region_ref_t exec_region = proc->snapshot;
	int new_region = exec_region.index;
	if (new_region < 0)
		for (int r = 0; r < LXP_NREG; r++)
			if (region_free(r)) {
				new_region = r;
				break;
			}

	int pid = proc->pid;
	int ppid = proc->group->ppid;
	lxp_slot_ref_t parent_ref = proc->vfork_parent;
	int parent_slot = parent_ref.index;
	if (new_region < 0) {
		/* Region exhaustion kills this process, not the entire personality. */
		if (coordinator_abort_slot(eng, slot) != LXP_OK)
			return;
		deferred_slot_reassign(slot);
		lxp_proc_resources_put(proc);
		proc_mm_put(proc);
		proc->exit_status = 127;
		proc->exit_reason = LXP_EXIT_REASON_EXEC_RESOURCE;
		proc->exit_signal = 0;
		notify_guest_exit(slot, proc);
		proc->alive = 0;
		g_lxp_slots[slot].runnable = 0;
		if (lxp_slot_ref_is_current(parent_ref))
			(void)coordinator_resume_slot(
				eng, parent_slot, g_lxp_slots[parent_slot].proc.mm->region.index,
				&g_lxp_slots[parent_slot].resume, pid);
		reap_to_parent(eng, ppid, pid, 127,
			       /*sigchld=*/!lxp_slot_ref_is_current(parent_ref));
		lxp_proc_group_put(proc);
		return;
	}

	if (lxp_slot_ref_is_current(parent_ref)) {
		/* Restore the vfork parent before it runs. argv/envp are already in
		 * trusted staging storage, so restoring the guest bytes is safe. */
		if (proc->snapshot.index < 0 ||
		    vfork_restore(eng, &g_lxp_slots[parent_slot].proc, proc->snapshot, exec_ref,
				  g_lxp_slots[parent_slot].resume.sp) != 0) {
			vfork_contain_stale(exec_ref, proc);
			return;
		}
		proc->vfork_parent = lxp_slot_ref_none();
		(void)coordinator_resume_slot(eng, parent_slot,
					      g_lxp_slots[parent_slot].proc.mm->region.index,
					      &g_lxp_slots[parent_slot].resume, pid);
	}

	/* execve gets a private descriptor table, preserves its entries and fs
	 * context, and resets signal dispositions. */
	if (lxp_proc_files_unshare(proc) != 0) {
		(void)coordinator_resume_slot(eng, slot, proc->mm->region.index,
					      &g_lxp_slots[slot].resume, -LXP_ENOMEM);
		return;
	}
	for (int fd = 0; fd < LXP_MAX_FDS; fd++)
		if (proc->files->fd[fd].ofd && proc->files->fd[fd].cloexec)
			(void)lxp_fd_close(proc, fd);

	lxp_files_t *saved_files = proc->files;
	lxp_fs_context_t *saved_fs = proc->fs_context;
	lxp_sighand_t *old_sighand = proc->sighand;
	lxp_thread_group_t *saved_group = proc->group;
	uint64_t saved_mask = proc->sig_blocked;
	int region_reserved = lxp_region_ref_equal(exec_region, proc->snapshot) &&
			      lxp_slot_ref_equal(g_regions[new_region].lease_owner, exec_ref) &&
			      g_regions[new_region].refs == 1 &&
			      g_regions[new_region].generation == exec_region.generation;

	if (thread_group_stop_exec_peers(eng, slot, 127) != LXP_OK) {
		slot_transition_failed(slot, SLOT_EXITING, -LXP_EAGAIN);
		return;
	}
	if (coordinator_abort_slot(eng, slot) != LXP_OK)
		return;
	deferred_slot_reassign(slot);
	lxp_slot_ref_t relaunched_ref = slot_ref_at(slot);
	if (eng->map_device)
		(void)eng->map_device(slot, 0, 0, 0);
	proc_mm_put(proc);

	/* Transfer these objects across launch()'s process reinitialization. */
	proc->files = NULL;
	proc->fs_context = NULL;
	proc->sighand = NULL;
	proc->group = NULL;
	if (region_reserved)
		g_regions[new_region].lease_owner = relaunched_ref;
	else
		exec_region = region_reserve(new_region, relaunched_ref);
	if (exec_region.index < 0) {
		proc->files = saved_files;
		proc->fs_context = saved_fs;
		proc->sighand = old_sighand;
		proc->group = saved_group;
		proc->exit_status = 127;
		proc->exit_reason = LXP_EXIT_REASON_EXEC_RESOURCE;
		proc->exit_signal = 0;
		notify_guest_exit(slot, proc);
		lxp_proc_resources_put(proc);
		lxp_proc_group_put(proc);
		proc->alive = 0;
		g_lxp_slots[slot].runnable = 0;
		reap_to_parent(eng, ppid, pid, 127,
			       /*sigchld=*/!lxp_slot_ref_is_current(parent_ref));
		return;
	}

	const uint8_t *image = cfg->rootfs[image_index].data;
	size_t image_size = cfg->rootfs[image_index].size;
	int remote_exec = 0;
#if LXP_ENABLE_NETFS_EXEC
	if (image_index == LXP_NETFS_EXEC_SENTINEL) {
		image = lxp_netfs_exec_image(&image_size);
		remote_exec = 1;
	}
#endif
	if (!image || launch(eng, slot, new_region, image, image_size, pid, ppid, argc, argv, envp,
			     remote_exec) != 0) {
		(void)region_release_if_owned(exec_region, relaunched_ref);
		lxp_proc_resources_put(&g_lxp_slots[slot].proc);
		lxp_proc_t old_resources = {
			.files = saved_files,
			.fs_context = saved_fs,
			.sighand = old_sighand,
		};
		lxp_proc_resources_put(&old_resources);
		lxp_proc_mm_put(&g_lxp_slots[slot].proc);
		g_lxp_slots[slot].proc.exit_status = 127;
		g_lxp_slots[slot].proc.exit_reason = LXP_EXIT_REASON_EXEC_LOAD;
		g_lxp_slots[slot].proc.exit_signal = 0;
		notify_guest_exit(slot, &g_lxp_slots[slot].proc);
		lxp_proc_group_put(&g_lxp_slots[slot].proc);
		lxp_proc_t old_group = {.group = saved_group};
		lxp_proc_group_put(&old_group);
		g_lxp_slots[slot].proc.alive = 0;
		g_lxp_slots[slot].runnable = 0;
		reap_to_parent(eng, ppid, pid, 127,
			       /*sigchld=*/!lxp_slot_ref_is_current(parent_ref));
		return;
	}

	/* Discard launch's fresh files/fs, retain its default sighand, then
	 * transfer the exec-surviving objects without changing their refs. */
	lxp_sighand_t *fresh_sighand = g_lxp_slots[slot].proc.sighand;
	lxp_thread_group_t *fresh_group = g_lxp_slots[slot].proc.group;
	g_lxp_slots[slot].proc.sighand = NULL;
	g_lxp_slots[slot].proc.group = NULL;
	lxp_proc_resources_put(&g_lxp_slots[slot].proc);
	lxp_proc_t discarded_group = {.group = fresh_group};
	lxp_proc_group_put(&discarded_group);
	g_lxp_slots[slot].proc.files = saved_files;
	g_lxp_slots[slot].proc.fs_context = saved_fs;
	g_lxp_slots[slot].proc.sighand = fresh_sighand;
	g_lxp_slots[slot].proc.group = saved_group;
	lxp_proc_t discarded_sighand = {.sighand = old_sighand};
	lxp_proc_resources_put(&discarded_sighand);
	g_lxp_slots[slot].proc.sig_blocked = saved_mask;
	g_lxp_slots[slot].proc.exec_file_idx = image_index;
}
