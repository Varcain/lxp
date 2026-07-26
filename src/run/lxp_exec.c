/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator exec handler. Unity-included by lxp_run.c.
 */

enum exec_txn_phase {
	EXEC_TXN_EMPTY,
	EXEC_TXN_RESERVED,
	EXEC_TXN_VALIDATED,
	EXEC_TXN_COMMITTED,
	EXEC_TXN_IMAGE_READY,
	EXEC_TXN_PUBLISHED,
	EXEC_TXN_FINISHED,
	EXEC_TXN_ABORTED,
};

struct exec_txn {
	lxp_proc_t *old;
	struct image_txn image;
	lxp_slot_ref_t old_ref;
	lxp_slot_ref_t new_ref;
	lxp_slot_ref_t parent_ref;
	lxp_region_ref_t region;
	lxp_files_t *saved_files;
	lxp_fs_context_t *saved_fs;
	lxp_sighand_t *old_sighand;
	lxp_thread_group_t *saved_group;
	enum exec_txn_phase phase;
	int slot;
	int pid;
	int ppid;
	int image_index;
	uint64_t saved_mask;
	char comm[sizeof(((lxp_proc_t *)0)->comm)];
	uint8_t region_acquired;
	uint8_t uses_snapshot;
	uint8_t parent_restored;
	uint8_t parent_resumed;
	uint8_t old_detached;
	uint8_t slot_reassigned;
	uint8_t image_initialized;
	uint8_t terminal;
};

static void exec_txn_init(struct exec_txn *tx, int slot)
{
	memset(tx, 0, sizeof(*tx));
	tx->phase = EXEC_TXN_EMPTY;
	tx->slot = slot;
	tx->old = &g_lxp_slots[slot].proc;
	tx->old_ref = slot_ref_at(slot);
	tx->parent_ref = tx->old->vfork_parent;
	tx->pid = tx->old->pid;
	tx->ppid = tx->old->group->ppid;
	tx->image_index = tx->old->exec_file_idx;
	memcpy(tx->comm, tx->old->comm, sizeof(tx->comm));
	tx->region = lxp_region_ref_none();
	tx->new_ref = lxp_slot_ref_none();
}

static int exec_txn_reserve(struct exec_txn *tx)
{
	if (tx->phase != EXEC_TXN_EMPTY || !lxp_slot_ref_is_current(tx->old_ref))
		return -LXP_EINVAL;

	if (tx->old->snapshot.index >= 0) {
		int ridx = tx->old->snapshot.index;
		tx->region = tx->old->snapshot;
		if (ridx >= LXP_NREG || tx->region.generation == 0 ||
		    g_regions[ridx].generation != tx->region.generation ||
		    g_regions[ridx].refs != 1 ||
		    !lxp_slot_ref_equal(g_regions[ridx].lease_owner, tx->old_ref)) {
			/* The child may already have dirtied its parent's shared
			 * image. A stale snapshot cannot be retried as a guest-visible
			 * exec error because the parent would remain parked with no
			 * trustworthy restore source. */
			vfork_contain_stale(tx->old_ref, tx->old);
			tx->terminal = 1;
			return -LXP_EIO;
		}
		tx->uses_snapshot = 1;
	} else {
		int ridx = -1;
		for (int r = 0; r < LXP_NREG; r++)
			if (region_free(r)) {
				ridx = r;
				break;
			}
		if (ridx < 0)
			return -LXP_ENOMEM;
		tx->region = region_reserve(ridx, tx->old_ref);
		if (tx->region.index < 0)
			return -LXP_ENOMEM;
	}
	tx->region_acquired = 1;
	tx->phase = EXEC_TXN_RESERVED;
	return lifecycle_failpoint(LXP_FAIL_EXEC_REGION_ACQUIRED) ? -LXP_ENOMEM : LXP_OK;
}

static int exec_txn_validate_image(struct exec_txn *tx, const uint8_t *image,
				   size_t image_size, int remote_exec)
{
	if (tx->phase != EXEC_TXN_RESERVED || !image)
		return -LXP_ENOEXEC;
	if (lxp_loader_validate_fdpic(image, image_size, LXP_PROG_REGION_SIZE, remote_exec) !=
	    LXP_OK)
		return -LXP_ENOEXEC;
	tx->phase = EXEC_TXN_VALIDATED;
	return lifecycle_failpoint(LXP_FAIL_EXEC_IMAGE_VALIDATED) ? -LXP_ENOEXEC : LXP_OK;
}

/* Transfer the old image's process objects to the transaction after its native
 * task has stopped. No later path may release them through tx->old. */
static void exec_txn_detach_old(struct exec_txn *tx)
{
	if (tx->old_detached)
		return;
	lxp_proc_t *old = tx->old;
	tx->saved_files = old->files;
	tx->saved_fs = old->fs_context;
	tx->old_sighand = old->sighand;
	tx->saved_group = old->group;
	tx->saved_mask = old->sig_blocked;
	old->files = NULL;
	old->fs_context = NULL;
	old->sighand = NULL;
	old->group = NULL;
	proc_mm_put(old);
	old->snapshot = lxp_region_ref_none();
	old->alive = 0;
	g_lxp_slots[tx->slot].runnable = 0;
	tx->old_detached = 1;
}

static int exec_txn_commit(struct exec_txn *tx, const lxp_os_ops_t *eng)
{
	if (tx->phase != EXEC_TXN_VALIDATED)
		return -LXP_EINVAL;

	/* Everything below is the image-replacement commit boundary. Failures no
	 * longer return to the old program; they contain this guest instead. */
	tx->phase = EXEC_TXN_COMMITTED;
	if (tx->parent_ref.index >= 0) {
		if (!lxp_slot_ref_is_current(tx->parent_ref) || tx->old->snapshot.index < 0 ||
		    vfork_restore(eng, &g_lxp_slots[tx->parent_ref.index].proc,
				  tx->old->snapshot, tx->old_ref,
				  g_lxp_slots[tx->parent_ref.index].resume.sp) != 0) {
			vfork_contain_stale(tx->old_ref, tx->old);
			tx->terminal = 1;
			return -LXP_EIO;
		}
		tx->parent_restored = 1;
		/* Keep the parent identity on the process until publish succeeds. If a
		 * native abort fails, the ordinary exit handler can still resume it. */
		tx->old->snapshot = lxp_region_ref_none();
	}

	if (thread_group_stop_exec_peers(eng, tx->slot, 127) != LXP_OK)
		return -LXP_EAGAIN;
	if (coordinator_abort_slot(eng, tx->slot) != LXP_OK)
		return -LXP_EAGAIN;

	/* execve gets a private descriptor table and applies close-on-exec only
	 * after the old native task is gone. Before this commit, every failure left
	 * the descriptor table and old image untouched. */
	if (lxp_proc_files_unshare(tx->old) != 0)
		return -LXP_ENOMEM;
	for (int fd = 0; fd < LXP_MAX_FDS; fd++)
		if (tx->old->files->fd[fd].ofd && tx->old->files->fd[fd].cloexec)
			(void)lxp_fd_close(tx->old, fd);

	exec_txn_detach_old(tx);
	deferred_slot_reassign(tx->slot);
	tx->slot_reassigned = 1;
	tx->new_ref = slot_ref_at(tx->slot);
	if (tx->region.index < 0 || tx->region.index >= LXP_NREG ||
	    !lxp_slot_ref_equal(g_regions[tx->region.index].lease_owner, tx->old_ref))
		return -LXP_EIO;
	g_regions[tx->region.index].lease_owner = tx->new_ref;
	if (eng->map_device)
		(void)eng->map_device(tx->slot, 0, 0, 0);
	return lifecycle_failpoint(LXP_FAIL_EXEC_COMMITTED) ? -LXP_EIO : LXP_OK;
}

static void exec_txn_adopt_old_resources(struct exec_txn *tx)
{
	lxp_proc_t *image = &tx->image.proc;
	lxp_sighand_t *fresh_sighand = image->sighand;
	image->sighand = NULL;
	lxp_proc_resources_put(image); /* discard fresh files + fs */
	image->sighand = fresh_sighand;
	lxp_proc_group_put(image); /* preserve the old thread-group identity */

	image->files = tx->saved_files;
	image->fs_context = tx->saved_fs;
	image->group = tx->saved_group;
	image->sig_blocked = tx->saved_mask;
	image->exec_file_idx = tx->image_index;
	image->vfork_parent = tx->parent_ref;
	tx->saved_files = NULL;
	tx->saved_fs = NULL;
	tx->saved_group = NULL;

	lxp_proc_t discarded = {.sighand = tx->old_sighand};
	lxp_proc_resources_put(&discarded);
	tx->old_sighand = NULL;
}

static void exec_txn_release_saved(struct exec_txn *tx)
{
	lxp_proc_t saved = {
		.files = tx->saved_files,
		.fs_context = tx->saved_fs,
		.sighand = tx->old_sighand,
		.group = tx->saved_group,
	};
	lxp_proc_resources_put(&saved);
	lxp_proc_group_put(&saved);
	tx->saved_files = NULL;
	tx->saved_fs = NULL;
	tx->old_sighand = NULL;
	tx->saved_group = NULL;
}

static void exec_txn_resume_parent(struct exec_txn *tx, const lxp_os_ops_t *eng)
{
	if (!tx->parent_restored || tx->parent_resumed ||
	    !lxp_slot_ref_is_current(tx->parent_ref))
		return;
	int parent_slot = tx->parent_ref.index;
	(void)coordinator_resume_slot(eng, parent_slot,
				      g_lxp_slots[parent_slot].proc.mm->region.index,
				      &g_lxp_slots[parent_slot].resume, tx->pid);
	tx->parent_resumed = 1;
}

static void exec_txn_report_failure(struct exec_txn *tx, const lxp_os_ops_t *eng, int reason)
{
	lxp_thread_group_t group = {.ppid = tx->ppid};
	lxp_proc_t report = {
		.pid = tx->pid,
		.group = &group,
		.exit_status = 127,
		.exit_reason = (uint8_t)reason,
	};
	memcpy(report.comm, tx->comm, sizeof(report.comm));
	exec_txn_resume_parent(tx, eng);
	notify_guest_exit(tx->slot, &report);
	reap_to_parent(eng, tx->ppid, tx->pid, 127,
		       /*sigchld=*/!lxp_slot_ref_is_current(tx->parent_ref));
}

/*
 * Abort is safe to call more than once. Before commit it releases only the
 * prepared region and resumes the intact old image. After commit it first
 * proves the native task stopped, then releases whichever side still owns the
 * staged image and process resources.
 */
static void exec_txn_abort(struct exec_txn *tx, const lxp_os_ops_t *eng, long error, int reason)
{
	if (!tx || tx->phase == EXEC_TXN_ABORTED || tx->phase == EXEC_TXN_FINISHED ||
	    tx->terminal)
		return;

	if (tx->phase < EXEC_TXN_COMMITTED) {
		if (tx->region_acquired && !tx->uses_snapshot)
			(void)region_release_if_owned(tx->region, tx->old_ref);
		tx->region_acquired = 0;
		tx->phase = EXEC_TXN_ABORTED;
		(void)coordinator_resume_slot(eng, tx->slot, tx->old->mm->region.index,
					      &g_lxp_slots[tx->slot].resume, error);
		return;
	}

	if (!tx->old_detached) {
		if (coordinator_abort_slot(eng, tx->slot) != LXP_OK) {
			/* The old process still owns every released-state candidate.
			 * Keep it intact for the ordinary exit retry. */
			if (tx->region_acquired)
				(void)region_release_if_owned(tx->region, tx->old_ref);
			return;
		}
		exec_txn_detach_old(tx);
	}
	if (!tx->slot_reassigned) {
		deferred_slot_reassign(tx->slot);
		tx->slot_reassigned = 1;
		tx->new_ref = slot_ref_at(tx->slot);
		if (tx->region_acquired &&
		    lxp_slot_ref_equal(g_regions[tx->region.index].lease_owner, tx->old_ref))
			g_regions[tx->region.index].lease_owner = tx->new_ref;
	}

	if (tx->image_initialized) {
		if (image_txn_abort(&tx->image, eng) != LXP_OK)
			return; /* published slot still owns every resource */
	} else if (tx->region_acquired &&
		   lxp_slot_ref_equal(g_regions[tx->region.index].lease_owner, tx->new_ref)) {
		(void)region_release_if_owned(tx->region, tx->new_ref);
	}
	exec_txn_release_saved(tx);
	exec_txn_report_failure(tx, eng, reason);
	memset(&g_lxp_slots[tx->slot].proc, 0, sizeof(g_lxp_slots[tx->slot].proc));
	g_lxp_slots[tx->slot].proc.snapshot = lxp_region_ref_none();
	g_lxp_slots[tx->slot].proc.vfork_parent = lxp_slot_ref_none();
	g_lxp_slots[tx->slot].runnable = 0;
	primary_slot_clear(tx->slot);
	fork_child_guard_reset(tx->slot);
	tx->region_acquired = 0;
	tx->phase = EXEC_TXN_ABORTED;
}

static void lxp_handle_exec(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg, int slot)
{
	lxp_proc_t *proc = &g_lxp_slots[slot].proc;

	/* Freeze the old image before copying its trusted capture. */
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

	int argc = capture->argc;
	int envc = capture->envc;
	static char args[LXP_EXEC_ARGBUF];
	static const char *argv[LXP_EXEC_MAXARGS + 1];
	static char envs[LXP_EXEC_ENVBUF];
	static const char *envp[LXP_EXEC_MAXENVS + 1];
	flatten_vec(args, argv, capture->argv_buf, capture->argv, argc);
	flatten_vec(envs, envp, capture->env_buf, capture->env, envc);

	struct exec_txn tx;
	exec_txn_init(&tx, slot);
	const uint8_t *image = NULL;
	size_t image_size = 0;
	int remote_exec = 0;
#if LXP_ENABLE_NETFS_EXEC
	if (tx.image_index == LXP_NETFS_EXEC_SENTINEL) {
		image = lxp_netfs_exec_image(&image_size);
		remote_exec = 1;
	} else
#endif
		if (tx.image_index >= 0 && tx.image_index < cfg->rootfs_count) {
		image = cfg->rootfs[tx.image_index].data;
		image_size = cfg->rootfs[tx.image_index].size;
	}

	int rc = exec_txn_reserve(&tx);
	if (rc == LXP_OK)
		rc = exec_txn_validate_image(&tx, image, image_size, remote_exec);
	if (rc != LXP_OK) {
		exec_txn_abort(&tx, eng, rc, LXP_EXIT_REASON_EXEC_RESOURCE);
		return;
	}

	rc = exec_txn_commit(&tx, eng);
	if (rc != LXP_OK) {
		exec_txn_abort(&tx, eng, rc, LXP_EXIT_REASON_EXEC_RESOURCE);
		return;
	}

	image_txn_init(&tx.image, slot, tx.region, tx.new_ref);
	tx.image_initialized = 1;
	rc = image_txn_prepare(&tx.image, eng, image, image_size, tx.pid, tx.ppid, argc, argv,
			       envp, remote_exec);
	if (rc == LXP_OK && lifecycle_failpoint(LXP_FAIL_EXEC_IMAGE_PREPARED))
		rc = -LXP_EIO;
	if (rc != LXP_OK) {
		exec_txn_abort(&tx, eng, rc, LXP_EXIT_REASON_EXEC_LOAD);
		return;
	}
	tx.phase = EXEC_TXN_IMAGE_READY;
	exec_txn_adopt_old_resources(&tx);

	rc = image_txn_publish(&tx.image, eng);
	if (rc != LXP_OK) {
		exec_txn_abort(&tx, eng, rc, LXP_EXIT_REASON_EXEC_LOAD);
		return;
	}
	tx.phase = EXEC_TXN_PUBLISHED;
	rc = image_txn_start(&tx.image, eng);
	if (rc != LXP_OK) {
		exec_txn_abort(&tx, eng, rc, LXP_EXIT_REASON_EXEC_LOAD);
		return;
	}

	exec_txn_resume_parent(&tx, eng);
	g_lxp_slots[slot].proc.vfork_parent = lxp_slot_ref_none();
	tx.phase = EXEC_TXN_FINISHED;
}
