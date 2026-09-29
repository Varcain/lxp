/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#include "lxp/lxp_config.h"

#include "proc/lxp_proc.h"
#include "proc/lxp_exec_stage.h"

#include "fs/lxp_fd_private.h"

#include <string.h>

#ifndef LXP_RESOURCE_POOL_COUNT
#define LXP_RESOURCE_POOL_COUNT LXP_NSLOT
#endif
LXP_STATIC_ASSERT(LXP_RESOURCE_POOL_COUNT >= LXP_NSLOT,
		  "shared-resource pools must cover every live task");

/*
 * Process-owned resources have independent reference counts because clone(2)
 * can share each class separately. Only this module allocates and clears these
 * pools; descriptor backing objects remain owned by the fd module.
 */
static lxp_files_t g_files[LXP_RESOURCE_POOL_COUNT];
static lxp_fs_context_t g_fs_context[LXP_RESOURCE_POOL_COUNT];
static lxp_sighand_t g_sighand[LXP_RESOURCE_POOL_COUNT];
static lxp_mm_t g_mm[LXP_RESOURCE_POOL_COUNT];
static lxp_thread_group_t g_groups[LXP_RESOURCE_POOL_COUNT];

LXP_STATIC_ASSERT(offsetof(lxp_files_t, refs) == 0, "resource refs must lead the object");
LXP_STATIC_ASSERT(offsetof(lxp_fs_context_t, refs) == 0, "resource refs must lead the object");
LXP_STATIC_ASSERT(offsetof(lxp_sighand_t, refs) == 0, "resource refs must lead the object");
LXP_STATIC_ASSERT(offsetof(lxp_mm_t, refs) == 0, "resource refs must lead the object");
LXP_STATIC_ASSERT(offsetof(lxp_thread_group_t, refs) == 0, "resource refs must lead the object");

static void *resource_new(void *storage, size_t item_size)
{
	for (int i = 0; i < LXP_RESOURCE_POOL_COUNT; i++) {
		void *item = (uint8_t *)storage + (size_t)i * item_size;
		uint16_t *refs = item;
		if (*refs == 0) {
			memset(item, 0, item_size);
			*refs = 1;
			return item;
		}
	}
	return NULL;
}

static lxp_files_t *files_new(void)
{
	return resource_new(g_files, sizeof(g_files[0]));
}

static lxp_fs_context_t *fs_context_new(void)
{
	lxp_fs_context_t *context = resource_new(g_fs_context, sizeof(g_fs_context[0]));
	if (context) {
		context->umask = 022;
		context->cwd[0] = '/';
	}
	return context;
}

static lxp_sighand_t *sighand_new(void)
{
	return resource_new(g_sighand, sizeof(g_sighand[0]));
}

static lxp_mm_t *mm_new(void)
{
	lxp_mm_t *mm = resource_new(g_mm, sizeof(g_mm[0]));
	if (mm) {
		mm->region = lxp_region_ref_none();
		mm->device_generation = 1u;
		mm->exec_generation = 1u;
	}
	return mm;
}

static lxp_thread_group_t *group_new(void)
{
	return resource_new(g_groups, sizeof(g_groups[0]));
}

int lxp_intent_begin(lxp_proc_t *proc, const lxp_intent_t *intent)
{
	if (!proc || !intent || intent->kind <= LXP_INTENT_NONE || intent->kind >= LXP_INTENT_COUNT)
		return -LXP_EINVAL;
	if (proc->intent.kind != LXP_INTENT_NONE || proc->wait.kind != LXP_WAIT_NONE)
		return -LXP_EAGAIN;
	proc->intent = *intent;
	return 0;
}

int lxp_intent_complete(lxp_proc_t *proc, lxp_intent_kind_t expected)
{
	if (!proc || expected <= LXP_INTENT_NONE || expected >= LXP_INTENT_COUNT ||
	    proc->intent.kind != expected)
		return -LXP_EINVAL;
	memset(&proc->intent, 0, sizeof(proc->intent));
	return 0;
}

int lxp_intent_exit(lxp_proc_t *proc, int group)
{
	if (!proc)
		return -LXP_EINVAL;
	memset(&proc->intent, 0, sizeof(proc->intent));
	proc->intent.kind = LXP_INTENT_EXIT;
	proc->intent.data.exit.group = group != 0;
	return 0;
}

int lxp_wait_begin(lxp_proc_t *proc, const lxp_wait_t *wait)
{
	if (!proc || !wait || wait->kind <= LXP_WAIT_NONE || wait->kind >= LXP_WAIT_COUNT)
		return -LXP_EINVAL;
	if (proc->wait.kind != LXP_WAIT_NONE || proc->intent.kind != LXP_INTENT_NONE)
		return -LXP_EAGAIN;
	proc->wait = *wait;
	(void)lxp_time_us(&proc->wait.enqueued_us);
	return 0;
}

long lxp_wait_park(lxp_proc_t *proc, const lxp_wait_t *wait)
{
	return lxp_wait_begin(proc, wait) == 0 ? 0 : -LXP_EAGAIN;
}

static int wait_finish(lxp_proc_t *proc, lxp_wait_kind_t expected)
{
	if (!proc || expected <= LXP_WAIT_NONE || expected >= LXP_WAIT_COUNT ||
	    proc->wait.kind != expected)
		return -LXP_EINVAL;
	memset(&proc->wait, 0, sizeof(proc->wait));
	return 0;
}

int lxp_wait_complete(lxp_proc_t *proc, lxp_wait_kind_t expected)
{
	return wait_finish(proc, expected);
}

int lxp_wait_interrupt(lxp_proc_t *proc, lxp_wait_kind_t expected)
{
	return wait_finish(proc, expected);
}

int lxp_wait_timeout(lxp_proc_t *proc, lxp_wait_kind_t expected)
{
	return wait_finish(proc, expected);
}

int lxp_wait_cancel(lxp_proc_t *proc)
{
	if (!proc)
		return -LXP_EINVAL;
	memset(&proc->wait, 0, sizeof(proc->wait));
	return 0;
}

void lxp_proc_runtime_reset(void)
{
	memset(g_files, 0, sizeof(g_files));
	memset(g_fs_context, 0, sizeof(g_fs_context));
	memset(g_sighand, 0, sizeof(g_sighand));
	memset(g_mm, 0, sizeof(g_mm));
	memset(g_groups, 0, sizeof(g_groups));
	lxp_exec_stage_reset();
}

static void files_put(lxp_proc_t *proc)
{
	lxp_files_t *files = proc ? proc->files : NULL;
	if (!files)
		return;
	if (files->refs == 0) {
		proc->files = NULL;
		return;
	}
	if (--files->refs == 0) {
		for (int fd = 0; fd < LXP_MAX_FDS; fd++)
			(void)lxp_fd_close(proc, fd);
		memset(files, 0, sizeof(*files));
	}
	proc->files = NULL;
}

void lxp_proc_resources_put(lxp_proc_t *proc)
{
	if (!proc)
		return;
	files_put(proc);
	if (proc->fs_context) {
		if (proc->fs_context->refs > 0 && --proc->fs_context->refs == 0)
			memset(proc->fs_context, 0, sizeof(*proc->fs_context));
		proc->fs_context = NULL;
	}
	if (proc->sighand) {
		if (proc->sighand->refs > 0 && --proc->sighand->refs == 0)
			memset(proc->sighand, 0, sizeof(*proc->sighand));
		proc->sighand = NULL;
	}
}

int lxp_fd_fork_inherit(lxp_proc_t *child)
{
	if (!child || !child->files)
		return -1;
	lxp_files_t *source = child->files;
	lxp_files_t *copy = files_new();
	if (!copy)
		return -1;
	memcpy(copy->fd, source->fd, sizeof(copy->fd));
	child->files = copy;
	if (lxp_fd_table_retain(child) != 0) {
		memset(copy, 0, sizeof(*copy));
		child->files = source;
		return -1;
	}
	return 0;
}

int lxp_proc_files_unshare(lxp_proc_t *proc)
{
	if (!proc || !proc->files)
		return -1;
	if (proc->files->refs == 1)
		return 0;
	lxp_files_t *shared = proc->files;
	if (lxp_fd_fork_inherit(proc) != 0)
		return -1;
	shared->refs--;
	return 0;
}

int lxp_proc_resources_fork(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags)
{
	if (!child || !parent || !parent->files || !parent->fs_context || !parent->sighand)
		return -1;

	child->files = NULL;
	child->fs_context = NULL;
	child->sighand = NULL;
	if (clone_flags & LXP_CLONE_FILES) {
		if (parent->files->refs == UINT16_MAX)
			goto fail;
		child->files = parent->files;
		parent->files->refs++;
	} else {
		child->files = parent->files;
		if (lxp_fd_fork_inherit(child) != 0) {
			child->files = NULL;
			goto fail;
		}
	}

	if (clone_flags & LXP_CLONE_FS) {
		if (parent->fs_context->refs == UINT16_MAX)
			goto fail;
		child->fs_context = parent->fs_context;
		child->fs_context->refs++;
	} else {
		child->fs_context = fs_context_new();
		if (!child->fs_context)
			goto fail;
		memcpy(child->fs_context->cwd, parent->fs_context->cwd,
		       sizeof(child->fs_context->cwd));
		child->fs_context->umask = parent->fs_context->umask;
	}

	if (clone_flags & LXP_CLONE_SIGHAND) {
		if (parent->sighand->refs == UINT16_MAX)
			goto fail;
		child->sighand = parent->sighand;
		child->sighand->refs++;
	} else {
		child->sighand = sighand_new();
		if (!child->sighand)
			goto fail;
		memcpy(child->sighand->handler, parent->sighand->handler,
		       sizeof(child->sighand->handler));
		child->sighand->restorer = parent->sighand->restorer;
	}
	return 0;

fail:
	lxp_proc_resources_put(child);
	return -1;
}

int lxp_proc_mm_fork(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags)
{
	if (!child || !parent || !parent->mm)
		return -1;
	child->mm = NULL;
	if (clone_flags & LXP_CLONE_VM) {
		if (parent->mm->refs == UINT16_MAX)
			return -1;
		child->mm = parent->mm;
		child->mm->refs++;
		return 0;
	}
	lxp_mm_t *copy = mm_new();
	if (!copy)
		return -1;
	uint16_t refs = copy->refs;
	*copy = *parent->mm;
	copy->refs = refs;
	child->mm = copy;
	return 0;
}

void lxp_proc_mm_put(lxp_proc_t *proc)
{
	if (!proc || !proc->mm)
		return;
	if (proc->mm->refs > 0 && --proc->mm->refs == 0)
		memset(proc->mm, 0, sizeof(*proc->mm));
	proc->mm = NULL;
}

int lxp_proc_group_fork(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags,
			int child_pid)
{
	if (!child || !parent || !parent->group || child_pid <= 0)
		return -1;
	child->group = NULL;
	if (clone_flags & LXP_CLONE_THREAD) {
		if (parent->group->refs == UINT16_MAX)
			return -1;
		child->group = parent->group;
		child->group->refs++;
		return 0;
	}
	lxp_thread_group_t *group = group_new();
	if (!group)
		return -1;
	group->tgid = child_pid;
	group->ppid = parent->group->tgid;
	group->pgid = parent->group->pgid;
	child->group = group;
	return 0;
}

void lxp_proc_group_put(lxp_proc_t *proc)
{
	if (!proc || !proc->group)
		return;
	if (proc->group->refs > 0 && --proc->group->refs == 0)
		memset(proc->group, 0, sizeof(*proc->group));
	proc->group = NULL;
}

static void proc_child_reset(lxp_proc_t *child)
{
	memset(child, 0, sizeof(*child));
	child->vfork_parent = lxp_slot_ref_none();
	child->snapshot = lxp_region_ref_none();
}

void lxp_proc_child_discard(lxp_proc_t *child)
{
	if (!child)
		return;
	lxp_proc_resources_put(child);
	lxp_proc_mm_put(child);
	lxp_proc_group_put(child);
	proc_child_reset(child);
}

/*
 * Classify every lxp_proc field instead of inheriting the coordinator's
 * transient state by assignment. Shared/copy-owned objects are acquired below.
 * These are the task-local values Linux actually inherits across fork/clone:
 * host I/O bindings, rootfs/image identity, comm, the signal mask, address-space
 * layout boundary and FDPIC mode. Everything else deliberately remains in the
 * reset state until the coordinator publishes the child.
 */
static void proc_child_copy_values(lxp_proc_t *child, const lxp_proc_t *parent, int child_pid)
{
	proc_child_reset(child);
	child->write_fn = parent->write_fn;
	child->read_fn = parent->read_fn;
	child->console_poll = parent->console_poll;
	child->io_ctx = parent->io_ctx;
	child->fs = parent->fs;
	child->fs_count = parent->fs_count;
	child->pid = child_pid;
	child->nice = lxp_proc_nice_get(parent);
	memcpy(child->comm, parent->comm, sizeof(child->comm));
	child->sig_blocked = parent->sig_blocked;
	child->exec_file_idx = parent->exec_file_idx;
	child->stack_lo = parent->stack_lo;
	child->is_fdpic = parent->is_fdpic;
}

static int proc_init_child(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags,
			   int child_pid, int thread)
{
	if (!child || !parent || child == parent || child_pid <= 0 || !parent->mm ||
	    !parent->files || !parent->fs_context || !parent->sighand || !parent->group)
		return LXP_ERR_INVALID_PARAM;
	if ((clone_flags & LXP_CLONE_SIGHAND) && !(clone_flags & LXP_CLONE_VM))
		return LXP_ERR_INVALID_PARAM;
	if (thread) {
		if ((clone_flags & (LXP_CLONE_THREAD | LXP_CLONE_VM | LXP_CLONE_SIGHAND)) !=
		    (LXP_CLONE_THREAD | LXP_CLONE_VM | LXP_CLONE_SIGHAND))
			return LXP_ERR_INVALID_PARAM;
	} else if (clone_flags & LXP_CLONE_THREAD) {
		return LXP_ERR_INVALID_PARAM;
	}

	proc_child_copy_values(child, parent, child_pid);
	if (lxp_proc_mm_fork(child, parent, clone_flags) != 0 ||
	    lxp_proc_resources_fork(child, parent, clone_flags) != 0 ||
	    lxp_proc_group_fork(child, parent, clone_flags, child_pid) != 0) {
		lxp_proc_child_discard(child);
		return LXP_ERR_NO_MEMORY;
	}
	return LXP_OK;
}

int lxp_proc_init_process_child(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags,
				int child_pid)
{
	return proc_init_child(child, parent, clone_flags, child_pid, 0);
}

int lxp_proc_init_thread_child(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags,
			       int child_tid)
{
	return proc_init_child(child, parent, clone_flags, child_tid, 1);
}

int lxp_proc_init(lxp_proc_t *proc, lxp_arena_t *arena, size_t brk_bytes)
{
	if (!proc || !arena)
		return LXP_ERR_INVALID_PARAM;

	memset(proc, 0, sizeof(*proc));
	proc->mm = mm_new();
	proc->group = group_new();
	proc->files = files_new();
	proc->fs_context = fs_context_new();
	proc->sighand = sighand_new();
	if (!proc->mm || !proc->group || !proc->files || !proc->fs_context || !proc->sighand) {
		lxp_proc_resources_put(proc);
		lxp_proc_mm_put(proc);
		lxp_proc_group_put(proc);
		return LXP_ERR_NO_MEMORY;
	}
	proc->mm->arena = arena;
	proc->pid = 1; /* the initial task is tid/tgid 1 (ppid 0); fork assigns the rest */
	proc->group->tgid = 1;
	proc->group->pgid = 1;
	/*
	 * Console backing 0 is readable; backing 1 is writable. lxp_fd_install()
	 * chooses the lowest free descriptor, so these become stdin/out/err.
	 */
	if (lxp_fd_install(proc, LXP_FD_CONSOLE, 0, LXP_O_RDWR) != 0 ||
	    lxp_fd_install(proc, LXP_FD_CONSOLE, 1, LXP_O_RDWR) != 1 ||
	    lxp_fd_install(proc, LXP_FD_CONSOLE, 1, LXP_O_RDWR) != 2) {
		lxp_proc_resources_put(proc);
		lxp_proc_mm_put(proc);
		lxp_proc_group_put(proc);
		return LXP_ERR_NO_MEMORY;
	}
	if (brk_bytes) {
		void *brk = lxp_arena_alloc(arena, brk_bytes);
		if (!brk) {
			lxp_proc_resources_put(proc);
			lxp_proc_mm_put(proc);
			lxp_proc_group_put(proc);
			return LXP_ERR_NO_MEMORY;
		}
		proc->mm->brk_base = (uintptr_t)brk;
		proc->mm->brk_cur = proc->mm->brk_base;
		proc->mm->brk_max = proc->mm->brk_base + brk_bytes;
	}
	return LXP_OK;
}

int lxp_proc_nice_get(const lxp_proc_t *proc)
{
	return proc ? __atomic_load_n(&proc->nice, __ATOMIC_ACQUIRE) : 0;
}

void lxp_proc_nice_set(lxp_proc_t *proc, int nice)
{
	if (!proc)
		return;
	if (nice < -20)
		nice = -20;
	else if (nice > 19)
		nice = 19;
	__atomic_store_n(&proc->nice, nice, __ATOMIC_RELEASE);
}

uint32_t lxp_nice_weight(int nice)
{
	if (nice < -20)
		nice = -20;
	else if (nice > 19)
		nice = 19;
	return (uint32_t)(20 - nice);
}

void lxp_proc_bind_exec_capture(lxp_proc_t *proc, lxp_exec_capture_t *capture)
{
	if (!proc)
		return;
	proc->exec_capture = capture;
	if (capture)
		memset(capture, 0, sizeof(*capture));
}

void lxp_proc_set_rootfs(lxp_proc_t *proc, const lxp_file_t *files, int count)
{
	if (!proc)
		return;
	proc->fs = files;
	proc->fs_count = (files && count > 0) ? count : 0;
}
