/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Parent-visible child events: complete an eligible wait4 or retain one
 * bounded status record and notify the parent with SIGCHLD.
 */

#include "run/lxp_coordinator.h"

#include "lxp_internal.h"
#include "lxp_run_internal.h"

struct lxp_child_event {
	int pid;
	int value;
	uint8_t kind;
	uint8_t notify;
};

static int child_wait_accepts(const lxp_proc_t *proc, const struct lxp_child_event *event)
{
	return proc->wait.kind == LXP_WAIT_CHILD &&
	       (proc->wait.data.child.pid <= 0 || proc->wait.data.child.pid == event->pid) &&
	       (event->kind != LXP_CHILD_STOPPED ||
		(proc->wait.data.child.options & LXP_WUNTRACED));
}

static lxp_proc_t *parent_task_for_child(int ppid, const struct lxp_child_event *event)
{
	lxp_proc_t *fallback = NULL;
	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		lxp_proc_t *proc = lxp_slot_proc(slot);
		if (!proc || !proc->alive || !proc->group || proc->group->tgid != ppid)
			continue;
		if (!fallback)
			fallback = proc;
		if (child_wait_accepts(proc, event))
			return proc;
	}
	return fallback;
}

static int child_wait_status(const struct lxp_child_event *event)
{
	return event->kind == LXP_CHILD_STOPPED ? lxp_encode_wstopped(event->value)
						: lxp_encode_wstatus(event->value);
}

static void child_event_publish(int ppid, const struct lxp_child_event *event)
{
	lxp_proc_t *parent = parent_task_for_child(ppid, event);
	if (!parent)
		return;
	if (event->kind == LXP_CHILD_EXITED && parent->group->live_children > 0)
		parent->group->live_children--;

	if (child_wait_accepts(parent, event)) {
		if (parent->wait.data.child.status)
			*(int *)(uintptr_t)parent->wait.data.child.status =
				child_wait_status(event);
		int slot = slot_of(parent);
		(void)lxp_wait_complete(parent, LXP_WAIT_CHILD);
		coordinator_park_slot(slot);
		(void)coordinator_complete_slot(slot_ref_at(slot), event->pid);
		return;
	}

	if (parent->group->child_count >= 0 && parent->group->child_count < LXP_MAX_CHILD) {
		int index = parent->group->child_count++;
		parent->group->child_pid[index] = event->pid;
		parent->group->child_status[index] = event->value;
		parent->group->child_kind[index] = event->kind;
	}
	if (event->notify)
		lxp_signal_latch(parent, LXP_SIGCHLD);
}

void reap_to_parent(int ppid, int cpid, int status, int sigchld)
{
	const struct lxp_child_event event = {
		.pid = cpid,
		.value = status,
		.kind = LXP_CHILD_EXITED,
		.notify = sigchld != 0,
	};
	child_event_publish(ppid, &event);
}

void notify_parent_stopped(int ppid, int cpid, int stopsig)
{
	const struct lxp_child_event event = {
		.pid = cpid,
		.value = stopsig,
		.kind = LXP_CHILD_STOPPED,
		.notify = 1,
	};
	child_event_publish(ppid, &event);
}
