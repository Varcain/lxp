/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator diagnostics: the ps/top snapshot and native-task census, per-slot and
 * per-region snapshots, the world-consistency validator and its running health record,
 * the static size report, and the names of the reported states.
 */
#include "run/lxp_diag.h"

#include <string.h>

#include "lxp_stats.h"
#include "lxp_internal.h"
#include "lxp_provider.h"
#include "lxp_run_internal.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_runtime_store.h"

/* Latest native-task census collected by lxp_diag_refresh(). A separate known bit
 * distinguishes a clean "no task" result from an engine without introspection
 * or a truncated kernel-thread list. Diagnostic reads never invoke the engine
 * from an arbitrary caller context. */

static uint32_t diag_epoch_next(uint32_t epoch)
{
	epoch++;
	return epoch != 0 ? epoch : 1;
}

static int diag_native_census_current(void)
{
	return g_lxp_rt.diag.native_known &&
	       g_lxp_rt.diag.native_epoch == g_lxp_rt.diag.lifecycle_epoch;
}

/* Rebuild the ps/top snapshot from the live process set + the host kernel threads.
 * Run-loop thread only (the host snapshot may lock its scheduler — unsafe from the svc
 * handler). The seam attaches an explicit slot ID to each guest thread; names
 * remain diagnostic only. The idle thread is folded into /proc/stat idle, not
 * shown as a process (else it crushes top's %CPU math). */
void lxp_diag_refresh(void)
{
	/* Short-lived shell commands must not consume cumulative-CPU slots
	 * forever. The preceding completed snapshot is the safe liveness set. */
	lxp_stats_prune();

	struct lxp_thread_info ti[LXP_MAX_KTHREAD];
	size_t n = 0;
	int trc = lxp_thread_list(ti, LXP_MAX_KTHREAD, &n);
	int overflow = trc == LXP_ERR_QUEUE_FULL;
	if (trc != LXP_OK && trc != LXP_ERR_QUEUE_FULL)
		n = 0; /* no host introspection: /proc shows only the Linux procs */
	if (n > LXP_MAX_KTHREAD) {
		n = LXP_MAX_KTHREAD;
		overflow = 1;
	}
	memset(g_lxp_rt.diag.native_present, 0, sizeof(g_lxp_rt.diag.native_present));
	g_lxp_rt.diag.native_known = trc == LXP_OK;
	g_lxp_rt.diag.native_epoch = g_lxp_rt.diag.lifecycle_epoch;
	for (size_t i = 0; i < n; i++)
		if (ti[i].lxp_slot >= 0 && ti[i].lxp_slot < LXP_NSLOT)
			g_lxp_rt.diag.native_present[ti[i].lxp_slot] = 1;

	/* 1. Charge each live Linux thread's CPU to its explicitly assigned slot. */
	uint64_t idle = 0, busy = 0;
	for (size_t i = 0; i < n; i++) {
		const char *name = ti[i].name ? ti[i].name : "?";
		uint64_t rus = (ti[i].valid_fields & LXP_THREAD_INFO_VALID_RUNNING_TIME)
				       ? ti[i].state_times.running_us
				       : 0;
		int cls = lxp_stats_classify(name);
		if (cls == 1) {
			idle += rus;
			continue;
		}
		busy += rus;
		int s = ti[i].lxp_slot;
		if (s >= 0 && s < LXP_NSLOT && g_lxp_rt.slots[s].proc.alive)
			lxp_stats_charge(g_lxp_rt.slots[s].proc.pid, rus);
	}
	/* 2. Build the snapshot: the live Linux procs, then the kernel threads [name]. */
	lxp_stats_begin();
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
		if (!p->alive)
			continue;
		int running = lxp_slot_runnable_load(s) && p->wait.kind == LXP_WAIT_NONE;
		char state = running ? 'R' : 'S';
		if (lxp_stats_add(p->pid, p->group->ppid, p->comm, state, lxp_proc_cpu_us(p->pid),
				  lxp_proc_nice_get(p), 0) != LXP_OK)
			overflow = 1;
	}
	for (size_t i = 0; i < n; i++) {
		const char *name = ti[i].name ? ti[i].name : "?";
		if (lxp_stats_classify(name) != 0 || ti[i].lxp_slot != LXP_THREAD_SLOT_NONE)
			continue; /* idle or a Linux slot thread */
		int kpid = lxp_kpid_for(name);
		uint64_t running_us = (ti[i].valid_fields & LXP_THREAD_INFO_VALID_RUNNING_TIME)
					      ? ti[i].state_times.running_us
					      : 0;
		if (kpid < 0 || lxp_stats_add(kpid, 0, name, 'S', running_us, 0, 1) != LXP_OK)
			overflow = 1;
	}
	if (overflow)
		(void)lxp_stats_add(LXP_KPID_BASE + LXP_MAX_KTHREAD, 0, "threads-overflow", 'S', 0,
				    0, 1);
	lxp_stats_set_cpu(idle, busy);
}

void lxp_diag_run_begin(void)
{
	memset(&g_lxp_rt.diag, 0, sizeof(g_lxp_rt.diag));
	lxp_diag_reset_health();
}

void lxp_diag_forget_natives(void)
{
	memset(g_lxp_rt.diag.native_present, 0, sizeof(g_lxp_rt.diag.native_present));
	g_lxp_rt.diag.native_known = 0;
}

void lxp_diag_lifecycle_changed(void)
{
	g_lxp_rt.diag.lifecycle_epoch = diag_epoch_next(g_lxp_rt.diag.lifecycle_epoch);
}

static uint32_t diag_intent_mask(int slot)
{
	const lxp_proc_t *p = &g_lxp_rt.slots[slot].proc;
	switch (p->intent.kind) {
	case LXP_INTENT_NONE:
		return LXP_DIAG_INTENT_NONE;
	case LXP_INTENT_DEFERRED_SYSCALL:
		return LXP_DIAG_INTENT_DEFERRED_SYSCALL;
	case LXP_INTENT_FORK:
		return LXP_DIAG_INTENT_FORK;
	case LXP_INTENT_EXEC:
		return LXP_DIAG_INTENT_EXEC;
	case LXP_INTENT_EXIT:
		return LXP_DIAG_INTENT_EXIT;
	default:
		return UINT32_MAX;
	}
}

static uint32_t diag_wait_mask(const lxp_proc_t *p)
{
	switch (p->wait.kind) {
	case LXP_WAIT_NONE:
		return LXP_DIAG_WAIT_NONE;
	case LXP_WAIT_TIMER:
		return LXP_DIAG_WAIT_TIMER;
	case LXP_WAIT_CHILD:
		return LXP_DIAG_WAIT_CHILD;
	case LXP_WAIT_FUTEX:
		return LXP_DIAG_WAIT_FUTEX;
	case LXP_WAIT_PIPE:
		return LXP_DIAG_WAIT_PIPE;
	case LXP_WAIT_CONSOLE:
		return LXP_DIAG_WAIT_CONSOLE;
	case LXP_WAIT_DEVICE:
		return LXP_DIAG_WAIT_DEVICE;
	case LXP_WAIT_SOCKET:
		return LXP_DIAG_WAIT_SOCKET;
	case LXP_WAIT_NETFS:
		return LXP_DIAG_WAIT_NETFS;
	case LXP_WAIT_HOSTFS:
		return LXP_DIAG_WAIT_HOSTFS;
	case LXP_WAIT_PTY:
		return LXP_DIAG_WAIT_PTY;
	case LXP_WAIT_SIGSUSPEND:
		return LXP_DIAG_WAIT_SIGSUSPEND;
	case LXP_WAIT_POLL:
		return LXP_DIAG_WAIT_POLL;
	default:
		return UINT32_MAX;
	}
}

static uint8_t diag_task_status(const lxp_proc_t *p)
{
	if (!p->alive)
		return LXP_DIAG_TASK_FREE;
	if (p->intent.kind == LXP_INTENT_EXIT)
		return LXP_DIAG_TASK_ZOMBIE;
	if (p->stopped)
		return LXP_DIAG_TASK_STOPPED;
	return LXP_DIAG_TASK_LIVE;
}

int lxp_diag_slot_snapshot(int slot, lxp_diag_slot_t *out)
{
	if (!out || slot < 0 || slot >= LXP_NSLOT)
		return LXP_ERR_INVALID_PARAM;
	const lxp_proc_t *p = &g_lxp_rt.slots[slot].proc;
	memset(out, 0, sizeof(*out));
	out->slot = slot;
	out->generation = lxp_slot_generation(slot);
	out->pid = p->pid;
	out->tgid = p->group ? p->group->tgid : 0;
	out->ppid = p->group ? p->group->ppid : 0;
	out->region = p->mm ? p->mm->region.index : -1;
	out->vfork_parent_slot = p->vfork_parent.index;
	out->snapshot_region = p->snapshot.index;
	out->host_state = g_lxp_rt.slots[slot].host_state;
	out->task_status = diag_task_status(p);
	out->deferred_state = lxp_deferred_state_load(slot);
	out->runnable = lxp_slot_runnable_load(slot);
	out->primary_pending = lxp_primary_slot_pending(slot);
	out->signal_depth = g_lxp_sig_save[slot].depth;
	out->native_task_known = diag_native_census_current();
	out->native_task_present = out->native_task_known ? g_lxp_rt.diag.native_present[slot] : 0;
	out->intent_mask = diag_intent_mask(slot);
	out->wait_mask = diag_wait_mask(p);
	out->mm_identity = (uintptr_t)p->mm;
	out->files_identity = (uintptr_t)p->files;
	out->fs_identity = (uintptr_t)p->fs_context;
	out->sighand_identity = (uintptr_t)p->sighand;
	out->group_identity = (uintptr_t)p->group;
	out->mm_refs = p->mm ? p->mm->refs : 0;
	out->files_refs = p->files ? p->files->refs : 0;
	out->fs_refs = p->fs_context ? p->fs_context->refs : 0;
	out->sighand_refs = p->sighand ? p->sighand->refs : 0;
	out->group_refs = p->group ? p->group->refs : 0;
	if (out->region >= 0 && out->region < LXP_NREG) {
		out->region_generation = g_lxp_rt.regions[out->region].generation;
		out->region_refs = g_lxp_rt.regions[out->region].refs;
	}
	return LXP_OK;
}

int lxp_diag_region_snapshot(int region, lxp_diag_region_t *out)
{
	if (!out || region < 0 || region >= LXP_NREG)
		return LXP_ERR_INVALID_PARAM;
	memset(out, 0, sizeof(*out));
	out->region = region;
	/* Kept as owner_slot in diagnostic ABI v1: it now reports only an
	 * uncommitted transaction lease. -1 means the address space owns it. */
	out->owner_slot = g_lxp_rt.regions[region].lease_owner.index;
	out->refs = g_lxp_rt.regions[region].refs;
	out->generation = g_lxp_rt.regions[region].generation;
	out->live_users = lxp_region_live_users(region);
	return LXP_OK;
}

static int diag_error(lxp_diag_error_t *error, lxp_diag_issue_t issue, int slot, int region,
		      uint32_t actual, uint32_t expected)
{
	if (error) {
		memset(error, 0, sizeof(*error));
		error->issue = issue;
		error->slot = slot;
		error->region = region;
		error->actual = actual;
		error->expected = expected;
	}
	return -LXP_EINVAL;
}

static unsigned diag_live_resource_users(const void *identity, int resource)
{
	unsigned users = 0;
	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		const lxp_proc_t *p = &g_lxp_rt.slots[slot].proc;
		if (!p->alive)
			continue;
		const void *candidate = resource == 0	? (const void *)p->mm
					: resource == 1 ? (const void *)p->files
					: resource == 2 ? (const void *)p->fs_context
					: resource == 3 ? (const void *)p->sighand
							: (const void *)p->group;
		if (candidate == identity)
			users++;
	}
	return users;
}

int lxp_validate_world(lxp_diag_error_t *error)
{
	if (error) {
		memset(error, 0, sizeof(*error));
		error->slot = -1;
		error->region = -1;
	}

	for (int region = 0; region < LXP_NREG; region++) {
		lxp_slot_ref_t lease = g_lxp_rt.regions[region].lease_owner;
		int owner = lease.index;
		uint16_t refs = g_lxp_rt.regions[region].refs;
		unsigned live_users = lxp_region_live_users(region);
		if (refs == 0 && owner != -1)
			return diag_error(error, LXP_DIAG_REGION_OWNER_WITHOUT_REFS, owner, region,
					  (uint32_t)owner, UINT32_MAX);
		if (refs != 0 && g_lxp_rt.regions[region].generation == 0)
			return diag_error(error, LXP_DIAG_REGION_REFS_WITHOUT_GENERATION, owner,
					  region, 0, 1);
		if (owner >= 0 && (owner >= LXP_NSLOT || lease.generation == 0 ||
				   !lxp_slot_ref_equal(lease, lxp_slot_ref_at(owner))))
			return diag_error(
				error, LXP_DIAG_REGION_LEASE_STALE, owner, region, lease.generation,
				owner >= 0 && owner < LXP_NSLOT ? lxp_slot_generation(owner) : 0);
		if (refs != 0 && owner < 0 && live_users == 0)
			return diag_error(error, LXP_DIAG_REGION_REFS_WITHOUT_OWNER, -1, region,
					  refs, 0);
	}

	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		const lxp_proc_t *p = &g_lxp_rt.slots[slot].proc;
		uint8_t host = g_lxp_rt.slots[slot].host_state;
		uint8_t deferred = lxp_deferred_state_load(slot);
		uint32_t intents = diag_intent_mask(slot);
		uint32_t waits = diag_wait_mask(p);

		if (host > SLOT_FAILED)
			return diag_error(error, LXP_DIAG_BAD_SLOT, slot, -1, host, SLOT_FAILED);
		if (deferred > DEFER_RUNNING)
			return diag_error(error, LXP_DIAG_DEFERRED_STATE_INVALID, slot, -1,
					  deferred, DEFER_RUNNING);
		if (host != SLOT_FREE && lxp_slot_generation(slot) == 0)
			return diag_error(error, LXP_DIAG_HOST_STATE_WITHOUT_GENERATION, slot, -1,
					  0, 1);
		if (p->alive && lxp_slot_generation(slot) == 0)
			return diag_error(error, LXP_DIAG_HOST_STATE_WITHOUT_GENERATION, slot, -1,
					  0, 1);
		if (deferred != DEFER_IDLE &&
		    (!lxp_slot_ref_is_current(g_lxp_rt.slots[slot].deferred.owner) ||
		     g_lxp_rt.slots[slot].deferred.owner.index != slot))
			return diag_error(error, LXP_DIAG_DEFERRED_GENERATION_STALE, slot, -1,
					  g_lxp_rt.slots[slot].deferred.owner.generation,
					  lxp_slot_generation(slot));
		if (p->intent.kind >= LXP_INTENT_COUNT)
			return diag_error(error, LXP_DIAG_MULTIPLE_INTENTS, slot, -1, intents, 1);
		if (p->wait.kind >= LXP_WAIT_COUNT)
			return diag_error(error, LXP_DIAG_MULTIPLE_WAITS, slot, -1, waits, 1);
		if (deferred >= DEFER_READY && p->intent.kind != LXP_INTENT_DEFERRED_SYSCALL &&
		    p->intent.kind != LXP_INTENT_EXIT)
			return diag_error(error, LXP_DIAG_MULTIPLE_INTENTS, slot, -1, intents,
					  LXP_DIAG_INTENT_DEFERRED_SYSCALL);
		if (p->guest_view)
			return diag_error(error, LXP_DIAG_GUEST_VIEW_LEAKED, slot, -1, 1, 0);

		if (!p->alive) {
			if (lxp_slot_runnable_load(slot))
				return diag_error(error, LXP_DIAG_FREE_TASK_RUNNABLE, slot, -1, 1,
						  0);
			if (diag_native_census_current() && g_lxp_rt.diag.native_present[slot] &&
			    (host == SLOT_FREE || host == SLOT_DEAD))
				return diag_error(error, LXP_DIAG_NATIVE_TASK_LEAKED, slot, -1,
						  host, SLOT_FREE);
			continue;
		}
		if (!p->mm || !p->files || !p->fs_context || !p->sighand || !p->group)
			return diag_error(error, LXP_DIAG_LIVE_TASK_WITHOUT_RESOURCES, slot, -1, 0,
					  5);
		int region = p->mm->region.index;
		if (region < 0 || region >= LXP_NREG)
			return diag_error(error, LXP_DIAG_LIVE_TASK_BAD_REGION, slot, region,
					  (uint32_t)region, LXP_NREG);
		if (g_lxp_rt.regions[region].refs == 0)
			return diag_error(error, LXP_DIAG_LIVE_TASK_WITHOUT_REGION_REF, slot,
					  region, 0, 1);
		if (p->mm->region.generation == 0 ||
		    p->mm->region.generation != g_lxp_rt.regions[region].generation)
			return diag_error(error, LXP_DIAG_LIVE_TASK_STALE_REGION_REF, slot, region,
					  p->mm->region.generation,
					  g_lxp_rt.regions[region].generation);
		unsigned region_users = lxp_region_live_users(region);
		if (g_lxp_rt.regions[region].refs < region_users)
			return diag_error(error, LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL, slot, region,
					  g_lxp_rt.regions[region].refs, region_users);

#define CHECK_RESOURCE_REFS(member, which)                                                   \
	do {                                                                                 \
		unsigned users = diag_live_resource_users(p->member, which);                 \
		if (p->member->refs < users)                                                 \
			return diag_error(error, LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL, slot, \
					  region, p->member->refs, users);                   \
	} while (0)
		CHECK_RESOURCE_REFS(mm, 0);
		CHECK_RESOURCE_REFS(files, 1);
		CHECK_RESOURCE_REFS(fs_context, 2);
		CHECK_RESOURCE_REFS(sighand, 3);
		CHECK_RESOURCE_REFS(group, 4);
#undef CHECK_RESOURCE_REFS

		if (lxp_slot_runnable_load(slot) && host != SLOT_RUNNING && host != SLOT_FAILED &&
		    host != SLOT_STARTING && host != SLOT_RESUMING)
			return diag_error(error, LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH, slot,
					  region, host, SLOT_RUNNING);
		if (host == SLOT_RUNNING && !lxp_slot_runnable_load(slot))
			return diag_error(error, LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH, slot,
					  region, 0, 1);
		if (host == SLOT_PARKED && lxp_slot_runnable_load(slot))
			return diag_error(error, LXP_DIAG_PARKED_TASK_RUNNABLE, slot, region, 1, 0);
		if (diag_native_census_current() &&
		    (host == SLOT_RUNNING || host == SLOT_PARKED || host == SLOT_FAILED) &&
		    !g_lxp_rt.diag.native_present[slot])
			return diag_error(error, LXP_DIAG_NATIVE_TASK_MISSING, slot, region, 0, 1);
	}
	return LXP_OK;
}

void lxp_diag_size_report(lxp_diag_size_report_t *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->slots = LXP_NSLOT;
	out->regions = LXP_NREG;
	out->proc = sizeof(lxp_proc_t);
	out->mm = sizeof(lxp_mm_t);
	out->files = sizeof(lxp_files_t);
	out->fs = sizeof(lxp_fs_context_t);
	out->sighand = sizeof(lxp_sighand_t);
	out->thread_group = sizeof(lxp_thread_group_t);
	out->arena = sizeof(lxp_arena_t);
	out->exec_capture = sizeof(lxp_exec_capture_t);
	out->resume_context = sizeof(struct lxp_resume_ctx);
	out->deferred_request = sizeof(struct deferred_req);
	out->signal_save_stack = sizeof(struct sig_save_stack_s);
	out->vfork_guard = sizeof(struct vfork_snapshot_guard);
	out->debug_record = sizeof(lxp_debug_image_t);
	out->per_slot_core = sizeof(g_lxp_rt.slots[0]) + out->signal_save_stack + out->vfork_guard +
			     out->debug_record;
	out->per_region_core = out->arena + sizeof(g_lxp_rt.regions[0]);
	out->slot_table = sizeof(g_lxp_rt.slots);
	out->coordinator_static = sizeof(g_lxp_rt) + sizeof(g_lxp_dbg) + sizeof(g_lxp_sig_save) +
				  sizeof(g_lxp_trap_gate);
}

void lxp_diag_health(lxp_diag_health_t *out)
{
	if (out)
		*out = g_lxp_rt.diag.health;
}

const char *lxp_diag_host_state_name(unsigned state)
{
	static const char *const names[LXP_DIAG_HOST_COUNT] = {
		[LXP_DIAG_HOST_FREE] = "free",	     [LXP_DIAG_HOST_STARTING] = "starting",
		[LXP_DIAG_HOST_RUNNING] = "running", [LXP_DIAG_HOST_PARKING] = "parking",
		[LXP_DIAG_HOST_PARKED] = "parked",   [LXP_DIAG_HOST_RESUMING] = "resuming",
		[LXP_DIAG_HOST_EXITING] = "exiting", [LXP_DIAG_HOST_DEAD] = "dead",
		[LXP_DIAG_HOST_FAILED] = "failed",
	};
	return state < LXP_DIAG_HOST_COUNT && names[state] ? names[state] : "invalid";
}

const char *lxp_diag_task_status_name(unsigned status)
{
	static const char *const names[LXP_DIAG_TASK_COUNT] = {
		[LXP_DIAG_TASK_FREE] = "free",
		[LXP_DIAG_TASK_LIVE] = "live",
		[LXP_DIAG_TASK_STOPPED] = "stopped",
		[LXP_DIAG_TASK_ZOMBIE] = "zombie",
	};
	return status < LXP_DIAG_TASK_COUNT && names[status] ? names[status] : "invalid";
}

const char *lxp_diag_issue_name(unsigned issue)
{
	static const char *const names[LXP_DIAG_ISSUE_COUNT] = {
		[LXP_DIAG_OK] = "ok",
		[LXP_DIAG_BAD_SLOT] = "bad-slot",
		[LXP_DIAG_BAD_REGION] = "bad-region",
		[LXP_DIAG_REGION_OWNER_WITHOUT_REFS] = "region-owner-without-refs",
		[LXP_DIAG_REGION_REFS_WITHOUT_OWNER] = "region-refs-without-owner",
		[LXP_DIAG_REGION_REFS_WITHOUT_GENERATION] = "region-refs-without-generation",
		[LXP_DIAG_LIVE_TASK_WITHOUT_RESOURCES] = "live-task-without-resources",
		[LXP_DIAG_LIVE_TASK_BAD_REGION] = "live-task-bad-region",
		[LXP_DIAG_LIVE_TASK_WITHOUT_REGION_REF] = "live-task-without-region-ref",
		[LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL] = "resource-refcount-too-small",
		[LXP_DIAG_FREE_TASK_RUNNABLE] = "free-task-runnable",
		[LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH] = "runnable-host-state-mismatch",
		[LXP_DIAG_PARKED_TASK_RUNNABLE] = "parked-task-runnable",
		[LXP_DIAG_NATIVE_TASK_MISSING] = "native-task-missing",
		[LXP_DIAG_NATIVE_TASK_LEAKED] = "native-task-leaked",
		[LXP_DIAG_HOST_STATE_WITHOUT_GENERATION] = "host-state-without-generation",
		[LXP_DIAG_DEFERRED_STATE_INVALID] = "deferred-state-invalid",
		[LXP_DIAG_DEFERRED_GENERATION_STALE] = "deferred-generation-stale",
		[LXP_DIAG_MULTIPLE_INTENTS] = "multiple-intents",
		[LXP_DIAG_MULTIPLE_WAITS] = "multiple-waits",
		[LXP_DIAG_REGION_LEASE_STALE] = "region-lease-stale",
		[LXP_DIAG_LIVE_TASK_STALE_REGION_REF] = "live-task-stale-region-ref",
		[LXP_DIAG_GUEST_VIEW_LEAKED] = "guest-view-leaked",
	};
	return issue < LXP_DIAG_ISSUE_COUNT && names[issue] ? names[issue] : "invalid";
}

void lxp_diag_reset_health(void)
{
	memset(&g_lxp_rt.diag.health, 0, sizeof(g_lxp_rt.diag.health));
	g_lxp_rt.diag.health.first_error.slot = -1;
	g_lxp_rt.diag.health.first_error.region = -1;
	g_lxp_rt.diag.health.last_error.slot = -1;
	g_lxp_rt.diag.health.last_error.region = -1;
}

void lxp_diag_checkpoint(void)
{
	lxp_diag_error_t error;
	g_lxp_rt.diag.health.checks++;
	if (lxp_validate_world(&error) == LXP_OK)
		return;
	if (g_lxp_rt.diag.health.failures++ == 0)
		g_lxp_rt.diag.health.first_error = error;
	g_lxp_rt.diag.health.last_error = error;
}
