/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private contracts between the coordinator core and its compiled policy
 * modules. This header is not installed and is not part of the port ABI.
 */
#ifndef LXP_COORDINATOR_H
#define LXP_COORDINATOR_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_arena.h"
#include "lxp/lxp_diag.h"
#include "lxp/lxp_guest.h"
#include "lxp/lxp_latency.h"
#include "lxp/lxp_proc.h"
#include "lxp/lxp_seam.h"

struct lxp_dbg_s;

enum deferred_state {
	DEFER_IDLE,
	DEFER_FILLING,
	DEFER_READY,
	DEFER_RUNNING,
};

enum slot_lifecycle {
	SLOT_FREE = LXP_DIAG_HOST_FREE,
	SLOT_STARTING = LXP_DIAG_HOST_STARTING,
	SLOT_RUNNING = LXP_DIAG_HOST_RUNNING,
	SLOT_PARKING = LXP_DIAG_HOST_PARKING,
	SLOT_PARKED = LXP_DIAG_HOST_PARKED,
	SLOT_RESUMING = LXP_DIAG_HOST_RESUMING,
	SLOT_EXITING = LXP_DIAG_HOST_EXITING,
	SLOT_DEAD = LXP_DIAG_HOST_DEAD,
	SLOT_FAILED = LXP_DIAG_HOST_FAILED,
};

_Static_assert(SLOT_FAILED + 1 == LXP_DIAG_HOST_COUNT,
	       "private and diagnostic lifecycle states must stay aligned");

enum lxp_lifecycle_failpoint {
	LXP_FAIL_NONE,
	LXP_FAIL_FORK_REGION_ACQUIRED,
	LXP_FAIL_FORK_CHILD_PREPARED,
	LXP_FAIL_FORK_MAPS_PREPARED,
	LXP_FAIL_FORK_CHILD_COUNTED,
	LXP_FAIL_FORK_SNAPSHOT_ACQUIRED,
	LXP_FAIL_FORK_PUBLISHED,
	LXP_FAIL_EXEC_REGION_ACQUIRED,
	LXP_FAIL_EXEC_IMAGE_VALIDATED,
	LXP_FAIL_EXEC_COMMITTED,
	LXP_FAIL_EXEC_IMAGE_PREPARED,
	LXP_FAIL_EXEC_PUBLISHED,
	LXP_FAIL_EXEC_NATIVE_STARTED,
	LXP_FAIL_EXEC_REGION_COMMITTED,
};

struct lxp_claimed_event {
	int slot;
	int type;
};

enum lxp_primary_flow {
	LXP_PRIMARY_SCAN_BLOCKED,
	LXP_PRIMARY_HANDLED,
	LXP_PRIMARY_STOP,
};

struct lxp_primary_result {
	enum lxp_primary_flow flow;
	int status;
};

struct lxp_exit_result {
	int stop_coordinator;
	int status;
};

enum lxp_blocked_wait_policy {
	LXP_BLOCKED_WAIT_POLL = 1u << 0,
	LXP_BLOCKED_WAIT_SOCKET = 1u << 1,
	LXP_BLOCKED_WAIT_CONSOLE = 1u << 2,
};

struct lxp_blocked_scan {
	uint64_t next_deadline_us;
	uint32_t wait_policy;
	uint8_t progress;
	uint8_t any_alive;
	uint8_t any_busy;
};

/* Slot state stays private to lxp_run.c. Resume contexts are borrowed through
 * generation-qualified const views; fork cloning is the only policy mutation. */
const struct lxp_resume_ctx *lxp_slot_resume_view(lxp_slot_ref_t slot);
int lxp_slot_resume_clone_for_fork(lxp_slot_ref_t child, lxp_slot_ref_t parent,
				   uintptr_t child_sp);
lxp_proc_t *lxp_slot_proc(int slot);
uint8_t lxp_slot_host_state(int slot);
void lxp_slot_set_host_state(int slot, uint8_t state);
int slot_runnable_load(int slot);
void slot_runnable_store(int slot, int runnable);
uint32_t slot_generation(int slot);
lxp_slot_ref_t slot_ref_at(int slot);
int lxp_slot_publish_image(int slot, lxp_proc_t *image, lxp_exec_capture_t *capture,
			   const struct lxp_dbg_s *debug);
void lxp_slot_signal_reset(int slot);
void lxp_slot_signal_clone(int child_slot, int parent_slot);
lxp_arena_t *lxp_region_arena(int region);
uint8_t deferred_state_load(int slot);
void deferred_slot_reassign(int slot);
void lxp_slot_proc_reset(int slot);

int lifecycle_failpoint(enum lxp_lifecycle_failpoint point);
int lxp_region_lease_matches(lxp_region_ref_t region, lxp_slot_ref_t owner, unsigned refs);
int lxp_region_lease_reassign(lxp_region_ref_t region, lxp_slot_ref_t old_owner,
			      lxp_slot_ref_t new_owner);

void primary_slot_mark(int slot);
int primary_slot_pending(int slot);
void primary_slot_clear(int slot);
void lxp_primary_events_reset(void);
size_t lxp_primary_events_bytes(void);
int claim_slot_event(int slot);
void lxp_event_post_slot(const lxp_os_ops_t *eng, int slot);
struct lxp_claimed_event coordinator_claim_event(const lxp_os_ops_t *eng, unsigned *cursor);

void *lxp_lifecycle_prepare_park(const lxp_os_ops_t *eng, int slot,
				 const struct lxp_resume_ctx *ctx);
int coordinator_abort_slot(const lxp_os_ops_t *eng, int slot);
int coordinator_park_slot(const lxp_os_ops_t *eng, int slot);
int coordinator_resume_slot(const lxp_os_ops_t *eng, int slot, int region,
			    const struct lxp_resume_ctx *ctx, long r0);
int coordinator_complete_slot(const lxp_os_ops_t *eng, lxp_slot_ref_t slot, long r0);
int coordinator_launch_slot(const lxp_os_ops_t *eng, int slot, int region,
			    const lxp_guest_launch_t *launch);

int coordinator_guest_view_begin(int slot, lxp_guest_view_t *view);
void guest_view_failure(int slot, int rc);
int coordinator_map_mm_range(const lxp_os_ops_t *eng, lxp_mm_t *mm, uintptr_t addr,
			     size_t len, unsigned attrs);
int coordinator_restore_mm_maps(const lxp_os_ops_t *eng, int slot, const lxp_mm_t *mm);
int device_map_index(const lxp_proc_t *proc, uintptr_t addr, size_t len);

void console_signal_fg(int sig);
int pending_deliverable(const lxp_proc_t *proc);
void flatten_vec(char *buf, const char **ptrs, const char *src_buf, const uint16_t *offsets,
		 int count);
void deliver_signal_parked(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc, int sig,
			   long ret);
void notify_parent_stopped(const lxp_os_ops_t *eng, int ppid, int cpid, int stopsig);
void notify_guest_exit(int slot, const lxp_proc_t *proc);
void reap_to_parent(const lxp_os_ops_t *eng, int ppid, int cpid, int status, int sigchld);
int fork_capacity_available(const lxp_proc_t *proc);
int thread_group_live_count(const lxp_thread_group_t *group);
void thread_group_request_exit(int source_slot, int status);
int thread_group_stop_exec_peers(const lxp_os_ops_t *eng, int source_slot, int status);
void execute_deferred(const lxp_os_ops_t *eng, int slot);

int region_free(int region);
lxp_region_ref_t region_reserve(int region, lxp_slot_ref_t owner);
int region_get(lxp_region_ref_t region);
int region_put(lxp_region_ref_t region);
int lxp_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t lease_owner);
void proc_mm_put(lxp_proc_t *proc);
int region_release_if_owned(lxp_region_ref_t region, lxp_slot_ref_t owner);
lxp_region_ref_t vfork_snapshot(const lxp_os_ops_t *eng, lxp_proc_t *parent,
				lxp_slot_ref_t child, uintptr_t parent_sp);
int vfork_restore(const lxp_os_ops_t *eng, lxp_proc_t *parent, lxp_region_ref_t snapshot,
		  lxp_slot_ref_t child, uintptr_t parent_sp);
void vfork_contain_stale(lxp_slot_ref_t child, lxp_proc_t *proc);
void fork_child_guard_reset(int child_slot);

void lxp_handle_fork(const lxp_os_ops_t *eng, int parent_slot, int *next_pid);
void lxp_handle_exec(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg, int slot);
struct lxp_exit_result lxp_handle_exit(const lxp_os_ops_t *eng, int slot);
struct lxp_primary_result lxp_handle_primary_event(const lxp_os_ops_t *eng,
						   const lxp_run_config_t *cfg, int slot,
						   int event, int *next_pid);
struct lxp_blocked_scan lxp_scan_blocked(const lxp_os_ops_t *eng,
					 const lxp_run_config_t *cfg, uint64_t now);
void lxp_blocked_fair_reset(void);
#if LXP_ENABLE_NETFS
void lxp_blocked_complete_netfs_retry(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				      long rc, struct lxp_blocked_scan *scan);
#endif

#endif /* LXP_COORDINATOR_H */
