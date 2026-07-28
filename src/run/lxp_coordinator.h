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
#include "lxp/lxp_guest.h"
#include "lxp/lxp_latency.h"
#include "lxp/lxp_seam.h"

enum deferred_state {
	DEFER_IDLE,
	DEFER_FILLING,
	DEFER_READY,
	DEFER_RUNNING,
};

enum slot_lifecycle {
	SLOT_FREE,
	SLOT_STARTING,
	SLOT_RUNNING,
	SLOT_PARKING,
	SLOT_PARKED,
	SLOT_RESUMING,
	SLOT_EXITING,
	SLOT_DEAD,
	SLOT_FAILED,
};

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

struct lxp_dbg_s {
	uintptr_t text_base;
	uintptr_t data_base;
	uintptr_t entry;
	uintptr_t dynamic;
	uintptr_t interp_base;
};

struct image_txn {
	lxp_proc_t proc;
	lxp_flat_t prog;
	struct lxp_dbg_s debug;
	lxp_slot_ref_t owner;
	lxp_region_ref_t region;
	void *entry;
	void *sp;
	uint8_t *stack_lo;
	int slot;
	uint8_t prepared;
	uint8_t published;
	uint8_t native_started;
	uint8_t region_committed;
};

enum fork_txn_phase {
	FORK_TXN_EMPTY,
	FORK_TXN_PREPARING,
	FORK_TXN_PREPARED,
	FORK_TXN_PUBLISHED,
	FORK_TXN_COMMITTED,
	FORK_TXN_ABORTED,
};

struct fork_txn {
	lxp_proc_t *parent;
	lxp_proc_t *child;
	lxp_slot_ref_t parent_ref;
	lxp_slot_ref_t child_ref;
	lxp_region_ref_t parent_region;
	enum fork_txn_phase phase;
	uint8_t region_acquired;
	uint8_t child_constructed;
	uint8_t maps_touched;
	uint8_t child_counted;
};

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

struct lxp_blocked_scan {
	uint64_t next_deadline_us;
	uint8_t progress;
	uint8_t any_alive;
	uint8_t any_busy;
	uint8_t external_activity;
	uint8_t pipe_wait;
	uint8_t device_wait;
	uint8_t socket_wait;
	uint8_t netfs_wait;
	uint8_t pty_wait;
	uint8_t console_wait;
	uint8_t futex_wait;
};

/* Slot state stays private to lxp_run.c. These are the only mutable operations
 * available to compiled coordinator policy modules. */
struct lxp_resume_ctx *lxp_slot_resume(int slot);
lxp_proc_t *lxp_slot_proc(int slot);
uint8_t lxp_slot_host_state(int slot);
void lxp_slot_set_host_state(int slot, uint8_t state);
int slot_runnable_load(int slot);
void slot_runnable_store(int slot, int runnable);
uint32_t slot_generation(int slot);
lxp_slot_ref_t slot_ref_at(int slot);
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
int coordinator_launch_slot(const lxp_os_ops_t *eng, int slot, int region,
			    const lxp_flat_t *prog, void *entry, void *sp, void *stack_lo);

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
void proc_mm_put(lxp_proc_t *proc);
int region_release_if_owned(lxp_region_ref_t region, lxp_slot_ref_t owner);
lxp_region_ref_t vfork_snapshot(const lxp_os_ops_t *eng, lxp_proc_t *parent,
				lxp_slot_ref_t child, uintptr_t parent_sp);
int vfork_restore(const lxp_os_ops_t *eng, lxp_proc_t *parent, lxp_region_ref_t snapshot,
		  lxp_slot_ref_t child, uintptr_t parent_sp);
void vfork_contain_stale(lxp_slot_ref_t child, lxp_proc_t *proc);
void fork_child_guard_reset(int child_slot);

void image_txn_init(struct image_txn *tx, int slot, lxp_region_ref_t region,
		    lxp_slot_ref_t owner);
int image_txn_prepare(struct image_txn *tx, const lxp_os_ops_t *eng, const uint8_t *data,
		      size_t len, int pid, int ppid, int argc, const char *const argv[],
		      const char *const envp[], int remote_exec);
int image_txn_publish(struct image_txn *tx, const lxp_os_ops_t *eng);
int image_txn_start(struct image_txn *tx, const lxp_os_ops_t *eng);
int image_txn_abort(struct image_txn *tx, const lxp_os_ops_t *eng);

int fork_txn_prepare(struct fork_txn *tx, const lxp_os_ops_t *eng, int parent_slot,
		     int child_slot, uint32_t clone_flags, int child_pid);
int fork_txn_count_child(struct fork_txn *tx);
int fork_txn_snapshot(struct fork_txn *tx, const lxp_os_ops_t *eng, uintptr_t parent_sp);
int fork_txn_publish(struct fork_txn *tx);
void fork_txn_abort(struct fork_txn *tx, const lxp_os_ops_t *eng);
int fork_txn_commit(struct fork_txn *tx);
void fork_parent_resume_error(const lxp_os_ops_t *eng, int parent_slot, long error);

void exec_txn_init(struct exec_txn *tx, int slot);
int exec_txn_reserve(struct exec_txn *tx);
int exec_txn_validate_image(struct exec_txn *tx, const uint8_t *image, size_t image_size,
			    int remote_exec);
int exec_txn_commit(struct exec_txn *tx, const lxp_os_ops_t *eng);
void exec_txn_abort(struct exec_txn *tx, const lxp_os_ops_t *eng, long error, int reason);

void lxp_handle_fork(const lxp_os_ops_t *eng, int parent_slot, int *next_pid);
void lxp_handle_exec(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg, int slot);
struct lxp_exit_result lxp_handle_exit(const lxp_os_ops_t *eng, int slot);
struct lxp_primary_result lxp_handle_primary_event(const lxp_os_ops_t *eng,
						   const lxp_run_config_t *cfg, int slot,
						   int event, int *next_pid);
struct lxp_blocked_scan lxp_scan_blocked(const lxp_os_ops_t *eng,
					 const lxp_run_config_t *cfg, uint64_t now);
#if LXP_ENABLE_NETFS
void lxp_blocked_complete_netfs_retry(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc,
				      long rc, struct lxp_blocked_scan *scan);
#endif

#endif /* LXP_COORDINATOR_H */
