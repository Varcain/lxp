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

#include "lxp_arena.h"
#include "lxp/lxp_debug.h"
#include "lxp/lxp_diag.h"
#include "lxp_guest.h"
#include "lxp_provider.h" /* g_lxp_os_ops: the engine every coordinator unit uses */
#include "lxp/lxp_latency.h"
#include "proc/lxp_proc.h"
#include "lxp/lxp_seam.h"
#include "run/lxp_runtime_store.h" /* LXP_SERVICE_CLASSES */
#include "signal/lxp_signal_policy.h"


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
int lxp_slot_runnable_load(int slot);
void lxp_slot_runnable_store(int slot, int runnable);
uint32_t lxp_slot_generation(int slot);
lxp_slot_ref_t lxp_slot_ref_at(int slot);
int lxp_slot_publish_image(int slot, lxp_proc_t *image, lxp_exec_capture_t *capture,
			   const lxp_debug_image_t *debug);
/* The slot's process has ended: clear its debugger record (lxp/lxp_debug.h). */
void lxp_slot_debug_clear(int slot);
void lxp_slot_signal_reset(int slot);
void lxp_slot_signal_clone(int child_slot, int parent_slot);
lxp_arena_t *lxp_region_arena(int region);
uint8_t lxp_deferred_state_load(int slot);
void lxp_deferred_slot_reassign(int slot);
void lxp_slot_proc_reset(int slot);

int lxp_lifecycle_failpoint_hit(enum lxp_lifecycle_failpoint point);
#if defined(LXP_TEST_FAILPOINTS)
/* The failpoint the next matching transaction observes (single-shot). */
extern enum lxp_lifecycle_failpoint g_lxp_lifecycle_failpoint;
#endif
/* Open or close the trap gate (run start and teardown). */
void lxp_trap_publish(int active);
/* How long the coordinator may sleep with the given blocked-wait classes pending, in ms. */
unsigned lxp_coordinator_wait_timeout(uint32_t wait_policy, int socket_ready_events,
				  int console_ready_events);
/* End the run: quiesce every slot, release its resources and reset every pool. */
void lxp_coordinator_teardown_all(void);
int lxp_region_lease_matches(lxp_region_ref_t region, lxp_slot_ref_t owner, unsigned refs);
int lxp_region_lease_reassign(lxp_region_ref_t region, lxp_slot_ref_t old_owner,
			      lxp_slot_ref_t new_owner);

void lxp_primary_slot_mark(int slot);
int lxp_primary_slot_pending(int slot);
void lxp_primary_slot_clear(int slot);
void lxp_primary_events_reset(void);
int lxp_claim_slot_event(int slot);
void lxp_event_post_slot(int slot);
struct lxp_claimed_event lxp_coordinator_claim_event(unsigned *cursor);
#if LXP_ENABLE_FS
void lxp_fs_completion_ready(const void *context);
int lxp_fs_completion_hint_take(void);
#endif

void *lxp_lifecycle_prepare_park(int slot, const struct lxp_resume_ctx *ctx);
int lxp_coordinator_abort_slot(int slot);
int lxp_coordinator_park_slot(int slot);
int lxp_coordinator_resume_slot(int slot, int region, const struct lxp_resume_ctx *ctx, long r0);
int lxp_coordinator_complete_slot(lxp_slot_ref_t slot, long r0);
int lxp_coordinator_launch_slot(int slot, int region, const lxp_guest_launch_t *launch);

int lxp_coordinator_guest_view_begin(int slot, lxp_guest_view_t *view);
void lxp_guest_view_failure(int slot, int rc);
int lxp_coordinator_map_mm_range(lxp_mm_t *mm, uintptr_t addr, size_t len, unsigned attrs);
int lxp_coordinator_restore_mm_maps(int slot, const lxp_mm_t *mm);
int lxp_device_map_index(const lxp_proc_t *proc, uintptr_t addr, size_t len);

/* Raise @p sig on the console's foreground process group (src/run/lxp_console_input.c). */
void lxp_console_signal_fg(int sig);
void lxp_flatten_vec(char *buf, const char **ptrs, const char *src_buf, const uint16_t *offsets,
		 int count);
/* Where a signal goes (src/run/lxp_signal_route.c). lxp_signal_send latches @p sig on every
 * live process except init and @p skip that matches: the one with @p pid when it is
 * positive, else the members of process group @p pgid when it is positive, else every
 * process. It wakes the coordinator and returns how many were signalled. */
int lxp_signal_send(const lxp_proc_t *skip, int pid, int pgid, int sig);
void lxp_deliver_signal_parked(int slot, lxp_proc_t *proc, int sig, long ret);
void lxp_notify_parent_stopped(int ppid, int cpid, int stopsig);
void lxp_notify_guest_exit(int slot, const lxp_proc_t *proc);
void lxp_reap_to_parent(int ppid, int cpid, int status, int sigchld);
int lxp_fork_capacity_available(const lxp_proc_t *proc);
int lxp_thread_group_live_count(const lxp_thread_group_t *group);
void lxp_thread_group_request_exit(int source_slot, int status);
int lxp_thread_group_stop_exec_peers(int source_slot, int status);
void lxp_execute_deferred(int slot);

int lxp_region_free(int region);
lxp_region_ref_t lxp_region_reserve(int region, lxp_slot_ref_t owner);
int lxp_region_get(lxp_region_ref_t region);
int lxp_region_put(lxp_region_ref_t region);
int lxp_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t lease_owner);
void lxp_region_mm_put(lxp_proc_t *proc);
int lxp_region_release_if_owned(lxp_region_ref_t region, lxp_slot_ref_t owner);
lxp_region_ref_t lxp_vfork_snapshot(lxp_proc_t *parent, lxp_slot_ref_t child, uintptr_t parent_sp);
int lxp_vfork_restore(lxp_proc_t *parent, lxp_region_ref_t snapshot,
		  lxp_slot_ref_t child, uintptr_t parent_sp);
void lxp_vfork_contain_stale(lxp_slot_ref_t child, lxp_proc_t *proc);
void lxp_vfork_guard_reset(int slot);
/* The trap top half (src/run/lxp_trap.c). */
void lxp_trap_dispatch(struct lxp_frame *f, lxp_proc_t *proc);
void lxp_deferred_state_store(int slot, uint8_t state);
void lxp_coordinator_report_enosys(long nr, long result);
/* End @p slot's process for a coordinator reason (not a signal): record the status,
 * reason and detail, ask for its exit (its whole thread group when @p group), and mark
 * the slot for the primary loop (src/run/lxp_exit.c). */
void lxp_coordinator_exit_slot(int slot, int group, int status, uint8_t reason, uint32_t detail);
/* futex(2) from the trap: answers in @p f->r[0] or parks the caller (src/run/lxp_futex.c). */
void lxp_futex(struct lxp_frame *f, lxp_proc_t *proc, int is_time64);
/* Whether another live thread shares @p proc's address space and could wake its futex wait. */
int lxp_futex_has_corunner(const lxp_proc_t *proc);
/* The slots whose live address space lies in region @p region. */
unsigned lxp_region_live_users(int region);
lxp_region_ref_t lxp_region_ref_at(int region);
/* Forget every lease and snapshot guard at teardown; no guest survives it. */
void lxp_region_runtime_reset(void);

void lxp_handle_fork(int parent_slot, int *next_pid);
void lxp_handle_exec(int slot);
struct lxp_exit_result lxp_handle_exit(int slot);
struct lxp_primary_result lxp_handle_primary_event(int slot, int event, int *next_pid);
struct lxp_blocked_scan lxp_scan_blocked(uint64_t now);
/* The service class the next blocked-slot scan serves, given which classes have work and
 * how long each has waited; -1 when none has. */
int lxp_blocked_service_select(const uint8_t pending[LXP_SERVICE_CLASSES],
			       const uint64_t oldest[LXP_SERVICE_CLASSES], uint64_t now);
void lxp_blocked_fair_reset(void);
#if LXP_ENABLE_NETFS
void lxp_blocked_complete_netfs_retry(int slot, lxp_proc_t *proc,
				      long rc, struct lxp_blocked_scan *scan);
#endif

#endif /* LXP_COORDINATOR_H */
