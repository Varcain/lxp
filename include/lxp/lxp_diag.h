/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_DIAG_H
#define LXP_DIAG_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Version of the structured diagnostic records below. */
#define LXP_DIAG_ABI_VERSION 1u

/** Coordinator-owned native-task lifecycle, exported read-only for diagnostics. */
typedef enum lxp_diag_host_state {
	LXP_DIAG_HOST_FREE,
	LXP_DIAG_HOST_STARTING,
	LXP_DIAG_HOST_RUNNING,
	LXP_DIAG_HOST_PARKING,
	LXP_DIAG_HOST_PARKED,
	LXP_DIAG_HOST_RESUMING,
	LXP_DIAG_HOST_EXITING,
	LXP_DIAG_HOST_DEAD,
	LXP_DIAG_HOST_FAILED,
	LXP_DIAG_HOST_COUNT,
} lxp_diag_host_state_t;

/** Linux-visible state derived from the current task flags. */
typedef enum lxp_diag_task_status {
	LXP_DIAG_TASK_FREE,
	LXP_DIAG_TASK_LIVE,
	LXP_DIAG_TASK_STOPPED,
	LXP_DIAG_TASK_ZOMBIE,
	LXP_DIAG_TASK_COUNT,
} lxp_diag_task_status_t;

/** Pending coordinator intent, reported as one bit (all bits for an invalid kind). */
enum lxp_diag_intent {
	LXP_DIAG_INTENT_NONE = 0,
	LXP_DIAG_INTENT_DEFERRED_SYSCALL = 1u << 0,
	LXP_DIAG_INTENT_FORK = 1u << 1,
	LXP_DIAG_INTENT_EXEC = 1u << 2,
	LXP_DIAG_INTENT_EXIT = 1u << 3,
};

/** Current blocking reason, reported as one bit (all bits for an invalid kind). */
enum lxp_diag_wait {
	LXP_DIAG_WAIT_NONE = 0,
	LXP_DIAG_WAIT_TIMER = 1u << 0,
	LXP_DIAG_WAIT_CHILD = 1u << 1,
	LXP_DIAG_WAIT_FUTEX = 1u << 2,
	LXP_DIAG_WAIT_PIPE = 1u << 3,
	LXP_DIAG_WAIT_CONSOLE = 1u << 4,
	LXP_DIAG_WAIT_DEVICE = 1u << 5,
	LXP_DIAG_WAIT_SOCKET = 1u << 6,
	LXP_DIAG_WAIT_NETFS = 1u << 7,
	LXP_DIAG_WAIT_PTY = 1u << 8,
	LXP_DIAG_WAIT_SIGSUSPEND = 1u << 9,
	LXP_DIAG_WAIT_HOSTFS = 1u << 10,
	LXP_DIAG_WAIT_POLL = 1u << 11,
};

/** One read-only slot dump. Pointer fields are opaque equality identities. */
typedef struct lxp_diag_slot {
	uint32_t abi_version;
	uint32_t struct_size;
	uint32_t generation;
	uint32_t region_generation;
	uint32_t intent_mask;
	uint32_t wait_mask;
	uintptr_t mm_identity;
	uintptr_t files_identity;
	uintptr_t fs_identity;
	uintptr_t sighand_identity;
	uintptr_t group_identity;
	int32_t slot;
	int32_t pid;
	int32_t tgid;
	int32_t ppid;
	int32_t region;
	int32_t vfork_parent_slot;
	int32_t snapshot_region;
	uint16_t region_refs;
	uint16_t mm_refs;
	uint16_t files_refs;
	uint16_t fs_refs;
	uint16_t sighand_refs;
	uint16_t group_refs;
	uint8_t host_state;
	uint8_t task_status;
	uint8_t deferred_state;
	uint8_t runnable;
	uint8_t primary_pending;
	uint8_t signal_depth;
	uint8_t native_task_known;
	uint8_t native_task_present;
} lxp_diag_slot_t;

/** One read-only program-region ownership dump.
 *
 * owner_slot is the temporary reservation-lease holder, or -1 after ownership
 * has transferred to an address space.
 */
typedef struct lxp_diag_region {
	uint32_t abi_version;
	uint32_t struct_size;
	uint32_t generation;
	int32_t region;
	int32_t owner_slot;
	uint16_t refs;
	uint16_t live_users;
} lxp_diag_region_t;

/** Whole-world invariant reported by @ref lxp_validate_world. */
typedef enum lxp_diag_issue {
	LXP_DIAG_OK = 0,
	LXP_DIAG_BAD_SLOT,
	LXP_DIAG_BAD_REGION,
	LXP_DIAG_REGION_OWNER_WITHOUT_REFS,
	LXP_DIAG_REGION_REFS_WITHOUT_OWNER,
	LXP_DIAG_REGION_REFS_WITHOUT_GENERATION,
	LXP_DIAG_LIVE_TASK_WITHOUT_RESOURCES,
	LXP_DIAG_LIVE_TASK_BAD_REGION,
	LXP_DIAG_LIVE_TASK_WITHOUT_REGION_REF,
	LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL,
	LXP_DIAG_FREE_TASK_RUNNABLE,
	LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH,
	LXP_DIAG_PARKED_TASK_RUNNABLE,
	LXP_DIAG_NATIVE_TASK_MISSING,
	LXP_DIAG_NATIVE_TASK_LEAKED,
	LXP_DIAG_HOST_STATE_WITHOUT_GENERATION,
	LXP_DIAG_DEFERRED_STATE_INVALID,
	LXP_DIAG_DEFERRED_GENERATION_STALE,
	LXP_DIAG_MULTIPLE_INTENTS,
	LXP_DIAG_MULTIPLE_WAITS,
	LXP_DIAG_REGION_LEASE_STALE,
	LXP_DIAG_LIVE_TASK_STALE_REGION_REF,
	LXP_DIAG_GUEST_VIEW_LEAKED,
	LXP_DIAG_ISSUE_COUNT,
} lxp_diag_issue_t;

/** First offending location and values from a validation pass. */
typedef struct lxp_diag_error {
	uint32_t abi_version;
	uint32_t struct_size;
	uint32_t issue;
	int32_t slot;
	int32_t region;
	uint32_t actual;
	uint32_t expected;
} lxp_diag_error_t;

/** Exact target-ABI sizes compiled into this LXP image. */
typedef struct lxp_diag_size_report {
	uint32_t abi_version;
	uint32_t struct_size;
	uint32_t slots;
	uint32_t regions;
	size_t proc;
	size_t mm;
	size_t files;
	size_t fs;
	size_t sighand;
	size_t thread_group;
	size_t arena;
	size_t exec_capture;
	size_t resume_context;
	size_t deferred_request;
	size_t signal_save_stack;
	size_t vfork_guard;
	size_t debug_record;
	size_t per_slot_core;
	size_t per_region_core;
	size_t slot_table;
	size_t coordinator_static;
} lxp_diag_size_report_t;

/** Result of automatic coordinator checkpoints during the most recent run. */
typedef struct lxp_diag_health {
	uint32_t abi_version;
	uint32_t struct_size;
	uint32_t checks;
	uint32_t failures;
	lxp_diag_error_t first_error;
	lxp_diag_error_t last_error;
} lxp_diag_health_t;

/**
 * Snapshot one slot or region without changing it.
 *
 * Call these from coordinator context while a run is active, or after
 * @ref lxp_run has returned. The records expose the coordinator's per-slot and
 * per-region state for diagnostics and tests.
 */
int lxp_diag_slot_snapshot(int slot, lxp_diag_slot_t *out);
int lxp_diag_region_snapshot(int region, lxp_diag_region_t *out);

/** Validate the current bounded slot/region world without repairing it. */
int lxp_validate_world(lxp_diag_error_t *error);

/** Exact object/table sizes for this build's ABI and feature configuration. */
void lxp_diag_size_report(lxp_diag_size_report_t *out);

/** Automatic validator checkpoint counts for the most recent run. */
void lxp_diag_health(lxp_diag_health_t *out);

/** Stable, allocation-free names suitable for compact debug output. */
const char *lxp_diag_host_state_name(unsigned state);
const char *lxp_diag_task_status_name(unsigned status);
const char *lxp_diag_issue_name(unsigned issue);

#ifdef __cplusplus
}
#endif

#endif /* LXP_DIAG_H */
