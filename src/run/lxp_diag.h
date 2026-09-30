/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator diagnostics (src/run/lxp_diag.c): the slot and region records, the
 * whole-world validator, what the run loop tells them, and the state they keep between
 * its calls. Hosts read the resulting health and sizes through lxp/lxp_observe.h.
 */
#ifndef LXP_RUN_DIAG_H
#define LXP_RUN_DIAG_H

#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_observe.h"

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
	uint32_t generation;
	int32_t region;
	int32_t owner_slot;
	uint16_t refs;
	uint16_t live_users;
} lxp_diag_region_t;

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

struct lxp_diag_state {
	/* The native-task census taken by the last lxp_diag_refresh(): whether it is known,
	 * which slots had a live host task, and the lifecycle epoch it describes. */
	uint8_t native_known;
	uint8_t native_present[LXP_NSLOT];
	uint32_t lifecycle_epoch;
	uint32_t native_epoch;
	lxp_diag_health_t health;
};

/* Start a run with no census and a clean health record. */
void lxp_diag_run_begin(void);
/* Drop the census (the host tasks it described are gone). */
void lxp_diag_forget_natives(void);
/* A slot changed hands: a census taken before is stale. */
void lxp_diag_lifecycle_changed(void);
/* Rebuild the ps/top snapshot and the native-task census (run-loop thread only). */
void lxp_diag_refresh(void);
/* Validate the world and record the outcome in the health record. */
void lxp_diag_checkpoint(void);
void lxp_diag_reset_health(void);

#endif /* LXP_RUN_DIAG_H */
