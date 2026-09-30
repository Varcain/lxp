/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * What a host can read about its most recent run: coordinator health, object sizes and
 * invariant checks, guest stack use, and latency histograms. The layout is the same in
 * every build; a build without LXP_ENABLE_LATENCY reports zero latency rows.
 */

#ifndef LXP_OBSERVE_H
#define LXP_OBSERVE_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_run.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lxp_host;

/* ---- invariant checks and sizes ------------------------------------------------ */

/** A coordinator invariant that a validation checkpoint found broken. */
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
	uint32_t issue;
	int32_t slot;
	int32_t region;
	uint32_t actual;
	uint32_t expected;
} lxp_diag_error_t;

/** Exact target-ABI sizes compiled into this LXP image. */
typedef struct lxp_diag_size_report {
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
	/** The coordinator's static RAM: its runtime record, debugger records, signal-save
	 *  stacks and trap gate. */
	size_t coordinator_static;
} lxp_diag_size_report_t;

/** Result of automatic coordinator checkpoints during the most recent run. */
typedef struct lxp_diag_health {
	uint32_t checks;
	uint32_t failures;
	lxp_diag_error_t first_error;
	lxp_diag_error_t last_error;
} lxp_diag_health_t;

/** Stable, allocation-free name of issue @p issue, or "?" for an unknown one. */
const char *lxp_diag_issue_name(unsigned issue);

/* ---- latency histograms ------------------------------------------------------ */

/* Exponential buckets: [0]<1us, [1]<2us, [2]<4us ... [7]>=64us. The top bucket
 * is open-ended, so a max_ns far above 64us reads as an outlier rather than
 * being lost in it. */
#define LXP_LAT_BUCKETS 8

typedef struct lxp_lat_stat {
	uint32_t count;			  /**< events recorded */
	uint32_t max_ns;		  /**< worst observed, nanoseconds */
	uint32_t buckets[LXP_LAT_BUCKETS]; /**< distribution, see LXP_LAT_BUCKETS */
} lxp_lat_stat_t;

/** Service rows in an observation: one per coordinator event class. */
#define LXP_LAT_SERVICE_ROWS 15
/** Wake rows in an observation: one per slot. */
#define LXP_LAT_WAKE_ROWS LXP_NSLOT

/**
 * Record @p ns into a caller-owned @p s.
 *
 * The module's own counters are kept with this. It is public, and built whether or
 * not LXP_ENABLE_LATENCY is, so a port can measure a host-side quantity (e.g. how
 * late a periodic task woke while the coordinator held a critical section) into the
 * same buckets. Those numbers are only meaningful against the coordinator's if both
 * are binned identically, and a second copy of the bucket rule would drift.
 */
void lxp_lat_record(lxp_lat_stat_t *s, uint64_t ns);

/** Name of event class @p cls, a service row's id ("EXIT", "DEFER", ...), or "?". */
const char *lxp_lat_class_name(int cls);

/* ---- the observation ------------------------------------------------------- */

/** One copied latency row. @p id is a service class or guest slot. */
typedef struct lxp_latency_observation {
	uint32_t id;
	lxp_lat_stat_t stat;
} lxp_latency_observation_t;

/** Normalized aggregate of native guest-task stack use. */
typedef struct lxp_guest_stack_observation {
	size_t used;
	size_t size;
	uint32_t available;
} lxp_guest_stack_observation_t;

/**
 * One self-contained observation of the most recently completed run.
 *
 * Take this after lxp_host_run() returns, when coordinator-owned diagnostic and
 * latency counters are quiescent.
 */
typedef struct lxp_host_observation {
	lxp_run_health_t run_health;
	lxp_diag_size_report_t sizes;
	lxp_diag_health_t diagnostics;
	lxp_guest_stack_observation_t guest_stack;
	uint32_t latency_service_count; /**< Rows filled; 0 without LXP_ENABLE_LATENCY. */
	uint32_t latency_wake_count;	/**< Rows filled; 0 without LXP_ENABLE_LATENCY. */
	lxp_latency_observation_t latency_services[LXP_LAT_SERVICE_ROWS];
	lxp_latency_observation_t latency_wakes[LXP_LAT_WAKE_ROWS];
} lxp_host_observation_t;

/** Copy the complete observation for an initialized, quiescent host.
 * Returns LXP_ERR_BUSY rather than taking a torn snapshot during a run. */
int lxp_host_observe(const struct lxp_host *host, lxp_host_observation_t *out);

#ifdef __cplusplus
}
#endif

#endif /* LXP_OBSERVE_H */
