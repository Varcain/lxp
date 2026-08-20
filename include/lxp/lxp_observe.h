/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_OBSERVE_H
#define LXP_OBSERVE_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_diag.h"
#include "lxp/lxp_latency.h"
#include "lxp/lxp_run.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lxp_host;

/** Version of the complete, post-run host observation below. */
#define LXP_HOST_OBSERVATION_ABI_VERSION 1u

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
 * latency counters are quiescent. The copy deliberately groups data which was
 * previously read piecemeal from process-global registries. Latency storage is
 * absent from builds which compile the recorder out.
 */
typedef struct lxp_host_observation {
	uint32_t abi_version;
	uint32_t struct_size;
	lxp_run_health_t run_health;
	lxp_diag_size_report_t sizes;
	lxp_diag_health_t diagnostics;
	lxp_guest_stack_observation_t guest_stack;
#if LXP_ENABLE_LATENCY
	uint32_t latency_service_count;
	uint32_t latency_wake_count;
	lxp_latency_observation_t latency_services[LXP_LAT_CLASSES - 1];
	lxp_latency_observation_t latency_wakes[LXP_NSLOT];
#endif
} lxp_host_observation_t;

/** Copy the complete observation for an initialized, quiescent host.
 * Returns LXP_ERR_BUSY rather than taking a torn snapshot during a run. */
int lxp_host_observe(const struct lxp_host *host, lxp_host_observation_t *out);

/** Stable name for a copied service row, or "?" for an invalid record/index. */
const char *lxp_host_observation_service_name(const lxp_host_observation_t *observation,
					      unsigned row);

#ifdef __cplusplus
}
#endif

#endif /* LXP_OBSERVE_H */
