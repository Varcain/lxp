/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Optional low-overhead timing metrics owned by the Linux personality.
 */
#ifndef LXP_RT_METRICS_H
#define LXP_RT_METRICS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lxp_rt_svc_metrics {
	uint32_t calls;
	uint32_t min_cycles;
	uint32_t max_cycles;
	uint64_t total_cycles;
	uint32_t max_syscall;
} lxp_rt_svc_metrics_t;

/** Record one completed Linux SVC. The selected RTOS port is the sole writer. */
void lxp_rt_svc_metrics_record(uint32_t syscall_nr, uint32_t cycles);

/** Rotate the report window and return both it and a coherent lifetime sample. */
void lxp_rt_svc_metrics_take(lxp_rt_svc_metrics_t *window, lxp_rt_svc_metrics_t *total);

/** Return a coherent lifetime sample without rotating the report window. */
void lxp_rt_svc_metrics_snapshot(lxp_rt_svc_metrics_t *total);

/** Return the diagnostic name of a commonly observed ARM EABI syscall. */
const char *lxp_rt_syscall_name(uint32_t syscall_nr);

#ifdef __cplusplus
}
#endif

#endif /* LXP_RT_METRICS_H */
