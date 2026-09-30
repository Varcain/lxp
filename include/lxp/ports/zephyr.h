/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Consumer contract for LXP's production Zephyr Cortex-M port. The port owns
 * native K_USER threads, memory domains, software-fault interposition,
 * parking and guest scheduling; the embedding system owns memory placement
 * and host-service providers.
 */

#ifndef LXP_PORTS_ZEPHYR_H
#define LXP_PORTS_ZEPHYR_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/arch/cortex_m_cache.h"
#include "lxp/lxp_config.h"
#include "lxp/lxp_exec.h"
#include "lxp/lxp_port.h"
#include "lxp/ports/cortex_m.h"


typedef struct lxp_zephyr_port_config {
	/* Storage, memory attributes and host services every Cortex-M port shares.
	 * This port also requires common.thread_list and random_fill below. */
	lxp_cortex_m_port_common_t common;

	/* Optional non-static rootfs partition. Static XIP mappings do not need a
	 * domain partition and leave this disabled. */
	uintptr_t rootfs_base;
	size_t rootfs_size;
	uint8_t rootfs_partition_enabled;
	uint8_t guest_priority;
	uint8_t quantum_priority;
	uint32_t guest_quantum_ms;

	int (*random_fill)(void *buf, size_t len);
} lxp_zephyr_port_config_t;

typedef struct lxp_zephyr_fault_diag {
	uint32_t count;
	uint32_t reason;
	uint32_t cfsr;
	uint32_t hfsr;
	uint32_t mmfar;
	uint32_t bfar;
	uint32_t pc;
	uint32_t suppressed_dump_lines;
} lxp_zephyr_fault_diag_t;

typedef struct lxp_zephyr_critical_metrics {
	uint32_t sections;
	uint32_t max_cycles;
	uint64_t total_cycles;
} lxp_zephyr_critical_metrics_t;

/** Supplied exactly once by the embedding system. */
extern const lxp_zephyr_port_config_t g_lxp_zephyr_port_config;

/** Bounded post-mortem records for contained unprivileged guest faults. */
extern volatile lxp_zephyr_fault_diag_t g_lxp_zephyr_fault_diag[LXP_NSLOT];

/** Rotate the critical-section window and return a coherent lifetime sample. */
void lxp_zephyr_critical_metrics_take(lxp_zephyr_critical_metrics_t *window,
				      lxp_zephyr_critical_metrics_t *total);

#endif /* LXP_PORTS_ZEPHYR_H */
