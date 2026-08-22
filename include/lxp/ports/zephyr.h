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

#define LXP_ZEPHYR_PORT_CONFIG_ABI_VERSION 3u

typedef int32_t (*lxp_zephyr_slot_lookup_t)(uintptr_t identity);

typedef struct lxp_zephyr_port_config {
	uint32_t abi_version;
	uint32_t struct_size;

	/* Board/linker-owned external storage. Strides and counts are checked
	 * before the first guest is made runnable. */
	uint8_t *program_regions;
	size_t program_region_stride;
	size_t program_region_count;
	uint8_t *dynamic_pools;
	size_t dynamic_pool_stride;
	size_t dynamic_pool_count;
	lxp_exec_capture_t *exec_captures;
	size_t exec_capture_count;
	uint8_t *exec_stage;
	size_t exec_stage_size;

	/* Optional non-static rootfs partition. Static XIP mappings do not need a
	 * domain partition and leave this disabled. */
	uintptr_t rootfs_base;
	size_t rootfs_size;
	uint8_t rootfs_partition_enabled;
	uint8_t guest_memory_texscb;
	uint8_t guest_priority;
	uint8_t quantum_priority;
	uint32_t guest_quantum_ms;

	lxp_cpu_memory_contract_t cpu_memory_contract;
	struct lxp_cortex_m_cache_geometry *cache_geometry;

	/* Board/HAL and product-policy providers. */
	int (*host_prepare)(void);
	int (*time_us)(uint64_t *out);
	int (*time_ns)(uint64_t *out);
	int (*thread_list)(struct lxp_thread_info *out, size_t max_count, size_t *actual_count,
			   lxp_zephyr_slot_lookup_t slot_lookup);
	int (*mem_stats)(struct lxp_mem_stats *out);
	const char *system_version;
	int (*random_fill)(void *buf, size_t len);
	int (*validate_memory_contract)(const lxp_cpu_memory_contract_t *declared,
					const struct lxp_cortex_m_cache_geometry *geometry);
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

/** Engine table owned by this port and consumed by the host composition. */
extern const lxp_os_ops_t g_lxp_host_engine;

/** Bounded post-mortem records for contained unprivileged guest faults. */
extern volatile lxp_zephyr_fault_diag_t g_lxp_zephyr_fault_diag[LXP_NSLOT];

/** Rotate the critical-section window and return a coherent lifetime sample. */
void lxp_zephyr_critical_metrics_take(lxp_zephyr_critical_metrics_t *window,
				      lxp_zephyr_critical_metrics_t *total);

#endif /* LXP_PORTS_ZEPHYR_H */
