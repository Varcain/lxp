/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Consumer contract for LXP's production NuttX Cortex-M port. The port owns
 * native guest tasks, SVCall/fault interposition, scheduler-note integration,
 * parking and MPU profiles; the embedding system owns memory placement and
 * host-service providers.
 */

#ifndef LXP_PORTS_NUTTX_H
#define LXP_PORTS_NUTTX_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/arch/cortex_m_cache.h"
#include "lxp/lxp_exec.h"
#include "lxp/lxp_port.h"

#define LXP_NUTTX_PORT_CONFIG_ABI_VERSION 1u

typedef int32_t (*lxp_nuttx_slot_lookup_t)(uintptr_t identity);

typedef struct lxp_nuttx_mpu_region {
	uintptr_t base;
	size_t size;
	uint8_t texscb;
	uint8_t subregion_disable;
	uint8_t enabled;
	uint8_t _reserved;
} lxp_nuttx_mpu_region_t;

typedef struct lxp_nuttx_port_config {
	uint32_t abi_version;
	uint32_t struct_size;

	/* Board/linker-owned storage. Strides and counts are validated before any
	 * guest is made runnable. Slot stacks hold trusted NuttX TLS metadata. */
	uint8_t *program_regions;
	size_t program_region_stride;
	size_t program_region_count;
	uint8_t *dynamic_pools;
	size_t dynamic_pool_stride;
	size_t dynamic_pool_count;
	lxp_exec_capture_t *exec_captures;
	size_t exec_capture_count;
	uint8_t *slot_stacks;
	size_t slot_stack_stride;
	size_t slot_stack_size;
	size_t slot_stack_count;
	uint8_t *exec_stage;
	size_t exec_stage_size;

	/* Complete static PMSAv7 policy. LXP owns fixed region numbers and dynamic
	 * overlays; the host supplies physical layout and memory attributes. */
	lxp_nuttx_mpu_region_t code_region;
	lxp_nuttx_mpu_region_t pool_region;
	lxp_nuttx_mpu_region_t rootfs_region;
	uint8_t guest_memory_texscb;
	uint8_t guest_priority;
	uint8_t _reserved_policy[2];
	uintptr_t trusted_tcb_base;
	uintptr_t trusted_tcb_end;

	lxp_cpu_memory_contract_t cpu_memory_contract;
	struct lxp_cortex_m_cache_geometry *cache_geometry;

	/* Board/HAL and product-policy providers. Runtime callbacks are driven by
	 * the port's scheduler-note hook and may be omitted when attribution is not
	 * required. */
	int (*host_prepare)(void);
	int (*time_us)(uint64_t *out);
	int (*time_ns)(uint64_t *out);
	int (*host_thread_list)(struct lxp_thread_info *out, size_t max_count, size_t *actual_count,
				lxp_nuttx_slot_lookup_t slot_lookup);
	int (*mem_stats)(struct lxp_mem_stats *out);
	const char *(*system_version)(void);
	int (*validate_memory_contract)(const lxp_cpu_memory_contract_t *declared,
					const struct lxp_cortex_m_cache_geometry *geometry);
	void (*runtime_reset)(int32_t current_pid);
	void (*runtime_start)(int32_t pid);
	void (*runtime_stop)(int32_t pid);
	void (*runtime_switch)(int32_t next_pid);
	uint64_t (*runtime_us)(int32_t pid);

	/* Optional low-overhead observer. The cycle endpoint is sampled before
	 * observer bookkeeping so telemetry is excluded from the charged SVC. */
	void (*svc_metrics_record)(uint32_t syscall_nr, uint32_t cycles);
} lxp_nuttx_port_config_t;

/** Supplied exactly once by the embedding system. */
extern const lxp_nuttx_port_config_t g_lxp_nuttx_port_config;

/** Engine table owned by this port and consumed by the host composition. */
extern const lxp_os_ops_t g_lxp_host_engine;

#endif /* LXP_PORTS_NUTTX_H */
