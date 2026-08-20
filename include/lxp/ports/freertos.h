/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Consumer contract for LXP's production FreeRTOS MPU port. The port owns
 * native tasks, exception entry, parking and MPU profile installation; the
 * embedding system owns board memory placement and host-service providers.
 */

#ifndef LXP_PORTS_FREERTOS_H
#define LXP_PORTS_FREERTOS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/arch/cortex_m_cache.h"
#include "lxp/lxp_exec.h"
#include "lxp/lxp_port.h"

#define LXP_FREERTOS_PORT_CONFIG_ABI_VERSION 1u
#define LXP_FREERTOS_ROOTFS_REGION_MAX 2u

typedef int32_t (*lxp_freertos_slot_lookup_t)(uintptr_t identity);

typedef struct lxp_freertos_rootfs_region {
	uintptr_t base;
	size_t size;
	uint8_t texscb;
	uint8_t _reserved[3];
} lxp_freertos_rootfs_region_t;

typedef struct lxp_freertos_port_config {
	uint32_t abi_version;
	uint32_t struct_size;

	/* Board/linker-owned storage. Every stride is explicit so a mismatched
	 * consumer layout fails during prepare instead of corrupting a neighbour. */
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

	/* PMSAv7 policy supplied by the board integration. LXP compiles and
	 * validates the native task descriptors from these logical attributes. */
	uint8_t guest_memory_texscb;
	uint8_t rootfs_region_count;
	uint8_t coordinator_cacheable_map;
	uint8_t coordinator_rootfs_region;
	lxp_freertos_rootfs_region_t rootfs_regions[LXP_FREERTOS_ROOTFS_REGION_MAX];

	lxp_cpu_memory_contract_t cpu_memory_contract;
	struct lxp_cortex_m_cache_geometry *cache_geometry;
	uint32_t guest_quantum_ms;

	/* Board/HAL and host-policy providers. Callbacks execute in the context
	 * documented by lxp_os_ops_t unless noted otherwise. */
	int (*host_prepare)(void);
	int (*time_us)(uint64_t *out);
	int (*time_ns)(uint64_t *out);
	int (*thread_list)(struct lxp_thread_info *out, size_t max_count, size_t *actual_count,
			   lxp_freertos_slot_lookup_t slot_lookup);
	int (*mem_stats)(struct lxp_mem_stats *out);
	const char *(*system_version)(void);
	int (*random_fill)(void *buf, size_t len);
	void (*cache_clean)(const void *base, size_t len);
	void (*cache_invalidate)(const void *base, size_t len);
	int (*validate_memory_contract)(const lxp_cpu_memory_contract_t *declared,
					const struct lxp_cortex_m_cache_geometry *geometry);
	void (*host_fatal)(uint32_t cfsr, uint32_t hfsr, uint32_t pc);

	/* Optional low-overhead observer. Reading the counter happens in the trap;
	 * observer bookkeeping is deliberately excluded from the charged sample. */
	volatile const uint32_t *svc_cycle_counter;
	void (*svc_metrics_record)(uint32_t syscall_nr, uint32_t cycles);
} lxp_freertos_port_config_t;

/** Supplied exactly once by the embedding system. */
extern const lxp_freertos_port_config_t g_lxp_freertos_port_config;

/** Engine table owned by this port and consumed by the host composition. */
extern const lxp_os_ops_t g_lxp_host_engine;

/** Called once per FreeRTOS tick to apply guest-only weighted slicing. */
void lxp_freertos_tick(void);

#endif /* LXP_PORTS_FREERTOS_H */
