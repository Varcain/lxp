/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Configuration shared by LXP's Cortex-M OS ports. Each port's own configuration
 * embeds it as `.common`: the storage the guests run in, their memory attributes,
 * and the host services every port forwards unchanged.
 */

#ifndef LXP_PORTS_CORTEX_M_H
#define LXP_PORTS_CORTEX_M_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/arch/cortex_m_cache.h"
#include "lxp/lxp_exec.h"
#include "lxp/lxp_port.h"

/** Map a native thread identity to its LXP slot, or LXP_THREAD_SLOT_NONE. */
typedef int32_t (*lxp_cortex_m_slot_lookup_t)(uintptr_t identity);

typedef struct lxp_cortex_m_port_common {
	/* Board/linker-owned storage: LXP_NREG program regions and dynamic pools and
	 * LXP_NSLOT exec captures. Every stride is explicit so a mismatched consumer
	 * layout fails during prepare instead of corrupting a neighbour. */
	uint8_t *program_regions;
	size_t program_region_stride;
	size_t program_region_count;
	uint8_t *dynamic_pools;
	size_t dynamic_pool_stride;
	size_t dynamic_pool_count;
	lxp_exec_capture_t *exec_captures;
	size_t exec_capture_count;
	/* Staging buffer for an image fetched over netfs; required with LXP_ENABLE_NETFS_EXEC. */
	uint8_t *exec_stage;
	size_t exec_stage_size;

	/* PMSAv7 attributes (TEX/S/C/B) of guest program memory, the CPU-memory
	 * contract the core validates, and the caches to maintain (NULL: none). */
	uint8_t guest_memory_texscb;
	lxp_cpu_memory_contract_t cpu_memory_contract;
	struct lxp_cortex_m_cache_geometry *cache_geometry;

	/* Host services. host_prepare is optional everywhere; a port states which of
	 * the others beyond time_us, time_ns, mem_stats, system_version and
	 * validate_memory_contract it also requires. */
	/* Returns LXP_OK, or an lxp_err_t that the port's prepare() reports. */
	int (*host_prepare)(void);
	int (*time_us)(uint64_t *out);
	int (*time_ns)(uint64_t *out);
	int (*thread_list)(struct lxp_thread_info *out, size_t max_count, size_t *actual_count,
			   lxp_cortex_m_slot_lookup_t slot_lookup);
	int (*mem_stats)(struct lxp_mem_stats *out);
	const char *system_version;
	int (*validate_memory_contract)(const lxp_cpu_memory_contract_t *declared,
					const struct lxp_cortex_m_cache_geometry *geometry);
} lxp_cortex_m_port_common_t;

#endif /* LXP_PORTS_CORTEX_M_H */
