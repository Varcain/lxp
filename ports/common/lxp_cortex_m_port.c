/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Services shared by LXP's Cortex-M OS ports (see lxp_cortex_m_port.h).
 */

#include "lxp_cortex_m_port.h"

#include "lxp/arch/cortex_m_cache.h"

#define COMMON (*g_lxp_cortex_m_port_common)

int lxp_cortex_m_port_config_valid(void)
{
	const size_t program_bytes = (size_t)LXP_NREG * LXP_PROG_REGION_SIZE;
	const size_t dynamic_bytes = (size_t)LXP_NREG * LXP_DYN_POOL_SIZE;
	if (!COMMON.program_regions || COMMON.program_region_stride != LXP_PROG_REGION_SIZE ||
	    COMMON.program_region_count < LXP_NREG || !COMMON.dynamic_pools ||
	    COMMON.dynamic_pool_stride != LXP_DYN_POOL_SIZE ||
	    COMMON.dynamic_pool_count < LXP_NREG || !COMMON.exec_captures ||
	    COMMON.exec_capture_count < LXP_NSLOT || !COMMON.time_us || !COMMON.time_ns ||
	    !COMMON.mem_stats || !COMMON.system_version || !COMMON.validate_memory_contract ||
	    lxp_range_overlaps((uintptr_t)COMMON.program_regions, program_bytes,
			       (uintptr_t)COMMON.dynamic_pools, dynamic_bytes))
		return 0;
#if LXP_ENABLE_NETFS_EXEC
	if (!COMMON.exec_stage || COMMON.exec_stage_size == 0u)
		return 0;
#endif
	return 1;
}

int lxp_cortex_m_port_cache_prepare(void)
{
	if (COMMON.cache_geometry && lxp_cortex_m_cache_geometry_read(COMMON.cache_geometry) != 0)
		return LXP_ERR_NOT_SUPPORTED;
	return LXP_OK;
}

int lxp_cortex_m_port_host_prepare(void)
{
	return COMMON.host_prepare ? COMMON.host_prepare() : LXP_OK;
}

uint8_t *lxp_cortex_m_port_region(int ridx)
{
	return COMMON.program_regions + (size_t)ridx * LXP_PROG_REGION_SIZE;
}

uint8_t *lxp_cortex_m_port_dyn_pool(int ridx, size_t *size)
{
	if (size)
		*size = LXP_DYN_POOL_SIZE;
	return COMMON.dynamic_pools + (size_t)ridx * LXP_DYN_POOL_SIZE;
}

lxp_exec_capture_t *lxp_cortex_m_port_exec_capture(int sidx)
{
	return (sidx >= 0 && sidx < LXP_NSLOT) ? &COMMON.exec_captures[sidx] : NULL;
}

#if LXP_ENABLE_NETFS_EXEC
/* Staging buffer for a fetched remote ELF: the netfs layer fills it, the loader
 * copies its text into the program region. Placement and capacity are the host's. */
uint8_t *lxp_cortex_m_port_exec_stage(size_t *cap)
{
	if (cap)
		*cap = COMMON.exec_stage_size;
	return COMMON.exec_stage;
}
#endif

int lxp_cortex_m_port_time_us(uint64_t *out)
{
	return COMMON.time_us ? COMMON.time_us(out) : LXP_ERR_NOT_SUPPORTED;
}

int lxp_cortex_m_port_time_ns(uint64_t *out)
{
	return COMMON.time_ns ? COMMON.time_ns(out) : LXP_ERR_NOT_SUPPORTED;
}

int lxp_cortex_m_port_mem_stats(struct lxp_mem_stats *out)
{
	return COMMON.mem_stats ? COMMON.mem_stats(out) : LXP_ERR_NOT_SUPPORTED;
}

const char *lxp_cortex_m_port_system_version(void)
{
	return COMMON.system_version ? COMMON.system_version : "";
}

/* The only executable a guest publishes is the text half of its own program region;
 * make it visible to instruction fetch before the guest runs it. */
int lxp_cortex_m_port_publish_executable(lxp_region_ref_t address_space, uintptr_t base,
					 size_t len)
{
	int ridx = address_space.index;
	if (ridx < 0 || ridx >= LXP_NREG || address_space.generation == 0 || len == 0)
		return LXP_ERR_INVALID_PARAM;
	if (base != (uintptr_t)lxp_cortex_m_port_region(ridx) || len != LXP_PROG_REGION_SIZE / 2u)
		return LXP_ERR_INVALID_PARAM;
	if (COMMON.cache_geometry &&
	    lxp_cortex_m_publish_executable(COMMON.cache_geometry, base, len) != 0)
		return LXP_ERR_INVALID_PARAM;
	return LXP_OK;
}

int lxp_cortex_m_port_validate_memory_contract(const lxp_cpu_memory_contract_t *declared)
{
	if (declared != &COMMON.cpu_memory_contract)
		return LXP_ERR_INVALID_PARAM;
	return COMMON.validate_memory_contract(declared, COMMON.cache_geometry);
}
