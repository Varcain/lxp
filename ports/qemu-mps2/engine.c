/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Standalone MPS2-AN500 host policy for LXP's production FreeRTOS MPU port.
 * Native task, SVC, fault-containment, parking and MPU code lives once in
 * ports/freertos/lxp_freertos_port.c.
 */

#include "FreeRTOS.h"
#include "task.h"

#include <stdint.h>

#include "lxp/arch/cortex_m_cache.h"
#include "lxp/lxp_config.h"
#include "lxp/ports/freertos.h"

extern uint64_t lxp_qemu_now_us(void);
extern int lxp_qemu_tick_subscribe(lxp_freertos_tick_fn callback);
extern void lxp_qemu_tick_unsubscribe(lxp_freertos_tick_fn callback);

/* Program images remain in emulated SRAM; large dynamic FDPIC arenas occupy
 * the upper 4 MiB of PSRAM, above the two rootfs XIP windows. */
static uint8_t g_prog_regions[LXP_NREG][LXP_PROG_REGION_SIZE]
	__attribute__((aligned(LXP_PROG_REGION_SIZE)));
static uint8_t g_dyn_pools[LXP_NREG][LXP_DYN_POOL_SIZE]
	__attribute__((section(".psram"), aligned(LXP_DYN_POOL_SIZE)));
static lxp_exec_capture_t g_exec_captures[LXP_NSLOT];

static int qemu_time_us(uint64_t *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	*out = lxp_qemu_now_us();
	return LXP_OK;
}

static int qemu_time_ns(uint64_t *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	*out = lxp_qemu_now_us() * 1000u;
	return LXP_OK;
}

static int qemu_mem_stats(struct lxp_mem_stats *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	*out = (struct lxp_mem_stats){0};
	return LXP_OK;
}

static const char *qemu_system_version(void)
{
	return "FreeRTOS " tskKERNEL_VERSION_NUMBER " lxp-standalone";
}

/* Deterministic and explicitly non-cryptographic: this is a development port. */
static int qemu_random_fill(void *buf, size_t len)
{
	static uint32_t state = 0x6c787071u;
	uint8_t *out = buf;
	for (size_t i = 0; i < len; i++) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		out[i] = (uint8_t)(state >> 24);
	}
	return LXP_OK;
}

static int qemu_validate_memory_contract(const lxp_cpu_memory_contract_t *declared,
					 const struct lxp_cortex_m_cache_geometry *geometry)
{
	(void)geometry;
	return declared && declared->model == LXP_CPU_MEM_UNCACHED &&
			       (LXP_CORTEX_M_SCB_CCR & LXP_CORTEX_M_SCB_CCR_DC) == 0u
		       ? LXP_OK
		       : LXP_ERR_INVALID_PARAM;
}

const lxp_freertos_port_config_t g_lxp_freertos_port_config = {
	.abi_version = LXP_FREERTOS_PORT_CONFIG_ABI_VERSION,
	.struct_size = sizeof(lxp_freertos_port_config_t),
	.program_regions = &g_prog_regions[0][0],
	.program_region_stride = LXP_PROG_REGION_SIZE,
	.program_region_count = LXP_NREG,
	.dynamic_pools = &g_dyn_pools[0][0],
	.dynamic_pool_stride = LXP_DYN_POOL_SIZE,
	.dynamic_pool_count = LXP_NREG,
	.exec_captures = g_exec_captures,
	.exec_capture_count = LXP_NSLOT,
	.guest_memory_texscb = configTEX_S_C_B_SRAM,
	.rootfs_region_count = 2u,
	.coordinator_rootfs_region = UINT8_MAX,
	.rootfs_regions =
		{
			{
				.base = 0x60000000u,
				.size = 8u * 1024u * 1024u,
				.texscb = configTEX_S_C_B_SRAM,
			},
			{
				.base = 0x60800000u,
				.size = 4u * 1024u * 1024u,
				.texscb = configTEX_S_C_B_SRAM,
			},
		},
	.cpu_memory_contract =
		{
			.abi_version = LXP_CPU_MEMORY_CONTRACT_ABI_VERSION,
			.struct_size = sizeof(lxp_cpu_memory_contract_t),
			.model = LXP_CPU_MEM_UNCACHED,
			.normal_attrs = LXP_CPU_MEM_ATTR_NORMAL_NC_NSH,
		},
	.guest_quantum_ms = 10u,
	.tick_subscribe = lxp_qemu_tick_subscribe,
	.tick_unsubscribe = lxp_qemu_tick_unsubscribe,
	.time_us = qemu_time_us,
	.time_ns = qemu_time_ns,
	.mem_stats = qemu_mem_stats,
	.system_version = qemu_system_version,
	.random_fill = qemu_random_fill,
	.validate_memory_contract = qemu_validate_memory_contract,
};
