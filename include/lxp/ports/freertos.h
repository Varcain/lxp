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
#include "lxp/ports/cortex_m.h"

#define LXP_FREERTOS_ROOTFS_REGION_MAX 2u

typedef void (*lxp_freertos_tick_fn)(void);

typedef struct lxp_freertos_rootfs_region {
	uintptr_t base;
	size_t size;
	uint8_t texscb;
	uint8_t _reserved[3];
} lxp_freertos_rootfs_region_t;

typedef struct lxp_freertos_port_config {
	/* Storage, memory attributes and host services every Cortex-M port shares.
	 * This port also requires random_fill below; common.thread_list is optional. */
	lxp_cortex_m_port_common_t common;

	/* PMSAv7 policy supplied by the board integration. LXP compiles and
	 * validates the native task descriptors from these logical attributes. */
	uint8_t rootfs_region_count;
	uint8_t coordinator_cacheable_map;
	uint8_t coordinator_rootfs_region;
	lxp_freertos_rootfs_region_t rootfs_regions[LXP_FREERTOS_ROOTFS_REGION_MAX];
	uint32_t guest_quantum_ms;

	/* Board/HAL and host-policy providers. Callbacks execute in the context
	 * documented by lxp_os_ops_t unless noted otherwise. */
	/* Publish exactly one callback into the embedding system's FreeRTOS tick
	 * hook for this run, then withdraw that same callback during teardown.
	 * subscribe/unsubscribe execute in coordinator task context and must
	 * synchronize against SysTick before returning. The subscribed callback
	 * executes in SysTick ISR context and must not be called after unsubscribe
	 * returns. Both operations are required. subscribe returns 0, or nonzero when
	 * the hook already serves another callback (prepare() then fails LXP_ERR_BUSY). */
	int (*tick_subscribe)(lxp_freertos_tick_fn callback);
	void (*tick_unsubscribe)(lxp_freertos_tick_fn callback);
	int (*random_fill)(void *buf, size_t len);
	void (*cache_clean)(const void *base, size_t len);
	void (*cache_invalidate)(const void *base, size_t len);
	void (*host_fatal)(uint32_t cfsr, uint32_t hfsr, uint32_t pc);

	/* Optional low-overhead cycle source. LXP owns the accumulator; reading the
	 * endpoint before recording excludes telemetry bookkeeping from the sample. */
	volatile const uint32_t *svc_cycle_counter;
} lxp_freertos_port_config_t;

/** Supplied exactly once by the embedding system. */
extern const lxp_freertos_port_config_t g_lxp_freertos_port_config;

#endif /* LXP_PORTS_FREERTOS_H */
