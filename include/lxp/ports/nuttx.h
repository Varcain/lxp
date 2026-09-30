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
#include "lxp/ports/cortex_m.h"

#define LXP_NUTTX_PORT_CONFIG_ABI_VERSION 4u

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

	/* Storage, memory attributes and host services every Cortex-M port shares.
	 * This port also requires common.thread_list: it lists the host's threads,
	 * and the port appends the guest tasks it owns. */
	lxp_cortex_m_port_common_t common;

	/* Board/linker-owned slot stacks, validated before any guest is made
	 * runnable. They hold trusted NuttX TLS metadata. */
	uint8_t *slot_stacks;
	size_t slot_stack_stride;
	size_t slot_stack_size;
	size_t slot_stack_count;

	/* Complete static PMSAv7 policy. LXP owns fixed region numbers and dynamic
	 * overlays; the host supplies physical layout and memory attributes. */
	lxp_nuttx_mpu_region_t code_region;
	lxp_nuttx_mpu_region_t pool_region;
	lxp_nuttx_mpu_region_t rootfs_region;
	uint8_t guest_priority;
	uint8_t _reserved_policy[3];
	uintptr_t trusted_tcb_base;
	uintptr_t trusted_tcb_end;

	/* Per-guest runtime attribution, driven by the port's scheduler-note hook.
	 * Optional: omit them when attribution is not required. */
	void (*runtime_reset)(int32_t current_pid);
	void (*runtime_start)(int32_t pid);
	void (*runtime_stop)(int32_t pid);
	void (*runtime_switch)(int32_t next_pid);
	uint64_t (*runtime_us)(int32_t pid);
} lxp_nuttx_port_config_t;

/** Supplied exactly once by the embedding system. */
extern const lxp_nuttx_port_config_t g_lxp_nuttx_port_config;

#endif /* LXP_PORTS_NUTTX_H */
