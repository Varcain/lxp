/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Services shared by LXP's Cortex-M OS ports: the engine operations that only
 * read the common configuration, and the checks of that configuration. A port
 * binds the operations directly in its lxp_os_ops_t, calls the checks from its
 * prepare(), and defines g_lxp_cortex_m_port_common. Private to the ports.
 */

#ifndef LXP_CORTEX_M_PORT_H
#define LXP_CORTEX_M_PORT_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/ports/cortex_m.h"

/* The `.common` of the one port linked into the image; the port defines it. */
extern const lxp_cortex_m_port_common_t *const g_lxp_cortex_m_port_common;

/* 1 when the common configuration is complete and consistent, else 0. */
int lxp_cortex_m_port_config_valid(void);
/* Read the cache geometry: LXP_OK, or LXP_ERR_NOT_SUPPORTED for a cache hierarchy
 * the port cannot maintain. */
int lxp_cortex_m_port_cache_prepare(void);
/* Run the host's prepare hook, if it has one. */
int lxp_cortex_m_port_host_prepare(void);

/* lxp_os_ops_t operations. */
uint8_t *lxp_cortex_m_port_region(int ridx);
uint8_t *lxp_cortex_m_port_dyn_pool(int ridx, size_t *size);
lxp_exec_capture_t *lxp_cortex_m_port_exec_capture(int sidx);
#if LXP_ENABLE_NETFS_EXEC
uint8_t *lxp_cortex_m_port_exec_stage(size_t *cap);
#endif
int lxp_cortex_m_port_time_us(uint64_t *out);
int lxp_cortex_m_port_time_ns(uint64_t *out);
int lxp_cortex_m_port_mem_stats(struct lxp_mem_stats *out);
const char *lxp_cortex_m_port_system_version(void);
int lxp_cortex_m_port_publish_executable(lxp_region_ref_t address_space, uintptr_t base,
					 size_t len);
int lxp_cortex_m_port_validate_memory_contract(const lxp_cpu_memory_contract_t *declared);

#endif /* LXP_CORTEX_M_PORT_H */
