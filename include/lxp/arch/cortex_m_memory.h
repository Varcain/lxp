/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Cortex-M validation for LXP's CPU memory contract.
 */

#ifndef LXP_ARCH_CORTEX_M_MEMORY_H
#define LXP_ARCH_CORTEX_M_MEMORY_H

#include "lxp/arch/cortex_m_cache.h"
#include "lxp/lxp_port.h"

#if defined(__arm__) || defined(__thumb__)
static inline int lxp_cortex_m_memory_contract_matches_cache(
	const lxp_cpu_memory_contract_t *contract,
	const struct lxp_cortex_m_cache_geometry *geometry)
{
	if (!contract || !geometry)
		return 0;

	uint32_t flags = 0u;
	if ((LXP_CORTEX_M_SCB_CCR & LXP_CORTEX_M_SCB_CCR_DC) != 0u)
		flags |= LXP_CPU_MEMORY_DCACHE_ENABLED;
	if ((LXP_CORTEX_M_SCB_CCR & LXP_CORTEX_M_SCB_CCR_IC) != 0u)
		flags |= LXP_CPU_MEMORY_ICACHE_ENABLED;

	return contract->flags == flags &&
	       contract->dcache_line_size == geometry->d_line_size &&
	       contract->icache_line_size == geometry->i_line_size &&
	       contract->dcache_size == geometry->d_size &&
	       contract->icache_size == geometry->i_size;
}
#endif

#endif /* LXP_ARCH_CORTEX_M_MEMORY_H */
