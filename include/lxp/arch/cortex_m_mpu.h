/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal PMSAv7 MPU descriptor decoding and live snapshot support. The pure
 * helpers are host-testable; the register reader is available only on ARM.
 */

#ifndef LXP_ARCH_CORTEX_M_MPU_H
#define LXP_ARCH_CORTEX_M_MPU_H

#include <stddef.h>
#include <stdint.h>

#define LXP_CORTEX_M_MPU_MAX_REGIONS 16u
#define LXP_CORTEX_M_MPU_CTRL_ENABLE (1u << 0)
#define LXP_CORTEX_M_MPU_CTRL_PRIVDEFENA (1u << 2)
#define LXP_CORTEX_M_MPU_PROFILE_FAULT UINT32_C(0x4d505546) /* "MPUF" */

struct lxp_cortex_m_mpu_region {
	uint32_t rbar;
	uint32_t rasr;
	uint32_t base;
	uint64_t size;
	uint8_t subregion_disable;
	uint8_t texscb;
	uint8_t access;
	uint8_t execute_never;
	uint8_t enabled;
};

struct lxp_cortex_m_mpu_snapshot {
	uint32_t ctrl;
	uint8_t count;
	struct lxp_cortex_m_mpu_region regions[LXP_CORTEX_M_MPU_MAX_REGIONS];
};

struct lxp_cortex_m_mpu_expectation {
	uintptr_t base;
	uint64_t size;
	uint8_t subregion_disable;
	uint8_t texscb;
	uint8_t access;
	uint8_t execute_never;
};

static inline int lxp_cortex_m_mpu_region_decode(uint32_t rbar, uint32_t rasr,
						 struct lxp_cortex_m_mpu_region *region)
{
	if (!region)
		return -1;

	uint32_t size_field = (rasr >> 1) & 0x1fu;
	uint8_t enabled = (uint8_t)(rasr & 1u);
	if (enabled && size_field < 4u)
		return -1;

	uint64_t size = enabled ? (UINT64_C(1) << (size_field + 1u)) : 0u;
	uint32_t base = 0u;
	if (enabled && size < (UINT64_C(1) << 32))
		base = rbar & ~((uint32_t)size - 1u);

	*region = (struct lxp_cortex_m_mpu_region){
		.rbar = rbar,
		.rasr = rasr,
		.base = base,
		.size = size,
		.subregion_disable = (uint8_t)(rasr >> 8),
		.texscb = (uint8_t)((rasr >> 16) & 0x3fu),
		.access = (uint8_t)((rasr >> 24) & 0x7u),
		.execute_never = (uint8_t)((rasr >> 28) & 1u),
		.enabled = enabled,
	};
	return 0;
}

/** RASR's ENABLE bit and SIZE field for a region of @p size bytes (a power of two from
 *  32 bytes to 4 GiB), or 0 for a size RASR cannot express. The caller ORs in the
 *  attribute bits; with a 0 the region stays disabled whatever they are. */
static inline uint32_t lxp_cortex_m_mpu_rasr_size(uint64_t size)
{
	if (size < 32u || size > (UINT64_C(1) << 32) || (size & (size - 1u)) != 0u)
		return 0u;
	return 1u | ((uint32_t)(62 - __builtin_clzll(size)) << 1); /* SIZE = log2(size) - 1 */
}

/** Encode an enabled region's RASR, the inverse of lxp_cortex_m_mpu_region_decode():
 *  @p size bytes (a power of two from 32 bytes to 4 GiB), access permission @p access,
 *  memory type @p texscb (TEX:S:C:B), execute-never when @p execute_never, and the
 *  subregion-disable mask @p subregion_disable. 0 for a size RASR cannot express. */
static inline uint32_t lxp_cortex_m_mpu_rasr(uint64_t size, uint8_t access, uint8_t texscb,
					     int execute_never, uint8_t subregion_disable)
{
	uint32_t rasr = lxp_cortex_m_mpu_rasr_size(size);
	if (rasr == 0u)
		return 0u;
	return rasr | ((uint32_t)subregion_disable << 8) | ((uint32_t)(texscb & 0x3fu) << 16) |
	       ((uint32_t)(access & 7u) << 24) | ((execute_never ? 1u : 0u) << 28);
}

static inline int lxp_cortex_m_mpu_region_contains(const struct lxp_cortex_m_mpu_region *region,
						   uintptr_t base, size_t len)
{
	if (!region || !region->enabled || len == 0u || (uint64_t)base + len > UINT64_C(1) << 32)
		return 0;

	uint64_t first = base;
	uint64_t end = first + len;
	uint64_t region_first = region->base;
	uint64_t region_end = region_first + region->size;
	if (first < region_first || end > region_end)
		return 0;
	if (region->size < 256u || region->subregion_disable == 0u)
		return 1;

	uint64_t subregion_size = region->size / 8u;
	unsigned first_subregion = (unsigned)((first - region_first) / subregion_size);
	unsigned last_subregion = (unsigned)((end - 1u - region_first) / subregion_size);
	for (unsigned i = first_subregion; i <= last_subregion; i++)
		if ((region->subregion_disable & (1u << i)) != 0u)
			return 0;
	return 1;
}

static inline int
lxp_cortex_m_mpu_region_overlaps_enabled(const struct lxp_cortex_m_mpu_region *region,
					 uintptr_t base, size_t len)
{
	if (!region || !region->enabled || len == 0u || (uint64_t)base + len > UINT64_C(1) << 32)
		return 0;

	uint64_t first = base;
	uint64_t end = first + len;
	uint64_t region_first = region->base;
	uint64_t region_end = region_first + region->size;
	if (first >= region_end || end <= region_first)
		return 0;
	if (region->size < 256u || region->subregion_disable == 0u)
		return 1;

	uint64_t subregion_size = region->size / 8u;
	for (unsigned i = 0; i < 8u; i++) {
		if ((region->subregion_disable & (1u << i)) != 0u)
			continue;
		uint64_t subregion_first = region_first + i * subregion_size;
		uint64_t subregion_end = subregion_first + subregion_size;
		if (first < subregion_end && end > subregion_first)
			return 1;
	}
	return 0;
}

static inline int lxp_cortex_m_mpu_region_matches(const struct lxp_cortex_m_mpu_region *region,
						  uintptr_t base, uint64_t size,
						  uint8_t subregion_disable, uint8_t texscb,
						  uint8_t access, uint8_t execute_never)
{
	return region && region->enabled && region->base == base && region->size == size &&
	       region->subregion_disable == subregion_disable && region->texscb == texscb &&
	       region->access == access && region->execute_never == execute_never;
}

static inline int
lxp_cortex_m_mpu_region_matches_expectation(const struct lxp_cortex_m_mpu_region *region,
					    const struct lxp_cortex_m_mpu_expectation *expected)
{
	return expected &&
	       lxp_cortex_m_mpu_region_matches(region, expected->base, expected->size,
					       expected->subregion_disable, expected->texscb,
					       expected->access, expected->execute_never);
}

static inline int
lxp_cortex_m_mpu_descriptor_matches(uint32_t rbar, uint32_t rasr,
				    const struct lxp_cortex_m_mpu_expectation *expected)
{
	struct lxp_cortex_m_mpu_region region;
	return lxp_cortex_m_mpu_region_decode(rbar, rasr, &region) == 0 &&
	       lxp_cortex_m_mpu_region_matches_expectation(&region, expected);
}

/* Require expected to be the effective mapping over its complete range.
 * PMSAv7 resolves overlaps in favour of the highest-numbered region. */
static inline int
lxp_cortex_m_mpu_snapshot_effective_matches(const struct lxp_cortex_m_mpu_snapshot *snapshot,
					    const struct lxp_cortex_m_mpu_expectation *expected)
{
	if (!snapshot || !expected || expected->size == 0u || snapshot->count == 0u ||
	    snapshot->count > LXP_CORTEX_M_MPU_MAX_REGIONS || expected->size > SIZE_MAX)
		return 0;

	for (unsigned i = snapshot->count; i > 0u; i--) {
		const struct lxp_cortex_m_mpu_region *region = &snapshot->regions[i - 1u];
		if (!lxp_cortex_m_mpu_region_overlaps_enabled(region, expected->base,
						      (size_t)expected->size))
			continue;
		return lxp_cortex_m_mpu_region_matches_expectation(region, expected);
	}
	return 0;
}

/* Require live region @p number to hold the descriptor a port programmed into it:
 * disabled when @p rasr is 0, otherwise the region @p rbar / @p rasr encode. With
 * @p effective it must also win over every other descriptor that overlaps it. */
static inline int
lxp_cortex_m_mpu_snapshot_region_holds(const struct lxp_cortex_m_mpu_snapshot *snapshot,
				       unsigned number, uint32_t rbar, uint32_t rasr, int effective)
{
	if (!snapshot || number >= snapshot->count || number >= LXP_CORTEX_M_MPU_MAX_REGIONS)
		return 0;
	if (rasr == 0u)
		return !snapshot->regions[number].enabled;
	struct lxp_cortex_m_mpu_region native;
	if (lxp_cortex_m_mpu_region_decode(rbar, rasr, &native) != 0)
		return 0;
	const struct lxp_cortex_m_mpu_expectation expected = {
		.base = native.base,
		.size = native.size,
		.subregion_disable = native.subregion_disable,
		.texscb = native.texscb,
		.access = native.access,
		.execute_never = native.execute_never,
	};
	return lxp_cortex_m_mpu_region_matches_expectation(&snapshot->regions[number], &expected) &&
	       (!effective || lxp_cortex_m_mpu_snapshot_effective_matches(snapshot, &expected));
}

#if defined(__arm__) || defined(__thumb__)

#define LXP_CORTEX_M_MPU_TYPE (*(volatile uint32_t *)0xe000ed90u)
#define LXP_CORTEX_M_MPU_CTRL (*(volatile uint32_t *)0xe000ed94u)
#define LXP_CORTEX_M_MPU_RNR (*(volatile uint32_t *)0xe000ed98u)
#define LXP_CORTEX_M_MPU_RBAR (*(volatile uint32_t *)0xe000ed9cu)
#define LXP_CORTEX_M_MPU_RASR (*(volatile uint32_t *)0xe000eda0u)

static inline int lxp_cortex_m_mpu_snapshot_read(struct lxp_cortex_m_mpu_snapshot *snapshot)
{
	if (!snapshot)
		return -1;

	uint32_t count = (LXP_CORTEX_M_MPU_TYPE >> 8) & 0xffu;
	if (count == 0u || count > LXP_CORTEX_M_MPU_MAX_REGIONS)
		return -1;

	uint32_t primask;
	__asm volatile("mrs %0, primask" : "=r"(primask));
	__asm volatile("cpsid i" ::: "memory");
	uint32_t saved_rnr = LXP_CORTEX_M_MPU_RNR;
	snapshot->ctrl = LXP_CORTEX_M_MPU_CTRL;
	snapshot->count = (uint8_t)count;
	for (uint32_t i = 0; i < count; i++) {
		LXP_CORTEX_M_MPU_RNR = i;
		__asm volatile("dsb 0xf\nisb 0xf" ::: "memory");
		if (lxp_cortex_m_mpu_region_decode(LXP_CORTEX_M_MPU_RBAR,
						   LXP_CORTEX_M_MPU_RASR,
						   &snapshot->regions[i]) != 0) {
			LXP_CORTEX_M_MPU_RNR = saved_rnr;
			__asm volatile("dsb 0xf\nisb 0xf" ::: "memory");
			__asm volatile("msr primask, %0" : : "r"(primask) : "memory");
			return -1;
		}
	}
	LXP_CORTEX_M_MPU_RNR = saved_rnr;
	__asm volatile("dsb 0xf\nisb 0xf" ::: "memory");
	__asm volatile("msr primask, %0" : : "r"(primask) : "memory");
	return 0;
}

#endif /* __arm__ || __thumb__ */

#endif /* LXP_ARCH_CORTEX_M_MPU_H */
