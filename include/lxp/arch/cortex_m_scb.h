/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Cortex-M System Control Block registers the ports use for fault handling and
 * exception control, and the barriers that order writes to them. The register
 * accessors are meaningful only on an ARMv7-M target; the pure helpers are
 * host-testable.
 */

#ifndef LXP_ARCH_CORTEX_M_SCB_H
#define LXP_ARCH_CORTEX_M_SCB_H

#include <stdint.h>

/* Interrupt control and state: pend PendSV to request a context switch. */
#define LXP_CORTEX_M_SCB_ICSR (*(volatile uint32_t *)0xe000ed04u)
#define LXP_CORTEX_M_SCB_ICSR_PENDSVSET (1u << 28)

/* System handler control and state: enable the configurable fault handlers. */
#define LXP_CORTEX_M_SCB_SHCSR (*(volatile uint32_t *)0xe000ed24u)
#define LXP_CORTEX_M_SCB_SHCSR_MEMFAULTENA (1u << 16)
#define LXP_CORTEX_M_SCB_SHCSR_BUSFAULTENA (1u << 17)
#define LXP_CORTEX_M_SCB_SHCSR_USGFAULTENA (1u << 18)

/* Fault status (CFSR is write-one-to-clear) and the fault address registers, which
 * hold a valid address only while CFSR says so. */
#define LXP_CORTEX_M_SCB_CFSR (*(volatile uint32_t *)0xe000ed28u)
#define LXP_CORTEX_M_SCB_HFSR (*(volatile uint32_t *)0xe000ed2cu)
#define LXP_CORTEX_M_SCB_MMFAR (*(volatile uint32_t *)0xe000ed34u)
#define LXP_CORTEX_M_SCB_BFAR (*(volatile uint32_t *)0xe000ed38u)
#define LXP_CORTEX_M_SCB_CFSR_MMARVALID (1u << 7)
#define LXP_CORTEX_M_SCB_CFSR_BFARVALID (1u << 15)

/* Floating-point context control. The address has no suffix so that assembly can load
 * it: "ldr r3, =" LXP_CORTEX_M_STR(LXP_CORTEX_M_FPCCR_ADDR). */
#define LXP_CORTEX_M_FPCCR_ADDR 0xe000ef34
#define LXP_CORTEX_M_FPCCR (*(volatile uint32_t *)LXP_CORTEX_M_FPCCR_ADDR)

/* Expand a macro into a string, for inline assembly. */
#define LXP_CORTEX_M_STR_(x) #x
#define LXP_CORTEX_M_STR(x) LXP_CORTEX_M_STR_(x)

/** The fault registers as one fault handler saw them. */
struct lxp_cortex_m_fault_status {
	uint32_t cfsr;
	uint32_t hfsr;
	uint32_t mmfar;
	uint32_t bfar;
};

/** The data address a fault reported: MMFAR for a memory-management fault, BFAR for a
 *  precise bus fault, and 0 when CFSR vouches for neither. */
static inline uintptr_t lxp_cortex_m_fault_address(const struct lxp_cortex_m_fault_status *status)
{
	if (status->cfsr & LXP_CORTEX_M_SCB_CFSR_MMARVALID)
		return status->mmfar;
	if (status->cfsr & LXP_CORTEX_M_SCB_CFSR_BFARVALID)
		return status->bfar;
	return 0u;
}

static inline void lxp_cortex_m_dsb(void)
{
	__asm volatile("dsb 0xf" ::: "memory");
}

static inline void lxp_cortex_m_isb(void)
{
	__asm volatile("isb 0xf" ::: "memory");
}

/** Read the fault registers; call from a fault handler before anything else faults. */
static inline void lxp_cortex_m_fault_status_read(struct lxp_cortex_m_fault_status *out)
{
	out->cfsr = LXP_CORTEX_M_SCB_CFSR;
	out->hfsr = LXP_CORTEX_M_SCB_HFSR;
	out->mmfar = LXP_CORTEX_M_SCB_MMFAR;
	out->bfar = LXP_CORTEX_M_SCB_BFAR;
}

/** Clear every CFSR status bit that is set (write-one-to-clear). */
static inline void lxp_cortex_m_fault_status_clear(void)
{
	LXP_CORTEX_M_SCB_CFSR = LXP_CORTEX_M_SCB_CFSR;
}

#endif /* LXP_ARCH_CORTEX_M_SCB_H */
