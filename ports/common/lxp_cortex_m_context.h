/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Guest register context shared by the Cortex-M ports that capture a guest's
 * syscall frame themselves (FreeRTOS, Zephyr): lazy-FP capture and write-back
 * around a syscall. NuttX saves and restores the complete frame natively.
 * Private to the ports.
 */

#ifndef LXP_CORTEX_M_CONTEXT_H
#define LXP_CORTEX_M_CONTEXT_H

#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_seam.h"

#if LXP_ENABLE_FPU_CONTEXT
/* Bytes an extended exception frame adds for s0-s15, FPSCR and a reserved word. */
#define LXP_CORTEX_M_FP_FRAME_BYTES (18u * sizeof(uint32_t))

/* Capture a guest's VFP state at a syscall whose exception frame is extended.
 * @p frame_s and @p frame_fpscr point at the frame's s0-s15 and FPSCR words.
 * With lazy preservation the frame is reserved but not yet written until the
 * first handler-mode VFP instruction, so force that store first (keeping s0 on
 * the handler stack), and only then read the frame and s16-s31. */
static inline void lxp_cortex_m_fp_capture(struct lxp_fp_context *fp, const uint32_t *frame_s,
					   const uint32_t *frame_fpscr)
{
	__asm__ volatile("vpush {s0}\n"
			 "vpop  {s0}\n"
			 :
			 :
			 : "memory");
	for (int i = 0; i < 16; i++)
		fp->s[i] = frame_s[i];
	__asm__ volatile("vstmia %0, {s16-s31}" : : "r"(&fp->s[16]) : "memory");
	fp->fpscr = *frame_fpscr;
	fp->active = 1;
}

/* Hand a guest's (possibly rewritten) VFP state back: s0-s15 and FPSCR into the
 * exception frame, which restores them on return, and s16-s31 into the registers. */
static inline void lxp_cortex_m_fp_writeback(const struct lxp_fp_context *fp, uint32_t *frame_s,
					     uint32_t *frame_fpscr)
{
	for (int i = 0; i < 16; i++)
		frame_s[i] = fp->s[i];
	*frame_fpscr = fp->fpscr;
	__asm__ volatile("vldmia %0, {s16-s31}" : : "r"(&fp->s[16]) : "memory");
}

#endif

#endif /* LXP_CORTEX_M_CONTEXT_H */
