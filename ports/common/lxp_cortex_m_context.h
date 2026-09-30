/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Guest register context shared by the Cortex-M ports that resume guests through
 * a trampoline of their own (FreeRTOS, Zephyr): lazy-FP capture and write-back
 * around a syscall, and the assembly that restores a struct lxp_resume_ctx.
 * NuttX saves and restores the complete frame natively and needs neither.
 * Private to the ports.
 */

#ifndef LXP_CORTEX_M_CONTEXT_H
#define LXP_CORTEX_M_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/arch/cortex_m_scb.h"
#include "lxp/lxp_config.h"
#include "lxp/lxp_seam.h"

/* Byte offsets in struct lxp_resume_ctx that the trampoline reads. The core
 * registers are consecutive, so the trampoline walks them with post-increment. */
#define LXP_RESUME_CTX_R4_11 0
#define LXP_RESUME_CTX_R12 32
#define LXP_RESUME_CTX_LR 36
#define LXP_RESUME_CTX_SP 40
#define LXP_RESUME_CTX_PC 44
#define LXP_RESUME_CTX_R1 48
#define LXP_RESUME_CTX_R2 52
#define LXP_RESUME_CTX_R3 56
#define LXP_RESUME_CTX_XPSR 60
_Static_assert(offsetof(struct lxp_resume_ctx, r4_11) == LXP_RESUME_CTX_R4_11, "resume r4-r11");
_Static_assert(offsetof(struct lxp_resume_ctx, r12) == LXP_RESUME_CTX_R12, "resume r12");
_Static_assert(offsetof(struct lxp_resume_ctx, lr) == LXP_RESUME_CTX_LR, "resume lr");
_Static_assert(offsetof(struct lxp_resume_ctx, sp) == LXP_RESUME_CTX_SP, "resume sp");
_Static_assert(offsetof(struct lxp_resume_ctx, pc) == LXP_RESUME_CTX_PC, "resume pc");
_Static_assert(offsetof(struct lxp_resume_ctx, r1) == LXP_RESUME_CTX_R1, "resume r1");
_Static_assert(offsetof(struct lxp_resume_ctx, r2) == LXP_RESUME_CTX_R2, "resume r2");
_Static_assert(offsetof(struct lxp_resume_ctx, r3) == LXP_RESUME_CTX_R3, "resume r3");
_Static_assert(offsetof(struct lxp_resume_ctx, xpsr) == LXP_RESUME_CTX_XPSR, "resume xpsr");

#if LXP_ENABLE_FPU_CONTEXT
#define LXP_RESUME_CTX_FP_S 64
#define LXP_RESUME_CTX_FP_FPSCR 192
#define LXP_RESUME_CTX_FP_ACTIVE 196
_Static_assert(offsetof(struct lxp_resume_ctx, fp.s) == LXP_RESUME_CTX_FP_S, "resume fp.s");
_Static_assert(offsetof(struct lxp_resume_ctx, fp.fpscr) == LXP_RESUME_CTX_FP_FPSCR,
	       "resume fp.fpscr");
_Static_assert(offsetof(struct lxp_resume_ctx, fp.active) == LXP_RESUME_CTX_FP_ACTIVE,
	       "resume fp.active");

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

/* Trampoline step: restore s0-s31 and FPSCR from the context at r3 when it holds
 * active FP state. Uses r2 as scratch. */
#define LXP_CORTEX_M_RESUME_FP_R3                                                          \
	"ldr   r2, [r3, #" LXP_CORTEX_M_STR(LXP_RESUME_CTX_FP_ACTIVE) "]\n"               \
	"cbz   r2, 9f\n"                                                                   \
	"add   r2, r3, #" LXP_CORTEX_M_STR(LXP_RESUME_CTX_FP_S) "\n"                      \
	"vldmia r2, {s0-s31}\n"                                                            \
	"ldr   r2, [r3, #" LXP_CORTEX_M_STR(LXP_RESUME_CTX_FP_FPSCR) "]\n"                \
	"vmsr  fpscr, r2\n"                                                                \
	"9:\n"
#else
#define LXP_CORTEX_M_RESUME_FP_R3 ""
#endif

/* Trampoline tail: with r3 at a struct lxp_resume_ctx and the resume value already
 * in r0, restore the guest's registers and flags and branch to its pc. APSR.NZCVQ
 * matters: an immediate hardware exception return preserves the flags, and optimized
 * code may carry a comparison across its next syscall. The pc is staged below the
 * guest's sp so r1-r3 can all reach their final values before the branch, and the
 * flags are read before that push overwrites ctx.xpsr. */
#define LXP_CORTEX_M_RESUME_FROM_R3                                                        \
	LXP_CORTEX_M_RESUME_FP_R3                                                          \
	"ldmia r3!, {r4-r11}\n"                                                            \
	"ldr   r12, [r3], #4\n"                                                            \
	"ldr   lr,  [r3], #4\n"                                                            \
	"ldr   r1,  [r3], #4\n" /* ctx.sp (temp) */                                        \
	"ldr   r2,  [r3], #4\n" /* ctx.pc (temp); r3 -> ctx.r1 */                          \
	"mov   sp,  r1\n"                                                                  \
	"ldr   r1,  [r3, #12]\n" /* ctx.xpsr */                                            \
	"msr   APSR_nzcvq, r1\n"                                                           \
	"push  {r2}\n" /* stage ctx.pc */                                                  \
	"ldr   r1,  [r3]\n"                                                                \
	"ldr   r2,  [r3, #4]\n"                                                            \
	"ldr   r3,  [r3, #8]\n"                                                            \
	"pop   {pc}\n"

#endif /* LXP_CORTEX_M_CONTEXT_H */
