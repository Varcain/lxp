/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The standalone QEMU harness engine: it fills lxp_os_ops_t on top of a vendored
 * FreeRTOS kernel (Arm MPS2-AN500 / Cortex-M7, ARM_CM4_MPU port), so the lxp module
 * runs under QEMU with FreeRTOS providing the proven task/context-switch — this is
 * a de-oveRTOS'd distillation of backends/freertos/freertos_lnx.c. Each guest is a
 * FreeRTOS task; its Linux syscall traps to SVC_Handler, which captures the frame,
 * drives lxp_dispatch(), and (on a park) wakes the coordinator via a semaphore.
 *
 * Guests are restricted, unprivileged tasks. Per-task MPU regions grant only the
 * program, dynamic pool and rootfs XIP windows; user_ok/user_strnlen remain the
 * privileged dispatcher's confused-deputy guards rather than a substitute for
 * MPU isolation.
 */

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"

#include <stdint.h>
#include <string.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_loader.h"
#include "lxp/lxp_port.h"
#include "lxp/lxp_seam.h"

/* Monotonic microsecond clock, maintained by the FreeRTOS tick hook (boot.c). */
extern uint64_t lxp_qemu_now_us(void);

/* Cold per-slot execve captures stay in the harness's roomy SRAM. Production
 * STM32 ports place the same port-owned storage in external SDRAM. */
static lxp_exec_capture_t g_exec_captures[LXP_NSLOT];

/* ---- guest program regions (RW image + arena + stack), in RAM --------------- */
/* Plain .bss (zeroed by Reset): the FDPIC loader relies on the region — the guest's
 * .bss + arena — starting zeroed. A NOLOAD section would be uninitialised garbage. */
/* Size-aligned: each region is a per-task MPU region, and PMSAv7 requires the base
 * aligned to its (power-of-2) size. */
static uint8_t g_prog_regions[LXP_NREG][LXP_PROG_REGION_SIZE]
	__attribute__((aligned(LXP_PROG_REGION_SIZE)));

/* ---- M3 dynamic-FDPIC dyn_pools, in PSRAM ---------------------------------- */
/* A dynamic proc's shared arena: every loaded .so's RW segment + brk/mmap heap.
 * ld.so mmaps libc.so (~500K) here — far past the in-region 96K static arena. Lives
 * in PSRAM (.psram, top 4M) so it stays off the 4M SRAM; 8*512K = exactly 4M. Unused
 * by M1/M2 (static FDPIC), so this costs nothing there. */
static uint8_t g_dyn_pools[LXP_NREG][LXP_DYN_POOL_SIZE]
	__attribute__((section(".psram"), aligned(LXP_DYN_POOL_SIZE)));

#define SLOT_PRIO 1 /* guests run below the coordinator; NO portPRIVILEGE_BIT (unprivileged) */
#define TRAMP_STACK_WORDS 256
/* The tramp stack is the restricted task's auto MPU stack region, so it must be
 * aligned to its (power-of-2) size (PMSAv7). 256 words = 1 KB. */
static StackType_t g_tramp_stacks[LXP_NSLOT][TRAMP_STACK_WORDS]
	__attribute__((aligned(TRAMP_STACK_WORDS * sizeof(StackType_t))));
static StaticTask_t g_tcb[LXP_NSLOT];
static TaskHandle_t g_tid[LXP_NSLOT];

static int current_slot(void)
{
	/* Read pxCurrentTCB directly, NOT xTaskGetCurrentTaskHandle(): under the MPU port the
	 * accessor is an MPU_* wrapper that svc-raises-privilege when the caller looks
	 * unprivileged — which HardFaults from the svc/fault handler context. The handle IS the
	 * TCB pointer, and handler mode reads privileged data fine. */
	extern void *volatile pxCurrentTCB;
	TaskHandle_t t = (TaskHandle_t)pxCurrentTCB;
	for (int i = 0; i < LXP_NSLOT; i++)
		if (g_lxp_used[i] && g_tid[i] == t)
			return i;
	return -1;
}

/* ---- the SVC trap ---------------------------------------------------------- */
struct lnx_capture {
	uint32_t *hw;      /* hw[0..7] = r0,r1,r2,r3,r12,lr,pc,xpsr (HW-stacked) */
	uint32_t psp;
	uint32_t r4_11[8];
	uint32_t exc_return;
#if LXP_ENABLE_FPU_CONTEXT
	struct lxp_fp_context fp;
#endif
};
_Static_assert(offsetof(struct lnx_capture, exc_return) == 40u, "SVC capture EXC_RETURN offset");
static struct lnx_capture g_cap __attribute__((used));

/* Build the uniform frame, dispatch, write it back. Returns 1 if it handled a
 * program's Linux svc, 0 to FORWARD the svc to FreeRTOS (start-scheduler etc.). */
int lxp_qemu_svc_c(struct lnx_capture *g)
{
	int sidx = current_slot();
	if (!g_lxp_active || sidx < 0)
		return 0; /* not a running program → FreeRTOS's own svc */
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	uint32_t fp_frame_bytes = 0;
#if LXP_ENABLE_FPU_CONTEXT
	f.fp = &g->fp;
	memset(&g->fp, 0, sizeof(g->fp));
	if ((g->exc_return & (1u << 4)) == 0) {
		/* With lazy preservation enabled, the extended frame can be reserved but
		 * its s0-s15 contents are not valid until the first handler-mode VFP
		 * instruction. Preserve s0 on MSP while forcing that pending operation. */
		__asm__ volatile("vpush {s0}\n"
				 "vpop  {s0}\n"
				 :
				 :
				 : "memory");
		for (int i = 0; i < 16; i++)
			g->fp.s[i] = g->hw[8 + i];
		uint32_t *high = &g->fp.s[16];
		__asm__ volatile("vstmia %0, {s16-s31}" : : "r"(high) : "memory");
		g->fp.fpscr = g->hw[24];
		g->fp.active = 1;
		fp_frame_bytes = 18u * sizeof(uint32_t);
	}
#endif
	f.r[0] = g->hw[0];
	f.r[1] = g->hw[1];
	f.r[2] = g->hw[2];
	f.r[3] = g->hw[3];
	for (int i = 0; i < 8; i++)
		f.r[4 + i] = g->r4_11[i];
	f.r[12] = g->hw[4];
	/* The guest ABI observes the SP before exception entry. An extended FP frame
	 * adds s0-s15, FPSCR and one reserved word after the 8-word core frame. */
	f.r[13] = g->psp + 32u + fp_frame_bytes + ((g->hw[7] & (1u << 9)) ? 4u : 0u);
	f.r[14] = g->hw[5];
	f.r[15] = g->hw[6];
	f.xpsr = g->hw[7];

	lxp_dispatch(&f, &g_lxp_proc[sidx]);

	g->hw[0] = f.r[0];
	g->hw[1] = f.r[1];
	g->hw[2] = f.r[2];
	g->hw[3] = f.r[3];
	g->hw[4] = f.r[12];
	g->hw[5] = f.r[14];
	g->hw[6] = f.r[15];
	g->hw[7] = f.xpsr;
	/* Write r4-r11 back so a dispatch that rewrites a callee-saved register on the fast path takes
	 * effect. rt_sigreturn restores the interrupted code's r9 (FDPIC GOT) via sig_restore — a signal
	 * handler runs with its OWN r9, so without this the interrupted syscall resumes with the handler's
	 * GOT and its __errno_location PLT resolves through the wrong module (-> sigaction -> SIGSEGV).
	 * For every other syscall these equal the captured values, so SVC_Handler's reload is a no-op. */
	for (int i = 0; i < 8; i++)
		g->r4_11[i] = f.r[4 + i];
#if LXP_ENABLE_FPU_CONTEXT
	if ((g->exc_return & (1u << 4)) == 0) {
		for (int i = 0; i < 16; i++)
			g->hw[8 + i] = g->fp.s[i];
		g->hw[24] = g->fp.fpscr;
		uint32_t *high = &g->fp.s[16];
		__asm__ volatile("vldmia %0, {s16-s31}" : : "r"(high) : "memory");
	}
#endif
	return 1;
}

extern void vPortSVCHandler(void); /* FreeRTOS's own (start-scheduler) handler */

__attribute__((naked)) void SVC_Handler(void)
{
	__asm__ volatile("ldr   r1, =g_lxp_active  \n"
			 "ldr   r1, [r1]           \n"
			 "cmp   r1, #0             \n"
			 "beq   1f                 \n" /* no run active → FreeRTOS (start scheduler) */
			 "tst   lr, #8             \n" /* handler-mode svc (yield/priv) → FreeRTOS */
			 "beq   1f                 \n"
			 "mrs   r0, psp            \n"
			 "ldr   r1, =g_cap         \n"
			 "str   r0, [r1, #0]       \n"
			 "str   r0, [r1, #4]       \n"
			 "add   r2, r1, #8         \n"
			 "stmia r2, {r4-r11}       \n"
			 "str   lr, [r1, #40]      \n" /* EXC_RETURN: bit 4 selects basic/extended frame */
			 "mov   r0, r1             \n"
			 /* The dispatch runs in HANDLER mode but inherits the program's CONTROL.nPRIV=1.
			  * FreeRTOS MPU_* wrappers (event_post's semaphore-give) would read nPRIV, believe
			  * they're unprivileged, and svc-raise-privilege — nested inside this active SVCall
			  * that escalates to a HardFault. Clear nPRIV across the dispatch (handler mode is
			  * privileged regardless), then restore so the program resumes UNPRIVILEGED. */
			 "mrs   r2, control        \n"
			 "push  {r2, lr}           \n"
			 "bic   r3, r2, #1         \n"
			 "msr   control, r3        \n"
			 "isb                      \n"
			 "bl    lxp_qemu_svc_c     \n"
			 "pop   {r2, lr}           \n"
			 "msr   control, r2        \n"
			 "isb                      \n"
			 "cmp   r0, #0             \n"
			 "beq   1f                 \n" /* 0 = not a program svc → forward */
			 /* Reload r4-r11 from g_cap (lxp_qemu_svc_c wrote them back post-dispatch): the
			  * exception return only replays the HW frame (r0-r3,r12,lr,pc,xpsr), so a callee-saved
			  * register the dispatch rewrote (rt_sigreturn's r9/FDPIC-GOT restore) would otherwise be
			  * dropped and the interrupted code resumes with the signal handler's GOT. */
			 "ldr   r1, =g_cap         \n"
			 "add   r1, r1, #8         \n"
			 "ldmia r1, {r4-r11}       \n"
			 "bx    lr                 \n" /* 1 = handled: replay the frame */
			 "1:                       \n"
			 "b     vPortSVCHandler    \n");
}

/* ---- program-fault containment -------------------------------------------- */
static void engine_event_post(void);
extern void HardFault_Handler(void);

void lxp_qemu_fault_c(uint32_t *frame /* the faulting program's PSP HW frame */)
{
	int sidx = current_slot();
	if (g_lxp_active && sidx >= 0) {
		g_lxp_proc[sidx].exited = 1;
		g_lxp_proc[sidx].exit_status = 139;             /* 128 + SIGSEGV */
		frame[6] = ((uint32_t)&lxp_park_loop) & ~1u;    /* stacked PC → park loop */
		frame[7] |= (1u << 24);                         /* xPSR.T */
		*(volatile uint32_t *)0xE000ED28u = *(volatile uint32_t *)0xE000ED28u; /* clear CFSR */
		lxp_event_post_slot(sidx);
		return;
	}
	HardFault_Handler(); /* not a program fault → fatal */
}

/* An UNPRIVILEGED program's illegal access raises MemManage (the MPU port enables
 * MEMFAULTENA). Contain it as a default SIGSEGV. Same nPRIV dance as SVC_Handler:
 * lxp_qemu_fault_c calls event_post (a FreeRTOS API) which must not svc-raise-privilege
 * from here. Bus/Usage get identical containment (the handler is fault-type-agnostic). */
__attribute__((naked)) void MemManage_Handler(void)
{
	__asm__ volatile("mrs  r0, psp             \n" /* r0 = faulting program's HW frame */
			 "mrs  r2, control         \n"
			 "push {r2, lr}            \n"
			 "bic  r3, r2, #1          \n"
			 "msr  control, r3         \n"
			 "isb                      \n"
			 "bl   lxp_qemu_fault_c    \n"
			 "pop  {r2, lr}            \n"
			 "msr  control, r2         \n"
			 "isb                      \n"
			 "bx   lr                  \n");
}
__attribute__((naked)) void UsageFault_Handler(void)
{
	__asm__ volatile("b MemManage_Handler");
}
__attribute__((naked)) void BusFault_Handler(void)
{
	__asm__ volatile("b MemManage_Handler");
}

/* ---- thread entry: in-region descriptor + unified trampoline --------------- */
struct resume_desc {
	uint32_t r0;
	struct lxp_resume_ctx ctx;
};

#if LXP_ENABLE_FPU_CONTEXT
/* prog_tramp is naked assembly, so pin every optional field offset it consumes.
 * Appending the FP state to lxp_resume_ctx deliberately leaves the established
 * core-register offsets unchanged. */
_Static_assert(offsetof(struct resume_desc, ctx.fp.s) == 68u, "resume FP register offset");
_Static_assert(offsetof(struct resume_desc, ctx.fp.fpscr) == 196u, "resume FPSCR offset");
_Static_assert(offsetof(struct resume_desc, ctx.fp.active) == 200u, "resume FP-active offset");
#define LXP_TRAMP_RESTORE_FP                                                        \
	"ldr   r1, [r0, #200]  \n" /* ctx.fp.active */                              \
	"cbz   r1, 0f          \n"                                                    \
	"add   r2, r0, #68     \n" /* ctx.fp.s */                                   \
	"vldmia r2!, {s0-s31}  \n"                                                    \
	"ldr   r1, [r0, #196]  \n" /* ctx.fp.fpscr */                               \
	"vmsr  fpscr, r1       \n"                                                    \
	"0:                    \n"
#else
#define LXP_TRAMP_RESTORE_FP ""
#endif

__attribute__((naked)) static void prog_tramp(void *desc __attribute__((unused)))
{
	/* desc in r0. Restore r4..r11 (r7/r8/r9 = FDPIC exec/interp loadmap + GOT), r12, lr,
	 * then r1..r3 and APSR.NZCVQ (state preserved by a hardware exception return), r0 =
	 * desc->r0, switch SP, and branch to ctx.pc. Every register ends up holding its final
	 * value, so ctx.pc is staged on the guest stack rather than kept in a scratch register. */
	__asm__ volatile(LXP_TRAMP_RESTORE_FP
			 "add   r3, r0, #4     \n" /* r3 -> ctx */
			 "ldmia r3!, {r4-r11} \n" /* r4..r11;  r3 -> ctx.r12 */
			 "ldr   r12, [r3], #4 \n" /* r12;      r3 -> ctx.lr */
			 "ldr   lr,  [r3], #4 \n" /* lr;       r3 -> ctx.sp */
			 "ldr   r1,  [r3], #4 \n" /* r1 = ctx.sp (temp);  r3 -> ctx.pc */
			 "ldr   r2,  [r3], #4 \n" /* r2 = ctx.pc (temp);  r3 -> ctx.r1 */
			 "mov   sp,  r1       \n" /* sp = ctx.sp */
			 "ldr   r1,  [r3, #12]\n" /* ctx.xpsr (temp; NZCVQ only below) */
			 "msr   APSR_nzcvq, r1\n"
			 "push  {r2}          \n" /* stage ctx.pc on the guest stack */
			 "ldr   r1,  [r3]     \n" /* r1 = ctx.r1 (final) */
			 "ldr   r2,  [r3, #4] \n" /* r2 = ctx.r2 (final) */
			 "ldr   r0,  [r0]     \n" /* r0 = desc->r0 (the resume value) */
			 "ldr   r3,  [r3, #8] \n" /* r3 = ctx.r3 (final; last use as ptr) */
			 "pop   {pc}          \n"); /* branch ctx.pc; sp restored to ctx.sp */
}

static struct resume_desc *stash_desc(uint32_t sp, const struct lxp_resume_ctx *ctx, long r0)
{
	/* Reserve 8 bytes just below sp: prog_tramp stages ctx.pc there (push) as it enters
	 * the guest, so the descriptor must NOT occupy [sp-8, sp) — otherwise that push
	 * overwrites the descriptor's tail (ctx.r3) before prog_tramp reads it back. */
	uint32_t top = (sp & ~7u) - 8u;
	struct resume_desc *d = (struct resume_desc *)(top - ((sizeof(struct resume_desc) + 7u) & ~7u));
	d->r0 = (uint32_t)r0;
	d->ctx = *ctx;
	return d;
}

/* ---- the lxp_os_ops_t vtable ----------------------------------------------- */
static uint8_t *qemu_region(int ridx)
{
	return g_prog_regions[ridx];
}

/* M3: the PSRAM dyn_pool backing a dynamic proc's arena (libc.so mmap + heap). */
static uint8_t *qemu_dyn_pool(int ridx, size_t *sz)
{
	if (sz)
		*sz = LXP_DYN_POOL_SIZE;
	return g_dyn_pools[ridx];
}

static lxp_exec_capture_t *qemu_exec_capture(int sidx)
{
	return (sidx >= 0 && sidx < LXP_NSLOT) ? &g_exec_captures[sidx] : NULL;
}

/* Spawn the guest as a RESTRICTED, UNPRIVILEGED FreeRTOS task entering prog_tramp.
 * Its only RW regions are its program region + dyn_pool (both execute-never), plus an
 * unprivileged RO+X window over the PSRAM cpio so it can XIP ld.so/libc/busybox in
 * place — clean W^X. Code for M1/M2 XIPs from the flash cpio, covered by the port's
 * static unprivileged-RX flash region. A stray access outside these faults MemManage. */
static int spawn_common(int sidx, int ridx, struct resume_desc *desc)
{
	char nm[5] = {'l', 'n', 'x', (char)('0' + sidx), 0};
	const uint32_t rw_xn = portMPU_REGION_READ_WRITE | portMPU_REGION_EXECUTE_NEVER |
			       portMPU_REGION_CACHEABLE_BUFFERABLE;
	const uint32_t ro_x = portMPU_REGION_READ_ONLY | portMPU_REGION_CACHEABLE_BUFFERABLE;
	TaskParameters_t tp = {
		.pvTaskCode = prog_tramp,
		.pcName = nm,
		.usStackDepth = TRAMP_STACK_WORDS,
		.pvParameters = desc,
		.uxPriority = SLOT_PRIO, /* NO portPRIVILEGE_BIT → UNPRIVILEGED */
		.puxStackBuffer = g_tramp_stacks[sidx],
		.pxTaskBuffer = &g_tcb[sidx],
		.xRegions = {
			{g_prog_regions[ridx], LXP_PROG_REGION_SIZE, rw_xn}, /* [0] image + stack */
			{g_dyn_pools[ridx], LXP_DYN_POOL_SIZE, rw_xn},       /* [1] dynamic arena */
			/* [2],[3] the M3 PSRAM cpio window (bottom 12 MiB), unprivileged RO+X. Two
			 * power-of-2 regions (8M+4M) so they don't overlap the dyn_pools at 0x60C00000.
			 * Inert for M1/M2 (their cpio is in flash; the guest never touches PSRAM). */
			{(uint8_t *)0x60000000u, 8u * 1024u * 1024u, ro_x},
			{(uint8_t *)0x60800000u, 4u * 1024u * 1024u, ro_x},
		},
	};
	BaseType_t ok = xTaskCreateRestrictedStatic(&tp, &g_tid[sidx]);
	g_lxp_used[sidx] = (ok == pdPASS);
	return (ok == pdPASS) ? 0 : -1;
}

static int qemu_spawn_launch(int sidx, int ridx, const lxp_flat_t *prog, void *entry, void *sp,
			     void *stack_lo)
{
	(void)stack_lo;
	struct lxp_resume_ctx c;
	memset(&c, 0, sizeof(c));
	c.r4_11[3] = prog->is_fdpic ? (uint32_t)prog->loadmap : 0u;        /* r7 */
	c.r4_11[4] = prog->is_fdpic ? (uint32_t)prog->interp_loadmap : 0u; /* r8 */
	c.r4_11[5] = prog->is_fdpic ? (uint32_t)prog->got : 0u;            /* r9 */
	c.sp = (uint32_t)sp;
	c.pc = (uint32_t)entry | 1u; /* Cortex-M is Thumb-only: prog_tramp's bx needs bit0 set */
	return spawn_common(sidx, ridx, stash_desc((uint32_t)sp, &c, 0));
}

static void qemu_spawn_resume(int sidx, int ridx, const struct lxp_resume_ctx *ctx, long r0val)
{
	(void)spawn_common(sidx, ridx, stash_desc(ctx->sp, ctx, r0val));
}

static void qemu_abort_slot(int sidx)
{
	if (g_lxp_used[sidx] && g_tid[sidx])
		vTaskDelete(g_tid[sidx]);
	g_lxp_used[sidx] = 0;
	g_tid[sidx] = NULL;
}

static void qemu_sleep_ms(unsigned ms)
{
	vTaskDelay(pdMS_TO_TICKS(ms ? ms : 1));
}
static void qemu_crit_enter(void)
{
	taskENTER_CRITICAL();
}
static void qemu_crit_exit(void)
{
	taskEXIT_CRITICAL();
}

static StaticSemaphore_t g_ev_buf;
static SemaphoreHandle_t g_ev;
static void engine_event_post(void)
{
	BaseType_t woken = pdFALSE;
	if (g_ev)
		xSemaphoreGiveFromISR(g_ev, &woken);
	portYIELD_FROM_ISR(woken);
}
static void qemu_event_wait(unsigned ms)
{
	if (g_ev)
		xSemaphoreTake(g_ev, ms ? pdMS_TO_TICKS(ms) : portMAX_DELAY);
}

static int qemu_prepare(void)
{
	if (!g_ev)
		g_ev = xSemaphoreCreateBinaryStatic(&g_ev_buf);
	/* Contain program Bus/Usage/MemManage faults in our handlers instead of
	 * escalating to HardFault. SHCSR @ 0xE000ED24: MEM=16, BUS=17, USG=18. */
	*(volatile uint32_t *)0xE000ED24u |= (1u << 16) | (1u << 17) | (1u << 18);
	return g_ev ? 0 : -1;
}

static int qemu_time_us(uint64_t *out)
{
	*out = lxp_qemu_now_us();
	return LXP_OK;
}
static int qemu_time_ns(uint64_t *out)
{
	*out = lxp_qemu_now_us() * 1000u;
	return LXP_OK;
}

static int qemu_mem_stats(struct lxp_mem_stats *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	out->total = configTOTAL_HEAP_SIZE;
	out->free = xPortGetFreeHeapSize();
	out->used = out->total - out->free;
	out->peak_used = out->total - xPortGetMinimumEverFreeHeapSize();
	return LXP_OK;
}

static const char *qemu_system_version(void)
{
	return "FreeRTOS " tskKERNEL_VERSION_NUMBER " lxp-standalone";
}

/* Explicitly non-cryptographic entropy for the deterministic development-only
 * QEMU target. Production ports must provide a hardware/OS entropy source; the
 * personality core itself has no weak fallback. */
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

const lxp_os_ops_t g_lxp_qemu_engine = {
	.region = qemu_region,
	.spawn_launch = qemu_spawn_launch,
	.spawn_resume = qemu_spawn_resume,
	.abort_slot = qemu_abort_slot,
	.sleep_ms = qemu_sleep_ms,
	.crit_enter = qemu_crit_enter,
	.crit_exit = qemu_crit_exit,
	.event_post = engine_event_post,
	.event_wait = qemu_event_wait,
	.prepare = qemu_prepare,
	.time_us = qemu_time_us,
	.time_ns = qemu_time_ns,
	.random_fill = qemu_random_fill,
	.mem_stats = qemu_mem_stats,
	.system_version = qemu_system_version,
	.dyn_pool = qemu_dyn_pool, /* M3: hosts a dynamic proc's libc.so mmap + arena */
	.exec_capture = qemu_exec_capture,
	/* map_device / thread_list / cache_* / rootfs_window / exec_stage: NULL — the
	 * target is coherent (no cache), the rootfs is a plain RAM/PSRAM window (weak
	 * lxp_rootfs_window no-op), and the spawn path already installs each task's MPU
	 * view. Device mapping and netfs exec staging are not provided by this port. */
};
