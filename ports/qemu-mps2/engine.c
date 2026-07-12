/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The standalone QEMU harness engine: it fills lxp_os_ops_t on top of a vendored
 * FreeRTOS kernel (Arm MPS2-AN500 / Cortex-M7, non-MPU port), so the lxp module
 * runs under QEMU with FreeRTOS providing the proven task/context-switch — this is
 * a de-oveRTOS'd distillation of backends/freertos/freertos_lnx.c. Each guest is a
 * FreeRTOS task; its Linux syscall traps to SVC_Handler, which captures the frame,
 * drives lxp_dispatch(), and (on a park) wakes the coordinator via a semaphore.
 *
 * M1 scope: guests run PRIVILEGED, no MPU (the process model is cooperative +
 * serialized). Unprivileged + per-region MPU (the ARM_CM4_MPU port + the QSPI/PSRAM
 * XIP window) is a later milestone; the module's user_ok/user_strnlen guards still
 * cover the confused-deputy vector meanwhile.
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

/* ---- guest program regions (RW image + arena + stack), in RAM --------------- */
/* Plain .bss (zeroed by Reset): the FDPIC loader relies on the region — the guest's
 * .bss + arena — starting zeroed. A NOLOAD section would be uninitialised garbage. */
static uint8_t g_prog_regions[LXP_NREG][LXP_PROG_REGION_SIZE] __attribute__((aligned(8)));

#define SLOT_PRIO 1 /* guests run below the coordinator (which calls lxp_run) */
#define TRAMP_STACK_WORDS 256
static StackType_t g_tramp_stacks[LXP_NSLOT][TRAMP_STACK_WORDS]
	__attribute__((aligned(8)));
static StaticTask_t g_tcb[LXP_NSLOT];
static TaskHandle_t g_tid[LXP_NSLOT];

static int current_slot(void)
{
	TaskHandle_t t = xTaskGetCurrentTaskHandle();
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
};
static struct lnx_capture g_cap __attribute__((used));

/* Build the uniform frame, dispatch, write it back. Returns 1 if it handled a
 * program's Linux svc, 0 to FORWARD the svc to FreeRTOS (start-scheduler etc.). */
int lxp_qemu_svc_c(struct lnx_capture *g)
{
	int sidx = current_slot();
	if (!g_lxp_active || sidx < 0)
		return 0; /* not a running program → FreeRTOS's own svc */
	struct lxp_frame f;
	f.r[0] = g->hw[0];
	f.r[1] = g->hw[1];
	f.r[2] = g->hw[2];
	f.r[3] = g->hw[3];
	for (int i = 0; i < 8; i++)
		f.r[4 + i] = g->r4_11[i];
	f.r[12] = g->hw[4];
	f.r[13] = g->psp + 32u + ((g->hw[7] & (1u << 9)) ? 4u : 0u);
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
	return 1;
}

extern void vPortSVCHandler(void); /* FreeRTOS's own (start-scheduler) handler */

__attribute__((naked)) void SVC_Handler(void)
{
	__asm__ volatile("tst   lr, #8              \n" /* svc from thread mode? (a program svc) */
			 "beq   1f                  \n" /* handler-mode svc → FreeRTOS */
			 "mrs   r0, psp             \n"
			 "ldr   r1, =g_cap          \n"
			 "str   r0, [r1, #0]        \n"
			 "str   r0, [r1, #4]        \n"
			 "add   r2, r1, #8          \n"
			 "stmia r2, {r4-r11}        \n"
			 "mov   r0, r1              \n"
			 "push  {lr}                \n"
			 "bl    lxp_qemu_svc_c      \n"
			 "pop   {lr}                \n"
			 "cmp   r0, #0              \n"
			 "beq   1f                  \n" /* 0 = not a program svc → forward */
			 "bx    lr                  \n" /* 1 = handled: replay the frame */
			 "1:                        \n"
			 "b     vPortSVCHandler     \n");
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
		engine_event_post();
		return;
	}
	HardFault_Handler(); /* not a program fault → fatal */
}

__attribute__((naked)) void MemManage_Handler(void)
{
	__asm__ volatile("mrs r0, psp \n b lxp_qemu_fault_c");
}
__attribute__((naked)) void UsageFault_Handler(void)
{
	__asm__ volatile("mrs r0, psp \n b lxp_qemu_fault_c");
}
__attribute__((naked)) void BusFault_Handler(void)
{
	__asm__ volatile("mrs r0, psp \n b lxp_qemu_fault_c");
}

/* ---- thread entry: in-region descriptor + unified trampoline --------------- */
struct resume_desc {
	uint32_t r0;
	struct lxp_resume_ctx ctx; /* r4_11[8], r12, lr, sp, pc */
};

__attribute__((naked)) static void prog_tramp(void *desc __attribute__((unused)))
{
	/* desc in r0. Restore r4..r11 (r7/r8/r9 = FDPIC exec/interp loadmap + GOT), r12,
	 * lr, r0 = desc->r0; switch SP last, then branch to ctx.pc. */
	__asm__ volatile("add   r1, r0, #4    \n"
			 "ldmia r1!, {r4-r11}\n"
			 "ldr   r12, [r1], #4\n"
			 "ldr   lr,  [r1], #4\n"
			 "ldr   r2,  [r1], #4\n" /* ctx.sp */
			 "ldr   r3,  [r1]    \n" /* ctx.pc */
			 "ldr   r0,  [r0]    \n" /* desc->r0 */
			 "mov   sp,  r2      \n"
			 "bx    r3           \n");
}

static struct resume_desc *stash_desc(uint32_t sp, const struct lxp_resume_ctx *ctx, long r0)
{
	struct resume_desc *d = (struct resume_desc *)((sp & ~7u) - ((sizeof(struct resume_desc) + 7u) & ~7u));
	d->r0 = (uint32_t)r0;
	d->ctx = *ctx;
	return d;
}

/* ---- the lxp_os_ops_t vtable ----------------------------------------------- */
static uint8_t *qemu_region(int ridx)
{
	return g_prog_regions[ridx];
}

static int spawn_common(int sidx, struct resume_desc *desc)
{
	char nm[5] = {'l', 'n', 'x', (char)('0' + sidx), 0};
	g_tid[sidx] = xTaskCreateStatic(prog_tramp, nm, TRAMP_STACK_WORDS, desc, SLOT_PRIO,
					g_tramp_stacks[sidx], &g_tcb[sidx]);
	g_lxp_used[sidx] = (g_tid[sidx] != NULL);
	return g_tid[sidx] ? 0 : -1;
}

static int qemu_spawn_launch(int sidx, int ridx, const lxp_flat_t *prog, void *entry, void *sp,
			     void *stack_lo)
{
	(void)ridx;
	(void)stack_lo;
	struct lxp_resume_ctx c;
	memset(&c, 0, sizeof(c));
	c.r4_11[3] = prog->is_fdpic ? (uint32_t)prog->loadmap : 0u;        /* r7 */
	c.r4_11[4] = prog->is_fdpic ? (uint32_t)prog->interp_loadmap : 0u; /* r8 */
	c.r4_11[5] = prog->is_fdpic ? (uint32_t)prog->got : 0u;            /* r9 */
	c.sp = (uint32_t)sp;
	c.pc = (uint32_t)entry | 1u; /* Cortex-M is Thumb-only: prog_tramp's bx needs bit0 set */
	return spawn_common(sidx, stash_desc((uint32_t)sp, &c, 0));
}

static void qemu_spawn_resume(int sidx, int ridx, const struct lxp_resume_ctx *ctx, long r0val)
{
	(void)ridx;
	(void)spawn_common(sidx, stash_desc(ctx->sp, ctx, r0val));
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
	/* dyn_pool / map_device / thread_list / cache_* / rootfs_window / exec_stage:
	 * NULL — M1 is static FDPIC on a coherent, MPU-less target. */
};
