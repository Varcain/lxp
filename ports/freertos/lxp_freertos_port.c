/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of lxp.
 *
 * Production FreeRTOS MPU port for the Linux personality. The engine-agnostic
 * run loop, syscall dispatch and signal delivery live in src/lxp_run.c. This
 * file owns the native task lifecycle, exception traps, parking and PMSAv7
 * profile machinery. Board placement and services enter through one explicit
 * lxp_freertos_port_config_t supplied by the embedding system.
 *
 * On supported personality boards the program runs as a restricted,
 * UNPRIVILEGED task under the ARM_CM4_MPU port. Its `svc #0` takes the SVCall
 * exception, which this seam OWNS: the board's FreeRTOSConfig.h does NOT alias
 * vPortSVCHandler->SVC_Handler, so the strong SVC_Handler below is the vector; it
 * dispatches the program's svc (while a run is active) to the personality and
 * forwards FreeRTOS's own start-scheduler svc to vPortSVCHandler.
 */

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"

#if !defined(portUSING_MPU_WRAPPERS) || (portUSING_MPU_WRAPPERS != 1)
#error "The FreeRTOS Linux personality requires an MPU-wrapper port"
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lxp/arch/cortex_m_cache.h"
#include "lxp/arch/cortex_m_mpu.h"
#include "lxp/arch/cortex_m_scb.h"
#include "lxp/lxp_run.h"
#include "lxp/lxp_rt_metrics.h"
#include "lxp/lxp_seam.h"
#include "lxp/ports/freertos.h"

#include "../common/lxp_cortex_m_context.h"
#include "../common/lxp_cortex_m_port.h"

#define TRAMP_STACK_WORDS 192u		  /* tramp prologue; the program uses its own stack */
#define TRAMP_STORAGE_WORDS 256u	  /* 768-byte stack + 256-byte resume handoff */
#define SLOT_PRIO (tskIDLE_PRIORITY + 1u) /* below the run-loop task (its creator) */
#define GUEST_SCHED_PRIO (SLOT_PRIO + 1u) /* no higher than coordinator; above every guest */
#define GUEST_SCHED_STACK_WORDS 128u /* measured peak: 33 words under QEMU M9 stress */
#define PORT_CONFIG g_lxp_freertos_port_config
#define dyn_pools ((uint8_t (*)[LXP_DYN_POOL_SIZE])(void *)PORT_CONFIG.common.dynamic_pools)
#define prog_regions ((uint8_t (*)[LXP_PROG_REGION_SIZE])(void *)PORT_CONFIG.common.program_regions)
struct freertos_prepared_profile {
	lxp_memory_policy_key_t key;
	MemoryRegion_t regions[portNUM_CONFIGURABLE_REGIONS];
	uint32_t native_rbar[portNUM_CONFIGURABLE_REGIONS];
	uint32_t native_rasr[portNUM_CONFIGURABLE_REGIONS];
	uint8_t live_validated;
	uint8_t valid;
};
struct resume_desc;
struct freertos_lxp_slot {
	TaskHandle_t tid;
	uint32_t generation;
	struct freertos_prepared_profile profile;
	struct resume_desc *park_desc;
	uint8_t sched_blocked;
};
static struct freertos_lxp_slot g_slots[LXP_NSLOT];
/* FreeRTOS owns the opaque task control-block storage; this port owns g_slots. */
static StaticTask_t g_tcb[LXP_NSLOT];
static uint32_t g_tick_budget_ticks;
static TaskHandle_t g_tick_budget_owner;
static uint8_t g_tick_subscribed;
static int g_selected_slot = -1;
static TaskHandle_t g_rotate_owner;
static uint32_t g_rotate_generation;
static uint8_t g_rotate_pending;
static StaticSemaphore_t g_sched_ev_buf;
static SemaphoreHandle_t g_sched_ev;
static StaticTask_t g_sched_tcb;
static StackType_t g_sched_stack[GUEST_SCHED_STACK_WORDS];
static TaskHandle_t g_sched_task;
static void freertos_park_entry(void *token);
static int freertos_validate_active_profile(int sidx);

_Static_assert(GUEST_SCHED_PRIO < configMAX_PRIORITIES,
	       "FreeRTOS needs a native priority between Linux guests and their coordinator");

static lxp_slot_ref_t task_slot_ref(int slot)
{
	return lxp_slot_ref(slot,
			    slot >= 0 && slot < LXP_NSLOT ? g_slots[slot].generation : 0);
}

/* Each allocation is a 1K-aligned PMSAv7 stack region. The task uses the
 * bottom 768 bytes; the top 256 bytes retain its persistent resume handoff. */
static StackType_t g_tramp_stacks[LXP_NSLOT][TRAMP_STORAGE_WORDS]
	__attribute__((aligned(TRAMP_STORAGE_WORDS * sizeof(StackType_t))));

/* Exception-containment code must never issue a VFP instruction.  A guest can
 * fault while lazy FP preservation is pending and its PSP is already invalid;
 * touching the FPU in that state retries the failed lazy store and escalates
 * the configurable fault to HardFault before the guest can be reaped. */
#define LXP_FAULT_GPR_ONLY __attribute__((target("general-regs-only")))

static int current_slot(void)
{
	/* Read pxCurrentTCB directly instead of xTaskGetCurrentTaskHandle(): under the MPU port the
	 * accessor is an MPU_* wrapper that does a privilege check + trampoline on every call, and it
	 * svc-raises-privilege when the caller looks unprivileged — which HardFaults from the svc-handler
	 * context (the reason e70fc5f switched the tick sampler to the raw read too). The handle IS the
	 * TCB pointer, and handler mode reads privileged data fine. Removes the wrapper indirection from
	 * every syscall's slot lookup. */
	extern void *volatile pxCurrentTCB;
	TaskHandle_t t = (TaskHandle_t)pxCurrentTCB;
	for (int i = 0; i < LXP_NSLOT; i++)
		if (g_slots[i].tid == t && lxp_slot_ref_is_runnable(task_slot_ref(i)))
			return i;
	return -1;
}

/* Guest-only proportional scheduling. FreeRTOS advances an equal-priority
 * ready-list cursor every time it selects that priority, even when global time
 * slicing is off. A frequent higher-priority host wakeup would therefore
 * rotate guests independently of their LXP quantum. Keep exactly one guest
 * native-runnable and defer weighted rotation from SysTick to a small
 * privileged task. All guests remain in SLOT_PRIO; this gate cannot raise a
 * Linux process above host service or real-time work. */
static void freertos_tick_budget_reset(void)
{
	g_tick_budget_ticks = 0;
	g_tick_budget_owner = NULL;
}

static int freertos_sched_slot_runnable(int sidx)
{
	return sidx >= 0 && sidx < LXP_NSLOT && g_slots[sidx].tid &&
	       lxp_slot_ref_is_runnable(task_slot_ref(sidx));
}

static void freertos_sched_cancel_rotation_locked(void)
{
	g_rotate_owner = NULL;
	g_rotate_generation = 0;
	g_rotate_pending = 0u;
}

/* Called with the FreeRTOS critical section held. The ignored slot can still
 * be core-runnable while its synchronous park/abort callback is committing. */
static int freertos_sched_find_next_locked(int after, int ignore)
{
	for (int n = 1; n <= LXP_NSLOT; n++) {
		int sidx = (after + n + LXP_NSLOT) % LXP_NSLOT;
		if (sidx != ignore && freertos_sched_slot_runnable(sidx) &&
		    g_slots[sidx].sched_blocked)
			return sidx;
	}
	return -1;
}

static void freertos_sched_activate_locked(int sidx)
{
	if (sidx < 0)
		return;
	g_slots[sidx].sched_blocked = 0u;
	g_selected_slot = sidx;
	freertos_tick_budget_reset();
	vTaskResume(g_slots[sidx].tid);
}

/* Register a newly core-runnable task. Fresh tasks are already ready after
 * xTaskCreateRestrictedStatic; persistent tasks remain suspended from park. */
static void freertos_sched_register_ready(int sidx, int native_suspended)
{
	taskENTER_CRITICAL();
	if (!freertos_sched_slot_runnable(g_selected_slot) ||
	    g_slots[g_selected_slot].sched_blocked) {
		g_selected_slot = sidx;
		g_slots[sidx].sched_blocked = 0u;
		freertos_tick_budget_reset();
		if (native_suspended)
			vTaskResume(g_slots[sidx].tid);
	} else if (g_selected_slot != sidx) {
		g_slots[sidx].sched_blocked = 1u;
		if (!native_suspended)
			vTaskSuspend(g_slots[sidx].tid);
	}
	taskEXIT_CRITICAL();
}

static void freertos_sched_task_entry(void *arg)
{
	(void)arg;
	for (;;) {
		(void)xSemaphoreTake(g_sched_ev, portMAX_DELAY);
		taskENTER_CRITICAL();
		TaskHandle_t owner = g_rotate_owner;
		uint32_t generation = g_rotate_generation;
		int current = g_selected_slot;
		freertos_sched_cancel_rotation_locked();
		if (freertos_sched_slot_runnable(current) && g_slots[current].tid == owner &&
		    g_slots[current].generation == generation) {
			int next = freertos_sched_find_next_locked(current, -1);
			if (next >= 0) {
				g_slots[current].sched_blocked = 1u;
				vTaskSuspend(g_slots[current].tid);
				freertos_sched_activate_locked(next);
			}
		}
		taskEXIT_CRITICAL();
	}
}

static void lxp_freertos_tick(void)
{
	if (!lxp_trap_active()) {
		freertos_tick_budget_reset();
		return;
	}
	/* A tick that finds host work running (a higher-priority task, the coordinator) pauses
	 * the guest's budget. Resetting it instead let a frequent host wakeup keep a heavily
	 * weighted guest from ever using up its quantum, so it never rotated out and starved
	 * every other guest. */
	int current = current_slot();
	if (current < 0)
		return;
	if (g_tick_budget_owner != g_slots[current].tid) {
		g_tick_budget_owner = g_slots[current].tid;
		g_tick_budget_ticks = 0;
	}
	uint32_t quantum_ms = PORT_CONFIG.guest_quantum_ms ? PORT_CONFIG.guest_quantum_ms : 10u;
	uint32_t base_ticks = (quantum_ms * (uint32_t)configTICK_RATE_HZ + 999u) / 1000u;
	if (base_ticks == 0)
		base_ticks = 1;
	uint32_t weight = lxp_guest_sched_weight(current);
	uint32_t quantum_ticks = (base_ticks * weight + 19u) / 20u;
	if (quantum_ticks == 0)
		quantum_ticks = 1;
	if (++g_tick_budget_ticks < quantum_ticks)
		return;
	g_tick_budget_ticks = 0;
	for (int s = 0; s < LXP_NSLOT; s++) {
		if (s != current && freertos_sched_slot_runnable(s) && g_slots[s].sched_blocked &&
		    !g_rotate_pending && g_sched_task) {
			BaseType_t woken = pdFALSE;
			g_rotate_owner = g_slots[current].tid;
			g_rotate_generation = g_slots[current].generation;
			g_rotate_pending = 1u;
			xSemaphoreGiveFromISR(g_sched_ev, &woken);
			portYIELD_FROM_ISR(woken);
			return;
		}
	}
}

/* ---- the SVC trap ---------------------------------------------------------- */
/* The HW-stacked exception frame (live on the program PSP) + the callee-saved
 * registers the asm shim captures before they are clobbered. */
struct lnx_capture {
	uint32_t *hw;	   /* hw[0..7] = r0,r1,r2,r3,r12,lr,pc,xpsr */
	uint32_t psp;	   /* the program SP at the HW frame */
	uint32_t r4_11[8]; /* r4..r11 */
	uint32_t exc_return;
#if LXP_ENABLE_FPU_CONTEXT
	struct lxp_fp_context fp;
#endif
};
/* SVC_Handler stores into g_cap by hardcoded byte offset (str r0,[r1,#0]; #4; add r2,r1,#8;
 * str lr,[r1,#40]) — pin each so a struct-layout change is a build error, not silent corruption
 * of the syscall-capture path. */
_Static_assert(offsetof(struct lnx_capture, hw) == 0u, "SVC capture hw offset");
_Static_assert(offsetof(struct lnx_capture, psp) == 4u, "SVC capture psp offset");
_Static_assert(offsetof(struct lnx_capture, r4_11) == 8u, "SVC capture r4-r11 offset");
_Static_assert(offsetof(struct lnx_capture, exc_return) == 40u, "SVC capture EXC_RETURN offset");
static struct lnx_capture g_cap __attribute__((used)); /* referenced from SVC_Handler asm */

/* The C body of the svc trap: build the uniform frame, dispatch, write back.
 * Returns 1 if it handled a program's svc #0 (Linux syscall), 0 to FORWARD the svc
 * to FreeRTOS. Under the MPU port FreeRTOS uses svc itself (portYIELD = svc #101,
 * raised by the privileged idle task; raise-privilege = svc #102; start-scheduler =
 * svc #100), so any svc from a non-program task (current_slot() < 0) must reach
 * vPortSVCHandler. The current_slot() gate also blocks escalation: a malicious svc
 * #102 from a program task is current_slot() >= 0 → dispatched as a (bogus) syscall,
 * never reaching the port's raise-privilege path. */
int lxp_freertos_svc_c(struct lnx_capture *g)
{
#if LXP_ENABLE_RT_METRICS
	uint32_t svc_start_cycles = PORT_CONFIG.svc_cycle_counter ? *PORT_CONFIG.svc_cycle_counter
								  : 0u;
#endif
	int sidx = current_slot();
	if (sidx < 0)
		return 0; /* not a program task → forward to FreeRTOS */
	if (!freertos_validate_active_profile(sidx)) {
		lxp_guest_fault_t fault = {
			.detail = LXP_CORTEX_M_MPU_PROFILE_FAULT,
			.address = 0u,
		};
		(void)lxp_slot_report_memory_fault(task_slot_ref(sidx), &fault);
		g->hw[6] = ((uint32_t)&freertos_park_entry) & ~1u;
		g->hw[7] |= (1u << 24);
		return 1;
	}
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	uint32_t fp_frame_bytes = 0;
#if LXP_ENABLE_FPU_CONTEXT
	f.fp = &g->fp;
	memset(&g->fp, 0, sizeof(g->fp));
	if ((g->exc_return & (1u << 4)) == 0) {
		lxp_cortex_m_fp_capture(&g->fp, &g->hw[8], &g->hw[24]);
		fp_frame_bytes = LXP_CORTEX_M_FP_FRAME_BYTES;
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

	(void)lxp_dispatch_slot(task_slot_ref(sidx), &f);

	g->hw[0] = f.r[0];
	g->hw[1] = f.r[1];
	g->hw[2] = f.r[2];
	g->hw[3] = f.r[3];
	g->hw[4] = f.r[12];
	g->hw[5] = f.r[14];
	g->hw[6] = f.r[15];
	g->hw[7] = f.xpsr;
	/* Write r4-r11 back so a dispatch that rewrites a callee-saved register on the fast path
	 * takes effect. rt_sigreturn restores the interrupted code's r9 (FDPIC GOT) via
	 * lxp_sig_restore; a signal handler runs with its OWN r9, so without this the interrupted
	 * syscall resumes with the handler's GOT and its __errno_location PLT resolves through the
	 * wrong module (-> sigaction -> SIGSEGV). For every other syscall these equal the captured
	 * values, so SVC_Handler's reload is a no-op. */
	for (int i = 0; i < 8; i++)
		g->r4_11[i] = f.r[4 + i];
#if LXP_ENABLE_FPU_CONTEXT
	if ((g->exc_return & (1u << 4)) == 0)
		lxp_cortex_m_fp_writeback(&g->fp, &g->hw[8], &g->hw[24]);
#endif
#if LXP_ENABLE_RT_METRICS
	if (PORT_CONFIG.svc_cycle_counter) {
		/* Read before updating statistics so observer bookkeeping is excluded.
		 * Unsigned subtraction remains correct across counter wrap. */
		uint32_t svc_cycles = *PORT_CONFIG.svc_cycle_counter - svc_start_cycles;
		lxp_rt_svc_metrics_record(f.r[7], svc_cycles);
	}
#endif
	return 1;
}

extern void vPortSVCHandler(void); /* FreeRTOS's own (start-scheduler / yield / priv) handler */

/* SVC vector: while a run is active, capture the frame + dispatch the program's
 * svc; otherwise forward to FreeRTOS (start scheduler). */
__attribute__((naked)) void SVC_Handler(void)
{
	__asm__ volatile(
		"ldr   r1, =g_lxp_trap_gate \n"
		"ldr   r1, [r1]              \n"
		"cmp   r1, #0                \n"
		"beq   1f                    \n" /* inactive -> FreeRTOS */
		"dmb                          \n"
		/* EXC_RETURN bit 3 == 0 -> the svc was taken from HANDLER mode.  A Linux program
			  * always syscalls from THREAD mode (it runs as an unprivileged thread-mode task),
			  * so a handler-mode svc is never a program syscall — it is FreeRTOS's own (yield /
			  * raise-privilege / start-scheduler).  Capturing it from PSP (stale program frame)
			  * + dispatching it as a syscall is what corrupted the post-exit context.  Forward. */
		"tst   lr, #8                \n"
		"beq   1f                    \n"
		"mrs   r0, psp               \n" /* r0 = HW exception frame */
		"ldr   r1, =g_cap            \n"
		"str   r0, [r1, #0]          \n" /* g_cap.hw  */
		"str   r0, [r1, #4]          \n" /* g_cap.psp */
		"add   r2, r1, #8            \n"
		"stmia r2, {r4-r11}          \n" /* g_cap.r4_11 */
		"str   lr, [r1, #40]         \n" /* EXC_RETURN selects basic/extended frame */
		"mov   r0, r1                \n"
		/* The dispatch runs in HANDLER mode but inherits the program's CONTROL.nPRIV=1.
			  * FreeRTOS MPU_* wrappers (e.g. the event_post semaphore-give on a parking syscall)
			  * read nPRIV, believe they're unprivileged, and raise-privilege via svc #102 — taken
			  * inside this active SVCall it escalates to a HardFault. Clear nPRIV across the
			  * dispatch (handler mode is privileged regardless), then restore so the program
			  * resumes UNPRIVILEGED. */
		"mrs   r2, control           \n"
		"push  {r2, lr}              \n"
		"bic   r3, r2, #1            \n"
		"msr   control, r3           \n"
		"isb                         \n"
		"bl    lxp_freertos_svc_c    \n"
		"pop   {r2, lr}              \n"
		"msr   control, r2           \n"
		"isb                         \n"
		"cmp   r0, #0                \n"
		"beq   1f                    \n" /* 0 = not a program svc -> forward */
		/* Reload r4-r11 from g_cap (lxp_freertos_svc_c wrote them back post-dispatch): the
			  * exception return only replays the HW frame (r0-r3,r12,lr,pc,xpsr), so a callee-saved
			  * register the dispatch rewrote (rt_sigreturn's r9/FDPIC-GOT restore) would otherwise be
			  * dropped and the interrupted code resumes with the signal handler's GOT. */
		"ldr   r1, =g_cap            \n"
		"add   r1, r1, #8            \n"
		"ldmia r1, {r4-r11}          \n"
		"bx    lr                    \n" /* 1 = handled: exception return, replay frame */
		"1:                          \n"
		"b     vPortSVCHandler       \n");
}

/* ---- MemManage fault containment ------------------------------------------- */
/* An UNPRIVILEGED program making an illegal access raises MemManage (enabled by the MPU port's
 * prvSetupMPU). Contain it like a default-action SIGSEGV: publish a typed exit intent (139),
 * synthesize a trusted return frame on its internal trampoline stack, wake the coordinator (which
 * reaps the slot + frees the region via EV_EXIT), and exception-return to the park entry. A fault
 * from any NON-program (privileged kernel) context is a real bug -> fatal. Strong symbol overriding
 * the weak MemManage_Handler in the CMSIS startup. */
static void freertos_event_post(void) LXP_FAULT_GPR_ONLY; /* defined with the vtable below */
static void freertos_park_entry(void *token);

/* Terminal handler for a fault that cannot be attributed to a guest — i.e. a fault in host /
 * privileged context (the coordinator, an ISR, or before any guest is live). Such a fault means the
 * trusted side is compromised, so the only safe action is to STOP; recovering as if it were a guest
 * would run the host on corrupted state. Weak default: halt (a watchdog, if armed, reboots). The
 * board overrides it to print a diagnostic first. Runs in fault context, so it must never return
 * and must not touch VFP (general-regs-only) — an in-flight lazy-FP stack to an invalid frame would
 * nest another fault. */
static LXP_FAULT_GPR_ONLY void freertos_host_fatal(uint32_t cfsr, uint32_t hfsr, uint32_t pc)
{
	if (PORT_CONFIG.host_fatal)
		PORT_CONFIG.host_fatal(cfsr, hfsr, pc);
	for (;;) {
	}
}

struct lnx_fault_diag {
	uint32_t count;
	uint32_t cfsr;
	uint32_t hfsr;
	uint32_t mmfar;
	uint32_t bfar;
	uint32_t psp;
	uint32_t exc_return;
	uint32_t last_spawn_sp;
	uint32_t last_spawn_pc;
	uint32_t last_desc;
	uint32_t last_ridx;
	uint32_t last_kind; /* 1 = image launch, 2 = context resume */
};
/* Kept in host SRAM and intentionally non-static so a stopped target can be
 * diagnosed without logging or formatting in fault context. */
volatile struct lnx_fault_diag g_lxp_fault_diag[LXP_NSLOT];

uint32_t *LXP_FAULT_GPR_ONLY lxp_freertos_memfault_c(uint32_t exc_return, uint32_t psp)
{
	int sidx = current_slot();
	/* A Linux guest always runs in Thread mode on PSP.  Do not misclassify a
	 * nested host/ISR fault merely because a guest TCB is current. */
	if (lxp_trap_active() && sidx >= 0 && (exc_return & (1u << 3)) &&
	    (exc_return & (1u << 2))) {
		volatile struct lnx_fault_diag *diag = &g_lxp_fault_diag[sidx];
		diag->count++;
		diag->cfsr = LXP_CORTEX_M_SCB_CFSR;
		diag->hfsr = LXP_CORTEX_M_SCB_HFSR;
		diag->mmfar = LXP_CORTEX_M_SCB_MMFAR;
		diag->bfar = LXP_CORTEX_M_SCB_BFAR;
		diag->psp = psp;
		diag->exc_return = exc_return;

		lxp_guest_fault_t fault = {
			.detail = diag->cfsr,
			.address = (diag->cfsr & LXP_CORTEX_M_SCB_CFSR_MMARVALID)   ? diag->mmfar
				   : (diag->cfsr & LXP_CORTEX_M_SCB_CFSR_BFARVALID) ? diag->bfar
										    : 0u,
		};
		(void)lxp_slot_report_memory_fault(task_slot_ref(sidx), &fault);

		/* Never trust the faulting PSP frame: MSTKERR/MLSPERR means it may not
		 * exist at all, and an arbitrary guest PSP may point at read-only QSPI or
		 * host memory.  Build a basic frame at the top of the task's original
		 * internal-SRAM trampoline stack, which is still its automatic MPU stack
		 * region.  Exception return consumes the frame and enters the stackless
		 * park entry; the already-pended coordinator then deletes the task. */
		volatile uint32_t *frame =
			(uint32_t *)&g_tramp_stacks[sidx][TRAMP_STACK_WORDS - 8u];
		frame[0] = 0;
		frame[1] = 0;
		frame[2] = 0;
		frame[3] = 0;
		frame[4] = 0;
		frame[5] = 0;
		frame[6] = ((uint32_t)&freertos_park_entry) & ~1u;
		frame[7] = (1u << 24); /* xPSR.T (Thumb) */

		lxp_cortex_m_fault_status_clear();
		return (uint32_t *)frame;
	}
	/* Not a guest fault: host/privileged context, handler mode, or no active guest. Capture the
	 * fault registers and the faulting PC (offset 6 of a Thread-mode PSP frame), then go fatal —
 * host_fatal reports and halts, and does not return. */
	uint32_t cfsr = LXP_CORTEX_M_SCB_CFSR;
	uint32_t hfsr = LXP_CORTEX_M_SCB_HFSR;
	uint32_t pc = ((exc_return & (1u << 2)) && psp) ? ((volatile uint32_t *)psp)[6] : 0u;
	freertos_host_fatal(cfsr, hfsr, pc);
	for (;;) { /* belt-and-suspenders: the override must not return */
	}
}

__attribute__((naked)) void MemManage_Handler(void)
{
	__asm__ volatile("mrs  r1, psp                \n" /* r1 = untrusted fault-time PSP */
			 /* Same nPRIV dance as SVC_Handler: memfault_c calls FreeRTOS APIs
			  * (event_post) which must not raise-privilege via svc from here. */
			 "mrs  r2, control            \n"
			 "push {r2, lr}               \n"
			 "bic  r3, r2, #1             \n"
			 "msr  control, r3            \n"
			 "isb                         \n"
			 /* Cancel a pending lazy FP store before entering compiled code.  If
			  * the guest PSP caused MLSPERR, any VFP use before this write would
			  * immediately refault.  FPCCR.LSPACT is architecturally R/W. */
			 "ldr  r3, =" LXP_CORTEX_M_STR(LXP_CORTEX_M_FPCCR_ADDR) "\n"
			 "ldr  r0, [r3]               \n"
			 "bic  r0, r0, #1             \n"
			 "str  r0, [r3]               \n"
			 "dsb                         \n"
			 "isb                         \n"
			 "mov  r0, lr                 \n" /* r0 = original EXC_RETURN */
			 "bl   lxp_freertos_memfault_c\n"
			 "cbz  r0, 1f                 \n"
			 "msr  psp, r0                \n" /* trusted internal-SRAM basic frame */
			 "pop  {r2, lr}               \n"
			 "bic  r2, r2, #4             \n" /* CONTROL.FPCA = 0 */
			 "msr  control, r2            \n"
			 "orr  lr, lr, #0x10          \n" /* exception return uses basic frame */
			 "isb                         \n"
			 "bx   lr                     \n"
			 "1:                          \n"
			 "pop  {r2, lr}               \n"
			 "b    HardFault_Handler       \n");
}

/* UsageFault (undefined instruction / bad control flow) + BusFault get the SAME containment as
 * MemManage: a program fault is killed (139), a kernel fault is fatal. Both tail-branch into
 * MemManage_Handler's body (which reads the faulting PSP frame + calls lxp_freertos_memfault_c —
 * fault-type-agnostic, and its CFSR write-back already clears BFSR/UFSR too). Enabled via SHCSR in
 * lxp_run; the MPU port's prvSetupMPU only turns on MEMFAULTENA. */
__attribute__((naked)) void UsageFault_Handler(void)
{
	__asm__ volatile("b MemManage_Handler");
}
__attribute__((naked)) void BusFault_Handler(void)
{
	__asm__ volatile("b MemManage_Handler");
}

/* ---- thread entry: task-local descriptor + unified trampoline -------------- */
/* The program's entry/resume context is stashed in the user-readable tail of
 * its bootstrap stack, so the unprivileged trampoline can consume it while the
 * privileged coordinator can update it directly. */
struct resume_desc {
	uint32_t r0;
	struct lxp_resume_ctx ctx;
	volatile uint32_t ready;
};

/* prog_tramp reaches the context at desc + 4 (add r3, r0, #4) and the resume value at
 * desc + 0; the shared tail pins the context's own layout. */
_Static_assert(offsetof(struct resume_desc, r0) == 0u, "resume value offset (ldr r0, [r0])");
_Static_assert(offsetof(struct resume_desc, ctx) == 4u, "resume ctx offset (add r3, r0, #4)");

/* Resume a guest at its captured context: r0 is the descriptor. */
__attribute__((naked)) static void prog_tramp(void *desc __attribute__((unused)))
{
	__asm__ volatile("add   r3, r0, #4\n" /* r3 -> ctx */
			 "ldr   r0, [r0]\n"   /* the resume value */
			 LXP_CORTEX_M_RESUME_FROM_R3);
}

/* Bytes the descriptor occupies, rounded up to the MPU/cache-line granularity. */
#define RESUME_DESC_CLSPAN (((uint32_t)sizeof(struct resume_desc) + 31u) & ~31u)
_Static_assert(RESUME_DESC_CLSPAN <=
		       (TRAMP_STORAGE_WORDS - TRAMP_STACK_WORDS) * sizeof(StackType_t),
	       "resume descriptor exceeds reserved trampoline-stack tail");

/* Reserve the top 256 bytes of each aligned 1K bootstrap-stack allocation for
 * the persistent resume descriptor. The FreeRTOS task receives the lower 768
 * bytes as its logical stack; the ARM MPU port rounds that 768-byte stack region
 * to the containing aligned 1K region, so the unprivileged park entry can read
 * the tail without consuming another configurable MPU region. Unlike storage
 * below ctx->sp, this address is independent of Linux stack depth and cannot be
 * overwritten by exception or context-switch frames. */
static struct resume_desc *stash_desc(int sidx, const struct lxp_resume_ctx *ctx, long r0)
{
	struct resume_desc *d = (struct resume_desc *)&g_tramp_stacks[sidx][TRAMP_STACK_WORDS];
	d->r0 = (uint32_t)r0;
	d->ctx = *ctx;
	d->ready = 1u;
	return d;
}

/* Exception-side half of the persistent handoff. The descriptor remains in the
 * task's user-readable bootstrap-stack MPU region while it is suspended. */
static void *freertos_park_prepare(lxp_slot_ref_t slot, const struct lxp_resume_ctx *ctx)
{
	int sidx = slot.index;
	uint32_t generation = slot.generation;
	if (sidx < 0 || sidx >= LXP_NSLOT || !g_slots[sidx].tid ||
	    g_slots[sidx].generation != generation)
		return NULL;
	struct resume_desc *d = stash_desc(sidx, ctx, 0);
	__atomic_store_n(&d->ready, 0u, __ATOMIC_RELEASE);
	g_slots[sidx].park_desc = d;
	return d;
}

/* Runs unprivileged in the existing guest task. Normally the higher-priority
 * coordinator suspends the task before exception return; the bounded race is a
 * read-only wait on guest memory. spawn_resume publishes the descriptor and
 * resumes this same task, which restores the complete Linux register context. */
static void freertos_park_entry(void *token)
{
	struct resume_desc *d = token;
	while (!__atomic_load_n(&d->ready, __ATOMIC_ACQUIRE))
		__asm__ volatile("nop");
	prog_tramp(d);
	__builtin_unreachable();
}

/* Compile the core's versioned policy once into the exact native descriptors
 * consumed by xTaskCreateRestrictedStatic(). A fresh slot/address-space/device/
 * execute tuple invalidates the cache; a persistent parked-task resume does not
 * rebuild or reprogram its TCB MPU settings. */
static int freertos_prepare_profile(int sidx, uint32_t generation, int ridx)
{
	lxp_memory_policy_t policy;
	lxp_slot_ref_t slot = lxp_slot_ref(sidx, generation);
	if (lxp_slot_memory_policy(slot, &policy) != LXP_OK ||
	    lxp_memory_policy_validate(&policy) != LXP_OK || policy.address_space.index != ridx ||
	    policy.device_count != 0)
		return -1;
	struct freertos_prepared_profile *prepared = &g_slots[sidx].profile;
	if (prepared->valid && lxp_memory_policy_matches_key(&policy, &prepared->key))
		return 0;

	memset(prepared, 0, sizeof(*prepared));
	const uint32_t tex_s_c_b = PORT_CONFIG.common.guest_memory_texscb;
	const uint32_t rw_xn = portMPU_REGION_READ_WRITE | portMPU_REGION_EXECUTE_NEVER |
			       (tex_s_c_b << portMPU_RASR_TEX_S_C_B_LOCATION);
	prepared->regions[0] = (MemoryRegion_t){
		.pvBaseAddress = prog_regions[ridx],
		.ulLengthInBytes = LXP_PROG_REGION_SIZE,
		.ulParameters = rw_xn,
	};
	prepared->regions[1] = (MemoryRegion_t){
		.pvBaseAddress = dyn_pools[ridx],
		.ulLengthInBytes = LXP_DYN_POOL_SIZE,
		.ulParameters = rw_xn,
	};
	for (unsigned i = 0; i < PORT_CONFIG.rootfs_region_count; i++) {
		const lxp_freertos_rootfs_region_t *rootfs = &PORT_CONFIG.rootfs_regions[i];
		prepared->regions[2u + i] = (MemoryRegion_t){
			.pvBaseAddress = (void *)rootfs->base,
			.ulLengthInBytes = rootfs->size,
			.ulParameters = portMPU_REGION_READ_ONLY |
					(rootfs->texscb << portMPU_RASR_TEX_S_C_B_LOCATION),
		};
	}
	const unsigned copied_region = 2u + PORT_CONFIG.rootfs_region_count;
	if (policy.copied_text_executable) {
		if (policy.copied_text_base != (uintptr_t)prog_regions[ridx] ||
		    policy.copied_text_size != LXP_PROG_REGION_SIZE / 2u ||
		    copied_region >= portNUM_CONFIGURABLE_REGIONS)
			return -1;
		prepared->regions[0] = (MemoryRegion_t){
			.pvBaseAddress =
				(void *)(policy.copied_text_base + policy.copied_text_size),
			.ulLengthInBytes = LXP_PROG_REGION_SIZE - policy.copied_text_size,
			.ulParameters = rw_xn,
		};
		prepared->regions[copied_region] = (MemoryRegion_t){
			.pvBaseAddress = (void *)policy.copied_text_base,
			.ulLengthInBytes = policy.copied_text_size,
			.ulParameters = portMPU_REGION_READ_ONLY |
					(tex_s_c_b << portMPU_RASR_TEX_S_C_B_LOCATION),
		};
	}
	prepared->key = lxp_memory_policy_make_key(&policy);
	prepared->valid = 1u;
	return 0;
}

static int freertos_capture_native_profile(int sidx)
{
	if (sidx < 0 || sidx >= LXP_NSLOT || !g_slots[sidx].tid || !g_slots[sidx].profile.valid)
		return 0;
	struct freertos_prepared_profile *prepared = &g_slots[sidx].profile;
	const xMPU_SETTINGS *settings = xTaskGetMPUSettings(g_slots[sidx].tid);
	if (!settings)
		return 0;

	for (unsigned i = 0; i < portNUM_CONFIGURABLE_REGIONS; i++) {
		const MemoryRegion_t *logical = &prepared->regions[i];
		uint32_t rbar = settings->xRegion[i + 1u].ulRegionBaseAddress;
		uint32_t rasr = settings->xRegion[i + 1u].ulRegionAttribute;
		struct lxp_cortex_m_mpu_region native;
		if (lxp_cortex_m_mpu_region_decode(rbar, rasr, &native) != 0)
			return 0;
		if (logical->ulLengthInBytes == 0u) {
			if (native.enabled)
				return 0;
		} else {
			const struct lxp_cortex_m_mpu_expectation expected = {
				.base = (uintptr_t)logical->pvBaseAddress,
				.size = logical->ulLengthInBytes,
				.texscb = (uint8_t)((logical->ulParameters >> 16) & 0x3fu),
				.access = (uint8_t)((logical->ulParameters >> 24) & 0x7u),
				.execute_never = (uint8_t)((logical->ulParameters >> 28) & 1u),
			};
			if (!lxp_cortex_m_mpu_region_matches_expectation(&native, &expected))
				return 0;
		}
		prepared->native_rbar[i] = rbar;
		prepared->native_rasr[i] = rasr;
	}
	prepared->live_validated = 0u;
	return 1;
}

static int freertos_validate_active_profile(int sidx)
{
	if (sidx < 0 || sidx >= LXP_NSLOT)
		return 0;
	struct freertos_prepared_profile *prepared = &g_slots[sidx].profile;
	lxp_slot_ref_t slot = task_slot_ref(sidx);
	if (!prepared->valid || !lxp_slot_ref_equal(prepared->key.slot, slot))
		return 0;
	if (prepared->live_validated)
		return 1;

	struct lxp_cortex_m_mpu_snapshot snapshot;
	if (lxp_cortex_m_mpu_snapshot_read(&snapshot) != 0 ||
	    (snapshot.ctrl & (LXP_CORTEX_M_MPU_CTRL_ENABLE | LXP_CORTEX_M_MPU_CTRL_PRIVDEFENA)) !=
		    (LXP_CORTEX_M_MPU_CTRL_ENABLE | LXP_CORTEX_M_MPU_CTRL_PRIVDEFENA))
		return 0;
	for (unsigned i = 0; i < portNUM_CONFIGURABLE_REGIONS; i++) {
		unsigned region = portFIRST_CONFIGURABLE_REGION + i;
		if (!lxp_cortex_m_mpu_snapshot_region_holds(&snapshot, region,
							    prepared->native_rbar[i],
							    prepared->native_rasr[i], 1))
			return 0;
	}
	prepared->live_validated = 1u;
	return 1;
}

/* Spawn a RESTRICTED, UNPRIVILEGED task whose only RW regions are its program
 * region and dynamic pool. Ordinary code XIPs from a separate RO+X window. */
static int freertos_spawn_common(int sidx, uint32_t generation, int ridx, struct resume_desc *desc)
{
	char nm[6];
	lxp_slot_name(nm, sidx); /* diagnostic only; attribution uses the task handle */
	if (freertos_prepare_profile(sidx, generation, ridx) != 0)
		return -1;
	TaskParameters_t tp = {
		.pvTaskCode = prog_tramp,
		.pcName = nm,
		.usStackDepth = TRAMP_STACK_WORDS,
		.pvParameters = desc,
		.uxPriority = SLOT_PRIO, /* NO portPRIVILEGE_BIT -> UNPRIVILEGED */
		.puxStackBuffer = g_tramp_stacks[sidx],
		.pxTaskBuffer = &g_tcb[sidx],
	};
	for (unsigned i = 0; i < portNUM_CONFIGURABLE_REGIONS; i++)
		tp.xRegions[i] = g_slots[sidx].profile.regions[i];
	/* xTaskCreateRestrictedStatic may make the guest ready before returning.
	 * Publish its generation first so an immediate SVC resolves the current
	 * slot against the core's already-published runnable capability. */
	g_slots[sidx].generation = generation;
	BaseType_t ok = xTaskCreateRestrictedStatic(&tp, &g_slots[sidx].tid);
	if (ok != pdPASS) {
		g_slots[sidx].generation = 0;
		return -1;
	}
	/* The coordinator outranks SLOT_PRIO, so the new task cannot execute before
	 * this native TCB readback validates the port's logical-to-PMSAv7
	 * translation. The first guest SVC separately validates the live install. */
	if (!freertos_capture_native_profile(sidx)) {
		vTaskDelete(g_slots[sidx].tid);
		g_slots[sidx].tid = NULL;
		g_slots[sidx].generation = 0;
		g_slots[sidx].profile.valid = 0;
		return -1;
	}
	freertos_sched_register_ready(sidx, 0);
	return 0;
}

/* ---- the vtable: FreeRTOS task spawn --------------------------------------- */

static int freertos_spawn_launch(lxp_slot_ref_t slot, int ridx, const lxp_guest_launch_t *launch)
{
	int sidx = slot.index;
	uint32_t generation = slot.generation;
	if (sidx < 0 || sidx >= LXP_NSLOT || generation == 0 || !launch || g_slots[sidx].tid)
		return -1;
	g_slots[sidx].park_desc = NULL;
	struct lxp_resume_ctx c;
	lxp_resume_ctx_from_launch(&c, launch);
	struct resume_desc *d = stash_desc(sidx, &c, launch->r[0]);
	volatile struct lnx_fault_diag *diag = &g_lxp_fault_diag[sidx];
	diag->last_spawn_sp = c.sp;
	diag->last_spawn_pc = c.pc;
	diag->last_desc = (uint32_t)(uintptr_t)d;
	diag->last_ridx = (uint32_t)ridx;
	diag->last_kind = 1u;
	return freertos_spawn_common(sidx, generation, ridx, d);
}

static int freertos_spawn_resume(lxp_slot_ref_t slot, int ridx, lxp_spawn_resume_mode_t mode,
				 const struct lxp_resume_ctx *ctx, long r0val)
{
	int sidx = slot.index;
	uint32_t generation = slot.generation;
	if (sidx < 0 || sidx >= LXP_NSLOT || generation == 0)
		return -1;
	struct resume_desc *d = g_slots[sidx].park_desc;
	if (mode == LXP_SPAWN_RESUME_PARKED) {
		if (!g_slots[sidx].tid || !d || g_slots[sidx].generation != generation)
			return -1;
		lxp_memory_policy_t policy;
		if (!g_slots[sidx].profile.valid ||
		    lxp_slot_memory_policy(task_slot_ref(sidx), &policy) != LXP_OK ||
		    !lxp_memory_policy_matches_key(&policy, &g_slots[sidx].profile.key))
			return -1;
		d->r0 = (uint32_t)r0val;
		d->ctx = *ctx;
		__atomic_store_n(&d->ready, 1u, __ATOMIC_RELEASE);
		volatile struct lnx_fault_diag *diag = &g_lxp_fault_diag[sidx];
		diag->last_spawn_sp = ctx->sp;
		diag->last_spawn_pc = ctx->pc;
		diag->last_desc = (uint32_t)(uintptr_t)d;
		diag->last_ridx = (uint32_t)ridx;
		diag->last_kind = 3u;
		g_slots[sidx].profile.live_validated = 0u;
		freertos_sched_register_ready(sidx, 1);
		return 0;
	}
	if (mode != LXP_SPAWN_RESUME_START || g_slots[sidx].tid)
		return -1;
	d = stash_desc(sidx, ctx, r0val);
	volatile struct lnx_fault_diag *diag = &g_lxp_fault_diag[sidx];
	diag->last_spawn_sp = ctx->sp;
	diag->last_spawn_pc = ctx->pc;
	diag->last_desc = (uint32_t)(uintptr_t)d;
	diag->last_ridx = (uint32_t)ridx;
	diag->last_kind = 2u;
	return freertos_spawn_common(sidx, generation, ridx, d);
}

/* Give the coordinator (this run-loop task) a Normal-cacheable MPU view of guest region
 * `ridx`'s program region + dyn_pool while it services that slot's DEFERRED syscall or
 * parked-op retry, so the coordinator's CPU reads/writes of the guest's buffers hit the
 * SAME (PIPT) D-cache lines the guest uses — coherent by construction, no per-buffer
 * clean/invalidate. Off this hook the coordinator sees the pools through the uncached
 * background map. Uses the coordinator's own configurable regions 0 and 1, which are
 * unused on this non-restricted task; guests reprogram all configurable regions from
 * their own TCB on switch-in, so this never leaks into a guest's view. The framebuffer
 * (0xC0000000) and the ETH TX bounce (0xC07FF800) sit OUTSIDE the pools → they keep the
 * background non-cacheable attributes and stay DMA/scanout-safe. */
static int g_coord_mapped_ridx = -1;

/* The persistent bounded, non-cacheable window over memory-mapped rootfs storage:
 * rootfs_window installs it in the configured coordinator region (coord_map owns 0 and 1).
 * Recorded here so coord_map RE-SPECIFIES that region in the TCB on every remap and
 * never drops it: otherwise the first coord_map would zero the descriptor, and the loader's next
 * read (launch() reading an FDPIC ELF straight from QSPI) would fall through to the oversized
 * cacheable PRIVDEFENA background — the exact burst/speculation hazard the window prevents. Zero
 * base = not installed (no QSPI rootfs), so the preserve step below is a no-op. */
static uint32_t g_qspi_win_base;
static uint32_t g_qspi_win_len;
static uint32_t g_qspi_win_par;

static void freertos_coord_map(int ridx)
{
	if (!PORT_CONFIG.coordinator_cacheable_map || ridx < 0 || ridx >= LXP_NREG)
		return;
	if ((LXP_CORTEX_M_SCB_CCR & LXP_CORTEX_M_SCB_CCR_DC) == 0u)
		return; /* D-cache off: coordinator and guest already agree through SDRAM */
	if (ridx == g_coord_mapped_ridx)
		return; /* already live; the TCB copy restores it across a preemption */

	/* Normal WBWA cacheable, non-shareable, RW, execute-never — the exact attributes
	 * freertos_spawn_common gives the guest's own view of these pools. */
	const uint32_t attr = portMPU_REGION_READ_WRITE | portMPU_REGION_EXECUTE_NEVER |
			      ((uint32_t)PORT_CONFIG.common.guest_memory_texscb
			       << portMPU_RASR_TEX_S_C_B_LOCATION);
	/* The pool arrays are size-aligned (see prog_regions/dyn_pools), so each base is
	 * region-aligned. */
	const uint32_t prog_rasr = lxp_cortex_m_mpu_rasr_size(LXP_PROG_REGION_SIZE) | attr;
	const uint32_t dyn_rasr = lxp_cortex_m_mpu_rasr_size(LXP_DYN_POOL_SIZE) | attr;

	/* Record in the TCB FIRST so a preemption mid-service restores this same mapping
	 * (the port reprograms configurable regions from the TCB on switch-in); then write
	 * the live registers for immediate effect. The configured rootfs region carries the persistent NC
	 * window (g_qspi_win_*, installed by rootfs_window) — re-specify it so this remap
	 * preserves it in the TCB rather than zeroing it (the loader reads the NOR through it).
	 * Only regions 0 and 1 are written live below, so the live rootfs region is untouched. */
	MemoryRegion_t regions[portNUM_CONFIGURABLE_REGIONS];
	memset(regions, 0, sizeof(regions));
	regions[0].pvBaseAddress = prog_regions[ridx];
	regions[0].ulLengthInBytes = LXP_PROG_REGION_SIZE;
	regions[0].ulParameters = attr;
	regions[1].pvBaseAddress = dyn_pools[ridx];
	regions[1].ulLengthInBytes = LXP_DYN_POOL_SIZE;
	regions[1].ulParameters = attr;
	if (g_qspi_win_base &&
	    PORT_CONFIG.coordinator_rootfs_region < portNUM_CONFIGURABLE_REGIONS) {
		unsigned rootfs_region = PORT_CONFIG.coordinator_rootfs_region;
		regions[rootfs_region].pvBaseAddress = (void *)(uintptr_t)g_qspi_win_base;
		regions[rootfs_region].ulLengthInBytes = g_qspi_win_len;
		regions[rootfs_region].ulParameters = g_qspi_win_par;
	}
	vTaskAllocateMPURegions(NULL, regions);

	volatile uint32_t *const mpu_rbar = &LXP_CORTEX_M_MPU_RBAR;
	volatile uint32_t *const mpu_rasr = &LXP_CORTEX_M_MPU_RASR;
	*mpu_rbar = ((uint32_t)(uintptr_t)prog_regions[ridx]) | (1u << 4) |
		    (portFIRST_CONFIGURABLE_REGION + 0u);
	*mpu_rasr = prog_rasr;
	*mpu_rbar = ((uint32_t)(uintptr_t)dyn_pools[ridx]) | (1u << 4) |
		    (portFIRST_CONFIGURABLE_REGION + 1u);
	*mpu_rasr = dyn_rasr;
	lxp_cortex_m_dsb();
	lxp_cortex_m_isb();

	g_coord_mapped_ridx = ridx;
}

/* Worst tramp-stack usage seen across all guest slots this run, for the R9 stack audit. A task's
 * high-water mark is lost when it is deleted and each slot's static tramp stack is refilled when
 * reused, so the peak is captured here at abort and kept as a running max. The public query also
 * folds in any slot still live at the call. This bounds the entry PROLOGUE only — a guest runs on
 * its own stack inside its arena region, not on this FreeRTOS task stack. */
static size_t g_slot_stack_used_max;

static void slot_sample_stack(int sidx)
{
	if (!g_slots[sidx].tid)
		return;
	/* uxTaskGetStackHighWaterMark returns the minimum free stack ever seen, in words. */
	UBaseType_t free_words = uxTaskGetStackHighWaterMark(g_slots[sidx].tid);
	size_t used = (size_t)(TRAMP_STACK_WORDS - free_words) * sizeof(StackType_t);
	if (used > g_slot_stack_used_max)
		g_slot_stack_used_max = used;
}

/* Bytes used at the high-water mark by the deepest guest-slot trampoline task
 * since port initialization. Exposed only through the generic port contract. */
static int freertos_guest_stack_usage(size_t *used, size_t *size)
{
	if (!used || !size)
		return LXP_ERR_INVALID_PARAM;
	for (int i = 0; i < LXP_NSLOT; i++)
		if (g_slots[i].tid)
			slot_sample_stack(i);
	*used = g_slot_stack_used_max;
	*size = (size_t)TRAMP_STACK_WORDS * sizeof(StackType_t);
	return LXP_OK;
}

static int freertos_abort_slot(lxp_slot_ref_t slot)
{
	int sidx = slot.index;
	uint32_t generation = slot.generation;
	if (sidx < 0 || sidx >= LXP_NSLOT)
		return -1;
	if (g_slots[sidx].tid && g_slots[sidx].generation != generation)
		return -1;
	taskENTER_CRITICAL();
	int was_selected = g_selected_slot == sidx;
	if (g_slots[sidx].tid) {
		slot_sample_stack(
			sidx); /* capture the HWM before the task (and its mark) is gone */
		vTaskDelete(g_slots[sidx].tid);
	}
	g_slots[sidx].tid = NULL;
	g_slots[sidx].park_desc = NULL;
	g_slots[sidx].generation = 0;
	g_slots[sidx].profile.valid = 0;
	g_slots[sidx].sched_blocked = 0u;
	if (was_selected) {
		g_selected_slot = -1;
		freertos_sched_cancel_rotation_locked();
		freertos_tick_budget_reset();
		freertos_sched_activate_locked(freertos_sched_find_next_locked(sidx, sidx));
	}
	taskEXIT_CRITICAL();
	return 0;
}

static int freertos_park_slot(lxp_slot_ref_t slot)
{
	int sidx = slot.index;
	uint32_t generation = slot.generation;
	if (sidx < 0 || sidx >= LXP_NSLOT || !lxp_slot_ref_is_runnable(task_slot_ref(sidx)) ||
	    !g_slots[sidx].tid || g_slots[sidx].generation != generation)
		return -1;
	taskENTER_CRITICAL();
	int was_selected = g_selected_slot == sidx;
	if (!g_slots[sidx].sched_blocked)
		vTaskSuspend(g_slots[sidx].tid);
	g_slots[sidx].sched_blocked = 0u; /* now suspended by lifecycle ownership */
	if (was_selected) {
		g_selected_slot = -1;
		freertos_sched_cancel_rotation_locked();
		freertos_tick_budget_reset();
		freertos_sched_activate_locked(freertos_sched_find_next_locked(sidx, sidx));
	}
	taskEXIT_CRITICAL();
	return 0;
}

/* Coordinator critical section: taskENTER_CRITICAL raises BASEPRI to mask the
 * configurable-priority interrupts (NOT vTaskSuspendAll, which only defers thread
 * switches). Held only for the brief proc-table flag snapshot. */
static lxp_critical_token_t freertos_crit_enter(void)
{
	taskENTER_CRITICAL();
	return 0;
}
static void freertos_crit_exit(lxp_critical_token_t token)
{
	(void)token;
	taskEXIT_CRITICAL();
}

/* Event wakeup: the coordinator blocks here instead of busy-polling; the dispatch
 * (SVC exception context) gives the binary semaphore when a program parks. */
static StaticSemaphore_t g_ev_buf;
static SemaphoreHandle_t g_ev;
static void LXP_FAULT_GPR_ONLY freertos_event_post(void)
{
	BaseType_t woken = pdFALSE;
	if (g_ev)
		xSemaphoreGiveFromISR(g_ev, &woken);
	/* Pend a context switch if the (higher-priority) coordinator was woken: event_post runs
	 * from the SVC/MemManage handler (e.g. a program's exit lxp_park_frame). Without this yield
	 * the woken coordinator does NOT preempt, so an EXITED unprivileged restricted task keeps
	 * spinning in the park entry and is context-switched (corrupting its saved registers under
	 * the MPU port) before the coordinator reaps it. Yielding reaps it promptly, before any
	 * such switch. */
	portYIELD_FROM_ISR(woken);
}
static void freertos_event_wait(unsigned ms)
{
	if (g_ev)
		xSemaphoreTake(g_ev, pdMS_TO_TICKS(ms));
}

static int32_t slot_for_thread(uintptr_t identity)
{
	for (int s = 0; s < LXP_NSLOT; s++)
		if (identity == (uintptr_t)g_slots[s].tid)
			return s;
	return LXP_THREAD_SLOT_NONE;
}

static int lxp_seam_thread_list(struct lxp_thread_info *out, size_t max_count, size_t *actual_count)
{
	return PORT_CONFIG.common.thread_list
		       ? PORT_CONFIG.common.thread_list(out, max_count, actual_count,
							slot_for_thread)
		       : LXP_ERR_NOT_SUPPORTED;
}

static int freertos_random_fill(void *buf, size_t len)
{
	return PORT_CONFIG.random_fill ? PORT_CONFIG.random_fill(buf, len) : LXP_ERR_NOT_SUPPORTED;
}

static void freertos_cache_clean(const void *base, size_t len)
{
	if (PORT_CONFIG.cache_clean)
		PORT_CONFIG.cache_clean(base, len);
}

static void freertos_cache_invalidate(const void *base, size_t len)
{
	if (PORT_CONFIG.cache_invalidate)
		PORT_CONFIG.cache_invalidate(base, len);
}

/* Per-run bring-up (was the body of the old lxp_run() wrapper): create the
 * coordinator wakeup semaphore in thread context and enable Bus/UsageFault so a
 * program's fault is contained by our handlers instead of escalating to HardFault
 * (the MPU port's prvSetupMPU only turns on MEMFAULTENA). Invoked by the module's
 * lxp_run() via g_lxp_host_engine.core.prepare before the run loop. */
static int freertos_prepare(void)
{
	if (PORT_CONFIG.abi_version != LXP_FREERTOS_PORT_CONFIG_ABI_VERSION ||
	    PORT_CONFIG.struct_size != sizeof(PORT_CONFIG) || !lxp_cortex_m_port_config_valid() ||
	    !PORT_CONFIG.tick_subscribe || !PORT_CONFIG.tick_unsubscribe ||
	    !PORT_CONFIG.random_fill ||
	    PORT_CONFIG.rootfs_region_count > LXP_FREERTOS_ROOTFS_REGION_MAX ||
	    2u + PORT_CONFIG.rootfs_region_count >= portNUM_CONFIGURABLE_REGIONS)
		return LXP_ERR_INVALID_PARAM;
	if (PORT_CONFIG.coordinator_cacheable_map &&
	    PORT_CONFIG.coordinator_rootfs_region != UINT8_MAX &&
	    (PORT_CONFIG.coordinator_rootfs_region < 2u ||
	     PORT_CONFIG.coordinator_rootfs_region >= portNUM_CONFIGURABLE_REGIONS))
		return LXP_ERR_INVALID_PARAM;
	for (unsigned i = 0; i < PORT_CONFIG.rootfs_region_count; i++) {
		const lxp_freertos_rootfs_region_t *region = &PORT_CONFIG.rootfs_regions[i];
		if (region->size < 32u || (region->size & (region->size - 1u)) != 0u ||
		    (region->base & (region->size - 1u)) != 0u)
			return LXP_ERR_INVALID_PARAM;
	}
	int rc = lxp_cortex_m_port_cache_prepare();
	if (rc != LXP_OK)
		return rc;
	if (!g_ev)
		g_ev = xSemaphoreCreateBinaryStatic(&g_ev_buf);
	if (!g_sched_ev)
		g_sched_ev = xSemaphoreCreateBinaryStatic(&g_sched_ev_buf);
	if (!g_ev || !g_sched_ev)
		return LXP_ERR_NO_MEMORY;
	if (uxTaskPriorityGet(NULL) < GUEST_SCHED_PRIO)
		return LXP_ERR_INVALID_PARAM; /* the coordinator may not run below the scheduler */
	rc = lxp_cortex_m_port_host_prepare();
	if (rc != LXP_OK)
		return rc;
	(void)xSemaphoreTake(g_sched_ev, 0);
	g_selected_slot = -1;
	freertos_sched_cancel_rotation_locked();
	freertos_tick_budget_reset();
	g_sched_task = xTaskCreateStatic(freertos_sched_task_entry, "lxp-sched",
					 GUEST_SCHED_STACK_WORDS, NULL,
					 GUEST_SCHED_PRIO | portPRIVILEGE_BIT, g_sched_stack,
					 &g_sched_tcb);
	if (!g_sched_task)
		return LXP_ERR_NO_MEMORY;
	if (PORT_CONFIG.tick_subscribe(lxp_freertos_tick) != 0) {
		rc = LXP_ERR_BUSY; /* the tick hook serves another subscriber */
		goto fail_sched_task;
	}
	g_tick_subscribed = 1u;
	for (int s = 0; s < LXP_NSLOT; s++) {
		g_slots[s].profile.valid = 0;
		g_slots[s].sched_blocked = 0u;
	}
	LXP_CORTEX_M_SCB_SHCSR |=
		LXP_CORTEX_M_SCB_SHCSR_BUSFAULTENA | LXP_CORTEX_M_SCB_SHCSR_USGFAULTENA;
	return LXP_OK;

fail_sched_task:
	vTaskDelete(g_sched_task);
	g_sched_task = NULL;
	return rc;
}

static void freertos_teardown(void)
{
	if (g_tick_subscribed) {
		PORT_CONFIG.tick_unsubscribe(lxp_freertos_tick);
		g_tick_subscribed = 0u;
	}
	if (g_sched_task) {
		vTaskDelete(g_sched_task);
		g_sched_task = NULL;
	}
	g_selected_slot = -1;
	freertos_sched_cancel_rotation_locked();
	freertos_tick_budget_reset();
}

static void freertos_rootfs_window(const void *base, size_t len);

const lxp_cortex_m_port_common_t *const g_lxp_cortex_m_port_common = &PORT_CONFIG.common;

const lxp_os_ops_t g_lxp_host_engine = {
	.abi_version = LXP_OS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_os_ops_t),
	.core =
		{
			.prepare = freertos_prepare,
			.teardown = freertos_teardown,
			.crit_enter = freertos_crit_enter,
			.crit_exit = freertos_crit_exit,
			.event_post = freertos_event_post,
			.event_wait = freertos_event_wait,
		},
	.task =
		{
			.spawn_launch = freertos_spawn_launch,
			.spawn_resume = freertos_spawn_resume,
			.abort_slot = freertos_abort_slot,
			.park_entry = freertos_park_entry,
			.park_prepare = freertos_park_prepare,
			.park_slot = freertos_park_slot,
			.guest_stack_usage = freertos_guest_stack_usage,
		},
	.memory =
		{
			.region = lxp_cortex_m_port_region,
			.dyn_pool = lxp_cortex_m_port_dyn_pool,
			.exec_capture = lxp_cortex_m_port_exec_capture,
#if LXP_ENABLE_NETFS_EXEC
			.exec_stage = lxp_cortex_m_port_exec_stage,
#endif
			.publish_executable = lxp_cortex_m_port_publish_executable,
			/* A coherent coordinator view of the serviced slot's pools. */
			.coord_map = freertos_coord_map,
			.rootfs_window = freertos_rootfs_window,
			.cache_clean = freertos_cache_clean,
			.cache_invalidate = freertos_cache_invalidate,
			.cpu_memory_contract = &PORT_CONFIG.common.cpu_memory_contract,
			.validate_memory_contract = lxp_cortex_m_port_validate_memory_contract,
		},
	.services =
		{
			.time_us = lxp_cortex_m_port_time_us,
			.time_ns = lxp_cortex_m_port_time_ns,
			.thread_list = lxp_seam_thread_list,
			.mem_stats = lxp_cortex_m_port_mem_stats,
			.system_version = lxp_cortex_m_port_system_version,
			.random_fill = freertos_random_fill,
		},
};

/* The rootfs.cpio is XIP'd from the memory-mapped QUADSPI NOR at 0x90000000.  The coordinator —
 * THIS task: it runs lxp_cpio_to_rootfs + the FDPIC loader — is a PRIVILEGED, non-restricted
 * FreeRTOS-MPU task, so absent an explicit region it reads the NOR through the PRIVDEFENA
 * background map: the 512 MB Normal-cacheable 0x80000000..0x9FFFFFFF block.  With the M7 D-cache
 * on, that view corrupts the reads two ways —
 *   (1) the cache issues 32-byte line-fill BURSTS to the memory-mapped QUADSPI; a non-cacheable
 *       region issues none (proven on silicon: an NC bounded region reads the NOR reliably where
 *       a cacheable / write-through one still faults), and
 *   (2) speculative prefetch within the oversized 512 MB region wanders PAST the 16 MB chip into
 *       unmapped QUADSPI address space.
 * Give THIS task a private MPU region over exactly the mapped NOR — Normal non-cacheable +
 * execute-never: no bursts (1), speculation bounded to the chip (2).  It rides configurable
 * the configured coordinator region and, being per-task, leaves the UNPRIVILEGED guest's cacheable
 * rootfs region
 * (freertos_spawn_common — fast in-place XIP) untouched.  vPortStoreTaskMPUSettings with
 * uxStackDepth==0 preserves this task's stack/all-SRAM region; taskYIELD forces the pended MPU
 * reprogram so the region is live before the very next QUADSPI read (the cpio parse). */
static void freertos_rootfs_window(const void *base, size_t len)
{
	if (!PORT_CONFIG.coordinator_cacheable_map ||
	    PORT_CONFIG.coordinator_rootfs_region >= portNUM_CONFIGURABLE_REGIONS)
		return;
	const uint32_t par =
		portMPU_REGION_PRIVILEGED_READ_ONLY | portMPU_REGION_EXECUTE_NEVER |
		(0x08u << portMPU_RASR_TEX_S_C_B_LOCATION); /* TEX=001,S/C/B=0 = Normal NC */
	/* The configured region is reserved for the coordinator rootfs window
	 * (coord_map owns 0 and 1). Record it so coord_map re-specifies the
	 * window on every remap and never drops it. */
	g_qspi_win_base = (uint32_t)(uintptr_t)base;
	g_qspi_win_len = (uint32_t)len;
	g_qspi_win_par = par;
	MemoryRegion_t regions[portNUM_CONFIGURABLE_REGIONS] = {0};
	unsigned rootfs_region = PORT_CONFIG.coordinator_rootfs_region;
	regions[rootfs_region].pvBaseAddress = (void *)(uintptr_t)base;
	regions[rootfs_region].ulLengthInBytes = (uint32_t)len;
	regions[rootfs_region].ulParameters = par;
	/* vTaskAllocateMPURegions replaces every configurable descriptor, so the
	 * zero entries above remove coord_map's region 0/1 views from the TCB. A
	 * previous sequential lxp_run may have left g_coord_mapped_ridx pointing at
	 * the same region the next run launches in. Invalidate that software cache:
	 * otherwise coord_map returns early and the coordinator reads guest WBWA
	 * data through the uncached background map (stale argv/path bytes showed up
	 * as intermittent EFAULT/ENOENT while BusyBox init launched its children). */
	g_coord_mapped_ridx = -1;
	/* Record it in this task's TCB so PendSV re-applies it on every
	 * context switch back to the coordinator — persistent for the whole coordinator life. */
	vTaskAllocateMPURegions(NULL, regions);
	/* vTaskAllocateMPURegions only updates the TCB; the live MPU is not reprogrammed until the
	 * next context switch. Clear stale coordinator pool overlays from regions 0/1, then install
	 * the bounded NC QSPI view before the very next cpio read. Doing it directly
	 * avoids forcing a first context switch that trips the FreeRTOS stack-overflow guard. */
	volatile uint32_t *const mpu_rbar = &LXP_CORTEX_M_MPU_RBAR;
	volatile uint32_t *const mpu_rasr = &LXP_CORTEX_M_MPU_RASR;
	*mpu_rbar = (1u << 4) /* VALID */ | 0u /* region 0 */;
	*mpu_rasr = 0u;
	*mpu_rbar = (1u << 4) /* VALID */ | 1u /* region 1 */;
	*mpu_rasr = 0u;
	*mpu_rbar = (uint32_t)(uintptr_t)base | (1u << 4) /* VALID */ | rootfs_region;
	*mpu_rasr = lxp_cortex_m_mpu_rasr_size(len) | par;
	lxp_cortex_m_dsb();
	lxp_cortex_m_isb();
}

/* The public lxp_run() now lives in the module (src/lxp_run.c): it publishes the
 * net/display ops and brackets the run loop with g_lxp_host_engine.core.prepare() /
 * .teardown(). This port supplies only the engine vtable (g_lxp_host_engine). */
