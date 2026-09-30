/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Bare-metal bring-up for the standalone FreeRTOS-based QEMU harness (MPS2-AN500,
 * Cortex-M7): the vector table (PendSV/SysTick → FreeRTOS, SVC/faults → the shared port),
 * reset, a SysTick-tick monotonic clock, the FreeRTOS static-allocation + hook
 * callbacks, an Arm-semihosting console + clean exit, and main() — which parses the
 * embedded rootfs cpio and runs the guest via lxp_run() from a coordinator task.
 */
#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_run.h"
#include "lxp/lxp_bootstrap.h"
#include "lxp/ports/freertos.h"

/* Which milestone this firmware runs (set by build.sh -DLXP_MILESTONE). M1/M2 embed a
 * small cpio in flash; M3 XIPs a big busybox cpio from PSRAM (QEMU `-device loader`). */
#ifndef LXP_MILESTONE
#define LXP_MILESTONE 1
#endif
/* Only the dynamic busybox milestones (M3, M6) XIP the big cpio from PSRAM; the rest embed
 * the small fixture in flash. Name it once so a new milestone touches one line, not three. */
#define LXP_ROOTFS_PSRAM (LXP_MILESTONE == 3 || LXP_MILESTONE == 6)
#if !LXP_ROOTFS_PSRAM
#include "rootfs_cpio.h" /* generated: rootfs_cpio[], rootfs_cpio_len */
#else
/* M3: the raw cpio is injected into PSRAM @ 0x60000000 by `-device loader`. The length
 * is an upper bound (the 12 MiB bottom-of-PSRAM window); the parser stops at TRAILER!!!. */
#define LXP_PSRAM_ROOTFS ((const uint8_t *)0x60000000u)
#define LXP_PSRAM_ROOTFS_MAX (12u * 1024u * 1024u)
#endif

/* ---- Arm semihosting (console + exit) -------------------------------------- */
static long semihost(long op, void *arg)
{
	register long r0 __asm__("r0") = op;
	register void *r1 __asm__("r1") = arg;
	__asm__ volatile("bkpt 0xAB" : "+r"(r0) : "r"(r1) : "memory");
	return r0;
}
static void sh_putc(char c)
{
	semihost(0x03 /* SYS_WRITEC */, &c);
}
void lxp_dbg(const char *s) /* diagnostics for the fault/overflow/rootfs-error paths */
{
	while (*s)
		sh_putc(*s++);
}
static void sh_exit(int code)
{
	/* Arm M-profile semihosting: SYS_EXIT takes the reason VALUE in r1 (ApplicationExit
	 * → QEMU exit 0). A non-zero status uses SYS_EXIT_EXTENDED with a {reason, code} block. */
	if (code == 0) {
		semihost(0x18 /* SYS_EXIT */, (void *)0x20026u /* ApplicationExit */);
	} else {
		uint32_t block[2] = {0x20026u, (uint32_t)code};
		semihost(0x20 /* SYS_EXIT_EXTENDED */, block);
	}
	for (;;) {
	}
}

/* ---- monotonic microsecond clock (FreeRTOS tick hook) ---------------------- */
static volatile uint64_t g_us;
static lxp_freertos_tick_fn g_tick_callback;

#if LXP_MILESTONE == 9
/* A native task above both the Linux guests (priority 1) and their selector
 * (priority 2). Waking it every tick reproduces the ready-list perturbation
 * which used to defeat guest nice weighting after each host preemption. */
static StaticSemaphore_t g_preempt_sem_buf;
static SemaphoreHandle_t g_preempt_sem;
static StaticTask_t g_preempt_tcb;
static StackType_t g_preempt_stack[configMINIMAL_STACK_SIZE];
static volatile uint32_t g_preempt_count;
static volatile uint32_t g_preempt_mix;

static void preempt_task(void *arg)
{
	(void)arg;
	for (;;) {
		(void)xSemaphoreTake(g_preempt_sem, portMAX_DELAY);
		uint32_t value = g_preempt_mix ^ 0x9e3779b9u;
		for (unsigned i = 0; i < 16u; i++)
			value = (value << 5) ^ (value >> 3) ^ i;
		g_preempt_mix = value;
		g_preempt_count++;
	}
}
#endif

int lxp_qemu_tick_subscribe(lxp_freertos_tick_fn callback)
{
	if (!callback)
		return -1;
	taskENTER_CRITICAL();
	int result = g_tick_callback && g_tick_callback != callback ? -1 : 0;
	if (result == 0)
		g_tick_callback = callback;
	taskEXIT_CRITICAL();
	return result;
}

void lxp_qemu_tick_unsubscribe(lxp_freertos_tick_fn callback)
{
	taskENTER_CRITICAL();
	if (g_tick_callback == callback)
		g_tick_callback = NULL;
	taskEXIT_CRITICAL();
}

void vApplicationTickHook(void)
{
	g_us += 1000000u / configTICK_RATE_HZ;
	lxp_freertos_tick_fn callback = g_tick_callback;
	if (callback)
		callback();
#if LXP_MILESTONE == 9
	if (g_preempt_sem) {
		BaseType_t woken = pdFALSE;
		xSemaphoreGiveFromISR(g_preempt_sem, &woken);
		portYIELD_FROM_ISR(woken);
	}
#endif
}
uint64_t lxp_qemu_now_us(void)
{
	return g_us;
}

/* ---- personality console callbacks ----------------------------------------- */
static long con_write(void *ctx, int fd, const void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	const char *p = (const char *)buf;
	for (size_t i = 0; i < len; i++)
		sh_putc(p[i]);
	return (long)len;
}
static long con_read(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	(void)buf;
	(void)len;
	return 0; /* EOF: M1 guests do not read stdin */
}

/* ---- the coordinator task: parse the rootfs, run the guest ----------------- */
/* Sized for a real busybox rootfs (the full Buildroot cpio has ~400 entries). */
static lxp_file_t g_files[512];
static char g_names[24576];

static void coordinator_task(void *arg)
{
	(void)arg;
#if !LXP_ROOTFS_PSRAM
	/* Flash-embedded fixture (M1/M2/M4/M5); the busybox milestones XIP from PSRAM instead. */
	const uint8_t *cpio = (const uint8_t *)rootfs_cpio;
	size_t cpio_len = rootfs_cpio_len;
#else
	const uint8_t *cpio = LXP_PSRAM_ROOTFS;
	size_t cpio_len = LXP_PSRAM_ROOTFS_MAX;
#endif
	int n = lxp_cpio_to_rootfs(cpio, cpio_len, g_files,
				   (int)(sizeof(g_files) / sizeof(g_files[0])), g_names,
				   sizeof(g_names));
	if (n <= 0) {
		lxp_dbg("lxp: rootfs parse failed\n");
		sh_exit(70);
	}
	/* A minimal initial environment for pid 1, as a real board/bootloader would supply.
	 * Guests read these (busybox sh's PATH, TERM for interactive tools) and propagate
	 * them through execve; without it every program starts with an empty environ. */
	static const char *const g_env[] = {
		"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
		"HOME=/root",
		"TERM=vt100",
		"PWD=/",
		"SHELL=/bin/sh",
		"USER=root",
		NULL,
	};
	lxp_run_config_t cfg = {
		.rootfs = g_files,
		.rootfs_count = n,
		.rootfs_image = cpio,
		.rootfs_image_size = cpio_len,
		.write_fn = con_write,
		.read_fn = con_read,
		.io_ctx = NULL,
		.env = g_env,
	};
	/* The initial program + argv, selected at build time per milestone:
	 *   M1 = /hello           M2 = /init (execs /child)
	 *   M3 = /bin/busybox echo lxp-m3-ok  (dynamic-FDPIC: ld.so + libc.so + busybox) */
#if LXP_MILESTONE == 9
	/* M9 = two CPU-bound CLONE_VM workers at nice -20/+19 while a native,
	 * higher-priority task wakes at 1 kHz. */
	const char *entry = "/schedtest";
	const char *const argv[] = {"schedtest", NULL};
	int argc = 1;
#elif LXP_MILESTONE == 8
	/* M8 = vfork + FAILED exec + wait4: the command-not-found path. The parent must reap
	 * the child's 127 without faulting or losing the code to the child's-death SIGCHLD. */
	const char *entry = "/vforkx";
	const char *const argv[] = {"vforkx", NULL};
	int argc = 1;
#elif LXP_MILESTONE == 7
	/* M7 = hard-float FDPIC VFP-state regression across deferred and blocking
	 * syscalls, including saved-frame resume of the persistent guest task. */
	const char *entry = "/fpcheck";
	const char *const argv[] = {"fpcheck", NULL};
	int argc = 1;
#elif LXP_MILESTONE == 6
	/* M6 = a real busybox /bin/sh script (dynamic FDPIC: ld.so + libc + busybox). Proves an
	 * unmodified shell runs and that the port-supplied environment reaches it ($TERM/$HOME/
	 * $PATH) — the payoff of the env plumbing. Uses only shell builtins so the check is
	 * deterministic; prints lxp-m6-ok iff the environment came through. */
	const char *entry = "/bin/busybox";
	const char *const argv[] = {
		"busybox", "sh", "-c",
		"test \"$TERM\" = vt100 && test \"$HOME\" = /root && "
		"case \"$PATH\" in */bin*) echo lxp-m6-ok ;; *) echo lxp-m6-FAIL ;; esac",
		NULL};
	int argc = 4;
#elif LXP_MILESTONE == 5
	/* M5 = /futex: two co-running CLONE_VM threads hand off through a real uaddr-keyed
	 * futex (WAIT parks, WAKE resumes) — the path host cmocka cannot reach. */
	const char *entry = "/futex";
	const char *const argv[] = {"futex", NULL};
	int argc = 1;
#elif LXP_MILESTONE == 4
	/* M4 = /syscheck: drives the SVC/dispatch/resume ABI, 32-bit r0, statx via svc6, and the
	 * run-loop-intercepted fork/kill/wait4 that host cmocka cannot reach (execs /spin). */
	const char *entry = "/syscheck";
	const char *const argv[] = {"syscheck", NULL};
	int argc = 1;
#elif LXP_MILESTONE >= 3
	const char *entry = "/bin/busybox";
	const char *const argv[] = {"busybox", "echo", "lxp-m3-ok", NULL};
	int argc = 3;
#elif LXP_MILESTONE == 2
	const char *entry = "/init";
	const char *const argv[] = {"init", NULL};
	int argc = 1;
#else
	const char *entry = "/hello";
	const char *const argv[] = {"hello", NULL};
	int argc = 1;
#endif
	const lxp_providers_t providers = {.os = &g_lxp_host_engine};
	int rc = lxp_run(&providers, &cfg, entry, argc, argv);
#if LXP_MILESTONE == 9
	/* The guest's zero status proves bounded weighted progress. This separate
	 * minimum proves the 1 kHz native interference was present throughout it. */
	if (rc == 0 && g_preempt_count >= 1000u)
		lxp_dbg("lxp-m9-ok\n");
	else
		lxp_dbg("lxp-m9-FAIL\n");
#endif
	sh_exit(rc >= 0 ? rc : 100 - rc);
}

static StaticTask_t g_coord_tcb;
static StackType_t g_coord_stack[4096]; /* lxp_run + the FDPIC loader run here */

int main(void)
{
	/* The ARM_CM4_MPU port requires the hardware MPU region count (MPU_TYPE.DREGION) to equal
	 * configTOTAL_MPU_REGIONS (16 — what the real AN500 has); on a mismatch it SILENTLY skips
	 * MPU setup and the first unprivileged guest task HardFaults with no clue why. QEMU's
	 * mps2-an500 modelled the M7 with the CPU default of 8 regions until the fix that landed in
	 * qemu 10.0.3 ("Configure the AN500 CPU with 16 MPU regions") — so on an older QEMU the
	 * guests HardFault unless run.sh forces 16 via -global. Fail LOUDLY here instead. */
	uint32_t dregion = (*(volatile uint32_t *)0xe000ed90u >> 8) & 0xffu;
	if (dregion != configTOTAL_MPU_REGIONS) {
		lxp_dbg("lxp: FATAL — emulated MPU has ");
		sh_putc((char)('0' + (dregion / 10) % 10));
		sh_putc((char)('0' + dregion % 10));
		lxp_dbg(" regions, need 16. Upgrade QEMU to >=10.0.3, or pass\n"
			"      -global cortex-m7-arm-cpu.pmsav7-dregion=16 (see ports/qemu-mps2/run.sh).\n");
		sh_exit(83);
	}
	/* The coordinator runs ABOVE the guest slots (SLOT_PRIO) so it preempts a parked
	 * guest the instant event_post wakes it. It runs the FDPIC loader + lxp_run
	 * and touches the cpio, every program region and kernel state, so it must be
	 * PRIVILEGED (portPRIVILEGE_BIT) under the MPU port — the guests are the only
	 * unprivileged tasks. */
#if LXP_MILESTONE == 9
	g_preempt_sem = xSemaphoreCreateBinaryStatic(&g_preempt_sem_buf);
	if (!g_preempt_sem ||
	    !xTaskCreateStatic(preempt_task, "host-rt", configMINIMAL_STACK_SIZE, NULL,
			       4 | portPRIVILEGE_BIT, g_preempt_stack, &g_preempt_tcb))
		sh_exit(84);
#endif
	xTaskCreateStatic(coordinator_task, "coord", 4096, NULL, 2 | portPRIVILEGE_BIT,
			  g_coord_stack, &g_coord_tcb);
	vTaskStartScheduler();
	for (;;) {
	}
}

/* ---- FreeRTOS static-allocation + fault hooks ------------------------------ */
void vApplicationGetIdleTaskMemory(StaticTask_t **tcb, StackType_t **stack, uint32_t *depth)
{
	static StaticTask_t idle_tcb;
	static StackType_t idle_stack[configMINIMAL_STACK_SIZE];
	*tcb = &idle_tcb;
	*stack = idle_stack;
	*depth = configMINIMAL_STACK_SIZE;
}
void vApplicationStackOverflowHook(TaskHandle_t task, char *name)
{
	(void)task;
	lxp_dbg("lxp: stack overflow in ");
	lxp_dbg(name);
	sh_exit(82);
}

/* ---- reset + vector table -------------------------------------------------- */
extern uint32_t __etext, __data_start__, __data_end__, __bss_start__, __bss_end__;
extern uint32_t __msp_top;
extern int main(void);
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);
void MemManage_Handler(void);
void BusFault_Handler(void);
void UsageFault_Handler(void);

void Reset_Handler(void)
{
	/* Enable the Cortex-M7 FPU (CP10/CP11) so libc/libgcc FPU code doesn't NOCP-fault. */
	*(volatile uint32_t *)0xE000ED88u |= (0xFu << 20);
	__asm__ volatile("dsb\n\tisb");
	for (uint32_t *s = &__etext, *d = &__data_start__; d < &__data_end__;)
		*d++ = *s++;
	for (uint32_t *d = &__bss_start__; d < &__bss_end__;)
		*d++ = 0;
	main();
	sh_exit(0);
}

static uint32_t read_ipsr(void)
{
	uint32_t v;
	__asm__ volatile("mrs %0, ipsr" : "=r"(v));
	return v;
}
void HardFault_Handler(void)
{
	lxp_dbg("\nlxp: HARDFAULT exc=");
	sh_putc((char)('0' + (read_ipsr() & 0xf)));
	sh_putc('\n');
	sh_exit(81);
}
void NMI_Handler(void) __attribute__((weak, alias("HardFault_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("HardFault_Handler")));

__attribute__((section(".isr_vector"), used)) void (*const g_vectors[])(void) = {
	(void (*)(void))(&__msp_top),
	Reset_Handler,
	NMI_Handler,
	HardFault_Handler,
	MemManage_Handler, /* ports/freertos */
	BusFault_Handler,  /* ports/freertos */
	UsageFault_Handler, /* ports/freertos */
	0, 0, 0, 0,
	SVC_Handler,       /* ports/freertos (traps program syscalls) */
	DebugMon_Handler,
	0,
	PendSV_Handler,    /* FreeRTOS (xPortPendSVHandler) */
	SysTick_Handler,   /* FreeRTOS (xPortSysTickHandler) */
};
