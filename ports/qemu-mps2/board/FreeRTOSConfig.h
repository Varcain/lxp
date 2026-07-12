/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Lean FreeRTOS config for the standalone lxp QEMU harness (MPS2-AN500, Cortex-M7,
 * ARM_CM4_MPU port: guests run UNPRIVILEGED behind a per-task MPU region set;
 * all-static allocation → no heap needed).
 */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configUSE_PREEMPTION 1
#define configUSE_TIME_SLICING 1
#define configCPU_CLOCK_HZ 25000000u
#define configTICK_RATE_HZ 1000u
#define configMAX_PRIORITIES 5
#define configMINIMAL_STACK_SIZE 256
#define configMAX_TASK_NAME_LEN 8
#define configUSE_16_BIT_TICKS 0
#define configIDLE_SHOULD_YIELD 1

/* ---- MPU (ARM_CM4_MPU) ------------------------------------------------------
 * Each Linux guest runs UNPRIVILEGED in a per-task MPU region set (program region +
 * dyn_pool RW-execute-never, cpio RO-executable = W^X), so a stray access faults
 * (MemManage) instead of corrupting the kernel or another guest. */
#define configUSE_MPU_WRAPPERS_V1 1
/* MUST equal the hardware MPU region count or the port SILENTLY SKIPS all MPU setup
 * (and then HardFaults at scheduler start). QEMU's mps2-an500 Cortex-M7 = 16. */
#define configTOTAL_MPU_REGIONS 16
#define configENABLE_ERRATA_837070_WORKAROUND 0
/* Our SVC vector is the seam's strong SVC_Handler (engine.c), NOT vPortSVCHandler,
 * so the port's handler-installation self-check must be disabled. */
#define configCHECK_HANDLER_INSTALLATION 0
#define configENFORCE_SYSTEM_CALLS_FROM_KERNEL_ONLY 0
#define configALLOW_UNPRIVILEGED_CRITICAL_SECTIONS 0

#define configSUPPORT_STATIC_ALLOCATION 1
#define configSUPPORT_DYNAMIC_ALLOCATION 0

#define configUSE_MUTEXES 1
#define configUSE_COUNTING_SEMAPHORES 1
#define configUSE_TIMERS 0
/* Unused subsystems — off so the V1 MPU wrappers don't reference their (uncompiled)
 * event-group / stream-buffer APIs. The harness needs only tasks + a binary semaphore. */
#define configUSE_EVENT_GROUPS 0
#define configUSE_STREAM_BUFFERS 0
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 1
#define configCHECK_FOR_STACK_OVERFLOW 2
#define configUSE_MALLOC_FAILED_HOOK 0

/* Cortex-M interrupt priorities (M7: 3 priority bits implemented on the an500). */
#define configPRIO_BITS 3
#define configKERNEL_INTERRUPT_PRIORITY (7 << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY (2 << (8 - configPRIO_BITS))

/* Route the FreeRTOS core exceptions to the CMSIS-style vector names in boot.c.
 * NOTE: SVC is NOT routed here — the harness's own SVC_Handler (engine.c) traps
 * program syscalls and forwards FreeRTOS's start-scheduler svc to vPortSVCHandler. */
#define xPortPendSVHandler PendSV_Handler
#define xPortSysTickHandler SysTick_Handler

#define INCLUDE_vTaskDelete 1
#define INCLUDE_vTaskDelay 1
#define INCLUDE_vTaskSuspend 1
#define INCLUDE_xTaskGetCurrentTaskHandle 1
#define INCLUDE_uxTaskPriorityGet 1

#endif /* FREERTOS_CONFIG_H */
