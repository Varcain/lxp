/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Lean FreeRTOS config for the standalone lxp QEMU harness (MPS2-AN500, Cortex-M7,
 * non-MPU port, all-static allocation → no heap needed).
 */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configUSE_PREEMPTION 1
#define configUSE_TIME_SLICING 1
#define configCPU_CLOCK_HZ 25000000u
#define configTICK_RATE_HZ 1000u
#define configMAX_PRIORITIES 5
#define configMINIMAL_STACK_SIZE 192
#define configMAX_TASK_NAME_LEN 8
#define configUSE_16_BIT_TICKS 0
#define configIDLE_SHOULD_YIELD 1

#define configSUPPORT_STATIC_ALLOCATION 1
#define configSUPPORT_DYNAMIC_ALLOCATION 0

#define configUSE_MUTEXES 1
#define configUSE_COUNTING_SEMAPHORES 1
#define configUSE_TIMERS 0
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
