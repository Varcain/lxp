/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linker script for the standalone FreeRTOS lxp QEMU harness (MPS2-AN500, CM7).
 *   FLASH 0x00000000 4M   — vectors + code + the (small) embedded M1/M2 rootfs cpio (XIP'd)
 *   RAM   0x20000000 4M   — .data/.bss + FDPIC program regions + FreeRTOS/task stacks
 *   PSRAM 0x60000000 16M  — M3: the big busybox rootfs cpio XIP'd from the bottom 12M
 *                           (injected by QEMU `-device loader`), the dynamic-FDPIC
 *                           dyn_pools in the top 4M (.psram). Inert for M1/M2.
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
    PSRAM (rwx) : ORIGIN = 0x60000000, LENGTH = 16M
}
ENTRY(Reset_Handler)

SECTIONS
{
    .text :
    {
        KEEP(*(.isr_vector))
        . = ALIGN(4);
        *(.text*)
        /* ARM_CM4_MPU annotates kernel code PRIVILEGED_FUNCTION -> "privileged_functions"
         * and the V1 wrappers put the unprivileged system-call entry points in
         * "freertos_system_calls". BOTH must land in .text BEFORE __etext (else they
         * become orphan sections after __etext, pushing .data's flash LMA past __etext
         * so the startup .data-copy reads garbage). The whole flash is unprivileged-RX
         * via the static MPU region, so no separate region is needed. */
        *(privileged_functions)
        *(freertos_system_calls)
        *(.rodata*)          /* includes the embedded M1/M2 rootfs cpio */
        KEEP(*(.init))
        KEEP(*(.fini))
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
        . = ALIGN(4);
        __etext = .;
    } > FLASH

    .data : AT (__etext)
    {
        __data_start__ = .;
        *(.data*)
        . = ALIGN(4);
        __data_end__ = .;
    } > RAM

    .bss (NOLOAD) :
    {
        __bss_start__ = .;
        *(.bss*)
        *(privileged_data)   /* ARM_CM4_MPU kernel data (in RAM, no unpriv access) */
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
    } > RAM

    /* FDPIC program regions (guest RW image + arena + stack). */
    .lxp_regions (NOLOAD) :
    {
        . = ALIGN(0x40000);
        *(.lxp_regions*)
    } > RAM

    /* MSP (main + exception) stack. FreeRTOS tasks use their own static stacks. */
    .stack (NOLOAD) :
    {
        . = ALIGN(8);
        __msp_bottom = .;
        . = . + 0x4000;   /* 16 KB */
        __msp_top = .;
    } > RAM

    /* M3 dynamic-FDPIC dyn_pools (each proc's shared arena: every loaded .so's RW +
     * brk/mmap heap — ld.so mmaps libc.so ~500K here). Placed at 0x60C00000 (top 4M of
     * PSRAM), NOT at 0x60000000: a NOLOAD reservation at the base would emit a segment
     * QEMU flags as ROM overlapping the `-device loader` cpio in the bottom 12M. NOLOAD
     * → no flash cost; inert for M1/M2 (static FDPIC never calls the dyn_pool op). */
    .psram 0x60C00000 (NOLOAD) :
    {
        *(.psram*)
    } > PSRAM

    /* ARM_CM4_MPU static-region bounds, referenced by prvSetupMPU(). The
     * unprivileged-flash region spans the WHOLE flash RX, so an unprivileged guest
     * executes its FDPIC text in-place from the flash cpio (M1/M2) and prog_tramp /
     * lxp_park_loop. The privileged sub-regions are DEGENERATE (start==end at the
     * segment end → a harmless empty region): isolation comes from the MPU background
     * region + the per-task regions, not from privilege-gating the kernel code here. */
    __FLASH_segment_start__        = ORIGIN(FLASH);
    __FLASH_segment_end__          = ORIGIN(FLASH) + LENGTH(FLASH);
    __SRAM_segment_start__         = ORIGIN(RAM);
    __SRAM_segment_end__           = ORIGIN(RAM) + LENGTH(RAM);
    __privileged_functions_start__ = ORIGIN(FLASH) + LENGTH(FLASH);
    __privileged_functions_end__   = ORIGIN(FLASH) + LENGTH(FLASH);
    __privileged_data_start__      = ORIGIN(RAM) + LENGTH(RAM);
    __privileged_data_end__        = ORIGIN(RAM) + LENGTH(RAM);
}
