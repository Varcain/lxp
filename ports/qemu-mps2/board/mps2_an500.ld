/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linker script for the standalone FreeRTOS lxp QEMU harness (MPS2-AN500, CM7).
 *   FLASH 0x00000000 4M  — vectors + code + the (small) embedded rootfs cpio (XIP'd)
 *   RAM   0x20000000 4M  — .data/.bss + FDPIC program regions + FreeRTOS/task stacks
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}
ENTRY(Reset_Handler)

SECTIONS
{
    .text :
    {
        KEEP(*(.isr_vector))
        . = ALIGN(4);
        *(.text*)
        *(.rodata*)          /* includes the embedded rootfs cpio */
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
}
