/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Compile-time configuration: feature gates + sizing/placement knobs. Replaces
 * the module's former dependence on oveRTOS's generated ove_config.h and its
 * CONFIG_OVE_RTOS_* branches. A consumer sets these three ways (highest wins):
 *
 *   1. -DLXP_ENABLE_NET=1 … on the compiler command line (the oveRTOS build maps
 *      its Kconfig to these; a standalone CMake exposes them as option()s).
 *   2. A drop-in "lxp_config_user.h" anywhere on the include path (picked up
 *      automatically below).
 *   3. Otherwise the safe defaults here apply — smallest footprint, so a missing
 *      knob degrades capacity, never correctness.
 */

#ifndef LXP_CONFIG_H
#define LXP_CONFIG_H

#if defined(__has_include)
#if __has_include("lxp_config_user.h")
#include "lxp_config_user.h"
#endif
#endif

/* ---- feature gates -----------------------------------------------------------
 * The module gates with #if LXP_ENABLE_X (VALUE-based, not presence-based): every
 * gate is defined here — to 0 (off) by default — and the code tests its VALUE. So
 * -DLXP_ENABLE_NET=1 enables and -DLXP_ENABLE_NET=0 (or leaving it unset) disables.
 * There is no footgun where "-DLXP_ENABLE_NET=0" still enables the subsystem. The
 * core (the personality itself + the FDPIC loader) is always on; the optional
 * subsystems are OPT-IN — a consumer sets the ones it wants to 1 (the oveRTOS build
 * maps its Kconfig to -D flags; a standalone CMake exposes them as option()s; or
 * set them in lxp_config_user.h / on the command line). */
#ifndef LXP_ENABLE_LINUX
#define LXP_ENABLE_LINUX 1
#endif
#ifndef LXP_ENABLE_LOADER
#define LXP_ENABLE_LOADER 1 /* the FDPIC loader is core; always on */
#endif
/* Optional subsystems — default OFF; a consumer sets the ones it wants to 1. */
#ifndef LXP_ENABLE_NET
#define LXP_ENABLE_NET 0
#endif
#ifndef LXP_ENABLE_NETFS
#define LXP_ENABLE_NETFS 0 /* needs NET */
#endif
#ifndef LXP_ENABLE_NETFS_EXEC
#define LXP_ENABLE_NETFS_EXEC 0 /* needs NETFS */
#endif
#ifndef LXP_ENABLE_PTY
#define LXP_ENABLE_PTY 0
#endif
#ifndef LXP_ENABLE_DEV
#define LXP_ENABLE_DEV 0
#endif
#ifndef LXP_ENABLE_DEV_FB
#define LXP_ENABLE_DEV_FB 0 /* needs DEV + a display-ops port */
#endif
#ifndef LXP_ENABLE_DEV_DMA2D
#define LXP_ENABLE_DEV_DMA2D 0 /* needs DEV + a display-ops dma2d_submit op */
#endif
#ifndef LXP_ENABLE_DEV_INPUT
#define LXP_ENABLE_DEV_INPUT 0 /* needs DEV */
#endif
#ifndef LXP_ENABLE_DEV_INPUT_TESTPAD
#define LXP_ENABLE_DEV_INPUT_TESTPAD 0 /* needs DEV_INPUT */
#endif
#ifndef LXP_ENABLE_TOUCH
#define LXP_ENABLE_TOUCH 0
#endif
/* Preserve a guest's complete single-precision VFP context when the host parks
 * and recreates its task. This is needed for hard-float (and any VFP-using)
 * guests because a deferred syscall does not return through the original RTOS
 * task's exception frame. Keep it opt-in: soft-float guests pay no per-slot RAM
 * cost and ports without an FPU do not acquire VFP instructions. */
#ifndef LXP_ENABLE_FPU_CONTEXT
#define LXP_ENABLE_FPU_CONTEXT 0
#endif
#if LXP_ENABLE_FPU_CONTEXT != 0 && LXP_ENABLE_FPU_CONTEXT != 1
#error "LXP_ENABLE_FPU_CONTEXT must be 0 or 1"
#endif

/* Host-owned signal contexts retained per guest thread. Different signals may
 * interrupt an active handler, so one save area is not sufficient. Keep the
 * default at two levels: it covers one nested handler while adding about 2.2K
 * across the STM32F746 build's twelve slots when full VFP state is enabled.
 * A target with more deterministic RAM may raise this bound. Exceeding it
 * terminates only the affected guest instead of overwriting an older frame. */
#ifndef LXP_SIGNAL_NEST_MAX
#define LXP_SIGNAL_NEST_MAX 2
#endif
#if LXP_SIGNAL_NEST_MAX < 1
#error "LXP_SIGNAL_NEST_MAX must be at least 1"
#endif
#if LXP_SIGNAL_NEST_MAX > 255
#error "LXP_SIGNAL_NEST_MAX must fit the signal-stack depth field"
#endif

/* ---- sizing / placement knobs (were the CONFIG_OVE_RTOS_* #if blocks) ------ */
/* Per-process program region: a dynamic FDPIC proc XIPs its text from the rootfs,
 * so the region holds only the main exec's RW + ld.so RW + stack. 256K is the
 * default (Zephyr used 512K for roomy PSRAM). */
#ifndef LXP_PROG_REGION_SIZE
#define LXP_PROG_REGION_SIZE 0x40000u /* 256K */
#endif
#ifndef LXP_PROG_ARENA_SIZE
#define LXP_PROG_ARENA_SIZE 0x18000u /* 96K program heap */
#endif
/* A dynamic proc's shared arena: every loaded .so's RW segment + brk/mmap heap. */
#ifndef LXP_DYN_POOL_SIZE
#define LXP_DYN_POOL_SIZE 0x80000u /* 512K */
#endif
/* Maximum simultaneously-live arena-backed mmap extents per arena.  The table
 * lives in the privileged arena control block (not in guest-writable arena
 * memory), so munmap can require an exact live address/length pair. */
#ifndef LXP_ARENA_MAX_MAPPINGS
#define LXP_ARENA_MAX_MAPPINGS 32
#endif
/* Maximum guest-controlled payload handled by one syscall dispatch quantum.
 * Byte-stream interfaces may legally return a short read/write; libc retries
 * the remainder. Keeping this finite prevents one hostile request from
 * monopolising the privileged deferred-syscall coordinator. */
#ifndef LXP_SYSCALL_QUANTUM_BYTES
#define LXP_SYSCALL_QUANTUM_BYTES 4096u
#endif
/* In-memory rootfs/tmpfs pread/pwrite operations are task-preemptible memcpy
 * paths rather than external callbacks. uClibc's FDPIC loader requires one
 * 22 KiB pread to complete in full, so give file copies a separate finite
 * quantum without expanding UART/socket callback work. */
#ifndef LXP_SYSCALL_FILE_QUANTUM_BYTES
#define LXP_SYSCALL_FILE_QUANTUM_BYTES 65536u
#endif
/* Fixed writev/sendmsg vector fan-out bound. Consumers may lower this when a
 * smaller metadata-walk budget is preferable to Linux's usual IOV_MAX. */
#ifndef LXP_SYSCALL_MAX_IOV
#define LXP_SYSCALL_MAX_IOV 1024
#endif
#if LXP_SYSCALL_QUANTUM_BYTES < 1
#error "LXP_SYSCALL_QUANTUM_BYTES must be positive"
#endif
#if LXP_SYSCALL_FILE_QUANTUM_BYTES < 1
#error "LXP_SYSCALL_FILE_QUANTUM_BYTES must be positive"
#endif
#if LXP_SYSCALL_MAX_IOV < 1 || LXP_SYSCALL_MAX_IOV > 1024
#error "LXP_SYSCALL_MAX_IOV must be in [1, 1024]"
#endif
/* Max program images live at once (init + login shell + concurrent jobs). */
#ifndef LXP_NREG
#define LXP_NREG 8
#endif
/* NREG + transient vfork-window slots. */
#ifndef LXP_NSLOT
#define LXP_NSLOT (LXP_NREG + 4)
#endif
/* Pipe pool: count + per-pipe ring size. The STM32F746 consumer bumps NPIPE to
 * 12 (SSH pipelines) and relocates the pool via LXP_FAR_BSS; Zephyr shrinks the
 * ring to 2048. Defaults are the safe minimum. */
#ifndef LXP_NPIPE
#define LXP_NPIPE 4
#endif
#ifndef LXP_PIPE_BUF
#define LXP_PIPE_BUF 4096
#endif
/* PTY line buffer. Zephyr used 512; default 1024. */
#ifndef LXP_PTY_BUF
#define LXP_PTY_BUF 1024
#endif

/* Section attribute for large "far" pools (the pipe ring on the STM32 lives in
 * external SDRAM). Empty default => ordinary .bss. The STM32 consumer defines
 * this to __attribute__((section(".sdram_bss"))). */
#ifndef LXP_FAR_BSS
#define LXP_FAR_BSS
#endif

#endif /* LXP_CONFIG_H */
