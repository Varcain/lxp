/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The OS / engine port for the Linux personality. A host (any RTOS or
 * bare-metal) implements this process-model substrate; the independent network
 * and display providers live in lxp_net_ops.h and lxp_disp_ops.h.
 *
 * The module is single-instance (one run at a time). The ops are plain vtables
 * with no per-call context pointer: a port keeps whatever state it needs in its
 * own file-scope storage, exactly as an embedded host naturally would. (This
 * mirrors the proven per-engine vtable the personality has always used.)
 */

#ifndef LXP_PORT_H
#define LXP_PORT_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Incomplete types owned by the module's own headers (run config / saved
 * register context). The port only ever passes pointers to these. */
typedef struct lxp_run_config lxp_run_config_t; /* full def in lxp_run.h     */
typedef struct lxp_exec_capture lxp_exec_capture_t; /* full definition in lxp_exec.h */
struct lxp_resume_ctx;                          /* full definition in lxp_seam.h */

/* Device-mmap attribute selectors for lxp_os_ops.map_device. */
#define LXP_MAP_NC 0u  /**< Non-cacheable. */
#define LXP_MAP_WT 1u  /**< Write-through. */
#define LXP_MAP_DEV 2u /**< Device / strongly-ordered. */

/**
 * Ordinary CPU-access coherency contract for guest program/dynamic pools.
 *
 * This deliberately excludes framebuffer, peripheral, and DMA ownership
 * transfers: those remain explicit device capabilities with their own memory
 * attributes and maintenance boundaries.
 */
typedef enum lxp_cpu_memory_model {
	/** The host D-cache is disabled while the personality runs. */
	LXP_CPU_MEM_UNCACHED = 1,
	/** Guest and privileged coordinator use matching cacheable Normal-memory
	 * attributes on one coherent CPU cache. */
	LXP_CPU_MEM_COHERENT_SAME_ATTRS = 2,
} lxp_cpu_memory_model_t;

#define LXP_OS_OPS_ABI_VERSION 8u

/* Opaque host critical-section state. Ports which use irq-save primitives
 * return the native key through this value; ports with internally nested
 * critical sections may return zero. */
typedef uintptr_t lxp_critical_token_t;

/**
 * Complete Cortex-M state and executable-publication boundary for a fresh
 * guest image. The personality core derives this once from its private loader
 * result; ports translate it into their native initial task frame without
 * knowing the ELF/FDPIC representation.
 *
 * r[0..15] names r0..r15 (sp/lr/pc are r[13]/r[14]/r[15]). A non-zero
 * copied_text_size identifies the RAM text range which must be made visible to
 * instruction fetch before the task becomes runnable. Both copied-text fields
 * are zero for ordinary execute-in-place images.
 */
typedef struct lxp_guest_launch {
	uint32_t r[16];
	uint32_t xpsr;
	uintptr_t copied_text_base;
	size_t copied_text_size;
} lxp_guest_launch_t;

/** Native action requested through spawn_resume(). A captured Linux context
 * either starts a new host task (fork/vfork child) or resumes the persistent
 * task previously blocked by park_slot(). Ports must not infer this distinction
 * from a mutable runnable flag or native handle. */
typedef enum lxp_spawn_resume_mode {
	LXP_SPAWN_RESUME_START = 1,
	LXP_SPAWN_RESUME_PARKED = 2,
} lxp_spawn_resume_mode_t;

/* ─────────────────────────────────────────────────────────────────────────
 * OS / engine port — the process-model substrate.
 *
 * The leading entries are the per-engine "how do I place program memory, spawn
 * a task, take a critical section" primitives the run loop drives on its hot
 * path. The trailing entries are genuine OS services (monotonic time, thread
 * introspection) and optional cache / rootfs / remote-exec hooks (NULL => the
 * feature quietly degrades, matching the old weak-symbol stubs).
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct lxp_os_ops {
	uint32_t abi_version; /**< Must be LXP_OS_OPS_ABI_VERSION. */
	uint32_t struct_size; /**< Must be sizeof(lxp_os_ops_t). */

	/* The engine owns prog_regions[]; return region `ridx`'s base. */
	uint8_t *(*region)(int ridx);
	/* Host task transitions are generation checked and synchronous. The engine
	 * records `generation` when it creates a task and rejects park/resume/abort
	 * requests for another slot incarnation. Return LXP_OK only after the host
	 * transition has committed; a negative result leaves the prior host state
	 * intact (or, for a failed create, leaves no task). The core publishes the
	 * generation-qualified runnable capability before either spawn callback;
	 * a port must likewise publish its native generation before an API which
	 * can schedule the new task. */
	int (*spawn_launch)(int sidx, uint32_t generation, int ridx,
			    const lxp_guest_launch_t *launch);
	int (*spawn_resume)(int sidx, uint32_t generation, int ridx,
			    lxp_spawn_resume_mode_t mode, const struct lxp_resume_ctx *c,
			    long r0val);
	int (*abort_slot)(int sidx, uint32_t generation);
	/* Coordinator critical section: mask the program svc exception. The token
	 * belongs to this enter/exit pair and must not be retained by the core. */
	lxp_critical_token_t (*crit_enter)(void);
	void (*crit_exit)(lxp_critical_token_t token);
	/* Run-loop wakeup: dispatch posts when a program parks; the coordinator
	 * blocks in event_wait (ms timeout for sleeper deadlines / snapshot). */
	void (*event_post)(void);
	void (*event_wait)(unsigned ms);
	/* FDPIC dynamic-linking scratch pool for region `ridx` (ld.so mmaps libc
	 * here). NULL => dynamic execs can't launch on that engine. */
	uint8_t *(*dyn_pool)(int ridx, size_t *size);
	/* Privileged cold storage for slot `sidx`'s transient execve argv/env
	 * capture. Required by the coordinator; ports may place it in external RAM. */
	lxp_exec_capture_t *(*exec_capture)(int sidx);
	/* Map [addr,addr+size) RW into slot sidx's view with attrs (LXP_MAP_*).
	 * NULL => a device mmap returns -ENODEV. */
	int (*map_device)(int sidx, uintptr_t addr, size_t size, unsigned attrs);

	/* Monotonic clock (required). *out = microseconds / nanoseconds since boot. */
	int (*time_us)(uint64_t *out);
	int (*time_ns)(uint64_t *out);
	/* Host kernel-thread snapshot for the ps/top /proc view. NULL => omitted. */
	int (*thread_list)(struct lxp_thread_info *out, size_t max, size_t *n);

	/* Guest-memory cache maintenance (NULL => no-op; a coherent host needs none). */
	void (*cache_clean)(const void *base, size_t len);
	void (*cache_invalidate)(const void *base, size_t len);
	/* Give the coordinator a coherent (cacheable) view of guest region `ridx`
	 * (its program region + dyn_pool) before it services that guest's DEFERRED
	 * syscalls / parked-op retries, so the coordinator's reads and writes of the
	 * guest's buffers are coherent with the guest's own cached view (no per-call
	 * clean/invalidate needed). Only the single active region need be mapped; the
	 * coordinator services one slot at a time. On a host whose coordinator already
	 * shares the guest's cacheable mapping this is a no-op (NULL). */
	void (*coord_map)(int ridx);
	/* Tell the engine where the (XIP) rootfs image lives, for PC discrimination. */
	void (*rootfs_window)(const void *base, size_t len);
	/* Staging buffer for fetching a remote exec image. NULL => no remote exec. */
	uint8_t *(*exec_stage)(size_t *cap);

	/* Optional per-run bring-up / teardown, invoked by lxp_run() around the run
	 * loop. A host homes its engine-specific setup here — create the coordinator
	 * semaphore, enable Bus/UsageFault, program the MPU, attach the svc IRQ — and its
	 * restore in teardown. NULL => skipped. Once prepare() is entered, teardown()
	 * runs exactly once even when prepare() returns an error, so prepare() may
	 * acquire resources incrementally and rely on teardown() to roll back its
	 * completed steps. A failed prepare() makes lxp_run() return LXP_RUN_ELAUNCH. */
	int (*prepare)(void);
	void (*teardown)(void);

	/* Fill every byte in [buf, buf+len) from a host entropy source. The callback
	 * runs on the privileged coordinator task, must have a finite host-defined
	 * deadline, and returns LXP_OK only when the entire buffer is valid. A port
	 * without trustworthy entropy leaves this NULL; the guest then fails closed
	 * instead of receiving a predictable in-core fallback. Kept at the end so
	 * extending the source-level vtable does not move existing members. */
	int (*random_fill)(void *buf, size_t len);

	/* Host system-heap snapshot for sysinfo(2) and /proc/meminfo. NULL reports
	 * zero memory rather than inventing a fixed total. Kept at the end so source
	 * initializers for older ports remain valid. */
	int (*mem_stats)(struct lxp_mem_stats *out);

	/* Immutable host identity for the utsname.version field and /proc/version,
	 * e.g. "Zephyr 4.4.0 ove-1a2b3c4 lxp-5d6e7f8". The returned string must
	 * remain valid for the run; lxp truncates it to Linux's 64-byte field. */
	const char *(*system_version)(void);

	/* Persistent parked-task handoff. park_entry is the engine-owned,
	 * guest-executable target installed in the parked exception frame.
	 * park_prepare runs in the guest's svc exception and may return an opaque,
	 * guest-readable token which LXP passes to park_entry in r0 (NULL is valid
	 * for a native saved-frame restore). park_slot then blocks the existing RTOS
	 * task from coordinator context; a later
	 * spawn_resume(..., LXP_SPAWN_RESUME_PARKED, ...) restores and resumes that
	 * same task. A captured fork child instead uses
	 * LXP_SPAWN_RESUME_START. Both callbacks are required: deleting and
	 * recreating a task on every blocking syscall is not a supported lifecycle.
	 * Kept at the end for source-level compatibility with older designated
	 * initializers. */
	void (*park_entry)(void *token);
	void *(*park_prepare)(int sidx, uint32_t generation,
			      const struct lxp_resume_ctx *c);
	int (*park_slot)(int sidx, uint32_t generation);

	/* Declared CPU-memory contract plus a live-hardware validator. lxp_run()
	 * invokes validate_memory_model after prepare() has installed the port's
	 * MPU/cache state and before any guest image is loaded. A mismatch fails
	 * the run closed. */
	lxp_cpu_memory_model_t cpu_memory_model;
	int (*validate_memory_model)(lxp_cpu_memory_model_t declared);
} lxp_os_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* LXP_PORT_H */
