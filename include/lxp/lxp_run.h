/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_RUN_H
#define LXP_RUN_H

#include "lxp/lxp_diag.h"
#include "lxp/lxp_display_ops.h"
#include "lxp/lxp_exec.h"
#include "lxp/lxp_fs_ops.h"
#include "lxp/lxp_block_ops.h"
#include "lxp/lxp_net_ops.h"
#include "lxp/lxp_netfs_config.h"
#include "lxp/lxp_port.h"
#include "lxp/lxp_program.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Immutable termination record passed to @c lxp_launch_config.on_guest_exit in
 * coordinator task context. @c comm points into the process slot and is valid
 * only for the duration of the callback. */
typedef struct lxp_guest_exit_info {
	int slot;
	int pid;
	int ppid;
	int status;
	const char *comm;
	uint8_t reason; /**< @c LXP_EXIT_REASON_* */
	uint8_t signal;
	uint16_t _pad;
	uint32_t detail;   /**< Port-defined status, e.g. Cortex-M CFSR. */
	uintptr_t address; /**< Port-defined fault address, or 0 when unavailable. */
} lxp_guest_exit_info_t;

/** Run-scoped process-exit notification. @p ctx is copied from the launch
 * configuration and remains owned by the caller. */
typedef void (*lxp_guest_exit_fn)(void *ctx, const lxp_guest_exit_info_t *info);

/** Host-owned formatter for the optional real-time diagnostic proc node.
 * The callback must not block or mutate the measured interval. It returns the
 * number of bytes placed in @p buf, or a negative value when unavailable. */
typedef long (*lxp_rt_scope_read_fn)(void *ctx, char *buf, size_t cap);

/**
 * @file
 * @defgroup lxp_run Linux personality runner
 * @brief Engine-agnostic public API for running a Linux program under the
 *        lxp Linux personality.
 *
 * The engine-agnostic core translates the Linux ABI through explicit OS, network,
 * filesystem, block and display provider contracts and implements the NOMMU process
 * model (vfork/exec/wait, signals, the run loop). A per-engine port binds the OS
 * contract to a concrete RTOS: it traps the unprivileged program's syscalls, runs each
 * loaded FDPIC program in its own memory domain and manages its task. This header is
 * the public contract a host application uses; the FreeRTOS, NuttX and Zephyr ports
 * live under ports/, with the POSIX and QEMU ports as reference integrations.
 *
 * A host supplies a parsed rootfs and console callbacks, then calls
 * @ref lxp_run with an init program.
 * @{
 */

/** Per-launch policy: the console, environment and diagnostics of one run. lxp_host_run()
 * layers it over a host's immutable rootfs and providers. Zero initialization selects
 * every optional default. */
typedef struct lxp_launch_config {
	lxp_console_t console;	    /**< The terminal behind fds 0-2 and /dev/console. */
	void (*on_enosys)(long nr); /**< Optional: notified of an unimplemented syscall. */
	/** Optional NULL-terminated initial environment for pid 1 (e.g. @c PATH, @c HOME,
	 * @c TERM). NULL → an empty environment. The strings are copied onto the guest's
	 * startup stack; a guest's @c execve(2) replaces the environment for the new image,
	 * and a @c fork inherits it. Bounded by @c LXP_EXEC_MAXENVS / @c LXP_EXEC_ENVBUF. */
	const char *const *env;
	/** Optional process-exit diagnostic. Called once per terminated guest from the
	 * privileged coordinator task, after all fault/exit metadata is stable and
	 * before the slot is reused. It must return within a host-defined finite bound. */
	lxp_guest_exit_fn on_guest_exit;
	void *guest_exit_ctx; /**< Opaque, passed to @p on_guest_exit. */
	/** Touch/input coordinate extent for this run. Zero selects the module default
	 * (480x272) independently for each dimension. These fields configure no static
	 * storage; process counts and pool sizes remain compile-time properties. */
	uint16_t display_width;
	uint16_t display_height;
	/** Optional host real-time snapshot exposed verbatim as /proc/rt_scope. */
	lxp_rt_scope_read_fn rt_scope_read;
	void *rt_scope_ctx; /**< Opaque, passed to @p rt_scope_read. */
	lxp_identity_t identity; /**< Host, framebuffer and input names the guest sees. */
} lxp_launch_config_t;

/** Host configuration for a personality run. Zero-initialize it (a designated initializer
 * such as @c {.rootfs=..., .launch.env=...} or @c memset) so every optional field reads NULL/0:
 * the runner dereferences pointer fields like @c env, so an uninitialized one faults at
 * launch. New optional fields are always added at the end and default to "unset" when zero. */
typedef struct lxp_run_config {
	const lxp_file_t *rootfs; /**< Parsed (read-only) rootfs table. */
	int rootfs_count;	      /**< Entry count in @p rootfs. */
	/** Trusted contiguous image that owns every @p rootfs data extent. Required.
	 * Dynamic FDPIC text executes in place from this window, so the core validates
	 * every table entry before publishing the window to an MPU seam. */
	const void *rootfs_image;
	size_t rootfs_image_size;
	/** Run-scoped interface used by eth0 ioctls and /proc/net. NULL leaves
	 * interface reporting unavailable without changing socket availability. */
	lxp_netif_t netif;
	/** Optional run-scoped 9P mount. LXP copies it before initiating the
	 * connection; NULL disables netfs for this run. */
	const lxp_netfs_config_t *netfs_config;
	lxp_launch_config_t launch; /**< The console and policy of this launch. */
} lxp_run_config_t;

/** The host services one run uses. The caller keeps every table alive until
 * lxp_run() returns; a table for a feature the build leaves out is ignored. */
typedef struct lxp_providers {
	/** The engine / OS port (required): program-memory placement, task spawn and
	 * abort, critical section, run-loop event wait/post, monotonic time, plus
	 * optional cache, thread introspection, prepare and teardown. */
	const lxp_os_ops_t *os;
	const lxp_net_ops_t *net;         /**< Sockets (LXP_ENABLE_NET). */
	const lxp_display_ops_t *display; /**< Framebuffer, DMA2D, touch (LXP_ENABLE_DEV_*). */
	const lxp_fs_ops_t *fs;           /**< Writable filesystem (LXP_ENABLE_FS). */
	const lxp_block_ops_t *block;     /**< Raw block media (LXP_ENABLE_BLOCK). */
} lxp_providers_t;

/**
 * Load @p path from the rootfs and run it as pid 1, driving the NOMMU process
 * model (vfork/exec/wait, signals, pipes) until it exits. This is THE port entry
 * (the lwIP sys_arch / FatFs diskio pattern): the host fills provider vtables and
 * passes them here rather than wiring module globals directly.
 *
 * @p providers  the host services this run uses (required).
 * @p run_config the rootfs table, console callbacks, and optional display
 *               geometry (required).
 *
 * @p argv[0] is the program name seen by the program (it may differ from @p path,
 * e.g. run @c /bin/busybox as @c "sh"). @p path must name a regular file or a
 * @c #! interpreter script in @p run_config->rootfs; symlinks are followed for
 * both the initial path and its interpreter. Calls are sequential: each run
 * publishes the ops, runs
 * @c os_ops->prepare(), drives the loop, then @c os_ops->teardown() and tears down
 * its threads before returning, so a host may call this repeatedly.
 *
 * @return the init exit status (>= 0), or a negative lxp_err_t naming why the run
 * failed: @c LXP_ERR_INVALID_PARAM for a malformed call; the failing provider's or
 * @c os_ops->prepare()'s own result when host setup fails; @c LXP_ERR_NOT_SUPPORTED
 * when the console refuses its readiness subscription; why @p path could not be
 * launched (@c LXP_ERR_NOT_FOUND for a missing program, @c LXP_ERR_NOT_SUPPORTED for
 * one that cannot be executed, @c LXP_ERR_NO_MEMORY); or @c LXP_ERR_TIMEOUT when every
 * process stays blocked with nothing left to wake it.
 */
int lxp_run(const lxp_providers_t *providers, const lxp_run_config_t *run_config,
	    const char *path, int argc, const char *const argv[]);

/**
 * A read-only snapshot of coordinator liveness, for a host watchdog.
 *
 * @c coord_iters counts iterations of the coordinator's dispatch loop. The loop
 * blocks only in a bounded @c event_wait (≤ tens of ms) even when fully idle, so
 * in a healthy system this advances continuously; the one thing that stops it is
 * the loop itself wedging (a stuck dispatch, a privileged spin). A host feeder
 * can therefore treat "advanced since last check" as "the personality is live"
 * and withhold the feed otherwise — but only while @c active, since the loop is
 * not running before/between @c lxp_run() calls (there @c coord_iters is frozen
 * and means nothing). It is a free-running counter: compare successive samples
 * for inequality, do not read absolute values, and expect wraparound.
 *
 * This measures host liveness only. Guest progress is deliberately absent: a
 * guest must not be able to hold the watchdog open, nor a stuck guest force a
 * reset — a faulting guest is contained, not fatal.
 */
typedef struct lxp_run_health {
	uint32_t coord_iters; /**< coordinator dispatch-loop iterations (free-running) */
	int active;	      /**< nonzero while lxp_run() is driving a guest */
} lxp_run_health_t;

/** Snapshot coordinator liveness into @p out (ignored if NULL). */
void lxp_run_health(lxp_run_health_t *out);

/**
 * Return a lock-free scheduling-share weight for one live guest slot.
 *
 * The bounded range is 1..40 (nice 19..-20); zero means that @p slot is not a
 * live guest. Ports may use this only to divide time among guests in their
 * existing best-effort RTOS class. It is never an RTOS priority and must not
 * let a guest outrank the coordinator, service workers, or real-time tasks.
 */
uint32_t lxp_guest_sched_weight(int slot);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* LXP_RUN_H */
