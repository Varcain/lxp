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
#include "lxp/lxp_disp_ops.h"
#include "lxp/lxp_exec.h"
#include "lxp/lxp_fs_ops.h"
#include "lxp/lxp_net_ops.h"
#include "lxp/lxp_port.h"
#include "lxp/lxp_program.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Immutable termination record passed to @c lxp_run_config.on_guest_exit in
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
 * The engine-agnostic core (@ref lxp_syscall) translates the Linux ABI through
 * explicit OS, network, filesystem, and display provider contracts; a per-engine seam binds
 * those contracts to a concrete RTOS engine —
 * trapping the unprivileged program's syscalls, running each loaded FDPIC program in its
 * own isolated memory domain, and implementing the NOMMU process model
 * (sequentialised vfork/exec/wait, signal delivery, the run loop). This header
 * is the public contract a host application uses; the seam provides the
 * implementation (a per-engine backend — e.g. the FreeRTOS/Zephyr/NuttX seams in
 * oveRTOS, or the bundled QEMU / POSIX reference ports).
 *
 * A host supplies a parsed rootfs and console callbacks, then calls
 * @ref lxp_run with an init program.
 * @{
 */

/** Host configuration for a personality run. Zero-initialize it (a designated initializer
 * such as @c {.rootfs=..., .write_fn=...} or @c memset) so every optional field reads NULL/0:
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
	/** Console sink (fd 1/2), called from the privileged coordinator task. It must
	 * return within a host-defined finite interval; byte count is bounded by
	 * LXP_SYSCALL_QUANTUM_BYTES but the module cannot bound an external callback. */
	lxp_write_fn write_fn;
	/** Console source (fd 0), called from the privileged coordinator task; see the
	 * tty helpers. Pair a potentially blocking source with console_poll so the
	 * coordinator can park the guest instead of entering read_fn before data exists. */
	lxp_read_fn read_fn;
	void *io_ctx;		      /**< Opaque, passed to @p write_fn / @p read_fn. */
	void (*on_enosys)(long nr);   /**< Optional: notified of an unimplemented syscall. */
	/** Optional: strictly non-blocking "is a console keystroke available right now?" (1/0).
	 * Enables a true poll(2) on the console fd (e.g. interactive `top`'s 'q' quit):
	 * without it the console transport is blocking-only and poll falls back to a
	 * heuristic. Backed by a UART RX-ready check when the host uses a UART console. */
	int (*console_poll)(void *ctx);
	/** Optional NULL-terminated initial environment for pid 1 (e.g. @c PATH, @c HOME,
	 * @c TERM). NULL → an empty environment. The strings are copied onto the guest's
	 * startup stack; a guest's @c execve(2) replaces the environment for the new image,
	 * and a @c fork inherits it. Bounded by @c LXP_EXEC_MAXENVS / @c LXP_EXEC_ENVBUF. */
	const char *const *env;
	/** Optional process-exit diagnostic. Called once per terminated guest from the
	 * privileged coordinator task, after all fault/exit metadata is stable and
	 * before the slot is reused. It must return within a host-defined finite bound. */
	void (*on_guest_exit)(const lxp_guest_exit_info_t *info);
	/** Touch/input coordinate extent for this run. Zero selects the module default
	 * (480x272) independently for each dimension. These fields configure no static
	 * storage; process counts and pool sizes remain compile-time properties. */
	uint16_t display_width;
	uint16_t display_height;
	/** Optional host real-time snapshot exposed verbatim as /proc/rt_scope. */
	lxp_rt_scope_read_fn rt_scope_read;
	void *rt_scope_ctx; /**< Opaque, passed to @p rt_scope_read. */
} lxp_run_config_t;

/** @ref lxp_run outcomes (negative; a non-negative result is the init
 * process's exit status). */
#define LXP_RUN_ELAUNCH (-1)  /**< The init program could not be loaded. */
#define LXP_RUN_EEXEC (-2)	  /**< A child execve relaunch failed. */
#define LXP_RUN_ETIMEOUT (-3) /**< init did not exit within the run budget. */

/**
 * Load @p path from the rootfs and run it as pid 1, driving the NOMMU process
 * model (vfork/exec/wait, signals, pipes) until it exits. This is THE port entry
 * (the lwIP sys_arch / FatFs diskio pattern): the host fills provider vtables and
 * passes them here rather than wiring module globals directly.
 *
 * @p os_ops     the engine / OS port (required): program-memory placement, task
 *               spawn/abort, critical section, run-loop event wait/post, monotonic
 *               time, + optional cache / thread-introspection / prepare / teardown.
 * @p net_ops    the handle-based socket port, or NULL when built without NET.
 * @p disp_ops   the framebuffer / touch port, or NULL when built without DEV.
 * @p fs_ops     the writable-filesystem port, or NULL when built without FS.
 * @p run_config the rootfs table, console callbacks, and optional display
 *               geometry (required).
 *
 * @p argv[0] is the program name seen by the program (it may differ from @p path,
 * e.g. run @c /bin/busybox as @c "sh"). @p path must name a regular file in
 * @p run_config->rootfs. Calls are sequential: each run publishes the ops, runs
 * @c os_ops->prepare(), drives the loop, then @c os_ops->teardown() and tears down
 * its threads before returning, so a host may call this repeatedly.
 *
 * @return the init exit status (>= 0), or one of the @c LXP_RUN_E* codes (< 0).
 */
int lxp_run(const lxp_os_ops_t *os_ops, const lxp_net_ops_t *net_ops,
	    const lxp_display_ops_t *disp_ops, const lxp_fs_ops_t *fs_ops,
	    const lxp_run_config_t *run_config, const char *path, int argc,
	    const char *const argv[]);

/**
 * Notify the active coordinator that console input became ready.
 *
 * Console providers call this from their RX-ready path after publishing the
 * byte(s). It is safe before/after a run and becomes a no-op when no
 * coordinator owns the provider.
 */
void lxp_console_kick(void);

/**
 * Whether the tty is in ISIG (canonical) mode. A @c read_fn consults this to
 * decide whether a console ^C is the interrupt key (raise SIGINT) or a literal
 * byte (the shell's raw line editor turns ISIG off). Tracked from TCSETS.
 */
int lxp_tty_isig(void);

/**
 * Latch an asynchronous signal (e.g. SIGINT from a console ^C) for delivery to
 * the running program at the next syscall boundary (the Linux async-delivery
 * model). Typically called by a @c read_fn that is returning @c -LXP_EINTR.
 */
void lxp_post_signal(int sig);

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
