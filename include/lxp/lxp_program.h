/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Host-facing program image, console, and termination types. These are shared
 * by the runner and process core without exposing mutable process state.
 */

#ifndef LXP_PROGRAM_H
#define LXP_PROGRAM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Host-side attribution for a guest process termination. */
#define LXP_EXIT_REASON_NONE 0
#define LXP_EXIT_REASON_NORMAL 1
#define LXP_EXIT_REASON_SIGNAL 2
#define LXP_EXIT_REASON_SIGNAL_DEPTH 3
#define LXP_EXIT_REASON_MEMORY_FAULT 4
#define LXP_EXIT_REASON_EXEC_RESOURCE 5
#define LXP_EXIT_REASON_EXEC_LOAD 6
#define LXP_EXIT_REASON_STATE_CORRUPTION 7
#define LXP_EXIT_REASON_HOST_TRANSITION 8

/** fd 1/2 output sink. Returns bytes written or a negated Linux errno. */
typedef long (*lxp_write_fn)(void *ctx, int fd, const void *buf, size_t len);
/** fd 0 input source. Returns bytes read (0 = EOF) or a negated Linux errno. */
typedef long (*lxp_read_fn)(void *ctx, int fd, void *buf, size_t len);
/** Run-scoped notification that console input may now be readable. */
typedef void (*lxp_console_ready_fn)(const void *context);
/** Subscribe the active console source to a coordinator readiness callback. */
typedef int (*lxp_console_subscribe_fn)(void *ctx, lxp_console_ready_fn ready,
					const void *ready_context);
/** Stop console readiness callbacks before their run context is withdrawn. */
typedef void (*lxp_console_unsubscribe_fn)(void *ctx);

/** The console of one run: the terminal behind the initial program's fds 0-2 and
 * /dev/console. Every callback runs in the privileged coordinator task and receives
 * @c ctx. */
typedef struct lxp_console {
	/** fd 1/2 sink. It must return within a host-defined finite interval: a call
	 * carries at most LXP_SYSCALL_QUANTUM_BYTES, but LXP cannot bound the callback. */
	lxp_write_fn write;
	/** fd 0 source; see the tty helpers. Pair a source that may block with @c poll so
	 * the coordinator can park the guest instead of entering @c read before data exists. */
	lxp_read_fn read;
	/** Optional, strictly non-blocking "is a keystroke available right now?" (1/0). It
	 * gives the console fd a true poll(2) (e.g. interactive `top`'s 'q' quit); without it
	 * the console is blocking-only and poll falls back to a heuristic. */
	int (*poll)(void *ctx);
	/** Optional readiness subscription, paired with @c unsubscribe (both or neither) and
	 * requiring @c read and @c poll. It lets the coordinator wait for an event instead of
	 * polling a parked console every 5 ms. It returns 0 once subscribed; any other result
	 * makes lxp_run() fail with LXP_ERR_NOT_SUPPORTED. The provider must stop callbacks
	 * before @c unsubscribe returns. */
	lxp_console_subscribe_fn subscribe;
	lxp_console_unsubscribe_fn unsubscribe;
	void *ctx; /**< Opaque, passed to every callback above. */
} lxp_console_t;

/** The names a guest sees for the system it runs on. A NULL name selects LXP's default. */
typedef struct lxp_identity {
	const char *nodename;	/**< uname(2) nodename, up to 64 bytes; default "lxp". */
	const char *fb_id;	/**< /dev/fb0 FSCREENINFO id, up to 15 bytes; default "lxpfb". */
	const char *input_name; /**< /dev/input/event0 EVIOCGNAME; default "lxp-touch". */
} lxp_identity_t;

/** One node in the read-only in-memory rootfs (a flat path to bytes table). */
typedef struct lxp_file {
	const char *path;
	const uint8_t *data;
	size_t size;
	uint32_t mode;
} lxp_file_t;

#ifdef __cplusplus
}
#endif

#endif /* LXP_PROGRAM_H */
