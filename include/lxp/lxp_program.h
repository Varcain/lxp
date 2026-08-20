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
