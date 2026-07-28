/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bounded execve capture shared by the process core and RTOS-owned per-slot
 * storage. It has no dependency on the mutable process representation.
 */

#ifndef LXP_EXEC_H
#define LXP_EXEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bounds for an execve() argument vector captured for the engine to relaunch.
 * Overridable by the consumer: entries cost 2 bytes each per slot, the payload
 * buffer costs its full width per slot. */
#ifndef LXP_EXEC_MAXARGS
#define LXP_EXEC_MAXARGS 32
#endif
#ifndef LXP_EXEC_ARGBUF
#define LXP_EXEC_ARGBUF 768
#endif

/** Marks an exec vector entry the capture never wrote. Offset 0 is valid. */
#define LXP_EXEC_OFF_NONE ((uint16_t)0xffffu)

/** Bounds for an execve() environment vector captured for relaunch. */
#ifndef LXP_EXEC_MAXENVS
#define LXP_EXEC_MAXENVS 24
#endif
#ifndef LXP_EXEC_ENVBUF
#define LXP_EXEC_ENVBUF 512
#endif

_Static_assert(LXP_EXEC_ARGBUF < LXP_EXEC_OFF_NONE,
	       "LXP_EXEC_ARGBUF exceeds uint16_t offsets");
_Static_assert(LXP_EXEC_ENVBUF < LXP_EXEC_OFF_NONE,
	       "LXP_EXEC_ENVBUF exceeds uint16_t offsets");
_Static_assert(LXP_EXEC_MAXARGS <= LXP_EXEC_ARGBUF,
	       "more argv entries than argv buffer bytes");
_Static_assert(LXP_EXEC_MAXENVS <= LXP_EXEC_ENVBUF,
	       "more envp entries than envp buffer bytes");
_Static_assert(LXP_EXEC_MAXARGS >= 4,
	       "argv vector too short for a #! rewrite plus one argument");

/**
 * Transient argv/environment capture consumed by the coordinator during image
 * replacement. Ports may place this cold per-slot object in external memory.
 */
typedef struct lxp_exec_capture {
	int argc;
	uint16_t argv[LXP_EXEC_MAXARGS];
	char argv_buf[LXP_EXEC_ARGBUF];
	int envc;
	uint16_t env[LXP_EXEC_MAXENVS];
	char env_buf[LXP_EXEC_ENVBUF];
} lxp_exec_capture_t;

#ifdef __cplusplus
}
#endif

#endif /* LXP_EXEC_H */
