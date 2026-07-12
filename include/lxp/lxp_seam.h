/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Internal interface between the engine-agnostic Linux-personality run loop +
 * svc dispatch (src/lxp_run.c) and a concrete host engine. NOT a public API.
 *
 * The shared core owns the NOMMU process model — the vfork/exec/wait run loop,
 * the syscall-dispatch body, and signal delivery — all written against a uniform
 * register frame and the port vtable (lxp_os_ops_t, in lxp_port.h). Each host
 * engine supplies only what genuinely differs: the svc-trap mechanism, the
 * program memory (whose placement differs — e.g. an MPU-partitioned region), and
 * the task spawn/abort. This header adds the register frame + the shared run-loop
 * state the engine's trap reads/writes; the vtable itself is the public port type.
 */

#ifndef LXP_SEAM_H
#define LXP_SEAM_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h" /* LXP_PROG_REGION_SIZE / LXP_NREG / LXP_NSLOT / sizing knobs */
#include "lxp/lxp_loader.h"
#include "lxp/lxp_port.h" /* lxp_os_ops_t — the engine/OS port vtable the run loop drives */
#include "lxp/lxp_run.h"
#include "lxp/lxp_syscall.h"

/* Program-region / arena / dyn-pool sizes + LXP_NREG / LXP_NSLOT come from
 * lxp_config.h (host-overridable; the oveRTOS build maps them per engine). */


/* A uniform Cortex-M register frame the dispatch reads/writes. The seam populates
 * it from its native exception frame and writes the modified HW registers back.
 * r[0..15] = r0..r15 (r[13]=sp = the program's pre-svc SP, r[14]=lr, r[15]=pc). */
struct lxp_frame {
	uint32_t r[16];
	uint32_t xpsr;
};

/* Parent context captured at a vfork svc, replayed to resume the parent + child.
 * (Full definition of the lxp_port.h opaque struct lxp_resume_ctx.) */
struct lxp_resume_ctx {
	uint32_t r4_11[8];
	uint32_t r12;
	uint32_t lr;
	uint32_t sp;
	uint32_t pc;
	/* r1..r3 at the parked svc. The Linux syscall ABI preserves r1-r14 across a
	 * syscall (only r0 is the return); a parking syscall that resumes must therefore
	 * restore them, or a guest that (validly) reuses an arg register after the call
	 * sees garbage. Appended after pc so a seam prog_tramp that predates this still
	 * reads r4_11/r12/lr/sp/pc at the same offsets. r0 is delivered separately (the
	 * resume value). */
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
};

/* The per-engine operations the shared run loop drives are the public port vtable
 * lxp_os_ops_t (lxp_port.h): region/spawn_launch/spawn_resume/abort_slot, the
 * crit/event primitives, dyn_pool/map_device, and the OS-service hooks (time,
 * thread_list, cache, rootfs_window, exec_stage) + prepare/teardown. */

/* ---- shared state (defined in lxp_run.c) ------------------------------- */
extern struct lxp_resume_ctx g_lxp_vfork; /* vfork capture buffer */
extern lxp_proc_t g_lxp_proc[LXP_NSLOT];
extern int g_lxp_used[LXP_NSLOT]; /* slot in use (run loop + seam read) */
extern volatile int g_lxp_active;	  /* a run is in progress (seam trap gate) */
extern volatile int g_lxp_halt;	  /* reboot(2)/poweroff: stop the run loop */
/* The embedded cpio's data span [lo, hi): a dynamic FDPIC proc runs its shared in-place text from
 * here, so a PC-discriminating seam (NuttX) treats a cpio PC as a program svc. NULL pre-run. */
extern const uint8_t *g_lxp_rootfs_lo, *g_lxp_rootfs_hi;

/* Where a parked program spins (in shared .text) until the run loop reaps it. */
void lxp_park_loop(void);

/* The shared svc-dispatch body. Called by the seam's trap with the uniform frame
 * and the running slot's proc; on return the seam writes the frame back. */
void lxp_dispatch(struct lxp_frame *f, lxp_proc_t *proc);

/* The shared run loop. The public lxp_run() (lxp_run.c) wraps this: it publishes
 * the net/display ports, runs ops->prepare(), drives this loop, then ops->teardown(). */
int lxp_run_common(const lxp_os_ops_t *ops, const lxp_run_config_t *cfg,
		       const char *path, int argc, const char *const argv[]);

#endif /* LXP_SEAM_H */
