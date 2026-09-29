/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Coordinator-owned runtime records. This header is private to the run-loop
 * implementation and its white-box test fixture; it is not an installed API.
 */
#ifndef LXP_RUNTIME_STORE_H
#define LXP_RUNTIME_STORE_H

#include <stdint.h>

#include "lxp/lxp_latency.h"
#include "lxp/lxp_run.h"
#include "lxp_arena.h"
#include "proc/lxp_proc.h"
#include "lxp/lxp_seam.h"
#include "run/lxp_diag.h"

struct deferred_req {
	uint32_t a0;
	lxp_slot_ref_t owner;
	uint8_t state;
	uint8_t _pad[3];
#if LXP_ENABLE_LATENCY
	uint64_t pub_ns;
#endif
};

/* One core-owned record is the authority for a slot incarnation. */
struct lxp_slot_runtime {
	lxp_proc_t proc;
	struct lxp_resume_ctx resume;
	struct deferred_req deferred;
	uint32_t generation;
	uint8_t host_state;
	uint8_t runnable;
	uint8_t _pad[2];
};

/* Exact region reservations, including address spaces and temporary snapshot/exec
 * leases. A committed region belongs to the lxp_mm_t carrying its generation-bearing
 * reference; lease_owner is populated only until a prepared image/snapshot is either
 * committed or aborted. */
struct lxp_region_runtime {
	lxp_slot_ref_t lease_owner;
	uint16_t refs;
	uint16_t _pad;
	uint32_t generation;
};

/* vfork data isolation: a snapshot of the shared arena's allocator metadata, taken when a
 * vfork child is spawned and restored when it execs/exits. The region+dyn_pool bytes and
 * the coordinator-owned allocator metadata all use the same reserved snapshot region: its
 * arenas[] entry is otherwise idle until the child either execs into or releases it. */
struct vfork_snapshot_guard {
	lxp_slot_ref_t parent;
	lxp_region_ref_t parent_region;
	lxp_region_ref_t snapshot;
};

struct lxp_dbg_s {
	uintptr_t text_base;
	uintptr_t data_base;
	uintptr_t entry;
	uintptr_t dynamic;
	uintptr_t interp_base;
};

/* The coordinator's state for one run. It is one global on purpose: the SVC handler has no
 * context pointer, and there is one coordinator. Keeping it in one record makes its size
 * exact (lxp_diag_sizes) and gives tests and debuggers one place to look. Three objects
 * stay separately named because something outside the coordinator finds them by name:
 * the trap gate (port SVC assembly), the signal-save stacks (the host's linker script)
 * and the debugger records (g_lxp_dbg). */
struct lxp_runtime {
	const lxp_run_config_t *cfg; /* the running configuration; NULL between runs */
	/* The rootfs cpio region [rootfs_lo, rootfs_hi). Dynamic FDPIC processes execute
	 * busybox.so, ld.so and libc.so text shared in place from it; engine MPU policies grant
	 * it user RO+X access. NULL until a run starts. */
	const uint8_t *rootfs_lo;
	const uint8_t *rootfs_hi;
	struct lxp_slot_runtime slots[LXP_NSLOT];
	struct lxp_region_runtime regions[LXP_NREG];
	lxp_arena_t arenas[LXP_NREG]; /* each region's allocator bookkeeping */
	struct vfork_snapshot_guard vfork_guard[LXP_NSLOT];
	struct lxp_diag_state diag; /* src/run/lxp_diag.c */
	/* Heartbeat: bumped once per dispatch-loop iteration and read by a host watchdog
	 * through lxp_run_health(). Free-running; a stalled value while active is the wedge
	 * signal. An aligned volatile u32 makes the cross-task read atomic without a lock
	 * (the reader only needs to observe change, not a precise count). */
	volatile uint32_t coord_iters;
#if LXP_ENABLE_FS
	int fs_completion_ready; /* a host fs completion arrived (lxp_fs_completion_ready) */
#endif
};

extern struct lxp_runtime g_lxp_rt;
extern struct lxp_dbg_s g_lxp_dbg[LXP_NSLOT];

#endif /* LXP_RUNTIME_STORE_H */
