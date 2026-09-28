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
#include "proc/lxp_proc.h"
#include "lxp/lxp_seam.h"

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

struct lxp_region_runtime {
	lxp_slot_ref_t lease_owner;
	uint16_t refs;
	uint16_t _pad;
	uint32_t generation;
};

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

#endif /* LXP_RUNTIME_STORE_H */
