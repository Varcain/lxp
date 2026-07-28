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
#include "lxp/lxp_exec.h"
#include "lxp/lxp_identity.h"
#include "lxp/lxp_port.h" /* lxp_os_ops_t — the engine/OS port vtable the run loop drives */
#include "lxp/lxp_run.h"

/* Program-region / arena / dyn-pool sizes + LXP_NREG / LXP_NSLOT come from
 * lxp_config.h (host-overridable; the oveRTOS build maps them per engine). */


/* Complete Cortex-M single-precision floating-point state. `active` records
 * whether the interrupted task owned an extended FP exception frame. The seam
 * is responsible for forcing any lazy stack operation before populating this
 * object and for applying changes before exception return or task resume. */
#if LXP_ENABLE_FPU_CONTEXT
struct lxp_fp_context {
	uint32_t s[32];
	uint32_t fpscr;
	uint32_t active;
};
#endif

/* A uniform Cortex-M register frame the dispatch reads/writes. The seam populates
 * it from its native exception frame and writes the modified HW registers back.
 * r[0..15] = r0..r15 (r[13]=sp = the program's pre-svc SP, r[14]=lr, r[15]=pc). */
struct lxp_frame {
	uint32_t r[16];
	uint32_t xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	/* Mutable seam-owned storage; NULL means that this execution context cannot
	 * capture/restore VFP state and therefore must not run a VFP guest. */
	struct lxp_fp_context *fp;
#endif
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
	/** APSR condition flags captured at the SVC. A deferred syscall may resume
	 * through a native saved frame or a trampoline; either path must restore
	 * NZCVQ just as the immediate hardware exception return would. */
	uint32_t xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	/* Appended to retain all legacy core-register offsets used by assembly
	 * trampolines. A port enabling this feature must restore it on spawn_resume. */
	struct lxp_fp_context fp;
#endif
};

/** Translate a fresh-image register contract into the context consumed by
 * trampoline-based ports. Native-frame ports may copy launch->r[] directly. */
static inline void lxp_resume_ctx_from_launch(struct lxp_resume_ctx *out,
					      const lxp_guest_launch_t *launch)
{
	*out = (struct lxp_resume_ctx){0};
	for (unsigned i = 0; i < 8; i++)
		out->r4_11[i] = launch->r[4u + i];
	out->r12 = launch->r[12];
	out->lr = launch->r[14];
	out->sp = launch->r[13];
	out->pc = launch->r[15];
	out->r1 = launch->r[1];
	out->r2 = launch->r[2];
	out->r3 = launch->r[3];
	out->xpsr = launch->xpsr;
}

/* The per-engine operations the shared run loop drives are the public port vtable
 * lxp_os_ops_t (lxp_port.h): region/spawn_launch/spawn_resume, task
 * park/abort, the crit/event primitives, dyn_pool/map_device, and the OS-service
 * hooks (time, thread_list, cache, rootfs_window, exec_stage) + prepare/teardown. */

/* ---- narrow shared-core operations (defined in lxp_run.c) -------------- */
/** Acquire the run-active publication gate before consulting slot state. */
int lxp_trap_active(void);

/** Maximum device capabilities represented by an address-space policy. */
#define LXP_MEMORY_DEVICE_MAX 2u
#define LXP_MEMORY_POLICY_ABI_VERSION 1u

typedef struct lxp_device_capability {
	uintptr_t base;
	size_t size;
	uint32_t attrs; /**< LXP_MAP_*; backing range came from a registered driver. */
} lxp_device_capability_t;

/**
 * Immutable logical policy from which a seam prepares its native MPU/domain
 * descriptors. The complete validity key is slot + address-space + device +
 * execute-policy generation; a seam may skip native reprogramming only when
 * all four still match.
 */
typedef struct lxp_memory_policy {
	uint32_t abi_version;
	uint32_t struct_size;
	lxp_slot_ref_t slot;
	lxp_region_ref_t address_space;
	uint32_t device_generation;
	uint32_t exec_generation;
	uint8_t copied_text_executable;
	uint8_t device_count;
	uint16_t _pad;
	lxp_device_capability_t devices[LXP_MEMORY_DEVICE_MAX];
} lxp_memory_policy_t;

/** Compact cache key for a prepared native MPU/domain descriptor set. */
typedef struct lxp_memory_policy_key {
	lxp_slot_ref_t slot;
	lxp_region_ref_t address_space;
	uint32_t device_generation;
	uint32_t exec_generation;
	uint8_t copied_text_executable;
	uint8_t _pad[3];
} lxp_memory_policy_key_t;

/**
 * Validate the complete, versioned memory-policy representation before a
 * seam translates it into native MPU/domain state.
 *
 * Returns LXP_OK for the current canonical representation, -LXP_EINVAL for a
 * malformed, truncated, stale-version, or otherwise non-canonical policy.
 */
int lxp_memory_policy_validate(const lxp_memory_policy_t *policy);

static inline lxp_memory_policy_key_t
lxp_memory_policy_make_key(const lxp_memory_policy_t *policy)
{
	lxp_memory_policy_key_t key = {0};
	if (lxp_memory_policy_validate(policy) != LXP_OK)
		return key;
	key.slot = policy->slot;
	key.address_space = policy->address_space;
	key.device_generation = policy->device_generation;
	key.exec_generation = policy->exec_generation;
	key.copied_text_executable = policy->copied_text_executable;
	return key;
}

static inline int lxp_memory_policy_matches_key(const lxp_memory_policy_t *policy,
						const lxp_memory_policy_key_t *key)
{
	return key && lxp_memory_policy_validate(policy) == LXP_OK &&
	       lxp_slot_ref_equal(policy->slot, key->slot) &&
	       lxp_region_ref_equal(policy->address_space, key->address_space) &&
	       policy->device_generation == key->device_generation &&
	       policy->exec_generation == key->exec_generation &&
	       policy->copied_text_executable == key->copied_text_executable;
}

static inline int lxp_memory_policy_address_space_matches_key(
	const lxp_memory_policy_t *policy, const lxp_memory_policy_key_t *key)
{
	return key && lxp_memory_policy_validate(policy) == LXP_OK &&
	       lxp_region_ref_equal(policy->address_space, key->address_space) &&
	       policy->device_generation == key->device_generation &&
	       policy->exec_generation == key->exec_generation &&
	       policy->copied_text_executable == key->copied_text_executable;
}

/** Fault metadata published by an engine containment path. */
typedef struct lxp_guest_fault {
	uint32_t detail;
	uintptr_t address;
} lxp_guest_fault_t;

/** Capture the current incarnation of @p slot. */
int lxp_slot_ref_current(int slot, lxp_slot_ref_t *out);
/** Whether @p ref still identifies the same live slot incarnation. */
int lxp_slot_ref_is_current(lxp_slot_ref_t ref);
/** Whether @p ref is the current incarnation and its native task is runnable. */
int lxp_slot_ref_is_runnable(lxp_slot_ref_t ref);
/** Obtain the current address-space region capability for @p ref. */
int lxp_slot_region_ref(lxp_slot_ref_t ref, lxp_region_ref_t *out);
/** Snapshot the current slot's abstract MPU/cache policy. */
int lxp_slot_memory_policy(lxp_slot_ref_t ref, lxp_memory_policy_t *out);

/** Dispatch one guest SVC only if @p ref remains current and runnable. */
int lxp_dispatch_slot(lxp_slot_ref_t ref, struct lxp_frame *frame);

/** Publish a contained memory fault and its exit event for a current slot. */
int lxp_slot_report_memory_fault(lxp_slot_ref_t ref, const lxp_guest_fault_t *fault);

#endif /* LXP_SEAM_H */
