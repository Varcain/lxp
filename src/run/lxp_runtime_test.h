/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * White-box fixture for the separately linked coordinator test. Nothing in
 * this header is available in production builds.
 */
#ifndef LXP_RUNTIME_TEST_H
#define LXP_RUNTIME_TEST_H

#if !defined(LXP_TEST_INTERNALS)
#error "lxp_runtime_test.h is restricted to coordinator tests"
#endif

#include "lxp/lxp.h"
#include "lxp_run_internal.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_runtime_store.h"

struct lxp_runtime_test_fixture {
	struct lxp_slot_runtime *slots;
	struct lxp_region_runtime *regions;
	struct vfork_snapshot_guard *vfork_guards;
	const lxp_run_config_t **config;
	const lxp_os_ops_t **engine;
	const uint8_t **rootfs_lo;
	const uint8_t **rootfs_hi;
	uint8_t *diag_native_known;
	uint8_t *diag_native_present;
	uint32_t *diag_lifecycle_epoch;
	uint32_t *diag_native_epoch;
	volatile int *pending_signal;
	volatile int *tty_isig;
	volatile int *tty_icrnl;
#if defined(LXP_TEST_FAILPOINTS)
	enum lxp_lifecycle_failpoint *lifecycle_failpoint;
#endif
};

struct lxp_runtime_test_fixture *lxp_runtime_test_fixture(void);
lxp_region_ref_t lxp_test_region_ref_at(int region);
int lxp_test_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t owner);
unsigned lxp_test_coordinator_wait_timeout(uint32_t wait_policy, int socket_ready_events);
void lxp_test_coordinator_teardown_all(const lxp_os_ops_t *eng);
int lxp_test_futex_has_corunner(const lxp_proc_t *proc);
void lxp_test_diag_reset_health(void);
void lxp_test_diag_checkpoint(void);
void lxp_test_trap_publish(int active);
void lxp_test_deferred_state_store(int slot, uint8_t state);
int lxp_test_os_ops_valid(const lxp_os_ops_t *ops);
int lxp_test_run_config_valid(const lxp_run_config_t *cfg);
void lxp_test_futex(struct lxp_frame *frame, lxp_proc_t *proc, int is_time64);
void lxp_test_dispatch(struct lxp_frame *frame, lxp_proc_t *proc);
int lxp_test_service_select(uint8_t pending_mask, const uint64_t oldest[4], uint64_t now);

#endif /* LXP_RUNTIME_TEST_H */
