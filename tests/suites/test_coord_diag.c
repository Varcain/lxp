/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator tests for diagnostics: the world validator, state snapshots, size and resource
 * reports, exit attribution and the debugger record.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "lxp_internal.h"
#include "lxp_run_internal.h"
#include "../framework/lxp_coord_fixture.h"
#include "../framework/lxp_mock_engine.h"

/* A debugger finds each slot's program in g_lxp_dbg (lxp/lxp_debug.h): publishing an image
 * records its name and bases, and the record clears when the slot's process goes away,
 * whether its launch is aborted or it exits. */
static void test_debug_record_follows_slot_program(void **state)
{
	(void)state;
	struct image_txn tx;
	prepare_mock_image_txn(&tx, 1, 1);
	strcpy(tx.proc.comm, "dbgdemo");
	tx.debug.text_base = 0x1000u;
	tx.debug.entry = 0x1041u;
	assert_int_equal(lxp_image_txn_publish(&tx), LXP_OK);
	assert_string_equal(g_lxp_dbg[1].comm, "dbgdemo");
	assert_int_equal(g_lxp_dbg[1].text_base, 0x1000u);
	assert_int_equal(g_lxp_dbg[1].entry, 0x1041u);
	assert_int_equal(lxp_image_txn_abort(&tx), LXP_OK);
	assert_null(g_lxp_dbg[1].comm);

	make_valid_running_slot(0, 0);
	g_lxp_dbg[0].comm = g_lxp_rt.slots[0].proc.comm;
	assert_int_equal(lxp_intent_exit(&g_lxp_rt.slots[0].proc, 0), LXP_OK);
	lxp_primary_slot_clear(0);
	(void)lxp_handle_exit(0);
	assert_null(g_lxp_dbg[0].comm);
}

static void test_world_diagnostics_snapshot_current_states(void **state)
{
	(void)state;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(error.issue, LXP_DIAG_OK);

	make_valid_running_slot(0, 0);
	g_lxp_rt.diag.native_known = 1;
	g_lxp_rt.diag.native_present[0] = 1;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	lxp_diag_slot_t slot;
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.abi_version, LXP_DIAG_ABI_VERSION);
	assert_int_equal(slot.struct_size, sizeof(slot));
	assert_int_equal(slot.generation, g_lxp_rt.slots[0].generation);
	assert_int_equal(slot.host_state, LXP_DIAG_HOST_RUNNING);
	assert_int_equal(slot.task_status, LXP_DIAG_TASK_LIVE);
	assert_int_equal(slot.runnable, 1);
	assert_int_equal(slot.native_task_known, 1);
	assert_int_equal(slot.native_task_present, 1);
	assert_int_equal(slot.region, 0);
	assert_int_equal(slot.region_refs, 1);
	assert_int_equal(slot.mm_refs, 1);
	assert_int_equal(slot.intent_mask, LXP_DIAG_INTENT_NONE);
	assert_int_equal(slot.wait_mask, LXP_DIAG_WAIT_NONE);

	lxp_slot_set_host_state(0, SLOT_PARKED);
	g_lxp_rt.slots[0].runnable = 0;
	g_lxp_rt.slots[0].proc.wait.kind = LXP_WAIT_PIPE;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.host_state, LXP_DIAG_HOST_PARKED);
	assert_int_equal(slot.wait_mask, LXP_DIAG_WAIT_PIPE);
	assert_int_equal(slot.native_task_known, 0);
	assert_int_equal(slot.native_task_present, 0);

	/* A successful census is usable only for the lifecycle epoch it observed.
	 * This mirrors refresh_stats() without invoking the mock thread provider. */
	g_lxp_rt.diag.native_epoch = g_lxp_rt.diag.lifecycle_epoch;
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.native_task_known, 1);
	assert_int_equal(slot.native_task_present, 1);

	g_lxp_rt.slots[0].proc.stopped = 1;
	g_lxp_rt.slots[0].proc.stop_kind = LXP_STOP_PARKED;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.task_status, LXP_DIAG_TASK_STOPPED);

	g_lxp_rt.slots[0].proc.stopped = 0;
	g_lxp_rt.slots[0].proc.wait.kind = LXP_WAIT_NONE;
	g_lxp_rt.slots[0].proc.intent.kind = LXP_INTENT_FORK;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.intent_mask, LXP_DIAG_INTENT_FORK);
	g_lxp_rt.slots[0].proc.intent.kind = LXP_INTENT_EXEC;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	g_lxp_rt.slots[0].proc.intent.kind = LXP_INTENT_NONE;
	g_lxp_sig_save[0].depth = 1;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.signal_depth, 1);

	g_lxp_rt.slots[0].proc.intent.kind = LXP_INTENT_EXIT;
	lxp_slot_set_host_state(0, SLOT_DEAD);
	g_lxp_rt.diag.native_present[0] = 0;
	g_lxp_rt.diag.native_epoch = g_lxp_rt.diag.lifecycle_epoch;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.task_status, LXP_DIAG_TASK_ZOMBIE);

	lxp_diag_region_t region;
	assert_int_equal(lxp_diag_region_snapshot(0, &region), LXP_OK);
	assert_int_equal(region.abi_version, LXP_DIAG_ABI_VERSION);
	assert_int_equal(region.owner_slot, -1);
	assert_int_equal(region.refs, 1);
	assert_int_equal(region.live_users, 1);
	assert_true(region.generation != 0);
	assert_int_equal(lxp_diag_slot_snapshot(-1, &slot), -LXP_EINVAL);
	assert_int_equal(lxp_diag_region_snapshot(LXP_NREG, &region), -LXP_EINVAL);
}

static void test_world_validator_reports_conflicting_waits(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	g_lxp_rt.slots[0].proc.wait.kind = LXP_WAIT_COUNT;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_MULTIPLE_WAITS);
	assert_int_equal(error.slot, 0);
	assert_int_equal(error.actual, UINT32_MAX);
}

static void test_world_validator_reports_stale_mailbox(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	g_lxp_rt.slots[0].deferred.owner = lxp_slot_ref_at(0);
	g_lxp_rt.slots[0].deferred.owner.generation++;
	lxp_deferred_state_store(0, DEFER_READY);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_DEFERRED_GENERATION_STALE);
	assert_int_equal(error.slot, 0);
	assert_int_equal(error.expected, g_lxp_rt.slots[0].generation);
}

static void test_world_validator_reports_region_ownership_drift(void **state)
{
	(void)state;
	g_lxp_rt.regions[2].lease_owner = (lxp_slot_ref_t){.index = 3, .generation = 1};
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_REGION_OWNER_WITHOUT_REFS);
	assert_int_equal(error.slot, 3);
	assert_int_equal(error.region, 2);
}

static void test_world_validator_rejects_stale_region_capabilities(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	g_lxp_rt.slots[0].proc.mm->region.generation++;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_LIVE_TASK_STALE_REGION_REF);
	assert_int_equal(error.slot, 0);
	assert_int_equal(error.region, 0);
}

static void test_world_validator_rejects_stale_region_leases(void **state)
{
	(void)state;
	lxp_deferred_slot_reassign(0);
	lxp_region_ref_t lease = lxp_region_reserve(1, lxp_slot_ref_at(0));
	assert_int_equal(lease.index, 1);
	lxp_deferred_slot_reassign(0);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_REGION_LEASE_STALE);
	assert_int_equal(error.slot, 0);
	assert_int_equal(error.region, 1);
}

static void test_world_validator_reports_resource_refcount_drift(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	make_valid_running_slot(1, 1);
	assert_int_equal(lxp_region_put(lxp_region_ref_at(1)), LXP_OK);
	g_lxp_rt.slots[1].proc.mm = g_lxp_rt.slots[0].proc.mm;
	g_lxp_rt.slots[1].proc.mm->region = lxp_region_ref_at(0);
	assert_int_equal(lxp_region_get(g_lxp_rt.slots[1].proc.mm->region), LXP_OK);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL);
	assert_int_equal(error.actual, 1);
	assert_int_equal(error.expected, 2);
}

static void test_world_validator_checkpoints_latch_first_failure(void **state)
{
	(void)state;
	lxp_diag_checkpoint();
	g_lxp_rt.regions[0].lease_owner = (lxp_slot_ref_t){.index = 0, .generation = 1};
	lxp_diag_checkpoint();
	g_lxp_rt.regions[1].lease_owner = (lxp_slot_ref_t){.index = 1, .generation = 1};
	lxp_diag_checkpoint();

	lxp_diag_health_t health;
	lxp_diag_health(&health);
	assert_int_equal(health.abi_version, LXP_DIAG_ABI_VERSION);
	assert_int_equal(health.checks, 3);
	assert_int_equal(health.failures, 2);
	assert_int_equal(health.first_error.issue, LXP_DIAG_REGION_OWNER_WITHOUT_REFS);
	assert_int_equal(health.first_error.region, 0);
	assert_int_equal(health.last_error.region, 0);
}

static void test_world_diagnostic_size_report_matches_compiled_objects(void **state)
{
	(void)state;
	lxp_diag_size_report_t sizes;
	lxp_diag_size_report(&sizes);
	assert_int_equal(sizes.abi_version, LXP_DIAG_ABI_VERSION);
	assert_int_equal(sizes.struct_size, sizeof(sizes));
	assert_int_equal(sizes.slots, LXP_NSLOT);
	assert_int_equal(sizes.regions, LXP_NREG);
	assert_int_equal(sizes.proc, sizeof(lxp_proc_t));
	assert_int_equal(sizes.mm, sizeof(lxp_mm_t));
	assert_int_equal(sizes.files, sizeof(lxp_files_t));
	assert_int_equal(sizes.fs, sizeof(lxp_fs_context_t));
	assert_int_equal(sizes.sighand, sizeof(lxp_sighand_t));
	assert_int_equal(sizes.thread_group, sizeof(lxp_thread_group_t));
	assert_int_equal(sizes.arena, sizeof(lxp_arena_t));
	assert_int_equal(sizes.exec_capture, sizeof(lxp_exec_capture_t));
	assert_int_equal(sizes.resume_context, sizeof(struct lxp_resume_ctx));
	assert_int_equal(sizes.deferred_request, sizeof(struct deferred_req));
	assert_int_equal(sizes.signal_save_stack, sizeof(struct sig_save_stack_s));
	assert_int_equal(sizes.vfork_guard, sizeof(struct vfork_snapshot_guard));
	assert_int_equal(sizes.debug_record, sizeof(lxp_debug_image_t));
	assert_int_equal(sizes.slot_table, sizeof(*g_lxp_rt.slots) * LXP_NSLOT);
	assert_true(sizes.per_slot_core > sizes.proc);
	assert_true(sizes.coordinator_static > sizes.slot_table);
	static const char *const host_names[LXP_DIAG_HOST_COUNT] = {
		"free",	    "starting", "running", "parking", "parked",
		"resuming", "exiting",	"dead",	   "failed",
	};
	static const char *const task_names[LXP_DIAG_TASK_COUNT] = {
		"free",
		"live",
		"stopped",
		"zombie",
	};
	static const char *const issue_names[LXP_DIAG_ISSUE_COUNT] = {
		"ok",
		"bad-slot",
		"bad-region",
		"region-owner-without-refs",
		"region-refs-without-owner",
		"region-refs-without-generation",
		"live-task-without-resources",
		"live-task-bad-region",
		"live-task-without-region-ref",
		"resource-refcount-too-small",
		"free-task-runnable",
		"runnable-host-state-mismatch",
		"parked-task-runnable",
		"native-task-missing",
		"native-task-leaked",
		"host-state-without-generation",
		"deferred-state-invalid",
		"deferred-generation-stale",
		"multiple-intents",
		"multiple-waits",
		"region-lease-stale",
		"live-task-stale-region-ref",
		"guest-view-leaked",
	};
	for (unsigned i = 0; i < LXP_DIAG_HOST_COUNT; i++)
		assert_string_equal(lxp_diag_host_state_name(i), host_names[i]);
	for (unsigned i = 0; i < LXP_DIAG_TASK_COUNT; i++)
		assert_string_equal(lxp_diag_task_status_name(i), task_names[i]);
	for (unsigned i = 0; i < LXP_DIAG_ISSUE_COUNT; i++)
		assert_string_equal(lxp_diag_issue_name(i), issue_names[i]);
	assert_string_equal(lxp_diag_host_state_name(LXP_DIAG_HOST_COUNT), "invalid");
	assert_string_equal(lxp_diag_task_status_name(LXP_DIAG_TASK_COUNT), "invalid");
	assert_string_equal(lxp_diag_issue_name(LXP_DIAG_ISSUE_COUNT), "invalid");
}

static void test_resource_stats_track_slots_and_reserved_regions(void **state)
{
	(void)state;
	lxp_trap_publish(1);
	lxp_deferred_slot_reassign(0);
	lxp_deferred_slot_reassign(1);
	lxp_region_ref_t shared = lxp_region_reserve(0, lxp_slot_ref_at(0));
	lxp_region_ref_t reserved = lxp_region_reserve(2, lxp_slot_ref_at(1));
	assert_int_equal(shared.index, 0);
	assert_int_equal(reserved.index, 2);
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.mm->region = shared;
	g_lxp_rt.slots[1].proc.alive = 1;
	g_lxp_rt.slots[1].proc.mm->region = shared; /* thread shares region 0 but consumes a slot */

	struct lxp_resource_stats resources;
	lxp_get_resource_stats(&resources);
	assert_int_equal(resources.slots_total, LXP_NSLOT);
	assert_int_equal(resources.slots_free, LXP_NSLOT - 2);
	assert_int_equal(resources.processes, 2);
	assert_int_equal(resources.regions_total, LXP_NREG);
	assert_int_equal(resources.regions_free, LXP_NREG - 2);
	assert_int_equal(resources.program_region_bytes, LXP_PROG_REGION_SIZE);
	assert_int_equal(resources.dynamic_pool_bytes, sizeof(g_mock_dyn_pools[0]));
	uint64_t region_bytes = LXP_PROG_REGION_SIZE + sizeof(g_mock_dyn_pools[0]);
	assert_int_equal(resources.total_bytes, region_bytes * LXP_NREG);
	assert_int_equal(resources.free_bytes, region_bytes * (LXP_NREG - 2));
	assert_int_equal(resources.available_bytes, region_bytes * (LXP_NREG - 2));

	/* Clone-style processes can share a region but still exhaust process slots. */
	for (int s = 2; s < LXP_NSLOT; s++) {
		g_lxp_rt.slots[s].proc.alive = 1;
		g_lxp_rt.slots[s].proc.mm->region.index = 0;
	}
	lxp_get_resource_stats(&resources);
	assert_int_equal(resources.slots_free, 0);
	assert_int_equal(resources.processes, LXP_NSLOT);
	assert_int_equal(resources.regions_free, LXP_NREG - 2);
	assert_int_equal(resources.available_bytes, 0);
}

static void test_notify_guest_exit_preserves_attribution(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[3].proc;
	p->pid = 27;
	p->group->ppid = 7;
	p->exit_status = 139;
	p->exit_reason = LXP_EXIT_REASON_MEMORY_FAULT;
	p->exit_signal = LXP_SIGSEGV;
	p->exit_detail = 0x92;
	p->exit_address = 0x4c;
	memcpy(p->comm, "sigctx", 7);
	g_lxp_rt.cfg = &g_mock_cfg;

	lxp_notify_guest_exit(3, p);

	assert_int_equal(g_mock.exit_notify_calls, 1);
	assert_int_equal(g_mock.exit_info.slot, 3);
	assert_int_equal(g_mock.exit_info.pid, 27);
	assert_int_equal(g_mock.exit_info.ppid, 7);
	assert_int_equal(g_mock.exit_info.status, 139);
	assert_int_equal(g_mock.exit_info.reason, LXP_EXIT_REASON_MEMORY_FAULT);
	assert_int_equal(g_mock.exit_info.signal, LXP_SIGSEGV);
	assert_int_equal(g_mock.exit_info.detail, 0x92);
	assert_int_equal(g_mock.exit_info.address, 0x4c);
	assert_string_equal(g_mock.exit_info.comm, "sigctx");
}

int test_coord_diag_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_debug_record_follows_slot_program, reset_state),
		cmocka_unit_test_setup(test_world_diagnostics_snapshot_current_states, reset_state),
		cmocka_unit_test_setup(test_world_validator_reports_conflicting_waits, reset_state),
		cmocka_unit_test_setup(test_world_validator_reports_stale_mailbox, reset_state),
		cmocka_unit_test_setup(test_world_validator_reports_region_ownership_drift,
				       reset_state),
		cmocka_unit_test_setup(test_world_validator_rejects_stale_region_capabilities,
				       reset_state),
		cmocka_unit_test_setup(test_world_validator_rejects_stale_region_leases,
				       reset_state),
		cmocka_unit_test_setup(test_world_validator_reports_resource_refcount_drift,
				       reset_state),
		cmocka_unit_test_setup(test_world_validator_checkpoints_latch_first_failure,
				       reset_state),
		cmocka_unit_test_setup(test_world_diagnostic_size_report_matches_compiled_objects,
				       reset_state),
		cmocka_unit_test_setup(test_resource_stats_track_slots_and_reserved_regions,
				       reset_state),
		cmocka_unit_test_setup(test_notify_guest_exit_preserves_attribution, reset_state),
	};
	return cmocka_run_group_tests_name("coordinator: diagnostics", tests, NULL, NULL);
}
