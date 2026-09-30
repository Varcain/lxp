/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Shared set-up for the coordinator tests; see lxp_coord_fixture.h.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "pty/lxp_pty.h"
#include "fs/lxp_pipe.h"
#include "lxp_internal.h"
#include "lxp_run_internal.h"
#include "lxp_coord_fixture.h"

int reset_state(void **state)
{
	(void)state;
	lxp_proc_runtime_reset();
	lxp_fd_runtime_reset();
	lxp_pipe_runtime_reset();
#if LXP_ENABLE_PTY
	lxp_pty_runtime_reset();
#endif
	memset(g_lxp_rt.slots, 0, sizeof(*g_lxp_rt.slots) * LXP_NSLOT);
	memset(g_mock_arenas, 0, sizeof(g_mock_arenas));
	for (int s = 0; s < LXP_NSLOT; s++) {
		assert_int_equal(lxp_proc_init(&g_lxp_rt.slots[s].proc, &g_mock_arenas[s], 0),
				 LXP_OK);
		g_lxp_rt.slots[s].proc.alive = 0;
	}
	lxp_primary_events_reset();
	lxp_blocked_fair_reset();
	memset(g_lxp_rt.regions, 0, sizeof(*g_lxp_rt.regions) * LXP_NREG);
	memset(g_lxp_rt.vfork_guard, 0, sizeof(*g_lxp_rt.vfork_guard) * LXP_NSLOT);
	memset(g_lxp_sig_save, 0, sizeof(g_lxp_sig_save));
	memset(g_lxp_rt.diag.native_present, 0, LXP_NSLOT);
	g_lxp_rt.diag.native_known = 0;
	g_lxp_rt.diag.lifecycle_epoch = 0;
	g_lxp_rt.diag.native_epoch = 0;
	lxp_diag_reset_health();
	memset(g_mock_regions, 0, sizeof(g_mock_regions));
	memset(g_mock_dyn_pools, 0, sizeof(g_mock_dyn_pools));
	memset(&g_mock, 0, sizeof(g_mock));
	g_mock.map_fail_slot = -1;
	g_mock.abort_fail_slot = -1;
	g_mock.observe_wait_slot = -1;
	for (int r = 0; r < LXP_NREG; r++)
		g_lxp_rt.regions[r].lease_owner = lxp_slot_ref_none();
	for (int s = 0; s < LXP_NSLOT; s++)
		lxp_vfork_guard_reset(s);
	lxp_os_publish(&g_mock_eng);
	g_lxp_rt.cfg = NULL;
	g_lxp_lifecycle_failpoint = LXP_FAIL_NONE;
	lxp_trap_publish(0);
	lxp_console_reset();
	lxp_providers_publish(g_test_net_ops, NULL, NULL, NULL);
	return 0;
}

void make_valid_running_slot(int slot, int region)
{
	deferred_slot_reassign(slot);
	lxp_slot_ref_t owner = slot_ref_at(slot);
	lxp_region_ref_t region_ref = region_reserve(region, owner);
	assert_int_equal(region_ref.index, region);
	assert_int_equal(lxp_region_commit_address_space(region_ref, owner), LXP_OK);
	g_lxp_rt.slots[slot].proc.alive = 1;
	g_lxp_rt.slots[slot].proc.pid = slot + 1;
	g_lxp_rt.slots[slot].proc.group->tgid = slot + 1;
	g_lxp_rt.slots[slot].proc.mm->region = region_ref;
	g_lxp_rt.slots[slot].proc.snapshot = lxp_region_ref_none();
	g_lxp_rt.slots[slot].proc.vfork_parent = lxp_slot_ref_none();
	g_lxp_rt.slots[slot].host_state = SLOT_RUNNING;
	g_lxp_rt.slots[slot].runnable = 1;
}

void prepare_mock_image_txn(struct image_txn *tx, int slot, int region)
{
	lxp_proc_child_discard(&g_lxp_rt.slots[slot].proc);
	deferred_slot_reassign(slot);
	lxp_slot_ref_t owner = slot_ref_at(slot);
	lxp_region_ref_t region_ref = region_reserve(region, owner);
	assert_int_equal(region_ref.index, region);
	image_txn_init(tx, slot, region_ref, owner);
	assert_int_equal(lxp_proc_init(&tx->proc, &g_mock_arenas[slot], 0), LXP_OK);
	tx->proc.alive = 1;
	tx->proc.mm->region = region_ref;
	tx->prepared = 1;
}

void set_child_wait(lxp_proc_t *p, int pid, int options, int *status)
{
	p->wait = (lxp_wait_t){
		.kind = LXP_WAIT_CHILD,
		.data.child.pid = pid,
		.data.child.options = options,
		.data.child.status = (uintptr_t)status,
	};
}
