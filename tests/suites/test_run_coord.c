/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Host unit tests for the run-loop coordinator. The coordinator is excluded
 * from the main test binary because its 32-bit-target pointer casts warn on a
 * 64-bit host and its OS-service symbols clash with tests/stub_lnx_run.c.
 *
 * This dedicated binary links the coordinator exactly like production and
 * reaches its records only through a test-only fixture bridge. Coordinator
 * policy modules are also linked as their production translation units and
 * driven against a mock engine with no guest threads.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "lxp/lxp_syscall.h"
#include "lxp/lxp_port_posix.h"
#include "lxp_internal.h"
#include "lxp_provider.h"
#include "run/lxp_exec_private.h"
#include "run/lxp_fork_private.h"
#include "run/lxp_image.h"
#include "run/lxp_runtime_test.h"

#define TEST_RUNTIME (lxp_runtime_test_fixture())
#define g_lxp_slots (TEST_RUNTIME->slots)
#define g_regions (TEST_RUNTIME->regions)
#define g_vfork_guard (TEST_RUNTIME->vfork_guards)
#define g_cfg (*TEST_RUNTIME->config)
#define g_eng (*TEST_RUNTIME->engine)
#define g_lxp_rootfs_lo (*TEST_RUNTIME->rootfs_lo)
#define g_lxp_rootfs_hi (*TEST_RUNTIME->rootfs_hi)
#define g_diag_native_known (*TEST_RUNTIME->diag_native_known)
#define g_diag_native_present (TEST_RUNTIME->diag_native_present)
#define g_diag_lifecycle_epoch (*TEST_RUNTIME->diag_lifecycle_epoch)
#define g_diag_native_epoch (*TEST_RUNTIME->diag_native_epoch)
#define g_pending_sig (*TEST_RUNTIME->pending_signal)
#define g_tty_isig (*TEST_RUNTIME->tty_isig)
#define g_tty_icrnl (*TEST_RUNTIME->tty_icrnl)
#define g_lifecycle_failpoint (*TEST_RUNTIME->lifecycle_failpoint)
#define region_ref_at lxp_test_region_ref_at
#define region_commit_address_space lxp_test_region_commit_address_space
#define coordinator_wait_timeout lxp_test_coordinator_wait_timeout
#define coordinator_teardown_all lxp_test_coordinator_teardown_all
#define futex_has_corunner lxp_test_futex_has_corunner
#define lxp_diag_reset_health lxp_test_diag_reset_health
#define lxp_diag_checkpoint lxp_test_diag_checkpoint
#define lxp_trap_publish lxp_test_trap_publish
#define deferred_state_store lxp_test_deferred_state_store
#define os_ops_valid lxp_test_os_ops_valid
#define run_config_valid lxp_test_run_config_valid
#define lxp_futex lxp_test_futex
#define lxp_dispatch lxp_test_dispatch

static const lxp_net_ops_t *g_test_net_ops;

/* ---- mock engine ------------------------------------------------------------ */
static struct {
	int launch_calls;
	int launch_sidx;
	uint32_t launch_generation;
	uint8_t launch_observed_runnable;
	uint8_t launch_observed_host_state;
	int resume_calls;
	int resume_sidx;
	uint32_t resume_generation;
	lxp_spawn_resume_mode_t resume_mode;
	uint8_t resume_observed_runnable;
	uint8_t resume_observed_host_state;
	long resume_r0;
	uint32_t resume_xpsr;
	struct lxp_fp_context resume_fp;
	int resume_order[LXP_NSLOT];
	long resume_results[LXP_NSLOT];
	int resume_failures;
	int abort_calls;
	int abort_sidx;
	uint32_t abort_generation;
	int abort_failures;
	int abort_fail_slot;
	int park_prepare_calls;
	int park_calls;
	int park_sidx;
	uint32_t park_generation;
	int park_failures;
	int event_posts;
	int event_wait_calls;
	int observe_wait_slot;
	int wait_observed_alive;
	unsigned wait_observed_region_refs;
	int wait_observed_trap_active;
	int cache_clean_calls;
	const void *cache_clean_base[8];
	size_t cache_clean_len[8];
	int cache_invalidate_calls;
	const void *cache_invalidate_base[8];
	size_t cache_invalidate_len[8];
	int coord_map_calls;
	int coord_map_region;
	int exit_notify_calls;
	lxp_guest_exit_info_t exit_info;
	int map_calls;
	int map_sidx[16];
	uintptr_t map_addr[16];
	size_t map_size[16];
	unsigned map_attrs[16];
	int map_fail_slot;
	int prepare_calls;
	int prepare_result;
	int teardown_calls;
} g_mock;

static uint8_t g_mock_regions[LXP_NREG][256];
static uint8_t g_mock_dyn_pools[LXP_NREG][64];
static lxp_exec_capture_t g_mock_exec_captures[LXP_NSLOT];
static lxp_arena_t g_mock_arenas[LXP_NSLOT];
static uint8_t g_mock_exec_stage[128];

static uint8_t *mock_region(int ridx)
{
	return g_mock_regions[ridx];
}
static uint8_t *mock_dyn_pool(int ridx, size_t *size)
{
	if (size)
		*size = sizeof(g_mock_dyn_pools[ridx]);
	return g_mock_dyn_pools[ridx];
}
static lxp_exec_capture_t *mock_exec_capture(int sidx)
{
	return (sidx >= 0 && sidx < LXP_NSLOT) ? &g_mock_exec_captures[sidx] : NULL;
}
static uint8_t *mock_exec_stage(size_t *cap)
{
	if (cap)
		*cap = sizeof(g_mock_exec_stage);
	return g_mock_exec_stage;
}
static void mock_cache_clean(const void *base, size_t len)
{
	int i = g_mock.cache_clean_calls++;
	if (i < 8) {
		g_mock.cache_clean_base[i] = base;
		g_mock.cache_clean_len[i] = len;
	}
}
static void mock_cache_invalidate(const void *base, size_t len)
{
	int i = g_mock.cache_invalidate_calls++;
	if (i < 8) {
		g_mock.cache_invalidate_base[i] = base;
		g_mock.cache_invalidate_len[i] = len;
	}
}
static void mock_coord_map(int region)
{
	g_mock.coord_map_calls++;
	g_mock.coord_map_region = region;
}
static int mock_spawn_launch(int sidx, uint32_t generation, int ridx, const lxp_flat_t *prog,
			     void *entry, void *sp, void *stack_lo)
{
	(void)ridx;
	(void)prog;
	(void)entry;
	(void)sp;
	(void)stack_lo;
	g_mock.launch_calls++;
	g_mock.launch_sidx = sidx;
	g_mock.launch_generation = generation;
	g_mock.launch_observed_runnable =
		(uint8_t)lxp_slot_ref_is_runnable((lxp_slot_ref_t){
			.index = (int16_t)sidx,
			.generation = generation,
		});
	g_mock.launch_observed_host_state = lxp_slot_host_state(sidx);
	return LXP_OK;
}
static int mock_spawn_resume(int sidx, uint32_t generation, int ridx,
			     lxp_spawn_resume_mode_t mode,
			     const struct lxp_resume_ctx *c, long r0)
{
	(void)ridx;
	g_mock.resume_calls++;
	g_mock.resume_sidx = sidx;
	g_mock.resume_generation = generation;
	g_mock.resume_mode = mode;
	g_mock.resume_observed_runnable =
		(uint8_t)lxp_slot_ref_is_runnable((lxp_slot_ref_t){
			.index = (int16_t)sidx,
			.generation = generation,
		});
	g_mock.resume_observed_host_state = lxp_slot_host_state(sidx);
	g_mock.resume_r0 = r0;
	g_mock.resume_xpsr = c->xpsr;
	g_mock.resume_fp = c->fp;
	if (g_mock.resume_calls <= LXP_NSLOT) {
		g_mock.resume_order[g_mock.resume_calls - 1] = sidx;
		g_mock.resume_results[g_mock.resume_calls - 1] = r0;
	}
	if (g_mock.resume_failures > 0) {
		g_mock.resume_failures--;
		return -LXP_EIO;
	}
	return LXP_OK;
}
static int mock_abort_slot(int sidx, uint32_t generation)
{
	(void)generation;
	g_mock.abort_calls++;
	g_mock.abort_sidx = sidx;
	g_mock.abort_generation = generation;
	if (g_mock.abort_failures > 0 &&
	    (g_mock.abort_fail_slot < 0 || g_mock.abort_fail_slot == sidx)) {
		g_mock.abort_failures--;
		return -LXP_EIO;
	}
	return LXP_OK;
}
static void *mock_park_prepare(int sidx, uint32_t generation, const struct lxp_resume_ctx *c)
{
	(void)sidx;
	(void)generation;
	g_mock.park_prepare_calls++;
	return (void *)c;
}
static int mock_park_slot(int sidx, uint32_t generation)
{
	(void)generation;
	g_mock.park_calls++;
	g_mock.park_sidx = sidx;
	g_mock.park_generation = generation;
	if (g_mock.park_failures > 0) {
		g_mock.park_failures--;
		return -LXP_EIO;
	}
	return LXP_OK;
}
static void mock_event_post(void)
{
	g_mock.event_posts++;
}
static void mock_event_wait(unsigned ms)
{
	(void)ms;
	g_mock.event_wait_calls++;
	if (g_mock.observe_wait_slot >= 0) {
		lxp_proc_t *proc = lxp_slot_proc(g_mock.observe_wait_slot);
		g_mock.wait_observed_alive = proc && proc->alive;
		g_mock.wait_observed_region_refs =
			proc && proc->mm && proc->mm->region.index >= 0
				? g_regions[proc->mm->region.index].refs
				: 0;
		g_mock.wait_observed_trap_active = lxp_trap_active();
	}
}
static void mock_crit(void)
{
}
static int mock_time(uint64_t *out)
{
	*out = 1;
	return LXP_OK;
}
static int mock_random_fill(void *buf, size_t len)
{
	memset(buf, 0x5a, len);
	return LXP_OK;
}
static int mock_map_device(int sidx, uintptr_t addr, size_t size, unsigned attrs)
{
	int i = g_mock.map_calls++;
	if (i < 16) {
		g_mock.map_sidx[i] = sidx;
		g_mock.map_addr[i] = addr;
		g_mock.map_size[i] = size;
		g_mock.map_attrs[i] = attrs;
	}
	if (size && g_mock.map_fail_slot == sidx) {
		g_mock.map_fail_slot = -1;
		return -1;
	}
	return 0;
}

static int mock_validate_memory_model(lxp_cpu_memory_model_t declared)
{
	return declared == LXP_CPU_MEM_UNCACHED ? LXP_OK : LXP_ERR_INVALID_PARAM;
}
static int mock_prepare(void)
{
	g_mock.prepare_calls++;
	return g_mock.prepare_result;
}
static void mock_teardown(void)
{
	g_mock.teardown_calls++;
}
static const char *mock_system_version(void)
{
	return "MockRTOS 9.8.7 ove-fedcba9 lxp-7654321";
}

static const lxp_os_ops_t g_mock_eng = {
	.abi_version = LXP_OS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_os_ops_t),
	.prepare = mock_prepare,
	.teardown = mock_teardown,
	.region = mock_region,
	.dyn_pool = mock_dyn_pool,
	.exec_capture = mock_exec_capture,
	.exec_stage = mock_exec_stage,
	.spawn_launch = mock_spawn_launch,
	.spawn_resume = mock_spawn_resume,
	.abort_slot = mock_abort_slot,
	.park_prepare = mock_park_prepare,
	.park_slot = mock_park_slot,
	.crit_enter = mock_crit,
	.crit_exit = mock_crit,
	.event_post = mock_event_post,
	.event_wait = mock_event_wait,
	.map_device = mock_map_device,
	.time_us = mock_time,
	.time_ns = mock_time,
	.random_fill = mock_random_fill,
	.cache_clean = mock_cache_clean,
	.cache_invalidate = mock_cache_invalidate,
	.coord_map = mock_coord_map,
	.cpu_memory_model = LXP_CPU_MEM_UNCACHED,
	.validate_memory_model = mock_validate_memory_model,
	.system_version = mock_system_version,
};

static void mock_on_guest_exit(const lxp_guest_exit_info_t *info)
{
	g_mock.exit_notify_calls++;
	g_mock.exit_info = *info;
}

static const lxp_run_config_t g_mock_cfg = {
	.on_guest_exit = mock_on_guest_exit,
};

static int reset_state(void **state)
{
	(void)state;
	lxp_proc_runtime_reset();
	lxp_fd_runtime_reset();
	memset(g_lxp_slots, 0, sizeof(*g_lxp_slots) * LXP_NSLOT);
	memset(g_mock_arenas, 0, sizeof(g_mock_arenas));
	for (int s = 0; s < LXP_NSLOT; s++) {
		assert_int_equal(lxp_proc_init(&g_lxp_slots[s].proc, &g_mock_arenas[s], 0), LXP_OK);
		g_lxp_slots[s].proc.alive = 0;
	}
	lxp_primary_events_reset();
	memset(g_regions, 0, sizeof(*g_regions) * LXP_NREG);
	memset(g_vfork_guard, 0, sizeof(*g_vfork_guard) * LXP_NSLOT);
	memset(g_sig_save, 0, sizeof(g_sig_save));
	memset(g_diag_native_present, 0, LXP_NSLOT);
	g_diag_native_known = 0;
	g_diag_lifecycle_epoch = 0;
	g_diag_native_epoch = 0;
	lxp_diag_reset_health();
	memset(g_mock_regions, 0, sizeof(g_mock_regions));
	memset(g_mock_dyn_pools, 0, sizeof(g_mock_dyn_pools));
	memset(&g_mock, 0, sizeof(g_mock));
	g_mock.map_fail_slot = -1;
	g_mock.abort_fail_slot = -1;
	g_mock.observe_wait_slot = -1;
	for (int r = 0; r < LXP_NREG; r++)
		g_regions[r].lease_owner = lxp_slot_ref_none();
	for (int s = 0; s < LXP_NSLOT; s++)
		fork_child_guard_reset(s);
	lxp_console_set_fg_pgrp(0);
	g_eng = &g_mock_eng;
	g_cfg = NULL;
	g_lifecycle_failpoint = LXP_FAIL_NONE;
	lxp_trap_publish(0);
	g_pending_sig = 0;
	g_tty_isig = 1;
	g_tty_icrnl = 1;
	lxp_providers_publish(g_test_net_ops, NULL);
	return 0;
}

static void make_valid_running_slot(int slot, int region)
{
	deferred_slot_reassign(slot);
	lxp_slot_ref_t owner = slot_ref_at(slot);
	lxp_region_ref_t region_ref = region_reserve(region, owner);
	assert_int_equal(region_ref.index, region);
	assert_int_equal(region_commit_address_space(region_ref, owner), LXP_OK);
	g_lxp_slots[slot].proc.alive = 1;
	g_lxp_slots[slot].proc.pid = slot + 1;
	g_lxp_slots[slot].proc.group->tgid = slot + 1;
	g_lxp_slots[slot].proc.mm->region = region_ref;
	g_lxp_slots[slot].proc.snapshot = lxp_region_ref_none();
	g_lxp_slots[slot].proc.vfork_parent = lxp_slot_ref_none();
	g_lxp_slots[slot].host_state = SLOT_RUNNING;
	g_lxp_slots[slot].runnable = 1;
}

static lxp_region_ref_t make_address_space_region(int region, int slot)
{
	lxp_slot_ref_t owner = slot_ref_at(slot);
	lxp_region_ref_t ref = region_reserve(region, owner);
	assert_int_equal(ref.index, region);
	assert_int_equal(region_commit_address_space(ref, owner), LXP_OK);
	return ref;
}

static long child_test_write(void *ctx, int fd, const void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	(void)buf;
	return (long)len;
}

static long child_test_read(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	(void)buf;
	return (long)len;
}

static int child_test_poll(void *ctx)
{
	return ctx != NULL;
}

static void prepare_child_test_parent(lxp_proc_t *parent)
{
	static const lxp_file_t rootfs[] = {
		{.path = "/bin/parent"},
	};
	parent->write_fn = child_test_write;
	parent->read_fn = child_test_read;
	parent->console_poll = child_test_poll;
	parent->io_ctx = parent;
	parent->fs = rootfs;
	parent->fs_count = 1;
	memcpy(parent->comm, "parent-image", sizeof("parent-image"));
	parent->sig_blocked = UINT64_C(0x1122334455667788);
	parent->exec_file_idx = 17;
	parent->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	parent->is_fdpic = 1;

	/* Poison every non-inherited family. A constructor that starts copying the
	 * whole task again makes this table fail immediately. */
	parent->intent.kind = LXP_INTENT_FORK;
	parent->intent.data.fork.flags = UINT32_MAX;
	parent->intent.data.fork.child_stack = 0x1234u;
	parent->exit_status = 23;
	parent->stopped = 1;
	parent->stop_kind = LXP_STOP_PARKED;
	parent->pending_sigs = UINT64_C(0xff);
	parent->sigsuspend_saved_mask = UINT64_C(0xa5);
	parent->sigsuspend_active = 1;
	parent->wait.kind = LXP_WAIT_NETFS;
	parent->wait.op = 2;
	parent->wait.data.io.request = 7;
	parent->alarm_deadline_us = 123;
	parent->alarm_interval_us = 456;
}

static void assert_child_local_state(const lxp_proc_t *child, int child_pid)
{
	assert_int_equal(child->pid, child_pid);
	assert_ptr_equal(child->write_fn, child_test_write);
	assert_ptr_equal(child->read_fn, child_test_read);
	assert_ptr_equal(child->console_poll, child_test_poll);
	assert_non_null(child->io_ctx);
	assert_non_null(child->fs);
	assert_int_equal(child->fs_count, 1);
	assert_string_equal(child->comm, "parent-image");
	assert_int_equal(child->sig_blocked, UINT64_C(0x1122334455667788));
	assert_int_equal(child->exec_file_idx, 17);
	assert_int_equal(child->stack_lo, (uintptr_t)g_mock_regions[0] + 128u);
	assert_int_equal(child->is_fdpic, 1);

	assert_false(child->alive);
	assert_int_equal(child->intent.kind, LXP_INTENT_NONE);
	assert_false(child->stopped);
	assert_false(child->pending_sigs);
	assert_false(child->sigsuspend_active);
	assert_int_equal(child->wait.kind, LXP_WAIT_NONE);
	assert_false(child->alarm_deadline_us);
	assert_false(child->alarm_interval_us);
	assert_int_equal(child->vfork_parent.index, -1);
	assert_int_equal(child->snapshot.index, -1);
}

static void test_child_constructors_cover_clone_flag_matrix(void **state)
{
	(void)state;
	static const uint32_t flag_bits[] = {
		LXP_CLONE_VM, LXP_CLONE_FILES, LXP_CLONE_FS, LXP_CLONE_SIGHAND, LXP_CLONE_THREAD,
	};

	lxp_proc_t *parent = &g_lxp_slots[0].proc;
	prepare_child_test_parent(parent);
	unsigned valid_cases = 0;
	for (unsigned mask = 0; mask < (1u << 5); mask++) {
		uint32_t flags = 0;
		for (unsigned bit = 0; bit < 5; bit++)
			if (mask & (1u << bit))
				flags |= flag_bits[bit];
		if (((flags & LXP_CLONE_SIGHAND) && !(flags & LXP_CLONE_VM)) ||
		    ((flags & LXP_CLONE_THREAD) && (flags & (LXP_CLONE_VM | LXP_CLONE_SIGHAND)) !=
							   (LXP_CLONE_VM | LXP_CLONE_SIGHAND)))
			continue;
		valid_cases++;
		uint16_t mm_refs = parent->mm->refs;
		uint16_t files_refs = parent->files->refs;
		uint16_t fs_refs = parent->fs_context->refs;
		uint16_t sighand_refs = parent->sighand->refs;
		uint16_t group_refs = parent->group->refs;
		lxp_proc_t child;
		memset(&child, 0xa5, sizeof(child));

		int child_pid = 100 + (int)mask;
		int rc = (flags & LXP_CLONE_THREAD)
				 ? lxp_proc_init_thread_child(&child, parent, flags, child_pid)
				 : lxp_proc_init_process_child(&child, parent, flags, child_pid);
		assert_int_equal(rc, LXP_OK);
		assert_child_local_state(&child, child_pid);
		assert_int_equal(child.mm == parent->mm, (flags & LXP_CLONE_VM) != 0);
		assert_int_equal(child.files == parent->files, (flags & LXP_CLONE_FILES) != 0);
		assert_int_equal(child.fs_context == parent->fs_context,
				 (flags & LXP_CLONE_FS) != 0);
		assert_int_equal(child.sighand == parent->sighand,
				 (flags & LXP_CLONE_SIGHAND) != 0);
		assert_int_equal(child.group == parent->group, (flags & LXP_CLONE_THREAD) != 0);
		if (!(flags & LXP_CLONE_THREAD)) {
			assert_int_equal(child.group->tgid, child_pid);
			assert_int_equal(child.group->ppid, parent->group->tgid);
			assert_int_equal(child.group->pgid, parent->group->pgid);
		}

		lxp_proc_child_discard(&child);
		assert_null(child.mm);
		assert_null(child.files);
		assert_null(child.fs_context);
		assert_null(child.sighand);
		assert_null(child.group);
		assert_int_equal(parent->mm->refs, mm_refs);
		assert_int_equal(parent->files->refs, files_refs);
		assert_int_equal(parent->fs_context->refs, fs_refs);
		assert_int_equal(parent->sighand->refs, sighand_refs);
		assert_int_equal(parent->group->refs, group_refs);
	}
	assert_int_equal(valid_cases, 16);
}

static void assert_failed_child_is_empty(const lxp_proc_t *child)
{
	assert_null(child->mm);
	assert_null(child->files);
	assert_null(child->fs_context);
	assert_null(child->sighand);
	assert_null(child->group);
	assert_false(child->alive);
	assert_int_equal(child->vfork_parent.index, -1);
	assert_int_equal(child->snapshot.index, -1);
}

static void test_child_constructor_rolls_back_each_acquisition(void **state)
{
	(void)state;
	lxp_proc_t *parent = &g_lxp_slots[0].proc;
	prepare_child_test_parent(parent);
	const uint32_t all_shared = LXP_CLONE_VM | LXP_CLONE_FILES | LXP_CLONE_FS |
				    LXP_CLONE_SIGHAND | LXP_CLONE_THREAD;
	lxp_proc_t child;

#define EXPECT_STAGE_FAILURE(member, flags)                                              \
	do {                                                                             \
		uint16_t saved = parent->member->refs;                                   \
		uint16_t mm_refs = parent->mm->refs;                                     \
		uint16_t files_refs = parent->files->refs;                               \
		uint16_t fs_refs = parent->fs_context->refs;                             \
		uint16_t sighand_refs = parent->sighand->refs;                           \
		uint16_t group_refs = parent->group->refs;                               \
		parent->member->refs = UINT16_MAX;                                       \
		memset(&child, 0, sizeof(child));                                        \
		assert_int_equal(lxp_proc_init_thread_child(&child, parent, flags, 200), \
				 LXP_ERR_NO_MEMORY);                                     \
		assert_failed_child_is_empty(&child);                                    \
		parent->member->refs = saved;                                            \
		assert_int_equal(parent->mm->refs, mm_refs);                             \
		assert_int_equal(parent->files->refs, files_refs);                       \
		assert_int_equal(parent->fs_context->refs, fs_refs);                     \
		assert_int_equal(parent->sighand->refs, sighand_refs);                   \
		assert_int_equal(parent->group->refs, group_refs);                       \
	} while (0)

	EXPECT_STAGE_FAILURE(mm, all_shared);
	EXPECT_STAGE_FAILURE(files, all_shared);
	EXPECT_STAGE_FAILURE(fs_context, all_shared);
	EXPECT_STAGE_FAILURE(sighand, all_shared);
	EXPECT_STAGE_FAILURE(group, all_shared);
#undef EXPECT_STAGE_FAILURE

	memset(&child, 0, sizeof(child));
	assert_int_equal(lxp_proc_init_process_child(&child, parent, LXP_CLONE_SIGHAND, 201),
			 LXP_ERR_INVALID_PARAM);
	assert_int_equal(lxp_proc_init_process_child(&child, parent, LXP_CLONE_THREAD, 201),
			 LXP_ERR_INVALID_PARAM);
	assert_int_equal(lxp_proc_init_thread_child(&child, parent, LXP_CLONE_THREAD, 201),
			 LXP_ERR_INVALID_PARAM);
}

static void test_fork_build_abort_restores_world(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *parent = &g_lxp_slots[0].proc;
	parent->mm->region_lo = (uintptr_t)g_mock_regions[0];
	parent->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	parent->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	g_lxp_slots[0].resume.sp = (uintptr_t)g_mock_regions[0] + 192u;
	lxp_proc_child_discard(&g_lxp_slots[1].proc);

	/* Region acquisition failure must not touch the destination or parent. */
	g_regions[0].refs = LXP_NSLOT;
	struct fork_txn tx;
	assert_int_equal(fork_txn_prepare(&tx, &g_mock_eng, 0, 1, 0, 2), -LXP_EAGAIN);
	fork_txn_abort(&tx, &g_mock_eng);
	assert_int_equal(g_regions[0].refs, LXP_NSLOT);
	assert_failed_child_is_empty(&g_lxp_slots[1].proc);
	g_regions[0].refs = 1;

	/* A failed native-map restore releases every constructor acquisition. */
	uint16_t mm_refs = parent->mm->refs;
	uint16_t files_refs = parent->files->refs;
	uint16_t fs_refs = parent->fs_context->refs;
	uint16_t sighand_refs = parent->sighand->refs;
	uint16_t group_refs = parent->group->refs;
	parent->mm->dev_map_lo[0] = 0x1000u;
	parent->mm->dev_map_hi[0] = 0x1100u;
	parent->mm->dev_map_attrs[0] = LXP_MAP_NC;
	g_mock.map_fail_slot = 1;
	assert_int_equal(fork_txn_prepare(&tx, &g_mock_eng, 0, 1, 0, 2), -LXP_ENOMEM);
	fork_txn_abort(&tx, &g_mock_eng);
	assert_int_equal(g_regions[0].refs, 1);
	assert_int_equal(parent->mm->refs, mm_refs);
	assert_int_equal(parent->files->refs, files_refs);
	assert_int_equal(parent->fs_context->refs, fs_refs);
	assert_int_equal(parent->sighand->refs, sighand_refs);
	assert_int_equal(parent->group->refs, group_refs);
	assert_failed_child_is_empty(&g_lxp_slots[1].proc);

	/* Snapshot exhaustion happens after publication preparation and child
	 * accounting; the same abort reverses both. */
	assert_int_equal(fork_txn_prepare(&tx, &g_mock_eng, 0, 1, 0, 2), LXP_OK);
	assert_int_equal(fork_txn_count_child(&tx), LXP_OK);
	for (int r = 1; r < LXP_NREG; r++)
		assert_int_equal(region_reserve(r, slot_ref_at(0)).index, r);
	assert_int_equal(
		vfork_snapshot(&g_mock_eng, parent, tx.child_ref, g_lxp_slots[0].resume.sp).index,
		-1);
	fork_txn_abort(&tx, &g_mock_eng);
	assert_int_equal(parent->group->live_children, 0);
	assert_int_equal(g_regions[0].refs, 1);
	assert_failed_child_is_empty(&g_lxp_slots[1].proc);
	for (int r = 1; r < LXP_NREG; r++)
		assert_int_equal(region_put(region_ref_at(r)), LXP_OK);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_fork_transaction_failpoints_restore_world(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *parent = &g_lxp_slots[0].proc;
	parent->mm->region_lo = (uintptr_t)g_mock_regions[0];
	parent->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	parent->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	uintptr_t parent_sp = (uintptr_t)g_mock_regions[0] + 192u;
	lxp_proc_child_discard(&g_lxp_slots[1].proc);
	lxp_diag_error_t error;

	const enum lxp_lifecycle_failpoint prepare_points[] = {
		LXP_FAIL_FORK_REGION_ACQUIRED,
		LXP_FAIL_FORK_CHILD_PREPARED,
		LXP_FAIL_FORK_MAPS_PREPARED,
	};
	for (size_t i = 0; i < sizeof(prepare_points) / sizeof(prepare_points[0]); i++) {
		struct fork_txn tx;
		g_lifecycle_failpoint = prepare_points[i];
		assert_true(fork_txn_prepare(&tx, &g_mock_eng, 0, 1, 0, 2) < 0);
		fork_txn_abort(&tx, &g_mock_eng);
		fork_txn_abort(&tx, &g_mock_eng); /* idempotent */
		assert_int_equal(parent->group->live_children, 0);
		assert_int_equal(g_regions[0].refs, 1);
		assert_failed_child_is_empty(&g_lxp_slots[1].proc);
		assert_int_equal(lxp_validate_world(&error), LXP_OK);
	}

	/* Child accounting, snapshot ownership, and publication are later
	 * boundaries of the same transaction and must converge on the same state. */
	for (enum lxp_lifecycle_failpoint point = LXP_FAIL_FORK_CHILD_COUNTED;
	     point <= LXP_FAIL_FORK_PUBLISHED; point++) {
		struct fork_txn tx;
		assert_int_equal(fork_txn_prepare(&tx, &g_mock_eng, 0, 1, 0, 2), LXP_OK);
		g_lifecycle_failpoint = point;
		int rc = fork_txn_count_child(&tx);
		if (point >= LXP_FAIL_FORK_SNAPSHOT_ACQUIRED && rc == LXP_OK) {
			tx.child->vfork_parent = tx.parent_ref;
			rc = fork_txn_snapshot(&tx, &g_mock_eng, parent_sp);
		}
		if (point == LXP_FAIL_FORK_PUBLISHED && rc == LXP_OK)
			rc = fork_txn_publish(&tx);
		assert_true(rc < 0);
		fork_txn_abort(&tx, &g_mock_eng);
		fork_txn_abort(&tx, &g_mock_eng);
		assert_int_equal(parent->group->live_children, 0);
		assert_int_equal(g_regions[0].refs, 1);
		for (int r = 1; r < LXP_NREG; r++)
			assert_int_equal(g_regions[r].refs, 0);
		assert_failed_child_is_empty(&g_lxp_slots[1].proc);
		assert_int_equal(lxp_validate_world(&error), LXP_OK);
	}
}

static void coord_w16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
}

static void coord_w32(uint8_t *p, uint32_t value)
{
	for (int i = 0; i < 4; i++)
		p[i] = (uint8_t)(value >> (8 * i));
}

static size_t build_coord_fdpic(uint8_t image[128])
{
	memset(image, 0, 128);
	image[0] = 0x7f;
	image[1] = 'E';
	image[2] = 'L';
	image[3] = 'F';
	image[4] = 1;
	image[7] = 65;
	coord_w16(image + 16, 3);
	coord_w16(image + 18, 40);
	coord_w32(image + 28, 52);
	coord_w16(image + 42, 32);
	coord_w16(image + 44, 2);
	uint8_t *text = image + 52;
	coord_w32(text, 1);
	coord_w32(text + 16, 16);
	coord_w32(text + 20, 16);
	coord_w32(text + 24, 1);
	uint8_t *data = image + 84;
	coord_w32(data, 1);
	coord_w32(data + 4, 116);
	coord_w32(data + 8, 0x1000);
	coord_w32(data + 16, 8);
	coord_w32(data + 20, 16);
	coord_w32(data + 24, 6);
	return 128;
}

static void test_exec_precommit_failpoints_preserve_old_image(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *old = &g_lxp_slots[0].proc;
	lxp_mm_t *mm = old->mm;
	lxp_files_t *files = old->files;
	lxp_fs_context_t *fs = old->fs_context;
	lxp_sighand_t *sighand = old->sighand;
	lxp_thread_group_t *group = old->group;
	uint32_t generation = slot_generation(0);
	uint8_t image[128];
	size_t image_size = build_coord_fdpic(image);
	lxp_diag_error_t error;

	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
	struct exec_txn tx;
	exec_txn_init(&tx, 0);
	g_lifecycle_failpoint = LXP_FAIL_EXEC_REGION_ACQUIRED;
	assert_true(exec_txn_reserve(&tx) < 0);
	exec_txn_abort(&tx, &g_mock_eng, -LXP_ENOMEM, LXP_EXIT_REASON_EXEC_RESOURCE);
	exec_txn_abort(&tx, &g_mock_eng, -LXP_ENOMEM, LXP_EXIT_REASON_EXEC_RESOURCE);
	assert_int_equal(g_lxp_slots[0].host_state, SLOT_RUNNING);
	assert_int_equal(slot_generation(0), generation);
	assert_ptr_equal(old->mm, mm);
	assert_ptr_equal(old->files, files);
	assert_ptr_equal(old->fs_context, fs);
	assert_ptr_equal(old->sighand, sighand);
	assert_ptr_equal(old->group, group);
	assert_true(old->alive);
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
	exec_txn_init(&tx, 0);
	assert_int_equal(exec_txn_reserve(&tx), LXP_OK);
	g_lifecycle_failpoint = LXP_FAIL_EXEC_IMAGE_VALIDATED;
	assert_true(exec_txn_validate_image(&tx, image, image_size, 0) < 0);
	exec_txn_abort(&tx, &g_mock_eng, -LXP_ENOEXEC, LXP_EXIT_REASON_EXEC_LOAD);
	assert_int_equal(g_lxp_slots[0].host_state, SLOT_RUNNING);
	assert_int_equal(slot_generation(0), generation);
	assert_ptr_equal(old->mm, mm);
	assert_ptr_equal(old->files, files);
	assert_ptr_equal(old->fs_context, fs);
	assert_ptr_equal(old->sighand, sighand);
	assert_ptr_equal(old->group, group);
	assert_true(old->alive);
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_exec_stale_snapshot_contains_vfork_pair(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *parent = &g_lxp_slots[0].proc;
	parent->mm->region_lo = (uintptr_t)g_mock_regions[0];
	parent->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	parent->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	uintptr_t parent_sp = (uintptr_t)g_mock_regions[0] + 192u;
	lxp_proc_child_discard(&g_lxp_slots[1].proc);

	struct fork_txn fork;
	assert_int_equal(fork_txn_prepare(&fork, &g_mock_eng, 0, 1, 0, 2), LXP_OK);
	assert_int_equal(fork_txn_count_child(&fork), LXP_OK);
	fork.child->vfork_parent = fork.parent_ref;
	assert_int_equal(g_lifecycle_failpoint, LXP_FAIL_NONE);
	assert_true(lxp_slot_ref_is_current(fork.parent_ref));
	assert_true(region_free(1));
	assert_int_equal(fork_txn_snapshot(&fork, &g_mock_eng, parent_sp), LXP_OK);
	int snapshot_region = fork.child->snapshot.index;
	assert_int_equal(fork_txn_publish(&fork), LXP_OK);
	assert_int_equal(fork_txn_commit(&fork), LXP_OK);
	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
	g_lxp_slots[1].host_state = SLOT_RUNNING;
	g_lxp_slots[1].runnable = 1;

	/* Corrupt only the child's stored capability. The guarded reservation is
	 * still valid and must be released by containment without copying it. */
	g_lxp_slots[1].proc.snapshot.generation++;
	struct exec_txn exec;
	exec_txn_init(&exec, 1);
	assert_int_equal(exec_txn_reserve(&exec), -LXP_EIO);
	assert_true(exec.terminal);
	exec_txn_abort(&exec, &g_mock_eng, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);

	assert_int_equal(parent->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(parent->exit_reason, LXP_EXIT_REASON_STATE_CORRUPTION);
	assert_int_equal(g_lxp_slots[1].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_slots[1].proc.exit_reason, LXP_EXIT_REASON_STATE_CORRUPTION);
	assert_int_equal(g_lxp_slots[1].proc.snapshot.index, -1);
	assert_int_equal(g_lxp_slots[1].proc.vfork_parent.index, -1);
	assert_int_equal(g_regions[snapshot_region].refs, 0);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_exec_commit_failure_contains_only_transitioning_guest(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	make_valid_running_slot(2, 2);
	lxp_slot_ref_t unrelated = slot_ref_at(2);
	uint8_t image[128];
	size_t image_size = build_coord_fdpic(image);
	lxp_diag_error_t error;

	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
	struct exec_txn tx;
	exec_txn_init(&tx, 0);
	assert_int_equal(exec_txn_reserve(&tx), LXP_OK);
	assert_int_equal(exec_txn_validate_image(&tx, image, image_size, 0), LXP_OK);
	g_lifecycle_failpoint = LXP_FAIL_EXEC_COMMITTED;
	assert_true(exec_txn_commit(&tx, &g_mock_eng) < 0);
	exec_txn_abort(&tx, &g_mock_eng, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);
	exec_txn_abort(&tx, &g_mock_eng, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);

	assert_false(g_lxp_slots[0].proc.alive);
	assert_int_equal(g_lxp_slots[0].host_state, SLOT_DEAD);
	assert_true(lxp_slot_ref_is_current(unrelated));
	assert_int_equal(g_lxp_slots[2].host_state, SLOT_RUNNING);
	assert_true(g_lxp_slots[2].runnable);
	assert_int_equal(g_regions[2].refs, 1);
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void prepare_mock_image_txn(struct image_txn *tx, int slot, int region)
{
	lxp_proc_child_discard(&g_lxp_slots[slot].proc);
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

static void test_image_publish_failpoints_release_every_owner(void **state)
{
	(void)state;
	const enum lxp_lifecycle_failpoint points[] = {
		LXP_FAIL_EXEC_IMAGE_PREPARED,
		LXP_FAIL_EXEC_PUBLISHED,
		LXP_FAIL_EXEC_NATIVE_STARTED,
		LXP_FAIL_EXEC_REGION_COMMITTED,
	};
	lxp_diag_error_t error;
	for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
		struct image_txn tx;
		prepare_mock_image_txn(&tx, 1, 1);
		g_lifecycle_failpoint = points[i];
		int rc;
		if (points[i] == LXP_FAIL_EXEC_IMAGE_PREPARED)
			rc = lifecycle_failpoint(points[i]) ? -LXP_EIO : LXP_OK;
		else {
			rc = image_txn_publish(&tx, &g_mock_eng);
			if (rc == LXP_OK)
				rc = image_txn_start(&tx, &g_mock_eng);
		}
		assert_true(rc < 0);
		assert_int_equal(image_txn_abort(&tx, &g_mock_eng), LXP_OK);
		assert_int_equal(image_txn_abort(&tx, &g_mock_eng), LXP_OK);
		assert_false(g_lxp_slots[1].proc.alive);
		assert_int_equal(g_regions[1].refs, 0);
		assert_int_equal(lxp_validate_world(&error), LXP_OK);
	}
}

static void test_world_diagnostics_snapshot_current_states(void **state)
{
	(void)state;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(error.issue, LXP_DIAG_OK);

	make_valid_running_slot(0, 0);
	g_diag_native_known = 1;
	g_diag_native_present[0] = 1;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	lxp_diag_slot_t slot;
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.abi_version, LXP_DIAG_ABI_VERSION);
	assert_int_equal(slot.struct_size, sizeof(slot));
	assert_int_equal(slot.generation, g_lxp_slots[0].generation);
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
	g_lxp_slots[0].runnable = 0;
	g_lxp_slots[0].proc.wait.kind = LXP_WAIT_PIPE;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.host_state, LXP_DIAG_HOST_PARKED);
	assert_int_equal(slot.wait_mask, LXP_DIAG_WAIT_PIPE);
	assert_int_equal(slot.native_task_known, 0);
	assert_int_equal(slot.native_task_present, 0);

	/* A successful census is usable only for the lifecycle epoch it observed.
	 * This mirrors refresh_stats() without invoking the mock thread provider. */
	g_diag_native_epoch = g_diag_lifecycle_epoch;
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.native_task_known, 1);
	assert_int_equal(slot.native_task_present, 1);

	g_lxp_slots[0].proc.stopped = 1;
	g_lxp_slots[0].proc.stop_kind = LXP_STOP_PARKED;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.task_status, LXP_DIAG_TASK_STOPPED);

	g_lxp_slots[0].proc.stopped = 0;
	g_lxp_slots[0].proc.wait.kind = LXP_WAIT_NONE;
	g_lxp_slots[0].proc.intent.kind = LXP_INTENT_FORK;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.intent_mask, LXP_DIAG_INTENT_FORK);
	g_lxp_slots[0].proc.intent.kind = LXP_INTENT_EXEC;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	g_lxp_slots[0].proc.intent.kind = LXP_INTENT_NONE;
	g_sig_save[0].depth = 1;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
	assert_int_equal(lxp_diag_slot_snapshot(0, &slot), LXP_OK);
	assert_int_equal(slot.signal_depth, 1);

	g_lxp_slots[0].proc.intent.kind = LXP_INTENT_EXIT;
	lxp_slot_set_host_state(0, SLOT_DEAD);
	g_diag_native_present[0] = 0;
	g_diag_native_epoch = g_diag_lifecycle_epoch;
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
	g_lxp_slots[0].proc.wait.kind = LXP_WAIT_COUNT;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_MULTIPLE_WAITS);
	assert_int_equal(error.slot, 0);
	assert_int_equal(error.actual, UINT32_MAX);
}

static void test_typed_intent_transitions_are_exclusive(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	for (int kind = LXP_INTENT_DEFERRED_SYSCALL; kind < LXP_INTENT_COUNT; kind++) {
		lxp_intent_t intent = {.kind = (lxp_intent_kind_t)kind};
		assert_int_equal(lxp_intent_begin(p, &intent), 0);
		assert_int_equal(lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}),
				 -LXP_EAGAIN);
		assert_int_equal(p->intent.kind, kind);
		assert_int_equal(lxp_intent_complete(p, (lxp_intent_kind_t)kind), 0);
		assert_int_equal(p->intent.kind, LXP_INTENT_NONE);
	}
	assert_int_equal(lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_NONE}),
			 -LXP_EINVAL);
	assert_int_equal(lxp_wait_begin(p, &(lxp_wait_t){.kind = LXP_WAIT_CHILD}), 0);
	assert_int_equal(lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}),
			 -LXP_EAGAIN);
	assert_int_equal(lxp_wait_cancel(p), 0);
	assert_int_equal(lxp_intent_exit(p, 1), 0);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_true(p->intent.data.exit.group);
}

static void test_exit_intent_supersedes_deferred_work(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->intent.kind = LXP_INTENT_DEFERRED_SYSCALL;
	g_lxp_slots[0].deferred.owner = slot_ref_at(0);
	deferred_state_store(0, DEFER_READY);

	assert_int_equal(lxp_intent_exit(p, 0), 0);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(claim_slot_event(0), LXP_EV_EXIT);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_typed_wait_transitions_cover_every_kind(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	for (int kind = LXP_WAIT_TIMER; kind < LXP_WAIT_COUNT; kind++) {
		lxp_wait_t wait = {.kind = (lxp_wait_kind_t)kind};
		assert_int_equal(lxp_wait_begin(p, &wait), 0);
		assert_int_equal(lxp_wait_begin(p, &(lxp_wait_t){.kind = LXP_WAIT_CHILD}),
				 -LXP_EAGAIN);
		assert_int_equal(p->wait.kind, kind);
		assert_int_equal(lxp_wait_interrupt(p, (lxp_wait_kind_t)kind), 0);
		assert_int_equal(p->wait.kind, LXP_WAIT_NONE);

		assert_int_equal(lxp_wait_begin(p, &wait), 0);
		assert_int_equal(lxp_wait_timeout(p, (lxp_wait_kind_t)kind), 0);
		assert_int_equal(p->wait.kind, LXP_WAIT_NONE);
	}
	assert_int_equal(lxp_wait_begin(p, &(lxp_wait_t){.kind = LXP_WAIT_NONE}), -LXP_EINVAL);
}

static void test_world_validator_reports_stale_mailbox(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	g_lxp_slots[0].deferred.owner = slot_ref_at(0);
	g_lxp_slots[0].deferred.owner.generation++;
	deferred_state_store(0, DEFER_READY);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_DEFERRED_GENERATION_STALE);
	assert_int_equal(error.slot, 0);
	assert_int_equal(error.expected, g_lxp_slots[0].generation);
}

static void test_world_validator_reports_region_ownership_drift(void **state)
{
	(void)state;
	g_regions[2].lease_owner = (lxp_slot_ref_t){.index = 3, .generation = 1};
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_REGION_OWNER_WITHOUT_REFS);
	assert_int_equal(error.slot, 3);
	assert_int_equal(error.region, 2);
}

static void test_slot_references_reject_recycled_incarnations_and_skip_zero(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	g_lxp_slots[0].generation = UINT32_MAX;
	lxp_slot_ref_t stale = slot_ref_at(0);

	deferred_slot_reassign(0);
	lxp_slot_ref_t current;
	assert_int_equal(lxp_slot_ref_current(0, &current), LXP_OK);
	assert_int_equal(current.generation, 1);
	assert_false(lxp_slot_ref_is_current(stale));
	assert_true(lxp_slot_ref_is_current(current));

	struct lxp_frame frame = {0};
	frame.r[0] = 0xfeedbeefu;
	frame.r[7] = LXP_NR_getpid;
	assert_int_equal(lxp_dispatch_slot(stale, &frame), -LXP_ESRCH);
	assert_int_equal(frame.r[0], 0xfeedbeefu);
	assert_int_equal(lxp_dispatch_slot(current, &frame), LXP_OK);
	assert_int_equal(frame.r[0], g_lxp_slots[0].proc.pid);
}

static void test_fault_publication_rejects_stale_slot_reference(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_slot_ref_t stale = slot_ref_at(0);
	deferred_slot_reassign(0);
	lxp_slot_ref_t current = slot_ref_at(0);
	const lxp_guest_fault_t fault = {
		.detail = 0x82u,
		.address = 0x12345678u,
	};

	assert_int_equal(lxp_slot_report_memory_fault(stale, &fault), -LXP_ESRCH);
	assert_int_equal(g_lxp_slots[0].proc.intent.kind, LXP_INTENT_NONE);
	assert_false(primary_slot_pending(0));
	assert_int_equal(lxp_slot_report_memory_fault(current, &fault), LXP_OK);
	assert_int_equal(g_lxp_slots[0].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_slots[0].proc.exit_reason, LXP_EXIT_REASON_MEMORY_FAULT);
	assert_int_equal(g_lxp_slots[0].proc.exit_detail, fault.detail);
	assert_int_equal(g_lxp_slots[0].proc.exit_address, fault.address);
	assert_true(primary_slot_pending(0));
}

static void test_memory_policy_snapshot_and_key_track_every_generation(void **state)
{
	(void)state;
	make_valid_running_slot(0, 2);
	lxp_slot_ref_t slot = slot_ref_at(0);
	lxp_mm_t *mm = g_lxp_slots[0].proc.mm;
	mm->device_generation = 7u;
	mm->exec_generation = 11u;
	mm->copied_text_executable = 1u;
	mm->dev_map_lo[0] = 0x40001000u;
	mm->dev_map_hi[0] = 0x40002000u;
	mm->dev_map_attrs[0] = LXP_MAP_DEV;

	lxp_memory_policy_t policy;
	assert_int_equal(lxp_slot_memory_policy(slot, &policy), LXP_OK);
	assert_int_equal(policy.abi_version, LXP_MEMORY_POLICY_ABI_VERSION);
	assert_int_equal(policy.struct_size, sizeof(policy));
	assert_true(lxp_slot_ref_equal(policy.slot, slot));
	assert_true(lxp_region_ref_equal(policy.address_space, mm->region));
	assert_int_equal(policy.device_generation, 7u);
	assert_int_equal(policy.exec_generation, 11u);
	assert_int_equal(policy.copied_text_executable, 1u);
	assert_int_equal(policy.device_count, 1u);
	assert_int_equal(policy.devices[0].base, 0x40001000u);
	assert_int_equal(policy.devices[0].size, 0x1000u);
	assert_int_equal(policy.devices[0].attrs, LXP_MAP_DEV);

	lxp_memory_policy_key_t key = lxp_memory_policy_make_key(&policy);
	assert_true(lxp_memory_policy_matches_key(&policy, &key));
	mm->device_generation++;
	assert_int_equal(lxp_slot_memory_policy(slot, &policy), LXP_OK);
	assert_false(lxp_memory_policy_matches_key(&policy, &key));
	assert_true(lxp_memory_policy_address_space_matches_key(&policy, &key) == 0);

	lxp_slot_ref_t stale = slot;
	deferred_slot_reassign(0);
	assert_int_equal(lxp_slot_memory_policy(stale, &policy), -LXP_ESRCH);
}

static void test_region_references_reject_reuse_and_skip_zero(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	lxp_slot_ref_t owner = slot_ref_at(0);
	lxp_region_ref_t stale = region_reserve(1, owner);
	assert_int_equal(stale.index, 1);
	assert_int_equal(region_release_if_owned(stale, owner), LXP_OK);

	lxp_region_ref_t current = region_reserve(1, owner);
	assert_int_equal(current.index, 1);
	assert_true(current.generation != stale.generation);
	assert_int_equal(region_put(stale), -1);
	assert_int_equal(region_release_if_owned(stale, owner), -1);
	assert_int_equal(g_regions[1].refs, 1);
	assert_int_equal(region_release_if_owned(current, owner), LXP_OK);

	g_regions[1].generation = UINT32_MAX;
	current = region_reserve(1, owner);
	assert_int_equal(current.generation, 1);
	assert_int_equal(region_release_if_owned(current, owner), LXP_OK);
}

static void test_world_validator_rejects_stale_region_capabilities(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	g_lxp_slots[0].proc.mm->region.generation++;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), -LXP_EINVAL);
	assert_int_equal(error.issue, LXP_DIAG_LIVE_TASK_STALE_REGION_REF);
	assert_int_equal(error.slot, 0);
	assert_int_equal(error.region, 0);
}

static void test_world_validator_rejects_stale_region_leases(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	lxp_region_ref_t lease = region_reserve(1, slot_ref_at(0));
	assert_int_equal(lease.index, 1);
	deferred_slot_reassign(0);
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
	assert_int_equal(region_put(region_ref_at(1)), LXP_OK);
	g_lxp_slots[1].proc.mm = g_lxp_slots[0].proc.mm;
	g_lxp_slots[1].proc.mm->region = region_ref_at(0);
	assert_int_equal(region_get(g_lxp_slots[1].proc.mm->region), LXP_OK);
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
	g_regions[0].lease_owner = (lxp_slot_ref_t){.index = 0, .generation = 1};
	lxp_diag_checkpoint();
	g_regions[1].lease_owner = (lxp_slot_ref_t){.index = 1, .generation = 1};
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
	assert_int_equal(sizes.debug_record, sizeof(struct lxp_dbg_s));
	assert_int_equal(sizes.slot_table, sizeof(*g_lxp_slots) * LXP_NSLOT);
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

static void test_system_version_routes_to_engine(void **state)
{
	(void)state;
	assert_string_equal(lxp_system_version(), "MockRTOS 9.8.7 ove-fedcba9 lxp-7654321");
	g_eng = NULL;
	assert_string_equal(lxp_system_version(), "lxp");
}

static void test_port_abi_and_required_ops_are_validated(void **state)
{
	(void)state;
	assert_true(os_ops_valid(&g_mock_eng));

	lxp_os_ops_t ops = g_mock_eng;
	ops.abi_version++;
	assert_false(os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.struct_size--;
	assert_false(os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.random_fill = NULL;
	assert_false(os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.cpu_memory_model = (lxp_cpu_memory_model_t)99;
	assert_false(os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.validate_memory_model = NULL;
	assert_false(os_ops_valid(&ops));
}

static void test_failed_prepare_is_rolled_back(void **state)
{
	(void)state;
	uint8_t image[1] = {0};
	const lxp_file_t files[] = {
		{.path = "/init", .data = image, .size = sizeof(image),
		 .mode = LXP_S_IFREG | 0755},
	};
	const lxp_run_config_t cfg = {
		.rootfs = files,
		.rootfs_count = 1,
		.rootfs_image = image,
		.rootfs_image_size = sizeof(image),
	};
	const char *const argv[] = {"init", NULL};

	g_mock.prepare_result = -LXP_EIO;
	assert_int_equal(lxp_run(&g_mock_eng, g_test_net_ops, NULL, &cfg, "/init", 1,
				 argv),
			 LXP_RUN_ELAUNCH);
	assert_int_equal(g_mock.prepare_calls, 1);
	assert_int_equal(g_mock.teardown_calls, 1);
	assert_null(g_eng);
	assert_null(g_cfg);
	assert_null(g_lxp_rootfs_lo);
	assert_null(g_lxp_rootfs_hi);
	assert_null(g_lxp_net_ops);
}

static void test_rootfs_requires_one_explicit_trusted_window(void **state)
{
	(void)state;
	uint8_t image[16] = {0};
	lxp_file_t files[] = {
		{.path = "/", .data = NULL, .size = 0, .mode = LXP_S_IFDIR | 0755},
		{.path = "/init", .data = image + 4, .size = 4, .mode = LXP_S_IFREG | 0755},
	};
	lxp_run_config_t cfg = {
		.rootfs = files,
		.rootfs_count = 2,
		.rootfs_image = image,
		.rootfs_image_size = sizeof(image),
	};
	assert_true(run_config_valid(&cfg));

	cfg.rootfs_image = image + 8;
	cfg.rootfs_image_size = 8;
	assert_false(run_config_valid(&cfg));
	cfg.rootfs_image = NULL;
	assert_false(run_config_valid(&cfg));
}

static void test_resource_stats_track_slots_and_reserved_regions(void **state)
{
	(void)state;
	lxp_trap_publish(1);
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_region_ref_t shared = region_reserve(0, slot_ref_at(0));
	lxp_region_ref_t reserved = region_reserve(2, slot_ref_at(1));
	assert_int_equal(shared.index, 0);
	assert_int_equal(reserved.index, 2);
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.mm->region = shared;
	g_lxp_slots[1].proc.alive = 1;
	g_lxp_slots[1].proc.mm->region = shared; /* thread shares region 0 but consumes a slot */

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
		g_lxp_slots[s].proc.alive = 1;
		g_lxp_slots[s].proc.mm->region.index = 0;
	}
	lxp_get_resource_stats(&resources);
	assert_int_equal(resources.slots_free, 0);
	assert_int_equal(resources.processes, LXP_NSLOT);
	assert_int_equal(resources.regions_free, LXP_NREG - 2);
	assert_int_equal(resources.available_bytes, 0);
}

static void test_coordinator_socket_wait_uses_readiness_events(void **state)
{
	(void)state;

	/* Legacy/portable ports retain the bounded polling fallback. */
	assert_int_equal(coordinator_wait_timeout(LXP_BLOCKED_WAIT_SOCKET, 0), 5);
	/* An event-driven net port can sleep until lxp_sock_kick() (or the normal
	 * 50 ms maintenance wakeup) without quantizing socket readiness to 5 ms. */
	assert_int_equal(coordinator_wait_timeout(LXP_BLOCKED_WAIT_SOCKET, 1), 50);
	/* A different polling wait class still requires the short timeout. */
	assert_int_equal(coordinator_wait_timeout(LXP_BLOCKED_WAIT_POLL |
							  LXP_BLOCKED_WAIT_SOCKET,
						  1),
			 5);
	assert_int_equal(coordinator_wait_timeout(0, 0), 50);
}

/* The per-slot claim helper maps one typed intent/wait without consuming its
 * payload inside the engine critical section. */
static void test_claim_slot_event_priority_and_consumption(void **state)
{
	(void)state;
	const int s = 2;
	lxp_proc_t *p = &g_lxp_slots[s].proc;

	assert_false(primary_slot_pending(s));
	lxp_event_post_slot(&g_mock_eng, s);
	assert_true(primary_slot_pending(s));
	assert_int_equal(g_mock.event_posts, 1);
	primary_slot_clear(s);
	assert_false(primary_slot_pending(s));

	assert_int_equal(claim_slot_event(s), LXP_EV_NONE);
	p->alive = 1;
	p->intent.kind = LXP_INTENT_EXIT;
	assert_int_equal(claim_slot_event(s), LXP_EV_EXIT);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	p->intent.kind = LXP_INTENT_EXEC;
	assert_int_equal(claim_slot_event(s), LXP_EV_EXEC);
	p->intent.kind = LXP_INTENT_FORK;
	assert_int_equal(claim_slot_event(s), LXP_EV_FORK);
	assert_int_equal(p->intent.kind, LXP_INTENT_FORK);
	p->intent.kind = LXP_INTENT_NONE;
	p->wait.kind = LXP_WAIT_TIMER;
	p->wait.data.timer.deadline_us = 1;
	assert_int_equal(claim_slot_event(s), LXP_EV_NONE);
	g_lxp_slots[s].runnable = 1;
	g_lxp_slots[s].host_state = SLOT_RUNNING;
	static const struct {
		lxp_wait_kind_t kind;
		int event;
	} cases[] = {
		{LXP_WAIT_TIMER, LXP_EV_SLEEP},		  {LXP_WAIT_CHILD, LXP_EV_WAITPARK},
		{LXP_WAIT_FUTEX, LXP_EV_FUTEXWAIT},	  {LXP_WAIT_PIPE, LXP_EV_PIPE},
		{LXP_WAIT_CONSOLE, LXP_EV_CONSOLEWAIT},	  {LXP_WAIT_DEVICE, LXP_EV_DEVWAIT},
		{LXP_WAIT_SOCKET, LXP_EV_SOCKWAIT},
#if LXP_ENABLE_NETFS
		{LXP_WAIT_NETFS, LXP_EV_NETFSWAIT},
#endif
#if LXP_ENABLE_PTY
		{LXP_WAIT_PTY, LXP_EV_PTYWAIT},
#endif
		{LXP_WAIT_SIGSUSPEND, LXP_EV_SIGSUSPEND},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		p->wait.kind = cases[i].kind;
		assert_int_equal(claim_slot_event(s), cases[i].event);
		assert_int_equal(p->wait.kind, cases[i].kind);
	}
}

static void test_coordinator_claim_rotates_fairly_and_discards_stale_hints(void **state)
{
	(void)state;
	make_valid_running_slot(2, 2);
	make_valid_running_slot(4, 4);
	g_lxp_slots[2].proc.wait.kind = LXP_WAIT_TIMER;
	g_lxp_slots[4].proc.wait.kind = LXP_WAIT_TIMER;
	primary_slot_mark(2);
	primary_slot_mark(4);

	unsigned cursor = 0;
	struct lxp_claimed_event claimed = coordinator_claim_event(&g_mock_eng, &cursor);
	assert_int_equal(claimed.slot, 2);
	assert_int_equal(claimed.type, LXP_EV_SLEEP);
	assert_int_equal(cursor, 3);

	/* Re-publishing slot 2 cannot starve the later pending slot. */
	primary_slot_mark(2);
	claimed = coordinator_claim_event(&g_mock_eng, &cursor);
	assert_int_equal(claimed.slot, 4);
	assert_int_equal(cursor, 5);
	claimed = coordinator_claim_event(&g_mock_eng, &cursor);
	assert_int_equal(claimed.slot, 2);
	assert_int_equal(cursor, 3);

	/* A stale bitmap hint is consumed without inventing an event. */
	primary_slot_mark(1);
	claimed = coordinator_claim_event(&g_mock_eng, &cursor);
	assert_int_equal(claimed.slot, -1);
	assert_int_equal(claimed.type, LXP_EV_NONE);
	assert_false(primary_slot_pending(1));
}

static void test_primary_wait_handler_applies_park_outcome(void **state)
{
	(void)state;
	const int slot = 2;
	make_valid_running_slot(slot, 2);
	g_lxp_slots[slot].proc.wait.kind = LXP_WAIT_TIMER;
	int next_pid = 10;

	struct lxp_primary_result result =
		lxp_handle_primary_event(&g_mock_eng, &g_mock_cfg, slot, LXP_EV_SLEEP, &next_pid);
	assert_int_equal(result.flow, LXP_PRIMARY_HANDLED);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.park_sidx, slot);
	assert_int_equal(g_lxp_slots[slot].host_state, SLOT_PARKED);
	assert_false(g_lxp_slots[slot].runnable);
	assert_int_equal(next_pid, 10);
}

static void test_primary_handler_rejects_out_of_range_slot(void **state)
{
	(void)state;
	int next_pid = 10;

	struct lxp_primary_result result = lxp_handle_primary_event(
		&g_mock_eng, &g_mock_cfg, LXP_NSLOT, LXP_EV_EXIT, &next_pid);
	assert_int_equal(result.flow, LXP_PRIMARY_SCAN_BLOCKED);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(next_pid, 10);
}

static void test_blocked_timer_handler_resumes_expired_wait(void **state)
{
	(void)state;
	const int slot = 3;
	make_valid_running_slot(slot, 3);
	assert_int_equal(coordinator_park_slot(&g_mock_eng, slot), LXP_OK);
	assert_int_equal(lxp_wait_begin(&g_lxp_slots[slot].proc,
					&(lxp_wait_t){
						.kind = LXP_WAIT_TIMER,
						.data.timer.deadline_us = 50,
					}),
			 LXP_OK);

	struct lxp_blocked_scan scan = lxp_scan_blocked(&g_mock_eng, &g_mock_cfg, 50);
	assert_true(scan.any_alive);
	assert_true(scan.any_busy);
	assert_true(scan.progress);
	assert_int_equal(scan.next_deadline_us, UINT64_MAX);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, slot);
	assert_int_equal(g_mock.resume_r0, 0);
	assert_int_equal(g_lxp_slots[slot].proc.wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_lxp_slots[slot].host_state, SLOT_RUNNING);
	assert_true(g_lxp_slots[slot].runnable);
}

/* ---- wait-status encoding --------------------------------------------------- */
static void test_encode_wstatus(void **state)
{
	(void)state;
	/* Normal exit: WIFEXITED, code in bits 8-15. */
	assert_int_equal(lxp_encode_wstatus(0), 0);
	assert_int_equal(lxp_encode_wstatus(42), 42 << 8);
	assert_int_equal(lxp_encode_wstatus(255), 255 << 8);
	/* Our "128 + signal" kill convention: WIFSIGNALED, signal in the low 7 bits. */
	assert_int_equal(lxp_encode_wstatus(128 + 9), 9);   /* SIGKILL */
	assert_int_equal(lxp_encode_wstatus(128 + 15), 15); /* SIGTERM */
	assert_int_equal(lxp_encode_wstatus(128 + 31), 31); /* highest signal delivered */
	/* Boundaries: 128 itself and >128+31 are ordinary exit codes, not signals. */
	assert_int_equal(lxp_encode_wstatus(128), 128 << 8);
	assert_int_equal(lxp_encode_wstatus(160), 160 << 8);
}

/* ---- reap_to_parent: parent blocked in wait4 -------------------------------- */
static void set_child_wait(lxp_proc_t *p, int pid, int options, int *status)
{
	p->wait = (lxp_wait_t){
		.kind = LXP_WAIT_CHILD,
		.data.child.pid = pid,
		.data.child.options = options,
		.data.child.status = (uintptr_t)status,
	};
}

static void test_reap_wakes_blocking_parent(void **state)
{
	(void)state;
	int status = -1;
	/* slot 0 = parent pid 1, blocked in wait4 for any child, with one live child. */
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_slots[0].proc, -1, 0, &status);
	g_lxp_slots[0].host_state = SLOT_PARKED;

	reap_to_parent(&g_mock_eng, /*ppid*/ 1, /*cpid*/ 7, /*status*/ 42, /*sigchld=*/1);

	/* Resumed once, returning the reaped pid; *status = WIFEXITED(42); child accounted. */
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, 0);
	assert_int_equal(g_mock.resume_r0, 7);
	assert_int_equal(status, 42 << 8);
	assert_int_equal(g_lxp_slots[0].proc.wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_lxp_slots[0].proc.group->live_children, 0);
	assert_int_equal(g_lxp_slots[0].proc.group->child_count, 0); /* woken, not queued */
	assert_int_equal(g_mock.abort_calls, 0); /* g_lxp_slots[0].runnable==0: no spin thread */
}

static void test_reap_wakes_waiter_in_parent_thread_group(void **state)
{
	(void)state;
	int status = -1;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 10;
	g_lxp_slots[0].proc.group->tgid = 10;
	lxp_proc_group_put(&g_lxp_slots[1].proc);
	assert_int_equal(lxp_proc_group_fork(&g_lxp_slots[1].proc, &g_lxp_slots[0].proc,
					     LXP_CLONE_THREAD, 11),
			 0);
	g_lxp_slots[1].proc.alive = 1;
	g_lxp_slots[1].proc.pid = 11;
	g_lxp_slots[1].proc.group->live_children = 1;
	set_child_wait(&g_lxp_slots[1].proc, -1, 0, &status);
	g_lxp_slots[1].host_state = SLOT_PARKED;

	reap_to_parent(&g_mock_eng, 10, 17, 9, /*sigchld=*/1);

	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, 1);
	assert_int_equal(g_mock.resume_r0, 17);
	assert_int_equal(status, 9 << 8);
	assert_int_equal(g_lxp_slots[0].proc.group->live_children, 0);
	assert_int_equal(g_lxp_slots[0].proc.group->child_count, 0);
}

/* A signal-killed child (128 + signo) wakes the waiter as WIFSIGNALED. */
static void test_reap_signaled_child_status(void **state)
{
	(void)state;
	int status = -1;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_slots[0].proc, -1, 0, &status);
	g_lxp_slots[0].runnable = 1; /* coordinator has not yet suspended the parked waiter */
	g_lxp_slots[0].host_state = SLOT_RUNNING;

	reap_to_parent(&g_mock_eng, 1, 7, 128 + 15 /* SIGTERM */, /*sigchld=*/1);

	assert_int_equal(status, 15); /* low 7 bits = the signal */
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.park_sidx, 0);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 1);
}

/* A wait4 targeting a specific other pid is NOT woken by an unrelated child. */
static void test_reap_specific_pid_not_woken(void **state)
{
	(void)state;
	int status = -1;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = 2;
	set_child_wait(&g_lxp_slots[0].proc, 9, 0, &status);

	reap_to_parent(&g_mock_eng, 1, 7, 0, /*sigchld=*/1); /* pid 7 exits, not 9 */

	/* Not resumed; the zombie is queued and SIGCHLD raised; still one live child left. */
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_slots[0].proc.wait.kind, LXP_WAIT_CHILD);
	assert_int_equal(g_lxp_slots[0].proc.group->child_count, 1);
	assert_int_equal(g_lxp_slots[0].proc.group->child_pid[0], 7);
	assert_int_equal(g_lxp_slots[0].proc.group->live_children, 1);
	assert_true((g_lxp_slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) != 0);
}

/* ---- reap_to_parent: parent not waiting → zombie queued + SIGCHLD ----------- */
static void test_reap_queues_zombie(void **state)
{
	(void)state;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = 1;
	/* No CHILD wait: the parent is off in select()/poll(), not blocking in wait4. */

	reap_to_parent(&g_mock_eng, 1, 7, 3, /*sigchld=*/1);

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_slots[0].proc.group->child_count, 1);
	assert_int_equal(g_lxp_slots[0].proc.group->child_pid[0], 7);
	assert_int_equal(g_lxp_slots[0].proc.group->child_status[0],
			 3); /* raw code; wait4 encodes on reap */
	assert_int_equal(g_lxp_slots[0].proc.group->live_children, 0);
	assert_true((g_lxp_slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) != 0);
}

/* ---- reap_to_parent: a vfork parent (already resumed) reaps WITHOUT SIGCHLD --- */
/* Regression: a vfork parent resumed at its child's exit has no CHILD wait yet, so the
 * zombie takes the else branch — but the parent will wait4() it immediately. Raising
 * SIGCHLD (sigchld != 0) here would -EINTR that wait4 before it reaps (the shell then
 * prints "waitpid: Interrupted" and loses the 127 exit code), so the vfork callers pass
 * sigchld=0: queue the zombie, do NOT signal. */
static void test_reap_vfork_parent_suppresses_sigchld(void **state)
{
	(void)state;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = 1;
	/* No CHILD wait: just resumed from vfork, about to wait4() the child. */

	reap_to_parent(&g_mock_eng, 1, 7, 127, /*sigchld=*/0);

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_slots[0].proc.group->child_count,
			 1); /* queued for the imminent wait4 */
	assert_int_equal(g_lxp_slots[0].proc.group->child_pid[0], 7);
	assert_int_equal(g_lxp_slots[0].proc.group->child_status[0], 127); /* exit code preserved */
	assert_int_equal(g_lxp_slots[0].proc.group->live_children, 0);
	assert_true((g_lxp_slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) ==
		    0); /* NOT signalled */
}

/* The zombie queue is bounded (LXP_MAX_CHILD): an overflow is dropped, not overrun. */
static void test_reap_zombie_queue_full(void **state)
{
	(void)state;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = LXP_MAX_CHILD + 1;
	g_lxp_slots[0].proc.group->child_count = LXP_MAX_CHILD; /* already full */

	reap_to_parent(&g_mock_eng, 1, 99, 0, /*sigchld=*/1);

	assert_int_equal(g_lxp_slots[0].proc.group->child_count,
			 LXP_MAX_CHILD); /* clamped, no overrun */
	assert_int_equal(g_lxp_slots[0].proc.group->live_children,
			 LXP_MAX_CHILD); /* still decremented */
}

/* An exit reported for a parent that no longer exists is a safe no-op. */
static void test_reap_unknown_parent(void **state)
{
	(void)state;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;

	reap_to_parent(&g_mock_eng, /*ppid*/ 42, 7, 0, /*sigchld=*/1); /* no proc has pid 42 */

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_lxp_slots[0].proc.group->child_count, 0);
}

static void test_notify_guest_exit_preserves_attribution(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[3].proc;
	p->pid = 27;
	p->group->ppid = 7;
	p->exit_status = 139;
	p->exit_reason = LXP_EXIT_REASON_MEMORY_FAULT;
	p->exit_signal = LXP_SIGSEGV;
	p->exit_detail = 0x92;
	p->exit_address = 0x4c;
	memcpy(p->comm, "sigctx", 7);
	g_cfg = &g_mock_cfg;

	notify_guest_exit(3, p);

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

static void test_fork_capacity_accounts_live_and_zombie_children(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	assert_true(fork_capacity_available(p));
	p->group->child_count = LXP_MAX_CHILD - 1;
	assert_true(fork_capacity_available(p));
	p->group->live_children = 1;
	assert_false(fork_capacity_available(p));
	p->group->child_count = 0;
	p->group->live_children = LXP_MAX_CHILD;
	assert_false(fork_capacity_available(p));
	p->group->live_children = -1;
	assert_false(fork_capacity_available(p));
}

static void test_vfork_snapshot_publishes_cacheable_destination(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	p->mm->is_dynamic = 1;
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	for (size_t i = 0; i < 128u; i++)
		g_mock_regions[0][i] = (uint8_t)(i ^ 0x5au);
	memset(&g_mock_regions[0][128], 0xee, 64u); /* unused stack reservation: not copied */
	for (size_t i = 192u; i < sizeof(g_mock_regions[0]); i++)
		g_mock_regions[0][i] = (uint8_t)(i ^ 0x3cu);
	for (size_t i = 0; i < sizeof(g_mock_dyn_pools[0]); i++)
		g_mock_dyn_pools[0][i] = (uint8_t)(i ^ 0xa5u);
	lxp_region_ref_t snapshot = vfork_snapshot(&g_mock_eng, p, slot_ref_at(1), sp);
	assert_int_equal(snapshot.index, 1);
	assert_memory_equal(g_mock_regions[1], g_mock_regions[0], 128u);
	assert_memory_equal(&g_mock_regions[1][192], &g_mock_regions[0][192], 64u);
	for (size_t i = 128u; i < 192u; i++)
		assert_int_equal(g_mock_regions[1][i], 0); /* inactive stack was not copied */
	assert_memory_equal(g_mock_dyn_pools[1], g_mock_dyn_pools[0], sizeof(g_mock_dyn_pools[0]));
	assert_int_equal(g_mock.cache_clean_calls, 6);
	assert_ptr_equal(g_mock.cache_clean_base[0], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_clean_base[1], g_mock_regions[1]);
	assert_ptr_equal(g_mock.cache_clean_base[2], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_clean_base[3], &g_mock_regions[1][192]);
	assert_ptr_equal(g_mock.cache_clean_base[4], g_mock_dyn_pools[0]);
	assert_ptr_equal(g_mock.cache_clean_base[5], g_mock_dyn_pools[1]);
	assert_int_equal(g_mock.cache_clean_len[0], 128u);
	assert_int_equal(g_mock.cache_clean_len[1], 128u);
	assert_int_equal(g_mock.cache_clean_len[2], 64u);
	assert_int_equal(g_mock.cache_clean_len[3], 64u);
	assert_int_equal(g_mock.cache_clean_len[4], sizeof(g_mock_dyn_pools[0]));
	assert_int_equal(g_mock.cache_clean_len[5], sizeof(g_mock_dyn_pools[1]));
	assert_int_equal(g_mock.cache_invalidate_calls, 3);
	assert_ptr_equal(g_mock.cache_invalidate_base[0], g_mock_regions[1]);
	assert_ptr_equal(g_mock.cache_invalidate_base[1], &g_mock_regions[1][192]);
	assert_ptr_equal(g_mock.cache_invalidate_base[2], g_mock_dyn_pools[1]);
	assert_int_equal(g_mock.cache_invalidate_len[0], 128u);
	assert_int_equal(g_mock.cache_invalidate_len[1], 64u);
	assert_int_equal(g_mock.cache_invalidate_len[2], sizeof(g_mock_dyn_pools[1]));
}

static void test_vfork_restore_publishes_cacheable_parent(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	p->mm->is_dynamic = 1;
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	for (size_t i = 0; i < 128u; i++)
		g_mock_regions[1][i] = (uint8_t)(i ^ 0x5au);
	for (size_t i = 192u; i < sizeof(g_mock_regions[1]); i++)
		g_mock_regions[1][i] = (uint8_t)(i ^ 0x3cu);
	for (size_t i = 0; i < sizeof(g_mock_dyn_pools[1]); i++)
		g_mock_dyn_pools[1][i] = (uint8_t)(i ^ 0xa5u);
	memset(g_mock_regions[0], 0xcc, 128u);
	memset(&g_mock_regions[0][192], 0xbb, 64u);
	memset(g_mock_dyn_pools[0], 0xdd, sizeof(g_mock_dyn_pools[0]));

	lxp_slot_ref_t child = slot_ref_at(1);
	lxp_region_ref_t snapshot = region_reserve(1, child);
	g_lxp_slots[1].proc.alive = 1;
	g_vfork_guard[1].parent = slot_ref_at(0);
	g_vfork_guard[1].parent_region = p->mm->region;
	g_vfork_guard[1].snapshot = snapshot;
	assert_int_equal(vfork_restore(&g_mock_eng, p, snapshot, child, sp), 0);

	assert_memory_equal(g_mock_regions[0], g_mock_regions[1], 128u);
	assert_memory_equal(&g_mock_regions[0][192], &g_mock_regions[1][192], 64u);
	assert_memory_equal(g_mock_dyn_pools[0], g_mock_dyn_pools[1], sizeof(g_mock_dyn_pools[0]));
	assert_int_equal(g_mock.cache_clean_calls, 3);
	assert_ptr_equal(g_mock.cache_clean_base[0], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_clean_base[1], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_clean_base[2], g_mock_dyn_pools[0]);
	assert_int_equal(g_mock.cache_invalidate_calls, 6);
	assert_ptr_equal(g_mock.cache_invalidate_base[0], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_invalidate_base[1], g_mock_regions[0]);
	assert_ptr_equal(g_mock.cache_invalidate_base[2], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_invalidate_base[3], &g_mock_regions[0][192]);
	assert_ptr_equal(g_mock.cache_invalidate_base[4], g_mock_dyn_pools[0]);
	assert_ptr_equal(g_mock.cache_invalidate_base[5], g_mock_dyn_pools[0]);
}

static void test_vfork_snapshot_refuses_no_spare_region(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	for (int r = 1; r < LXP_NREG; r++)
		(void)region_reserve(r, slot_ref_at(0));

	assert_int_equal(vfork_snapshot(&g_mock_eng, p, slot_ref_at(1),
					(uintptr_t)g_mock_regions[0] + 192u)
				 .index,
			 -1);
	assert_int_equal(g_mock.cache_clean_calls, 0);
	assert_int_equal(g_vfork_guard[1].snapshot.index, -1);
}

static void test_vfork_restore_rejects_recycled_snapshot(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	deferred_slot_reassign(2);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	g_lxp_slots[1].proc.alive = 1;
	lxp_slot_ref_t child = slot_ref_at(1);
	lxp_region_ref_t snapshot = vfork_snapshot(&g_mock_eng, p, child, sp);
	assert_int_equal(snapshot.index, 1);
	memset(g_mock_regions[0], 0x5a, sizeof(g_mock_regions[0]));
	assert_int_equal(region_release_if_owned(snapshot, child), LXP_OK);
	(void)region_reserve(1, slot_ref_at(2)); /* same index, new reservation */

	assert_int_equal(vfork_restore(&g_mock_eng, p, snapshot, child, sp), -1);
	for (size_t i = 0; i < sizeof(g_mock_regions[0]); i++)
		assert_int_equal(g_mock_regions[0][i], 0x5a);
}

static void test_vfork_restore_rejects_recycled_parent(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	g_lxp_slots[1].proc.alive = 1;
	lxp_slot_ref_t child = slot_ref_at(1);
	lxp_region_ref_t snapshot = vfork_snapshot(&g_mock_eng, p, child, sp);
	assert_int_equal(snapshot.index, 1);
	memset(g_mock_regions[0], 0xa5, sizeof(g_mock_regions[0]));
	deferred_slot_reassign(0); /* same slot, different process incarnation */

	assert_int_equal(vfork_restore(&g_mock_eng, p, snapshot, child, sp), -1);
	for (size_t i = 0; i < sizeof(g_mock_regions[0]); i++)
		assert_int_equal(g_mock_regions[0][i], 0xa5);
}

/* ---- region_free: references, leases, and liveness all gate reuse ----------- */
static void test_region_free(void **state)
{
	(void)state;
	/* All regions unreferenced and no live proc → every region is free. */
	assert_true(region_free(0));
	assert_true(region_free(1));

	/* A transaction-leased region is not free. */
	g_regions[1].lease_owner = (lxp_slot_ref_t){.index = 3, .generation = 1};
	assert_false(region_free(1));
	g_regions[1].lease_owner = lxp_slot_ref_none();

	/* Accounting says free, but a live proc still runs there: the
	 * anti-trample guard must fail closed. */
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.mm->region.index = 2;
	assert_false(region_free(2));

	/* A dead proc's stale region entry does not hold the region. */
	g_lxp_slots[0].proc.alive = 0;
	assert_true(region_free(2));
}

static void test_shared_region_lives_until_last_task_reference(void **state)
{
	(void)state;
	lxp_proc_t *leader = &g_lxp_slots[0].proc;
	lxp_proc_t *thread = &g_lxp_slots[1].proc;

	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_region_ref_t region = region_reserve(2, slot_ref_at(0));
	assert_int_equal(region.index, 2);
	assert_int_equal(region_commit_address_space(region, slot_ref_at(0)), LXP_OK);
	leader->alive = 1;
	leader->mm->region = region;
	assert_int_equal(region_get(region), 0);
	lxp_proc_mm_put(thread);
	assert_int_equal(lxp_proc_mm_fork(thread, leader, LXP_CLONE_VM), 0);
	thread->alive = 1;
	assert_ptr_equal(thread->mm, leader->mm);
	g_lxp_slots[0].host_state = SLOT_PARKED;
	g_lxp_slots[1].host_state = SLOT_PARKED;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	proc_mm_put(leader);
	leader->alive = 0;
	g_lxp_slots[0].host_state = SLOT_FREE;
	assert_int_equal(g_regions[2].refs, 1);
	assert_int_equal(g_regions[2].lease_owner.index, -1);
	assert_false(region_free(2));
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	proc_mm_put(thread);
	thread->alive = 0;
	g_lxp_slots[1].host_state = SLOT_FREE;
	assert_int_equal(g_regions[2].refs, 0);
	assert_int_equal(g_regions[2].lease_owner.index, -1);
	assert_true(region_free(2));
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_thread_group_exit_marks_every_peer(void **state)
{
	(void)state;
	for (int s = 0; s < 3; s++) {
		g_lxp_slots[s].proc.alive = 1;
		g_lxp_slots[s].proc.pid = 10 + s;
		g_lxp_slots[s].proc.group->tgid = s < 2 ? 10 : 12;
	}
	lxp_proc_group_put(&g_lxp_slots[1].proc);
	assert_int_equal(lxp_proc_group_fork(&g_lxp_slots[1].proc, &g_lxp_slots[0].proc,
					     LXP_CLONE_THREAD, 11),
			 0);

	assert_int_equal(thread_group_live_count(g_lxp_slots[0].proc.group), 2);
	thread_group_request_exit(1, 37);
	assert_int_equal(g_lxp_slots[0].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_slots[1].proc.intent.kind, LXP_INTENT_EXIT);
	assert_true(g_lxp_slots[0].proc.intent.data.exit.group);
	assert_int_equal(g_lxp_slots[0].proc.exit_status, 37);
	assert_int_equal(g_lxp_slots[2].proc.intent.kind, LXP_INTENT_NONE);
}

/* Group exit and CLONE_VM must compose: the first reaped thread drops exactly
 * one address-space reference and the region remains unavailable until its
 * final peer commits exit. */
static void test_group_exit_releases_shared_address_space_last(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	make_valid_running_slot(1, 1);
	lxp_proc_t *leader = &g_lxp_slots[0].proc;
	lxp_proc_t *thread = &g_lxp_slots[1].proc;
	leader->pid = 10;
	leader->group->tgid = 10;
	thread->pid = 11;

	proc_mm_put(thread);
	assert_int_equal(region_get(leader->mm->region), LXP_OK);
	assert_int_equal(lxp_proc_mm_fork(thread, leader, LXP_CLONE_VM), LXP_OK);
	lxp_proc_group_put(thread);
	assert_int_equal(lxp_proc_group_fork(thread, leader, LXP_CLONE_THREAD, 11), LXP_OK);
	assert_ptr_equal(thread->mm, leader->mm);
	assert_ptr_equal(thread->group, leader->group);
	assert_int_equal(g_regions[0].refs, 2);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);

	assert_int_equal(lxp_intent_exit(thread, 1), LXP_OK);
	thread->exit_status = 37;
	primary_slot_clear(1);
	(void)lxp_handle_exit(&g_mock_eng, 1);
	assert_false(thread->alive);
	assert_true(leader->alive);
	assert_int_equal(leader->intent.kind, LXP_INTENT_EXIT);
	assert_true(leader->intent.data.exit.group);
	assert_int_equal(g_regions[0].refs, 1);
	assert_false(region_free(0));
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);

	primary_slot_clear(0);
	(void)lxp_handle_exit(&g_mock_eng, 0);
	assert_false(leader->alive);
	assert_int_equal(g_regions[0].refs, 0);
	assert_true(region_free(0));
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_exec_stops_only_thread_group_peers(void **state)
{
	(void)state;
	for (int s = 0; s < 3; s++) {
		g_lxp_slots[s].proc.alive = 1;
		g_lxp_slots[s].proc.pid = 10 + s;
		g_lxp_slots[s].proc.group->tgid = s < 2 ? 10 : 12;
		g_lxp_slots[s].runnable = 1;
		g_lxp_slots[s].host_state = SLOT_RUNNING;
	}
	lxp_proc_group_put(&g_lxp_slots[1].proc);
	assert_int_equal(lxp_proc_group_fork(&g_lxp_slots[1].proc, &g_lxp_slots[0].proc,
					     LXP_CLONE_THREAD, 11),
			 0);

	thread_group_stop_exec_peers(&g_mock_eng, 0, 127);
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_lxp_slots[1].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_slots[1].proc.exit_status, 127);
	assert_int_equal(g_lxp_slots[1].runnable, 0);
	assert_int_equal(g_lxp_slots[0].proc.intent.kind, LXP_INTENT_NONE);
	assert_int_equal(g_lxp_slots[2].proc.intent.kind, LXP_INTENT_NONE);
}

/* ---- device mappings: each process owns two independently tracked ranges --- */
static void test_device_map_index_tracks_both_ranges(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;

	assert_int_equal(device_map_index(p, 0x1000u, 0x100u), 0);
	p->mm->dev_map_lo[0] = 0x1000u;
	p->mm->dev_map_hi[0] = 0x1100u;
	assert_int_equal(device_map_index(p, 0x1000u, 0x200u), 0);

	assert_int_equal(device_map_index(p, 0x2000u, 0x100u), 1);
	p->mm->dev_map_lo[1] = 0x2000u;
	p->mm->dev_map_hi[1] = 0x2100u;
	assert_int_equal(device_map_index(p, 0x3000u, 0x100u), -LXP_ENOMEM);

	assert_int_equal(device_map_index(p, 0x3000u, 0), -LXP_EINVAL);
	assert_int_equal(device_map_index(p, UINTPTR_MAX - 7u, 8u), -LXP_EINVAL);
}

static void test_device_maps_follow_shared_address_space(void **state)
{
	(void)state;
	lxp_proc_t *leader = &g_lxp_slots[0].proc;
	lxp_proc_t *thread = &g_lxp_slots[1].proc;
	leader->alive = 1;
	thread->alive = 1;
	lxp_proc_mm_put(thread);
	assert_int_equal(lxp_proc_mm_fork(thread, leader, LXP_CLONE_VM), 0);

	leader->mm->dev_map_lo[0] = 0x1000u;
	leader->mm->dev_map_hi[0] = 0x1100u;
	leader->mm->dev_map_attrs[0] = LXP_MAP_WT;

	/* A newly-created engine task reconstructs every inherited logical map. */
	assert_int_equal(coordinator_restore_mm_maps(&g_mock_eng, 1, thread->mm), 0);
	assert_int_equal(g_mock.map_calls, 2);
	assert_int_equal(g_mock.map_sidx[0], 1);
	assert_int_equal(g_mock.map_size[0], 0);
	assert_int_equal(g_mock.map_addr[1], 0x1000u);
	assert_int_equal(g_mock.map_size[1], 0x100u);
	assert_int_equal(g_mock.map_attrs[1], LXP_MAP_WT);

	/* A partial peer update rolls every task back to the committed mm. */
	g_mock.map_calls = 0;
	g_mock.map_fail_slot = 1;
	assert_int_equal(coordinator_map_mm_range(&g_mock_eng, leader->mm, 0x2000u, 0x80u,
						  LXP_MAP_NC),
			 -LXP_ENOMEM);
	assert_int_equal(g_mock.map_calls, 6);
	assert_int_equal(g_mock.map_sidx[0], 0);
	assert_int_equal(g_mock.map_sidx[1], 1);
	assert_int_equal(g_mock.map_size[2], 0);
	assert_int_equal(g_mock.map_addr[3], 0x1000u);
	assert_int_equal(g_mock.map_size[4], 0);
	assert_int_equal(g_mock.map_addr[5], 0x1000u);
	assert_int_equal(leader->mm->dev_map_lo[1], 0);

	/* Once every task accepts it, the caller can commit the logical range. */
	g_mock.map_calls = 0;
	assert_int_equal(
		coordinator_map_mm_range(&g_mock_eng, leader->mm, 0x2000u, 0x80u, LXP_MAP_NC), 0);
	assert_int_equal(g_mock.map_calls, 2);
	assert_int_equal(g_mock.map_sidx[0], 0);
	assert_int_equal(g_mock.map_sidx[1], 1);
}

static void test_teardown_releases_every_slot_resource(void **state)
{
	(void)state;
	const int s = 2;
	deferred_slot_reassign(s);
	lxp_slot_ref_t owner = slot_ref_at(s);
	lxp_proc_t *p = &g_lxp_slots[s].proc;
	p->alive = 1;
	p->mm->region = region_reserve(1, owner);
	p->snapshot = region_reserve(2, owner);
	g_lxp_slots[s].runnable = 1;
	g_lxp_slots[s].host_state = SLOT_RUNNING;
	assert_non_null(lxp_fd_description(p, 0));

	coordinator_teardown_all(&g_mock_eng);

	assert_int_equal(g_mock.abort_calls, LXP_NSLOT);
	assert_false(p->alive);
	assert_false(g_lxp_slots[s].runnable);
	assert_null(lxp_fd_description(p, 0));
	for (int r = 0; r < LXP_NREG; r++) {
		assert_int_equal(g_regions[r].lease_owner.index, -1);
		assert_int_equal(g_regions[r].refs, 0);
	}
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_teardown_quiesces_before_releasing_resources(void **state)
{
	(void)state;
	const int s = 2;
	deferred_slot_reassign(s);
	lxp_slot_ref_t owner = slot_ref_at(s);
	lxp_proc_t *p = &g_lxp_slots[s].proc;
	p->alive = 1;
	p->mm->region = region_reserve(1, owner);
	g_lxp_slots[s].runnable = 1;
	g_lxp_slots[s].host_state = SLOT_RUNNING;
	g_mock.abort_failures = 1;
	g_mock.abort_fail_slot = s;
	g_mock.observe_wait_slot = s;
	lxp_trap_publish(1);

	coordinator_teardown_all(&g_mock_eng);

	assert_int_equal(g_mock.abort_calls, LXP_NSLOT + 1);
	assert_int_equal(g_mock.event_wait_calls, 1);
	assert_true(g_mock.wait_observed_alive);
	assert_int_equal(g_mock.wait_observed_region_refs, 1);
	assert_true(g_mock.wait_observed_trap_active);
	assert_false(lxp_trap_active());
	assert_false(p->alive);
	assert_int_equal(g_regions[1].refs, 0);
}

static void test_spawn_callbacks_receive_explicit_mode_and_published_slot(void **state)
{
	(void)state;
	struct lxp_resume_ctx ctx;
	lxp_flat_t prog;
	memset(&ctx, 0, sizeof(ctx));
	memset(&prog, 0, sizeof(prog));

	/* A fresh image launch observes its dispatch capability before the mock
	 * engine can make a native task runnable. */
	const int launch_slot = 1;
	deferred_slot_reassign(launch_slot);
	g_lxp_slots[launch_slot].proc.alive = 1;
	uint32_t launch_generation = slot_generation(launch_slot);
	assert_int_equal(coordinator_launch_slot(&g_mock_eng, launch_slot, 0, &prog,
						 (void *)1, (void *)2, (void *)3),
			 LXP_OK);
	assert_int_equal(g_mock.launch_calls, 1);
	assert_int_equal(g_mock.launch_sidx, launch_slot);
	assert_int_equal(g_mock.launch_generation, launch_generation);
	assert_true(g_mock.launch_observed_runnable);
	assert_int_equal(g_mock.launch_observed_host_state, SLOT_STARTING);
	assert_int_equal(g_lxp_slots[launch_slot].host_state, SLOT_RUNNING);

	/* A captured fork child has no native task yet and is explicitly START,
	 * rather than being inferred from the absence of a handle. */
	const int start_slot = 2;
	deferred_slot_reassign(start_slot);
	g_lxp_slots[start_slot].proc.alive = 1;
	uint32_t start_generation = slot_generation(start_slot);
	assert_int_equal(coordinator_resume_slot(&g_mock_eng, start_slot, 0, &ctx, 7),
			 LXP_OK);
	assert_int_equal(g_mock.resume_mode, LXP_SPAWN_RESUME_START);
	assert_int_equal(g_mock.resume_generation, start_generation);
	assert_true(g_mock.resume_observed_runnable);
	assert_int_equal(g_mock.resume_observed_host_state, SLOT_STARTING);
	assert_int_equal(g_lxp_slots[start_slot].host_state, SLOT_RUNNING);

	/* A task suspended by park_slot is explicitly PARKED and sees the same
	 * pre-published dispatch capability before the engine wakes it. */
	const int parked_slot = 3;
	make_valid_running_slot(parked_slot, 3);
	assert_int_equal(coordinator_park_slot(&g_mock_eng, parked_slot), LXP_OK);
	uint32_t parked_generation = slot_generation(parked_slot);
	assert_int_equal(coordinator_resume_slot(&g_mock_eng, parked_slot, 3, &ctx, 9),
			 LXP_OK);
	assert_int_equal(g_mock.resume_mode, LXP_SPAWN_RESUME_PARKED);
	assert_int_equal(g_mock.resume_generation, parked_generation);
	assert_true(g_mock.resume_observed_runnable);
	assert_int_equal(g_mock.resume_observed_host_state, SLOT_RESUMING);
	assert_int_equal(g_lxp_slots[parked_slot].host_state, SLOT_RUNNING);
}

static void test_park_failure_aborts_and_kills_slot(void **state)
{
	(void)state;
	const int s = 2;
	lxp_proc_t *p = &g_lxp_slots[s].proc;
	p->alive = 1;
	g_lxp_slots[s].runnable = 1;
	g_lxp_slots[s].host_state = SLOT_RUNNING;
	deferred_slot_reassign(s);
	uint32_t generation = g_lxp_slots[s].generation;
	g_mock.park_failures = 1;

	assert_int_equal(coordinator_park_slot(&g_mock_eng, s), -LXP_EIO);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.park_generation, generation);
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_mock.abort_generation, generation);
	assert_int_equal(g_lxp_slots[s].host_state, SLOT_DEAD);
	assert_false(g_lxp_slots[s].runnable);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_reason, LXP_EXIT_REASON_HOST_TRANSITION);
	assert_true(primary_slot_pending(s));
}

static void test_resume_failure_aborts_parked_slot(void **state)
{
	(void)state;
	const int s = 3;
	lxp_proc_t *p = &g_lxp_slots[s].proc;
	p->alive = 1;
	g_lxp_slots[s].host_state = SLOT_PARKED;
	deferred_slot_reassign(s);
	uint32_t generation = g_lxp_slots[s].generation;
	g_mock.resume_failures = 1;

	assert_int_equal(coordinator_resume_slot(&g_mock_eng, s, 0, &g_lxp_slots[s].resume, 42),
			 -LXP_EIO);
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_generation, generation);
	assert_int_equal(g_mock.resume_mode, LXP_SPAWN_RESUME_PARKED);
	assert_true(g_mock.resume_observed_runnable);
	assert_int_equal(g_mock.resume_observed_host_state, SLOT_RESUMING);
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_mock.abort_generation, generation);
	assert_int_equal(g_lxp_slots[s].host_state, SLOT_DEAD);
	assert_false(g_lxp_slots[s].runnable);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_reason, LXP_EXIT_REASON_HOST_TRANSITION);
}

static void test_abort_failure_retains_slot_until_retry(void **state)
{
	(void)state;
	const int s = 4;
	lxp_proc_t *p = &g_lxp_slots[s].proc;
	p->alive = 1;
	g_lxp_slots[s].runnable = 1;
	g_lxp_slots[s].host_state = SLOT_RUNNING;
	deferred_slot_reassign(s);
	uint32_t generation = g_lxp_slots[s].generation;
	g_mock.abort_failures = 1;

	assert_int_equal(coordinator_abort_slot(&g_mock_eng, s), -LXP_EIO);
	assert_int_equal(g_lxp_slots[s].host_state, SLOT_FAILED);
	assert_true(g_lxp_slots[s].runnable);
	assert_true(p->alive);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_reason, LXP_EXIT_REASON_HOST_TRANSITION);
	assert_int_equal(g_mock.abort_generation, generation);

	assert_int_equal(coordinator_abort_slot(&g_mock_eng, s), LXP_OK);
	assert_int_equal(g_lxp_slots[s].host_state, SLOT_DEAD);
	assert_false(g_lxp_slots[s].runnable);
	assert_true(p->alive); /* Linux ownership is released only by EV_EXIT. */
}

/* ---- futex: co-runner gate + FUTEX_WAKE bookkeeping ------------------------- */
/* futex_has_corunner: a FUTEX_WAIT only parks when another live thread shares the region
 * (else nobody could ever wake it). */
static void test_futex_has_corunner(void **state)
{
	(void)state;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.mm->region.index = 2;
	assert_false(futex_has_corunner(&g_lxp_slots[0].proc)); /* alone in region 2 */

	g_lxp_slots[1].proc.alive = 1;
	g_lxp_slots[1].proc.mm->region.index = 3;
	assert_false(
		futex_has_corunner(&g_lxp_slots[0].proc)); /* a live proc, but a different region */

	lxp_proc_mm_put(&g_lxp_slots[2].proc);
	assert_int_equal(lxp_proc_mm_fork(&g_lxp_slots[2].proc, &g_lxp_slots[0].proc, LXP_CLONE_VM),
			 0);
	g_lxp_slots[2].proc.alive = 1;
	assert_true(futex_has_corunner(&g_lxp_slots[0].proc)); /* a co-runner shares the mm */

	g_lxp_slots[2].proc.alive = 0;
	assert_false(
		futex_has_corunner(&g_lxp_slots[0].proc)); /* it exited -> no longer a co-runner */
}

/* FUTEX_WAKE marks up to `val` waiters queued on the same uaddr (and no others). The
 * addresses here are only compared, never dereferenced, so plain integers stand in for the
 * 32-bit guest pointers (the deref path is covered on-target by the M5 QEMU guest). */
static void test_futex_wake_marks_waiters(void **state)
{
	(void)state;
	const uint32_t uaddr = 0x2000, other = 0x3000;
	g_lxp_slots[1].proc.alive = 1;
	g_lxp_slots[1].proc.wait.kind = LXP_WAIT_FUTEX;
	g_lxp_slots[1].proc.wait.data.futex.uaddr = uaddr;
	g_lxp_slots[2].proc.alive = 1;
	g_lxp_slots[2].proc.wait.kind = LXP_WAIT_FUTEX;
	g_lxp_slots[2].proc.wait.data.futex.uaddr = uaddr;
	g_lxp_slots[3].proc.alive = 1;
	g_lxp_slots[3].proc.wait.kind = LXP_WAIT_FUTEX;
	g_lxp_slots[3].proc.wait.data.futex.uaddr = other;

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[0] = uaddr;
	f.r[1] = 1; /* FUTEX_WAKE */
	f.r[2] = 1; /* wake at most one */
	lxp_futex(&f, &g_lxp_slots[0].proc, 0);

	assert_int_equal(f.r[0], 1); /* reported one woken */
	assert_int_equal(g_lxp_slots[1].proc.wait.data.futex.woken +
				 g_lxp_slots[2].proc.wait.data.futex.woken,
			 1);
	assert_int_equal(g_lxp_slots[3].proc.wait.data.futex.woken, 0);

	/* A second WAKE(all) picks up the remaining waiter on uaddr, still not the other. */
	memset(&f, 0, sizeof(f));
	f.r[0] = uaddr;
	f.r[1] = 1;
	f.r[2] = 0x7fffffff;
	lxp_futex(&f, &g_lxp_slots[0].proc, 0);
	assert_int_equal(f.r[0], 1); /* the one still-parked waiter */
	assert_int_equal(g_lxp_slots[1].proc.wait.data.futex.woken, 1);
	assert_int_equal(g_lxp_slots[2].proc.wait.data.futex.woken, 1);
	assert_int_equal(g_lxp_slots[3].proc.wait.data.futex.woken, 0);
}

/* pending_deliverable returns the lowest-numbered UNBLOCKED pending signal and leaves blocked
 * ones set — so the mask is honored (a blocked signal is deferred, #4) and no pending signal is
 * lost to a single slot when another arrives (#5). SIGKILL/SIGSTOP are never blocked. */
static void test_pending_deliverable(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->sig_blocked = lxp_sig_bit(LXP_SIGTERM); /* SIGTERM blocked, SIGINT not */
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM) | lxp_sig_bit(LXP_SIGINT);
	assert_int_equal(pending_deliverable(p), LXP_SIGINT); /* skips the blocked SIGTERM */

	p->pending_sigs &= ~lxp_sig_bit(LXP_SIGINT); /* consume SIGINT */
	assert_int_equal(pending_deliverable(p), 0); /* SIGTERM still blocked -> nothing */
	assert_true(p->pending_sigs & lxp_sig_bit(LXP_SIGTERM)); /* ...but not lost */
	p->sig_blocked = 0;
	assert_int_equal(pending_deliverable(p), LXP_SIGTERM); /* unblocked -> now deliverable */

	p->sig_blocked = (uint64_t)-1; /* even a full mask cannot block SIGKILL */
	p->pending_sigs = lxp_sig_bit(LXP_SIGKILL);
	assert_int_equal(pending_deliverable(p), LXP_SIGKILL);

	p->pending_sigs = 0;
	assert_int_equal(pending_deliverable(p), 0); /* empty set */
}

/* lxp_dispatch used to read TCSETS' arg before lxp_syscall reached the console handler. Because
 * dispatch runs privileged, a guest could point it at host memory or MMIO and fault the RTOS even
 * if the handler itself performed access_ok. Keep this at the trap-dispatch level, not merely in
 * the direct-syscall conformance suite. */
static void test_dispatch_rejects_bad_tcsets_pointer(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_slots[0].proc;
	proc->mm->region_lo = 0x1000u;
	proc->mm->region_hi = 0x2000u;
	proc->mm->pool_lo = proc->mm->pool_hi = 0;

	const uint32_t cmds[] = {LXP_TCSETS, LXP_TCSETSW, LXP_TCSETSF};
	for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
		struct lxp_frame f;
		memset(&f, 0, sizeof(f));
		f.r[0] = 0; /* stdin is a console fd */
		f.r[1] = cmds[i];
		f.r[2] = 0x20000000u; /* mapped host SRAM on target; outside this guest */
		f.r[7] = LXP_NR_ioctl;
		g_tty_isig = 1;
		g_tty_icrnl = 1;
		g_lxp_slots[0].runnable = 1;
		g_lxp_slots[0].host_state = SLOT_RUNNING;

		assert_int_equal(lxp_dispatch_slot(slot_ref_at(0), &f), LXP_OK);

		assert_int_equal(deferred_state_load(0), DEFER_READY);
		assert_int_equal(g_mock.event_posts, (int)i + 1);
		execute_deferred(&g_mock_eng, 0);
		assert_int_equal(g_mock.resume_r0, -LXP_EFAULT);
		assert_int_equal(g_tty_isig, 1); /* invalid input cannot alter console state */
		assert_int_equal(g_tty_icrnl, 1);
	}
}

/* The board transport supplies CR for Enter because BusyBox's raw shell editor expects
 * it.  A cooked tty advertising ICRNL must instead give applications LF: login's retry
 * path uses fgets(), which otherwise consumes the second username forever waiting for
 * a newline.  When a guest clears ICRNL, the transport byte must be preserved. */
static void test_console_icrnl_translation(void **state)
{
	(void)state;
	g_tty_icrnl = 1;
	assert_int_equal(lxp_console_input_xlate('\r'), '\n');
	assert_int_equal(lxp_console_input_xlate('x'), 'x');
	assert_int_equal(lxp_console_input_xlate('\n'), '\n');

	g_tty_icrnl = 0;
	assert_int_equal(lxp_console_input_xlate('\r'), '\r');
}

/* Pointer-free identity calls stay in the bounded top half; unknown/new calls
 * default to the deferred mailbox and therefore cannot accidentally run in SVC. */
static void test_dispatch_class_defaults_deferred(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->pid = 42;
	p->group->tgid = 42;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpid;
	assert_int_equal(lxp_dispatch_slot(slot_ref_at(0), &f), LXP_OK);
	assert_int_equal(f.r[0], 42);
	assert_int_equal(g_mock.event_posts, 0);
	assert_int_equal(deferred_state_load(0), DEFER_IDLE);

	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	f.xpsr = 0xa8000000u | (1u << 24); /* NZCV + Thumb survive task recreation */
	struct lxp_fp_context fp;
	memset(&fp, 0, sizeof(fp));
	for (int i = 0; i < 32; i++)
		fp.s[i] = 0x3f000000u + (uint32_t)i;
	fp.fpscr = 0x01c00000u;
	fp.active = 1;
	f.fp = &fp;
	g_lxp_slots[0].runnable = 1;
	g_lxp_slots[0].host_state = SLOT_RUNNING;
	assert_int_equal(lxp_dispatch_slot(slot_ref_at(0), &f), LXP_OK);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	assert_int_equal(g_mock.event_posts, 1);
	execute_deferred(&g_mock_eng, 0);
	assert_int_equal(g_mock.resume_r0, -LXP_ENOSYS);
	assert_int_equal(g_mock.coord_map_calls, 1);
	assert_int_equal(g_mock.coord_map_region, 0);
	assert_null(p->guest_view);
	assert_int_equal(g_mock.resume_xpsr, f.xpsr);
	assert_memory_equal(&g_mock.resume_fp, &fp, sizeof(fp));
}

/* Distinct slots have distinct fixed mailboxes. Both may queue while neither
 * bottom half has completed; servicing one cannot overwrite or lose the other. */
static void test_deferred_requests_are_per_slot(void **state)
{
	(void)state;
	for (int s = 0; s < 2; s++) {
		make_valid_running_slot(s, s);
		g_lxp_slots[s].proc.pid = s + 1;
		struct lxp_frame f;
		memset(&f, 0, sizeof(f));
		f.r[7] = 900u + (uint32_t)s;
		assert_int_equal(lxp_dispatch_slot(slot_ref_at(s), &f), LXP_OK);
	}
	assert_int_equal(g_mock.event_posts, 2);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	assert_int_equal(deferred_state_load(1), DEFER_READY);

	execute_deferred(&g_mock_eng, 1);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	assert_int_equal(deferred_state_load(1), DEFER_IDLE);
	execute_deferred(&g_mock_eng, 0);
	assert_int_equal(g_mock.resume_calls, 2);
	assert_int_equal(g_mock.resume_order[0], 1);
	assert_int_equal(g_mock.resume_order[1], 0);
}

/* A stale event from an old slot generation is discarded without aborting or
 * resuming the new occupant of that slot. */
static void test_deferred_generation_rejects_stale_work(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	lxp_dispatch(&f, p);
	lxp_slot_ref_t old_owner = g_lxp_slots[0].deferred.owner;
	deferred_slot_reassign(0);
	g_lxp_slots[0].deferred.owner = old_owner;
	deferred_state_store(0, DEFER_READY); /* delayed event from the prior occupant */
	g_lxp_slots[0].runnable = 1;
	g_lxp_slots[0].host_state = SLOT_RUNNING;

	execute_deferred(&g_mock_eng, 0);

	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_slots[0].runnable, 1); /* the replacement task was untouched */
}

/* One slot cannot overwrite its outstanding request, even if a broken seam
 * attempts to dispatch that slot again before the bottom half claims it. */
static void test_deferred_same_slot_rejects_overwrite(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->alive = 1;
	deferred_slot_reassign(0);
	struct lxp_frame first, second;
	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	first.r[7] = 998;
	second.r[7] = 999;
	lxp_dispatch(&first, p);
	lxp_dispatch(&second, p);
	assert_int_equal((int32_t)second.r[0], -LXP_EAGAIN);
	assert_int_equal(g_mock.event_posts, 1);
	assert_int_equal((int32_t)g_lxp_slots[0].resume.r4_11[3], 998);
}

/* A deliverable signal queued before resource acquisition cancels deferred work.
 * Default SIGTERM kills the guest without ever executing or resuming its syscall. */
static void test_deferred_signal_cancels_before_execute(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = 999;
	assert_int_equal(lxp_dispatch_slot(slot_ref_at(0), &f), LXP_OK);
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM);

	execute_deferred(&g_mock_eng, 0);

	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_status, 128 + LXP_SIGTERM);
}

/* A signal owns cancellation of an in-flight netfs wait before the generic
 * retry pass sees it. The late transport reply is covered by the netfs suite;
 * this crossing proves the coordinator cannot resume a killed guest first. */
static void test_signal_interrupts_blocked_netfs_before_retry(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	assert_int_equal(lxp_wait_begin(p, &(lxp_wait_t){
						 .kind = LXP_WAIT_NETFS,
						 .data.io.request = -1,
					 }),
			 LXP_OK);
	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
	p->pending_sigs = lxp_sig_bit(LXP_SIGTERM);

	struct lxp_blocked_scan scan = lxp_scan_blocked(&g_mock_eng, &g_mock_cfg, 1);

	assert_true(scan.progress);
	assert_int_equal(p->wait.kind, LXP_WAIT_NONE);
	assert_int_equal(p->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p->exit_status, 128 + LXP_SIGTERM);
	assert_true(primary_slot_pending(0));
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_slots[0].host_state, SLOT_PARKED);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

/*
 * A remote exec creates its EXEC intent in the coordinator only after the 9P
 * fetch completes. It has no SVC return path to publish that primary event.
 */
static void test_netfs_exec_completion_publishes_primary_event(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
	p->intent.kind = LXP_INTENT_EXEC;
	struct lxp_blocked_scan scan = {0};

	assert_false(primary_slot_pending(0));
	lxp_blocked_complete_netfs_retry(&g_mock_eng, 0, p, 0, &scan);

	assert_true(scan.progress);
	assert_true(primary_slot_pending(0));
	assert_int_equal(claim_slot_event(0), LXP_EV_EXEC);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_slots[0].host_state, SLOT_PARKED);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

/* exec's commit changes the slot incarnation. A deferred event captured before
 * that boundary must be rejected even if it becomes visible after commit. */
static void test_exec_commit_discards_older_deferred_request(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	struct lxp_frame frame;
	memset(&frame, 0, sizeof(frame));
	frame.r[7] = 999;
	assert_int_equal(lxp_dispatch_slot(slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal(deferred_state_load(0), DEFER_READY);
	lxp_slot_ref_t stale_owner = g_lxp_slots[0].deferred.owner;

	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
	uint8_t image[128];
	struct exec_txn tx;
	exec_txn_init(&tx, 0);
	assert_int_equal(exec_txn_reserve(&tx), LXP_OK);
	assert_int_equal(exec_txn_validate_image(&tx, image, build_coord_fdpic(image), 0),
			 LXP_OK);
	assert_int_equal(exec_txn_commit(&tx, &g_mock_eng), LXP_OK);
	assert_false(lxp_slot_ref_equal(stale_owner, slot_ref_at(0)));
	assert_int_equal(deferred_state_load(0), DEFER_IDLE);

	g_lxp_slots[0].deferred.owner = stale_owner;
	deferred_state_store(0, DEFER_READY);
	int resumes = g_mock.resume_calls;
	int aborts = g_mock.abort_calls;
	execute_deferred(&g_mock_eng, 0);
	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.resume_calls, resumes);
	assert_int_equal(g_mock.abort_calls, aborts);

	exec_txn_abort(&tx, &g_mock_eng, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

/* Reaping and then reusing a slot is a stronger boundary than merely advancing
 * its mailbox generation: no late completion may touch the new process. */
static void test_reused_slot_ignores_late_completion_from_dead_generation(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	struct lxp_frame frame;
	memset(&frame, 0, sizeof(frame));
	frame.r[7] = 999;
	assert_int_equal(lxp_dispatch_slot(slot_ref_at(0), &frame), LXP_OK);
	lxp_slot_ref_t stale_owner = g_lxp_slots[0].deferred.owner;

	lxp_proc_t *old = &g_lxp_slots[0].proc;
	assert_int_equal(lxp_intent_exit(old, 0), LXP_OK);
	old->exit_status = 0;
	primary_slot_clear(0);
	(void)lxp_handle_exit(&g_mock_eng, 0);
	assert_false(old->alive);
	assert_int_equal(g_regions[0].refs, 0);

	assert_int_equal(lxp_proc_init(old, &g_mock_arenas[0], 0), LXP_OK);
	make_valid_running_slot(0, 0);
	lxp_slot_ref_t replacement = slot_ref_at(0);
	assert_false(lxp_slot_ref_equal(stale_owner, replacement));
	int resumes = g_mock.resume_calls;
	int aborts = g_mock.abort_calls;

	g_lxp_slots[0].deferred.owner = stale_owner;
	deferred_state_store(0, DEFER_READY);
	execute_deferred(&g_mock_eng, 0);

	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_true(lxp_slot_ref_equal(replacement, slot_ref_at(0)));
	assert_true(g_lxp_slots[0].proc.alive);
	assert_true(g_lxp_slots[0].runnable);
	assert_int_equal(g_mock.resume_calls, resumes);
	assert_int_equal(g_mock.abort_calls, aborts);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

enum protocol_command {
	PROTOCOL_PARK_TIMER,
	PROTOCOL_TIMEOUT,
	PROTOCOL_SIGNAL_TERM,
	PROTOCOL_EXIT_COMMIT,
	PROTOCOL_REUSE_SLOT,
	PROTOCOL_STALE_COMPLETION,
	PROTOCOL_COMMAND_COUNT,
};

enum protocol_phase {
	PROTOCOL_RUNNING,
	PROTOCOL_PARKED,
	PROTOCOL_EXIT_PENDING,
	PROTOCOL_DEAD,
	PROTOCOL_REUSED,
};

struct protocol_model {
	enum protocol_phase phase;
	lxp_slot_ref_t first_owner;
};

static int protocol_apply(struct protocol_model *model, enum protocol_command command)
{
	lxp_proc_t *proc = &g_lxp_slots[0].proc;

	switch (command) {
	case PROTOCOL_PARK_TIMER:
		if (model->phase != PROTOCOL_RUNNING)
			return 0;
		assert_int_equal(lxp_wait_begin(proc, &(lxp_wait_t){
							 .kind = LXP_WAIT_TIMER,
							 .data.timer.deadline_us = 10,
						 }),
				 LXP_OK);
		assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);
		model->phase = PROTOCOL_PARKED;
		break;
	case PROTOCOL_TIMEOUT:
		if (model->phase != PROTOCOL_PARKED)
			return 0;
		assert_int_equal(lxp_wait_timeout(proc, LXP_WAIT_TIMER), LXP_OK);
		assert_int_equal(coordinator_resume_slot(&g_mock_eng, 0, 0,
							&g_lxp_slots[0].resume, 0),
				 LXP_OK);
		model->phase = PROTOCOL_RUNNING;
		break;
	case PROTOCOL_SIGNAL_TERM:
		if (model->phase != PROTOCOL_PARKED)
			return 0;
		proc->pending_sigs = lxp_sig_bit(LXP_SIGTERM);
		assert_true(lxp_scan_blocked(&g_mock_eng, &g_mock_cfg, 1).progress);
		assert_int_equal(proc->wait.kind, LXP_WAIT_NONE);
		assert_int_equal(proc->intent.kind, LXP_INTENT_EXIT);
		model->phase = PROTOCOL_EXIT_PENDING;
		break;
	case PROTOCOL_EXIT_COMMIT:
		if (model->phase != PROTOCOL_EXIT_PENDING)
			return 0;
		primary_slot_clear(0);
		(void)lxp_handle_exit(&g_mock_eng, 0);
		assert_false(proc->alive);
		model->phase = PROTOCOL_DEAD;
		break;
	case PROTOCOL_REUSE_SLOT:
		if (model->phase != PROTOCOL_DEAD)
			return 0;
		assert_int_equal(lxp_proc_init(proc, &g_mock_arenas[0], 0), LXP_OK);
		make_valid_running_slot(0, 0);
		model->phase = PROTOCOL_REUSED;
		break;
	case PROTOCOL_STALE_COMPLETION:
		if (model->phase != PROTOCOL_REUSED)
			return 0;
		g_lxp_slots[0].deferred.owner = model->first_owner;
		deferred_state_store(0, DEFER_READY);
		execute_deferred(&g_mock_eng, 0);
		assert_int_equal(deferred_state_load(0), DEFER_IDLE);
		assert_true(g_lxp_slots[0].runnable);
		break;
	default:
		fail_msg("invalid protocol command %d", command);
	}
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
	return 1;
}

/* Enumerate every five-command word over the lifecycle alphabet. Illegal
 * transitions stop that word; every transition which is applied is checked
 * against the independent world validator immediately. */
static void test_generated_protocol_sequences_preserve_world(void **state)
{
	(void)state;
	enum { PROTOCOL_DEPTH = 5 };
	unsigned coverage = 0;
	unsigned words = 1;
	for (int i = 0; i < PROTOCOL_DEPTH; i++)
		words *= PROTOCOL_COMMAND_COUNT;

	for (unsigned word = 0; word < words; word++) {
		assert_int_equal(reset_state(NULL), 0);
		make_valid_running_slot(0, 0);
		assert_int_equal(lxp_validate_world(NULL), LXP_OK);
		struct protocol_model model = {
			.phase = PROTOCOL_RUNNING,
			.first_owner = slot_ref_at(0),
		};
		unsigned encoded = word;
		for (int step = 0; step < PROTOCOL_DEPTH; step++) {
			enum protocol_command command = encoded % PROTOCOL_COMMAND_COUNT;
			encoded /= PROTOCOL_COMMAND_COUNT;
			if (!protocol_apply(&model, command))
				break;
			coverage |= 1u << command;
		}
	}
	assert_int_equal(coverage, (1u << PROTOCOL_COMMAND_COUNT) - 1u);
}

static int console_not_ready(void *ctx)
{
	(void)ctx;
	return 0;
}

static int console_ready(void *ctx)
{
	(void)ctx;
	return 1;
}

static long console_read_cr(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (!len)
		return 0;
	((uint8_t *)buf)[0] = '\r';
	return 1;
}

static long console_read_sigint(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (!len)
		return 0;
	((uint8_t *)buf)[0] = 3;
	return 1;
}

static void test_blocked_scan_reports_wait_policy(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_slots[0].proc;
	proc->console_poll = console_not_ready;
	assert_int_equal(lxp_wait_begin(proc, &(lxp_wait_t){
							 .kind = LXP_WAIT_CONSOLE,
							 .data.io.buffer =
								 (uintptr_t)g_mock_regions[0],
							 .data.io.length = 1,
						 }),
			 LXP_OK);
	assert_int_equal(coordinator_park_slot(&g_mock_eng, 0), LXP_OK);

	struct lxp_blocked_scan scan = lxp_scan_blocked(&g_mock_eng, &g_mock_cfg, 1);
	assert_int_equal(scan.wait_policy,
			 LXP_BLOCKED_WAIT_POLL | LXP_BLOCKED_WAIT_CONSOLE);
	assert_false(scan.progress);
}

static void test_async_console_signal_is_scan_progress(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *proc = &g_lxp_slots[0].proc;
	proc->pid = 2;
	proc->group->pgid = 2;
	lxp_console_set_fg_pgrp(2);
	const lxp_run_config_t cfg = {
		.read_fn = console_read_sigint,
		.console_poll = console_ready,
	};

	struct lxp_blocked_scan scan = lxp_scan_blocked(&g_mock_eng, &cfg, 1);
	assert_true(scan.progress);
	assert_true(proc->pending_sigs & lxp_sig_bit(LXP_SIGINT));
}

/* A byte may already be ready when read(2) enters, bypassing a console wait entirely.
 * That fast path must use the same ICRNL discipline as a coordinator-resumed read. */
static void test_console_icrnl_immediate_read(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	assert_int_equal(lxp_arena_init(&arena, g_mock_regions[0], sizeof(g_mock_regions[0])),
			 LXP_OK);
	assert_int_equal(lxp_proc_init(&p, &arena, 0), LXP_OK);
	p.mm->region_lo = 1;
	p.mm->region_hi = UINTPTR_MAX;
	p.read_fn = console_read_cr;
	p.console_poll = console_ready;

	uint8_t ch = 0;
	g_tty_icrnl = 1;
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, 0, (long)(uintptr_t)&ch, 1, 0, 0, 0), 1);
	assert_int_equal(ch, '\n');

	g_tty_icrnl = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, 0, (long)(uintptr_t)&ch, 1, 0, 0, 0), 1);
	assert_int_equal(ch, '\r');
}

/* Blocking handlers hand ownership to the existing wait state machine. The
 * coordinator suspends the existing task before executing the host syscall and
 * leaves it parked when the syscall establishes a wait condition. */
static void test_deferred_blocking_handoff_keeps_parked_task(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->console_poll = console_not_ready;

	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[0] = 0; /* no pollfd array: this is a pure timeout sleep */
	f.r[1] = 0;
	f.r[2] = 1000;
	f.r[7] = LXP_NR_poll;
	assert_int_equal(lxp_dispatch_slot(slot_ref_at(0), &f), LXP_OK);
	execute_deferred(&g_mock_eng, 0);

	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(p->wait.kind, LXP_WAIT_TIMER);
	assert_true(primary_slot_pending(0));
	assert_int_equal(g_lxp_slots[0].runnable, 0);
	assert_int_equal(g_mock.park_calls, 1);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_mock.resume_calls, 0);
}

/* kill(-pgid)/kill(0) target a PROCESS GROUP, not every proc — the fix for `kill %job` (and
 * fg's SIGCONT) no longer nuking unrelated daemons like inetd. */
static void test_kill_targets_process_group(void **state)
{
	(void)state;
	/* pid / pgid layout: init(1,1) shell(2,2) cmd1(3,3) cmd2(4,3 — cmd1's group) inetd(5,5) */
	const int pid[5] = {1, 2, 3, 4, 5};
	const int pgid[5] = {1, 2, 3, 3, 5};
	for (int i = 0; i < 5; i++) {
		g_lxp_slots[i].proc.alive = 1;
		g_lxp_slots[i].proc.pid = pid[i];
		g_lxp_slots[i].proc.group->pgid = pgid[i];
	}
	lxp_proc_t *shell = &g_lxp_slots[1].proc; /* the sender */
	const uint64_t bit = lxp_sig_bit(LXP_SIGTERM);

	/* shell: kill(-3, SIGTERM) -> process group 3 = {cmd1 pid3, cmd2 pid4} only. */
	struct lxp_frame f;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_kill;
	f.r[0] = (uint32_t)(-3); /* target = -pgid */
	f.r[1] = LXP_SIGTERM;
	lxp_dispatch(&f, shell);
	assert_int_equal((int32_t)f.r[0], 0);		      /* a target was found */
	assert_true(g_lxp_slots[2].proc.pending_sigs & bit);  /* cmd1 (pgid 3) */
	assert_true(g_lxp_slots[3].proc.pending_sigs & bit);  /* cmd2 (pgid 3) */
	assert_false(g_lxp_slots[0].proc.pending_sigs & bit); /* init untouched */
	assert_false(g_lxp_slots[1].proc.pending_sigs & bit); /* the sender itself */
	assert_false(g_lxp_slots[4].proc.pending_sigs &
		     bit); /* inetd (pgid 5) — the old broadcast bug */

	/* kill(0, SIGTERM) targets the SENDER's own group (pgid 2); put inetd in it. */
	for (int i = 0; i < 5; i++)
		g_lxp_slots[i].proc.pending_sigs = 0;
	g_lxp_slots[4].proc.group->pgid = 2;
	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_kill;
	f.r[0] = 0; /* caller's process group */
	f.r[1] = LXP_SIGTERM;
	lxp_dispatch(&f, shell);
	assert_true(g_lxp_slots[4].proc.pending_sigs & bit);  /* the group peer */
	assert_false(g_lxp_slots[2].proc.pending_sigs & bit); /* pgid 3, not in group 2 */
}

/* setpgid(0,pgid)/getpgrp track a real per-proc group; setsid makes the caller a leader. */
static void test_setpgid_getpgrp_track_group(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	p->alive = 1;
	p->pid = 7;
	p->group->pgid = 7;
	struct lxp_frame f;

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpgrp;
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 7); /* getpgrp -> current group */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_setpgid;
	f.r[0] = 0;  /* self */
	f.r[1] = 42; /* pgid */
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 0);
	assert_int_equal(p->group->pgid, 42); /* setpgid(0,42) joined group 42 */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_getpgrp;
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 42); /* getpgrp reflects it */

	memset(&f, 0, sizeof(f));
	f.r[7] = LXP_NR_setsid;
	lxp_dispatch(&f, p);
	assert_int_equal((int32_t)f.r[0], 7); /* setsid -> new session, pgid = pid */
	assert_int_equal(p->group->pgid, 7);
}

/* A console ^C raises SIGINT on the console's FOREGROUND process group only (the group
 * the shell set via tcsetpgrp/TIOCSPGRP) — the interactive shell (its own group) and any
 * background job survive. The console analog of the pty ^C: what makes a foreground
 * program interruptible from the direct console. */
static void test_console_sigint_targets_fg_group(void **state)
{
	(void)state;
	/* pid/pgid: init(1,1) shell(2,2) fg-job(3,3) fg-pipe-peer(4,3) bg-job(5,5) */
	const int pid[5] = {1, 2, 3, 4, 5};
	const int pgid[5] = {1, 2, 3, 3, 5};
	for (int i = 0; i < 5; i++) {
		g_lxp_slots[i].proc.alive = 1;
		g_lxp_slots[i].proc.pid = pid[i];
		g_lxp_slots[i].proc.group->pgid = pgid[i];
	}
	const uint64_t bit = lxp_sig_bit(LXP_SIGINT);

	/* No foreground group yet (pre-first-tcsetpgrp): ^C signals nobody. */
	lxp_console_set_fg_pgrp(0);
	console_signal_fg(LXP_SIGINT);
	for (int i = 0; i < 5; i++)
		assert_false(g_lxp_slots[i].proc.pending_sigs & bit);

	/* Shell put group 3 in the foreground: ^C hits that group only. */
	lxp_console_set_fg_pgrp(3);
	assert_int_equal(lxp_console_fg_pgrp(), 3);
	console_signal_fg(LXP_SIGINT);
	assert_true(g_lxp_slots[2].proc.pending_sigs & bit);  /* fg job (pgid 3) */
	assert_true(g_lxp_slots[3].proc.pending_sigs & bit);  /* fg pipeline peer (pgid 3) */
	assert_false(g_lxp_slots[0].proc.pending_sigs & bit); /* init (pgid 1) */
	assert_false(g_lxp_slots[1].proc.pending_sigs &
		     bit); /* the shell (pgid 2) — survives to re-prompt */
	assert_false(g_lxp_slots[4].proc.pending_sigs &
		     bit); /* background job (pgid 5) — untouched */
}

/* Ctrl+Z (VSUSP) fans SIGTSTP out to the foreground group only — the shell and background
 * jobs are untouched — exactly like the ^C→SIGINT path. */
static void test_console_sigtstp_targets_fg_group(void **state)
{
	(void)state;
	const int pid[3] = {2, 3, 5}; /* shell(2,2) fg-job(3,3) bg-job(5,5) */
	const int pgid[3] = {2, 3, 5};
	for (int i = 0; i < 3; i++) {
		g_lxp_slots[i].proc.alive = 1;
		g_lxp_slots[i].proc.pid = pid[i];
		g_lxp_slots[i].proc.group->pgid = pgid[i];
	}
	const uint64_t bit = lxp_sig_bit(LXP_SIGTSTP);
	lxp_console_set_fg_pgrp(3);
	console_signal_fg(LXP_SIGTSTP);
	assert_true(g_lxp_slots[1].proc.pending_sigs & bit);  /* fg job (pgid 3) */
	assert_false(g_lxp_slots[0].proc.pending_sigs & bit); /* the shell (pgid 2) */
	assert_false(g_lxp_slots[2].proc.pending_sigs & bit); /* background job (pgid 5) */
}

/* The stop-signal predicate: SIGSTOP always stops (uncatchable); SIGTSTP/TTIN/TTOU stop
 * only at their default disposition (a caught one runs the handler). */
static void test_sig_stops_proc_predicate(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_slots[0].proc;
	static lxp_sighand_t sighand;
	memset(&sighand, 0, sizeof(sighand));
	sighand.refs = 1;
	p->sighand = &sighand;
	p->sighand->handler[LXP_SIGTSTP] = LXP_SIG_DFL;
	assert_true(sig_is_stop(LXP_SIGTSTP));
	assert_true(sig_is_stop(LXP_SIGSTOP));
	assert_false(sig_is_stop(LXP_SIGINT));
	assert_true(sig_stops_proc(p, LXP_SIGTSTP)); /* SIG_DFL → stops */
	p->sighand->handler[LXP_SIGTSTP] = 0x1000;   /* a caught handler → runs it, no stop */
	assert_false(sig_stops_proc(p, LXP_SIGTSTP));
	p->sighand->handler[LXP_SIGSTOP] = 0x1000; /* SIGSTOP is uncatchable → always stops */
	assert_true(sig_stops_proc(p, LXP_SIGSTOP));
	assert_false(sig_stops_proc(p, LXP_SIGINT)); /* not a stop signal */
}

/* A stopped child wakes a parent blocked in wait4(WUNTRACED) with a WIFSTOPPED status and,
 * unlike an exit, leaves live_children intact (the child is still alive). */
static void test_stop_notify_wakes_wuntraced_waiter(void **state)
{
	(void)state;
	int status = -1;
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_slots[0].proc, -1, LXP_WUNTRACED, &status);
	g_lxp_slots[0].host_state = SLOT_PARKED;

	notify_parent_stopped(&g_mock_eng, /*ppid*/ 1, /*cpid*/ 7, LXP_SIGTSTP);

	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_r0, 7);
	assert_int_equal(status, ((LXP_SIGTSTP & 0xff) << 8) | 0x7f); /* WIFSTOPPED */
	assert_int_equal(g_lxp_slots[0].proc.wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_lxp_slots[0].proc.group->live_children,
			 1); /* NOT decremented — the child lives */
	assert_int_equal(g_lxp_slots[0].proc.group->child_count, 0);
}

/* A stopped child whose parent is NOT waiting (or waits without WUNTRACED) queues a STOPPED
 * notice + raises SIGCHLD, again without touching live_children. */
static void test_stop_notify_queues_without_wuntraced(void **state)
{
	(void)state;
	/* Parent blocked in wait4 but WITHOUT WUNTRACED → cannot take the stop → queue it. */
	g_lxp_slots[0].proc.alive = 1;
	g_lxp_slots[0].proc.pid = 1;
	g_lxp_slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_slots[0].proc, -1, 0, NULL);

	notify_parent_stopped(&g_mock_eng, /*ppid*/ 1, /*cpid*/ 7, LXP_SIGTSTP);

	assert_int_equal(g_mock.resume_calls, 0); /* the waiter is not woken */
	assert_int_equal(g_lxp_slots[0].proc.wait.kind, LXP_WAIT_CHILD);
	assert_int_equal(g_lxp_slots[0].proc.group->child_count, 1);
	assert_int_equal(g_lxp_slots[0].proc.group->child_pid[0], 7);
	assert_int_equal(g_lxp_slots[0].proc.group->child_status[0], LXP_SIGTSTP);
	assert_int_equal(g_lxp_slots[0].proc.group->child_kind[0], LXP_CHILD_STOPPED);
	assert_int_equal(g_lxp_slots[0].proc.group->live_children, 1); /* NOT decremented */
	assert_true(g_lxp_slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD));
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_child_constructors_cover_clone_flag_matrix,
				       reset_state),
		cmocka_unit_test_setup(test_child_constructor_rolls_back_each_acquisition,
				       reset_state),
		cmocka_unit_test_setup(test_fork_build_abort_restores_world, reset_state),
		cmocka_unit_test_setup(test_fork_transaction_failpoints_restore_world,
				       reset_state),
		cmocka_unit_test_setup(test_exec_precommit_failpoints_preserve_old_image,
				       reset_state),
		cmocka_unit_test_setup(test_exec_stale_snapshot_contains_vfork_pair,
				       reset_state),
		cmocka_unit_test_setup(
			test_exec_commit_failure_contains_only_transitioning_guest,
			reset_state),
		cmocka_unit_test_setup(test_image_publish_failpoints_release_every_owner,
				       reset_state),
		cmocka_unit_test_setup(test_world_diagnostics_snapshot_current_states, reset_state),
		cmocka_unit_test_setup(test_world_validator_reports_conflicting_waits, reset_state),
		cmocka_unit_test_setup(test_typed_intent_transitions_are_exclusive, reset_state),
		cmocka_unit_test_setup(test_exit_intent_supersedes_deferred_work, reset_state),
		cmocka_unit_test_setup(test_typed_wait_transitions_cover_every_kind, reset_state),
		cmocka_unit_test_setup(test_world_validator_reports_stale_mailbox, reset_state),
		cmocka_unit_test_setup(test_world_validator_reports_region_ownership_drift,
				       reset_state),
		cmocka_unit_test_setup(
			test_slot_references_reject_recycled_incarnations_and_skip_zero,
			reset_state),
		cmocka_unit_test_setup(test_fault_publication_rejects_stale_slot_reference,
				       reset_state),
		cmocka_unit_test_setup(
			test_memory_policy_snapshot_and_key_track_every_generation,
			reset_state),
		cmocka_unit_test_setup(test_region_references_reject_reuse_and_skip_zero,
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
		cmocka_unit_test_setup(test_system_version_routes_to_engine, reset_state),
		cmocka_unit_test_setup(test_port_abi_and_required_ops_are_validated, reset_state),
		cmocka_unit_test_setup(test_failed_prepare_is_rolled_back, reset_state),
		cmocka_unit_test_setup(test_rootfs_requires_one_explicit_trusted_window,
				       reset_state),
		cmocka_unit_test_setup(test_resource_stats_track_slots_and_reserved_regions,
				       reset_state),
		cmocka_unit_test_setup(test_coordinator_socket_wait_uses_readiness_events,
				       reset_state),
		cmocka_unit_test_setup(test_claim_slot_event_priority_and_consumption, reset_state),
		cmocka_unit_test_setup(
			test_coordinator_claim_rotates_fairly_and_discards_stale_hints,
			reset_state),
		cmocka_unit_test_setup(test_primary_wait_handler_applies_park_outcome, reset_state),
		cmocka_unit_test_setup(test_primary_handler_rejects_out_of_range_slot, reset_state),
		cmocka_unit_test_setup(test_blocked_timer_handler_resumes_expired_wait,
				       reset_state),
		cmocka_unit_test_setup(test_kill_targets_process_group, reset_state),
		cmocka_unit_test_setup(test_setpgid_getpgrp_track_group, reset_state),
		cmocka_unit_test_setup(test_console_sigint_targets_fg_group, reset_state),
		cmocka_unit_test_setup(test_console_sigtstp_targets_fg_group, reset_state),
		cmocka_unit_test_setup(test_sig_stops_proc_predicate, reset_state),
		cmocka_unit_test_setup(test_stop_notify_wakes_wuntraced_waiter, reset_state),
		cmocka_unit_test_setup(test_stop_notify_queues_without_wuntraced, reset_state),
		cmocka_unit_test_setup(test_encode_wstatus, reset_state),
		cmocka_unit_test_setup(test_dispatch_rejects_bad_tcsets_pointer, reset_state),
		cmocka_unit_test_setup(test_console_icrnl_translation, reset_state),
		cmocka_unit_test_setup(test_dispatch_class_defaults_deferred, reset_state),
		cmocka_unit_test_setup(test_deferred_requests_are_per_slot, reset_state),
		cmocka_unit_test_setup(test_deferred_generation_rejects_stale_work, reset_state),
		cmocka_unit_test_setup(test_deferred_same_slot_rejects_overwrite, reset_state),
		cmocka_unit_test_setup(test_deferred_signal_cancels_before_execute, reset_state),
		cmocka_unit_test_setup(test_signal_interrupts_blocked_netfs_before_retry,
				       reset_state),
		cmocka_unit_test_setup(
			test_netfs_exec_completion_publishes_primary_event, reset_state),
		cmocka_unit_test_setup(test_exec_commit_discards_older_deferred_request,
				       reset_state),
		cmocka_unit_test_setup(
			test_reused_slot_ignores_late_completion_from_dead_generation,
			reset_state),
		cmocka_unit_test_setup(test_generated_protocol_sequences_preserve_world,
				       reset_state),
		cmocka_unit_test_setup(test_console_icrnl_immediate_read, reset_state),
		cmocka_unit_test_setup(test_blocked_scan_reports_wait_policy, reset_state),
		cmocka_unit_test_setup(test_async_console_signal_is_scan_progress, reset_state),
		cmocka_unit_test_setup(test_deferred_blocking_handoff_keeps_parked_task,
				       reset_state),
		cmocka_unit_test_setup(test_pending_deliverable, reset_state),
		cmocka_unit_test_setup(test_futex_has_corunner, reset_state),
		cmocka_unit_test_setup(test_futex_wake_marks_waiters, reset_state),
		cmocka_unit_test_setup(test_reap_wakes_blocking_parent, reset_state),
		cmocka_unit_test_setup(test_reap_wakes_waiter_in_parent_thread_group, reset_state),
		cmocka_unit_test_setup(test_reap_signaled_child_status, reset_state),
		cmocka_unit_test_setup(test_reap_specific_pid_not_woken, reset_state),
		cmocka_unit_test_setup(test_reap_queues_zombie, reset_state),
		cmocka_unit_test_setup(test_reap_vfork_parent_suppresses_sigchld, reset_state),
		cmocka_unit_test_setup(test_reap_zombie_queue_full, reset_state),
		cmocka_unit_test_setup(test_reap_unknown_parent, reset_state),
		cmocka_unit_test_setup(test_notify_guest_exit_preserves_attribution, reset_state),
		cmocka_unit_test_setup(test_fork_capacity_accounts_live_and_zombie_children,
				       reset_state),
		cmocka_unit_test_setup(test_vfork_snapshot_publishes_cacheable_destination,
				       reset_state),
		cmocka_unit_test_setup(test_vfork_restore_publishes_cacheable_parent, reset_state),
		cmocka_unit_test_setup(test_vfork_snapshot_refuses_no_spare_region, reset_state),
		cmocka_unit_test_setup(test_vfork_restore_rejects_recycled_snapshot, reset_state),
		cmocka_unit_test_setup(test_vfork_restore_rejects_recycled_parent, reset_state),
		cmocka_unit_test_setup(test_region_free, reset_state),
		cmocka_unit_test_setup(test_shared_region_lives_until_last_task_reference,
				       reset_state),
		cmocka_unit_test_setup(test_thread_group_exit_marks_every_peer, reset_state),
		cmocka_unit_test_setup(test_group_exit_releases_shared_address_space_last,
				       reset_state),
		cmocka_unit_test_setup(test_exec_stops_only_thread_group_peers, reset_state),
		cmocka_unit_test_setup(test_device_map_index_tracks_both_ranges, reset_state),
		cmocka_unit_test_setup(test_device_maps_follow_shared_address_space, reset_state),
		cmocka_unit_test_setup(test_teardown_releases_every_slot_resource, reset_state),
		cmocka_unit_test_setup(test_teardown_quiesces_before_releasing_resources,
				       reset_state),
		cmocka_unit_test_setup(
			test_spawn_callbacks_receive_explicit_mode_and_published_slot,
			reset_state),
		cmocka_unit_test_setup(test_park_failure_aborts_and_kills_slot, reset_state),
		cmocka_unit_test_setup(test_resume_failure_aborts_parked_slot, reset_state),
		cmocka_unit_test_setup(test_abort_failure_retains_slot_until_retry, reset_state),
	};
	g_test_net_ops = lxp_posix_net_ops();
	return cmocka_run_group_tests(tests, NULL, NULL);
}
