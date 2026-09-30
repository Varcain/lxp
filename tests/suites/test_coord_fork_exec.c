/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator tests for fork, exec and exit: child construction, the fork, exec and image
 * transactions and their failpoints, region references and vfork snapshots, device maps,
 * thread-group exit and reaping.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "lxp_internal.h"
#include "run/lxp_fork_private.h"
#include "../framework/lxp_coord_fixture.h"
#include "../framework/lxp_mock_engine.h"

static lxp_region_ref_t make_address_space_region(int region, int slot)
{
	lxp_slot_ref_t owner = slot_ref_at(slot);
	lxp_region_ref_t ref = region_reserve(region, owner);
	assert_int_equal(ref.index, region);
	assert_int_equal(lxp_region_commit_address_space(ref, owner), LXP_OK);
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
	lxp_proc_nice_set(parent, -9);
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
	assert_int_equal(lxp_proc_nice_get(child), -9);
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

	lxp_proc_t *parent = &g_lxp_rt.slots[0].proc;
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
	lxp_proc_t *parent = &g_lxp_rt.slots[0].proc;
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
	lxp_proc_t *parent = &g_lxp_rt.slots[0].proc;
	parent->mm->region_lo = (uintptr_t)g_mock_regions[0];
	parent->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	parent->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	g_lxp_rt.slots[0].resume.sp = (uintptr_t)g_mock_regions[0] + 192u;
	lxp_proc_child_discard(&g_lxp_rt.slots[1].proc);

	/* Region acquisition failure must not touch the destination or parent. */
	g_lxp_rt.regions[0].refs = LXP_NSLOT;
	struct fork_txn tx;
	assert_int_equal(fork_txn_prepare(&tx, 0, 1, 0, 2), -LXP_EAGAIN);
	fork_txn_abort(&tx);
	assert_int_equal(g_lxp_rt.regions[0].refs, LXP_NSLOT);
	assert_failed_child_is_empty(&g_lxp_rt.slots[1].proc);
	g_lxp_rt.regions[0].refs = 1;

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
	assert_int_equal(fork_txn_prepare(&tx, 0, 1, 0, 2), -LXP_ENOMEM);
	fork_txn_abort(&tx);
	assert_int_equal(g_lxp_rt.regions[0].refs, 1);
	assert_int_equal(parent->mm->refs, mm_refs);
	assert_int_equal(parent->files->refs, files_refs);
	assert_int_equal(parent->fs_context->refs, fs_refs);
	assert_int_equal(parent->sighand->refs, sighand_refs);
	assert_int_equal(parent->group->refs, group_refs);
	assert_failed_child_is_empty(&g_lxp_rt.slots[1].proc);

	/* Snapshot exhaustion happens after publication preparation and child
	 * accounting; the same abort reverses both. */
	assert_int_equal(fork_txn_prepare(&tx, 0, 1, 0, 2), LXP_OK);
	assert_int_equal(fork_txn_count_child(&tx), LXP_OK);
	for (int r = 1; r < LXP_NREG; r++)
		assert_int_equal(region_reserve(r, slot_ref_at(0)).index, r);
	lxp_region_ref_t snapshot =
		vfork_snapshot(parent, tx.child_ref, g_lxp_rt.slots[0].resume.sp);
	assert_int_equal(snapshot.index, -1);
	fork_txn_abort(&tx);
	assert_int_equal(parent->group->live_children, 0);
	assert_int_equal(g_lxp_rt.regions[0].refs, 1);
	assert_failed_child_is_empty(&g_lxp_rt.slots[1].proc);
	for (int r = 1; r < LXP_NREG; r++)
		assert_int_equal(region_put(region_ref_at(r)), LXP_OK);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_fork_transaction_failpoints_restore_world(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *parent = &g_lxp_rt.slots[0].proc;
	parent->mm->region_lo = (uintptr_t)g_mock_regions[0];
	parent->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	parent->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	uintptr_t parent_sp = (uintptr_t)g_mock_regions[0] + 192u;
	lxp_proc_child_discard(&g_lxp_rt.slots[1].proc);
	lxp_diag_error_t error;

	const enum lxp_lifecycle_failpoint prepare_points[] = {
		LXP_FAIL_FORK_REGION_ACQUIRED,
		LXP_FAIL_FORK_CHILD_PREPARED,
		LXP_FAIL_FORK_MAPS_PREPARED,
	};
	for (size_t i = 0; i < sizeof(prepare_points) / sizeof(prepare_points[0]); i++) {
		struct fork_txn tx;
		g_lxp_lifecycle_failpoint = prepare_points[i];
		assert_true(fork_txn_prepare(&tx, 0, 1, 0, 2) < 0);
		fork_txn_abort(&tx);
		fork_txn_abort(&tx); /* idempotent */
		assert_int_equal(parent->group->live_children, 0);
		assert_int_equal(g_lxp_rt.regions[0].refs, 1);
		assert_failed_child_is_empty(&g_lxp_rt.slots[1].proc);
		assert_int_equal(lxp_validate_world(&error), LXP_OK);
	}

	/* Child accounting, snapshot ownership, and publication are later
	 * boundaries of the same transaction and must converge on the same state. */
	for (enum lxp_lifecycle_failpoint point = LXP_FAIL_FORK_CHILD_COUNTED;
	     point <= LXP_FAIL_FORK_PUBLISHED; point++) {
		struct fork_txn tx;
		assert_int_equal(fork_txn_prepare(&tx, 0, 1, 0, 2), LXP_OK);
		g_lxp_lifecycle_failpoint = point;
		int rc = fork_txn_count_child(&tx);
		if (point >= LXP_FAIL_FORK_SNAPSHOT_ACQUIRED && rc == LXP_OK) {
			tx.child->vfork_parent = tx.parent_ref;
			rc = fork_txn_snapshot(&tx, parent_sp);
		}
		if (point == LXP_FAIL_FORK_PUBLISHED && rc == LXP_OK)
			rc = fork_txn_publish(&tx);
		assert_true(rc < 0);
		fork_txn_abort(&tx);
		fork_txn_abort(&tx);
		assert_int_equal(parent->group->live_children, 0);
		assert_int_equal(g_lxp_rt.regions[0].refs, 1);
		for (int r = 1; r < LXP_NREG; r++)
			assert_int_equal(g_lxp_rt.regions[r].refs, 0);
		assert_failed_child_is_empty(&g_lxp_rt.slots[1].proc);
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
	lxp_proc_t *old = &g_lxp_rt.slots[0].proc;
	lxp_mm_t *mm = old->mm;
	lxp_files_t *files = old->files;
	lxp_fs_context_t *fs = old->fs_context;
	lxp_sighand_t *sighand = old->sighand;
	lxp_thread_group_t *group = old->group;
	uint32_t generation = slot_generation(0);
	uint8_t image[128];
	size_t image_size = build_coord_fdpic(image);
	lxp_diag_error_t error;

	assert_int_equal(coordinator_park_slot(0), LXP_OK);
	struct exec_txn tx;
	exec_txn_init(&tx, 0);
	assert_int_equal(exec_txn_validate_image(&tx, image, image_size, 0), LXP_OK);
	g_lxp_lifecycle_failpoint = LXP_FAIL_EXEC_REGION_ACQUIRED;
	assert_true(exec_txn_reserve(&tx) < 0);
	exec_txn_abort(&tx, -LXP_ENOMEM, LXP_EXIT_REASON_EXEC_RESOURCE);
	exec_txn_abort(&tx, -LXP_ENOMEM, LXP_EXIT_REASON_EXEC_RESOURCE);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_RUNNING);
	assert_int_equal(slot_generation(0), generation);
	assert_ptr_equal(old->mm, mm);
	assert_ptr_equal(old->files, files);
	assert_ptr_equal(old->fs_context, fs);
	assert_ptr_equal(old->sighand, sighand);
	assert_ptr_equal(old->group, group);
	assert_true(old->alive);
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	assert_int_equal(coordinator_park_slot(0), LXP_OK);
	exec_txn_init(&tx, 0);
	g_lxp_lifecycle_failpoint = LXP_FAIL_EXEC_IMAGE_VALIDATED;
	assert_true(exec_txn_validate_image(&tx, image, image_size, 0) < 0);
	exec_txn_abort(&tx, -LXP_ENOEXEC, LXP_EXIT_REASON_EXEC_LOAD);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_RUNNING);
	assert_int_equal(slot_generation(0), generation);
	assert_ptr_equal(old->mm, mm);
	assert_ptr_equal(old->files, files);
	assert_ptr_equal(old->fs_context, fs);
	assert_ptr_equal(old->sighand, sighand);
	assert_ptr_equal(old->group, group);
	assert_true(old->alive);
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

/* An image that can never load is refused as ENOEXEC even when no program
 * region is free: exec must not report resource pressure for a bad image. */
static void test_exec_rejects_unloadable_image_without_free_region(void **state)
{
	(void)state;
	for (int s = 0; s < LXP_NREG; s++)
		make_valid_running_slot(s, s);
	for (int r = 0; r < LXP_NREG; r++)
		assert_false(region_free(r));

	static const uint8_t passwd[] = "root:x:0:0:root:/root:/bin/sh\n";
	const lxp_file_t rootfs[] = {{"/etc/passwd", passwd, sizeof(passwd) - 1, 0100644}};
	lxp_run_config_t cfg = {.rootfs = rootfs, .rootfs_count = 1};
	g_lxp_rt.cfg = &cfg;
	lxp_proc_t *proc = &g_lxp_rt.slots[0].proc;
	memset(&g_mock_exec_captures[0], 0, sizeof(g_mock_exec_captures[0]));
	lxp_proc_bind_exec_capture(proc, &g_mock_exec_captures[0]);
	proc->exec_file_idx = 0;
	assert_int_equal(lxp_intent_begin(proc, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}), 0);
	lxp_mm_t *mm = proc->mm;

	lxp_handle_exec(0);

	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, 0);
	assert_int_equal(g_mock.resume_r0, -LXP_ENOEXEC);
	assert_true(proc->alive);
	assert_ptr_equal(proc->mm, mm);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_RUNNING);
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_exec_stale_snapshot_contains_vfork_pair(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *parent = &g_lxp_rt.slots[0].proc;
	parent->mm->region_lo = (uintptr_t)g_mock_regions[0];
	parent->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	parent->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	uintptr_t parent_sp = (uintptr_t)g_mock_regions[0] + 192u;
	lxp_proc_child_discard(&g_lxp_rt.slots[1].proc);

	struct fork_txn fork;
	assert_int_equal(fork_txn_prepare(&fork, 0, 1, 0, 2), LXP_OK);
	assert_int_equal(fork_txn_count_child(&fork), LXP_OK);
	fork.child->vfork_parent = fork.parent_ref;
	assert_int_equal(g_lxp_lifecycle_failpoint, LXP_FAIL_NONE);
	assert_true(lxp_slot_ref_is_current(fork.parent_ref));
	assert_true(region_free(1));
	assert_int_equal(fork_txn_snapshot(&fork, parent_sp), LXP_OK);
	int snapshot_region = fork.child->snapshot.index;
	assert_int_equal(fork_txn_publish(&fork), LXP_OK);
	assert_int_equal(fork_txn_commit(&fork), LXP_OK);
	assert_int_equal(coordinator_park_slot(0), LXP_OK);
	g_lxp_rt.slots[1].host_state = SLOT_RUNNING;
	g_lxp_rt.slots[1].runnable = 1;

	/* Corrupt only the child's stored capability. The guarded reservation is
	 * still valid and must be released by containment without copying it. */
	g_lxp_rt.slots[1].proc.snapshot.generation++;
	uint8_t image[128];
	struct exec_txn exec;
	exec_txn_init(&exec, 1);
	assert_int_equal(exec_txn_validate_image(&exec, image, build_coord_fdpic(image), 0),
			 LXP_OK);
	assert_int_equal(exec_txn_reserve(&exec), -LXP_EIO);
	assert_true(exec.terminal);
	exec_txn_abort(&exec, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);

	assert_int_equal(parent->intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(parent->exit_reason, LXP_EXIT_REASON_STATE_CORRUPTION);
	assert_int_equal(g_lxp_rt.slots[1].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_rt.slots[1].proc.exit_reason, LXP_EXIT_REASON_STATE_CORRUPTION);
	assert_int_equal(g_lxp_rt.slots[1].proc.snapshot.index, -1);
	assert_int_equal(g_lxp_rt.slots[1].proc.vfork_parent.index, -1);
	assert_int_equal(g_lxp_rt.regions[snapshot_region].refs, 0);
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

	assert_int_equal(coordinator_park_slot(0), LXP_OK);
	struct exec_txn tx;
	exec_txn_init(&tx, 0);
	assert_int_equal(exec_txn_validate_image(&tx, image, image_size, 0), LXP_OK);
	assert_int_equal(exec_txn_reserve(&tx), LXP_OK);
	g_lxp_lifecycle_failpoint = LXP_FAIL_EXEC_COMMITTED;
	assert_true(exec_txn_commit(&tx) < 0);
	exec_txn_abort(&tx, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);
	exec_txn_abort(&tx, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);

	assert_false(g_lxp_rt.slots[0].proc.alive);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_DEAD);
	assert_true(lxp_slot_ref_is_current(unrelated));
	assert_int_equal(g_lxp_rt.slots[2].host_state, SLOT_RUNNING);
	assert_true(g_lxp_rt.slots[2].runnable);
	assert_int_equal(g_lxp_rt.regions[2].refs, 1);
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
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
		g_lxp_lifecycle_failpoint = points[i];
		int rc;
		if (points[i] == LXP_FAIL_EXEC_IMAGE_PREPARED)
			rc = lifecycle_failpoint(points[i]) ? -LXP_EIO : LXP_OK;
		else {
			rc = image_txn_publish(&tx);
			if (rc == LXP_OK)
				rc = image_txn_start(&tx);
		}
		assert_true(rc < 0);
		assert_int_equal(image_txn_abort(&tx), LXP_OK);
		assert_int_equal(image_txn_abort(&tx), LXP_OK);
		assert_false(g_lxp_rt.slots[1].proc.alive);
		assert_int_equal(g_lxp_rt.regions[1].refs, 0);
		assert_int_equal(lxp_validate_world(&error), LXP_OK);
	}
}

static void test_image_start_preserves_executable_extent_and_rolls_back_spawn_failure(void **state)
{
	(void)state;
	struct image_txn tx;
	prepare_mock_image_txn(&tx, 1, 1);
	tx.proc.mm->copied_text_executable = 1u;
	tx.launch.copied_text_base = (uintptr_t)&g_mock_regions[1][0];
	tx.launch.copied_text_size = LXP_PROG_REGION_SIZE / 2u;
	tx.proc.mm->copied_text_base = tx.launch.copied_text_base;
	tx.proc.mm->copied_text_size = tx.launch.copied_text_size;

	assert_int_equal(image_txn_publish(&tx), LXP_OK);
	assert_int_equal(g_mock.publish_executable_calls, 1);
	assert_true(lxp_region_ref_equal(g_mock.publish_address_space, tx.region));
	assert_int_equal(g_mock.publish_base, tx.launch.copied_text_base);
	assert_int_equal(g_mock.publish_size, tx.launch.copied_text_size);
	assert_false(g_mock.publish_observed_alive);
	assert_true(image_txn_publish(&tx) < 0);
	assert_int_equal(g_mock.publish_executable_calls, 1);
	assert_int_equal(image_txn_start(&tx), LXP_OK);
	assert_int_equal(g_mock.launch_calls, 1);
	assert_int_equal(g_mock.launch.copied_text_base, tx.launch.copied_text_base);
	assert_int_equal(g_mock.launch.copied_text_size, tx.launch.copied_text_size);
	assert_true(g_mock.launch_observed_runnable);
	assert_int_equal(g_mock.launch_observed_host_state, SLOT_STARTING);
	assert_int_equal(image_txn_abort(&tx), LXP_OK);

	prepare_mock_image_txn(&tx, 1, 1);
	g_mock.launch_failures = 1;
	assert_int_equal(image_txn_publish(&tx), LXP_OK);
	assert_true(image_txn_start(&tx) < 0);
	assert_false(tx.native_started);
	assert_int_equal(image_txn_abort(&tx), LXP_OK);
	assert_false(g_lxp_rt.slots[1].proc.alive);
	assert_int_equal(g_lxp_rt.regions[1].refs, 0);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_image_start_marks_xip_launch_with_empty_executable_extent(void **state)
{
	(void)state;
	struct image_txn tx;
	prepare_mock_image_txn(&tx, 1, 1);

	assert_int_equal(image_txn_publish(&tx), LXP_OK);
	assert_int_equal(g_mock.publish_executable_calls, 0);
	assert_int_equal(image_txn_start(&tx), LXP_OK);
	assert_int_equal(g_mock.launch_calls, 1);
	assert_int_equal(g_mock.launch.copied_text_base, 0);
	assert_int_equal(g_mock.launch.copied_text_size, 0);
	assert_int_equal(image_txn_abort(&tx), LXP_OK);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_image_publication_rejects_invalid_extent_generation_and_port_failure(void **state)
{
	(void)state;
	struct image_txn tx;
	const uintptr_t region_lo = (uintptr_t)&g_mock_regions[1][0];

	prepare_mock_image_txn(&tx, 1, 1);
	tx.proc.mm->copied_text_executable = 1u;
	tx.launch.copied_text_base = region_lo + LXP_PROG_REGION_SIZE;
	tx.launch.copied_text_size = 1u;
	tx.proc.mm->copied_text_base = tx.launch.copied_text_base;
	tx.proc.mm->copied_text_size = tx.launch.copied_text_size;
	assert_true(image_txn_publish(&tx) < 0);
	assert_int_equal(g_mock.publish_executable_calls, 0);
	assert_int_equal(image_txn_abort(&tx), LXP_OK);

	prepare_mock_image_txn(&tx, 1, 1);
	tx.launch.copied_text_base = region_lo;
	tx.launch.copied_text_size = LXP_PROG_REGION_SIZE / 2u;
	assert_true(image_txn_publish(&tx) < 0);
	assert_int_equal(g_mock.publish_executable_calls, 0);
	assert_int_equal(image_txn_abort(&tx), LXP_OK);

	prepare_mock_image_txn(&tx, 1, 1);
	tx.proc.mm->copied_text_executable = 1u;
	tx.launch.copied_text_base = region_lo;
	tx.launch.copied_text_size = LXP_PROG_REGION_SIZE / 2u;
	tx.proc.mm->copied_text_base = tx.launch.copied_text_base;
	tx.proc.mm->copied_text_size = tx.launch.copied_text_size;
	lxp_region_ref_t current_region = tx.region;
	tx.region.generation++;
	assert_true(image_txn_publish(&tx) < 0);
	assert_int_equal(g_mock.publish_executable_calls, 0);
	tx.region = current_region;
	tx.proc.mm->region = current_region;
	assert_int_equal(image_txn_abort(&tx), LXP_OK);

	prepare_mock_image_txn(&tx, 1, 1);
	tx.proc.mm->copied_text_executable = 1u;
	tx.launch.copied_text_base = region_lo;
	tx.launch.copied_text_size = LXP_PROG_REGION_SIZE / 2u;
	tx.proc.mm->copied_text_base = tx.launch.copied_text_base;
	tx.proc.mm->copied_text_size = tx.launch.copied_text_size;
	g_mock.publish_result = -LXP_EIO;
	assert_int_equal(image_txn_publish(&tx), -LXP_EIO);
	assert_int_equal(g_mock.publish_executable_calls, 1);
	assert_false(tx.executable_published);
	assert_false(tx.published);
	assert_int_equal(g_mock.launch_calls, 0);
	assert_int_equal(image_txn_abort(&tx), LXP_OK);
	assert_false(g_lxp_rt.slots[1].proc.alive);
	assert_int_equal(g_lxp_rt.regions[1].refs, 0);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_fork_resume_clone_owns_context_mutation(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	memset(&g_lxp_rt.slots[0].resume, 0x5a, sizeof(g_lxp_rt.slots[0].resume));
	g_lxp_rt.slots[0].resume.sp = 0x1000u;
	lxp_slot_ref_t parent = slot_ref_at(0);
	deferred_slot_reassign(1);
	lxp_slot_ref_t child = slot_ref_at(1);

	struct lxp_resume_ctx expected = g_lxp_rt.slots[0].resume;
	expected.sp = 0x2000u;
	assert_int_equal(lxp_slot_resume_clone_for_fork(child, parent, expected.sp), LXP_OK);
	assert_memory_equal(&g_lxp_rt.slots[1].resume, &expected, sizeof(expected));

	deferred_slot_reassign(1);
	memset(&g_lxp_rt.slots[1].resume, 0xa5, sizeof(g_lxp_rt.slots[1].resume));
	struct lxp_resume_ctx unchanged = g_lxp_rt.slots[1].resume;
	assert_int_equal(lxp_slot_resume_clone_for_fork(child, parent, 0x3000u), -LXP_ESRCH);
	assert_memory_equal(&g_lxp_rt.slots[1].resume, &unchanged, sizeof(unchanged));

	child = slot_ref_at(1);
	deferred_slot_reassign(0);
	assert_int_equal(lxp_slot_resume_clone_for_fork(child, parent, 0x3000u), -LXP_ESRCH);
	assert_memory_equal(&g_lxp_rt.slots[1].resume, &unchanged, sizeof(unchanged));

	parent = slot_ref_at(0);
	g_lxp_rt.slots[1].proc.alive = 1;
	assert_int_equal(lxp_slot_resume_clone_for_fork(child, parent, 0x3000u), -LXP_ESRCH);
	assert_memory_equal(&g_lxp_rt.slots[1].resume, &unchanged, sizeof(unchanged));
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
	assert_int_equal(g_lxp_rt.regions[1].refs, 1);
	assert_int_equal(region_release_if_owned(current, owner), LXP_OK);

	g_lxp_rt.regions[1].generation = UINT32_MAX;
	current = region_reserve(1, owner);
	assert_int_equal(current.generation, 1);
	assert_int_equal(region_release_if_owned(current, owner), LXP_OK);
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
static void test_reap_wakes_blocking_parent(void **state)
{
	(void)state;
	int status = -1;
	/* slot 0 = parent pid 1, blocked in wait4 for any child, with one live child. */
	deferred_slot_reassign(0);
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_rt.slots[0].proc, -1, 0, &status);
	g_lxp_rt.slots[0].host_state = SLOT_PARKED;

	reap_to_parent(/*ppid*/ 1, /*cpid*/ 7, /*status*/ 42, /*sigchld=*/1);

	/* Resumed once, returning the reaped pid; *status = WIFEXITED(42); child accounted. */
	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, 0);
	assert_int_equal(g_mock.resume_r0, 7);
	assert_int_equal(status, 42 << 8);
	assert_int_equal(g_lxp_rt.slots[0].proc.wait.kind, LXP_WAIT_NONE);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children, 0);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count, 0); /* woken, not queued */
	assert_int_equal(g_mock.abort_calls, 0); /* g_lxp_rt.slots[0].runnable==0: no spin thread */
}

static void test_reap_wakes_waiter_in_parent_thread_group(void **state)
{
	(void)state;
	int status = -1;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 10;
	g_lxp_rt.slots[0].proc.group->tgid = 10;
	lxp_proc_group_put(&g_lxp_rt.slots[1].proc);
	assert_int_equal(lxp_proc_group_fork(&g_lxp_rt.slots[1].proc, &g_lxp_rt.slots[0].proc,
					     LXP_CLONE_THREAD, 11),
			 0);
	g_lxp_rt.slots[1].proc.alive = 1;
	g_lxp_rt.slots[1].proc.pid = 11;
	g_lxp_rt.slots[1].proc.group->live_children = 1;
	set_child_wait(&g_lxp_rt.slots[1].proc, -1, 0, &status);
	g_lxp_rt.slots[1].host_state = SLOT_PARKED;

	reap_to_parent(10, 17, 9, /*sigchld=*/1);

	assert_int_equal(g_mock.resume_calls, 1);
	assert_int_equal(g_mock.resume_sidx, 1);
	assert_int_equal(g_mock.resume_r0, 17);
	assert_int_equal(status, 9 << 8);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children, 0);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count, 0);
}

/* A signal-killed child (128 + signo) wakes the waiter as WIFSIGNALED. */
static void test_reap_signaled_child_status(void **state)
{
	(void)state;
	int status = -1;
	deferred_slot_reassign(0);
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = 1;
	set_child_wait(&g_lxp_rt.slots[0].proc, -1, 0, &status);
	g_lxp_rt.slots[0].runnable = 1; /* coordinator has not yet suspended the parked waiter */
	g_lxp_rt.slots[0].host_state = SLOT_RUNNING;

	reap_to_parent(1, 7, 128 + 15 /* SIGTERM */, /*sigchld=*/1);

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
	deferred_slot_reassign(0);
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = 2;
	set_child_wait(&g_lxp_rt.slots[0].proc, 9, 0, &status);

	reap_to_parent(1, 7, 0, /*sigchld=*/1); /* pid 7 exits, not 9 */

	/* Not resumed; the zombie is queued and SIGCHLD raised; still one live child left. */
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].proc.wait.kind, LXP_WAIT_CHILD);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count, 1);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_pid[0], 7);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children, 1);
	assert_true((g_lxp_rt.slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) != 0);
}

/* ---- reap_to_parent: parent not waiting → zombie queued + SIGCHLD ----------- */
static void test_reap_queues_zombie(void **state)
{
	(void)state;
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = 1;
	/* No CHILD wait: the parent is off in select()/poll(), not blocking in wait4. */

	reap_to_parent(1, 7, 3, /*sigchld=*/1);

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count, 1);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_pid[0], 7);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_status[0],
			 3); /* raw code; wait4 encodes on reap */
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children, 0);
	assert_true((g_lxp_rt.slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) != 0);
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
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = 1;
	/* No CHILD wait: just resumed from vfork, about to wait4() the child. */

	reap_to_parent(1, 7, 127, /*sigchld=*/0);

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count,
			 1); /* queued for the imminent wait4 */
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_pid[0], 7);
	/* the exit code is preserved */
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_status[0], 127);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children, 0);
	assert_true((g_lxp_rt.slots[0].proc.pending_sigs & lxp_sig_bit(LXP_SIGCHLD)) ==
		    0); /* NOT signalled */
}

/* The zombie queue is bounded (LXP_MAX_CHILD): an overflow is dropped, not overrun. */
static void test_reap_zombie_queue_full(void **state)
{
	(void)state;
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;
	g_lxp_rt.slots[0].proc.group->live_children = LXP_MAX_CHILD + 1;
	g_lxp_rt.slots[0].proc.group->child_count = LXP_MAX_CHILD; /* already full */

	reap_to_parent(1, 99, 0, /*sigchld=*/1);

	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count,
			 LXP_MAX_CHILD); /* clamped, no overrun */
	assert_int_equal(g_lxp_rt.slots[0].proc.group->live_children,
			 LXP_MAX_CHILD); /* still decremented */
}

/* An exit reported for a parent that no longer exists is a safe no-op. */
static void test_reap_unknown_parent(void **state)
{
	(void)state;
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.pid = 1;

	reap_to_parent(/*ppid*/ 42, 7, 0, /*sigchld=*/1); /* no proc has pid 42 */

	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_mock.abort_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].proc.group->child_count, 0);
}

static void test_fork_capacity_accounts_live_and_zombie_children(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
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
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
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
	lxp_region_ref_t snapshot = vfork_snapshot(p, slot_ref_at(1), sp);
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
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
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
	g_lxp_rt.slots[1].proc.alive = 1;
	g_lxp_rt.vfork_guard[1].parent = slot_ref_at(0);
	g_lxp_rt.vfork_guard[1].parent_region = p->mm->region;
	g_lxp_rt.vfork_guard[1].snapshot = snapshot;
	assert_int_equal(vfork_restore(p, snapshot, child, sp), 0);

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
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	for (int r = 1; r < LXP_NREG; r++)
		(void)region_reserve(r, slot_ref_at(0));

	assert_int_equal(vfork_snapshot(p, slot_ref_at(1), (uintptr_t)g_mock_regions[0] + 192u)
				 .index,
			 -1);
	assert_int_equal(g_mock.cache_clean_calls, 0);
	assert_int_equal(g_lxp_rt.vfork_guard[1].snapshot.index, -1);
}

static void test_vfork_restore_rejects_recycled_snapshot(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	deferred_slot_reassign(2);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	g_lxp_rt.slots[1].proc.alive = 1;
	lxp_slot_ref_t child = slot_ref_at(1);
	lxp_region_ref_t snapshot = vfork_snapshot(p, child, sp);
	assert_int_equal(snapshot.index, 1);
	memset(g_mock_regions[0], 0x5a, sizeof(g_mock_regions[0]));
	assert_int_equal(region_release_if_owned(snapshot, child), LXP_OK);
	(void)region_reserve(1, slot_ref_at(2)); /* same index, new reservation */

	assert_int_equal(vfork_restore(p, snapshot, child, sp), -1);
	for (size_t i = 0; i < sizeof(g_mock_regions[0]); i++)
		assert_int_equal(g_mock_regions[0][i], 0x5a);
}

static void test_vfork_restore_rejects_recycled_parent(void **state)
{
	(void)state;
	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	p->alive = 1;
	p->mm->region = make_address_space_region(0, 0);
	p->stack_lo = (uintptr_t)g_mock_regions[0] + 128u;
	p->mm->region_hi = (uintptr_t)g_mock_regions[0] + sizeof(g_mock_regions[0]);
	uintptr_t sp = (uintptr_t)g_mock_regions[0] + 192u;
	g_lxp_rt.slots[1].proc.alive = 1;
	lxp_slot_ref_t child = slot_ref_at(1);
	lxp_region_ref_t snapshot = vfork_snapshot(p, child, sp);
	assert_int_equal(snapshot.index, 1);
	memset(g_mock_regions[0], 0xa5, sizeof(g_mock_regions[0]));
	deferred_slot_reassign(0); /* same slot, different process incarnation */

	assert_int_equal(vfork_restore(p, snapshot, child, sp), -1);
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
	g_lxp_rt.regions[1].lease_owner = (lxp_slot_ref_t){.index = 3, .generation = 1};
	assert_false(region_free(1));
	g_lxp_rt.regions[1].lease_owner = lxp_slot_ref_none();

	/* Accounting says free, but a live proc still runs there: the
	 * anti-trample guard must fail closed. */
	g_lxp_rt.slots[0].proc.alive = 1;
	g_lxp_rt.slots[0].proc.mm->region.index = 2;
	assert_false(region_free(2));

	/* A dead proc's stale region entry does not hold the region. */
	g_lxp_rt.slots[0].proc.alive = 0;
	assert_true(region_free(2));
}

static void test_shared_region_lives_until_last_task_reference(void **state)
{
	(void)state;
	lxp_proc_t *leader = &g_lxp_rt.slots[0].proc;
	lxp_proc_t *thread = &g_lxp_rt.slots[1].proc;

	deferred_slot_reassign(0);
	deferred_slot_reassign(1);
	lxp_region_ref_t region = region_reserve(2, slot_ref_at(0));
	assert_int_equal(region.index, 2);
	assert_int_equal(lxp_region_commit_address_space(region, slot_ref_at(0)), LXP_OK);
	leader->alive = 1;
	leader->mm->region = region;
	assert_int_equal(region_get(region), 0);
	lxp_proc_mm_put(thread);
	assert_int_equal(lxp_proc_mm_fork(thread, leader, LXP_CLONE_VM), 0);
	thread->alive = 1;
	assert_ptr_equal(thread->mm, leader->mm);
	g_lxp_rt.slots[0].host_state = SLOT_PARKED;
	g_lxp_rt.slots[1].host_state = SLOT_PARKED;
	lxp_diag_error_t error;
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	proc_mm_put(leader);
	leader->alive = 0;
	g_lxp_rt.slots[0].host_state = SLOT_FREE;
	assert_int_equal(g_lxp_rt.regions[2].refs, 1);
	assert_int_equal(g_lxp_rt.regions[2].lease_owner.index, -1);
	assert_false(region_free(2));
	assert_int_equal(lxp_validate_world(&error), LXP_OK);

	proc_mm_put(thread);
	thread->alive = 0;
	g_lxp_rt.slots[1].host_state = SLOT_FREE;
	assert_int_equal(g_lxp_rt.regions[2].refs, 0);
	assert_int_equal(g_lxp_rt.regions[2].lease_owner.index, -1);
	assert_true(region_free(2));
	assert_int_equal(lxp_validate_world(&error), LXP_OK);
}

static void test_thread_group_exit_marks_every_peer(void **state)
{
	(void)state;
	for (int s = 0; s < 3; s++) {
		g_lxp_rt.slots[s].proc.alive = 1;
		g_lxp_rt.slots[s].proc.pid = 10 + s;
		g_lxp_rt.slots[s].proc.group->tgid = s < 2 ? 10 : 12;
	}
	lxp_proc_group_put(&g_lxp_rt.slots[1].proc);
	assert_int_equal(lxp_proc_group_fork(&g_lxp_rt.slots[1].proc, &g_lxp_rt.slots[0].proc,
					     LXP_CLONE_THREAD, 11),
			 0);

	assert_int_equal(thread_group_live_count(g_lxp_rt.slots[0].proc.group), 2);
	thread_group_request_exit(1, 37);
	assert_int_equal(g_lxp_rt.slots[0].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_rt.slots[1].proc.intent.kind, LXP_INTENT_EXIT);
	assert_true(g_lxp_rt.slots[0].proc.intent.data.exit.group);
	assert_int_equal(g_lxp_rt.slots[0].proc.exit_status, 37);
	assert_int_equal(g_lxp_rt.slots[2].proc.intent.kind, LXP_INTENT_NONE);
}

/* Group exit and CLONE_VM must compose: the first reaped thread drops exactly
 * one address-space reference and the region remains unavailable until its
 * final peer commits exit. */
static void test_group_exit_releases_shared_address_space_last(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	make_valid_running_slot(1, 1);
	lxp_proc_t *leader = &g_lxp_rt.slots[0].proc;
	lxp_proc_t *thread = &g_lxp_rt.slots[1].proc;
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
	assert_int_equal(g_lxp_rt.regions[0].refs, 2);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);

	assert_int_equal(lxp_intent_exit(thread, 1), LXP_OK);
	thread->exit_status = 37;
	primary_slot_clear(1);
	(void)lxp_handle_exit(1);
	assert_false(thread->alive);
	assert_true(leader->alive);
	assert_int_equal(leader->intent.kind, LXP_INTENT_EXIT);
	assert_true(leader->intent.data.exit.group);
	assert_int_equal(g_lxp_rt.regions[0].refs, 1);
	assert_false(region_free(0));
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);

	primary_slot_clear(0);
	(void)lxp_handle_exit(0);
	assert_false(leader->alive);
	assert_int_equal(g_lxp_rt.regions[0].refs, 0);
	assert_true(region_free(0));
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

static void test_exec_stops_only_thread_group_peers(void **state)
{
	(void)state;
	for (int s = 0; s < 3; s++) {
		g_lxp_rt.slots[s].proc.alive = 1;
		g_lxp_rt.slots[s].proc.pid = 10 + s;
		g_lxp_rt.slots[s].proc.group->tgid = s < 2 ? 10 : 12;
		g_lxp_rt.slots[s].runnable = 1;
		g_lxp_rt.slots[s].host_state = SLOT_RUNNING;
	}
	lxp_proc_group_put(&g_lxp_rt.slots[1].proc);
	assert_int_equal(lxp_proc_group_fork(&g_lxp_rt.slots[1].proc, &g_lxp_rt.slots[0].proc,
					     LXP_CLONE_THREAD, 11),
			 0);

	thread_group_stop_exec_peers(0, 127);
	assert_int_equal(g_mock.abort_calls, 1);
	assert_int_equal(g_lxp_rt.slots[1].proc.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(g_lxp_rt.slots[1].proc.exit_status, 127);
	assert_int_equal(g_lxp_rt.slots[1].runnable, 0);
	assert_int_equal(g_lxp_rt.slots[0].proc.intent.kind, LXP_INTENT_NONE);
	assert_int_equal(g_lxp_rt.slots[2].proc.intent.kind, LXP_INTENT_NONE);
}

/* ---- device mappings: each process owns two independently tracked ranges --- */
static void test_device_map_index_tracks_both_ranges(void **state)
{
	(void)state;
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;

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
	lxp_proc_t *leader = &g_lxp_rt.slots[0].proc;
	lxp_proc_t *thread = &g_lxp_rt.slots[1].proc;
	leader->alive = 1;
	thread->alive = 1;
	lxp_proc_mm_put(thread);
	assert_int_equal(lxp_proc_mm_fork(thread, leader, LXP_CLONE_VM), 0);

	leader->mm->dev_map_lo[0] = 0x1000u;
	leader->mm->dev_map_hi[0] = 0x1100u;
	leader->mm->dev_map_attrs[0] = LXP_MAP_WT;

	/* A newly-created engine task reconstructs every inherited logical map. */
	assert_int_equal(coordinator_restore_mm_maps(1, thread->mm), 0);
	assert_int_equal(g_mock.map_calls, 2);
	assert_int_equal(g_mock.map_sidx[0], 1);
	assert_int_equal(g_mock.map_size[0], 0);
	assert_int_equal(g_mock.map_addr[1], 0x1000u);
	assert_int_equal(g_mock.map_size[1], 0x100u);
	assert_int_equal(g_mock.map_attrs[1], LXP_MAP_WT);

	/* A partial peer update rolls every task back to the committed mm. */
	g_mock.map_calls = 0;
	g_mock.map_fail_slot = 1;
	assert_int_equal(coordinator_map_mm_range(leader->mm, 0x2000u, 0x80u, LXP_MAP_NC),
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
		coordinator_map_mm_range(leader->mm, 0x2000u, 0x80u, LXP_MAP_NC), 0);
	assert_int_equal(g_mock.map_calls, 2);
	assert_int_equal(g_mock.map_sidx[0], 0);
	assert_int_equal(g_mock.map_sidx[1], 1);
}

/*
 * A remote exec creates its EXEC intent in the coordinator only after the 9P
 * fetch completes. It has no SVC return path to publish that primary event.
 */
static void test_netfs_exec_completion_publishes_primary_event(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	lxp_proc_t *p = &g_lxp_rt.slots[0].proc;
	assert_int_equal(coordinator_park_slot(0), LXP_OK);
	p->intent.kind = LXP_INTENT_EXEC;
	struct lxp_blocked_scan scan = {0};

	assert_false(primary_slot_pending(0));
	lxp_blocked_complete_netfs_retry(0, p, 0, &scan);

	assert_true(scan.progress);
	assert_true(primary_slot_pending(0));
	assert_int_equal(claim_slot_event(0), LXP_EV_EXEC);
	assert_int_equal(g_mock.resume_calls, 0);
	assert_int_equal(g_lxp_rt.slots[0].host_state, SLOT_PARKED);
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
	lxp_slot_ref_t stale_owner = g_lxp_rt.slots[0].deferred.owner;

	assert_int_equal(coordinator_park_slot(0), LXP_OK);
	uint8_t image[128];
	struct exec_txn tx;
	exec_txn_init(&tx, 0);
	assert_int_equal(exec_txn_validate_image(&tx, image, build_coord_fdpic(image), 0), LXP_OK);
	assert_int_equal(exec_txn_reserve(&tx), LXP_OK);
	assert_int_equal(exec_txn_commit(&tx), LXP_OK);
	assert_false(lxp_slot_ref_equal(stale_owner, slot_ref_at(0)));
	assert_int_equal(deferred_state_load(0), DEFER_IDLE);

	g_lxp_rt.slots[0].deferred.owner = stale_owner;
	deferred_state_store(0, DEFER_READY);
	int resumes = g_mock.resume_calls;
	int aborts = g_mock.abort_calls;
	execute_deferred(0);
	assert_int_equal(deferred_state_load(0), DEFER_IDLE);
	assert_int_equal(g_mock.resume_calls, resumes);
	assert_int_equal(g_mock.abort_calls, aborts);

	exec_txn_abort(&tx, -LXP_EIO, LXP_EXIT_REASON_EXEC_RESOURCE);
	assert_int_equal(lxp_validate_world(NULL), LXP_OK);
}

int test_coord_fork_exec_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_child_constructors_cover_clone_flag_matrix,
				       reset_state),
		cmocka_unit_test_setup(test_child_constructor_rolls_back_each_acquisition,
				       reset_state),
		cmocka_unit_test_setup(test_fork_build_abort_restores_world, reset_state),
		cmocka_unit_test_setup(test_fork_transaction_failpoints_restore_world, reset_state),
		cmocka_unit_test_setup(test_exec_precommit_failpoints_preserve_old_image,
				       reset_state),
		cmocka_unit_test_setup(test_exec_rejects_unloadable_image_without_free_region,
				       reset_state),
		cmocka_unit_test_setup(test_exec_stale_snapshot_contains_vfork_pair, reset_state),
		cmocka_unit_test_setup(test_exec_commit_failure_contains_only_transitioning_guest,
				       reset_state),
		cmocka_unit_test_setup(test_image_publish_failpoints_release_every_owner,
				       reset_state),
		cmocka_unit_test_setup(
			test_image_start_preserves_executable_extent_and_rolls_back_spawn_failure,
			reset_state),
		cmocka_unit_test_setup(
			test_image_start_marks_xip_launch_with_empty_executable_extent,
			reset_state),
		cmocka_unit_test_setup(
			test_image_publication_rejects_invalid_extent_generation_and_port_failure,
			reset_state),
		cmocka_unit_test_setup(test_fork_resume_clone_owns_context_mutation, reset_state),
		cmocka_unit_test_setup(test_region_references_reject_reuse_and_skip_zero,
				       reset_state),
		cmocka_unit_test_setup(test_encode_wstatus, reset_state),
		cmocka_unit_test_setup(test_netfs_exec_completion_publishes_primary_event,
				       reset_state),
		cmocka_unit_test_setup(test_exec_commit_discards_older_deferred_request,
				       reset_state),
		cmocka_unit_test_setup(test_reap_wakes_blocking_parent, reset_state),
		cmocka_unit_test_setup(test_reap_wakes_waiter_in_parent_thread_group, reset_state),
		cmocka_unit_test_setup(test_reap_signaled_child_status, reset_state),
		cmocka_unit_test_setup(test_reap_specific_pid_not_woken, reset_state),
		cmocka_unit_test_setup(test_reap_queues_zombie, reset_state),
		cmocka_unit_test_setup(test_reap_vfork_parent_suppresses_sigchld, reset_state),
		cmocka_unit_test_setup(test_reap_zombie_queue_full, reset_state),
		cmocka_unit_test_setup(test_reap_unknown_parent, reset_state),
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
	};
	return cmocka_run_group_tests_name("coordinator: fork/exec/exit", tests, NULL, NULL);
}
