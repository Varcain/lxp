/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator tests for the run entry: provider and configuration validation, memory-policy
 * snapshots, initial launch and host-service routing.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "lxp_internal.h"
#include "run/lxp_initial.h"
#include "run/lxp_validate.h"
#include "../framework/lxp_coord_fixture.h"
#include "../framework/lxp_mock_engine.h"

static void test_memory_policy_snapshot_and_key_track_every_generation(void **state)
{
	(void)state;
	make_valid_running_slot(0, 2);
	lxp_slot_ref_t slot = lxp_slot_ref_at(0);
	lxp_mm_t *mm = g_lxp_rt.slots[0].proc.mm;
	mm->device_generation = 7u;
	mm->exec_generation = 11u;
	mm->copied_text_executable = 1u;
	mm->region_lo = 0x20000000u;
	mm->region_hi = 0x20040000u;
	mm->copied_text_base = 0x20000000u;
	mm->copied_text_size = LXP_PROG_REGION_SIZE / 2u;
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
	assert_int_equal(policy.copied_text_base, 0x20000000u);
	assert_int_equal(policy.copied_text_size, LXP_PROG_REGION_SIZE / 2u);
	assert_int_equal(policy.device_count, 1u);
	assert_int_equal(policy.devices[0].base, 0x40001000u);
	assert_int_equal(policy.devices[0].size, 0x1000u);
	assert_int_equal(policy.devices[0].attrs, LXP_MAP_DEV);
	assert_int_equal(lxp_memory_policy_validate(&policy), LXP_OK);

	lxp_memory_policy_key_t key = lxp_memory_policy_make_key(&policy);
	assert_true(lxp_memory_policy_matches_key(&policy, &key));
	mm->device_generation++;
	assert_int_equal(lxp_slot_memory_policy(slot, &policy), LXP_OK);
	assert_false(lxp_memory_policy_matches_key(&policy, &key));
	assert_true(lxp_memory_policy_address_space_matches_key(&policy, &key) == 0);

	lxp_slot_ref_t stale = slot;
	lxp_deferred_slot_reassign(0);
	assert_int_equal(lxp_slot_memory_policy(stale, &policy), LXP_ERR_NOT_FOUND);
}

static void test_memory_policy_validator_rejects_noncanonical_snapshots(void **state)
{
	(void)state;
	make_valid_running_slot(0, 2);
	lxp_slot_ref_t slot = lxp_slot_ref_at(0);
	lxp_mm_t *mm = g_lxp_rt.slots[0].proc.mm;
	mm->device_generation = 7u;
	mm->exec_generation = 11u;
	mm->dev_map_lo[0] = 0x40001000u;
	mm->dev_map_hi[0] = 0x40002000u;
	mm->dev_map_attrs[0] = LXP_MAP_DEV;

	lxp_memory_policy_t canonical;
	assert_int_equal(lxp_slot_memory_policy(slot, &canonical), LXP_OK);

	lxp_memory_policy_t invalid = canonical;
	invalid.abi_version++;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	lxp_memory_policy_key_t invalid_key = lxp_memory_policy_make_key(&invalid);
	lxp_memory_policy_key_t empty_key = {0};
	assert_memory_equal(&invalid_key, &empty_key, sizeof(invalid_key));

	invalid = canonical;
	invalid.struct_size--;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.slot.generation = 0;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.address_space.index = LXP_NREG;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.device_generation = 0;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.copied_text_executable = 2u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.copied_text_executable = 1u;
	invalid.copied_text_base = 0x20000000u;
	invalid.copied_text_size = LXP_PROG_REGION_SIZE / 4u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.copied_text_size = 0x18000u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.copied_text_base++;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.copied_text_base = 0x20000000u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.device_count = LXP_MEMORY_DEVICE_MAX + 1u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.devices[0].size = 0;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.devices[0].base = UINTPTR_MAX - 1u;
	invalid.devices[0].size = 4u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.devices[0].attrs = LXP_MAP_DEV + 1u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
	invalid = canonical;
	invalid.devices[1].size = 1u;
	assert_int_equal(lxp_memory_policy_validate(&invalid), LXP_ERR_INVALID_PARAM);
}

static void test_system_version_routes_to_engine(void **state)
{
	(void)state;
	assert_string_equal(lxp_system_version(), "MockRTOS 9.8.7 ove-fedcba9 lxp-7654321");
	lxp_os_publish(NULL);
	assert_string_equal(lxp_system_version(), "lxp");
}

static void test_port_abi_and_required_ops_are_validated(void **state)
{
	(void)state;
	assert_true(lxp_os_ops_valid(&g_mock_eng));
	assert_true(lxp_net_ops_valid(g_test_net_ops));

	lxp_net_ops_t net_ops = *g_test_net_ops;
	net_ops.abi_version++;
	assert_false(lxp_net_ops_valid(&net_ops));
	net_ops = *g_test_net_ops;
	net_ops.struct_size--;
	assert_false(lxp_net_ops_valid(&net_ops));
	net_ops = *g_test_net_ops;
	net_ops.run_begin = NULL;
	assert_false(lxp_net_ops_valid(&net_ops));
	net_ops = *g_test_net_ops;
	net_ops.capabilities = LXP_NET_CAP_SOCKET_READY_EVENT << 1;
	assert_false(lxp_net_ops_valid(&net_ops));

	lxp_os_ops_t ops = g_mock_eng;
	ops.abi_version++;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.struct_size--;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.random_fill = NULL;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.park_entry = NULL;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.publish_executable = NULL;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.cpu_memory_contract = NULL;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	lxp_cpu_memory_contract_t invalid_contract = g_mock_memory_contract;
	invalid_contract.abi_version++;
	ops.cpu_memory_contract = &invalid_contract;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	invalid_contract = g_mock_memory_contract;
	invalid_contract.struct_size--;
	ops.cpu_memory_contract = &invalid_contract;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	invalid_contract = g_mock_memory_contract;
	invalid_contract.model = (lxp_cpu_memory_model_t)99;
	ops.cpu_memory_contract = &invalid_contract;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	invalid_contract = g_mock_memory_contract;
	invalid_contract.normal_attrs = LXP_CPU_MEM_ATTR_NORMAL_WBWA_NSH;
	ops.cpu_memory_contract = &invalid_contract;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	invalid_contract = g_mock_memory_contract;
	invalid_contract.flags = 1u << 31;
	ops.cpu_memory_contract = &invalid_contract;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	invalid_contract = g_mock_memory_contract;
	invalid_contract.flags = LXP_CPU_MEMORY_ICACHE_ENABLED;
	invalid_contract.icache_line_size = 24u;
	invalid_contract.icache_size = 16u * 1024u;
	ops.cpu_memory_contract = &invalid_contract;
	assert_false(lxp_os_ops_valid(&ops));
	ops = g_mock_eng;
	ops.validate_memory_contract = NULL;
	assert_false(lxp_os_ops_valid(&ops));
}

static void test_failed_prepare_is_rolled_back(void **state)
{
	(void)state;
	uint8_t image[1] = {0};
	const lxp_file_t files[] = {
		{.path = "/init", .data = image, .size = sizeof(image), .mode = LXP_S_IFREG | 0755},
	};
	const lxp_run_config_t cfg = {
		.rootfs = files,
		.rootfs_count = 1,
		.rootfs_image = image,
		.rootfs_image_size = sizeof(image),
	};
	const char *const argv[] = {"init", NULL};
	lxp_net_ops_t net_ops = *g_test_net_ops;
	net_ops.run_begin = mock_net_begin;
	net_ops.run_end = mock_net_end;
	lxp_net_ops_t invalid_net_ops = net_ops;
	invalid_net_ops.run_end = NULL;
	assert_int_equal(lxp_run(&g_mock_eng, &invalid_net_ops, NULL, &g_mock_fs_ops, NULL, &cfg,
				 "/init", 1, argv),
			 LXP_ERR_INVALID_PARAM);
	assert_int_equal(g_mock.net_begin_calls, 0);
	assert_int_equal(g_mock.prepare_calls, 0);

	g_mock.prepare_result = LXP_ERR_IO;
	g_mock.net_ready_fire_in_prepare = 1;
	g_mock.fs_ready_fire_in_prepare = 1;
	assert_int_equal(lxp_run(&g_mock_eng, &net_ops, NULL, &g_mock_fs_ops, NULL, &cfg, "/init",
			 1, argv),
			 LXP_ERR_IO);
	assert_int_equal(g_mock.net_begin_calls, 1);
	assert_int_equal(g_mock.net_end_calls, 1);
	assert_int_equal(g_mock.fs_begin_calls, 1);
	assert_int_equal(g_mock.fs_end_calls, 1);
	assert_int_equal(g_mock.prepare_calls, 1);
	assert_int_equal(g_mock.teardown_calls, 1);
	assert_int_equal(g_mock.event_posts, 2);
	assert_null(g_mock.net_ready);
	assert_null(g_mock.net_ready_context);
	assert_null(g_mock.fs_ready);
	assert_null(g_mock.fs_ready_context);
	assert_null(g_lxp_os_ops);
	assert_null(g_lxp_rt.cfg);
	assert_null(g_lxp_rt.rootfs_lo);
	assert_null(g_lxp_rt.rootfs_hi);
	assert_null(g_lxp_net_ops);

	/* A rejected provider acquisition never starts host preparation or releases
	 * an already-active provider state through run_end(). */
	g_mock.net_begin_result = LXP_ERR_WOULD_BLOCK;
	assert_int_equal(lxp_run(&g_mock_eng, &net_ops, NULL, &g_mock_fs_ops, NULL, &cfg, "/init",
				 1, argv),
			 LXP_ERR_WOULD_BLOCK);
	assert_int_equal(g_mock.net_begin_calls, 2);
	assert_int_equal(g_mock.net_end_calls, 1);
	assert_int_equal(g_mock.prepare_calls, 1);
	assert_int_equal(g_mock.teardown_calls, 1);
	assert_null(g_lxp_net_ops);
}

static void test_run_reports_why_launch_failed(void **state)
{
	(void)state;
	uint8_t image[1] = {0};
	const lxp_file_t files[] = {
		{.path = "/init", .data = image, .size = sizeof(image), .mode = LXP_S_IFREG | 0755},
	};
	const lxp_run_config_t cfg = {
		.rootfs = files,
		.rootfs_count = 1,
		.rootfs_image = image,
		.rootfs_image_size = sizeof(image),
	};
	const char *const argv[] = {"init", NULL};
	lxp_net_ops_t net_ops = *g_test_net_ops;
	net_ops.run_begin = mock_net_begin;
	net_ops.run_end = mock_net_end;

	assert_int_equal(lxp_run(&g_mock_eng, &net_ops, NULL, &g_mock_fs_ops, NULL, &cfg, "/init",
				 0, argv),
			 LXP_ERR_INVALID_PARAM);
	assert_int_equal(lxp_run(&g_mock_eng, &net_ops, NULL, &g_mock_fs_ops, NULL, &cfg,
				 "/missing", 1, argv),
			 LXP_ERR_NOT_FOUND);
	assert_int_equal(lxp_run(&g_mock_eng, &net_ops, NULL, &g_mock_fs_ops, NULL, &cfg, "/init",
				 1, argv),
			 LXP_ERR_NOT_SUPPORTED); /* one byte is not an executable */
	assert_int_equal(g_mock.teardown_calls, 2);
}

static void test_initial_launch_resolves_scripts_and_symlinks(void **state)
{
	(void)state;
	static const uint8_t busybox[] = {0x7f, 'E', 'L', 'F'};
	static const uint8_t shell_link[] = "busybox";
	static const uint8_t script[] = "#!/bin/sh -e\nexec ignored\n";
	static const uint8_t malformed[] = "#!  \n";
	const lxp_file_t files[] = {
		{.path = "/bin/busybox",
		 .data = busybox,
		 .size = sizeof(busybox),
		 .mode = LXP_S_IFREG | 0755},
		{.path = "/bin/sh",
		 .data = shell_link,
		 .size = sizeof(shell_link) - 1u,
		 .mode = LXP_S_IFLNK | 0777},
		{.path = "/usr/libexec/guest",
		 .data = script,
		 .size = sizeof(script) - 1u,
		 .mode = LXP_S_IFREG | 0755},
		{.path = "/usr/libexec/bad",
		 .data = malformed,
		 .size = sizeof(malformed) - 1u,
		 .mode = LXP_S_IFREG | 0755},
	};
	const lxp_run_config_t cfg = {
		.rootfs = files,
		.rootfs_count = (int)(sizeof(files) / sizeof(files[0])),
	};
	const char *const script_argv[] = {"guest", "boot", "verbose", NULL};
	struct lxp_initial_image image;
	assert_int_equal(lxp_initial_resolve(&cfg, "/usr/libexec/guest", 3, script_argv, &image),
			 0);
	assert_ptr_equal(image.data, busybox);
	assert_int_equal(image.size, sizeof(busybox));
	assert_int_equal(image.file_index, 0);
	assert_int_equal(image.argc, 5);
	assert_string_equal(image.argv[0], "/bin/sh");
	assert_string_equal(image.argv[1], "-e");
	assert_string_equal(image.argv[2], "/usr/libexec/guest");
	assert_string_equal(image.argv[3], "boot");
	assert_string_equal(image.argv[4], "verbose");
	assert_null(image.argv[5]);

	const char *const direct_argv[] = {"sh", NULL};
	assert_int_equal(lxp_initial_resolve(&cfg, "/bin/sh", 1, direct_argv, &image), 0);
	assert_ptr_equal(image.data, busybox);
	assert_int_equal(image.file_index, 0);
	assert_int_equal(image.argc, 1);
	assert_string_equal(image.argv[0], "sh");
	assert_int_equal(lxp_initial_resolve(&cfg, "/usr/libexec/bad", 1, direct_argv, &image),
			 -LXP_ENOEXEC);
	assert_int_equal(lxp_initial_resolve(&cfg, "/missing", 1, direct_argv, &image),
			 -LXP_ENOENT);
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
	assert_true(lxp_run_config_valid(&cfg));

	cfg.rootfs_image = image + 8;
	cfg.rootfs_image_size = 8;
	assert_false(lxp_run_config_valid(&cfg));
	cfg.rootfs_image = NULL;
	assert_false(lxp_run_config_valid(&cfg));
}

/* Storage sync may enter an SD/FAT provider and therefore must never execute
 * in the constant-time SVC top half, even when the current fd is an inert one. */
static void test_storage_sync_is_deferred(void **state)
{
	(void)state;
	make_valid_running_slot(0, 0);
	struct lxp_frame frame;
	memset(&frame, 0, sizeof(frame));
	frame.r[0] = 1; /* stdout: valid, with no persistent backing in this fixture */
	frame.r[7] = LXP_NR_fsync;

	assert_int_equal(lxp_dispatch_slot(lxp_slot_ref_at(0), &frame), LXP_OK);
	assert_int_equal(lxp_deferred_state_load(0), DEFER_READY);
	assert_int_equal(g_mock.event_posts, 1);
	lxp_execute_deferred(0);
	assert_int_equal(g_mock.resume_r0, 0);
}

int test_coord_run_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_memory_policy_snapshot_and_key_track_every_generation,
				       reset_state),
		cmocka_unit_test_setup(test_memory_policy_validator_rejects_noncanonical_snapshots,
				       reset_state),
		cmocka_unit_test_setup(test_system_version_routes_to_engine, reset_state),
		cmocka_unit_test_setup(test_port_abi_and_required_ops_are_validated, reset_state),
		cmocka_unit_test_setup(test_failed_prepare_is_rolled_back, reset_state),
		cmocka_unit_test_setup(test_run_reports_why_launch_failed, reset_state),
		cmocka_unit_test_setup(test_initial_launch_resolves_scripts_and_symlinks,
				       reset_state),
		cmocka_unit_test_setup(test_rootfs_requires_one_explicit_trusted_window,
				       reset_state),
		cmocka_unit_test_setup(test_storage_sync_is_deferred, reset_state),
	};
	return cmocka_run_group_tests_name("coordinator: run entry", tests, NULL, NULL);
}
