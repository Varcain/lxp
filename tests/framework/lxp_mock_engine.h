/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The coordinator tests' fake host (tests/framework/lxp_mock_engine.c): an engine that
 * records every lifecycle callback in g_mock instead of running native tasks, program
 * regions and pools in host memory, a scripted console transport, and fs and net providers.
 */
#ifndef LXP_MOCK_ENGINE_H
#define LXP_MOCK_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp.h"
#include "lxp/lxp_program.h"
#include "lxp/lxp_seam.h"
#include "lxp_arena.h"
#include "proc/lxp_proc.h"

/* Everything the mock engine was asked to do, for tests to assert on; reset_state clears
 * it before each test. */
struct lxp_mock_state {
	int launch_calls;
	int launch_sidx;
	uint32_t launch_generation;
	uint8_t launch_observed_runnable;
	uint8_t launch_observed_host_state;
	lxp_guest_launch_t launch;
	int launch_failures;
	int publish_executable_calls;
	lxp_region_ref_t publish_address_space;
	uintptr_t publish_base;
	size_t publish_size;
	int publish_observed_alive;
	int publish_result;
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
	int critical_enter_calls;
	int critical_exit_calls;
	lxp_critical_token_t critical_exit_token;
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
	int net_begin_calls;
	int net_begin_result;
	int net_end_calls;
	lxp_net_ready_fn net_ready;
	const void *net_ready_context;
	int net_ready_fire_in_prepare;
	int fs_begin_calls;
	int fs_end_calls;
	lxp_fs_ready_fn fs_ready;
	const void *fs_ready_context;
	int fs_ready_fire_in_prepare;
	int console_subscribe_calls;
	int console_subscribe_result;
	int console_unsubscribe_calls;
	lxp_console_ready_fn console_ready;
	const void *console_ready_context;
};

/* A console transport that delivers a fixed byte script, one byte per read. */
struct lxp_console_script {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

/* The mock engine and its record. */
extern const lxp_os_ops_t g_mock_eng;
extern struct lxp_mock_state g_mock;
extern const lxp_cpu_memory_contract_t g_mock_memory_contract;

/* The program regions, dynamic pools, exec captures and arenas it hands out, in host memory. */
extern uint8_t g_mock_regions[LXP_NREG][256];
extern uint8_t g_mock_dyn_pools[LXP_NREG][64];
extern lxp_exec_capture_t g_mock_exec_captures[LXP_NSLOT];
extern lxp_arena_t g_mock_arenas[LXP_NSLOT];

/* Providers: the POSIX network provider (set by main), a filesystem that records its
 * run-scoped callbacks, and the run configuration. */
extern const lxp_net_ops_t *g_test_net_ops;
extern const lxp_fs_ops_t g_mock_fs_ops;
extern const lxp_run_config_t g_mock_cfg;
int mock_net_begin(lxp_net_ready_fn ready, const void *context);
void mock_net_end(void);

/* Console transports: one that records subscriptions, and one that plays back a script. */
int mock_console_subscribe(void *ctx, lxp_console_ready_fn ready, const void *ready_context);
void mock_console_unsubscribe(void *ctx);
long mock_console_read(void *ctx, int fd, void *buf, size_t len);
int mock_console_poll(void *ctx);
extern struct lxp_console_script g_console_script;
void console_script(const char *data, size_t len);
long script_console_read(void *ctx, int fd, void *buf, size_t len);
int script_console_poll(void *ctx);

#endif /* LXP_MOCK_ENGINE_H */
