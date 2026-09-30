/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The coordinator tests' fake host; see lxp_mock_engine.h.
 */
#include <setjmp.h> /* cmocka ordering */
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "run/lxp_coordinator.h"
#include "lxp_mock_engine.h"

const lxp_net_ops_t *g_test_net_ops;

struct lxp_mock_state g_mock;

uint8_t g_mock_regions[LXP_NREG][256] __attribute__((aligned(256)));
uint8_t g_mock_dyn_pools[LXP_NREG][64];
lxp_exec_capture_t g_mock_exec_captures[LXP_NSLOT];
lxp_arena_t g_mock_arenas[LXP_NSLOT];
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
static int mock_spawn_launch(int sidx, uint32_t generation, int ridx,
			     const lxp_guest_launch_t *launch)
{
	(void)ridx;
	g_mock.launch_calls++;
	g_mock.launch_sidx = sidx;
	g_mock.launch_generation = generation;
	g_mock.launch = *launch;
	g_mock.launch_observed_runnable = (uint8_t)lxp_slot_ref_is_runnable((lxp_slot_ref_t){
		.index = (int16_t)sidx,
		.generation = generation,
	});
	g_mock.launch_observed_host_state = lxp_slot_host_state(sidx);
	if (g_mock.launch_failures > 0) {
		g_mock.launch_failures--;
		return LXP_ERR_IO; /* engines report lxp_err_t */
	}
	return LXP_OK;
}
static int mock_spawn_resume(int sidx, uint32_t generation, int ridx, lxp_spawn_resume_mode_t mode,
			     const struct lxp_resume_ctx *c, long r0)
{
	(void)ridx;
	g_mock.resume_calls++;
	g_mock.resume_sidx = sidx;
	g_mock.resume_generation = generation;
	g_mock.resume_mode = mode;
	g_mock.resume_observed_runnable = (uint8_t)lxp_slot_ref_is_runnable((lxp_slot_ref_t){
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
		return LXP_ERR_IO; /* engines report lxp_err_t */
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
		return LXP_ERR_IO; /* engines report lxp_err_t */
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
		return LXP_ERR_IO; /* engines report lxp_err_t */
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
				? g_lxp_rt.regions[proc->mm->region.index].refs
				: 0;
		g_mock.wait_observed_trap_active = lxp_trap_active();
	}
}
static lxp_critical_token_t mock_crit_enter(void)
{
	g_mock.critical_enter_calls++;
	return (lxp_critical_token_t)0xa5a5u;
}
static void mock_crit_exit(lxp_critical_token_t token)
{
	g_mock.critical_exit_calls++;
	g_mock.critical_exit_token = token;
}
static void mock_park_entry(void *token)
{
	(void)token;
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

const lxp_cpu_memory_contract_t g_mock_memory_contract = {
	.abi_version = LXP_CPU_MEMORY_CONTRACT_ABI_VERSION,
	.struct_size = sizeof(lxp_cpu_memory_contract_t),
	.model = LXP_CPU_MEM_UNCACHED,
	.normal_attrs = LXP_CPU_MEM_ATTR_NORMAL_NC_NSH,
};

static int mock_validate_memory_contract(const lxp_cpu_memory_contract_t *declared)
{
	return declared == &g_mock_memory_contract ? LXP_OK : LXP_ERR_INVALID_PARAM;
}
static int mock_publish_executable(lxp_region_ref_t address_space, uintptr_t base, size_t size)
{
	g_mock.publish_executable_calls++;
	g_mock.publish_address_space = address_space;
	g_mock.publish_base = base;
	g_mock.publish_size = size;
	g_mock.publish_observed_alive = g_lxp_rt.slots[1].proc.alive;
	return g_mock.publish_result;
}
static int mock_prepare(void)
{
	g_mock.prepare_calls++;
	if (g_mock.net_ready_fire_in_prepare && g_mock.net_ready)
		g_mock.net_ready(g_mock.net_ready_context);
	if (g_mock.fs_ready_fire_in_prepare && g_mock.fs_ready)
		g_mock.fs_ready(g_mock.fs_ready_context);
	return g_mock.prepare_result;
}
static void mock_teardown(void)
{
	g_mock.teardown_calls++;
}
int mock_net_begin(lxp_net_ready_fn ready, const void *context)
{
	g_mock.net_begin_calls++;
	if (g_mock.net_begin_result != LXP_OK)
		return g_mock.net_begin_result;
	g_mock.net_ready = ready;
	g_mock.net_ready_context = context;
	return LXP_OK;
}
void mock_net_end(void)
{
	g_mock.net_end_calls++;
	g_mock.net_ready = NULL;
	g_mock.net_ready_context = NULL;
}
int mock_console_subscribe(void *ctx, lxp_console_ready_fn ready,
				  const void *ready_context)
{
	(void)ctx;
	g_mock.console_subscribe_calls++;
	if (g_mock.console_subscribe_result != LXP_OK)
		return g_mock.console_subscribe_result;
	g_mock.console_ready = ready;
	g_mock.console_ready_context = ready_context;
	ready(ready_context);
	return LXP_OK;
}
void mock_console_unsubscribe(void *ctx)
{
	(void)ctx;
	g_mock.console_unsubscribe_calls++;
	g_mock.console_ready = NULL;
	g_mock.console_ready_context = NULL;
}
long mock_console_read(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	(void)buf;
	(void)len;
	return 0;
}
int mock_console_poll(void *ctx)
{
	(void)ctx;
	return 0;
}

struct lxp_console_script g_console_script;

void console_script(const char *data, size_t len)
{
	g_console_script.data = (const uint8_t *)data;
	g_console_script.len = len;
	g_console_script.pos = 0;
}

long script_console_read(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (len == 0 || g_console_script.pos >= g_console_script.len)
		return 0;
	*(uint8_t *)buf = g_console_script.data[g_console_script.pos++];
	return 1;
}

int script_console_poll(void *ctx)
{
	(void)ctx;
	return g_console_script.pos < g_console_script.len;
}

/* The coordinator suite enables the writable-filesystem path so its blocked
 * completion semantics are compiled exactly as in firmware. Most tests never
 * perform storage I/O; this complete provider keeps lxp_run() validation and
 * lifecycle tests representative without introducing host filesystem state. */
static int mock_fs_begin(lxp_fs_ready_fn ready, const void *context)
{
	g_mock.fs_begin_calls++;
	g_mock.fs_ready = ready;
	g_mock.fs_ready_context = context;
	return LXP_OK;
}
static void mock_fs_end(void)
{
	g_mock.fs_end_calls++;
	g_mock.fs_ready = NULL;
	g_mock.fs_ready_context = NULL;
}
static void mock_fs_owner(uint64_t owner)
{
	(void)owner;
}
static int mock_fs_file_open(const char *path, unsigned flags, lxp_fs_file_t *out)
{
	(void)path;
	(void)flags;
	(void)out;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_object_open(const char *path, unsigned flags, int require_dir,
			       lxp_fs_open_result_t *out)
{
	(void)path;
	(void)flags;
	(void)require_dir;
	(void)out;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_close(lxp_fs_file_t file)
{
	(void)file;
	return LXP_OK;
}
static int mock_fs_file_read(lxp_fs_file_t file, void *buf, size_t count, size_t *done)
{
	(void)file;
	(void)buf;
	(void)count;
	(void)done;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_write(lxp_fs_file_t file, const void *buf, size_t count, size_t *done)
{
	(void)file;
	(void)buf;
	(void)count;
	(void)done;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_seek(lxp_fs_file_t file, int64_t offset, int whence, uint64_t *position)
{
	(void)file;
	(void)offset;
	(void)whence;
	(void)position;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_stat(lxp_fs_file_t file, lxp_fs_stat_t *out)
{
	(void)file;
	(void)out;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_truncate(lxp_fs_file_t file, uint64_t length)
{
	(void)file;
	(void)length;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_sync(lxp_fs_file_t file)
{
	(void)file;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_pread(lxp_fs_file_t file, void *buf, size_t count, uint64_t offset,
			      size_t *done)
{
	(void)file;
	(void)buf;
	(void)count;
	(void)offset;
	(void)done;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_file_pwrite(lxp_fs_file_t file, const void *buf, size_t count, uint64_t offset,
			       size_t *done)
{
	(void)file;
	(void)buf;
	(void)count;
	(void)offset;
	(void)done;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_dir_open(const char *path, lxp_fs_dir_t *out)
{
	(void)path;
	(void)out;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_dir_read(lxp_fs_dir_t dir, lxp_fs_dirent_t *entry)
{
	(void)dir;
	(void)entry;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_dir_close(lxp_fs_dir_t dir)
{
	(void)dir;
	return LXP_OK;
}
static int mock_fs_path_stat(const char *path, lxp_fs_stat_t *out)
{
	(void)path;
	(void)out;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_path_one(const char *path)
{
	(void)path;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_path_rename(const char *old_path, const char *new_path)
{
	(void)old_path;
	(void)new_path;
	return LXP_ERR_NOT_FOUND;
}
static int mock_fs_metrics(lxp_fs_metrics_t *out)
{
	memset(out, 0, sizeof(*out));
	return LXP_OK;
}
static int mock_fs_mount(const lxp_fs_mount_spec_t *spec)
{
	(void)spec;
	return LXP_OK;
}
static int mock_fs_unmount(void)
{
	return LXP_OK;
}
static int mock_fs_is_mounted(void)
{
	return 1;
}
static int mock_fs_volume_stat(lxp_fs_volume_stat_t *out)
{
	memset(out, 0, sizeof(*out));
	out->block_size = 512u;
	out->fragment_size = 512u;
	return LXP_OK;
}

const lxp_fs_ops_t g_mock_fs_ops = {
	.abi_version = LXP_FS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_fs_ops_t),
	.run_begin = mock_fs_begin,
	.run_end = mock_fs_end,
	.request_owner = mock_fs_owner,
	.request_cancel = mock_fs_owner,
	.mount = mock_fs_mount,
	.unmount = mock_fs_unmount,
	.is_mounted = mock_fs_is_mounted,
	.volume_stat = mock_fs_volume_stat,
	.file_open = mock_fs_file_open,
	.object_open = mock_fs_object_open,
	.file_close = mock_fs_file_close,
	.file_read = mock_fs_file_read,
	.file_write = mock_fs_file_write,
	.file_seek = mock_fs_file_seek,
	.file_stat = mock_fs_file_stat,
	.file_truncate = mock_fs_file_truncate,
	.file_sync = mock_fs_file_sync,
	.file_pread = mock_fs_file_pread,
	.file_pwrite = mock_fs_file_pwrite,
	.dir_open = mock_fs_dir_open,
	.dir_read = mock_fs_dir_read,
	.dir_close = mock_fs_dir_close,
	.path_stat = mock_fs_path_stat,
	.path_mkdir = mock_fs_path_one,
	.path_rmdir = mock_fs_path_one,
	.path_unlink = mock_fs_path_one,
	.path_rename = mock_fs_path_rename,
	.metrics = mock_fs_metrics,
};
static const char *mock_system_version(void)
{
	return "MockRTOS 9.8.7 ove-fedcba9 lxp-7654321";
}

const lxp_os_ops_t g_mock_eng = {
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
	.park_entry = mock_park_entry,
	.park_prepare = mock_park_prepare,
	.park_slot = mock_park_slot,
	.crit_enter = mock_crit_enter,
	.crit_exit = mock_crit_exit,
	.event_post = mock_event_post,
	.event_wait = mock_event_wait,
	.map_device = mock_map_device,
	.time_us = mock_time,
	.time_ns = mock_time,
	.random_fill = mock_random_fill,
	.cache_clean = mock_cache_clean,
	.cache_invalidate = mock_cache_invalidate,
	.coord_map = mock_coord_map,
	.publish_executable = mock_publish_executable,
	.cpu_memory_contract = &g_mock_memory_contract,
	.validate_memory_contract = mock_validate_memory_contract,
	.system_version = mock_system_version,
};

static void mock_on_guest_exit(void *ctx, const lxp_guest_exit_info_t *info)
{
	assert_ptr_equal(ctx, &g_mock);
	g_mock.exit_notify_calls++;
	g_mock.exit_info = *info;
}

const lxp_run_config_t g_mock_cfg = {
	.launch.on_guest_exit = mock_on_guest_exit,
	.launch.guest_exit_ctx = &g_mock,
};
