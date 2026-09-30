/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Focused contract tests for the zero-heap LXP host facade.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "lxp/lxp_host.h"
#include "lxp/lxp_diag.h"
#include "lxp/lxp_latency.h"
#include "lxp/lxp_observe.h"
#include "proc/lxp_proc.h"

static struct {
	unsigned rootfs_window_calls;
	const void *rootfs_window_base;
	size_t rootfs_window_size;
	unsigned run_calls;
	lxp_providers_t providers;
	lxp_run_config_t run_config;
	lxp_netfs_config_t netfs_config;
	char netfs_mountpoint[LXP_NETFS_MOUNTPOINT_CAP];
	char netfs_aname[LXP_NETFS_ANAME_CAP];
	char netfs_uname[LXP_NETFS_UNAME_CAP];
	const char *path;
	int argc;
	const char *const *argv;
} g_capture;

static lxp_run_health_t g_mock_run_health;
static lxp_diag_size_report_t g_mock_sizes;
static lxp_diag_health_t g_mock_diagnostics;
static lxp_lat_stat_t g_mock_services[LXP_LAT_CLASSES];
static lxp_lat_stat_t g_mock_wakes[LXP_NSLOT];

void lxp_run_health(lxp_run_health_t *out)
{
	if (out)
		*out = g_mock_run_health;
}

void lxp_diag_size_report(lxp_diag_size_report_t *out)
{
	if (out)
		*out = g_mock_sizes;
}

void lxp_diag_health(lxp_diag_health_t *out)
{
	if (out)
		*out = g_mock_diagnostics;
}

const lxp_lat_stat_t *lxp_lat_service_get(int cls)
{
	return cls >= 0 && cls < LXP_LAT_CLASSES ? &g_mock_services[cls] : NULL;
}

const lxp_lat_stat_t *lxp_lat_wake_get(int slot)
{
	return slot >= 0 && slot < LXP_NSLOT ? &g_mock_wakes[slot] : NULL;
}

const char *lxp_lat_class_name(int cls)
{
	static const char *const names[LXP_LAT_CLASSES] = {
		"none",
#define LXP_LAT_X(name) #name,
		LXP_LAT_CLASS_LIST(LXP_LAT_X)
#undef LXP_LAT_X
	};
	return cls >= 0 && cls < LXP_LAT_CLASSES ? names[cls] : "?";
}

static void mock_rootfs_window(const void *base, size_t size)
{
	g_capture.rootfs_window_calls++;
	g_capture.rootfs_window_base = base;
	g_capture.rootfs_window_size = size;
}

static int mock_guest_stack_usage(size_t *used, size_t *size)
{
	assert_non_null(used);
	assert_non_null(size);
	*used = 144u;
	*size = 768u;
	return LXP_OK;
}

static const lxp_os_ops_t g_os_ops = {
	.abi_version = LXP_OS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_os_ops_t),
	.rootfs_window = mock_rootfs_window,
	.guest_stack_usage = mock_guest_stack_usage,
};
static const lxp_net_ops_t g_net_ops;
static const lxp_display_ops_t g_display_ops;
static const lxp_fs_ops_t g_fs_ops;
static const lxp_block_ops_t g_block_ops;
static const lxp_providers_t g_all_providers = {
	.os = &g_os_ops,
	.net = &g_net_ops,
	.display = &g_display_ops,
	.fs = &g_fs_ops,
	.block = &g_block_ops,
};

/* lxp_host_run() owns composition; this focused test substitutes the lower
 * coordinator entry so every forwarded field can be checked directly. */
int lxp_run(const lxp_providers_t *providers, const lxp_run_config_t *run_config,
	    const char *path, int argc, const char *const argv[])
{
	g_capture.run_calls++;
	g_capture.providers = *providers;
	g_capture.run_config = *run_config;
	if (run_config->netfs_config) {
		g_capture.netfs_config = *run_config->netfs_config;
		strcpy(g_capture.netfs_mountpoint, run_config->netfs_config->mountpoint);
		strcpy(g_capture.netfs_aname, run_config->netfs_config->aname);
		strcpy(g_capture.netfs_uname, run_config->netfs_config->uname);
		g_capture.netfs_config.mountpoint = g_capture.netfs_mountpoint;
		g_capture.netfs_config.aname = g_capture.netfs_aname;
		g_capture.netfs_config.uname = g_capture.netfs_uname;
		g_capture.run_config.netfs_config = &g_capture.netfs_config;
	}
	g_capture.path = path;
	g_capture.argc = argc;
	g_capture.argv = argv;
	return 37;
}

/* lxp_bootstrap.c also owns stack setup; its entropy dependency is irrelevant
 * to these CPIO tests but must be satisfied by the focused link. */
int lxp_random_fill(void *buf, size_t len)
{
	memset(buf, 0xa5, len);
	return LXP_OK;
}

static size_t cpio_emit(uint8_t *buf, size_t off, const char *name, uint32_t mode, const void *data,
			uint32_t data_size)
{
	uint32_t name_size = (uint32_t)strlen(name) + 1u;
	uint32_t fields[13] = {1u, mode, 0u, 0u, 1u, 0u, data_size, 0u, 0u, 0u, 0u, name_size, 0u};
	char hex[9];
	memcpy(buf + off, "070701", 6u);
	off += 6u;
	for (size_t i = 0; i < 13u; i++) {
		int n = snprintf(hex, sizeof(hex), "%08x", fields[i]);
		assert_int_equal(n, 8);
		memcpy(buf + off, hex, 8u);
		off += 8u;
	}
	memcpy(buf + off, name, name_size);
	off += name_size;
	while ((off & 3u) != 0u)
		buf[off++] = 0u;
	if (data_size != 0u) {
		memcpy(buf + off, data, data_size);
		off += data_size;
		while ((off & 3u) != 0u)
			buf[off++] = 0u;
	}
	return off;
}

static size_t make_rootfs(uint8_t *image)
{
	static const uint8_t init[] = {0x7fu, 'E', 'L', 'F'};
	size_t size = 0u;
	size = cpio_emit(image, size, ".", LXP_S_IFDIR | 0755u, NULL, 0u);
	size = cpio_emit(image, size, "bin/init", LXP_S_IFREG | 0755u, init, sizeof(init));
	size = cpio_emit(image, size, "TRAILER!!!", 0u, NULL, 0u);
	return size;
}

static long mock_write(void *ctx, int fd, const void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	(void)buf;
	return (long)len;
}

static long mock_read(void *ctx, int fd, void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	(void)buf;
	(void)len;
	return 0;
}

static int mock_poll(void *ctx)
{
	return ctx != NULL;
}

static int mock_console_subscribe(void *ctx, lxp_console_ready_fn ready,
				  const void *ready_context)
{
	(void)ctx;
	(void)ready;
	(void)ready_context;
	return LXP_OK;
}

static void mock_console_unsubscribe(void *ctx)
{
	(void)ctx;
}

static long mock_rt_scope(void *ctx, char *buf, size_t cap)
{
	(void)ctx;
	(void)buf;
	(void)cap;
	return 0;
}

static void mock_enosys(long nr)
{
	(void)nr;
}

static void mock_exit(void *ctx, const lxp_guest_exit_info_t *info)
{
	(void)ctx;
	(void)info;
}

static void test_host_parses_once_and_composes_each_launch(void **state)
{
	(void)state;
	uint8_t image[512] = {0};
	lxp_file_t rootfs[4];
	char names[64];
	lxp_host_t host;
	const size_t image_size = make_rootfs(image);
	int netif_cookie;
	char mountpoint[] = "/mnt/pi";
	char aname[] = "/srv";
	char uname[] = "guest";
	const lxp_netfs_config_t netfs = {
		.mountpoint = mountpoint,
		.server_ip = {172, 1, 1, 1},
		.port = 564,
		.aname = aname,
		.uname = uname,
	};
	const lxp_host_config_t config = {
		.providers = g_all_providers,
		.rootfs_image = image,
		.rootfs_image_size = image_size,
		.rootfs_storage = rootfs,
		.rootfs_capacity = 4,
		.rootfs_name_storage = names,
		.rootfs_name_capacity = sizeof(names),
		.netif = (lxp_netif_t)&netif_cookie,
		.netfs_config = &netfs,
	};

	memset(&g_capture, 0, sizeof(g_capture));
	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_OK);
	assert_int_equal(g_capture.rootfs_window_calls, 1);
	assert_ptr_equal(g_capture.rootfs_window_base, image);
	assert_int_equal(g_capture.rootfs_window_size, image_size);
	assert_string_equal(rootfs[0].path, "/");
	assert_string_equal(rootfs[1].path, "/bin/init");
	assert_memory_equal(rootfs[1].data,
			    "\x7f"
			    "ELF",
			    4);
	/* Topology belongs to the initialized host, not the caller's temporary
	 * config strings. */
	mountpoint[1] = 'X';
	aname[1] = 'X';
	uname[0] = 'X';

	int io_cookie = 1;
	const char *const env[] = {"PATH=/bin", NULL};
	const char *const argv[] = {"init", NULL};
	const lxp_launch_config_t launch = {
		.console =
			{
				.write = mock_write,
				.read = mock_read,
				.poll = mock_poll,
				.subscribe = mock_console_subscribe,
				.unsubscribe = mock_console_unsubscribe,
				.ctx = &io_cookie,
			},
		.on_enosys = mock_enosys,
		.env = env,
		.on_guest_exit = mock_exit,
		.guest_exit_ctx = &io_cookie,
		.rt_scope_read = mock_rt_scope,
		.rt_scope_ctx = &host,
	};
	assert_int_equal(lxp_host_run(&host, &launch, "/bin/init", 1, argv), 37);
	assert_int_equal(g_capture.run_calls, 1);
	assert_ptr_equal(g_capture.providers.os, &g_os_ops);
	assert_ptr_equal(g_capture.providers.net, &g_net_ops);
	assert_ptr_equal(g_capture.providers.display, &g_display_ops);
	assert_ptr_equal(g_capture.providers.fs, &g_fs_ops);
	assert_ptr_equal(g_capture.providers.block, &g_block_ops);
	assert_ptr_equal(g_capture.run_config.rootfs, rootfs);
	assert_int_equal(g_capture.run_config.rootfs_count, 2);
	assert_ptr_equal(g_capture.run_config.rootfs_image, image);
	assert_int_equal(g_capture.run_config.rootfs_image_size, image_size);
	assert_ptr_equal(g_capture.run_config.launch.console.write, mock_write);
	assert_ptr_equal(g_capture.run_config.launch.console.read, mock_read);
	assert_ptr_equal(g_capture.run_config.launch.console.ctx, &io_cookie);
	assert_ptr_equal(g_capture.run_config.launch.on_enosys, mock_enosys);
	assert_ptr_equal(g_capture.run_config.launch.console.poll, mock_poll);
	assert_ptr_equal(g_capture.run_config.launch.env, env);
	assert_ptr_equal(g_capture.run_config.launch.on_guest_exit, mock_exit);
	assert_ptr_equal(g_capture.run_config.launch.guest_exit_ctx, &io_cookie);
	assert_ptr_equal(g_capture.run_config.launch.rt_scope_read, mock_rt_scope);
	assert_ptr_equal(g_capture.run_config.launch.rt_scope_ctx, &host);
	assert_ptr_equal(g_capture.run_config.launch.console.subscribe, mock_console_subscribe);
	assert_ptr_equal(g_capture.run_config.launch.console.unsubscribe, mock_console_unsubscribe);
	assert_ptr_equal(g_capture.run_config.netif, &netif_cookie);
	assert_non_null(g_capture.run_config.netfs_config);
	assert_string_equal(g_capture.run_config.netfs_config->mountpoint, "/mnt/pi");
	assert_memory_equal(g_capture.run_config.netfs_config->server_ip,
			    ((const uint8_t[]){172, 1, 1, 1}), 4);
	assert_int_equal(g_capture.run_config.netfs_config->port, 564);
	assert_string_equal(g_capture.run_config.netfs_config->aname, "/srv");
	assert_string_equal(g_capture.run_config.netfs_config->uname, "guest");
	assert_string_equal(g_capture.path, "/bin/init");
	assert_int_equal(g_capture.argc, 1);
	assert_ptr_equal(g_capture.argv, argv);

	/* Reuse the parsed host without inheriting launch-scoped callbacks from the
	 * preceding invocation. Host-owned providers and topology remain present. */
	assert_int_equal(lxp_host_run(&host, NULL, "/bin/init", 1, argv), 37);
	assert_int_equal(g_capture.run_calls, 2);
	assert_ptr_equal(g_capture.providers.os, &g_os_ops);
	assert_ptr_equal(g_capture.providers.net, &g_net_ops);
	assert_ptr_equal(g_capture.providers.display, &g_display_ops);
	assert_ptr_equal(g_capture.providers.fs, &g_fs_ops);
	assert_ptr_equal(g_capture.providers.block, &g_block_ops);
	assert_null(g_capture.run_config.launch.console.write);
	assert_null(g_capture.run_config.launch.console.read);
	assert_null(g_capture.run_config.launch.console.ctx);
	assert_null(g_capture.run_config.launch.on_guest_exit);
	assert_null(g_capture.run_config.launch.rt_scope_read);
	assert_ptr_equal(g_capture.run_config.netif, &netif_cookie);
	assert_non_null(g_capture.run_config.netfs_config);
	assert_string_equal(g_capture.run_config.netfs_config->mountpoint, "/mnt/pi");
}

static void test_failed_reinit_clears_previous_host(void **state)
{
	(void)state;
	uint8_t image[512] = {0};
	lxp_file_t rootfs[4];
	char names[64];
	lxp_host_t host;
	const lxp_host_config_t good = {
		.providers = {.os = &g_os_ops},
		.rootfs_image = image,
		.rootfs_image_size = make_rootfs(image),
		.rootfs_storage = rootfs,
		.rootfs_capacity = 4,
		.rootfs_name_storage = names,
		.rootfs_name_capacity = sizeof(names),
	};
	assert_int_equal(lxp_host_init_cpio(&host, &good), LXP_OK);

	lxp_host_config_t bad = good;
	bad.rootfs_image_size = 16u;
	assert_int_equal(lxp_host_init_cpio(&host, &bad), LXP_ERR_INVALID_PARAM);
	assert_int_equal(lxp_host_run(&host, NULL, "/bin/init", 1, NULL), LXP_ERR_INVALID_PARAM);
}

static void test_host_rejects_invalid_contract_before_rootfs_access(void **state)
{
	(void)state;
	lxp_host_t host;
	lxp_host_config_t config = {0};
	lxp_os_ops_t bad_ops = g_os_ops;
	memset(&g_capture, 0, sizeof(g_capture));
	assert_int_equal(lxp_host_init_cpio(NULL, &config), LXP_ERR_INVALID_PARAM);
	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_ERR_INVALID_PARAM);
	bad_ops.abi_version++;
	config.providers.os = &bad_ops;
	config.rootfs_image = &host;
	config.rootfs_image_size = sizeof(host);
	config.rootfs_storage = (lxp_file_t *)&host;
	config.rootfs_capacity = 1;
	config.rootfs_name_storage = (char *)&host;
	config.rootfs_name_capacity = sizeof(host);
	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_ERR_INVALID_PARAM);
	assert_int_equal(g_capture.rootfs_window_calls, 0);
}

static void test_host_rejects_invalid_topology_before_rootfs_access(void **state)
{
	(void)state;
	uint8_t image[512] = {0};
	lxp_file_t rootfs[4];
	char names[64];
	lxp_host_t host;
	const lxp_netfs_config_t invalid_netfs = {
		.mountpoint = "relative",
		.server_ip = {127, 0, 0, 1},
		.port = 564,
	};
	lxp_host_config_t config = {
		.providers = {.os = &g_os_ops, .net = &g_net_ops},
		.rootfs_image = image,
		.rootfs_image_size = make_rootfs(image),
		.rootfs_storage = rootfs,
		.rootfs_capacity = 4,
		.rootfs_name_storage = names,
		.rootfs_name_capacity = sizeof(names),
		.netfs_config = &invalid_netfs,
	};
	memset(&g_capture, 0, sizeof(g_capture));
	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_ERR_INVALID_PARAM);
	assert_int_equal(g_capture.rootfs_window_calls, 0);
	assert_int_equal(lxp_host_run(&host, NULL, "/bin/init", 1, NULL), LXP_ERR_INVALID_PARAM);

	config.netfs_config = NULL;
	config.providers.net = NULL;
	config.netif = (lxp_netif_t)&host;
	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_ERR_INVALID_PARAM);
	assert_int_equal(g_capture.rootfs_window_calls, 0);
}

static void test_host_copies_one_coherent_observation(void **state)
{
	(void)state;
	uint8_t image[512] = {0};
	lxp_file_t rootfs[4];
	char names[64];
	lxp_host_t host;
	lxp_host_observation_t observation;
	const lxp_host_config_t config = {
		.providers = {.os = &g_os_ops},
		.rootfs_image = image,
		.rootfs_image_size = make_rootfs(image),
		.rootfs_storage = rootfs,
		.rootfs_capacity = 4,
		.rootfs_name_storage = names,
		.rootfs_name_capacity = sizeof(names),
	};

	memset(&g_mock_run_health, 0, sizeof(g_mock_run_health));
	memset(&g_mock_sizes, 0, sizeof(g_mock_sizes));
	memset(&g_mock_diagnostics, 0, sizeof(g_mock_diagnostics));
	memset(g_mock_services, 0, sizeof(g_mock_services));
	memset(g_mock_wakes, 0, sizeof(g_mock_wakes));
	g_mock_run_health.coord_iters = 1234u;
	g_mock_sizes.slots = LXP_NSLOT;
	g_mock_sizes.regions = LXP_NREG;
	g_mock_diagnostics.checks = 91u;
	g_mock_services[LXP_EV_FORK].count = 7u;
	g_mock_services[LXP_EV_FORK].max_ns = 8100u;
	g_mock_wakes[2].count = 3u;
	g_mock_wakes[2].buckets[4] = 3u;

	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_OK);
	assert_int_equal(lxp_host_observe(&host, &observation), LXP_OK);
	assert_int_equal(observation.run_health.coord_iters, 1234u);
	assert_int_equal(observation.sizes.slots, LXP_NSLOT);
	assert_int_equal(observation.diagnostics.checks, 91u);
	assert_int_equal(observation.guest_stack.available, 1u);
	assert_int_equal(observation.guest_stack.used, 144u);
	assert_int_equal(observation.guest_stack.size, 768u);
	assert_int_equal(observation.latency_service_count, LXP_LAT_CLASSES - 1);
	assert_int_equal(observation.latency_wake_count, LXP_NSLOT);
	assert_int_equal(observation.latency_services[LXP_EV_FORK - 1].id, LXP_EV_FORK);
	assert_int_equal(observation.latency_services[LXP_EV_FORK - 1].stat.count, 7u);
	assert_int_equal(observation.latency_services[LXP_EV_FORK - 1].stat.max_ns, 8100u);
	const lxp_latency_observation_t *fork_row = &observation.latency_services[LXP_EV_FORK - 1];
	assert_string_equal(lxp_lat_class_name((int)fork_row->id), "FORK");
	assert_int_equal(observation.latency_wakes[2].id, 2u);
	assert_int_equal(observation.latency_wakes[2].stat.buckets[4], 3u);

	/* The record is a copy: later registry mutation cannot rewrite it. */
	g_mock_services[LXP_EV_FORK].count = 99u;
	assert_int_equal(observation.latency_services[LXP_EV_FORK - 1].stat.count, 7u);
}

static void test_host_observation_fails_closed(void **state)
{
	(void)state;
	lxp_host_t host = {0};
	lxp_host_observation_t observation;
	memset(&observation, 0xa5, sizeof(observation));
	assert_int_equal(lxp_host_observe(NULL, &observation), LXP_ERR_INVALID_PARAM);
	assert_int_equal(observation.latency_service_count, 0u);
	memset(&observation, 0xa5, sizeof(observation));
	assert_int_equal(lxp_host_observe(&host, &observation), LXP_ERR_INVALID_PARAM);
	assert_int_equal(observation.run_health.coord_iters, 0u);
	assert_int_equal(lxp_host_observe(&host, NULL), LXP_ERR_INVALID_PARAM);

	/* An active coordinator would make the multi-registry copy inconsistent. */
	uint8_t image[512] = {0};
	lxp_file_t rootfs[4];
	char names[64];
	const lxp_host_config_t config = {
		.providers = {.os = &g_os_ops},
		.rootfs_image = image,
		.rootfs_image_size = make_rootfs(image),
		.rootfs_storage = rootfs,
		.rootfs_capacity = 4,
		.rootfs_name_storage = names,
		.rootfs_name_capacity = sizeof(names),
	};
	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_OK);
	g_mock_run_health.active = 1;
	assert_int_equal(lxp_host_observe(&host, &observation), LXP_ERR_BUSY);
	assert_int_equal(observation.diagnostics.checks, 0u);
	g_mock_run_health.active = 0;
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_host_parses_once_and_composes_each_launch),
		cmocka_unit_test(test_failed_reinit_clears_previous_host),
		cmocka_unit_test(test_host_rejects_invalid_contract_before_rootfs_access),
		cmocka_unit_test(test_host_rejects_invalid_topology_before_rootfs_access),
		cmocka_unit_test(test_host_copies_one_coherent_observation),
		cmocka_unit_test(test_host_observation_fails_closed),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
