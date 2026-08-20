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
#include "lxp/lxp_proc.h"

static struct {
	unsigned rootfs_window_calls;
	const void *rootfs_window_base;
	size_t rootfs_window_size;
	unsigned run_calls;
	const lxp_os_ops_t *os_ops;
	const lxp_net_ops_t *net_ops;
	const lxp_display_ops_t *display_ops;
	const lxp_fs_ops_t *fs_ops;
	const lxp_block_ops_t *block_ops;
	lxp_run_config_t run_config;
	lxp_netfs_config_t netfs_config;
	char netfs_mountpoint[LXP_NETFS_MOUNTPOINT_CAP];
	char netfs_aname[LXP_NETFS_ANAME_CAP];
	char netfs_uname[LXP_NETFS_UNAME_CAP];
	const char *path;
	int argc;
	const char *const *argv;
} g_capture;

static void mock_rootfs_window(const void *base, size_t size)
{
	g_capture.rootfs_window_calls++;
	g_capture.rootfs_window_base = base;
	g_capture.rootfs_window_size = size;
}

static const lxp_os_ops_t g_os_ops = {
	.abi_version = LXP_OS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_os_ops_t),
	.rootfs_window = mock_rootfs_window,
};
static const lxp_net_ops_t g_net_ops;
static const lxp_display_ops_t g_display_ops;
static const lxp_fs_ops_t g_fs_ops;
static const lxp_block_ops_t g_block_ops;

/* lxp_host_run() owns composition; this focused test substitutes the lower
 * coordinator entry so every forwarded field can be checked directly. */
int lxp_run(const lxp_os_ops_t *os_ops, const lxp_net_ops_t *net_ops,
	    const lxp_display_ops_t *display_ops, const lxp_fs_ops_t *fs_ops,
	    const lxp_block_ops_t *block_ops, const lxp_run_config_t *run_config, const char *path,
	    int argc, const char *const argv[])
{
	g_capture.run_calls++;
	g_capture.os_ops = os_ops;
	g_capture.net_ops = net_ops;
	g_capture.display_ops = display_ops;
	g_capture.fs_ops = fs_ops;
	g_capture.block_ops = block_ops;
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

static void mock_exit(const lxp_guest_exit_info_t *info)
{
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
		.os_ops = &g_os_ops,
		.net_ops = &g_net_ops,
		.display_ops = &g_display_ops,
		.fs_ops = &g_fs_ops,
		.block_ops = &g_block_ops,
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
	assert_int_equal(host.rootfs_count, 2);
	assert_string_equal(host.rootfs[0].path, "/");
	assert_string_equal(host.rootfs[1].path, "/bin/init");
	assert_memory_equal(host.rootfs[1].data,
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
		.write_fn = mock_write,
		.read_fn = mock_read,
		.io_ctx = &io_cookie,
		.on_enosys = mock_enosys,
		.console_poll = mock_poll,
		.env = env,
		.on_guest_exit = mock_exit,
		.display_width = 800,
		.display_height = 480,
		.rt_scope_read = mock_rt_scope,
		.rt_scope_ctx = &host,
		.console_subscribe = mock_console_subscribe,
		.console_unsubscribe = mock_console_unsubscribe,
	};
	assert_int_equal(lxp_host_run(&host, &launch, "/bin/init", 1, argv), 37);
	assert_int_equal(g_capture.run_calls, 1);
	assert_ptr_equal(g_capture.os_ops, &g_os_ops);
	assert_ptr_equal(g_capture.net_ops, &g_net_ops);
	assert_ptr_equal(g_capture.display_ops, &g_display_ops);
	assert_ptr_equal(g_capture.fs_ops, &g_fs_ops);
	assert_ptr_equal(g_capture.block_ops, &g_block_ops);
	assert_ptr_equal(g_capture.run_config.rootfs, rootfs);
	assert_int_equal(g_capture.run_config.rootfs_count, 2);
	assert_ptr_equal(g_capture.run_config.rootfs_image, image);
	assert_int_equal(g_capture.run_config.rootfs_image_size, image_size);
	assert_ptr_equal(g_capture.run_config.write_fn, mock_write);
	assert_ptr_equal(g_capture.run_config.read_fn, mock_read);
	assert_ptr_equal(g_capture.run_config.io_ctx, &io_cookie);
	assert_ptr_equal(g_capture.run_config.on_enosys, mock_enosys);
	assert_ptr_equal(g_capture.run_config.console_poll, mock_poll);
	assert_ptr_equal(g_capture.run_config.env, env);
	assert_ptr_equal(g_capture.run_config.on_guest_exit, mock_exit);
	assert_int_equal(g_capture.run_config.display_width, 800);
	assert_int_equal(g_capture.run_config.display_height, 480);
	assert_ptr_equal(g_capture.run_config.rt_scope_read, mock_rt_scope);
	assert_ptr_equal(g_capture.run_config.rt_scope_ctx, &host);
	assert_ptr_equal(g_capture.run_config.console_subscribe, mock_console_subscribe);
	assert_ptr_equal(g_capture.run_config.console_unsubscribe, mock_console_unsubscribe);
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
}

static void test_failed_reinit_clears_previous_host(void **state)
{
	(void)state;
	uint8_t image[512] = {0};
	lxp_file_t rootfs[4];
	char names[64];
	lxp_host_t host;
	const lxp_host_config_t good = {
		.os_ops = &g_os_ops,
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
	assert_int_equal(lxp_host_init_cpio(&host, &bad), LXP_ERR_INVAL);
	assert_int_equal(host.initialized, 0);
	assert_int_equal(lxp_host_run(&host, NULL, "/bin/init", 1, NULL), LXP_RUN_ELAUNCH);
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
	config.os_ops = &bad_ops;
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
		.os_ops = &g_os_ops,
		.net_ops = &g_net_ops,
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
	assert_int_equal(host.initialized, 0);

	config.netfs_config = NULL;
	config.net_ops = NULL;
	config.netif = (lxp_netif_t)&host;
	assert_int_equal(lxp_host_init_cpio(&host, &config), LXP_ERR_INVALID_PARAM);
	assert_int_equal(g_capture.rootfs_window_calls, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_host_parses_once_and_composes_each_launch),
		cmocka_unit_test(test_failed_reinit_clears_previous_host),
		cmocka_unit_test(test_host_rejects_invalid_contract_before_rootfs_access),
		cmocka_unit_test(test_host_rejects_invalid_topology_before_rootfs_access),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
