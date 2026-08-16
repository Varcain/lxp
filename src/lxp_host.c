/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Reusable provider/rootfs composition for hosts embedding LXP.
 */

#include "lxp/lxp_host.h"

#include <string.h>

#include "lxp/lxp_bootstrap.h"

#define LXP_HOST_INITIALIZED 0x4c585048u /* "LXPH" */

int lxp_host_init_cpio(lxp_host_t *host, const lxp_host_config_t *config)
{
	if (!host)
		return LXP_ERR_INVALID_PARAM;
	memset(host, 0, sizeof(*host));
	if (!config || !config->os_ops || config->os_ops->abi_version != LXP_OS_OPS_ABI_VERSION ||
	    config->os_ops->struct_size != sizeof(*config->os_ops) || !config->rootfs_image ||
	    config->rootfs_image_size == 0u || !config->rootfs_storage ||
	    config->rootfs_capacity <= 0 || !config->rootfs_name_storage ||
	    config->rootfs_name_capacity == 0u)
		return LXP_ERR_INVALID_PARAM;

	uintptr_t lo = (uintptr_t)config->rootfs_image;
	if (lo + config->rootfs_image_size < lo)
		return LXP_ERR_INVALID_PARAM;

	/* Some targets must change MPU/cache attributes before even parsing an
	 * external-memory archive. lxp_run() repeats this publication per launch so
	 * a port can also restore a run-scoped coordinator mapping. */
	if (config->os_ops->rootfs_window)
		config->os_ops->rootfs_window(config->rootfs_image, config->rootfs_image_size);

	int count = lxp_cpio_to_rootfs(config->rootfs_image, config->rootfs_image_size,
				       config->rootfs_storage, config->rootfs_capacity,
				       config->rootfs_name_storage, config->rootfs_name_capacity);
	if (count <= 0)
		return LXP_ERR_INVAL;

	host->os_ops = config->os_ops;
	host->net_ops = config->net_ops;
	host->display_ops = config->display_ops;
	host->fs_ops = config->fs_ops;
	host->block_ops = config->block_ops;
	host->rootfs = config->rootfs_storage;
	host->rootfs_count = count;
	host->rootfs_image = config->rootfs_image;
	host->rootfs_image_size = config->rootfs_image_size;
	host->initialized = LXP_HOST_INITIALIZED;
	return LXP_OK;
}

int lxp_host_run(const lxp_host_t *host, const lxp_launch_config_t *launch_config, const char *path,
		 int argc, const char *const argv[])
{
	if (!host || host->initialized != LXP_HOST_INITIALIZED)
		return LXP_RUN_ELAUNCH;

	lxp_run_config_t config = {
		.rootfs = host->rootfs,
		.rootfs_count = host->rootfs_count,
		.rootfs_image = host->rootfs_image,
		.rootfs_image_size = host->rootfs_image_size,
	};
	if (launch_config) {
		config.write_fn = launch_config->write_fn;
		config.read_fn = launch_config->read_fn;
		config.io_ctx = launch_config->io_ctx;
		config.on_enosys = launch_config->on_enosys;
		config.console_poll = launch_config->console_poll;
		config.env = launch_config->env;
		config.on_guest_exit = launch_config->on_guest_exit;
		config.display_width = launch_config->display_width;
		config.display_height = launch_config->display_height;
		config.rt_scope_read = launch_config->rt_scope_read;
		config.rt_scope_ctx = launch_config->rt_scope_ctx;
	}

	return lxp_run(host->os_ops, host->net_ops, host->display_ops, host->fs_ops,
		       host->block_ops, &config, path, argc, argv);
}
