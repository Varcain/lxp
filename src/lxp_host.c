/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Reusable provider/rootfs composition for hosts embedding LXP.
 */

#include "lxp/lxp_host.h"
#include "lxp/lxp_observe.h"

#include <string.h>

#include "lxp/lxp_bootstrap.h"

#define LXP_HOST_INITIALIZED 0x4c585048u /* "LXPH" */

static void copy_config_string(char *dst, size_t capacity, const char *src)
{
	size_t len = src ? strlen(src) : 0u;
	if (len != 0u)
		memcpy(dst, src, len);
	dst[len < capacity ? len : capacity - 1u] = '\0';
}

int lxp_host_init_cpio(lxp_host_t *host, const lxp_host_config_t *config)
{
	if (!host)
		return LXP_ERR_INVALID_PARAM;
	memset(host, 0, sizeof(*host));
	const lxp_os_ops_t *os_ops = config ? config->providers.os : NULL;
	if (!os_ops || os_ops->abi_version != LXP_OS_OPS_ABI_VERSION ||
	    os_ops->struct_size != sizeof(*os_ops) || !config->rootfs_image ||
	    config->rootfs_image_size == 0u || !config->rootfs_storage ||
	    config->rootfs_capacity <= 0 || !config->rootfs_name_storage ||
	    config->rootfs_name_capacity == 0u)
		return LXP_ERR_INVALID_PARAM;
#if LXP_ENABLE_NET
	if (config->netif && !config->providers.net)
		return LXP_ERR_INVALID_PARAM;
#else
	if (config->netif)
		return LXP_ERR_INVALID_PARAM;
#endif
#if LXP_ENABLE_NETFS
	if (config->netfs_config &&
	    (!config->providers.net || !lxp_netfs_config_valid(config->netfs_config)))
		return LXP_ERR_INVALID_PARAM;
#else
	if (config->netfs_config)
		return LXP_ERR_INVALID_PARAM;
#endif

	uintptr_t lo = (uintptr_t)config->rootfs_image;
	if (lo + config->rootfs_image_size < lo)
		return LXP_ERR_INVALID_PARAM;

	/* Some targets must change MPU/cache attributes before even parsing an
	 * external-memory archive. lxp_run() repeats this publication per launch so
	 * a port can also restore a run-scoped coordinator mapping. */
	if (os_ops->rootfs_window)
		os_ops->rootfs_window(config->rootfs_image, config->rootfs_image_size);

	int count = lxp_cpio_to_rootfs(config->rootfs_image, config->rootfs_image_size,
				       config->rootfs_storage, config->rootfs_capacity,
				       config->rootfs_name_storage, config->rootfs_name_capacity);
	if (count <= 0)
		return LXP_ERR_INVALID_PARAM;

	host->providers = config->providers;
	host->rootfs = config->rootfs_storage;
	host->rootfs_count = count;
	host->rootfs_image = config->rootfs_image;
	host->rootfs_image_size = config->rootfs_image_size;
	host->netif = config->netif;
	if (config->netfs_config) {
		copy_config_string(host->netfs_mountpoint, sizeof(host->netfs_mountpoint),
				   config->netfs_config->mountpoint);
		memcpy(host->netfs_server_ip, config->netfs_config->server_ip,
		       sizeof(host->netfs_server_ip));
		host->netfs_port = config->netfs_config->port;
		copy_config_string(host->netfs_aname, sizeof(host->netfs_aname),
				   config->netfs_config->aname);
		copy_config_string(host->netfs_uname, sizeof(host->netfs_uname),
				   (config->netfs_config->uname && config->netfs_config->uname[0])
					   ? config->netfs_config->uname
					   : "root");
		host->netfs_configured = 1u;
	}
	host->initialized = LXP_HOST_INITIALIZED;
	return LXP_OK;
}

int lxp_host_run(const lxp_host_t *host, const lxp_launch_config_t *launch_config, const char *path,
		 int argc, const char *const argv[])
{
	if (!host || host->initialized != LXP_HOST_INITIALIZED)
		return LXP_ERR_INVALID_PARAM;
	lxp_netfs_config_t netfs_config = {
		.mountpoint = host->netfs_mountpoint,
		.server_ip = {host->netfs_server_ip[0], host->netfs_server_ip[1],
			      host->netfs_server_ip[2], host->netfs_server_ip[3]},
		.port = host->netfs_port,
		.aname = host->netfs_aname,
		.uname = host->netfs_uname,
	};

	lxp_run_config_t config = {
		.rootfs = host->rootfs,
		.rootfs_count = host->rootfs_count,
		.rootfs_image = host->rootfs_image,
		.rootfs_image_size = host->rootfs_image_size,
		.netif = host->netif,
		.netfs_config = host->netfs_configured ? &netfs_config : NULL,
	};
	if (launch_config) {
		config.console = launch_config->console;
		config.on_enosys = launch_config->on_enosys;
		config.env = launch_config->env;
		config.on_guest_exit = launch_config->on_guest_exit;
		config.guest_exit_ctx = launch_config->guest_exit_ctx;
		config.display_width = launch_config->display_width;
		config.display_height = launch_config->display_height;
		config.rt_scope_read = launch_config->rt_scope_read;
		config.rt_scope_ctx = launch_config->rt_scope_ctx;
	}

	return lxp_run(&host->providers, &config, path, argc, argv);
}

int lxp_host_observe(const lxp_host_t *host, lxp_host_observation_t *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	memset(out, 0, sizeof(*out));
	if (!host || host->initialized != LXP_HOST_INITIALIZED)
		return LXP_ERR_INVALID_PARAM;

	out->abi_version = LXP_HOST_OBSERVATION_ABI_VERSION;
	out->struct_size = sizeof(*out);
	lxp_run_health(&out->run_health);
	if (out->run_health.active) {
		memset(out, 0, sizeof(*out));
		return LXP_ERR_BUSY;
	}
	lxp_diag_size_report(&out->sizes);
	lxp_diag_health(&out->diagnostics);

	if (host->providers.os->guest_stack_usage) {
		size_t used = 0u;
		size_t size = 0u;
		if (host->providers.os->guest_stack_usage(&used, &size) == LXP_OK && size != 0u &&
		    used <= size) {
			out->guest_stack.used = used;
			out->guest_stack.size = size;
			out->guest_stack.available = 1u;
		}
	}

#if LXP_ENABLE_LATENCY
	for (int service = 1; service < LXP_LAT_CLASSES; service++) {
		const lxp_lat_stat_t *stat = lxp_lat_service_get(service);
		lxp_latency_observation_t *row =
			&out->latency_services[out->latency_service_count++];
		row->id = (uint32_t)service;
		if (stat)
			row->stat = *stat;
	}
	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		const lxp_lat_stat_t *stat = lxp_lat_wake_get(slot);
		lxp_latency_observation_t *row =
			&out->latency_wakes[out->latency_wake_count++];
		row->id = (uint32_t)slot;
		if (stat)
			row->stat = *stat;
	}
#endif
	return LXP_OK;
}

const char *lxp_host_observation_service_name(const lxp_host_observation_t *observation,
					      unsigned row)
{
#if LXP_ENABLE_LATENCY
	if (!observation || observation->abi_version != LXP_HOST_OBSERVATION_ABI_VERSION ||
	    observation->struct_size != sizeof(*observation) ||
	    row >= observation->latency_service_count)
		return "?";
	return lxp_lat_class_name((int)observation->latency_services[row].id);
#else
	(void)observation;
	(void)row;
	return "?";
#endif
}
