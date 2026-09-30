/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Reusable provider/rootfs composition for hosts embedding LXP.
 */

#include "lxp/lxp_host.h"
#include "run/lxp_diag.h"
#include "lxp_latency.h"
#include "lxp/lxp_observe.h"

#include <string.h>

#include "lxp/lxp_bootstrap.h"

#define LXP_HOST_INITIALIZED 0x4c585048u /* "LXPH" */

#if defined(__GNUC__)
#define LXP_HOST_MAY_ALIAS __attribute__((__may_alias__))
#else
#define LXP_HOST_MAY_ALIAS
#endif

/* The record behind the opaque lxp_host_t storage. */
typedef struct LXP_HOST_MAY_ALIAS lxp_host_state {
	lxp_providers_t providers;
	const lxp_file_t *rootfs;
	int rootfs_count;
	const void *rootfs_image;
	size_t rootfs_image_size;
	lxp_netif_t netif;
	char netfs_mountpoint[LXP_NETFS_MOUNTPOINT_CAP];
	uint8_t netfs_server_ip[4];
	uint16_t netfs_port;
	char netfs_aname[LXP_NETFS_ANAME_CAP];
	char netfs_uname[LXP_NETFS_UNAME_CAP];
	uint32_t netfs_configured;
	uint32_t initialized;
} lxp_host_state_t;

LXP_STATIC_ASSERT(sizeof(lxp_host_state_t) <= sizeof(lxp_host_t),
		  "the host record outgrew LXP_HOST_STORAGE_WORDS");
LXP_STATIC_ASSERT(_Alignof(lxp_host_state_t) <= _Alignof(lxp_host_t),
		  "lxp_host_t storage is not aligned for the host record");

static lxp_host_state_t *host_state(lxp_host_t *host)
{
	return (lxp_host_state_t *)(void *)host->_storage;
}

static const lxp_host_state_t *host_state_const(const lxp_host_t *host)
{
	return host ? (const lxp_host_state_t *)(const void *)host->_storage : NULL;
}

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
	lxp_host_state_t *state = host_state(host);
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
	if (os_ops->memory.rootfs_window)
		os_ops->memory.rootfs_window(config->rootfs_image, config->rootfs_image_size);

	int count = lxp_cpio_to_rootfs(config->rootfs_image, config->rootfs_image_size,
				       config->rootfs_storage, config->rootfs_capacity,
				       config->rootfs_name_storage, config->rootfs_name_capacity);
	if (count <= 0)
		return LXP_ERR_INVALID_PARAM;

	state->providers = config->providers;
	state->rootfs = config->rootfs_storage;
	state->rootfs_count = count;
	state->rootfs_image = config->rootfs_image;
	state->rootfs_image_size = config->rootfs_image_size;
	state->netif = config->netif;
	if (config->netfs_config) {
		copy_config_string(state->netfs_mountpoint, sizeof(state->netfs_mountpoint),
				   config->netfs_config->mountpoint);
		memcpy(state->netfs_server_ip, config->netfs_config->server_ip,
		       sizeof(state->netfs_server_ip));
		state->netfs_port = config->netfs_config->port;
		copy_config_string(state->netfs_aname, sizeof(state->netfs_aname),
				   config->netfs_config->aname);
		copy_config_string(state->netfs_uname, sizeof(state->netfs_uname),
				   (config->netfs_config->uname && config->netfs_config->uname[0])
					   ? config->netfs_config->uname
					   : "root");
		state->netfs_configured = 1u;
	}
	state->initialized = LXP_HOST_INITIALIZED;
	return LXP_OK;
}

int lxp_host_run(const lxp_host_t *host, const lxp_launch_config_t *launch_config, const char *path,
		 int argc, const char *const argv[])
{
	const lxp_host_state_t *state = host_state_const(host);
	if (!state || state->initialized != LXP_HOST_INITIALIZED)
		return LXP_ERR_INVALID_PARAM;
	lxp_netfs_config_t netfs_config = {
		.mountpoint = state->netfs_mountpoint,
		.server_ip = {state->netfs_server_ip[0], state->netfs_server_ip[1],
			      state->netfs_server_ip[2], state->netfs_server_ip[3]},
		.port = state->netfs_port,
		.aname = state->netfs_aname,
		.uname = state->netfs_uname,
	};

	lxp_run_config_t config = {
		.rootfs = state->rootfs,
		.rootfs_count = state->rootfs_count,
		.rootfs_image = state->rootfs_image,
		.rootfs_image_size = state->rootfs_image_size,
		.netif = state->netif,
		.netfs_config = state->netfs_configured ? &netfs_config : NULL,
	};
	if (launch_config)
		config.launch = *launch_config;

	return lxp_run(&state->providers, &config, path, argc, argv);
}

int lxp_host_observe(const lxp_host_t *host, lxp_host_observation_t *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	memset(out, 0, sizeof(*out));
	const lxp_host_state_t *state = host_state_const(host);
	if (!state || state->initialized != LXP_HOST_INITIALIZED)
		return LXP_ERR_INVALID_PARAM;

	lxp_run_health(&out->run_health);
	if (out->run_health.active) {
		memset(out, 0, sizeof(*out));
		return LXP_ERR_BUSY;
	}
	lxp_diag_size_report(&out->sizes);
	lxp_diag_health(&out->diagnostics);

	if (state->providers.os->task.guest_stack_usage) {
		size_t used = 0u;
		size_t size = 0u;
		if (state->providers.os->task.guest_stack_usage(&used, &size) == LXP_OK &&
		    size != 0u && used <= size) {
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
