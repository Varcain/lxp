/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Reusable host composition and immutable rootfs bootstrap.
 */

#ifndef LXP_HOST_H
#define LXP_HOST_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_run.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Inputs used once to construct an LXP host from a newc CPIO image.
 *
 * The caller owns every referenced provider and storage object for at least as
 * long as the resulting @ref lxp_host_t. LXP parses the archive without
 * allocating: @p rootfs_storage receives the immutable file table and
 * @p rootfs_name_storage receives its normalized absolute pathnames.
 */
typedef struct lxp_host_config {
	lxp_providers_t providers; /**< The services every run of this host uses. */
	const void *rootfs_image;
	size_t rootfs_image_size;
	lxp_file_t *rootfs_storage;
	int rootfs_capacity;
	char *rootfs_name_storage;
	size_t rootfs_name_capacity;
	/** Optional native interface exposed as eth0 for this host's runs. */
	lxp_netif_t netif;
	/** Optional 9P mount topology. All strings are copied into the host. */
	const lxp_netfs_config_t *netfs_config;
} lxp_host_config_t;

/** Per-launch policy layered over an initialized host's immutable rootfs and
 * provider composition. Zero initialization selects every optional default. */
typedef struct lxp_launch_config {
	lxp_console_t console;
	void (*on_enosys)(long nr);
	const char *const *env;
	lxp_guest_exit_fn on_guest_exit;
	uint16_t display_width;
	uint16_t display_height;
	lxp_rt_scope_read_fn rt_scope_read;
	void *rt_scope_ctx;
	void *guest_exit_ctx;
} lxp_launch_config_t;

/** Immutable, zero-heap host instance. Treat fields as read-only after a
 * successful @ref lxp_host_init_cpio call. Sequential launches may reuse one
 * instance; concurrent @ref lxp_host_run calls are not supported. */
typedef struct lxp_host {
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
} lxp_host_t;

/**
 * Publish the rootfs memory window to the OS port, then parse a newc CPIO image
 * into caller-owned storage. The port hook runs before the first archive read,
 * which is required by hosts that must first install a safe mapping for the
 * external memory holding the image (for example a memory-mapped flash window).
 *
 * @return @c LXP_OK, or @c LXP_ERR_INVALID_PARAM for an invalid contract, a malformed
 * archive, or table/name storage too small for it.
 */
int lxp_host_init_cpio(lxp_host_t *host, const lxp_host_config_t *config);

/** Run one Linux init program using the host's providers and rootfs. Returns what
 * @ref lxp_run returns, or @c LXP_ERR_INVALID_PARAM for a host never initialized. */
int lxp_host_run(const lxp_host_t *host, const lxp_launch_config_t *launch_config, const char *path,
		 int argc, const char *const argv[]);

#ifdef __cplusplus
}
#endif

#endif /* LXP_HOST_H */
