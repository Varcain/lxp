/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Immutable 9P mount topology shared by the host and run contracts.
 */

#ifndef LXP_NETFS_CONFIG_H
#define LXP_NETFS_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One optional, read-only 9P mount. String inputs are copied by lxp_host_init_cpio(). */
typedef struct lxp_netfs_config {
	const char *mountpoint; /**< Absolute guest path, for example @c /mnt/pi. */
	uint8_t server_ip[4];  /**< IPv4 address in network display order. */
	uint16_t port;         /**< TCP port; zero is invalid. */
	const char *aname;     /**< 9P attach name; NULL selects an empty attach name. */
	const char *uname;     /**< 9P user; NULL or empty selects @c root. */
} lxp_netfs_config_t;

static inline int lxp_netfs_config_string_fits(const char *text, size_t cap, int allow_empty)
{
	if (!text)
		return allow_empty;
	size_t len = 0u;
	while (len < cap && text[len] != '\0')
		len++;
	return len < cap && (allow_empty || len != 0u);
}

/** Validate one enabled mount. NULL is the separate, unconfigured state. */
static inline int lxp_netfs_config_valid(const lxp_netfs_config_t *config)
{
	return config && config->mountpoint && config->mountpoint[0] == '/' &&
	       lxp_netfs_config_string_fits(config->mountpoint, LXP_NETFS_MOUNTPOINT_CAP, 0) &&
	       config->port != 0u &&
	       lxp_netfs_config_string_fits(config->aname, LXP_NETFS_ANAME_CAP, 1) &&
	       lxp_netfs_config_string_fits(config->uname, LXP_NETFS_UNAME_CAP, 1);
}

#ifdef __cplusplus
}
#endif

#endif /* LXP_NETFS_CONFIG_H */
