/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The mount table: the fixed set of namespaces and the lookup that picks the one
 * answering a path.
 */
#include "fs/lxp_mount.h"

#include "fs/lxp_path.h"
#if LXP_ENABLE_FS
#include "fs/lxp_hostfs.h"
#endif
#if LXP_ENABLE_NETFS
#include "netfs/lxp_netfs.h"
#endif

#include <stddef.h>
#include <string.h>

static const char *proc_point(void)
{
	return "/proc";
}

static const char *dev_point(void)
{
	return "/dev";
}

static const char *root_point(void)
{
	return "/";
}

/* Each mount's current mountpoint, or NULL while its namespace is not mounted. */
static const struct mount {
	const char *(*point)(void);
	const lxp_mount_ops_t *ops;
} g_mounts[] = {
	{proc_point, &lxp_procfs_mount_ops},
	{dev_point, &lxp_devfs_mount_ops},
#if LXP_ENABLE_FS
	{lxp_hostfs_mount_path, &lxp_hostfs_mount_ops},
#endif
#if LXP_ENABLE_NETFS
	{lxp_netfs_mountpoint, &lxp_netfs_mount_ops},
#endif
	{root_point, &lxp_overlay_mount_ops},
};

const lxp_mount_ops_t *lxp_mount_of(const lxp_proc_t *p, const char *path)
{
	/* The longest mountpoint above the path wins, the first listed on a tie. A mount that
	 * shares its directory with the root passes the names it does not hold outward. */
	size_t below = SIZE_MAX;
	for (;;) {
		const struct mount *best = NULL;
		size_t best_len = 0;
		for (size_t i = 0; i < sizeof(g_mounts) / sizeof(g_mounts[0]); i++) {
			const char *point = g_mounts[i].point();
			size_t n = point ? lxp_path_under(path, point) : 0u;
			if (n > best_len && n < below) {
				best = &g_mounts[i];
				best_len = n;
			}
		}
		if (!best)
			return &lxp_overlay_mount_ops;
		if (!best->ops->holds || best->ops->holds(p, path))
			return best->ops;
		below = best_len;
	}
}

long lxp_mount_follow(lxp_proc_t *p, char *abspath)
{
	for (int hop = 0;; hop++) {
		char target[LXP_PATH_MAX];
		long n = lxp_mount_of(p, abspath) == &lxp_overlay_mount_ops
				 ? lxp_overlay_foreign_link(p, abspath, target, sizeof(target))
				 : 0;
		if (n == 0)
			return 0;
		if (hop == LXP_SYMLOOP_MAX)
			return -LXP_ELOOP;
		char next[LXP_PATH_MAX];
		long rc = lxp_path_link_target(abspath, target, (size_t)n, next, sizeof(next));
		if (rc < 0)
			return rc;
		memcpy(abspath, next, strlen(next) + 1);
	}
}

int lxp_mount_occupied(const char *path)
{
	for (size_t i = 0; i < sizeof(g_mounts) / sizeof(g_mounts[0]); i++) {
		const char *point = g_mounts[i].point();
		if (!point || g_mounts[i].ops == &lxp_overlay_mount_ops)
			continue;
#if LXP_ENABLE_FS
		if (g_mounts[i].ops == &lxp_hostfs_mount_ops)
			continue;
#endif
		if (lxp_path_under(path, point))
			return 1;
	}
	return 0;
}
