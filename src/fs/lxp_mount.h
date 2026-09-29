/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The mount table (src/fs/lxp_mount.c): which namespace answers a path. A mount owns
 * the paths at and below its mountpoint, and a path belongs to the mount with the
 * longest mountpoint above it (lxp_path_under). The set is fixed: /proc, /dev, the
 * hostfs and netfs mountpoints (which follow mount(2) and the netfs configuration) and
 * the root, tmpfs over the rootfs. /dev owns only the nodes it holds; any other name
 * under it belongs to the root.
 */
#ifndef LXP_FS_MOUNT_H
#define LXP_FS_MOUNT_H

#include <stdint.h>

#include "fs/lxp_stat.h"
#include "lxp/lxp_config.h"
#include "proc/lxp_proc.h"

typedef struct lxp_mount_ops {
	/** Only on a mount that shares its directory with the root: whether it holds @p path. */
	int (*holds)(const lxp_proc_t *p, const char *path);
	/** open(2): an fd, a negated errno, or 0 with the caller parked. */
	long (*open)(lxp_proc_t *p, const char *path, int flags);
	/** stat, following a trailing symlink when @p follow: 0 with @p st filled, or -errno. */
	long (*stat)(lxp_proc_t *p, const char *path, int follow, struct lxp_stat *st);
	/** A stat answered later, in place of @c stat: parks the caller, whose kstat64 (or
	 * statx when @p statx) at guest address @p buf is filled on completion. */
	long (*stat_park)(lxp_proc_t *p, const char *path, uintptr_t buf, int statx);
} lxp_mount_ops_t;

/** The mount that answers the normalized absolute @p path; never NULL. */
const lxp_mount_ops_t *lxp_mount_of(const lxp_proc_t *p, const char *path);

/* The mounts, each defined by the subsystem that owns its namespace. */
extern const lxp_mount_ops_t lxp_procfs_mount_ops;  /* src/proc/lxp_procfs.c */
extern const lxp_mount_ops_t lxp_devfs_mount_ops;   /* src/fs/lxp_devfs.c */
extern const lxp_mount_ops_t lxp_overlay_mount_ops; /* src/fs/lxp_overlay.c */
#if LXP_ENABLE_FS
extern const lxp_mount_ops_t lxp_hostfs_mount_ops; /* src/fs/lxp_hostfs.c */
#endif
#if LXP_ENABLE_NETFS
extern const lxp_mount_ops_t lxp_netfs_mount_ops; /* src/netfs/lxp_netfs.c */
#endif

#endif /* LXP_FS_MOUNT_H */
