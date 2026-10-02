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

	/* Name changes, each 0 or a negated errno; NULL where the mount takes none. Both
	 * names of a link or rename lie in this mount (the caller answers EXDEV). */
	long (*mkdir)(lxp_proc_t *p, const char *path, uint32_t mode);
	/** unlink(2), or rmdir(2) when @p dir. */
	long (*remove)(lxp_proc_t *p, const char *path, int dir);
	long (*symlink)(lxp_proc_t *p, const char *target, size_t target_len, const char *path);
	long (*link)(lxp_proc_t *p, const char *from, const char *to);
	long (*rename)(lxp_proc_t *p, const char *from, const char *to);
	long (*chmod)(lxp_proc_t *p, const char *path, uint32_t mode);
	long (*utimens)(lxp_proc_t *p, const char *path);
	/** statfs of a path; when NULL, a synthetic record of type @c magic. */
	long (*statfs)(lxp_proc_t *p, const char *path, struct lxp_statfs64 *st);

	/* Lookups. */
	/** readlink: the target (not NUL-terminated) into @p out, cut at @p cap; its length,
	 *  or EINVAL for a name that is not a symlink. NULL: the mount holds no symlinks. */
	long (*readlink)(lxp_proc_t *p, const char *path, char *out, size_t cap);
	/** access(2) for @p mode (R_OK 4, W_OK 2, X_OK 1). NULL: existence only. */
	long (*access)(lxp_proc_t *p, const char *path, int mode);
	/** chdir(2): make the directory at @p path the cwd, or park to do so. NULL: stat it,
	 *  following a symlink, and require a directory. */
	long (*chdir)(lxp_proc_t *p, const char *path);
	/** execve: the program at @p path, following a symlink. 0 with @p data / @p size its
	 *  bytes and @p rootfs_index its rootfs index (loaded in place) or -1 (to be copied
	 *  into the exec staging buffer); 1 with the caller parked while the mount fetches
	 *  it; EACCES for a directory. NULL: the mount runs no programs. */
	long (*exec)(lxp_proc_t *p, const char *path, const uint8_t **data, size_t *size,
		     int *rootfs_index);

	/** statfs f_type for a mount without a statfs operation. */
	uint32_t magic;
	/** The errno for a name change the mount does not take: EPERM, or EROFS for a
	 * read-only mount that cannot tell synchronously whether the name exists. */
	uint8_t name_errno;
} lxp_mount_ops_t;

/** The mount that answers the normalized absolute @p path; never NULL. */
const lxp_mount_ops_t *lxp_mount_of(const lxp_proc_t *p, const char *path);

/** Follow @p abspath (LXP_PATH_MAX bytes) through the symlinks the root overlay cannot
 *  follow itself, rewriting it to where they lead: 0, -ELOOP after LXP_SYMLOOP_MAX links,
 *  or -ENAMETOOLONG. Links that stay in the rootfs are left to the overlay, which follows
 *  them while keeping the name the caller used. */
long lxp_mount_follow(lxp_proc_t *p, char *abspath);

/** The target of the symlink at @p path when the overlay cannot follow it itself (a tmpfs
 *  link, or a rootfs link leading out of the rootfs), written to @p out without a NUL:
 *  its length, or 0 for any other name. (src/fs/lxp_overlay.c) */
long lxp_overlay_foreign_link(lxp_proc_t *p, const char *path, char *out, size_t cap);

/** Whether @p path is at or below a mountpoint that mount(2) cannot cover: /proc, /dev
 * and the netfs mount. The root and the hostfs point (which mount(2) moves) are free. */
int lxp_mount_occupied(const char *path);

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
