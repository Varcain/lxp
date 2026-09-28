/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Host-backed writable filesystem mount. The Linux VFS owns routing and open
 * descriptions; this module owns the bounded mapping from those descriptions
 * to opaque provider file/directory handles.
 */
#ifndef LXP_HOSTFS_H
#define LXP_HOSTFS_H

#include "lxp/lxp_config.h"

#if LXP_ENABLE_FS

#include "lxp/lxp_fs_ops.h"
#include "proc/lxp_proc.h"

#define LXP_HOSTFS_DEFAULT_MOUNT "/data"

/* st_dev reported for every hostfs object. */
#define LXP_HOSTFS_DEV_MAJOR 179u
#define LXP_HOSTFS_DEV_MINOR 0u
#define LXP_HOSTFS_DEV ((uint64_t)((LXP_HOSTFS_DEV_MAJOR << 8) | LXP_HOSTFS_DEV_MINOR))

/* Guest st_mode of a provider object (providers report no permission bits). */
static inline uint32_t lxp_hostfs_mode(const lxp_fs_stat_t *stat)
{
	return stat->type == LXP_FS_TYPE_DIR ? (LXP_S_IFDIR | 0777u) : (LXP_S_IFREG | 0666u);
}

/** Guest-visible attachment state for the single host filesystem provider. */
const char *lxp_hostfs_mount_path(void);
const char *lxp_hostfs_mount_source(void);
int lxp_hostfs_is_read_only(void);

/** True when @p abspath is /data or lies below it. */
int lxp_hostfs_match(const char *abspath);
/** Strip /data while preserving a provider-rooted path ("/data/x" -> "/x"). */
const char *lxp_hostfs_relative(const char *abspath);

/** Open a file or directory and return a hostfs open-pool index. */
long lxp_hostfs_open(lxp_proc_t *proc, const char *abspath, int linux_flags);
int lxp_hostfs_is_dir(int index);
/** Stable synthetic inode captured when an object is opened. */
uint32_t lxp_hostfs_inode(int index);
/** Stable synthetic inode for a normalized guest-visible hostfs path. */
uint32_t lxp_hostfs_path_inode(const char *abspath);
long lxp_hostfs_read(lxp_proc_t *proc, int index, void *buf, size_t len);
long lxp_hostfs_write(lxp_proc_t *proc, int index, const void *buf, size_t len);
long lxp_hostfs_seek(lxp_proc_t *proc, int index, int64_t offset, int whence);
long lxp_hostfs_pread(lxp_proc_t *proc, int index, void *buf, size_t len, uint64_t offset);
long lxp_hostfs_pwrite(lxp_proc_t *proc, int index, const void *buf, size_t len, uint64_t offset);
long lxp_hostfs_stat(lxp_proc_t *proc, int index, lxp_fs_stat_t *out);
long lxp_hostfs_truncate(lxp_proc_t *proc, int index, uint64_t length);
long lxp_hostfs_sync(lxp_proc_t *proc, int index);
long lxp_hostfs_sync_all(void);
long lxp_hostfs_mount(lxp_proc_t *proc, const char *source, const char *target, int read_only);
long lxp_hostfs_remount(lxp_proc_t *proc, int read_only);
long lxp_hostfs_unmount(lxp_proc_t *proc, const char *target);
int lxp_hostfs_is_mounted(void);
/** Query allocation statistics for the mounted host volume. */
long lxp_hostfs_volume_stat(lxp_proc_t *proc, lxp_fs_volume_stat_t *out);
void lxp_hostfs_close(int index);

/**
 * Peek the next directory entry without consuming it. Returns one when an
 * entry is available, zero at end-of-directory, or a negated Linux errno.
 */
long lxp_hostfs_dir_peek(lxp_proc_t *proc, int index, const lxp_fs_dirent_t **entry);
void lxp_hostfs_dir_consume(int index);

/** Stat a guest-visible /data path. */
long lxp_hostfs_path_stat(lxp_proc_t *proc, const char *abspath, lxp_fs_stat_t *out);
long lxp_hostfs_mkdir(lxp_proc_t *proc, const char *abspath);
long lxp_hostfs_rmdir(lxp_proc_t *proc, const char *abspath);
long lxp_hostfs_unlink(lxp_proc_t *proc, const char *abspath);
long lxp_hostfs_rename(lxp_proc_t *proc, const char *old_abspath, const char *new_abspath);
/** Capture the currently dispatched syscall so an async provider retry can
 * resume it after the guest has parked. */
void lxp_hostfs_syscall_enter(lxp_proc_t *proc, long nr, long a0, long a1, long a2, long a3,
			      long a4, long a5);
/** Abandon a generation-qualified request when a parked syscall is interrupted. */
void lxp_hostfs_cancel(lxp_proc_t *proc);
/** Convert an LXP_ERR_* provider result to a negated Linux errno. */
/** Release any handles left by an interrupted/test run. */
void lxp_hostfs_runtime_reset(void);

#endif /* LXP_ENABLE_FS */

#endif /* LXP_HOSTFS_H */
