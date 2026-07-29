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
#include "lxp/lxp_proc.h"

#define LXP_HOSTFS_MOUNT "/data"

/** True when @p abspath is /data or lies below it. */
int lxp_hostfs_match(const char *abspath);
/** Strip /data while preserving a provider-rooted path ("/data/x" -> "/x"). */
const char *lxp_hostfs_relative(const char *abspath);

/** Open a file or directory and return a hostfs open-pool index. */
long lxp_hostfs_open(const char *abspath, int linux_flags);
int lxp_hostfs_is_dir(int index);
long lxp_hostfs_read(int index, void *buf, size_t len);
long lxp_hostfs_write(int index, const void *buf, size_t len);
long lxp_hostfs_seek(int index, int64_t offset, int whence);
long lxp_hostfs_pread(int index, void *buf, size_t len, uint64_t offset);
long lxp_hostfs_pwrite(int index, const void *buf, size_t len, uint64_t offset);
long lxp_hostfs_stat(int index, lxp_fs_stat_t *out);
long lxp_hostfs_truncate(int index, uint64_t length);
long lxp_hostfs_sync(int index);
long lxp_hostfs_sync_all(void);
void lxp_hostfs_close(int index);

/**
 * Peek the next directory entry without consuming it. Returns one when an
 * entry is available, zero at end-of-directory, or a negated Linux errno.
 */
long lxp_hostfs_dir_peek(int index, const lxp_fs_dirent_t **entry);
void lxp_hostfs_dir_consume(int index);

/** Stat a guest-visible /data path. */
long lxp_hostfs_path_stat(const char *abspath, lxp_fs_stat_t *out);
long lxp_hostfs_mkdir(const char *abspath);
long lxp_hostfs_rmdir(const char *abspath);
long lxp_hostfs_unlink(const char *abspath);
long lxp_hostfs_rename(const char *old_abspath, const char *new_abspath);
/** Convert an LXP_ERR_* provider result to a negated Linux errno. */
long lxp_hostfs_error(int result);
/** Release any handles left by an interrupted/test run. */
void lxp_hostfs_runtime_reset(void);

#endif /* LXP_ENABLE_FS */

#endif /* LXP_HOSTFS_H */
