/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Host filesystem provider contract. The personality owns Linux path routing
 * and descriptor semantics; the host owns native filesystem handles, storage,
 * mounting, and serialization.
 */

#ifndef LXP_FS_OPS_H
#define LXP_FS_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LXP_FS_OPS_ABI_VERSION 2u
#define LXP_FS_NAME_MAX 256u

/* Provider open flags. Access mode is explicit instead of encoded in low bits
 * so hosts can translate without depending on Linux or POSIX flag values. */
#define LXP_FS_O_READ 0x01u
#define LXP_FS_O_WRITE 0x02u
#define LXP_FS_O_CREATE 0x04u
#define LXP_FS_O_APPEND 0x08u
#define LXP_FS_O_TRUNC 0x10u
#define LXP_FS_O_EXCL 0x20u

#define LXP_FS_SEEK_SET 0
#define LXP_FS_SEEK_CUR 1
#define LXP_FS_SEEK_END 2

#define LXP_FS_TYPE_UNKNOWN 0u
#define LXP_FS_TYPE_FILE 1u
#define LXP_FS_TYPE_DIR 2u

/* Host-owned opaque handles. The personality never embeds an RTOS-specific
 * file or directory object and never releases one except through this table. */
typedef struct lxp_fs_file *lxp_fs_file_t;
typedef struct lxp_fs_dir *lxp_fs_dir_t;

typedef struct lxp_fs_stat {
	uint64_t size;
	uint64_t mtime_sec;
	uint8_t type;
	uint8_t _reserved[7];
} lxp_fs_stat_t;

typedef struct lxp_fs_dirent {
	char name[LXP_FS_NAME_MAX];
	uint64_t size;
	uint8_t type;
	uint8_t _reserved[7];
} lxp_fs_dirent_t;

/* Run-scoped provider telemetry. Counters reset in run_begin(). Durations are
 * measured on the host side so they include native queueing and service time,
 * but exclude guest-side syscall dispatch. */
typedef struct lxp_fs_metrics {
	uint64_t requests_submitted;
	uint64_t requests_completed;
	uint64_t requests_failed;
	uint64_t bytes_read;
	uint64_t bytes_written;
	uint64_t queue_wait_us_total;
	uint64_t queue_wait_us_max;
	uint64_t service_us_total;
	uint64_t service_us_max;
	uint64_t budget_overruns;
	uint32_t pending;
	uint32_t queue_depth_max;
} lxp_fs_metrics_t;

/* All calls execute in privileged host context. A synchronous provider may
 * perform the operation directly; a real-time host may implement the same
 * contract through a serialized storage worker. Return LXP_OK or LXP_ERR_*.
 *
 * Paths are relative to the provider's mounted volume. "/" denotes its root.
 * The personality is solely responsible for selecting the mount and removing
 * the guest-visible prefix before calling the provider.
 *
 * Buffers passed to file_read/file_write belong to the guest address space,
 * but each synchronous call must return with normal CPU loads observing the
 * completed data. A provider that uses DMA must perform its cache maintenance
 * internally or stage through provider-owned DMA memory. The personality must
 * not invalidate a buffer after file_read: on a single-core system where a
 * privileged worker and guest share one write-back cache, that would discard
 * the worker's dirty CPU writes rather than publish them. */
typedef struct lxp_fs_ops {
	uint32_t abi_version; /**< Must be LXP_FS_OPS_ABI_VERSION. */
	uint32_t struct_size; /**< Must be sizeof(lxp_fs_ops_t). */

	/** Acquire and release run-scoped storage. A missing medium is not a
	 * provider-lifecycle failure: run_begin should succeed and let individual
	 * operations return LXP_ERR_NOT_REGISTERED until media is available. */
	int (*run_begin)(void);
	void (*run_end)(void);

	int (*file_open)(const char *path, unsigned flags, lxp_fs_file_t *out);
	int (*file_close)(lxp_fs_file_t file);
	int (*file_read)(lxp_fs_file_t file, void *buf, size_t count, size_t *bytes_read);
	int (*file_write)(lxp_fs_file_t file, const void *buf, size_t count, size_t *bytes_written);
	int (*file_seek)(lxp_fs_file_t file, int64_t offset, int whence, uint64_t *new_offset);
	int (*file_stat)(lxp_fs_file_t file, lxp_fs_stat_t *out);
	int (*file_truncate)(lxp_fs_file_t file, uint64_t length);
	int (*file_sync)(lxp_fs_file_t file);

	int (*dir_open)(const char *path, lxp_fs_dir_t *out);
	int (*dir_read)(lxp_fs_dir_t dir, lxp_fs_dirent_t *entry);
	int (*dir_close)(lxp_fs_dir_t dir);

	int (*path_stat)(const char *path, lxp_fs_stat_t *out);
	int (*path_mkdir)(const char *path);
	int (*path_rmdir)(const char *path);
	int (*path_unlink)(const char *path);
	int (*path_rename)(const char *old_path, const char *new_path);

	/** Snapshot run-scoped service telemetry without resetting it. */
	int (*metrics)(lxp_fs_metrics_t *out);
} lxp_fs_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* LXP_FS_OPS_H */
