/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bounded ownership bridge between Linux open-file descriptions and the
 * host-owned writable filesystem provider.
 */
#include "lxp/lxp_config.h"

#if LXP_ENABLE_LINUX && LXP_ENABLE_FS

#include "fs/lxp_hostfs.h"

#include "lxp_provider.h"

#include <limits.h>
#include <string.h>

typedef struct lxp_hostfs_open {
	union {
		lxp_fs_file_t file;
		lxp_fs_dir_t dir;
	} handle;
	lxp_fs_dirent_t pending;
	uint8_t used;
	uint8_t is_dir;
	uint8_t has_pending;
} lxp_hostfs_open_t;

static lxp_hostfs_open_t g_hostfs_open[LXP_NHOSTFS_OPEN];

long lxp_hostfs_error(int result)
{
	switch (result) {
	case LXP_OK:
		return 0;
	case LXP_ERR_NOT_REGISTERED:
		return -LXP_ENODEV;
	case LXP_ERR_INVALID_PARAM:
	case LXP_ERR_INVAL:
		return -LXP_EINVAL;
	case LXP_ERR_NO_MEMORY:
		return -LXP_ENOMEM;
	case LXP_ERR_TIMEOUT:
		return -LXP_ETIMEDOUT;
	case LXP_ERR_NOT_SUPPORTED:
		return -LXP_EOPNOTSUPP;
	case LXP_ERR_QUEUE_FULL:
	case LXP_ERR_QUEUE_EMPTY:
	case LXP_ERR_WOULD_BLOCK:
	case LXP_ERR_BUSY:
		return -LXP_EAGAIN;
	case LXP_ERR_EOF:
		return 0;
	case LXP_ERR_NOT_FOUND:
		return -LXP_ENOENT;
	case LXP_ERR_ALREADY_EXISTS:
		return -LXP_EEXIST;
	case LXP_ERR_NO_SPACE:
		return -LXP_ENOSPC;
	case LXP_ERR_NOT_DIR:
		return -LXP_ENOTDIR;
	case LXP_ERR_IS_DIR:
		return -LXP_EISDIR;
	case LXP_ERR_NOT_EMPTY:
		return -LXP_ENOTEMPTY;
	case LXP_ERR_READ_ONLY:
		return -LXP_EROFS;
	case LXP_ERR_NAME_TOO_LONG:
		return -LXP_ENAMETOOLONG;
	case LXP_ERR_BAD_HANDLE:
		return -LXP_EBADF;
	case LXP_ERR_PERMISSION:
		return -LXP_EACCES;
	default:
		return -LXP_EIO;
	}
}

int lxp_hostfs_match(const char *abspath)
{
	const size_t mount_len = sizeof(LXP_HOSTFS_MOUNT) - 1u;
	return abspath && strncmp(abspath, LXP_HOSTFS_MOUNT, mount_len) == 0 &&
	       (abspath[mount_len] == '\0' || abspath[mount_len] == '/');
}

const char *lxp_hostfs_relative(const char *abspath)
{
	const size_t mount_len = sizeof(LXP_HOSTFS_MOUNT) - 1u;
	if (!lxp_hostfs_match(abspath))
		return NULL;
	return abspath[mount_len] ? abspath + mount_len : "/";
}

static lxp_hostfs_open_t *hostfs_slot(int index)
{
	if (index < 0 || index >= LXP_NHOSTFS_OPEN || !g_hostfs_open[index].used)
		return NULL;
	return &g_hostfs_open[index];
}

static int hostfs_slot_alloc(void)
{
	for (int i = 0; i < LXP_NHOSTFS_OPEN; i++)
		if (!g_hostfs_open[i].used)
			return i;
	return -1;
}

static unsigned hostfs_open_flags(int flags)
{
	unsigned out = 0;
	switch (flags & LXP_O_ACCMODE) {
	case LXP_O_WRONLY:
		out = LXP_FS_O_WRITE;
		break;
	case LXP_O_RDWR:
		out = LXP_FS_O_READ | LXP_FS_O_WRITE;
		break;
	default:
		out = LXP_FS_O_READ;
		break;
	}
	if (flags & LXP_O_CREAT)
		out |= LXP_FS_O_CREATE;
	if (flags & LXP_O_APPEND)
		out |= LXP_FS_O_APPEND;
	if (flags & LXP_O_TRUNC)
		out |= LXP_FS_O_TRUNC;
	if (flags & LXP_O_EXCL)
		out |= LXP_FS_O_EXCL;
	return out;
}

long lxp_hostfs_open(const char *abspath, int linux_flags)
{
	const lxp_fs_ops_t *ops = g_lxp_fs_ops;
	const char *path = lxp_hostfs_relative(abspath);
	if (!path)
		return -LXP_ENOENT;
	if (!ops)
		return -LXP_ENODEV;

	int index = hostfs_slot_alloc();
	if (index < 0)
		return -LXP_EMFILE;

	lxp_fs_stat_t stat;
	int sr = ops->path_stat(path, &stat);
	if (sr == LXP_OK && stat.type == LXP_FS_TYPE_DIR) {
		if ((linux_flags & LXP_O_ACCMODE) != LXP_O_RDONLY ||
		    (linux_flags & (LXP_O_CREAT | LXP_O_TRUNC)))
			return -LXP_EISDIR;
		int rc = ops->dir_open(path, &g_hostfs_open[index].handle.dir);
		if (rc != LXP_OK)
			return lxp_hostfs_error(rc);
		g_hostfs_open[index].used = 1;
		g_hostfs_open[index].is_dir = 1;
		return index;
	}
	if (sr != LXP_OK && sr != LXP_ERR_NOT_FOUND)
		return lxp_hostfs_error(sr);
	if ((linux_flags & LXP_O_DIRECTORY) != 0)
		return sr == LXP_ERR_NOT_FOUND ? -LXP_ENOENT : -LXP_ENOTDIR;

	int rc = ops->file_open(path, hostfs_open_flags(linux_flags),
				&g_hostfs_open[index].handle.file);
	if (rc != LXP_OK)
		return lxp_hostfs_error(rc);
	g_hostfs_open[index].used = 1;
	return index;
}

int lxp_hostfs_is_dir(int index)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	return slot ? slot->is_dir != 0 : 0;
}

long lxp_hostfs_read(int index, void *buf, size_t len)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_EISDIR;
	size_t done = 0;
	int rc = g_lxp_fs_ops->file_read(slot->handle.file, buf, len, &done);
	return rc == LXP_OK || rc == LXP_ERR_EOF ? (long)done : lxp_hostfs_error(rc);
}

long lxp_hostfs_write(int index, const void *buf, size_t len)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_EISDIR;
	size_t done = 0;
	int rc = g_lxp_fs_ops->file_write(slot->handle.file, buf, len, &done);
	return rc == LXP_OK ? (long)done : lxp_hostfs_error(rc);
}

long lxp_hostfs_seek(int index, int64_t offset, int whence)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_ESPIPE;
	uint64_t position = 0;
	int rc = g_lxp_fs_ops->file_seek(slot->handle.file, offset, whence, &position);
	if (rc != LXP_OK)
		return lxp_hostfs_error(rc);
	if (position > (uint64_t)INT32_MAX)
		return -LXP_EOVERFLOW;
	return (long)position;
}

long lxp_hostfs_stat(int index, lxp_fs_stat_t *out)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot || !out)
		return -LXP_EBADF;
	if (slot->is_dir) {
		memset(out, 0, sizeof(*out));
		out->type = LXP_FS_TYPE_DIR;
		return 0;
	}
	int rc = g_lxp_fs_ops->file_stat(slot->handle.file, out);
	return rc == LXP_OK ? 0 : lxp_hostfs_error(rc);
}

void lxp_hostfs_close(int index)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return;
	if (slot->is_dir)
		(void)g_lxp_fs_ops->dir_close(slot->handle.dir);
	else
		(void)g_lxp_fs_ops->file_close(slot->handle.file);
	memset(slot, 0, sizeof(*slot));
}

long lxp_hostfs_dir_peek(int index, const lxp_fs_dirent_t **entry)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (!slot->is_dir)
		return -LXP_ENOTDIR;
	if (!slot->has_pending) {
		int rc = g_lxp_fs_ops->dir_read(slot->handle.dir, &slot->pending);
		if (rc == LXP_ERR_EOF)
			return 0;
		if (rc != LXP_OK)
			return lxp_hostfs_error(rc);
		slot->pending.name[LXP_FS_NAME_MAX - 1u] = '\0';
		slot->has_pending = 1;
	}
	*entry = &slot->pending;
	return 1;
}

void lxp_hostfs_dir_consume(int index)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (slot)
		slot->has_pending = 0;
}

long lxp_hostfs_path_stat(const char *abspath, lxp_fs_stat_t *out)
{
	const char *path = lxp_hostfs_relative(abspath);
	if (!path)
		return -LXP_ENOENT;
	if (!g_lxp_fs_ops)
		return -LXP_ENODEV;
	int rc = g_lxp_fs_ops->path_stat(path, out);
	return rc == LXP_OK ? 0 : lxp_hostfs_error(rc);
}

void lxp_hostfs_runtime_reset(void)
{
	for (int i = 0; i < LXP_NHOSTFS_OPEN; i++)
		if (g_hostfs_open[i].used)
			lxp_hostfs_close(i);
	memset(g_hostfs_open, 0, sizeof(g_hostfs_open));
}

#endif /* LXP_ENABLE_LINUX && LXP_ENABLE_FS */
