/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bounded ownership bridge between Linux open-file descriptions and the
 * host-owned writable filesystem provider.
 */
#include "lxp/lxp_config.h"

#if LXP_ENABLE_FS

#include "fs/lxp_hostfs.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_vfs.h"

#if LXP_ENABLE_BLOCK
#include "dev/lxp_dev_block.h"
#endif

#include "lxp_provider.h"

#include <limits.h>
#include <string.h>

typedef struct lxp_hostfs_open {
	union {
		lxp_fs_file_t file;
		lxp_fs_dir_t dir;
	} handle;
	lxp_fs_dirent_t pending;
	uint32_t inode;
	uint8_t used;
	uint8_t is_dir;
	uint8_t has_pending;
} lxp_hostfs_open_t;

static lxp_hostfs_open_t g_hostfs_open[LXP_NHOSTFS_OPEN];
static uint32_t g_hostfs_run_generation = 1u;
static char g_hostfs_mount_path[LXP_PATH_MAX] = LXP_HOSTFS_DEFAULT_MOUNT;
static char g_hostfs_mount_source[LXP_PATH_MAX] = "/dev/mmcblk0";
static int g_hostfs_read_only;
static struct {
	lxp_proc_t *proc;
	intptr_t nr;
	intptr_t args[6];
} g_hostfs_syscall;

static uint64_t hostfs_owner(const lxp_proc_t *proc)
{
	return proc ? ((uint64_t)g_hostfs_run_generation << 32) | (uint32_t)proc->pid : 0;
}

void lxp_hostfs_syscall_enter(lxp_proc_t *proc, long nr, long a0, long a1, long a2, long a3,
			      long a4, long a5)
{
	g_hostfs_syscall.proc = proc;
	g_hostfs_syscall.nr = (intptr_t)nr;
	g_hostfs_syscall.args[0] = (intptr_t)a0;
	g_hostfs_syscall.args[1] = (intptr_t)a1;
	g_hostfs_syscall.args[2] = (intptr_t)a2;
	g_hostfs_syscall.args[3] = (intptr_t)a3;
	g_hostfs_syscall.args[4] = (intptr_t)a4;
	g_hostfs_syscall.args[5] = (intptr_t)a5;
}

static void hostfs_select(lxp_proc_t *proc)
{
	if (g_lxp_fs_ops && g_lxp_fs_ops->request_owner)
		g_lxp_fs_ops->request_owner(hostfs_owner(proc));
}

static long hostfs_result(lxp_proc_t *proc, int result)
{
	if (result != LXP_ERR_WOULD_BLOCK)
		return result == LXP_OK ? 0 : lxp_provider_error(result);
	if (!proc || g_hostfs_syscall.proc != proc)
		return -LXP_EAGAIN;
	if (proc->wait.kind == LXP_WAIT_HOSTFS)
		return -LXP_EAGAIN;
	if (proc->wait.kind != LXP_WAIT_NONE)
		return -LXP_EAGAIN;
	lxp_wait_t wait = {
		.kind = LXP_WAIT_HOSTFS,
		.data.hostfs.nr = g_hostfs_syscall.nr,
		.data.hostfs.owner = hostfs_owner(proc),
	};
	for (size_t i = 0; i < 6; i++)
		wait.data.hostfs.args[i] = g_hostfs_syscall.args[i];
	if (lxp_wait_begin(proc, &wait) != LXP_OK)
		return -LXP_EAGAIN;
	return -LXP_EAGAIN;
}

void lxp_hostfs_cancel(lxp_proc_t *proc)
{
	if (proc && proc->wait.kind == LXP_WAIT_HOSTFS && g_lxp_fs_ops &&
	    g_lxp_fs_ops->request_cancel)
		g_lxp_fs_ops->request_cancel(proc->wait.data.hostfs.owner);
}

int lxp_hostfs_match(const char *abspath)
{
	const size_t mount_len = strlen(g_hostfs_mount_path);
	return abspath && strncmp(abspath, g_hostfs_mount_path, mount_len) == 0 &&
	       (abspath[mount_len] == '\0' || abspath[mount_len] == '/');
}

const char *lxp_hostfs_relative(const char *abspath)
{
	const size_t mount_len = strlen(g_hostfs_mount_path);
	if (!lxp_hostfs_match(abspath))
		return NULL;
	return abspath[mount_len] ? abspath + mount_len : "/";
}

const char *lxp_hostfs_mount_path(void)
{
	return g_hostfs_mount_path;
}

const char *lxp_hostfs_mount_source(void)
{
	return g_hostfs_mount_source;
}

int lxp_hostfs_is_read_only(void)
{
	return g_hostfs_read_only != 0;
}

uint32_t lxp_hostfs_path_inode(const char *abspath)
{
	if (!lxp_hostfs_match(abspath))
		return 0;

	/* The provider API deliberately exposes no RTOS-specific inode. Use a
	 * stable namespace-tagged FNV-1a value so stat(path), fstat(open(path)),
	 * and statx agree independent of the transient open-pool slot. */
	uint32_t hash = 2166136261u;
	for (const unsigned char *p = (const unsigned char *)abspath; *p; p++) {
		hash ^= *p;
		hash *= 16777619u;
	}
	return 0x70000000u | (hash & 0x0fffffffu);
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

long lxp_hostfs_open(lxp_proc_t *proc, const char *abspath, int linux_flags)
{
	const lxp_fs_ops_t *ops = g_lxp_fs_ops;
	const char *path = lxp_hostfs_relative(abspath);
	if (!path)
		return -LXP_ENOENT;
	if (!ops)
		return -LXP_ENODEV;
	if (g_hostfs_read_only && ((linux_flags & LXP_O_ACCMODE) != LXP_O_RDONLY ||
				   (linux_flags & (LXP_O_CREAT | LXP_O_TRUNC)) != 0))
		return -LXP_EROFS;

	int index = hostfs_slot_alloc();
	if (index < 0)
		return -LXP_EMFILE;

	lxp_fs_open_result_t opened;
	hostfs_select(proc);
	int rc = ops->object_open(path, hostfs_open_flags(linux_flags),
				  (linux_flags & LXP_O_DIRECTORY) != 0, &opened);
	if (rc != LXP_OK)
		return hostfs_result(proc, rc);
	if (opened.type == LXP_FS_TYPE_DIR) {
		g_hostfs_open[index].handle.dir = opened.handle.dir;
		g_hostfs_open[index].used = 1;
		g_hostfs_open[index].is_dir = 1;
		g_hostfs_open[index].inode = lxp_hostfs_path_inode(abspath);
		return index;
	}
	if (opened.type != LXP_FS_TYPE_FILE)
		return -LXP_EIO;
	g_hostfs_open[index].handle.file = opened.handle.file;
	g_hostfs_open[index].used = 1;
	g_hostfs_open[index].inode = lxp_hostfs_path_inode(abspath);
	return index;
}

int lxp_hostfs_is_dir(int index)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	return slot ? slot->is_dir != 0 : 0;
}

uint32_t lxp_hostfs_inode(int index)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	return slot ? slot->inode : 0;
}

long lxp_hostfs_read(lxp_proc_t *proc, int index, void *buf, size_t len)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_EISDIR;
	size_t done = 0;
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->file_read(slot->handle.file, buf, len, &done);
	if (rc == LXP_ERR_WOULD_BLOCK)
		return hostfs_result(proc, rc);
	if (done > len)
		return -LXP_EIO;
	return rc == LXP_OK || rc == LXP_ERR_EOF ? (long)done : lxp_provider_error(rc);
}

long lxp_hostfs_write(lxp_proc_t *proc, int index, const void *buf, size_t len)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_EISDIR;
	if (g_hostfs_read_only)
		return -LXP_EROFS;
	size_t done = 0;
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->file_write(slot->handle.file, buf, len, &done);
	if (rc == LXP_ERR_WOULD_BLOCK)
		return hostfs_result(proc, rc);
	if (done > len)
		return -LXP_EIO;
	return rc == LXP_OK ? (long)done : lxp_provider_error(rc);
}

long lxp_hostfs_seek(lxp_proc_t *proc, int index, int64_t offset, int whence)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_ESPIPE;
	uint64_t position = 0;
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->file_seek(slot->handle.file, offset, whence, &position);
	if (rc != LXP_OK)
		return hostfs_result(proc, rc);
	if (position > (uint64_t)INT32_MAX)
		return -LXP_EOVERFLOW;
	return (long)position;
}

static long hostfs_positioned(lxp_proc_t *proc, int index, void *buf, size_t len, uint64_t offset,
			      int write)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_EISDIR;
	if (write && g_hostfs_read_only)
		return -LXP_EROFS;
	if (offset > (uint64_t)INT64_MAX)
		return -LXP_EOVERFLOW;

	size_t done = 0;
	hostfs_select(proc);
	int rc = write ? g_lxp_fs_ops->file_pwrite(slot->handle.file, buf, len, offset, &done)
		       : g_lxp_fs_ops->file_pread(slot->handle.file, buf, len, offset, &done);
	if (rc == LXP_ERR_WOULD_BLOCK)
		return hostfs_result(proc, rc);
	if (done > len)
		return -LXP_EIO;
	return rc == LXP_OK || (!write && rc == LXP_ERR_EOF) ? (long)done : lxp_provider_error(rc);
}

long lxp_hostfs_pread(lxp_proc_t *proc, int index, void *buf, size_t len, uint64_t offset)
{
	return hostfs_positioned(proc, index, buf, len, offset, 0);
}

long lxp_hostfs_pwrite(lxp_proc_t *proc, int index, const void *buf, size_t len, uint64_t offset)
{
	return hostfs_positioned(proc, index, (void *)buf, len, offset, 1);
}

long lxp_hostfs_stat(lxp_proc_t *proc, int index, lxp_fs_stat_t *out)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot || !out)
		return -LXP_EBADF;
	if (slot->is_dir) {
		memset(out, 0, sizeof(*out));
		out->type = LXP_FS_TYPE_DIR;
		return 0;
	}
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->file_stat(slot->handle.file, out);
	return hostfs_result(proc, rc);
}

long lxp_hostfs_truncate(lxp_proc_t *proc, int index, uint64_t length)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_EISDIR;
	if (g_hostfs_read_only)
		return -LXP_EROFS;
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->file_truncate(slot->handle.file, length);
	return hostfs_result(proc, rc);
}

long lxp_hostfs_sync(lxp_proc_t *proc, int index)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (slot->is_dir)
		return -LXP_EINVAL;
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->file_sync(slot->handle.file);
	return hostfs_result(proc, rc);
}

long lxp_hostfs_sync_all(void)
{
	for (int i = 0; i < LXP_NHOSTFS_OPEN; i++) {
		if (!g_hostfs_open[i].used || g_hostfs_open[i].is_dir)
			continue;
		hostfs_select(NULL);
		int native = g_lxp_fs_ops->file_sync(g_hostfs_open[i].handle.file);
		long rc = native == LXP_OK ? 0 : lxp_provider_error(native);
		if (rc < 0)
			return rc;
	}
	return 0;
}

int lxp_hostfs_is_mounted(void)
{
	return g_lxp_fs_ops && g_lxp_fs_ops->is_mounted && g_lxp_fs_ops->is_mounted() > 0;
}

long lxp_hostfs_volume_stat(lxp_proc_t *proc, lxp_fs_volume_stat_t *out)
{
	if (!out)
		return -LXP_EFAULT;
	if (!g_lxp_fs_ops || !g_lxp_fs_ops->volume_stat)
		return -LXP_ENODEV;
	hostfs_select(proc);
	return hostfs_result(proc, g_lxp_fs_ops->volume_stat(out));
}

long lxp_hostfs_mount(lxp_proc_t *proc, const char *source, const char *target, int read_only)
{
	if (!g_lxp_fs_ops || !source || !target)
		return -LXP_ENODEV;
	if (strnlen(source, sizeof(g_hostfs_mount_source)) >= sizeof(g_hostfs_mount_source) ||
	    strnlen(target, sizeof(g_hostfs_mount_path)) >= sizeof(g_hostfs_mount_path))
		return -LXP_ENAMETOOLONG;
#if LXP_ENABLE_BLOCK
	lxp_block_view_info_t view;
	int resolved = lxp_block_resolve(source, &view);
	if (resolved < 0)
		return resolved;
	lxp_fs_mount_spec_t spec = {
		.first_block = view.first_block,
		.block_count = view.block_count,
		.logical_block_size = view.logical_block_size,
		.partition = view.partition,
	};
	hostfs_select(proc);
	long rc = hostfs_result(proc, g_lxp_fs_ops->mount(&spec));
	if (rc == 0) {
		strcpy(g_hostfs_mount_source, source);
		strcpy(g_hostfs_mount_path, target);
		g_hostfs_read_only = read_only != 0;
	}
	return rc;
#else
	(void)proc;
	(void)read_only;
	return -LXP_ENODEV;
#endif
}

long lxp_hostfs_remount(lxp_proc_t *proc, int read_only)
{
	if (!g_lxp_fs_ops || !lxp_hostfs_is_mounted())
		return -LXP_ENODEV;
	/* Switching to read-only while a regular file is open can leave a native
	 * writable handle alive behind the policy boundary. Require a clean handle
	 * set; callers can sync/close and retry. */
	if (read_only != 0)
		for (int i = 0; i < LXP_NHOSTFS_OPEN; i++)
			if (g_hostfs_open[i].used && !g_hostfs_open[i].is_dir)
				return -LXP_EBUSY;
	(void)proc;
	g_hostfs_read_only = read_only != 0;
	return 0;
}

long lxp_hostfs_unmount(lxp_proc_t *proc, const char *target)
{
	if (!g_lxp_fs_ops)
		return -LXP_ENODEV;
	if (!target || strcmp(target, g_hostfs_mount_path) != 0)
		return -LXP_EINVAL;
	for (int i = 0; i < LXP_NHOSTFS_OPEN; i++)
		if (g_hostfs_open[i].used)
			return -LXP_EBUSY;
	hostfs_select(proc);
	long rc = hostfs_result(proc, g_lxp_fs_ops->unmount());
	if (rc == 0) {
		strcpy(g_hostfs_mount_path, LXP_HOSTFS_DEFAULT_MOUNT);
		strcpy(g_hostfs_mount_source, "/dev/mmcblk0");
		g_hostfs_read_only = 0;
	}
	return rc;
}

void lxp_hostfs_close(int index)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return;
	hostfs_select(NULL);
	if (slot->is_dir)
		(void)g_lxp_fs_ops->dir_close(slot->handle.dir);
	else
		(void)g_lxp_fs_ops->file_close(slot->handle.file);
	memset(slot, 0, sizeof(*slot));
}

long lxp_hostfs_dir_peek(lxp_proc_t *proc, int index, const lxp_fs_dirent_t **entry)
{
	lxp_hostfs_open_t *slot = hostfs_slot(index);
	if (!slot)
		return -LXP_EBADF;
	if (!slot->is_dir)
		return -LXP_ENOTDIR;
	if (!slot->has_pending) {
		hostfs_select(proc);
		int rc = g_lxp_fs_ops->dir_read(slot->handle.dir, &slot->pending);
		if (rc == LXP_ERR_WOULD_BLOCK)
			return hostfs_result(proc, rc);
		if (rc == LXP_ERR_EOF)
			return 0;
		if (rc != LXP_OK)
			return lxp_provider_error(rc);
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

long lxp_hostfs_path_stat(lxp_proc_t *proc, const char *abspath, lxp_fs_stat_t *out)
{
	const char *path = lxp_hostfs_relative(abspath);
	if (!path)
		return -LXP_ENOENT;
	if (!g_lxp_fs_ops)
		return -LXP_ENODEV;
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->path_stat(path, out);
	return hostfs_result(proc, rc);
}

static long hostfs_path_call(lxp_proc_t *proc, const char *abspath, int (*operation)(const char *))
{
	const char *path = lxp_hostfs_relative(abspath);
	if (!path)
		return -LXP_ENOENT;
	if (strcmp(path, "/") == 0)
		return -LXP_EBUSY;
	if (!g_lxp_fs_ops)
		return -LXP_ENODEV;
	if (g_hostfs_read_only)
		return -LXP_EROFS;
	hostfs_select(proc);
	int rc = operation(path);
	return hostfs_result(proc, rc);
}

long lxp_hostfs_mkdir(lxp_proc_t *proc, const char *abspath)
{
	const char *path = lxp_hostfs_relative(abspath);
	/* The mount root already exists in the guest namespace. POSIX mkdir(2)
	 * reports EEXIST for an existing directory; mkdir -p depends on that
	 * distinction to continue creating descendants below /data. */
	if (path && strcmp(path, "/") == 0)
		return -LXP_EEXIST;
	return hostfs_path_call(proc, abspath, g_lxp_fs_ops ? g_lxp_fs_ops->path_mkdir : NULL);
}

long lxp_hostfs_rmdir(lxp_proc_t *proc, const char *abspath)
{
	return hostfs_path_call(proc, abspath, g_lxp_fs_ops ? g_lxp_fs_ops->path_rmdir : NULL);
}

long lxp_hostfs_unlink(lxp_proc_t *proc, const char *abspath)
{
	return hostfs_path_call(proc, abspath, g_lxp_fs_ops ? g_lxp_fs_ops->path_unlink : NULL);
}

long lxp_hostfs_rename(lxp_proc_t *proc, const char *old_abspath, const char *new_abspath)
{
	const char *old_path = lxp_hostfs_relative(old_abspath);
	const char *new_path = lxp_hostfs_relative(new_abspath);
	if (!old_path || !new_path)
		return -LXP_EXDEV;
	if (strcmp(old_path, "/") == 0 || strcmp(new_path, "/") == 0)
		return -LXP_EBUSY;
	if (!g_lxp_fs_ops)
		return -LXP_ENODEV;
	if (g_hostfs_read_only)
		return -LXP_EROFS;
	hostfs_select(proc);
	int rc = g_lxp_fs_ops->path_rename(old_path, new_path);
	return hostfs_result(proc, rc);
}

void lxp_hostfs_runtime_reset(void)
{
	for (int i = 0; i < LXP_NHOSTFS_OPEN; i++)
		if (g_hostfs_open[i].used)
			lxp_hostfs_close(i);
	memset(g_hostfs_open, 0, sizeof(g_hostfs_open));
	memset(&g_hostfs_syscall, 0, sizeof(g_hostfs_syscall));
	strcpy(g_hostfs_mount_path, LXP_HOSTFS_DEFAULT_MOUNT);
	strcpy(g_hostfs_mount_source, "/dev/mmcblk0");
	g_hostfs_read_only = 0;
	if (++g_hostfs_run_generation == 0u)
		g_hostfs_run_generation = 1u;
}

long lxp_hostfs_statfs(lxp_proc_t *p, struct lxp_statfs64 *st)
{
	lxp_fs_volume_stat_t volume;
	long rc = lxp_hostfs_volume_stat(p, &volume);
	if (rc < 0)
		return rc;
	if (volume.block_size == 0u || volume.fragment_size == 0u ||
	    volume.blocks_free > volume.blocks || volume.blocks_available > volume.blocks_free)
		return -LXP_EIO;

	memset(st, 0, sizeof(*st));
	st->f_type = LXP_MSDOS_SUPER_MAGIC;
	st->f_bsize = volume.block_size;
	st->f_frsize = volume.fragment_size;
	st->f_blocks = volume.blocks;
	st->f_bfree = volume.blocks_free;
	st->f_bavail = volume.blocks_available;
	st->f_files = volume.files;
	st->f_ffree = volume.files_free;
	st->f_fsid[0] = LXP_HOSTFS_DEV_MAJOR;
	st->f_fsid[1] = LXP_HOSTFS_DEV_MINOR;
	st->f_namelen = volume.name_max;
	st->f_flags = LXP_ST_NOSUID | LXP_ST_NODEV | LXP_ST_NOEXEC;
	if (lxp_hostfs_is_read_only())
		st->f_flags |= LXP_ST_RDONLY;
	return 0;
}

/* ---- FD_HOSTFS file operations ---- */
static long fop_read_hostfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	return lxp_hostfs_read(p, s->file_idx, buf, len);
}

static long fop_write_hostfs(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	return lxp_hostfs_write(p, s->file_idx, buf, len);
}

static long fop_pread_hostfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len, uint64_t off)
{
	if (s->accmode == LXP_O_WRONLY)
		return -LXP_EBADF;
	return lxp_hostfs_pread(p, s->file_idx, buf, len, off);
}

static long fop_pwrite_hostfs(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len,
			      uint64_t off)
{
	if (s->accmode == LXP_O_RDONLY)
		return -LXP_EBADF;
	if (len)
		lxp_cache_clean(buf, len);
	return lxp_hostfs_pwrite(p, s->file_idx, buf, len, off);
}

static long fop_lseek_hostfs(lxp_proc_t *p, lxp_ofd_t *s, long off, int whence)
{
	long position = lxp_hostfs_seek(p, s->file_idx, off, whence);
	if (position >= 0)
		s->offset = (size_t)position;
	return position;
}

/* One provider entry per call keeps an async retry idempotent: no earlier directory
 * entries are consumed before a later read parks. */
static long fop_getdents_hostfs(lxp_proc_t *p, lxp_ofd_t *s, lxp_dirent_sink_t *sink)
{
	if (!lxp_hostfs_is_dir(s->file_idx))
		return -LXP_ENOTDIR;
	const lxp_fs_dirent_t *entry = NULL;
	long rc = lxp_hostfs_dir_peek(p, s->file_idx, &entry);
	if (rc <= 0)
		return rc;
	uint32_t mode = entry->type == LXP_FS_TYPE_DIR ? LXP_S_IFDIR : LXP_S_IFREG;
	if (!lxp_dirent_put(sink, 0x700001u + (uint64_t)s->offset, (uint64_t)s->offset + 1u,
			    lxp_dirent_type(mode), entry->name, strlen(entry->name)))
		return sink->error ? sink->error : -LXP_EINVAL;
	s->offset++;
	lxp_hostfs_dir_consume(s->file_idx);
	return (long)sink->filled;
}

static long fop_fstat_hostfs(lxp_proc_t *p, lxp_ofd_t *s, void *statbuf)
{
	lxp_fs_stat_t stat;
	long rc = lxp_hostfs_stat(p, s->file_idx, &stat);
	if (rc < 0)
		return rc;
	lxp_fill_kstat64(statbuf, lxp_hostfs_inode(s->file_idx), lxp_hostfs_mode(&stat), stat.size);
	((struct lxp_kstat64 *)statbuf)->st_dev = LXP_HOSTFS_DEV;
	((struct lxp_kstat64 *)statbuf)->st_mtime = (uint32_t)stat.mtime_sec;
	return 0;
}

static long fop_fstatfs_hostfs(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_statfs64 *st)
{
	(void)s;
	return lxp_hostfs_statfs(p, st);
}

static long fop_ftruncate_hostfs(lxp_proc_t *p, lxp_ofd_t *s, uint64_t length)
{
	if (s->accmode == LXP_O_RDONLY)
		return -LXP_EINVAL;
	return lxp_hostfs_truncate(p, s->file_idx, length);
}

static long fop_fsync_hostfs(lxp_proc_t *p, lxp_ofd_t *s)
{
	return lxp_hostfs_sync(p, s->file_idx);
}

static void fop_close_hostfs(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_hostfs_close(s->file_idx);
}

const lxp_file_ops_t lxp_hostfs_fops = {
	.read = fop_read_hostfs,
	.write = fop_write_hostfs,
	.pread = fop_pread_hostfs,
	.pwrite = fop_pwrite_hostfs,
	.lseek = fop_lseek_hostfs,
	.getdents = fop_getdents_hostfs,
	.fstat = fop_fstat_hostfs,
	.fstatfs = fop_fstatfs_hostfs,
	.ftruncate = fop_ftruncate_hostfs,
	.fsync = fop_fsync_hostfs,
	.close = fop_close_hostfs,
};

#endif /* LXP_ENABLE_FS */
