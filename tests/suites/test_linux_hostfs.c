/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux personality host-filesystem tests. A bounded in-process provider
 * verifies /data routing, opaque-handle lifetime, file operations, stat/chdir,
 * and lossless directory paging without depending on a host filesystem.
 */
#include "../framework/lxp_test.h"
#include "../framework/lxp_stat_view.h"

#include "lxp/lxp_fs_ops.h"
#include "lxp/lxp_block_ops.h"
#include "lxp_guest.h"
#include "lxp_syscall.h"
#include "fs/lxp_hostfs.h"
#include "lxp_provider.h"
#include "proc/lxp_procfs.h"

#include <string.h>

struct fake_file {
	size_t position;
};

struct fake_dir {
	size_t position;
};

static struct fake_file g_file;
static struct fake_dir g_dir;
static char g_content[64];
static size_t g_content_len;
static char g_open_path[LXP_FS_NAME_MAX];
static unsigned g_open_flags;
static unsigned g_close_count;
static unsigned g_sync_count;
static int g_seek_extends_file;
static char g_mutation[16];
static char g_mutation_path[LXP_FS_NAME_MAX];
static char g_rename_new_path[LXP_FS_NAME_MAX];
static uint64_t g_request_owner;
static uint64_t g_cancelled_owner;
static int g_async_once;
static int g_async_pending;
static int g_async_ready;
static const lxp_net_ops_t *g_saved_net;
static const lxp_display_ops_t *g_saved_display;
static const lxp_block_ops_t *g_saved_block;

void lxp_dev_autoreg_block(void);

static int fake_block_info(lxp_block_info_t *out)
{
	memset(out, 0, sizeof(*out));
	out->block_count = 4096u;
	out->logical_block_size = 512u;
	out->erase_block_size = 512u;
	out->flags = LXP_BLOCK_F_REMOVABLE | LXP_BLOCK_F_MEDIA_PRESENT;
	out->generation = 1u;
	return LXP_OK;
}

static int fake_block_read(uint64_t offset, void *buf, size_t count, size_t *done)
{
	(void)offset;
	memset(buf, 0, count);
	*done = count;
	return LXP_OK;
}

static const lxp_block_ops_t g_fake_block_ops = {
	.abi_version = LXP_BLOCK_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_block_ops_t),
	.get_info = fake_block_info,
	.read = fake_block_read,
};

static int fake_run_begin(lxp_fs_ready_fn ready, const void *context)
{
	(void)ready;
	(void)context;
	return LXP_OK;
}
static int fake_mount(const lxp_fs_mount_spec_t *spec)
{
	(void)spec;
	return LXP_OK;
}
static int fake_unmount(void)
{
	return LXP_OK;
}
static int fake_is_mounted(void)
{
	return 1;
}

static int fake_volume_stat(lxp_fs_volume_stat_t *out)
{
	memset(out, 0, sizeof(*out));
	out->blocks = 1000u;
	out->blocks_free = 375u;
	out->blocks_available = 360u;
	out->files = 200u;
	out->files_free = 123u;
	out->block_size = 512u;
	out->fragment_size = 32768u;
	out->name_max = 255u;
	return LXP_OK;
}

static void fake_run_end(void)
{
}

static void fake_request_owner(uint64_t owner)
{
	g_request_owner = owner;
}

static void fake_request_cancel(uint64_t owner)
{
	g_cancelled_owner = owner;
	if (owner == g_request_owner)
		g_async_pending = 0;
}

static int fake_path_stat(const char *path, lxp_fs_stat_t *out)
{
	memset(out, 0, sizeof(*out));
	if (strcmp(path, "/") == 0 || strcmp(path, "/sub") == 0) {
		out->type = LXP_FS_TYPE_DIR;
		return LXP_OK;
	}
	if (strcmp(path, "/hello.txt") == 0) {
		out->type = LXP_FS_TYPE_FILE;
		out->size = g_content_len;
		out->mtime_sec = 123;
		return LXP_OK;
	}
	return LXP_ERR_NOT_FOUND;
}

static int fake_file_open(const char *path, unsigned flags, lxp_fs_file_t *out)
{
	if (strcmp(path, "/hello.txt") != 0)
		return LXP_ERR_NOT_FOUND;
	strcpy(g_open_path, path);
	g_open_flags = flags;
	g_file.position = (flags & LXP_FS_O_APPEND) ? g_content_len : 0;
	*out = (lxp_fs_file_t)&g_file;
	return LXP_OK;
}

static int fake_dir_open(const char *path, lxp_fs_dir_t *out);

static int fake_object_open(const char *path, unsigned flags, int require_dir,
			    lxp_fs_open_result_t *out)
{
	memset(out, 0, sizeof(*out));
	if (strcmp(path, "/") == 0 || strcmp(path, "/sub") == 0) {
		if (require_dir == 0 && ((flags & LXP_FS_O_WRITE) != 0 ||
					 (flags & (LXP_FS_O_CREATE | LXP_FS_O_TRUNC)) != 0))
			return LXP_ERR_IS_DIR;
		int rc = fake_dir_open(path, &out->handle.dir);
		if (rc == LXP_OK)
			out->type = LXP_FS_TYPE_DIR;
		return rc;
	}
	if (require_dir)
		return LXP_ERR_NOT_DIR;
	int rc = fake_file_open(path, flags, &out->handle.file);
	if (rc == LXP_OK)
		out->type = LXP_FS_TYPE_FILE;
	return rc;
}

static int fake_file_close(lxp_fs_file_t file)
{
	assert_ptr_equal(file, &g_file);
	g_close_count++;
	return LXP_OK;
}

static int fake_file_read(lxp_fs_file_t file, void *buf, size_t count, size_t *bytes_read)
{
	if (g_async_pending && !g_async_ready)
		return LXP_ERR_WOULD_BLOCK;
	if (g_async_once) {
		g_async_once = 0;
		g_async_pending = 1;
		return LXP_ERR_WOULD_BLOCK;
	}
	g_async_pending = 0;
	struct fake_file *f = (struct fake_file *)file;
	size_t left = f->position < g_content_len ? g_content_len - f->position : 0;
	size_t done = count < left ? count : left;
	memcpy(buf, g_content + f->position, done);
	f->position += done;
	*bytes_read = done;
	return done ? LXP_OK : LXP_ERR_EOF;
}

static int fake_file_write(lxp_fs_file_t file, const void *buf, size_t count, size_t *bytes_written)
{
	struct fake_file *f = (struct fake_file *)file;
	if (count > sizeof(g_content) - f->position)
		return LXP_ERR_NO_SPACE;
	memcpy(g_content + f->position, buf, count);
	f->position += count;
	if (f->position > g_content_len)
		g_content_len = f->position;
	*bytes_written = count;
	return LXP_OK;
}

static int fake_file_seek(lxp_fs_file_t file, int64_t offset, int whence, uint64_t *new_offset)
{
	struct fake_file *f = (struct fake_file *)file;
	int64_t base = whence == LXP_FS_SEEK_SET   ? 0
		       : whence == LXP_FS_SEEK_CUR ? (int64_t)f->position
						   : (int64_t)g_content_len;
	if (whence < LXP_FS_SEEK_SET || whence > LXP_FS_SEEK_END || base + offset < 0)
		return LXP_ERR_INVALID_PARAM;
	if ((uint64_t)(base + offset) > g_content_len) {
		if (!g_seek_extends_file)
			return LXP_ERR_INVALID_PARAM;
		memset(g_content + g_content_len, 0xa5, (size_t)(base + offset) - g_content_len);
		g_content_len = (size_t)(base + offset);
	}
	f->position = (size_t)(base + offset);
	*new_offset = f->position;
	return LXP_OK;
}

static int fake_file_stat(lxp_fs_file_t file, lxp_fs_stat_t *out)
{
	(void)file;
	return fake_path_stat("/hello.txt", out);
}

static int fake_file_truncate(lxp_fs_file_t file, uint64_t length)
{
	(void)file;
	if (length > sizeof(g_content))
		return LXP_ERR_NO_SPACE;
	if (length > g_content_len)
		memset(g_content + g_content_len, 0, (size_t)length - g_content_len);
	g_content_len = (size_t)length;
	return LXP_OK;
}

static int fake_file_sync(lxp_fs_file_t file)
{
	(void)file;
	g_sync_count++;
	return LXP_OK;
}

static int fake_file_pread(lxp_fs_file_t file, void *buf, size_t count, uint64_t offset,
			   size_t *bytes_read)
{
	struct fake_file *f = (struct fake_file *)file;
	size_t saved = f->position;
	if (offset > g_content_len) {
		*bytes_read = 0;
		return LXP_ERR_EOF;
	}
	f->position = (size_t)offset;
	int rc = fake_file_read(file, buf, count, bytes_read);
	f->position = saved;
	return rc;
}

static int fake_file_pwrite(lxp_fs_file_t file, const void *buf, size_t count, uint64_t offset,
			    size_t *bytes_written)
{
	struct fake_file *f = (struct fake_file *)file;
	size_t saved = f->position;
	if (offset > g_content_len) {
		int rc = fake_file_truncate(file, offset);
		if (rc != LXP_OK)
			return rc;
	}
	f->position = (size_t)offset;
	int rc = fake_file_write(file, buf, count, bytes_written);
	f->position = saved;
	return rc;
}

static int fake_dir_open(const char *path, lxp_fs_dir_t *out)
{
	if (strcmp(path, "/") != 0)
		return LXP_ERR_NOT_FOUND;
	g_dir.position = 0;
	*out = (lxp_fs_dir_t)&g_dir;
	return LXP_OK;
}

static int fake_dir_read(lxp_fs_dir_t dir, lxp_fs_dirent_t *entry)
{
	struct fake_dir *d = (struct fake_dir *)dir;
	memset(entry, 0, sizeof(*entry));
	if (d->position == 0) {
		strcpy(entry->name, "hello.txt");
		entry->type = LXP_FS_TYPE_FILE;
		entry->size = g_content_len;
	} else if (d->position == 1) {
		strcpy(entry->name, "sub");
		entry->type = LXP_FS_TYPE_DIR;
	} else {
		return LXP_ERR_EOF;
	}
	d->position++;
	return LXP_OK;
}

static int fake_dir_close(lxp_fs_dir_t dir)
{
	assert_ptr_equal(dir, &g_dir);
	g_close_count++;
	return LXP_OK;
}

static int fake_mutation(const char *operation, const char *path)
{
	strcpy(g_mutation, operation);
	strcpy(g_mutation_path, path);
	return LXP_OK;
}

static int fake_mkdir(const char *path)
{
	return fake_mutation("mkdir", path);
}

static int fake_rmdir(const char *path)
{
	return fake_mutation("rmdir", path);
}

static int fake_unlink(const char *path)
{
	return fake_mutation("unlink", path);
}

static int fake_rename(const char *old_path, const char *new_path)
{
	fake_mutation("rename", old_path);
	strcpy(g_rename_new_path, new_path);
	return LXP_OK;
}

static int fake_metrics(lxp_fs_metrics_t *out)
{
	memset(out, 0, sizeof(*out));
	out->requests_submitted = 17;
	out->requests_completed = 16;
	out->requests_failed = 2;
	out->bytes_read = 4096;
	out->bytes_written = 2048;
	out->queue_wait_us_total = 120;
	out->queue_wait_us_max = 45;
	out->service_us_total = 800;
	out->service_us_max = 210;
	out->budget_overruns = 3;
	out->media_available = 1;
	out->media_read_commands = 22;
	out->media_write_commands = 11;
	out->media_read_blocks = 32;
	out->media_write_blocks = 16;
	out->media_multiblock_commands = 4;
	out->media_completion_wait_us_total = 900;
	out->media_completion_wait_us_max = 90;
	out->media_ready_wait_us_total = 700;
	out->media_ready_wait_us_max = 80;
	out->media_errors = 2;
	out->media_recoveries = 1;
	out->pending = 1;
	out->queue_depth_max = 1;
	return LXP_OK;
}

static const lxp_fs_ops_t g_fake_ops = {
	.abi_version = LXP_FS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_fs_ops_t),
	.run_begin = fake_run_begin,
	.run_end = fake_run_end,
	.request_owner = fake_request_owner,
	.request_cancel = fake_request_cancel,
	.mount = fake_mount,
	.unmount = fake_unmount,
	.is_mounted = fake_is_mounted,
	.volume_stat = fake_volume_stat,
	.file_open = fake_file_open,
	.object_open = fake_object_open,
	.file_close = fake_file_close,
	.file_read = fake_file_read,
	.file_write = fake_file_write,
	.file_seek = fake_file_seek,
	.file_stat = fake_file_stat,
	.file_truncate = fake_file_truncate,
	.file_sync = fake_file_sync,
	.file_pread = fake_file_pread,
	.file_pwrite = fake_file_pwrite,
	.dir_open = fake_dir_open,
	.dir_read = fake_dir_read,
	.dir_close = fake_dir_close,
	.path_stat = fake_path_stat,
	.path_mkdir = fake_mkdir,
	.path_rmdir = fake_rmdir,
	.path_unlink = fake_unlink,
	.path_rename = fake_rename,
	.metrics = fake_metrics,
};

static uint8_t g_pool[8192] __attribute__((aligned(16)));
static const lxp_file_t g_rootfs[] = {
	{.path = "/", .mode = LXP_S_IFDIR | 0755u},
	{.path = "/mnt", .mode = LXP_S_IFDIR | 0755u},
};

static void setup(lxp_proc_t *proc, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_pool, sizeof(g_pool)), LXP_OK);
	assert_int_equal(lxp_test_proc_init(proc, arena, 4096), LXP_OK);
	proc->mm->region_lo = 1;
	proc->mm->region_hi = UINTPTR_MAX;
	proc->mm->pool_lo = proc->mm->pool_hi = 0;
	lxp_proc_set_rootfs(proc, g_rootfs, sizeof(g_rootfs) / sizeof(g_rootfs[0]));
	memcpy(g_content, "hello", 5);
	g_content_len = 5;
	g_open_path[0] = '\0';
	g_open_flags = 0;
	g_close_count = 0;
	g_sync_count = 0;
	g_seek_extends_file = 0;
	g_mutation[0] = '\0';
	g_mutation_path[0] = '\0';
	g_rename_new_path[0] = '\0';
	g_request_owner = 0;
	g_cancelled_owner = 0;
	g_async_once = 0;
	g_async_pending = 0;
	g_async_ready = 0;
}

static long call(lxp_proc_t *proc, long nr, long a0, long a1, long a2)
{
	return lxp_syscall(proc, nr, a0, a1, a2, 0, 0, 0);
}

static int contains_dirent64(const uint8_t *buf, size_t len, const char *name)
{
	size_t offset = 0;
	while (offset + 19u <= len) {
		uint16_t reclen;
		memcpy(&reclen, buf + offset + 16u, sizeof(reclen));
		if (reclen < 20u || offset + reclen > len)
			return 0;
		if (strcmp((const char *)buf + offset + 19u, name) == 0)
			return 1;
		offset += reclen;
	}
	return 0;
}

static void test_hostfs_file_lifetime_and_io(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long fd = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
		       LXP_O_RDONLY);
	assert_true(fd >= 3);
	assert_int_equal(lxp_fd_kind(&proc, (int)fd), LXP_FD_HOSTFS);
	assert_string_equal(g_open_path, "/hello.txt");
	assert_true((g_open_flags & LXP_FS_O_READ) != 0);

	char out[8] = {0};
	assert_int_equal(call(&proc, LXP_NR_read, fd, (long)(uintptr_t)out, 0), 0);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_read, fd, (long)(uintptr_t)out, 5, 0, 0, 0), 5);
	assert_memory_equal(out, "hello", 5);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_lseek, fd, 0, LXP_SEEK_END, 0, 0, 0), 5);

	long alias = lxp_syscall(&proc, LXP_NR_dup, fd, 0, 0, 0, 0, 0);
	assert_true(alias >= 0);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);
	assert_int_equal(g_close_count, 0);
	assert_int_equal(call(&proc, LXP_NR_close, alias, 0, 0), 0);
	assert_int_equal(g_close_count, 1);
}

static void test_hostfs_write_stat_and_chdir(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long fd = lxp_syscall(&proc, LXP_NR_openat, LXP_AT_FDCWD,
			      (long)(uintptr_t)"/data/hello.txt", LXP_O_RDWR | LXP_O_APPEND, 0, 0,
			      0);
	assert_true(fd >= 0);
	assert_true((g_open_flags & (LXP_FS_O_READ | LXP_FS_O_WRITE | LXP_FS_O_APPEND)) ==
		    (LXP_FS_O_READ | LXP_FS_O_WRITE | LXP_FS_O_APPEND));
	assert_int_equal(lxp_syscall(&proc, LXP_NR_write, fd, (long)(uintptr_t)"!", 1, 0, 0, 0), 1);

	uint8_t statbuf[104] = {0};
	assert_int_equal(
		lxp_syscall(&proc, LXP_NR_fstat64, fd, (long)(uintptr_t)statbuf, 0, 0, 0, 0), 0);
	uint32_t mode;
	int64_t size;
	memcpy(&mode, statbuf + 16, sizeof(mode));
	memcpy(&size, statbuf + 48, sizeof(size));
	assert_int_equal(mode & LXP_S_IFMT, LXP_S_IFREG);
	assert_int_equal(size, 6);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);

	assert_int_equal(call(&proc, LXP_NR_chdir, (long)(uintptr_t)"/data/sub", 0, 0), 0);
	assert_string_equal(proc.fs_context->cwd, "/data/sub");
	assert_int_equal(call(&proc, LXP_NR_access, (long)(uintptr_t)"/data/hello.txt", 0, 0), 0);
}

/* fstat64 and statx(AT_EMPTY_PATH) on one hostfs descriptor. */
static void test_hostfs_stat_fd_both(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long fd = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
		       LXP_O_RDONLY);
	assert_true(fd >= 0);
	uint8_t buf[256] = {0};
	assert_int_equal(call(&proc, LXP_NR_fstat64, fd, (long)(uintptr_t)buf, 0), 0);
	lxp_stat_view_t k = lxp_view_kstat64(buf);
	memset(buf, 0, sizeof(buf));
	assert_int_equal(lxp_syscall(&proc, LXP_NR_statx, fd, (long)(uintptr_t)"", LXP_AT_EMPTY_PATH,
				     0, (long)(uintptr_t)buf, 0),
			 0);
	lxp_stat_view_t x = lxp_view_statx(buf);

	assert_int_equal(k.mode, LXP_S_IFREG | 0666u);
	assert_int_equal(k.dev, (uint64_t)LXP_HOSTFS_DEV_MAJOR << 8);
	assert_int_equal(k.mtime, 123);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);
	assert_int_equal(x.size, k.size);
	assert_int_equal(x.dev, k.dev);
	assert_int_equal(x.mtime, k.mtime);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);
}

static void test_hostfs_inode_is_stable_across_open_slots(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long first = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
			  LXP_O_RDONLY);
	long second = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
			   LXP_O_RDONLY);
	assert_true(first >= 0);
	assert_true(second >= 0);

	uint8_t path_stat[104] = {0};
	uint8_t first_stat[104] = {0};
	uint8_t second_stat[104] = {0};
	assert_int_equal(call(&proc, LXP_NR_stat64, (long)(uintptr_t)"/data/hello.txt",
			      (long)(uintptr_t)path_stat, 0),
			 0);
	assert_int_equal(call(&proc, LXP_NR_fstat64, first, (long)(uintptr_t)first_stat, 0), 0);
	assert_int_equal(call(&proc, LXP_NR_fstat64, second, (long)(uintptr_t)second_stat, 0), 0);

	uint64_t path_inode;
	uint64_t first_inode;
	uint64_t second_inode;
	uint64_t path_device;
	uint64_t first_device;
	memcpy(&path_inode, path_stat + 96, sizeof(path_inode));
	memcpy(&first_inode, first_stat + 96, sizeof(first_inode));
	memcpy(&second_inode, second_stat + 96, sizeof(second_inode));
	memcpy(&path_device, path_stat, sizeof(path_device));
	memcpy(&first_device, first_stat, sizeof(first_device));
	assert_true(path_inode != 0);
	assert_int_equal(first_inode, path_inode);
	assert_int_equal(second_inode, path_inode);
	assert_int_equal(path_device, (179u << 8));
	assert_int_equal(first_device, path_device);

	assert_int_equal(call(&proc, LXP_NR_close, first, 0, 0), 0);
	assert_int_equal(call(&proc, LXP_NR_close, second, 0, 0), 0);
}

static void test_hostfs_volume_stats_and_syncfs(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);
	struct statfs_probe {
		uint32_t type;
		uint32_t block_size;
		uint64_t blocks;
		uint64_t blocks_free;
		uint64_t blocks_available;
		uint64_t files;
		uint64_t files_free;
		uint32_t fsid[2];
		uint32_t name_max;
		uint32_t fragment_size;
		uint32_t flags;
		uint32_t spare[4];
	} stat;

	memset(&stat, 0, sizeof(stat));
	assert_int_equal(call(&proc, LXP_NR_statfs64, (long)(uintptr_t)"/data", sizeof(stat),
			      (long)(uintptr_t)&stat),
			 0);
	assert_int_equal(stat.type, 0x4d44u);
	assert_int_equal(stat.block_size, 512u);
	assert_int_equal(stat.fragment_size, 32768u);
	assert_int_equal(stat.blocks, 1000u);
	assert_int_equal(stat.blocks_free, 375u);
	assert_int_equal(stat.blocks_available, 360u);
	assert_int_equal(stat.files, 200u);
	assert_int_equal(stat.files_free, 123u);
	assert_int_equal(stat.name_max, 255u);
	assert_int_equal(stat.flags, 0x0eu);

	long fd = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
		       LXP_O_RDWR);
	assert_true(fd >= 0);
	memset(&stat, 0, sizeof(stat));
	assert_int_equal(call(&proc, LXP_NR_fstatfs64, fd, sizeof(stat), (long)(uintptr_t)&stat),
			 0);
	assert_int_equal(stat.blocks_available, 360u);
	assert_int_equal(call(&proc, LXP_NR_fstatfs64, 99, sizeof(stat), (long)(uintptr_t)&stat),
			 -LXP_EBADF);
	assert_int_equal(call(&proc, LXP_NR_syncfs, fd, 0, 0), 0);
	assert_int_equal(g_sync_count, 1u);
	assert_int_equal(call(&proc, LXP_NR_syncfs, 99, 0, 0), -LXP_EBADF);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);
}

static void test_hostfs_directory_paging_and_mount_boundary(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long dfd = lxp_syscall(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data",
			       LXP_O_RDONLY | LXP_O_DIRECTORY, 0, 0, 0);
	assert_true(dfd >= 0);
	uint8_t first[32] = {0}, second[32] = {0};
	long n1 = lxp_syscall(&proc, LXP_NR_getdents64, dfd, (long)(uintptr_t)first, sizeof(first),
			      0, 0, 0);
	long n2 = lxp_syscall(&proc, LXP_NR_getdents64, dfd, (long)(uintptr_t)second,
			      sizeof(second), 0, 0, 0);
	assert_true(n1 > 0);
	assert_true(n2 > 0);
	assert_true(contains_dirent64(first, (size_t)n1, "hello.txt"));
	assert_true(contains_dirent64(second, (size_t)n2, "sub"));
	assert_int_equal(lxp_syscall(&proc, LXP_NR_getdents64, dfd, (long)(uintptr_t)second,
				     sizeof(second), 0, 0, 0),
			 0);
	assert_int_equal(call(&proc, LXP_NR_close, dfd, 0, 0), 0);

	/* /database is not under the mount and must not reach the provider. */
	g_open_path[0] = '\0';
	long local = lxp_syscall(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/database",
				 LXP_O_CREAT | LXP_O_RDWR, 0, 0, 0);
	assert_true(local >= 0);
	assert_int_equal(lxp_fd_kind(&proc, (int)local), LXP_FD_TMPFS);
	assert_string_equal(g_open_path, "");
	assert_int_equal(call(&proc, LXP_NR_close, local, 0, 0), 0);
}

static void test_hostfs_positioned_io_truncate_and_sync(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long fd = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
		       LXP_O_RDWR);
	assert_true(fd >= 0);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_lseek, fd, 2, LXP_SEEK_SET, 0, 0, 0), 2);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_pwrite64, fd, (long)(uintptr_t)"A", 1, 0, 1, 0),
			 1);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_lseek, fd, 0, LXP_SEEK_CUR, 0, 0, 0), 2);

	char out[6] = {0};
	assert_int_equal(lxp_syscall(&proc, LXP_NR_pread64, fd, (long)(uintptr_t)out, 5, 0, 0, 0),
			 5);
	assert_memory_equal(out, "hAllo", 5);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_lseek, fd, 0, LXP_SEEK_CUR, 0, 0, 0), 2);

	/* Positioned writes must grow a zero-filled hole even when an embedded
	 * provider rejects seeking beyond EOF. Simulate that provider policy. */
	assert_int_equal(fake_file_truncate((lxp_fs_file_t)&g_file, 3), LXP_OK);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_pwrite64, fd, (long)(uintptr_t)"Z", 1, 0, 6, 0),
			 1);
	assert_int_equal(g_content_len, 7);
	assert_memory_equal(g_content, "hAl\0\0\0Z", 7);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_lseek, fd, 0, LXP_SEEK_CUR, 0, 0, 0), 2);
	/* A provider whose seek primitive extends writable files must never see
	 * the beyond-EOF pread probe. */
	g_seek_extends_file = 1;
	assert_int_equal(lxp_syscall(&proc, LXP_NR_pread64, fd, (long)(uintptr_t)out, 1, 0, 20, 0),
			 0);
	assert_int_equal(g_content_len, 7);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_lseek, fd, 0, LXP_SEEK_CUR, 0, 0, 0), 2);

	/* ARM ftruncate64 aligns the 64-bit length to a2/a3. */
	assert_int_equal(lxp_syscall(&proc, LXP_NR_ftruncate64, fd, 0, 3, 0, 0, 0), 0);
	assert_int_equal(g_content_len, 3);
	assert_int_equal(call(&proc, LXP_NR_fsync, fd, 0, 0), 0);
	assert_int_equal(call(&proc, LXP_NR_fdatasync, fd, 0, 0), 0);
	assert_int_equal(g_sync_count, 2);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);
}

static void test_hostfs_mutations_and_cross_mount_errors(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	assert_int_equal(call(&proc, LXP_NR_mkdir, (long)(uintptr_t)"/data/new", 0755, 0), 0);
	assert_string_equal(g_mutation, "mkdir");
	assert_string_equal(g_mutation_path, "/new");
	assert_int_equal(call(&proc, LXP_NR_rmdir, (long)(uintptr_t)"/data/new", 0, 0), 0);
	assert_string_equal(g_mutation, "rmdir");
	assert_int_equal(call(&proc, LXP_NR_unlink, (long)(uintptr_t)"/data/old", 0, 0), 0);
	assert_string_equal(g_mutation, "unlink");
	assert_string_equal(g_mutation_path, "/old");

	assert_int_equal(lxp_syscall(&proc, LXP_NR_rename, (long)(uintptr_t)"/data/old",
				     (long)(uintptr_t)"/data/new", 0, 0, 0, 0),
			 0);
	assert_string_equal(g_mutation, "rename");
	assert_string_equal(g_mutation_path, "/old");
	assert_string_equal(g_rename_new_path, "/new");
	assert_int_equal(lxp_syscall(&proc, LXP_NR_rename, (long)(uintptr_t)"/data/old",
				     (long)(uintptr_t)"/tmp/new", 0, 0, 0, 0),
			 -LXP_EXDEV);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_renameat2, LXP_AT_FDCWD,
				     (long)(uintptr_t)"/data/old", LXP_AT_FDCWD,
				     (long)(uintptr_t)"/data/new", 1, 0),
			 -LXP_EINVAL);

	assert_int_equal(lxp_syscall(&proc, LXP_NR_link, (long)(uintptr_t)"/data/old",
				     (long)(uintptr_t)"/tmp/new", 0, 0, 0, 0),
			 -LXP_EXDEV);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_link, (long)(uintptr_t)"/data/old",
				     (long)(uintptr_t)"/data/new", 0, 0, 0, 0),
			 -LXP_EOPNOTSUPP);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_symlink, (long)(uintptr_t)"target",
				     (long)(uintptr_t)"/data/link", 0, 0, 0, 0),
			 -LXP_EOPNOTSUPP);
	/* The mount root is an existing directory: mkdir must report EEXIST so
	 * mkdir -p can safely walk through it. Destructive mutations stay busy. */
	assert_int_equal(call(&proc, LXP_NR_mkdir, (long)(uintptr_t)"/data", 0755, 0), -LXP_EEXIST);
}

static void test_hostfs_access_modes(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long fd = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
		       LXP_O_WRONLY);
	assert_true(fd >= 0);
	char byte = 0;
	assert_int_equal(call(&proc, LXP_NR_read, fd, (long)(uintptr_t)&byte, 1), -LXP_EBADF);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_fcntl64, fd, LXP_F_GETFL, 0, 0, 0, 0),
			 LXP_O_WRONLY);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);

	fd = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
		  LXP_O_RDONLY);
	assert_true(fd >= 0);
	assert_int_equal(call(&proc, LXP_NR_write, fd, (long)(uintptr_t)"x", 1), -LXP_EBADF);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);
}

static void test_hostfs_metrics_proc(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	char out[1024];
	setup(&proc, &arena);

	long len = proc_gen("/proc/lxp_fs", &proc, out, sizeof(out) - 1u);
	assert_true(len > 0);
	out[len] = '\0';
	assert_non_null(strstr(out, "provider_available 1\n"));
	assert_non_null(strstr(out, "requests_submitted 17\n"));
	assert_non_null(strstr(out, "requests_completed 16\n"));
	assert_non_null(strstr(out, "requests_failed 2\n"));
	assert_non_null(strstr(out, "pending 1\n"));
	assert_non_null(strstr(out, "bytes_read 4096\n"));
	assert_non_null(strstr(out, "service_us_max 210\n"));
	assert_non_null(strstr(out, "budget_overruns 3\n"));
	assert_non_null(strstr(out, "media_available 1\n"));
	assert_non_null(strstr(out, "media_read_commands 22\n"));
	assert_non_null(strstr(out, "media_write_commands 11\n"));
	assert_non_null(strstr(out, "media_multiblock_commands 4\n"));
	assert_non_null(strstr(out, "media_completion_wait_us_max 90\n"));
	assert_non_null(strstr(out, "media_ready_wait_us_max 80\n"));
	assert_non_null(strstr(out, "media_errors 2\n"));
	assert_non_null(strstr(out, "media_recoveries 1\n"));
}

static void test_hostfs_async_wait_is_generation_owned(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);
	proc.pid = 42;
	long fd = call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/data/hello.txt",
		       LXP_O_RDONLY);
	assert_true(fd >= 0);

	g_async_once = 1;
	char out[6] = {0};
	long rc = call(&proc, LXP_NR_read, fd, (long)(uintptr_t)out, 5);
	assert_int_equal(rc, -LXP_EAGAIN);
	assert_int_equal(proc.wait.kind, LXP_WAIT_HOSTFS);
	assert_true(proc.wait.data.hostfs.owner != 0);
	assert_int_equal(proc.wait.data.hostfs.owner, g_request_owner);

	g_async_ready = 1;
	rc = call(&proc, LXP_NR_read, fd, (long)(uintptr_t)out, 5);
	assert_int_equal(rc, 5);
	assert_memory_equal(out, "hello", 5);
	assert_int_equal(lxp_wait_complete(&proc, LXP_WAIT_HOSTFS), LXP_OK);

	g_async_once = 1;
	g_async_ready = 0;
	rc = call(&proc, LXP_NR_read, fd, (long)(uintptr_t)out, 1);
	assert_int_equal(rc, -LXP_EAGAIN);
	uint64_t owner = proc.wait.data.hostfs.owner;
	lxp_hostfs_cancel(&proc);
	assert_int_equal(g_cancelled_owner, owner);
	assert_int_equal(call(&proc, LXP_NR_close, fd, 0, 0), 0);
}

static void test_mount_semantics_read_only_and_proc_reporting(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	char out[512];
	setup(&proc, &arena);

	assert_int_equal(lxp_syscall(&proc, LXP_NR_mount, (long)(uintptr_t)"/dev/mmcblk0",
				     (long)(uintptr_t)"/mnt", (long)(uintptr_t)"ext2", 0, 0, 0),
			 -LXP_ENODEV);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_mount, (long)(uintptr_t)"/dev/mmcblk0",
				     (long)(uintptr_t)"/mnt", (long)(uintptr_t)"vfat", 0,
				     (long)(uintptr_t)"uid=0", 0),
			 -LXP_EOPNOTSUPP);
	assert_int_equal(lxp_syscall(&proc, LXP_NR_mount, (long)(uintptr_t)"/dev/mmcblk0",
				     (long)(uintptr_t)"/mnt", (long)(uintptr_t)"vfat", 0,
				     (long)(uintptr_t)"ro,noexec", 0),
			 0);
	assert_string_equal(lxp_hostfs_mount_path(), "/mnt");
	assert_true(lxp_hostfs_is_read_only());
	assert_int_equal(call(&proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/mnt/hello.txt",
			      LXP_O_WRONLY),
			 -LXP_EROFS);
	assert_int_equal(call(&proc, LXP_NR_access, (long)(uintptr_t)"/mnt/hello.txt", 2, 0),
			 -LXP_EROFS);
	assert_int_equal(call(&proc, LXP_NR_access, (long)(uintptr_t)"/mnt/hello.txt", 1, 0),
			 -LXP_EACCES);

	long len = proc_gen("/proc/mounts", &proc, out, sizeof(out) - 1u);
	assert_true(len > 0);
	out[len] = '\0';
	assert_non_null(strstr(out, "/dev/mmcblk0 /mnt vfat ro,nosuid,nodev,noexec 0 0\n"));
	len = proc_gen("/proc/filesystems", &proc, out, sizeof(out) - 1u);
	assert_true(len > 0);
	out[len] = '\0';
	assert_non_null(strstr(out, "\tvfat\n"));

	assert_int_equal(call(&proc, LXP_NR_umount2, (long)(uintptr_t)"/mnt", 0, 0), 0);
}

static int group_setup(void **state)
{
	(void)state;
	g_saved_net = g_lxp_net_ops;
	g_saved_display = g_lxp_display_ops;
	g_saved_block = g_lxp_block_ops;
	lxp_providers_publish(g_saved_net, g_saved_display, &g_fake_ops, &g_fake_block_ops);
	lxp_dev_autoreg_block();
	return 0;
}

static int group_teardown(void **state)
{
	(void)state;
	lxp_fd_runtime_reset();
	lxp_providers_publish(g_saved_net, g_saved_display, NULL, g_saved_block);
	return 0;
}

int test_linux_hostfs_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hostfs_file_lifetime_and_io),
		cmocka_unit_test(test_hostfs_write_stat_and_chdir),
		cmocka_unit_test(test_hostfs_stat_fd_both),
		cmocka_unit_test(test_hostfs_inode_is_stable_across_open_slots),
		cmocka_unit_test(test_hostfs_volume_stats_and_syncfs),
		cmocka_unit_test(test_hostfs_directory_paging_and_mount_boundary),
		cmocka_unit_test(test_hostfs_positioned_io_truncate_and_sync),
		cmocka_unit_test(test_hostfs_mutations_and_cross_mount_errors),
		cmocka_unit_test(test_hostfs_access_modes),
		cmocka_unit_test(test_hostfs_metrics_proc),
		cmocka_unit_test(test_hostfs_async_wait_is_generation_owned),
		cmocka_unit_test(test_mount_semantics_read_only_and_proc_reporting),
	};
	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
