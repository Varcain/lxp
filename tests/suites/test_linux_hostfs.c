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

#include "lxp/lxp_fs_ops.h"
#include "lxp/lxp_guest.h"
#include "lxp/lxp_syscall.h"
#include "lxp_provider.h"

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
static const lxp_net_ops_t *g_saved_net;
static const lxp_display_ops_t *g_saved_display;

static int fake_run_begin(void)
{
	return LXP_OK;
}

static void fake_run_end(void)
{
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

static int fake_file_close(lxp_fs_file_t file)
{
	assert_ptr_equal(file, &g_file);
	g_close_count++;
	return LXP_OK;
}

static int fake_file_read(lxp_fs_file_t file, void *buf, size_t count, size_t *bytes_read)
{
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
		memset(g_content + g_content_len, 0xa5,
		       (size_t)(base + offset) - g_content_len);
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

static const lxp_fs_ops_t g_fake_ops = {
	.abi_version = LXP_FS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_fs_ops_t),
	.run_begin = fake_run_begin,
	.run_end = fake_run_end,
	.file_open = fake_file_open,
	.file_close = fake_file_close,
	.file_read = fake_file_read,
	.file_write = fake_file_write,
	.file_seek = fake_file_seek,
	.file_stat = fake_file_stat,
	.file_truncate = fake_file_truncate,
	.file_sync = fake_file_sync,
	.dir_open = fake_dir_open,
	.dir_read = fake_dir_read,
	.dir_close = fake_dir_close,
	.path_stat = fake_path_stat,
	.path_mkdir = fake_mkdir,
	.path_rmdir = fake_rmdir,
	.path_unlink = fake_unlink,
	.path_rename = fake_rename,
};

static uint8_t g_pool[8192] __attribute__((aligned(16)));
static const lxp_file_t g_rootfs[] = {
	{.path = "/", .mode = LXP_S_IFDIR | 0755u},
};

static void setup(lxp_proc_t *proc, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_pool, sizeof(g_pool)), LXP_OK);
	assert_int_equal(lxp_test_proc_init(proc, arena, 4096), LXP_OK);
	proc->mm->region_lo = 1;
	proc->mm->region_hi = UINTPTR_MAX;
	proc->mm->pool_lo = proc->mm->pool_hi = 0;
	lxp_proc_set_rootfs(proc, g_rootfs, 1);
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

static void test_hostfs_inode_is_stable_across_open_slots(void **state)
{
	(void)state;
	lxp_proc_t proc;
	lxp_arena_t arena;
	setup(&proc, &arena);

	long first = call(&proc, LXP_NR_openat, LXP_AT_FDCWD,
			  (long)(uintptr_t)"/data/hello.txt", LXP_O_RDONLY);
	long second = call(&proc, LXP_NR_openat, LXP_AT_FDCWD,
			   (long)(uintptr_t)"/data/hello.txt", LXP_O_RDONLY);
	assert_true(first >= 0);
	assert_true(second >= 0);

	uint8_t path_stat[104] = {0};
	uint8_t first_stat[104] = {0};
	uint8_t second_stat[104] = {0};
	assert_int_equal(call(&proc, LXP_NR_stat64, (long)(uintptr_t)"/data/hello.txt",
			      (long)(uintptr_t)path_stat, 0),
			 0);
	assert_int_equal(call(&proc, LXP_NR_fstat64, first, (long)(uintptr_t)first_stat, 0), 0);
	assert_int_equal(call(&proc, LXP_NR_fstat64, second, (long)(uintptr_t)second_stat, 0),
			 0);

	uint64_t path_inode;
	uint64_t first_inode;
	uint64_t second_inode;
	memcpy(&path_inode, path_stat + 96, sizeof(path_inode));
	memcpy(&first_inode, first_stat + 96, sizeof(first_inode));
	memcpy(&second_inode, second_stat + 96, sizeof(second_inode));
	assert_true(path_inode != 0);
	assert_int_equal(first_inode, path_inode);
	assert_int_equal(second_inode, path_inode);

	assert_int_equal(call(&proc, LXP_NR_close, first, 0, 0), 0);
	assert_int_equal(call(&proc, LXP_NR_close, second, 0, 0), 0);
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
	assert_int_equal(
		lxp_syscall(&proc, LXP_NR_pread64, fd, (long)(uintptr_t)out, 1, 0, 20, 0),
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
	assert_int_equal(call(&proc, LXP_NR_mkdir, (long)(uintptr_t)"/data", 0755, 0),
			 -LXP_EEXIST);
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

static int group_setup(void **state)
{
	(void)state;
	g_saved_net = g_lxp_net_ops;
	g_saved_display = g_lxp_disp_ops;
	lxp_providers_publish(g_saved_net, g_saved_display, &g_fake_ops);
	return 0;
}

static int group_teardown(void **state)
{
	(void)state;
	lxp_fd_runtime_reset();
	lxp_providers_publish(g_saved_net, g_saved_display, NULL);
	return 0;
}

int test_linux_hostfs_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hostfs_file_lifetime_and_io),
		cmocka_unit_test(test_hostfs_write_stat_and_chdir),
		cmocka_unit_test(test_hostfs_inode_is_stable_across_open_slots),
		cmocka_unit_test(test_hostfs_directory_paging_and_mount_boundary),
		cmocka_unit_test(test_hostfs_positioned_io_truncate_and_sync),
		cmocka_unit_test(test_hostfs_mutations_and_cross_mount_errors),
		cmocka_unit_test(test_hostfs_access_modes),
	};
	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
