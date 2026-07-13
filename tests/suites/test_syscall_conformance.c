/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Syscall golden-conformance suite: the correctness half of the syscall-confirmation
 * effort (the coverage half is scripts/syscalls/check-syscalls.sh). For each implemented
 * syscall it pins the return value, the errno on the standard error paths, and — for the
 * struct-filling calls — the actual field VALUES against the Linux ABI (the static asserts
 * in lxp_syscall.c only pin sizes/offsets). The deliberate benign stubs and EOPNOTSUPP
 * refusals are asserted too, so the suite documents intent, not just successes.
 *
 * The proc runs on a bounded LOW-4 GiB region (tests/framework/lxp_proc_fixture.h), so
 * user_ok() bounds are real (a bad guest pointer is genuinely -EFAULT) and brk/mmap return
 * addresses that fit a 32-bit r0 exactly. The trap->dispatch->resume ABI and the run-loop-
 * intercepted fork/signal machinery are NOT reachable here (host cmocka calls lxp_syscall()
 * directly); those are confirmed on-target by the QEMU M4 conformance guest.
 */
#define _GNU_SOURCE

#include "../framework/lxp_test.h"
#include "../framework/lxp_proc_fixture.h"

#include <stdint.h>
#include <string.h>

/* ---- ABI mirrors (identical layout to the file-scope structs in lxp_syscall.c) -------- */

/* struct stat64 as the ARM guest sees it (fixed-width; sizeof 104). */
struct conf_kstat64 {
	uint64_t st_dev;
	uint8_t __pad0[4];
	uint32_t __st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint64_t st_rdev;
	uint8_t __pad3[4];
	int64_t st_size;
	uint32_t st_blksize;
	uint64_t st_blocks;
	uint32_t st_atime, st_atime_nsec, st_mtime, st_mtime_nsec, st_ctime, st_ctime_nsec;
	uint64_t st_ino;
};

/* struct statx (sizeof 256). */
struct conf_statx {
	uint32_t stx_mask;
	uint32_t stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink;
	uint32_t stx_uid;
	uint32_t stx_gid;
	uint16_t stx_mode;
	uint16_t __spare0;
	uint64_t stx_ino;
	uint64_t stx_size;
	uint64_t stx_blocks;
	uint64_t stx_attributes_mask;
	uint8_t __times[64];
	uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
	uint8_t __rest[256 - 144];
};

/* struct sysinfo (sizeof 64). */
struct conf_sysinfo {
	int32_t uptime;
	uint32_t loads[3];
	uint32_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
	uint16_t procs, pad;
	uint32_t totalhigh, freehigh, mem_unit;
	char _f[8];
};

/* ---- fixed rootfs the suite stats / lists / reads ------------------------------------- */

static const uint8_t k_motd[] = "Welcome to oveRTOS\n"; /* 19 bytes */
static const uint8_t k_host[] = "overtos\n";		/* 8 bytes */
static const uint8_t k_elf[] = {0x7f, 'E', 'L', 'F'};

static const lxp_file_t k_rootfs[] = {
	{"/", NULL, 0, LXP_S_IFDIR},
	{"/etc", NULL, 0, LXP_S_IFDIR},
	{"/etc/motd", k_motd, sizeof(k_motd) - 1, 0},		     /* rootfs idx 2 -> ino 3 */
	{"/etc/hostname", k_host, sizeof(k_host) - 1, 0},	     /* idx 3 -> ino 4 */
	{"/etc/self", (const uint8_t *)"/etc/motd", 9, LXP_S_IFLNK}, /* symlink -> /etc/motd */
	{"/bin", NULL, 0, LXP_S_IFDIR},
	{"/bin/sh", k_elf, sizeof(k_elf), 0},
};
#define K_ROOTFS_N ((int)(sizeof(k_rootfs) / sizeof(k_rootfs[0])))

/* Begin a proc; skip the test if the low region could not be mapped (never on normal CI). */
#define CONF_BEGIN(fx, p, rootfs, n)                                                                \
	lxp_conf_t *fx = lxp_conf_begin(&(p), (rootfs), (n));                                       \
	if (!fx) {                                                                                  \
		skip();                                                                            \
		return;                                                                            \
	}

#define SC(...) lxp_syscall(__VA_ARGS__)

/* =============================== compile-time number spot-check ======================== */

static void test_conf_numbers(void **state)
{
	(void)state;
	/* Belt-and-suspenders against scripts/syscalls/check-syscalls.sh: a few numbers the
	 * dispatcher relies on, pinned at compile time in this TU too. */
	assert_int_equal(LXP_NR_write, 4);
	assert_int_equal(LXP_NR_openat, 322);
	assert_int_equal(LXP_NR_statx, 397);
	assert_int_equal(LXP_NR_getdents64, 217);
	assert_int_equal(LXP_NR_futex, 240);
	assert_int_equal(LXP_NR_futex_time64, 422); /* the fix: was mis-typed 421 */
}

/* =============================== file I/O ============================================== */

static void test_conf_fileio(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	char *motd = lxp_conf_str(fx, "/etc/motd");
	uint8_t *buf = lxp_conf_alloc(fx, 64);

	/* openat + sequential read + short read + EOF. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)motd, LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 7, 0, 0, 0), 7);
	assert_memory_equal(buf, "Welcome", 7);
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 64, 0, 0, 0), 12); /* 19-7 */
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 64, 0, 0, 0), 0);  /* EOF */

	/* lseek SET/END/CUR. */
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_SET, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_END, 0, 0, 0), 19);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, -4, LXP_SEEK_CUR, 0, 0, 0), 15);

	/* pread64 reads at an absolute offset without disturbing the fd position (off in a4). */
	assert_int_equal(SC(&p, LXP_NR_pread64, fd, (long)(uintptr_t)buf, 2, 0, 8, 0), 2);
	assert_memory_equal(buf, "to", 2);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_CUR, 0, 0, 0), 15); /* unchanged */

	/* dup / dup2 / dup3 all yield a working alias. */
	long fd2 = SC(&p, LXP_NR_dup, fd, 0, 0, 0, 0, 0);
	assert_true(fd2 >= 3 && fd2 != fd);
	assert_int_equal(SC(&p, LXP_NR_dup2, fd, 20, 0, 0, 0, 0), 20);
	assert_int_equal(SC(&p, LXP_NR_dup3, fd, 21, LXP_O_CLOEXEC, 0, 0, 0), 21);
	assert_int_equal(SC(&p, LXP_NR_dup3, fd, fd, 0, 0, 0, 0), -LXP_EINVAL); /* old==new */

	/* fcntl F_DUPFD lands at or above the floor; F_GETFL is queryable. */
	long fd3 = SC(&p, LXP_NR_fcntl64, fd, LXP_F_DUPFD, 30, 0, 0, 0);
	assert_true(fd3 >= 30);
	assert_true(SC(&p, LXP_NR_fcntl, fd, LXP_F_GETFL, 0, 0, 0, 0) >= 0);

	assert_int_equal(SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 1, 0, 0, 0), -LXP_EBADF);

	/* error paths. */
	assert_int_equal(SC(&p, LXP_NR_write, 99, (long)(uintptr_t)motd, 1, 0, 0, 0), -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/nope"),
			    LXP_O_RDONLY, 0, 0, 0), -LXP_ENOENT);
	assert_int_equal(SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)motd, LXP_O_WRONLY, 0, 0, 0),
			 -LXP_EROFS);
	/* a read into an out-of-region buffer faults (bounded user_ok). */
	assert_int_equal(SC(&p, LXP_NR_open, (long)(uintptr_t)motd, LXP_O_RDONLY, 0, 0, 0, 0) >= 3 ? 0 : 1, 0);
}

static void test_conf_fileio_streams(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* write() to stdout is captured by value. */
	char *hi = lxp_conf_str(fx, "hello");
	assert_int_equal(SC(&p, LXP_NR_write, 1, (long)(uintptr_t)hi, 5, 0, 0, 0), 5);
	assert_int_equal((int)g_conf_cap_len, 5);
	assert_memory_equal(g_conf_cap, "hello", 5);

	/* writev() gathers the iovec (both bases in-region). */
	g_conf_cap_len = 0;
	lxp_iovec *iov = lxp_conf_alloc(fx, 2 * sizeof(lxp_iovec));
	iov[0].iov_base = lxp_conf_str(fx, "foo");
	iov[0].iov_len = 3;
	iov[1].iov_base = lxp_conf_str(fx, "bar!");
	iov[1].iov_len = 4;
	assert_int_equal(SC(&p, LXP_NR_writev, 1, (long)(uintptr_t)iov, 2, 0, 0, 0), 7);
	assert_memory_equal(g_conf_cap, "foobar!", 7);

	/* pipe2 allocates a read/write fd pair. The data path needs a parked reader in another
	 * proc (pipe_ends scans the global proc table), so the byte round-trip is a cooperative,
	 * multi-proc concern confirmed on-target by M2 — here we pin the fd allocation. */
	int *fds = lxp_conf_alloc(fx, 2 * sizeof(int));
	assert_int_equal(SC(&p, LXP_NR_pipe2, (long)(uintptr_t)fds, 0, 0, 0, 0, 0), 0);
	assert_true(fds[0] >= 3 && fds[1] >= 3 && fds[0] != fds[1]);
	assert_int_equal(SC(&p, LXP_NR_close, fds[0], 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_close, fds[1], 0, 0, 0, 0, 0), 0);

	/* a blocking poll reports the console readable straight away (the caller then read()s). */
	lxp_pollfd *pf = lxp_conf_alloc(fx, sizeof(lxp_pollfd));
	pf->fd = 0;
	pf->events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 1, -1, 0, 0, 0), 1);
	assert_int_equal(pf->revents, LXP_POLLIN);
}

/* =============================== memory: brk / mmap ==================================== */

static void test_conf_mem(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* brk(0) reports the break; a valid grow moves it; an over-reservation leaves it. */
	long base = SC(&p, LXP_NR_brk, 0, 0, 0, 0, 0, 0);
	assert_int_equal((uintptr_t)base, p.brk_base);
	assert_int_equal(SC(&p, LXP_NR_brk, base + 4096, 0, 0, 0, 0, 0), base + 4096);
	assert_int_equal(SC(&p, LXP_NR_brk, (long)(p.brk_max + 4096), 0, 0, 0, 0, 0), base + 4096);

	/* anonymous mmap: usable, zeroed, writable memory. */
	long m = SC(&p, LXP_NR_mmap2, 0, 4096, 0x3 /*PROT_RW*/, LXP_MAP_ANONYMOUS, -1, 0);
	assert_true(m > 0);
	uint8_t *mem = (uint8_t *)(uintptr_t)m;
	for (int i = 0; i < 4096; i++)
		assert_int_equal(mem[i], 0);
	mem[0] = 0xab;
	assert_int_equal(mem[0], 0xab);
	assert_int_equal(SC(&p, LXP_NR_munmap, m, 4096, 0, 0, 0, 0), 0);

	/* a file-backed mapping with a bad fd is -EBADF; an over-arena request is -ENOMEM. */
	assert_int_equal(SC(&p, LXP_NR_mmap2, 0, 4096, 0x3, 0 /*not ANON*/, 99, 0), -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_mmap2, 0, 8u * 1024 * 1024, 0x3, LXP_MAP_ANONYMOUS, -1, 0),
			 -LXP_ENOMEM);

	/* mprotect is a NOMMU no-op (accepted). */
	assert_int_equal(SC(&p, LXP_NR_mprotect, base, 4096, 0x1, 0, 0, 0), 0);

	/* On a genuine low-4GiB mapping, brk/mmap addresses fit a 32-bit r0 exactly. */
	if (lxp_conf_is_32bit(fx)) {
		assert_true((uintptr_t)base <= 0xffffffffu);
		long m2 = SC(&p, LXP_NR_mmap2, 0, 256, 0x3, LXP_MAP_ANONYMOUS, -1, 0);
		assert_true(m2 > 0 && (uintptr_t)m2 <= 0xffffffffu);
		assert_int_equal((uint32_t)m2, (uintptr_t)m2); /* round-trips through r0 */
	}
}

/* =============================== stat family ========================================== */

static void test_conf_stat(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	struct conf_kstat64 *st = lxp_conf_alloc(fx, sizeof(*st));
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
		     LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);

	/* fstat64 field VALUES (not just the size/offset the static asserts pin). */
	assert_int_equal(SC(&p, LXP_NR_fstat64, fd, (long)(uintptr_t)st, 0, 0, 0, 0), 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFREG);
	assert_int_equal((long)st->st_size, 19);
	assert_int_equal(st->st_nlink, 1);
	assert_int_equal(st->st_ino, 3); /* rootfs idx 2 -> ino 1+idx; unique & non-zero */
	assert_int_equal(st->st_blksize, 512);
	assert_int_equal((long)st->st_blocks, 1); /* (19 + 511) / 512 */
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* stat64 / lstat64 by path. */
	memset(st, 0, sizeof(*st));
	assert_int_equal(SC(&p, LXP_NR_stat64, (long)(uintptr_t)lxp_conf_str(fx, "/etc/hostname"),
			    (long)(uintptr_t)st, 0, 0, 0, 0), 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFREG);
	assert_int_equal((long)st->st_size, 8);

	/* lstat64 of a symlink reports the link itself (S_IFLNK); stat64 follows it. */
	memset(st, 0, sizeof(*st));
	assert_int_equal(SC(&p, LXP_NR_lstat64, (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"),
			    (long)(uintptr_t)st, 0, 0, 0, 0), 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFLNK);
	memset(st, 0, sizeof(*st));
	assert_int_equal(SC(&p, LXP_NR_stat64, (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"),
			    (long)(uintptr_t)st, 0, 0, 0, 0), 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFREG); /* followed to /etc/motd */
	assert_int_equal((long)st->st_size, 19);

	/* statx field values (uClibc-ng's real stat path). */
	struct conf_statx *sx = lxp_conf_alloc(fx, sizeof(*sx));
	assert_int_equal(SC(&p, LXP_NR_statx, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
			    0, 0, (long)(uintptr_t)sx, 0), 0);
	assert_int_equal(sx->stx_mode & LXP_S_IFMT, LXP_S_IFREG);
	assert_int_equal((long)sx->stx_size, 19);
	assert_int_equal((long)sx->stx_ino, 3);

	/* statfs64 reports a populated filesystem. */
	uint8_t *sf = lxp_conf_alloc(fx, 128);
	assert_int_equal(SC(&p, LXP_NR_statfs64, (long)(uintptr_t)lxp_conf_str(fx, "/"), 128,
			    (long)(uintptr_t)sf, 0, 0, 0), 0);

	/* a standard stream stats as a character device. */
	memset(st, 0, sizeof(*st));
	assert_int_equal(SC(&p, LXP_NR_fstat64, 1, (long)(uintptr_t)st, 0, 0, 0, 0), 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFCHR);
	assert_int_equal(st->st_blksize, 1024);

	/* error paths: missing path, and a statbuf pointer outside the region. */
	assert_int_equal(SC(&p, LXP_NR_stat64, (long)(uintptr_t)lxp_conf_str(fx, "/nope"),
			    (long)(uintptr_t)st, 0, 0, 0, 0), -LXP_ENOENT);
	assert_int_equal(SC(&p, LXP_NR_fstat64, 1, (long)(uintptr_t)lxp_conf_bad_ptr(fx), 0, 0, 0, 0),
			 -LXP_EFAULT);
}

/* =============================== directory entries ==================================== */

static void test_conf_dirent(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	uint8_t *dbuf = lxp_conf_alloc(fx, 512);

	/* getdents64 on /etc: the regular files show as DT_REG, the symlink as DT_LNK-or-REG. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc"),
		     LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	long n = SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0);
	assert_true(n > 0);
	assert_int_equal(lxp_conf_dirent_type(dbuf, n, "motd"), LXP_DT_REG);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0), 0); /* drained */
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)dbuf, 4, 0, 0, 0), -LXP_EISDIR);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents (32-bit variant) on / lists the subdirectories as DT_DIR. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/"), LXP_O_RDONLY, 0, 0, 0);
	n = SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0);
	assert_int_equal(lxp_conf_dirent_type(dbuf, n, "etc"), LXP_DT_DIR);
	assert_int_equal(lxp_conf_dirent_type(dbuf, n, "bin"), LXP_DT_DIR);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents64 on a regular file is -ENOTDIR. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
		LXP_O_RDONLY, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0), -LXP_ENOTDIR);
}

/* =============================== path metadata ======================================== */

static void test_conf_pathmeta(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	/* access: an existing file is reachable; a missing one is -ENOENT. */
	assert_int_equal(SC(&p, LXP_NR_access, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_access, (long)(uintptr_t)lxp_conf_str(fx, "/nope"), 0, 0, 0, 0, 0),
			 -LXP_ENOENT);
	assert_int_equal(SC(&p, LXP_NR_faccessat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/bin/sh"),
			    0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_faccessat2, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc"),
			    0, 0, 0, 0), 0);

	/* readlink returns the symlink target (not NUL-terminated; returns the length). */
	char *out = lxp_conf_alloc(fx, 64);
	long r = SC(&p, LXP_NR_readlink, (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"),
		    (long)(uintptr_t)out, 64, 0, 0, 0);
	assert_int_equal(r, 9);
	assert_memory_equal(out, "/etc/motd", 9);
	/* readlink of a non-symlink is -EINVAL. */
	assert_int_equal(SC(&p, LXP_NR_readlink, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
			    (long)(uintptr_t)out, 64, 0, 0, 0), -LXP_EINVAL);
}

/* =============================== writable-fs mutation ================================= */

static void test_conf_fsmutate(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	/* create + write + read-back in the writable overlay. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/a.txt"),
		     LXP_O_WRONLY | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_write, fd, (long)(uintptr_t)lxp_conf_str(fx, "hi"), 2, 0, 0, 0), 2);
	/* ftruncate64(fd, [pad a1], len_lo a2, len_hi a3): grow to 5 with zeros. */
	assert_int_equal(SC(&p, LXP_NR_ftruncate64, fd, 0, 5, 0, 0, 0), 0);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* mkdir then getdents shows the new directory. */
	assert_int_equal(SC(&p, LXP_NR_mkdir, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/d"), 0755, 0, 0, 0, 0), 0);

	/* rename within the overlay. */
	assert_int_equal(SC(&p, LXP_NR_rename, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/a.txt"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/b.txt"), 0, 0, 0, 0), 0);

	/* unlink the renamed file. */
	assert_int_equal(SC(&p, LXP_NR_unlink, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/b.txt"), 0, 0, 0, 0, 0), 0);

	/* symlink + chmod in the overlay are accepted. */
	assert_int_equal(SC(&p, LXP_NR_symlink, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/d"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/l"), 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_chmod, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/d"), 0700, 0, 0, 0, 0), 0);

	/* mutating the read-only rootfs is -EROFS. */
	assert_int_equal(SC(&p, LXP_NR_unlink, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), 0, 0, 0, 0, 0),
			 -LXP_EROFS);
}

/* =============================== time ================================================= */

static void test_conf_time(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* gettimeofday / clock_gettime write a sane (sec, sub) pair. */
	int32_t *tv = lxp_conf_alloc(fx, 2 * sizeof(int32_t));
	assert_int_equal(SC(&p, LXP_NR_gettimeofday, (long)(uintptr_t)tv, 0, 0, 0, 0, 0), 0);
	assert_true(tv[0] >= 0 && tv[1] >= 0 && tv[1] < 1000000);

	int32_t *ts = lxp_conf_alloc(fx, 2 * sizeof(int32_t));
	assert_int_equal(SC(&p, LXP_NR_clock_gettime, 1 /*MONOTONIC*/, (long)(uintptr_t)ts, 0, 0, 0, 0), 0);
	assert_true(ts[1] >= 0 && ts[1] < 1000000000);

	int64_t *ts64 = lxp_conf_alloc(fx, 2 * sizeof(int64_t));
	assert_int_equal(SC(&p, LXP_NR_clock_gettime64, 1, (long)(uintptr_t)ts64, 0, 0, 0, 0), 0);

	/* nanosleep records a wake deadline and asks the run loop to park (no blocking here). */
	int32_t *req = lxp_conf_alloc(fx, 2 * sizeof(int32_t));
	req[0] = 0;
	req[1] = 1000000; /* 1 ms */
	assert_int_equal(SC(&p, LXP_NR_nanosleep, (long)(uintptr_t)req, 0, 0, 0, 0, 0), 0);
	assert_int_equal(p.sleep_pending, 1);

	/* a timespec pointer outside the region is -EFAULT. */
	assert_int_equal(SC(&p, LXP_NR_clock_gettime, 1, (long)(uintptr_t)lxp_conf_bad_ptr(fx), 0, 0, 0, 0),
			 -LXP_EFAULT);
}

/* =============================== process identity ==================================== */

static void test_conf_identity(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	assert_int_equal(SC(&p, LXP_NR_getpid, 0, 0, 0, 0, 0, 0), 1);
	assert_int_equal(SC(&p, LXP_NR_getppid, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_gettid, 0, 0, 0, 0, 0, 0), 1);

	/* getcwd writes "/" + NUL and returns the length; a too-small buffer is -ERANGE. */
	char *cwd = lxp_conf_alloc(fx, 16);
	assert_int_equal(SC(&p, LXP_NR_getcwd, (long)(uintptr_t)cwd, 16, 0, 0, 0, 0), 2);
	assert_string_equal(cwd, "/");
	assert_int_equal(SC(&p, LXP_NR_getcwd, (long)(uintptr_t)cwd, 1, 0, 0, 0, 0), -LXP_ERANGE);

	/* chdir into a directory succeeds; into a file is -ENOTDIR; missing is -ENOENT. */
	assert_int_equal(SC(&p, LXP_NR_chdir, (long)(uintptr_t)lxp_conf_str(fx, "/etc"), 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_chdir, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), 0, 0, 0, 0, 0),
			 -LXP_ENOTDIR);
	assert_int_equal(SC(&p, LXP_NR_chdir, (long)(uintptr_t)lxp_conf_str(fx, "/nope"), 0, 0, 0, 0, 0),
			 -LXP_ENOENT);

	/* umask stores the new mask and returns the previous one. */
	int prev = (int)SC(&p, LXP_NR_umask, 0022, 0, 0, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_umask, 0077, 0, 0, 0, 0, 0), 0022);
	(void)prev;

	/* uname: the six impersonation fields at 65-byte strides. */
	char *u = lxp_conf_alloc(fx, 6 * 65);
	assert_int_equal(SC(&p, LXP_NR_uname, (long)(uintptr_t)u, 0, 0, 0, 0, 0), 0);
	assert_string_equal(u + 0 * 65, "Linux");
	assert_string_equal(u + 2 * 65, "6.1.0");
	assert_string_equal(u + 4 * 65, "armv7l");

	/* sysinfo: the fields uptime/free report. */
	struct conf_sysinfo *si = lxp_conf_alloc(fx, sizeof(*si));
	assert_int_equal(SC(&p, LXP_NR_sysinfo, (long)(uintptr_t)si, 0, 0, 0, 0, 0), 0);
	assert_int_equal(si->totalram, 4u * 1024 * 1024);
	assert_int_equal(si->freeram, 2u * 1024 * 1024);
	assert_int_equal(si->procs, 2);
	assert_int_equal(si->mem_unit, 1);

	/* times: non-negative ticks; the per-proc breakdown is zeroed. */
	long *tms = lxp_conf_alloc(fx, 4 * sizeof(long));
	assert_true(SC(&p, LXP_NR_times, (long)(uintptr_t)tms, 0, 0, 0, 0, 0) >= 0);
	assert_int_equal(tms[1], 0);
	assert_int_equal(tms[2], 0);
	assert_int_equal(tms[3], 0);

	/* prlimit64 reports a finite RLIMIT and accepts a new one. */
	uint64_t *lim = lxp_conf_alloc(fx, 2 * sizeof(uint64_t));
	assert_int_equal(SC(&p, LXP_NR_prlimit64, 0, 7 /*RLIMIT_NOFILE*/, 0, (long)(uintptr_t)lim, 0, 0), 0);
	assert_true(lim[0] > 0 && lim[0] != (uint64_t)-1);

	/* getrandom fills the buffer and returns the count. */
	uint8_t *rb = lxp_conf_alloc(fx, 16);
	assert_int_equal(SC(&p, LXP_NR_getrandom, (long)(uintptr_t)rb, 16, 0, 0, 0, 0), 16);

	/* execve captures a valid program; a missing one is -ENOENT. */
	char **av = lxp_conf_alloc(fx, 2 * sizeof(char *));
	av[0] = lxp_conf_str(fx, "sh");
	av[1] = NULL;
	assert_int_equal(SC(&p, LXP_NR_execve, (long)(uintptr_t)lxp_conf_str(fx, "/bin/sh"),
			    (long)(uintptr_t)av, 0, 0, 0, 0), 0);
	assert_int_equal(p.exec_pending, 1);
	assert_int_equal(SC(&p, LXP_NR_execve, (long)(uintptr_t)lxp_conf_str(fx, "/bin/nope"),
			    (long)(uintptr_t)av, 0, 0, 0, 0), -LXP_ENOENT);

	/* wait4 with no children is -ECHILD (the reaping path is confirmed on-target). */
	assert_int_equal(SC(&p, LXP_NR_wait4, -1, 0, 0, 0, 0, 0), -LXP_ECHILD);

	/* exit_group records the status. */
	assert_int_equal(SC(&p, LXP_NR_exit_group, 7, 0, 0, 0, 0, 0), 0);
	assert_int_equal(p.exited, 1);
	assert_int_equal(p.exit_status, 7);
}

/* =============================== signals (dispatch-reachable) ========================= */

static void test_conf_signal(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* rt_sigaction records a handler + restorer and reports the old ones back. */
	uint32_t *act = lxp_conf_alloc(fx, 3 * sizeof(uint32_t));
	act[0] = 0xdeadbeef; /* sa_handler */
	act[2] = 0xcafef00d; /* sa_restorer */
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGINT, (long)(uintptr_t)act, 0, 0, 0, 0), 0);
	assert_int_equal(p.sig_handler[LXP_SIGINT], 0xdeadbeef);
	assert_int_equal(p.sig_restorer, 0xcafef00d);
	uint32_t *oact = lxp_conf_alloc(fx, 3 * sizeof(uint32_t));
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGINT, 0, (long)(uintptr_t)oact, 0, 0, 0), 0);
	assert_int_equal(oact[0], 0xdeadbeef);
	/* an out-of-range signal is -EINVAL. */
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_NSIG, (long)(uintptr_t)act, 0, 0, 0, 0), -LXP_EINVAL);

	assert_int_equal(SC(&p, LXP_NR_rt_sigprocmask, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_set_robust_list, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_set_tid_address, 0, 0, 0, 0, 0, 0), 1);

	/* rt_sigsuspend parks (returns -EINTR) and flags itself when nothing is pending. */
	assert_int_equal(SC(&p, LXP_NR_rt_sigsuspend, 0, 0, 0, 0, 0, 0), -LXP_EINTR);
	assert_int_equal(p.sigsuspend_pending, 1);

	/* setitimer(ITIMER_REAL) arms the alarm deadline. */
	uint32_t *itv = lxp_conf_alloc(fx, 4 * sizeof(uint32_t));
	itv[2] = 1; /* it_value.sec = 1 */
	assert_int_equal(SC(&p, LXP_NR_setitimer, LXP_ITIMER_REAL, (long)(uintptr_t)itv, 0, 0, 0, 0), 0);
	assert_true(p.alarm_deadline_us != 0);
}

/* =============================== *at / 64-bit / legacy variants ====================== */

/* These share a handler with a sibling but shift WHICH register holds the path / length
 * (a dirfd prepends an argument; a 64-bit value is a register pair). A dispatch arg-index
 * bug would surface only here, so each variant gets its own call. */
static void test_conf_variants(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	struct conf_kstat64 *st = lxp_conf_alloc(fx, sizeof(*st));
	char *out = lxp_conf_alloc(fx, 64);

	/* fstatat64(dirfd, path@a1, buf@a2, flags); readlinkat(dirfd, path@a1, buf@a2, sz@a3). */
	assert_int_equal(SC(&p, LXP_NR_fstatat64, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
			    (long)(uintptr_t)st, 0, 0, 0), 0);
	assert_int_equal((long)st->st_size, 19);
	assert_int_equal(SC(&p, LXP_NR_readlinkat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"),
			    (long)(uintptr_t)out, 64, 0, 0), 9);
	assert_memory_equal(out, "/etc/motd", 9);

	/* _llseek(fd, off_hi, off_lo, result@a3, whence) writes the 64-bit offset through a3. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
		     LXP_O_RDONLY, 0, 0, 0);
	uint64_t *res = lxp_conf_alloc(fx, sizeof(uint64_t));
	assert_int_equal(SC(&p, LXP_NR__llseek, fd, 0, 5, (long)(uintptr_t)res, LXP_SEEK_SET, 0), 0);
	assert_int_equal((long)*res, 5);
	/* fstatfs64(fd@a0, sz, buf@a2). */
	uint8_t *sf = lxp_conf_alloc(fx, 128);
	assert_int_equal(SC(&p, LXP_NR_fstatfs64, fd, 128, (long)(uintptr_t)sf, 0, 0, 0), 0);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents (the 32-bit linux_dirent variant) lists a directory. */
	uint8_t *dbuf = lxp_conf_alloc(fx, 256);
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc"), LXP_O_RDONLY, 0, 0, 0);
	assert_true(SC(&p, LXP_NR_getdents, fd, (long)(uintptr_t)dbuf, 256, 0, 0, 0) > 0);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* pipe (legacy) + eventfd2 allocate fds. */
	int *fds = lxp_conf_alloc(fx, 2 * sizeof(int));
	assert_int_equal(SC(&p, LXP_NR_pipe, (long)(uintptr_t)fds, 0, 0, 0, 0, 0), 0);
	assert_true(fds[0] >= 3 && fds[1] >= 3 && fds[0] != fds[1]);
	assert_true(SC(&p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0) >= 3);

	/* ioctl TIOCGWINSZ on the console fills a winsize. */
	lxp_winsize *ws = lxp_conf_alloc(fx, sizeof(lxp_winsize));
	assert_int_equal(SC(&p, LXP_NR_ioctl, 1, LXP_TIOCGWINSZ, (long)(uintptr_t)ws, 0, 0, 0), 0);
	assert_int_equal(ws->ws_col, 80);

	/* ppoll_time64: timeout is a timespec* (NULL = block); the console reports readable. */
	lxp_pollfd *pf = lxp_conf_alloc(fx, sizeof(lxp_pollfd));
	pf->fd = 0;
	pf->events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_ppoll_time64, (long)(uintptr_t)pf, 1, 0 /*NULL*/, 0, 0, 0), 1);

	/* writable-overlay mutation variants (path/length shifted): pwrite64 + the *at forms. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/v.txt"),
		LXP_O_WRONLY | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_pwrite64, fd, (long)(uintptr_t)lxp_conf_str(fx, "abcd"), 4, 0, 0, 0), 4);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_mkdirat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"), 0755, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_symlinkat, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"), LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vl"), 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_fchmodat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"), 0700, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_renameat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/v.txt"),
			    LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/w.txt"), 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_renameat2, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/w.txt"),
			    LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/x.txt"), 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_unlinkat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/x.txt"), 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_rmdir, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"), 0, 0, 0, 0, 0), 0);

	/* clock_nanosleep / _time64 (clockid, flags, req@a2, rem): park like nanosleep. */
	int32_t *req = lxp_conf_alloc(fx, 2 * sizeof(int32_t));
	req[1] = 500000;
	assert_int_equal(SC(&p, LXP_NR_clock_nanosleep, 0, 0, (long)(uintptr_t)req, 0, 0, 0), 0);
	assert_int_equal(p.sleep_pending, 1);
	int64_t *req64 = lxp_conf_alloc(fx, 2 * sizeof(int64_t));
	req64[1] = 500000;
	assert_int_equal(SC(&p, LXP_NR_clock_nanosleep_time64, 0, 0, (long)(uintptr_t)req64, 0, 0, 0), 0);
}

/* =============================== deliberate behaviors ================================ */

static void test_conf_deliberate(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* futex: WAIT-family -> -EAGAIN, WAKE etc. -> 0 (both the number and the time64 alias). */
	assert_int_equal(SC(&p, LXP_NR_futex, 0, 0 /*FUTEX_WAIT*/, 0, 0, 0, 0), -LXP_EAGAIN);
	assert_int_equal(SC(&p, LXP_NR_futex, 0, 1 /*FUTEX_WAKE*/, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_futex_time64, 0, 0, 0, 0, 0, 0), -LXP_EAGAIN);

	/* mount/umount2/mprotect/utimensat: accepted no-ops. */
	assert_int_equal(SC(&p, LXP_NR_mount, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_umount2, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_utimensat, LXP_AT_FDCWD, 0, 0, 0, 0, 0), 0);

	/* privilege drop + identity: inert, all "root". */
	assert_int_equal(SC(&p, LXP_NR_setuid32, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_setresuid32, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_getuid32, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_geteuid32, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_getgid32, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_setpgid, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_sched_yield, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_prctl, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_sync, 0, 0, 0, 0, 0, 0), 0);

	/* getpgrp/setsid report the pid as the group/session leader. */
	assert_int_equal(SC(&p, LXP_NR_getpgrp, 0, 0, 0, 0, 0, 0), 1);
	assert_int_equal(SC(&p, LXP_NR_setsid, 0, 0, 0, 0, 0, 0), 1);

	/* getresuid32 writes all-root and returns 0. */
	uint32_t *ids = lxp_conf_alloc(fx, 3 * sizeof(uint32_t));
	ids[0] = ids[1] = ids[2] = 0xff;
	assert_int_equal(SC(&p, LXP_NR_getresuid32, (long)(uintptr_t)ids, (long)(uintptr_t)(ids + 1),
			    (long)(uintptr_t)(ids + 2), 0, 0, 0), 0);
	assert_int_equal(ids[0], 0);
	ids[0] = ids[1] = ids[2] = 0xff;
	assert_int_equal(SC(&p, LXP_NR_getresgid32, (long)(uintptr_t)ids, (long)(uintptr_t)(ids + 1),
			    (long)(uintptr_t)(ids + 2), 0, 0, 0), 0);
	assert_int_equal(ids[0], 0);

	/* the remaining inert privilege / sync / mode / times stubs all accept and return 0. */
	static const long inert0[] = {
		LXP_NR_setgid32,	LXP_NR_setreuid32, LXP_NR_setregid32,	LXP_NR_setresgid32,
		LXP_NR_setgroups32,	LXP_NR_fchown32,   LXP_NR_fchmod,	LXP_NR_fsync,
		LXP_NR_fdatasync,	LXP_NR_getegid32,  LXP_NR_umount2,	LXP_NR_utimensat_time64,
	};
	for (unsigned i = 0; i < sizeof(inert0) / sizeof(inert0[0]); i++)
		assert_int_equal(SC(&p, inert0[i], 0, 0, 0, 0, 0, 0), 0);

	/* The socket family (socket/bind/connect/.../getsockopt) + pselect6_time64 are NET-gated
	 * and covered by test_linux_net.c; the errno-translation boundary (lxp_err_t -> LXP_E*)
	 * is covered there and in test_linux_netfs.c. Not duplicated here. */

	/* scatter/gather sockets are explicitly refused. */
	assert_int_equal(SC(&p, LXP_NR_socketpair, 0, 0, 0, 0, 0, 0), -LXP_EOPNOTSUPP);
	assert_int_equal(SC(&p, LXP_NR_sendmsg, 0, 0, 0, 0, 0, 0), -LXP_EOPNOTSUPP);
	assert_int_equal(SC(&p, LXP_NR_recvmsg, 0, 0, 0, 0, 0, 0), -LXP_EOPNOTSUPP);

	/* reboot(CAD_OFF) is a no-op (does NOT latch the halt — that path is global). */
	assert_int_equal(SC(&p, LXP_NR_reboot, 0, 0, 0 /*CAD_OFF*/, 0, 0, 0), 0);
	assert_int_equal(p.exited, 0);

	/* an unassigned syscall number is -ENOSYS (the dispatcher floor). */
	assert_int_equal(SC(&p, 999, 0, 0, 0, 0, 0, 0), -LXP_ENOSYS);

	/* exit (a distinct NR from exit_group; same handler) records the status. Last, since
	 * it marks the proc exited. */
	assert_int_equal(SC(&p, LXP_NR_exit, 3, 0, 0, 0, 0, 0), 0);
	assert_int_equal(p.exit_status, 3);
}

/* =============================== socket-family dispatch =============================== */

#if LXP_ENABLE_NET
/* The socket family's CONNECTED paths (socket/bind/connect/listen/accept/send/recv/
 * get{sock,peer}name and the lxp_err_t->LXP_E* errno translation) live in test_linux_net.c,
 * which stands up a real peer. Here we touch the remaining entries network-free: on a
 * non-socket fd each rejects with -ENOTSOCK, and pselect6_time64 with a zero timeout returns
 * immediately. Together with test_linux_net.c this covers every NET-gated number. */
static void test_conf_net_dispatch(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* fd 1 is the console — not a socket. */
	assert_int_equal(SC(&p, LXP_NR_setsockopt, 1, 0, 0, 0, 0, 0), -LXP_ENOTSOCK);
	assert_int_equal(SC(&p, LXP_NR_getsockopt, 1, 0, 0, 0, 0, 0), -LXP_ENOTSOCK);
	assert_int_equal(SC(&p, LXP_NR_shutdown, 1, 0, 0, 0, 0, 0), -LXP_ENOTSOCK);
	assert_int_equal(SC(&p, LXP_NR_sendto, 1, 0, 0, 0, 0, 0), -LXP_ENOTSOCK);
	assert_int_equal(SC(&p, LXP_NR_recvfrom, 1, 0, 0, 0, 0, 0), -LXP_ENOTSOCK);
	assert_int_equal(SC(&p, LXP_NR_accept4, 1, 0, 0, 0, 0, 0), -LXP_ENOTSOCK);

	/* pselect6_time64(nfds, r, w, e, timeout@a4): an empty set with a zero timeout is 0. */
	int64_t *zts = lxp_conf_alloc(fx, 2 * sizeof(int64_t)); /* {0, 0} */
	assert_int_equal(SC(&p, LXP_NR_pselect6_time64, 0, 0, 0, 0, (long)(uintptr_t)zts, 0), 0);
}
#endif /* LXP_ENABLE_NET */

int test_syscall_conformance_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_conf_numbers),
		cmocka_unit_test(test_conf_fileio),
		cmocka_unit_test(test_conf_fileio_streams),
		cmocka_unit_test(test_conf_mem),
		cmocka_unit_test(test_conf_stat),
		cmocka_unit_test(test_conf_dirent),
		cmocka_unit_test(test_conf_pathmeta),
		cmocka_unit_test(test_conf_fsmutate),
		cmocka_unit_test(test_conf_time),
		cmocka_unit_test(test_conf_identity),
		cmocka_unit_test(test_conf_signal),
		cmocka_unit_test(test_conf_variants),
		cmocka_unit_test(test_conf_deliberate),
#if LXP_ENABLE_NET
		cmocka_unit_test(test_conf_net_dispatch),
#endif
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
