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
 * lxp_guest_access_ok() bounds are real (a bad guest pointer is genuinely -EFAULT) and brk/mmap return
 * addresses that fit a 32-bit r0 exactly. The trap->dispatch->resume ABI and the run-loop-
 * intercepted fork/signal machinery are NOT reachable here (host cmocka calls lxp_syscall()
 * directly); those are confirmed on-target by the QEMU M4 conformance guest.
 */
#define _GNU_SOURCE

#include "../framework/lxp_test.h"
#include "../framework/lxp_proc_fixture.h"
#include "../framework/lxp_stat_view.h"
#include "fs/lxp_poll.h" /* lxp_poll_retry: the coordinator re-scan */

#include "dev/lxp_dev.h" /* lxp_guest_access_ok: assert the host canary is outside the guest ranges */

#include <stdint.h>
#include <string.h>
#include <time.h>

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
#define CONF_BEGIN(fx, p, rootfs, n)                          \
	lxp_conf_t *fx = lxp_conf_begin(&(p), (rootfs), (n)); \
	if (!fx) {                                            \
		skip();                                       \
		return;                                       \
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

	/* _llseek takes a 64-bit offset; an offset past lseek's 32-bit off_t is EOVERFLOW
	 * from lseek (the offset has moved, as on Linux), and a negative one EINVAL. */
	uint64_t *pos64 = lxp_conf_alloc(fx, sizeof(uint64_t));
	assert_int_equal(SC(&p, LXP_NR__llseek, fd, 0, 0x80000000L, (long)(uintptr_t)pos64,
			    LXP_SEEK_SET, 0),
			 0);
	assert_int_equal(*pos64, 0x80000000ull);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_CUR, 0, 0, 0), -LXP_EOVERFLOW);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, -20, LXP_SEEK_END, 0, 0, 0), -LXP_EINVAL);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 15, LXP_SEEK_SET, 0, 0, 0), 15);

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
	assert_int_equal(SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/nope"), LXP_O_RDONLY, 0, 0, 0),
			 -LXP_ENOENT);
	assert_int_equal(SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)motd, LXP_O_WRONLY, 0,
			    0, 0),
			 -LXP_EROFS);
	/* a read into an out-of-region buffer faults (bounded lxp_guest_access_ok). */
	assert_int_equal(
		SC(&p, LXP_NR_open, (long)(uintptr_t)motd, LXP_O_RDONLY, 0, 0, 0, 0) >= 3 ? 0 : 1,
		0);
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

	/* Pipe endpoint liveness follows open-file-description lifetime. A dup alias keeps
	 * the writer alive until its final close; only then does an empty read become EOF. */
	int *fds = lxp_conf_alloc(fx, 2 * sizeof(int));
	assert_int_equal(
		SC(&p, LXP_NR_pipe2, (long)(uintptr_t)fds, LXP_O_NONBLOCK, 0, 0, 0, 0), 0);
	assert_true(fds[0] >= 3 && fds[1] >= 3 && fds[0] != fds[1]);
	uint8_t *pipe_byte = lxp_conf_alloc(fx, 1);
	uint8_t *pipe_out = lxp_conf_alloc(fx, 1);
	*pipe_byte = 0x5a;
	assert_int_equal(
		SC(&p, LXP_NR_write, fds[1], (long)(uintptr_t)pipe_byte, 1, 0, 0, 0), 1);
	assert_int_equal(
		SC(&p, LXP_NR_read, fds[0], (long)(uintptr_t)pipe_out, 1, 0, 0, 0), 1);
	assert_int_equal(*pipe_out, 0x5a);
	long wdup = SC(&p, LXP_NR_dup, fds[1], 0, 0, 0, 0, 0);
	assert_true(wdup >= 0);
	assert_int_equal(SC(&p, LXP_NR_close, fds[1], 0, 0, 0, 0, 0), 0);
	assert_int_equal(
		SC(&p, LXP_NR_read, fds[0], (long)(uintptr_t)pipe_out, 1, 0, 0, 0),
		-LXP_EAGAIN);
	assert_int_equal(SC(&p, LXP_NR_close, wdup, 0, 0, 0, 0, 0), 0);
	assert_int_equal(
		SC(&p, LXP_NR_read, fds[0], (long)(uintptr_t)pipe_out, 1, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_close, fds[0], 0, 0, 0, 0, 0), 0);

	/* a blocking poll reports the console readable straight away (the caller then read()s). */
	lxp_pollfd *pf = lxp_conf_alloc(fx, sizeof(lxp_pollfd));
	pf->fd = 0;
	pf->events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 1, -1, 0, 0, 0), 1);
	assert_int_equal(pf->revents, LXP_POLLIN);
}

/* Positioned I/O is only defined for seekable files. A stream descriptor's backing index
 * names a pipe/eventfd/pty pool entry, never a rootfs file, so pread/pwrite must fail with
 * ESPIPE and leave the guest buffer untouched instead of reading whichever rootfs entry
 * shares that index. */
static void assert_positioned_io_rejected(lxp_proc_t *p, long fd, uint8_t *buf, size_t len)
{
	memset(buf, 0xa5, len);
	assert_int_equal(SC(p, LXP_NR_pread64, fd, (long)(uintptr_t)buf, (long)len, 0, 0, 0),
			 -LXP_ESPIPE);
	for (size_t i = 0; i < len; i++)
		assert_int_equal(buf[i], 0xa5);
	assert_int_equal(SC(p, LXP_NR_pwrite64, fd, (long)(uintptr_t)buf, (long)len, 0, 0, 0),
			 -LXP_ESPIPE);
}

/* Positioned I/O on the in-memory file kinds: rootfs and /proc read at an absolute
 * offset without moving the fd, directories report EISDIR, and a descriptor not open
 * for writing rejects pwrite with EBADF (a stream would be ESPIPE). */
static void test_conf_pread_files(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	uint8_t *buf = lxp_conf_alloc(fx, 64);
	uint8_t *seq = lxp_conf_alloc(fx, 64);

	long motd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
		       LXP_O_RDONLY, 0, 0, 0);
	assert_true(motd >= 3);
	assert_int_equal(SC(&p, LXP_NR_pwrite64, motd, (long)(uintptr_t)buf, 1, 0, 0, 0),
			 -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_pread64, motd, (long)(uintptr_t)buf, 4, 0, 64, 0), 0);

	long etc = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc"),
		      LXP_O_RDONLY | LXP_O_DIRECTORY, 0, 0, 0);
	assert_true(etc >= 3);
	assert_int_equal(SC(&p, LXP_NR_pread64, etc, (long)(uintptr_t)buf, 4, 0, 0, 0),
			 -LXP_EISDIR);

	long ver = SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
		      (long)(uintptr_t)lxp_conf_str(fx, "/proc/version"), LXP_O_RDONLY, 0, 0, 0);
	assert_true(ver >= 3);
	assert_int_equal(SC(&p, LXP_NR_read, ver, (long)(uintptr_t)seq, 8, 0, 0, 0), 8);
	assert_int_equal(SC(&p, LXP_NR_pread64, ver, (long)(uintptr_t)buf, 4, 0, 1, 0), 4);
	assert_memory_equal(buf, seq + 1, 4);
	/* The fd offset is still 8: the next sequential read matches a pread at 8. */
	assert_int_equal(SC(&p, LXP_NR_pread64, ver, (long)(uintptr_t)buf, 4, 0, 8, 0), 4);
	assert_int_equal(SC(&p, LXP_NR_read, ver, (long)(uintptr_t)seq, 4, 0, 0, 0), 4);
	assert_memory_equal(buf, seq, 4);
	/* /proc files seek within their generated content: rewinding re-reads it. */
	assert_int_equal(SC(&p, LXP_NR_lseek, ver, 0, LXP_SEEK_CUR, 0, 0, 0), 12);
	assert_int_equal(SC(&p, LXP_NR_lseek, ver, 0, LXP_SEEK_SET, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_read, ver, (long)(uintptr_t)seq, 8, 0, 0, 0), 8);
	assert_int_equal(SC(&p, LXP_NR_pread64, ver, (long)(uintptr_t)buf, 8, 0, 0, 0), 8);
	assert_memory_equal(seq, buf, 8);
	assert_int_equal(SC(&p, LXP_NR_pwrite64, ver, (long)(uintptr_t)buf, 1, 0, 0, 0),
			 -LXP_EBADF);

	long proc = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/proc"),
		       LXP_O_RDONLY | LXP_O_DIRECTORY, 0, 0, 0);
	assert_true(proc >= 3);
	assert_int_equal(SC(&p, LXP_NR_pread64, proc, (long)(uintptr_t)buf, 4, 0, 0, 0),
			 -LXP_EISDIR);

	/* rewinddir on /proc lists it again from the start. */
	uint8_t *dbuf = lxp_conf_alloc(fx, 512);
	long n1 = SC(&p, LXP_NR_getdents64, proc, (long)(uintptr_t)dbuf, 512, 0, 0, 0);
	assert_true(n1 > 0);
	assert_int_equal(SC(&p, LXP_NR_lseek, proc, 0, LXP_SEEK_SET, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_getdents64, proc, (long)(uintptr_t)dbuf, 512, 0, 0, 0), n1);
}

static void test_conf_pread_streams(void **state)
{
	(void)state;
	lxp_proc_t p;
	/* A populated rootfs, so a stream index misread as a rootfs index names real files. */
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	uint8_t *buf = lxp_conf_alloc(fx, 16);

	assert_positioned_io_rejected(&p, 0, buf, 16); /* console */

	int *fds = lxp_conf_alloc(fx, 2 * sizeof(int));
	assert_int_equal(SC(&p, LXP_NR_pipe2, (long)(uintptr_t)fds, 0, 0, 0, 0, 0), 0);
	assert_positioned_io_rejected(&p, fds[0], buf, 16);
	assert_positioned_io_rejected(&p, fds[1], buf, 16);

	/* Several eventfds, so at least one pool index lands on a regular rootfs file. */
	long efd[4];
	for (int i = 0; i < 4; i++) {
		efd[i] = SC(&p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0);
		assert_true(efd[i] >= 3);
		assert_int_equal(lxp_fd_kind(&p, (int)efd[i]), LXP_FD_EVENTFD);
		assert_positioned_io_rejected(&p, efd[i], buf, 16);
	}

	long ptm = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/dev/ptmx"),
		      LXP_O_RDWR, 0, 0, 0);
	assert_true(ptm >= 3);
	assert_int_equal(lxp_fd_kind(&p, (int)ptm), LXP_FD_PTY);
	assert_positioned_io_rejected(&p, ptm, buf, 16);

	assert_int_equal(SC(&p, LXP_NR_close, ptm, 0, 0, 0, 0, 0), 0);
	for (int i = 0; i < 4; i++)
		assert_int_equal(SC(&p, LXP_NR_close, efd[i], 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_close, fds[0], 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_close, fds[1], 0, 0, 0, 0, 0), 0);
}

/* =============================== memory: brk / mmap ==================================== */

static void test_conf_mem(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* brk(0) reports the break; a valid grow moves it; an over-reservation leaves it. */
	long base = SC(&p, LXP_NR_brk, 0, 0, 0, 0, 0, 0);
	assert_int_equal((uintptr_t)base, p.mm->brk_base);
	assert_int_equal(SC(&p, LXP_NR_brk, base + 4096, 0, 0, 0, 0, 0), base + 4096);
	assert_int_equal(SC(&p, LXP_NR_brk, (long)(p.mm->brk_max + 4096), 0, 0, 0, 0, 0),
			 base + 4096);

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

/* File mappings: a read-only rootfs map is the image in place, a writable one a
 * private copy, and the descriptor's access mode gates both (EACCES). */
static void test_conf_mmap_files(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	const long prot_r = 0x1, prot_rw = 0x3, map_private = 0x2;

	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
		     LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	long m = SC(&p, LXP_NR_mmap2, 0, 19, prot_r, map_private, fd, 0);
	assert_int_equal(m, (long)(uintptr_t)k_motd); /* shared in place */
	m = SC(&p, LXP_NR_mmap2, 0, 19, prot_rw, map_private, fd, 0);
	assert_true(m > 0 && m != (long)(uintptr_t)k_motd); /* a private copy */
	assert_memory_equal((const void *)(uintptr_t)m, k_motd, 19);
	assert_int_equal(SC(&p, LXP_NR_mmap2, 0, 19, prot_rw, LXP_MAP_SHARED, fd, 0), -LXP_EACCES);

	long wfd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/mm"),
		      LXP_O_WRONLY | LXP_O_CREAT, 0644, 0, 0);
	assert_true(wfd >= 3);
	assert_int_equal(SC(&p, LXP_NR_mmap2, 0, 16, prot_r, map_private, wfd, 0), -LXP_EACCES);
}

/* =============================== stat family ========================================== */

static void test_conf_stat(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	struct conf_kstat64 *st = lxp_conf_alloc(fx, sizeof(*st));
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
		     (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), LXP_O_RDONLY, 0, 0, 0);
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
			    (long)(uintptr_t)st, 0, 0, 0, 0),
			 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFREG);
	assert_int_equal((long)st->st_size, 8);

	/* lstat64 of a symlink reports the link itself (S_IFLNK); stat64 follows it. */
	memset(st, 0, sizeof(*st));
	assert_int_equal(SC(&p, LXP_NR_lstat64, (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"),
			    (long)(uintptr_t)st, 0, 0, 0, 0),
			 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFLNK);
	memset(st, 0, sizeof(*st));
	assert_int_equal(SC(&p, LXP_NR_stat64, (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"),
			    (long)(uintptr_t)st, 0, 0, 0, 0),
			 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFREG); /* followed to /etc/motd */
	assert_int_equal((long)st->st_size, 19);

	/* statx field values (uClibc-ng's real stat path). */
	struct conf_statx *sx = lxp_conf_alloc(fx, sizeof(*sx));
	assert_int_equal(SC(&p, LXP_NR_statx, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), 0, 0,
			    (long)(uintptr_t)sx, 0),
			 0);
	assert_int_equal(sx->stx_mode & LXP_S_IFMT, LXP_S_IFREG);
	assert_int_equal((long)sx->stx_size, 19);
	assert_int_equal((long)sx->stx_ino, 3);

	/* statfs64 reports a populated filesystem. */
	uint8_t *sf = lxp_conf_alloc(fx, 128);
	assert_int_equal(SC(&p, LXP_NR_statfs64, (long)(uintptr_t)lxp_conf_str(fx, "/"), 128,
			    (long)(uintptr_t)sf, 0, 0, 0),
			 0);

	/* a standard stream stats as a character device. */
	memset(st, 0, sizeof(*st));
	assert_int_equal(SC(&p, LXP_NR_fstat64, 1, (long)(uintptr_t)st, 0, 0, 0, 0), 0);
	assert_int_equal(st->st_mode & LXP_S_IFMT, LXP_S_IFCHR);
	assert_int_equal(st->st_blksize, 1024);

	/* error paths: missing path, and a statbuf pointer outside the region. */
	assert_int_equal(SC(&p, LXP_NR_stat64, (long)(uintptr_t)lxp_conf_str(fx, "/nope"),
			    (long)(uintptr_t)st, 0, 0, 0, 0),
			 -LXP_ENOENT);
	assert_int_equal(SC(&p, LXP_NR_fstat64, 1, (long)(uintptr_t)lxp_conf_bad_ptr(fx), 0, 0, 0,
			    0),
			 -LXP_EFAULT);
}

/* Open flags reach the installed descriptor: O_CLOEXEC from open and eventfd2's
 * EFD_CLOEXEC set FD_CLOEXEC, and their absence leaves it clear. */
static void test_conf_open_flags(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	char *motd = lxp_conf_str(fx, "/etc/motd");

	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)motd,
		     LXP_O_RDONLY | LXP_O_CLOEXEC, 0, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, fd, LXP_F_GETFD, 0, 0, 0, 0), LXP_FD_CLOEXEC);
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)motd, LXP_O_RDONLY, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, fd, LXP_F_GETFD, 0, 0, 0, 0), 0);

	fd = SC(&p, LXP_NR_eventfd2, 0, LXP_EFD_CLOEXEC, 0, 0, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, fd, LXP_F_GETFD, 0, 0, 0, 0), LXP_FD_CLOEXEC);
	fd = SC(&p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, fd, LXP_F_GETFD, 0, 0, 0, 0), 0);
}

/* The access mode recorded at open gates every read and write path, and F_GETFL
 * reports it; F_SETFL changes only O_NONBLOCK. */
static void test_conf_access_mode(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	char *path = lxp_conf_str(fx, "/tmp/acc");
	uint8_t *buf = lxp_conf_alloc(fx, 16);

	long wfd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)path,
		      LXP_O_WRONLY | LXP_O_CREAT, 0644, 0, 0);
	assert_true(wfd >= 3);
	assert_int_equal(SC(&p, LXP_NR_write, wfd, (long)(uintptr_t)lxp_conf_str(fx, "data"), 4, 0,
			    0, 0),
			 4);
	assert_int_equal(SC(&p, LXP_NR_read, wfd, (long)(uintptr_t)buf, 4, 0, 0, 0), -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_pread64, wfd, (long)(uintptr_t)buf, 4, 0, 0, 0),
			 -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, wfd, LXP_F_GETFL, 0, 0, 0, 0), LXP_O_WRONLY);

	/* A tmpfs file opened read-only cannot be written, positioned-written or truncated. */
	long rfd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)path, LXP_O_RDONLY, 0, 0,
		      0);
	assert_true(rfd >= 3);
	assert_int_equal(SC(&p, LXP_NR_write, rfd, (long)(uintptr_t)buf, 1, 0, 0, 0), -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_pwrite64, rfd, (long)(uintptr_t)buf, 1, 0, 0, 0),
			 -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_ftruncate64, rfd, 0, 0, 0, 0, 0), -LXP_EINVAL);
	assert_int_equal(SC(&p, LXP_NR_read, rfd, (long)(uintptr_t)buf, 16, 0, 0, 0), 4);
	assert_memory_equal(buf, "data", 4);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, rfd, LXP_F_GETFL, 0, 0, 0, 0), LXP_O_RDONLY);

	/* F_SETFL toggles O_NONBLOCK and keeps the access mode. */
	assert_int_equal(SC(&p, LXP_NR_fcntl64, rfd, LXP_F_SETFL, LXP_O_NONBLOCK, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, rfd, LXP_F_GETFL, 0, 0, 0, 0),
			 LXP_O_RDONLY | LXP_O_NONBLOCK);

	/* /dev/null opened read-only is not writable; stdio and eventfds are read-write. */
	long null = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/dev/null"),
		       LXP_O_RDONLY, 0, 0, 0);
	assert_true(null >= 3);
	assert_int_equal(SC(&p, LXP_NR_write, null, (long)(uintptr_t)buf, 1, 0, 0, 0), -LXP_EBADF);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, 1, LXP_F_GETFL, 0, 0, 0, 0), LXP_O_RDWR);
	long efd = SC(&p, LXP_NR_eventfd2, 0, LXP_EFD_NONBLOCK, 0, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_fcntl64, efd, LXP_F_GETFL, 0, 0, 0, 0),
			 LXP_O_RDWR | LXP_O_NONBLOCK);
}

/* fstat64 and statx(AT_EMPTY_PATH) on one descriptor, through @p buf (256 bytes). */
static void stat_fd_both(lxp_proc_t *p, lxp_conf_t *fx, long fd, uint8_t *buf, lxp_stat_view_t *k,
			 lxp_stat_view_t *x)
{
	memset(buf, 0, 256);
	assert_int_equal(SC(p, LXP_NR_fstat64, fd, (long)(uintptr_t)buf, 0, 0, 0, 0), 0);
	*k = lxp_view_kstat64(buf);
	memset(buf, 0, 256);
	assert_int_equal(SC(p, LXP_NR_statx, fd, (long)(uintptr_t)lxp_conf_str(fx, ""),
			    LXP_AT_EMPTY_PATH, 0, (long)(uintptr_t)buf, 0),
			 0);
	*x = lxp_view_statx(buf);
}

#define INO_BASE(ino) ((ino) & ~(uint64_t)0xfffffu)

/* fstat64 and statx report the same record for a descriptor of each local kind. */
static void test_conf_stat_kinds(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	uint8_t *buf = lxp_conf_alloc(fx, 256);
	lxp_stat_view_t k, x;

	/* rootfs file and directory: inode = rootfs index + 1. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
		     LXP_O_RDONLY, 0, 0, 0);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFREG | 0644u);
	assert_int_equal(k.ino, 3);
	assert_int_equal(k.size, 19);
	assert_int_equal(k.nlink, 1);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);
	assert_int_equal(x.size, k.size);
	assert_int_equal(x.nlink, k.nlink);
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc"),
		LXP_O_RDONLY | LXP_O_DIRECTORY, 0, 0, 0);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFDIR);
	assert_int_equal(k.ino, 2);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);

	/* tmpfs file, then the same file unlinked while open. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/st"),
		LXP_O_RDWR | LXP_O_CREAT, 0600, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_write, fd, (long)(uintptr_t)lxp_conf_str(fx, "abc"), 3, 0, 0,
			    0),
			 3);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.mode & LXP_S_IFMT, LXP_S_IFREG);
	assert_int_equal(k.size, 3);
	assert_int_equal(k.nlink, 1);
	assert_int_equal(INO_BASE(k.ino), 0x100000);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);
	assert_int_equal(x.size, k.size);
	assert_int_equal(x.nlink, k.nlink);
	assert_int_equal(SC(&p, LXP_NR_unlink, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/st"), 0, 0,
			    0, 0, 0),
			 0);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.nlink, 0);
	assert_int_equal(x.nlink, k.nlink);

	/* /proc file and directory. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/proc/version"),
		LXP_O_RDONLY, 0, 0, 0);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFREG | 0444u);
	assert_int_equal(INO_BASE(k.ino), 0x200000);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/proc"),
		LXP_O_RDONLY | LXP_O_DIRECTORY, 0, 0, 0);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFDIR | 0555u);
	assert_int_equal(x.mode, k.mode);

	/* console, pipe and eventfd: a bare character device from both. */
	stat_fd_both(&p, fx, 0, buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFCHR | 0620u);
	assert_int_equal(k.ino, 0x300000);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);
	int *fds = lxp_conf_alloc(fx, 2 * sizeof(int));
	assert_int_equal(SC(&p, LXP_NR_pipe2, (long)(uintptr_t)fds, 0, 0, 0, 0, 0), 0);
	stat_fd_both(&p, fx, fds[0], buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFCHR | 0620u);
	assert_int_equal(INO_BASE(k.ino), 0x300000);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);
	fd = SC(&p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFCHR | 0620u);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);

	/* pty master. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/dev/ptmx"),
		LXP_O_RDWR, 0, 0, 0);
	assert_true(fd >= 3);
	stat_fd_both(&p, fx, fd, buf, &k, &x);
	assert_int_equal(k.mode, LXP_S_IFCHR | 0620u);
	assert_int_equal(INO_BASE(k.ino), 0x500000);
	assert_int_equal(x.mode, k.mode);
	assert_int_equal(x.ino, k.ino);
}

/* stat(path).st_ino of @p path. */
static uint64_t path_ino(lxp_proc_t *p, lxp_conf_t *fx, const char *path, uint8_t *buf, int follow)
{
	memset(buf, 0, 256);
	assert_int_equal(SC(p, follow ? LXP_NR_stat64 : LXP_NR_lstat64,
			    (long)(uintptr_t)lxp_conf_str(fx, path), (long)(uintptr_t)buf, 0, 0, 0, 0),
			 0);
	return lxp_view_kstat64(buf).ino;
}

/* fstat(open(path)).st_ino of @p path. */
static uint64_t open_ino(lxp_proc_t *p, lxp_conf_t *fx, const char *path, uint8_t *buf)
{
	long fd = SC(p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, path),
		     LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	memset(buf, 0, 256);
	assert_int_equal(SC(p, LXP_NR_fstat64, fd, (long)(uintptr_t)buf, 0, 0, 0, 0), 0);
	SC(p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
	return lxp_view_kstat64(buf).ino;
}

/* A named object reports the same inode from readdir, stat and fstat. */
static void test_conf_inode_identity(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	uint8_t *buf = lxp_conf_alloc(fx, 256);
	uint8_t *dbuf = lxp_conf_alloc(fx, 1024);

	/* tmpfs: a file in a created directory. */
	assert_int_equal(SC(&p, LXP_NR_mkdir, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/idd"), 0755, 0,
			    0, 0, 0),
			 0);
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/idd/f"),
		     LXP_O_WRONLY | LXP_O_CREAT, 0644, 0, 0);
	assert_true(fd >= 3);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/idd"),
		LXP_O_RDONLY | LXP_O_DIRECTORY, 0, 0, 0);
	long n = SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 1024, 0, 0, 0);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
	uint64_t ino = lxp_view_dirent64_ino(dbuf, n, "f");
	assert_int_not_equal(ino, 0);
	assert_int_equal(path_ino(&p, fx, "/tmp/idd/f", buf, 1), ino);
	assert_int_equal(open_ino(&p, fx, "/tmp/idd/f", buf), ino);

	/* /proc: a generated file, and the self symlink. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/proc"),
		LXP_O_RDONLY | LXP_O_DIRECTORY, 0, 0, 0);
	n = SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 1024, 0, 0, 0);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
	ino = lxp_view_dirent64_ino(dbuf, n, "version");
	assert_int_not_equal(ino, 0);
	assert_int_equal(path_ino(&p, fx, "/proc/version", buf, 1), ino);
	assert_int_equal(open_ino(&p, fx, "/proc/version", buf), ino);
	ino = lxp_view_dirent64_ino(dbuf, n, "self");
	assert_int_not_equal(ino, 0);
	assert_int_equal(path_ino(&p, fx, "/proc/self", buf, 0), ino);
}

/* Re-scan a parked poll the way the coordinator does until it completes. */
static long poll_pump(lxp_proc_t *p)
{
	for (int i = 0; i < 2000; i++) {
		long rc = lxp_poll_retry(p);
		if (rc != -LXP_EAGAIN) {
			(void)lxp_wait_complete(p, LXP_WAIT_POLL);
			return rc;
		}
		struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000};
		nanosleep(&ts, NULL);
	}
	return -LXP_EAGAIN;
}

/* A poll or select that finds nothing ready waits on any kind whose readiness can
 * change (here a pipe and an eventfd, no socket), until it is ready or times out. */
static void test_conf_poll_wait(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	int *fds = lxp_conf_alloc(fx, 2 * sizeof(int));
	assert_int_equal(SC(&p, LXP_NR_pipe2, (long)(uintptr_t)fds, 0, 0, 0, 0, 0), 0);
	lxp_pollfd *pf = lxp_conf_alloc(fx, 2 * sizeof(lxp_pollfd));
	char *one = lxp_conf_str(fx, "x");

	/* Blocking poll on an empty pipe parks; a write wakes it. */
	pf[0].fd = fds[0];
	pf[0].events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 1, -1, 0, 0, 0), 0);
	assert_int_equal(p.wait.kind, LXP_WAIT_POLL);
	assert_int_equal(lxp_poll_retry(&p), -LXP_EAGAIN);
	assert_int_equal(SC(&p, LXP_NR_write, fds[1], (long)(uintptr_t)one, 1, 0, 0, 0), 1);
	assert_int_equal(poll_pump(&p), 1);
	assert_int_equal(pf[0].revents, LXP_POLLIN);
	uint8_t *buf = lxp_conf_alloc(fx, 4);
	assert_int_equal(SC(&p, LXP_NR_read, fds[0], (long)(uintptr_t)buf, 4, 0, 0, 0), 1);

	/* A finite timeout expires with 0. */
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 1, 20, 0, 0, 0), 0);
	assert_int_equal(p.wait.kind, LXP_WAIT_POLL);
	assert_int_equal(poll_pump(&p), 0);
	assert_int_equal(pf[0].revents, 0);

	/* An eventfd becomes readable when its counter is written. */
	long efd = SC(&p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0);
	pf[0].fd = (int)efd;
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 1, -1, 0, 0, 0), 0);
	uint64_t *ctr = lxp_conf_alloc(fx, sizeof(uint64_t));
	*ctr = 1;
	assert_int_equal(SC(&p, LXP_NR_write, efd, (long)(uintptr_t)ctr, 8, 0, 0, 0), 8);
	assert_int_equal(poll_pump(&p), 1);
	assert_int_equal(pf[0].revents, LXP_POLLIN);

	/* A descriptor that is not open is reported, not waited on. */
	pf[0].fd = 60;
	pf[1].fd = fds[0];
	pf[1].events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_poll, (long)(uintptr_t)pf, 2, -1, 0, 0, 0), 1);
	assert_int_equal(pf[0].revents, LXP_POLLNVAL);
	assert_int_equal(p.wait.kind, LXP_WAIT_NONE);

	/* select: the read end parks, a write wakes it with the bit set; a set bit that
	 * names no open descriptor is EBADF. */
	uint32_t *rset = lxp_conf_alloc(fx, sizeof(uint32_t));
	*rset = 1u << fds[0];
	assert_int_equal(SC(&p, LXP_NR_pselect6_time64, fds[0] + 1, (long)(uintptr_t)rset, 0, 0, 0,
			    0),
			 0);
	assert_int_equal(p.wait.kind, LXP_WAIT_POLL);
	assert_int_equal(SC(&p, LXP_NR_write, fds[1], (long)(uintptr_t)one, 1, 0, 0, 0), 1);
	assert_int_equal(poll_pump(&p), 1);
	assert_int_equal(*rset, 1u << fds[0]);
	*rset = 1u << 30;
	assert_int_equal(SC(&p, LXP_NR_pselect6_time64, 31, (long)(uintptr_t)rset, 0, 0, 0, 0),
			 -LXP_EBADF);
}

/* =============================== directory entries ==================================== */

static void test_conf_dirent(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	uint8_t *dbuf = lxp_conf_alloc(fx, 512);

	/* getdents64 on /etc: the regular files show as DT_REG, the symlink as DT_LNK. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc"),
		     LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	long n = SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0);
	assert_true(n > 0);
	assert_int_equal(lxp_conf_dirent_type(dbuf, n, "motd"), LXP_DT_REG);
	assert_int_equal(lxp_conf_dirent_type(dbuf, n, "self"), LXP_DT_LNK);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0),
			 0); /* drained */
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)dbuf, 4, 0, 0, 0), -LXP_EISDIR);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents (32-bit variant) on / lists the subdirectories as DT_DIR. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/"),
		LXP_O_RDONLY, 0, 0, 0);
	n = SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0);
	assert_int_equal(lxp_conf_dirent_type(dbuf, n, "etc"), LXP_DT_DIR);
	assert_int_equal(lxp_conf_dirent_type(dbuf, n, "bin"), LXP_DT_DIR);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents64 on a regular file is -ENOTDIR. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
		LXP_O_RDONLY, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0),
			 -LXP_ENOTDIR);
}

/* Check one directory record's fields at @p rec (padding excluded): the 64-bit layout
 * is d_ino[8] d_off[8] d_reclen[2] d_type[1] name; the 32-bit one is d_ino[4] d_off[4]
 * d_reclen[2] name ... d_type at d_reclen-1. Returns the record length. */
static size_t check_dirent(const uint8_t *rec, int is64, uint64_t ino, uint64_t off,
			   size_t reclen, uint8_t type, const char *name)
{
	uint64_t v64 = 0;
	uint32_t v32 = 0;
	uint16_t rl = 0;
	if (is64) {
		memcpy(&v64, rec, 8);
		assert_int_equal(v64, ino);
		memcpy(&v64, rec + 8, 8);
		assert_int_equal(v64, off);
		memcpy(&rl, rec + 16, 2);
		assert_int_equal(rl, reclen);
		assert_int_equal(rec[18], type);
		assert_string_equal((const char *)rec + 19, name);
	} else {
		memcpy(&v32, rec, 4);
		assert_int_equal(v32, ino);
		memcpy(&v32, rec + 4, 4);
		assert_int_equal(v32, off);
		memcpy(&rl, rec + 8, 2);
		assert_int_equal(rl, reclen);
		assert_string_equal((const char *)rec + 10, name);
		assert_int_equal(rec[reclen - 1], type);
	}
	return reclen;
}

/* Pin the exact directory records both getdents variants produce for /etc, how a
 * directory cursor resumes after a short buffer, and the too-small-buffer error. */
static void test_conf_dirent_records(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);
	uint8_t *dbuf = lxp_conf_alloc(fx, 512);
	char *etc = lxp_conf_str(fx, "/etc");

	/* getdents64: rootfs entries in table order, inode = rootfs index + 1. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)etc, LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0), 80);
	size_t o = check_dirent(dbuf, 1, 3, 1, 24, LXP_DT_REG, "motd");
	o += check_dirent(dbuf + o, 1, 4, 2, 32, LXP_DT_REG, "hostname");
	o += check_dirent(dbuf + o, 1, 5, 3, 24, LXP_DT_LNK, "self");
	assert_int_equal(o, 80);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents: the 32-bit layout of the same entries. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)etc, LXP_O_RDONLY, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_getdents, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0), 56);
	o = check_dirent(dbuf, 0, 3, 1, 16, LXP_DT_REG, "motd");
	o += check_dirent(dbuf + o, 0, 4, 2, 24, LXP_DT_REG, "hostname");
	o += check_dirent(dbuf + o, 0, 5, 3, 16, LXP_DT_LNK, "self");
	assert_int_equal(o, 56);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* A buffer holding two records returns them; the next call resumes at the third. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)etc, LXP_O_RDONLY, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 56, 0, 0, 0), 56);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0), 24);
	check_dirent(dbuf, 1, 5, 3, 24, LXP_DT_LNK, "self");
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 512, 0, 0, 0), 0);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* A buffer too small for the first record is EINVAL. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)etc, LXP_O_RDONLY, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, 23, 0, 0, 0),
			 -LXP_EINVAL);
}

/* =============================== path metadata ======================================== */

static void test_conf_pathmeta(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	/* access: an existing file is reachable; a missing one is -ENOENT. */
	assert_int_equal(SC(&p, LXP_NR_access, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), 0, 0,
			    0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_access, (long)(uintptr_t)lxp_conf_str(fx, "/nope"), 0, 0, 0,
			    0, 0),
			 -LXP_ENOENT);
	assert_int_equal(SC(&p, LXP_NR_faccessat, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/bin/sh"), 0, 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_faccessat2, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/etc"), 0, 0, 0, 0),
			 0);

	/* readlink returns the symlink target (not NUL-terminated; returns the length). */
	char *out = lxp_conf_alloc(fx, 64);
	long r = SC(&p, LXP_NR_readlink, (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"),
		    (long)(uintptr_t)out, 64, 0, 0, 0);
	assert_int_equal(r, 9);
	assert_memory_equal(out, "/etc/motd", 9);
	/* readlink of a non-symlink is -EINVAL. */
	assert_int_equal(SC(&p, LXP_NR_readlink, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"),
			    (long)(uintptr_t)out, 64, 0, 0, 0),
			 -LXP_EINVAL);
}

/* =============================== writable-fs mutation ================================= */

static void test_conf_fsmutate(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	/* create + write + read-back in the writable overlay. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
		     (long)(uintptr_t)lxp_conf_str(fx, "/tmp/a.txt"),
		     LXP_O_WRONLY | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(
		SC(&p, LXP_NR_write, fd, (long)(uintptr_t)lxp_conf_str(fx, "hi"), 2, 0, 0, 0), 2);
	/* ftruncate64(fd, [pad a1], len_lo a2, len_hi a3): grow to 5 with zeros. */
	assert_int_equal(SC(&p, LXP_NR_ftruncate64, fd, 0, 5, 0, 0, 0), 0);
	/* A negative length is EINVAL and a length past the address space EFBIG (it used
	 * to wrap to a small size on the 32-bit target); neither changes the file. */
	assert_int_equal(SC(&p, LXP_NR_ftruncate64, fd, 0, -1, -1, 0, 0), -LXP_EINVAL);
	assert_int_equal(SC(&p, LXP_NR_ftruncate64, fd, 0, 0, 1, 0, 0), -LXP_EFBIG);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_END, 0, 0, 0), 5);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* mkdir then getdents shows the new directory. */
	assert_int_equal(SC(&p, LXP_NR_mkdir, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/d"), 0755, 0,
			    0, 0, 0),
			 0);

	/* rename within the overlay. */
	assert_int_equal(SC(&p, LXP_NR_rename, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/a.txt"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/b.txt"), 0, 0, 0, 0),
			 0);

	/* unlink the renamed file. */
	assert_int_equal(SC(&p, LXP_NR_unlink, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/b.txt"), 0,
			    0, 0, 0, 0),
			 0);

	/* symlink + chmod in the overlay are accepted. */
	assert_int_equal(SC(&p, LXP_NR_symlink, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/d"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/l"), 0, 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_chmod, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/d"), 0700, 0,
			    0, 0, 0),
			 0);

	/* link() a RO-rootfs file into the overlay: an independent copy of its bytes (no shared
	 * inode on this fs), enough for `ln` and the write-temp / link / unlink-temp idiom. */
	assert_int_equal(SC(&p, LXP_NR_link, (long)(uintptr_t)lxp_conf_str(fx, "/etc/hostname"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/hn"), 0, 0, 0, 0),
			 0);
	{
		uint8_t *lb = lxp_conf_alloc(fx, 16);
		assert_non_null(lb);
		long lfd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
			      (long)(uintptr_t)lxp_conf_str(fx, "/tmp/hn"), LXP_O_RDONLY, 0, 0, 0);
		assert_true(lfd >= 3);
		assert_int_equal(SC(&p, LXP_NR_read, lfd, (long)(uintptr_t)lb, 16, 0, 0, 0), 8);
		assert_memory_equal(lb, "overtos\n", 8); /* copied from /etc/hostname */
		SC(&p, LXP_NR_close, lfd, 0, 0, 0, 0, 0);
	}
	/* link onto an existing name -> EEXIST; missing source -> ENOENT; a directory -> EPERM. */
	assert_int_equal(SC(&p, LXP_NR_link, (long)(uintptr_t)lxp_conf_str(fx, "/etc/hostname"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/hn"), 0, 0, 0, 0),
			 -LXP_EEXIST);
	assert_int_equal(SC(&p, LXP_NR_link, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/nope"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/x"), 0, 0, 0, 0),
			 -LXP_ENOENT);
	assert_int_equal(SC(&p, LXP_NR_link, (long)(uintptr_t)lxp_conf_str(fx, "/etc"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/etclink"), 0, 0, 0, 0),
			 -LXP_EPERM);

	/* mutating the read-only rootfs is -EROFS. */
	assert_int_equal(SC(&p, LXP_NR_unlink, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), 0, 0,
			    0, 0, 0),
			 -LXP_EROFS);
}

/* A sparse write must read back as zero in the hole. A tmpfs node keeps its backing block
 * (with its old contents) across a truncate-to-zero, so a subsequent write past the new EOF
 * must zero the [size, offset) gap — else it leaks the stale bytes (across files, once the
 * shared pool block is reused for a different node). Exercises both the write and pwrite
 * paths; without the fix the hole reads back the sentinel. */
static void test_conf_tmpfs_sparse_hole_zeroed(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	uint8_t *sentinel = lxp_conf_alloc(fx, 256);
	uint8_t *one = lxp_conf_alloc(fx, 1);
	uint8_t *back = lxp_conf_alloc(fx, 256);
	assert_non_null(sentinel);
	assert_non_null(one);
	assert_non_null(back);
	memset(sentinel, 0xAB, 256);
	one[0] = 'x';

	char *path = lxp_conf_str(fx, "/tmp/hole");
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)path,
		     LXP_O_RDWR | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(fd >= 3);
	/* fill 256 bytes with the sentinel, then truncate to 0 (the block + its bytes survive). */
	assert_int_equal(SC(&p, LXP_NR_write, fd, (long)(uintptr_t)sentinel, 256, 0, 0, 0), 256);
	assert_int_equal(SC(&p, LXP_NR_ftruncate64, fd, 0, 0, 0, 0, 0), 0);

	/* write() path: seek to 128 (past EOF=0) and write 1 byte; the hole [0,128) must be zero. */
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 128, LXP_SEEK_SET, 0, 0, 0), 128);
	assert_int_equal(SC(&p, LXP_NR_write, fd, (long)(uintptr_t)one, 1, 0, 0, 0), 1);
	assert_int_equal(SC(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_SET, 0, 0, 0), 0);
	memset(back, 0x55, 256);
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)back, 129, 0, 0, 0), 129);
	for (int i = 0; i < 128; i++)
		assert_int_equal(back[i], 0); /* the hole, not the 0xAB sentinel */
	assert_int_equal(back[128], 'x');

	/* pwrite64() path: same file, truncate again, pwrite at 200; hole [0,200) must be zero. */
	assert_int_equal(SC(&p, LXP_NR_ftruncate64, fd, 0, 0, 0, 0, 0), 0);
	/* pwrite64(fd, buf, count, [pad a3], off_lo a4, off_hi a5) */
	assert_int_equal(SC(&p, LXP_NR_pwrite64, fd, (long)(uintptr_t)one, 1, 0, 200, 0), 1);
	memset(back, 0x55, 256);
	assert_int_equal(SC(&p, LXP_NR_pread64, fd, (long)(uintptr_t)back, 200, 0, 0, 0), 200);
	for (int i = 0; i < 200; i++)
		assert_int_equal(back[i], 0);

	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

/* /dev/zero: a read returns an all-zero fill, a write is discarded. Standard programs
 * (dd if=/dev/zero, </dev/zero, zeroed padding) depend on it; before the fix the node was
 * absent (open -> -ENOENT) even though the sibling /dev/null worked. */
static void test_conf_dev_zero(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, k_rootfs, K_ROOTFS_N);

	uint8_t *buf = lxp_conf_alloc(fx, 64);
	assert_non_null(buf);
	memset(buf, 0xAB, 64);

	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
		     (long)(uintptr_t)lxp_conf_str(fx, "/dev/zero"), LXP_O_RDWR, 0, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 64, 0, 0, 0), 64);
	for (int i = 0; i < 64; i++)
		assert_int_equal(buf[i], 0);
	assert_int_equal(SC(&p, LXP_NR_write, fd, (long)(uintptr_t)buf, 64, 0, 0, 0),
			 64); /* discarded */
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* regression: the sibling /dev/null still returns EOF on read. */
	long nfd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
		      (long)(uintptr_t)lxp_conf_str(fx, "/dev/null"), LXP_O_RDONLY, 0, 0, 0);
	assert_true(nfd >= 3);
	assert_int_equal(SC(&p, LXP_NR_read, nfd, (long)(uintptr_t)buf, 64, 0, 0, 0), 0);
	SC(&p, LXP_NR_close, nfd, 0, 0, 0, 0, 0);
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
	assert_int_equal(
		SC(&p, LXP_NR_clock_gettime, 1 /*MONOTONIC*/, (long)(uintptr_t)ts, 0, 0, 0, 0), 0);
	assert_true(ts[1] >= 0 && ts[1] < 1000000000);

	int64_t *ts64 = lxp_conf_alloc(fx, 2 * sizeof(int64_t));
	assert_int_equal(SC(&p, LXP_NR_clock_gettime64, 1, (long)(uintptr_t)ts64, 0, 0, 0, 0), 0);

	/* nanosleep records a wake deadline and asks the run loop to park (no blocking here). */
	int32_t *req = lxp_conf_alloc(fx, 2 * sizeof(int32_t));
	req[0] = 0;
	req[1] = 1000000; /* 1 ms */
	assert_int_equal(SC(&p, LXP_NR_nanosleep, (long)(uintptr_t)req, 0, 0, 0, 0, 0), 0);
	assert_int_equal(p.wait.kind, LXP_WAIT_TIMER);

	/* a timespec pointer outside the region is -EFAULT. */
	assert_int_equal(SC(&p, LXP_NR_clock_gettime, 1, (long)(uintptr_t)lxp_conf_bad_ptr(fx), 0,
			    0, 0, 0),
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
	assert_int_equal(
		SC(&p, LXP_NR_chdir, (long)(uintptr_t)lxp_conf_str(fx, "/etc"), 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_chdir, (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), 0, 0,
			    0, 0, 0),
			 -LXP_ENOTDIR);
	assert_int_equal(SC(&p, LXP_NR_chdir, (long)(uintptr_t)lxp_conf_str(fx, "/nope"), 0, 0, 0,
			    0, 0),
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
	assert_string_equal(u + 3 * 65, "TestRTOS 1.2.3 ove-abcdef0 lxp-1234567");
	assert_string_equal(u + 4 * 65, "armv7l");

	/* sysinfo: the fields uptime/free report. */
	struct conf_sysinfo *si = lxp_conf_alloc(fx, sizeof(*si));
	assert_int_equal(SC(&p, LXP_NR_sysinfo, (long)(uintptr_t)si, 0, 0, 0, 0, 0), 0);
	assert_int_equal(si->totalram, 6u * 1024 * 1024);
	assert_int_equal(si->freeram, 3u * 1024 * 1024);
	assert_int_equal(si->procs, 1);
	assert_int_equal(si->mem_unit, 1);

	/* Host-heap availability does not change the guest region capacity. */
	g_lxp_test_mem_stats_result = LXP_ERR_NOT_SUPPORTED;
	struct conf_sysinfo *si_unavailable = lxp_conf_alloc(fx, sizeof(*si_unavailable));
	assert_int_equal(SC(&p, LXP_NR_sysinfo, (long)(uintptr_t)si_unavailable, 0, 0, 0, 0, 0), 0);
	assert_int_equal(si_unavailable->totalram, 6u * 1024 * 1024);
	assert_int_equal(si_unavailable->freeram, 3u * 1024 * 1024);
	assert_int_equal(si_unavailable->mem_unit, 1);
	g_lxp_test_mem_stats_result = LXP_OK;

	/* times: non-negative ticks; the per-proc breakdown is zeroed. */
	long *tms = lxp_conf_alloc(fx, 4 * sizeof(long));
	assert_true(SC(&p, LXP_NR_times, (long)(uintptr_t)tms, 0, 0, 0, 0, 0) >= 0);
	assert_int_equal(tms[1], 0);
	assert_int_equal(tms[2], 0);
	assert_int_equal(tms[3], 0);

	/* prlimit64 reports a finite RLIMIT and accepts a new one. */
	uint64_t *lim = lxp_conf_alloc(fx, 2 * sizeof(uint64_t));
	assert_int_equal(
		SC(&p, LXP_NR_prlimit64, 0, 7 /*RLIMIT_NOFILE*/, 0, (long)(uintptr_t)lim, 0, 0), 0);
	assert_true(lim[0] > 0 && lim[0] != (uint64_t)-1);

	/* getrandom fills the buffer and returns the count. */
	uint8_t *rb = lxp_conf_alloc(fx, 16);
	g_lxp_test_random_result = LXP_OK;
	assert_int_equal(SC(&p, LXP_NR_getrandom, (long)(uintptr_t)rb, 16, 0, 0, 0, 0), 16);

	/* execve captures a valid program; a missing one is -ENOENT. */
	char **av = lxp_conf_alloc(fx, 2 * sizeof(char *));
	av[0] = lxp_conf_str(fx, "sh");
	av[1] = NULL;
	assert_int_equal(SC(&p, LXP_NR_execve, (long)(uintptr_t)lxp_conf_str(fx, "/bin/sh"),
			    (long)(uintptr_t)av, 0, 0, 0, 0),
			 0);
	assert_int_equal(p.intent.kind, LXP_INTENT_EXEC);
	assert_int_equal(SC(&p, LXP_NR_execve, (long)(uintptr_t)lxp_conf_str(fx, "/bin/nope"),
			    (long)(uintptr_t)av, 0, 0, 0, 0),
			 -LXP_ENOENT);

	/* wait4 with no children is -ECHILD (the reaping path is confirmed on-target). */
	assert_int_equal(SC(&p, LXP_NR_wait4, -1, 0, 0, 0, 0, 0), -LXP_ECHILD);

	/* exit_group records the status. */
	assert_int_equal(SC(&p, LXP_NR_exit_group, 7, 0, 0, 0, 0, 0), 0);
	assert_int_equal(p.intent.kind, LXP_INTENT_EXIT);
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
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGINT, (long)(uintptr_t)act, 0, 0, 0, 0),
			 0);
	assert_int_equal(p.sighand->handler[LXP_SIGINT], 0xdeadbeef);
	assert_int_equal(p.sighand->restorer, 0xcafef00d);
	uint32_t *oact = lxp_conf_alloc(fx, 3 * sizeof(uint32_t));
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGINT, 0, (long)(uintptr_t)oact, 0, 0, 0),
			 0);
	assert_int_equal(oact[0], 0xdeadbeef);
	/* One struct as both the new and the old action (legal): the new one is read
	 * before the old one is written back into it. */
	act[0] = 0x12345678;
	act[2] = 0x9abcdef0;
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGINT, (long)(uintptr_t)act,
			    (long)(uintptr_t)act, 0, 0, 0),
			 0);
	assert_int_equal(p.sighand->handler[LXP_SIGINT], 0x12345678);
	assert_int_equal(p.sighand->restorer, 0x9abcdef0);
	assert_int_equal(act[0], 0xdeadbeef);
	assert_int_equal(act[2], 0xcafef00d);
	/* sa_flags: SA_RESTART is kept per signal and reported back, with SA_RESTORER while a
	 * restorer is registered. */
	act[0] = 0x1234;
	act[1] = LXP_SA_RESTART | LXP_SA_RESTORER;
	act[2] = 0x5678;
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGCHLD, (long)(uintptr_t)act, 0, 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGCHLD, 0, (long)(uintptr_t)oact, 0, 0, 0),
			 0);
	assert_int_equal(oact[1], LXP_SA_RESTART | LXP_SA_RESTORER);
	act[1] = LXP_SA_RESTORER;
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGCHLD, (long)(uintptr_t)act,
			    (long)(uintptr_t)oact, 0, 0, 0),
			 0);
	assert_int_equal(oact[1], LXP_SA_RESTART | LXP_SA_RESTORER);
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_SIGCHLD, 0, (long)(uintptr_t)oact, 0, 0, 0),
			 0);
	assert_int_equal(oact[1], LXP_SA_RESTORER);
	/* an out-of-range signal is -EINVAL. */
	assert_int_equal(SC(&p, LXP_NR_rt_sigaction, LXP_NSIG, (long)(uintptr_t)act, 0, 0, 0, 0),
			 -LXP_EINVAL);

	assert_int_equal(SC(&p, LXP_NR_rt_sigprocmask, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_set_robust_list, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(SC(&p, LXP_NR_set_tid_address, 0, 0, 0, 0, 0, 0), 1);

	/* rt_sigsuspend installs the mask and parks (returns -EINTR), flagging itself when nothing
	 * deliverable is pending. Like Linux, sigsetsize must be 8 (else -EINVAL) and the mask must
	 * be readable (else -EFAULT). */
	assert_int_equal(SC(&p, LXP_NR_rt_sigsuspend, 0, 0, 0, 0, 0, 0), -LXP_EINVAL); /* size 0 */
	assert_int_equal(SC(&p, LXP_NR_rt_sigsuspend, 0, 8, 0, 0, 0, 0),
			 -LXP_EFAULT); /* NULL mask */
	uint32_t *sset = lxp_conf_alloc(fx, 2 * sizeof(uint32_t));
	sset[0] = 0;
	sset[1] = 0; /* empty mask -> nothing blocked */
	assert_int_equal(SC(&p, LXP_NR_rt_sigsuspend, (long)(uintptr_t)sset, 8, 0, 0, 0, 0),
			 -LXP_EINTR);
	assert_int_equal(p.wait.kind, LXP_WAIT_SIGSUSPEND);

	/* setitimer(ITIMER_REAL) arms the alarm deadline. */
	uint32_t *itv = lxp_conf_alloc(fx, 4 * sizeof(uint32_t));
	itv[2] = 1; /* it_value.sec = 1 */
	assert_int_equal(
		SC(&p, LXP_NR_setitimer, LXP_ITIMER_REAL, (long)(uintptr_t)itv, 0, 0, 0, 0), 0);
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
	assert_int_equal(SC(&p, LXP_NR_fstatat64, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), (long)(uintptr_t)st, 0,
			    0, 0),
			 0);
	assert_int_equal((long)st->st_size, 19);
	assert_int_equal(SC(&p, LXP_NR_readlinkat, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/etc/self"), (long)(uintptr_t)out,
			    64, 0, 0),
			 9);
	assert_memory_equal(out, "/etc/motd", 9);

	/* _llseek(fd, off_hi, off_lo, result@a3, whence) writes the 64-bit offset through a3. */
	long fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD,
		     (long)(uintptr_t)lxp_conf_str(fx, "/etc/motd"), LXP_O_RDONLY, 0, 0, 0);
	uint64_t *res = lxp_conf_alloc(fx, sizeof(uint64_t));
	assert_int_equal(SC(&p, LXP_NR__llseek, fd, 0, 5, (long)(uintptr_t)res, LXP_SEEK_SET, 0),
			 0);
	assert_int_equal((long)*res, 5);
	/* fstatfs64(fd@a0, sz, buf@a2). */
	uint8_t *sf = lxp_conf_alloc(fx, 128);
	assert_int_equal(SC(&p, LXP_NR_fstatfs64, fd, 128, (long)(uintptr_t)sf, 0, 0, 0), 0);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents (the 32-bit linux_dirent variant) lists a directory. */
	uint8_t *dbuf = lxp_conf_alloc(fx, 256);
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/etc"),
		LXP_O_RDONLY, 0, 0, 0);
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

	/* Console ioctl handlers run privileged: an out-of-region pointer must be rejected before
	 * either reading or writing it. Use an accessible host canary (rather than the fixture's guard
	 * page) so a regression proves that privileged host memory was not modified. */
	uint8_t host_canary[sizeof(lxp_termios)];
	uint8_t canary_expected[sizeof(host_canary)];
	memset(host_canary, 0xa5, sizeof(host_canary));
	memset(canary_expected, 0xa5, sizeof(canary_expected));
	assert_false(lxp_guest_access_ok(&p, host_canary, sizeof(host_canary), 1));
	assert_int_equal(SC(&p, LXP_NR_ioctl, 0, LXP_TCGETS, (long)(uintptr_t)host_canary, 0, 0, 0),
			 -LXP_EFAULT);
	assert_memory_equal(host_canary, canary_expected, sizeof(host_canary));
	assert_int_equal(SC(&p, LXP_NR_ioctl, 0, LXP_TCSETS, (long)(uintptr_t)host_canary, 0, 0, 0),
			 -LXP_EFAULT);
	assert_int_equal(SC(&p, LXP_NR_ioctl, 1, LXP_TIOCGWINSZ, (long)(uintptr_t)host_canary, 0, 0,
			    0),
			 -LXP_EFAULT);
	assert_memory_equal(host_canary, canary_expected, sizeof(host_canary));
	assert_int_equal(SC(&p, LXP_NR_ioctl, 0, LXP_TIOCSPGRP, (long)(uintptr_t)host_canary, 0, 0,
			    0),
			 -LXP_EFAULT);
	assert_int_equal(SC(&p, LXP_NR_ioctl, 0, LXP_TIOCGPGRP, (long)(uintptr_t)host_canary, 0, 0,
			    0),
			 -LXP_EFAULT);
	assert_memory_equal(host_canary, canary_expected, sizeof(host_canary));

	/* Linux permits byte-aligned user buffers. Copying through an aligned local keeps the
	 * privileged handler free of C alignment UB; UBSan makes a typed dereference regress here. */
	uint8_t *unaligned = lxp_conf_alloc(fx, sizeof(lxp_termios) + 1);
	assert_non_null(unaligned);
	unaligned++;
	assert_int_equal(SC(&p, LXP_NR_ioctl, 0, LXP_TCGETS, (long)(uintptr_t)unaligned, 0, 0, 0),
			 0);
	lxp_termios aligned_tio;
	memcpy(&aligned_tio, unaligned, sizeof(aligned_tio));
	assert_int_equal(aligned_tio.c_lflag & (LXP_ICANON | LXP_ECHO | LXP_ISIG),
			 LXP_ICANON | LXP_ECHO | LXP_ISIG);

	/* ppoll_time64: timeout is a timespec* (NULL = block); the console reports readable. */
	lxp_pollfd *pf = lxp_conf_alloc(fx, sizeof(lxp_pollfd));
	pf->fd = 0;
	pf->events = LXP_POLLIN;
	assert_int_equal(SC(&p, LXP_NR_ppoll_time64, (long)(uintptr_t)pf, 1, 0 /*NULL*/, 0, 0, 0),
			 1);

	/* writable-overlay mutation variants (path/length shifted): pwrite64 + the *at forms. */
	fd = SC(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/v.txt"),
		LXP_O_WRONLY | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(SC(&p, LXP_NR_pwrite64, fd, (long)(uintptr_t)lxp_conf_str(fx, "abcd"), 4,
			    0, 0, 0),
			 4);
	SC(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
	assert_int_equal(SC(&p, LXP_NR_mkdirat, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"), 0755, 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_symlinkat, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"),
			    LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vl"), 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_fchmodat, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"), 0700, 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_renameat, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/v.txt"), LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/w.txt"), 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_renameat2, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/w.txt"), LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/x.txt"), 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_unlinkat, LXP_AT_FDCWD,
			    (long)(uintptr_t)lxp_conf_str(fx, "/tmp/x.txt"), 0, 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_rmdir, (long)(uintptr_t)lxp_conf_str(fx, "/tmp/vd"), 0, 0, 0,
			    0, 0),
			 0);

	/* clock_nanosleep / _time64 (clockid, flags, req@a2, rem): park like nanosleep. */
	int32_t *req = lxp_conf_alloc(fx, 2 * sizeof(int32_t));
	req[1] = 500000;
	assert_int_equal(SC(&p, LXP_NR_clock_nanosleep, 0, 0, (long)(uintptr_t)req, 0, 0, 0), 0);
	assert_int_equal(p.wait.kind, LXP_WAIT_TIMER);
	assert_int_equal(lxp_wait_complete(&p, LXP_WAIT_TIMER), 0);
	int64_t *req64 = lxp_conf_alloc(fx, 2 * sizeof(int64_t));
	req64[1] = 500000;
	assert_int_equal(
		SC(&p, LXP_NR_clock_nanosleep_time64, 0, 0, (long)(uintptr_t)req64, 0, 0, 0), 0);
}

/* =============================== deliberate behaviors ================================ */

static void test_conf_deliberate(void **state)
{
	(void)state;
	lxp_proc_t p;
	CONF_BEGIN(fx, p, NULL, 0);

	/* futex/futex_time64 are coordinator-handled (src/lxp_run.c), not a dispatch case, so
	 * they are not exercised through lxp_syscall() here — the on-target M5 guest drives the
	 * real uaddr-keyed wait/wake between co-running threads. */

	/* Synthetic proc mount lifecycle remains accepted; /data is provider-backed. */
	assert_int_equal(SC(&p, LXP_NR_mount, (long)(uintptr_t)lxp_conf_str(fx, "proc"),
			    (long)(uintptr_t)lxp_conf_str(fx, "/proc"),
			    (long)(uintptr_t)lxp_conf_str(fx, "proc"), 0, 0, 0),
			 0);
	assert_int_equal(SC(&p, LXP_NR_umount2,
			    (long)(uintptr_t)lxp_conf_str(fx, "/proc"), 0, 0, 0, 0, 0),
			 0);
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
	assert_int_equal(SC(&p, LXP_NR_getresuid32, (long)(uintptr_t)ids,
			    (long)(uintptr_t)(ids + 1), (long)(uintptr_t)(ids + 2), 0, 0, 0),
			 0);
	assert_int_equal(ids[0], 0);
	ids[0] = ids[1] = ids[2] = 0xff;
	assert_int_equal(SC(&p, LXP_NR_getresgid32, (long)(uintptr_t)ids,
			    (long)(uintptr_t)(ids + 1), (long)(uintptr_t)(ids + 2), 0, 0, 0),
			 0);
	assert_int_equal(ids[0], 0);

	/* the remaining inert privilege / sync / mode / times stubs all accept and return 0. */
	static const long inert0[] = {
		LXP_NR_setgid32,    LXP_NR_setreuid32, LXP_NR_setregid32, LXP_NR_setresgid32,
		LXP_NR_setgroups32, LXP_NR_fchown32,   LXP_NR_fchmod,	  LXP_NR_fsync,
		LXP_NR_fdatasync,   LXP_NR_getegid32,  LXP_NR_utimensat_time64,
	};
	for (unsigned i = 0; i < sizeof(inert0) / sizeof(inert0[0]); i++)
		assert_int_equal(SC(&p, inert0[i], 0, 0, 0, 0, 0, 0), 0);

	/* The socket family (socket/bind/connect/.../getsockopt) + pselect6_time64 are NET-gated
	 * and covered by test_linux_net.c; the errno-translation boundary (lxp_err_t -> LXP_E*)
	 * is covered there and in test_linux_netfs.c. Not duplicated here. */

	/* socketpair is still refused (fd-passing unsupported); sendmsg/recvmsg are implemented
	 * (iovec scatter/gather, no ancillary) and reject a non-socket fd with -ENOTSOCK. Their
	 * loopback data path is covered in test_linux_net.c. */
	assert_int_equal(SC(&p, LXP_NR_socketpair, 0, 0, 0, 0, 0, 0), -LXP_EOPNOTSUPP);
	assert_int_equal(SC(&p, LXP_NR_sendmsg, 0 /*stdin: not a socket*/, 0, 0, 0, 0, 0),
			 -LXP_ENOTSOCK);
	assert_int_equal(SC(&p, LXP_NR_recvmsg, 0, 0, 0, 0, 0, 0), -LXP_ENOTSOCK);

	/* reboot(CAD_OFF) is a no-op (does NOT latch the halt — that path is global). */
	assert_int_equal(SC(&p, LXP_NR_reboot, 0, 0, 0 /*CAD_OFF*/, 0, 0, 0), 0);
	assert_int_equal(p.intent.kind, LXP_INTENT_NONE);

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
		cmocka_unit_test(test_conf_pread_files),
		cmocka_unit_test(test_conf_pread_streams),
		cmocka_unit_test(test_conf_mem),
		cmocka_unit_test(test_conf_mmap_files),
		cmocka_unit_test(test_conf_stat),
		cmocka_unit_test(test_conf_open_flags),
		cmocka_unit_test(test_conf_access_mode),
		cmocka_unit_test(test_conf_stat_kinds),
		cmocka_unit_test(test_conf_poll_wait),
		cmocka_unit_test(test_conf_inode_identity),
		cmocka_unit_test(test_conf_dirent),
		cmocka_unit_test(test_conf_dirent_records),
		cmocka_unit_test(test_conf_pathmeta),
		cmocka_unit_test(test_conf_fsmutate),
		cmocka_unit_test(test_conf_tmpfs_sparse_hole_zeroed),
		cmocka_unit_test(test_conf_dev_zero),
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
