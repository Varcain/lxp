/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Stage-2 memory-safety regression tests. Each asserts the defensive bound/guard a
 * fix added, so a revert fails here. On the 64-bit host the 32-bit size_t WRAP the
 * fixes ultimately target cannot itself occur, but the guards are observable, and
 * under the ASan/UBSan CI build a reverted bound scans OOB past the small test
 * buffers and aborts. (The pure 32-bit wraps in pwrite/arena/tmpfs, and the kill
 * signal-range check that lives in the excluded coordinator, are covered by the
 * cross-compiled gate matrix + on-target QEMU instead.)
 */
#include "../framework/lxp_test.h"
#include "lxp/lxp_arena.h"
#include "lxp/lxp_stats.h"
#include "lxp/lxp_syscall.h"

#include <stdint.h>
#include <string.h>

extern size_t g_lxp_test_random_clean_calls_on_entry;
extern size_t g_lxp_test_cache_clean_calls;
extern const void *g_lxp_test_cache_clean_base;
extern size_t g_lxp_test_cache_clean_len;
extern size_t g_lxp_test_cache_invalidate_calls;
extern const void *g_lxp_test_cache_invalidate_base;
extern size_t g_lxp_test_cache_invalidate_len;

static uint8_t g_pool[8192] __attribute__((aligned(16)));
static size_t g_write_calls;
static size_t g_write_len[4];

static long bounded_sink(void *ctx, int fd, const void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	(void)buf;
	if (g_write_calls < sizeof(g_write_len) / sizeof(g_write_len[0]))
		g_write_len[g_write_calls] = len;
	g_write_calls++;
	return (long)len;
}

static void setup_proc(lxp_proc_t *p, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_pool, sizeof(g_pool)), LXP_OK);
	assert_int_equal(lxp_test_proc_init(p, arena, 4096), LXP_OK);
	p->region_lo = 1;
	p->region_hi = UINTPTR_MAX; /* all-permitting; a test narrows it when needed */
	p->pool_lo = p->pool_hi = 0;
}

/* 2a: poll caps nfds at LXP_MAX_FDS before the nfds*sizeof(pollfd) that can wrap a
 * 32-bit size_t. A larger nfds over the small pf[] would scan OOB (ASan) pre-fix. */
static void test_poll_nfds_bound(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	lxp_pollfd pf[4];
	memset(pf, 0, sizeof(pf));
	long r = lxp_syscall(&p, LXP_NR_poll, (long)(uintptr_t)pf, LXP_MAX_FDS + 1, 0, 0, 0, 0);
	assert_int_equal(r, -LXP_EINVAL);
}

/* writev caps iovcnt before the iovcnt*sizeof(iovec) multiply. */
static void test_writev_iovcnt_bound(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	lxp_iovec iov[2];
	memset(iov, 0, sizeof(iov));
	long r = lxp_syscall(&p, LXP_NR_writev, 1, (long)(uintptr_t)iov, 2000, 0, 0, 0);
	assert_int_equal(r, -LXP_EINVAL);
}

/* Guest-controlled byte counts return a legal short result at the configured
 * quantum, including a vector that crosses the budget between segments. */
static void test_syscall_payload_quantum(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	p.write_fn = bounded_sink;
	static uint8_t payload[LXP_SYSCALL_QUANTUM_BYTES + 1u];
	g_write_calls = 0;
	memset(g_write_len, 0, sizeof(g_write_len));
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, 1, (long)(uintptr_t)payload,
				     sizeof(payload), 0, 0, 0),
			 LXP_SYSCALL_QUANTUM_BYTES);
	assert_int_equal(g_write_calls, 1);
	assert_int_equal(g_write_len[0], LXP_SYSCALL_QUANTUM_BYTES);

	const size_t first = LXP_SYSCALL_QUANTUM_BYTES > 1u
				     ? LXP_SYSCALL_QUANTUM_BYTES / 2u
				     : 1u;
	lxp_iovec iov[2] = {
		{.iov_base = payload, .iov_len = first},
		{.iov_base = payload, .iov_len = LXP_SYSCALL_QUANTUM_BYTES},
	};
	g_write_calls = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_writev, 1, (long)(uintptr_t)iov, 2, 0, 0, 0),
			 LXP_SYSCALL_QUANTUM_BYTES);
	assert_int_equal(g_write_calls, LXP_SYSCALL_QUANTUM_BYTES > 1u ? 2 : 1);
	assert_int_equal(g_write_len[0], first);
	if (LXP_SYSCALL_QUANTUM_BYTES > 1u)
		assert_int_equal(g_write_len[1], LXP_SYSCALL_QUANTUM_BYTES - first);

	/* A potentially blocking fd stops at one segment: its retry state can hold
	 * only one buffer, so returning a short write preserves the remaining iovec. */
	p.fds[1].kind = LXP_FD_SOCKET; /* retain the test console ops, change park capability */
	g_write_calls = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_writev, 1, (long)(uintptr_t)iov, 2, 0, 0, 0),
			 first);
	assert_int_equal(g_write_calls, 1);
	p.fds[1].kind = LXP_FD_CONSOLE;

	payload[LXP_SYSCALL_QUANTUM_BYTES] = 0xa5;
	g_lxp_test_random_result = LXP_OK;
	g_lxp_test_random_calls = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, (long)(uintptr_t)payload,
				     sizeof(payload), 0, 0, 0, 0),
			 LXP_SYSCALL_QUANTUM_BYTES);
	assert_int_equal(g_lxp_test_random_calls, 1);
	assert_int_equal(g_lxp_test_random_len, LXP_SYSCALL_QUANTUM_BYTES);
	assert_int_equal(payload[LXP_SYSCALL_QUANTUM_BYTES], 0xa5); /* byte beyond quantum untouched */
}

/* Entropy is host-supplied and fails closed. getrandom reports a missing
 * provider as ENOSYS, while an already-open random device reports EIO. Linux
 * flag validation happens before the provider is called. */
static void test_entropy_provider_contract(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	uint8_t out[32];

	g_lxp_test_random_result = LXP_OK;
	g_lxp_test_random_calls = 0;
	g_lxp_test_cache_clean_calls = 0;
	g_lxp_test_cache_invalidate_calls = 0;
	memset(out, 0, sizeof(out));
	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, (long)(uintptr_t)out,
				     sizeof(out), LXP_GRND_NONBLOCK, 0, 0, 0),
			 sizeof(out));
	assert_int_equal(g_lxp_test_random_calls, 1);
	assert_int_equal(g_lxp_test_random_len, sizeof(out));
	assert_int_equal(g_lxp_test_random_clean_calls_on_entry, 1);
	assert_int_equal(g_lxp_test_cache_clean_calls, 1);
	assert_ptr_equal(g_lxp_test_cache_clean_base, out);
	assert_int_equal(g_lxp_test_cache_clean_len, sizeof(out));
	assert_int_equal(g_lxp_test_cache_invalidate_calls, 1);
	assert_ptr_equal(g_lxp_test_cache_invalidate_base, out);
	assert_int_equal(g_lxp_test_cache_invalidate_len, sizeof(out));
	for (size_t i = 0; i < sizeof(out); i++)
		assert_int_equal(out[i], (uint8_t)(0xa5u ^ (uint8_t)i));

	/* A zero-byte request succeeds without dereferencing NULL or consulting the source. */
	g_lxp_test_random_calls = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(g_lxp_test_random_calls, 0);

	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, (long)(uintptr_t)out, 1,
				     0x80000000u, 0, 0, 0),
			 -LXP_EINVAL);
	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, (long)(uintptr_t)out, 1,
				     LXP_GRND_RANDOM | LXP_GRND_INSECURE, 0, 0, 0),
			 -LXP_EINVAL);
	assert_int_equal(g_lxp_test_random_calls, 0);

	g_lxp_test_random_result = LXP_ERR_NOT_SUPPORTED;
	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, (long)(uintptr_t)out, 1, 0, 0, 0,
				     0),
			 -LXP_ENOSYS);
	long fd = lxp_syscall(&p, LXP_NR_open, (long)(uintptr_t)"/dev/urandom",
			      LXP_O_RDONLY, 0, 0, 0, 0);
	assert_true(fd >= 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)out, 1, 0, 0, 0),
			 -LXP_EIO);

	g_lxp_test_random_result = LXP_ERR_WOULD_BLOCK;
	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, (long)(uintptr_t)out, 1, 0, 0, 0,
				     0),
			 -LXP_EAGAIN);
	g_lxp_test_random_result = LXP_ERR_TIMEOUT;
	assert_int_equal(lxp_syscall(&p, LXP_NR_getrandom, (long)(uintptr_t)out, 1, 0, 0, 0,
				     0),
			 -LXP_EIO);
	g_lxp_test_random_result = LXP_OK;
}

/* In-memory file copies have a larger but still finite quantum. The separate
 * bound lets the FDPIC loader complete its 22 KiB pread without expanding the
 * external console/socket callback budget. */
static void test_file_payload_quantum(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	static uint8_t file_data[LXP_SYSCALL_FILE_QUANTUM_BYTES + 1u];
	static uint8_t dst[LXP_SYSCALL_FILE_QUANTUM_BYTES + 1u];
	const lxp_file_t fs[] = {{"/big", file_data, sizeof(file_data), 0}};
	lxp_proc_set_rootfs(&p, fs, 1);
	long fd = lxp_syscall(&p, LXP_NR_open, (long)(uintptr_t)"/big", LXP_O_RDONLY, 0, 0, 0,
			      0);
	assert_true(fd >= 0);
	dst[LXP_SYSCALL_FILE_QUANTUM_BYTES] = 0xa5;
	assert_int_equal(lxp_syscall(&p, LXP_NR_pread64, fd, (long)(uintptr_t)dst, sizeof(dst), 0,
				     0, 0),
			 LXP_SYSCALL_FILE_QUANTUM_BYTES);
	assert_int_equal(dst[LXP_SYSCALL_FILE_QUANTUM_BYTES], 0xa5);
}

/* execve rejects vectors and strings larger than the storage the eventual
 * relaunch can preserve; it no longer scans 256 entries and silently truncates. */
static void test_exec_vector_bounds(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	char *too_many[LXP_EXEC_MAXARGS + 2];
	for (int i = 0; i < LXP_EXEC_MAXARGS + 1; i++)
		too_many[i] = (char *)"x";
	too_many[LXP_EXEC_MAXARGS + 1] = NULL;
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/x",
				     (long)(uintptr_t)too_many, 0, 0, 0, 0),
			 -LXP_E2BIG);

	static char too_long[LXP_EXEC_ARGBUF + 1];
	memset(too_long, 'x', sizeof(too_long));
	too_long[sizeof(too_long) - 1] = '\0';
	char *long_argv[] = {too_long, NULL};
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/x",
				     (long)(uintptr_t)long_argv, 0, 0, 0, 0),
			 -LXP_E2BIG);
}

/* The boundary itself, from the accepting side. The vectors are snapshotted
 * before the path is resolved, so a vector the capture accepts still fails on
 * the missing program: ENOENT means "the vector fit", E2BIG would mean the limit
 * is off by one. The capture's argc is not asserted — sys_execve only commits it
 * once the program resolves — so the capture is read through the offsets it wrote. */
static void test_exec_vector_at_limit(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);

	char *exact[LXP_EXEC_MAXARGS + 1];
	for (int i = 0; i < LXP_EXEC_MAXARGS; i++)
		exact[i] = (char *)"x";
	exact[LXP_EXEC_MAXARGS] = NULL;
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/x",
				     (long)(uintptr_t)exact, 0, 0, 0, 0),
			 -LXP_ENOENT);
	/* Every entry up to the limit was captured, the last one included. */
	for (int i = 0; i < LXP_EXEC_MAXARGS; i++) {
		assert_int_not_equal(p.exec_capture->argv[i], LXP_EXEC_OFF_NONE);
		assert_string_equal(p.exec_capture->argv_buf + p.exec_capture->argv[i], "x");
	}

	/* And the payload boundary: a string that exactly fills the buffer with its
	 * NUL is the largest that can round-trip, so it must not be rejected. */
	static char exact_buf[LXP_EXEC_ARGBUF];
	memset(exact_buf, 'y', sizeof(exact_buf));
	exact_buf[sizeof(exact_buf) - 1] = '\0';
	char *full_argv[] = {exact_buf, NULL};
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/x",
				     (long)(uintptr_t)full_argv, 0, 0, 0, 0),
			 -LXP_ENOENT);
	assert_int_equal(p.exec_capture->argv[0], 0);
	assert_string_equal(p.exec_capture->argv_buf + p.exec_capture->argv[0], exact_buf);
}

/* A slot outlives the image that captured into it. A shorter vector must not
 * leave the previous one's entries readable as valid offsets, or a later reader
 * trusting a stale count resurrects a dead image's arguments. */
static void test_exec_vector_no_stale_offsets(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);

	char *many[] = {(char *)"aaa", (char *)"bbb", (char *)"ccc", (char *)"ddd", NULL};
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/x",
				     (long)(uintptr_t)many, 0, 0, 0, 0),
			 -LXP_ENOENT);
	assert_string_equal(p.exec_capture->argv_buf + p.exec_capture->argv[3], "ddd");

	char *few[] = {(char *)"z", NULL};
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/x",
				     (long)(uintptr_t)few, 0, 0, 0, 0),
			 -LXP_ENOENT);
	assert_string_equal(p.exec_capture->argv_buf + p.exec_capture->argv[0], "z");
	for (int i = 1; i < LXP_EXEC_MAXARGS; i++)
		assert_int_equal(p.exec_capture->argv[i], LXP_EXEC_OFF_NONE);
}

/* 2g: dup(2)/dup2 clear FD_CLOEXEC on the new fd (Linux ABI). */
static void test_dup_clears_cloexec(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	p.fds[0].cloexec = 1; /* mark stdin close-on-exec */
	long nf = lxp_syscall(&p, LXP_NR_dup, 0, 0, 0, 0, 0, 0);
	assert_true(nf >= 3);
	assert_int_equal(p.fds[nf].cloexec, 0);
}

/* 2g: dup3(fd, fd, ...) is EINVAL (unlike dup2, which no-ops). */
static void test_dup3_same_fd_einval(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	long r = lxp_syscall(&p, LXP_NR_dup3, 0, 0, 0, 0, 0, 0);
	assert_int_equal(r, -LXP_EINVAL);
}

/* 2e: symlink(2) validates the target pointer (it is stored verbatim, then strlen'd).
 * With the region narrowed to cover only linkp, the far target is out of range and is
 * rejected -EFAULT; pre-fix the unchecked target was strlen'd from arbitrary memory. */
static char g_far_target[] = "loop/back/target";
static void test_symlink_target_fault(void **st)
{
	(void)st;
	lxp_arena_t a;
	lxp_proc_t p;
	setup_proc(&p, &a);
	static char lbuf[64];
	strcpy(lbuf, "/tmp/lnk");
	p.region_lo = (uintptr_t)lbuf; /* in range: linkp; out of range: the far target */
	p.region_hi = (uintptr_t)(lbuf + sizeof(lbuf));
	long r = lxp_syscall(&p, LXP_NR_symlink, (long)(uintptr_t)g_far_target,
			     (long)(uintptr_t)lbuf, 0, 0, 0, 0);
	assert_int_equal(r, -LXP_EFAULT);
}

/* Repeated short-lived commands must not exhaust the fixed /proc snapshot.
 * Every refresh leaves the preceding PID stale and the next add must reuse it. */
static void test_stats_snapshot_reuses_stale_entries(void **st)
{
	(void)st;
	lxp_stats_reset();

	for (int pid = 1; pid <= LXP_MAX_PENT + 8; pid++) {
		lxp_stats_begin();
		lxp_stats_add(pid, 0, "short", 'R', (uint64_t)pid * 1000u, 0);
		assert_int_equal(lxp_pent_count(), 1);
		assert_non_null(lxp_pent_find(pid));
	}
}

/* The cumulative CPU table is independently bounded. Reclaim records for PIDs
 * absent from the last completed snapshot while retaining a still-live PID. */
static void test_stats_prunes_exited_cpu_records(void **st)
{
	(void)st;
	lxp_stats_reset();

	for (int pid = 1; pid <= LXP_MAX_PENT; pid++) {
		assert_int_equal(lxp_stats_charge(pid, 1000u), 0);
		assert_int_equal(lxp_stats_charge(pid, 2000u), 1000);
	}

	lxp_stats_begin();
	lxp_stats_add(LXP_MAX_PENT, 0, "live", 'R',
		      lxp_proc_cpu_us(LXP_MAX_PENT), 0);
	lxp_stats_prune();

	const int replacement = LXP_MAX_PENT + 100;
	assert_int_equal(lxp_stats_charge(replacement, 5000u), 0);
	assert_int_equal(lxp_stats_charge(replacement, 7000u), 2000);
	assert_int_equal(lxp_proc_cpu_us(LXP_MAX_PENT), 1000);
}

int test_overflow_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_poll_nfds_bound),
		cmocka_unit_test(test_writev_iovcnt_bound),
		cmocka_unit_test(test_syscall_payload_quantum),
		cmocka_unit_test(test_entropy_provider_contract),
		cmocka_unit_test(test_file_payload_quantum),
		cmocka_unit_test(test_exec_vector_bounds),
		cmocka_unit_test(test_exec_vector_at_limit),
		cmocka_unit_test(test_exec_vector_no_stale_offsets),
		cmocka_unit_test(test_dup_clears_cloexec),
		cmocka_unit_test(test_dup3_same_fd_einval),
		cmocka_unit_test(test_symlink_target_fault),
		cmocka_unit_test(test_stats_snapshot_reuses_stale_entries),
		cmocka_unit_test(test_stats_prunes_exited_cpu_records),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
