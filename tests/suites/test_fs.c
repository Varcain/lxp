/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fresh unit suite for the subsystems extracted out of the syscall dispatcher and the
 * pure syscall-boundary helpers — none of which had dedicated tests before:
 *   - path resolution   (src/fs/lxp_path.c):  resolve_path normalization + rootfs
 *                                              symlink follow (lxp_rootfs_resolve).
 *   - writable VFS       (src/fs/lxp_tmpfs.c): wfs_create/find/reserve + wnode_at.
 *   - pipe ring          (src/fs/lxp_pipe.c):  alloc + the no-reader/no-writer guards.
 *   - synthetic /proc    (src/proc/lxp_procfs.c): proc_is / p_dec / proc_gen.
 *   - pointer validators (src/lxp_syscall.c):  user_ok / user_strnlen / file_mode.
 * The syscall suite drives these through lxp_syscall(); here they are exercised directly.
 */
#include "../framework/lxp_test.h"
#include "lxp/lxp_arena.h"
#include "lxp/lxp_syscall.h"

#include "fs/lxp_path.h"
#include "fs/lxp_pipe.h"
#include "fs/lxp_tmpfs.h"
#include "lxp_internal.h"
#include "proc/lxp_procfs.h"

#include <stdint.h>
#include <string.h>

static uint8_t g_pool[8192] __attribute__((aligned(16)));

/* Minimal host proc: an all-permitting access_ok range (NULL still rejected via
 * region_lo=1), so user-pointer checks pass on ordinary host buffers. Mirrors the
 * setup the syscall suite uses. */
static void setup_proc(lxp_proc_t *p, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_pool, sizeof(g_pool)), LXP_OK);
	assert_int_equal(lxp_proc_init(p, arena, 4096), LXP_OK);
	p->region_lo = 1;
	p->region_hi = UINTPTR_MAX;
	p->pool_lo = p->pool_hi = 0;
}

/* ---- path: normalization of "." / ".." / duplicate slashes + cwd join --------- */
static void test_path_normalize(void **s)
{
	(void)s;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	strcpy(p.cwd, "/foo");
	char out[LXP_PATH_MAX];

	assert_int_equal(resolve_path(&p, "/a/./b", out, sizeof(out)), 0);
	assert_string_equal(out, "/a/b");
	assert_int_equal(resolve_path(&p, "/a/b/../c", out, sizeof(out)), 0);
	assert_string_equal(out, "/a/c");
	assert_int_equal(resolve_path(&p, "//a//b/", out, sizeof(out)), 0);
	assert_string_equal(out, "/a/b");
	/* relative → joined onto (absolute, normalized) cwd */
	assert_int_equal(resolve_path(&p, "rel/x", out, sizeof(out)), 0);
	assert_string_equal(out, "/foo/rel/x");
	/* ".." can never escape the root */
	assert_int_equal(resolve_path(&p, "/../../a", out, sizeof(out)), 0);
	assert_string_equal(out, "/a");
	assert_int_equal(resolve_path(&p, "/a/../..", out, sizeof(out)), 0);
	assert_string_equal(out, "/");
	/* an input longer than LXP_PATH_MAX has no NUL in range → rejected, not overrun */
	char big[LXP_PATH_MAX + 64];
	memset(big, 'x', sizeof(big) - 1);
	big[0] = '/';
	big[sizeof(big) - 1] = '\0';
	assert_true(resolve_path(&p, big, out, sizeof(out)) < 0);
}

/* ---- path: rootfs lookup follows symlinks to the final target ----------------- */
static void test_path_rootfs_resolve(void **s)
{
	(void)s;
	static const uint8_t body[] = "hi";
	static const char tgt[] = "/real"; /* symlink payload = target path bytes */
	const lxp_file_t fs[] = {
		{"/real", body, sizeof(body) - 1, 0},
		{"/link", (const uint8_t *)tgt, sizeof(tgt) - 1, LXP_S_IFLNK},
	};
	const uint8_t *d = NULL;
	size_t n = 0;

	assert_int_equal(lxp_rootfs_resolve(fs, 2, "/real", &d, &n), 0);
	assert_ptr_equal(d, body);
	assert_int_equal((int)n, 2);

	d = NULL;
	n = 0;
	assert_int_equal(lxp_rootfs_resolve(fs, 2, "/link", &d, &n), 0);
	assert_ptr_equal(d, body); /* followed /link -> /real */
	assert_int_equal((int)n, 2);

	assert_int_equal(lxp_rootfs_resolve(fs, 2, "/missing", &d, &n), -LXP_ENOENT);
}

/* ---- tmpfs: create / find / reserve on the writable node table ---------------- */
static void wfs_reset(void)
{
	for (int i = 0; i < LXP_NWNODE; i++) {
		lxp_wnode_t *w = wnode_at(i);
		w->used = 0;
		w->size = 0;
		w->cap = 0;
		w->data = NULL;
	}
}

static void test_tmpfs_nodes(void **s)
{
	(void)s;
	wfs_reset();

	assert_int_equal(wfs_find("/tmp/a"), -1);
	int a = wfs_create("/tmp/a", LXP_S_IFREG | 0644u);
	assert_true(a >= 0);
	assert_int_equal(wfs_find("/tmp/a"), a);
	assert_int_equal(wnode_at(a)->mode, LXP_S_IFREG | 0644u);

	int d = wfs_create("/tmp/d", LXP_S_IFDIR | 0755u);
	assert_true(d >= 0);
	assert_int_not_equal(d, a); /* distinct paths → distinct nodes */
	assert_int_equal(wnode_at(d)->mode, LXP_S_IFDIR | 0755u);

	/* reserve grows capacity from the pool; the node can then hold the bytes */
	assert_int_equal(wfs_reserve(a, 100), 0);
	assert_true(wnode_at(a)->cap >= 100);
	assert_non_null(wnode_at(a)->data);
}

/* The pool reclaims freed blocks (arena-backed, not a leaky bump pool). Both cases
 * below allocate far more than the 64K pool in total; they only pass because each
 * removal / growth frees the prior block. Under the old bump pool they ENOSPC early. */
static void test_tmpfs_reclaim(void **s)
{
	(void)s;
	wfs_reset();

	/* unlink reclaims a node's bytes: create+grow+free an 8K file 64 times (512K total). */
	for (int i = 0; i < 64; i++) {
		int n = wfs_create("/tmp/big", LXP_S_IFREG | 0644u);
		assert_true(n >= 0);
		assert_int_equal(wfs_reserve(n, 8192), 0);
		assert_true(wnode_at(n)->cap >= 8192);
		wfs_free(n);
	}

	/* growth reclaims the old block: grow one node through many sizes up to 16K in 1K
	 * steps (each grow frees the previous block, so the leaked sum — well over the pool —
	 * never accumulates; capped at 16K so the brief old+new overlap during the copy fits). */
	int g = wfs_create("/tmp/grow", LXP_S_IFREG | 0644u);
	assert_true(g >= 0);
	for (size_t sz = 1024; sz <= 16u * 1024u; sz += 1024)
		assert_int_equal(wfs_reserve(g, sz), 0);
	assert_true(wnode_at(g)->cap >= 16u * 1024u);
	wfs_free(g);
	assert_null(wnode_at(g)->data); /* wfs_free clears the node */
}

/* ---- pipe: alloc + the empty/no-peer guard paths ------------------------------ */
static void test_pipe_guards(void **s)
{
	(void)s;
	int pi = lxp_pipe_alloc();
	assert_true(pi >= 0);

	/* No live process holds either end (host test has no proc-table fds), so: an empty
	 * pipe with no writer reads EOF, and a write with no reader is a broken pipe. */
	uint8_t buf[8];
	assert_int_equal(pipe_try_read(pi, buf, sizeof(buf)), 0);	 /* EOF */
	assert_int_equal(pipe_try_write(pi, "abc", 3), -LXP_EPIPE);	 /* no readers */
}

/* ---- procfs: membership test, decimal builder, content generation ------------- */
static void test_procfs(void **s)
{
	(void)s;
	assert_int_equal(proc_is("/proc"), 1);
	assert_int_equal(proc_is("/proc/meminfo"), 1);
	assert_int_equal(proc_is("/proctored"), 0); /* prefix must be exactly "/proc/" */
	assert_int_equal(proc_is("/etc/passwd"), 0);

	char b[32];
	size_t n = p_dec(b, 0, sizeof(b), 42);
	assert_int_equal((int)n, 2);
	assert_memory_equal(b, "42", 2);
	n = p_dec(b, 0, sizeof(b), 0);
	assert_int_equal((int)n, 1);
	assert_int_equal(b[0], '0');

	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	char out[512];
	long r = proc_gen("/proc/meminfo", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	assert_true((size_t)r < sizeof(out));
	out[r] = '\0';
	assert_non_null(strstr(out, "MemTotal:       12288 kB"));
	assert_non_null(strstr(out, "MemFree:        3072 kB"));
	assert_non_null(strstr(out, "MemAvailable:   3072 kB"));
	assert_non_null(strstr(out, "SReclaimable:      0 kB"));

	r = proc_gen("/proc/version", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	assert_true((size_t)r < sizeof(out));
	out[r] = '\0';
	assert_string_equal(out,
			    "Linux version 6.1.0 (TestRTOS 1.2.3 ove-abcdef0 lxp-1234567) "
			    "(uClibc)\n");
}

/* ---- pointer validators: user_ok / user_strnlen / file_mode ------------------- */
static void test_user_helpers(void **s)
{
	(void)s;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	int stackvar = 0;
	assert_int_equal(user_ok(&p, NULL, 4, 0), 0);	     /* NULL rejected (region_lo=1) */
	assert_int_equal(user_ok(&p, &stackvar, 4, 0), 1);   /* in the all-permitting range */
	assert_int_equal(user_ok(&p, &stackvar, 4, 1), 1);   /* writable too */

	assert_int_equal((int)user_strnlen(&p, "abc", 256), 3);
	assert_int_equal((int)user_strnlen(&p, "", 256), 0);
	assert_true(user_strnlen(&p, "abcdef", 3) < 0); /* no NUL within max → -EFAULT */

	const lxp_file_t reg = {"/f", NULL, 0, 0}; /* mode 0 → a regular file */
	const lxp_file_t dir = {"/d", NULL, 0, LXP_S_IFDIR | 0755u};
	assert_int_equal(file_mode(&reg), LXP_S_IFREG | 0644u);
	assert_int_equal(file_mode(&dir), LXP_S_IFDIR | 0755u);
}

int test_fs_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_path_normalize),
		cmocka_unit_test(test_path_rootfs_resolve),
		cmocka_unit_test(test_tmpfs_nodes),
		cmocka_unit_test(test_tmpfs_reclaim),
		cmocka_unit_test(test_pipe_guards),
		cmocka_unit_test(test_procfs),
		cmocka_unit_test(test_user_helpers),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
