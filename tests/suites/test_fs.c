/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fresh unit suite for the subsystems extracted out of the syscall dispatcher and the
 * pure syscall-boundary helpers — none of which had dedicated tests before:
 *   - path resolution   (src/fs/lxp_path.c):  lxp_resolve_path normalization + rootfs
 *                                              symlink follow (lxp_rootfs_resolve).
 *   - writable VFS       (src/fs/lxp_tmpfs.c): lxp_wfs_create/find/reserve + lxp_wnode_at.
 *   - pipe ring          (src/fs/lxp_pipe.c):  alloc + the no-reader/no-writer guards.
 *   - synthetic /proc    (src/proc/lxp_procfs.c): lxp_proc_is / lxp_proc_gen.
 *   - bounded text       (src/lxp_text.h): decimal construction and truncation.
 *   - pointer validators (src/lxp_syscall.c):  lxp_guest_access_ok / lxp_guest_strnlen /
 *     lxp_file_mode.
 * The syscall suite drives these through lxp_syscall(); here they are exercised directly.
 */
#include "../framework/lxp_test.h"
#include "lxp_arena.h"
#include "lxp_syscall.h"

#include "fs/lxp_path.h"
#include "fs/lxp_pipe.h"
#include "fs/lxp_tmpfs.h"
#include "lxp_internal.h"
#include "lxp_text.h"
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
	assert_int_equal(lxp_proc_init(p, arena, 4096), 0);
	p->mm->region_lo = 1;
	p->mm->region_hi = UINTPTR_MAX;
	p->mm->pool_lo = p->mm->pool_hi = 0;
}

/* ---- path: normalization of "." / ".." / duplicate slashes + cwd join --------- */
static void test_path_normalize(void **s)
{
	(void)s;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	strcpy(p.fs_context->cwd, "/foo");
	char out[LXP_PATH_MAX];

	assert_int_equal(lxp_resolve_path(&p, "/a/./b", out, sizeof(out)), 0);
	assert_string_equal(out, "/a/b");
	assert_int_equal(lxp_resolve_path(&p, "/a/b/../c", out, sizeof(out)), 0);
	assert_string_equal(out, "/a/c");
	assert_int_equal(lxp_resolve_path(&p, "//a//b/", out, sizeof(out)), 0);
	assert_string_equal(out, "/a/b");
	/* relative → joined onto (absolute, normalized) cwd */
	assert_int_equal(lxp_resolve_path(&p, "rel/x", out, sizeof(out)), 0);
	assert_string_equal(out, "/foo/rel/x");
	/* ".." can never escape the root */
	assert_int_equal(lxp_resolve_path(&p, "/../../a", out, sizeof(out)), 0);
	assert_string_equal(out, "/a");
	assert_int_equal(lxp_resolve_path(&p, "/a/../..", out, sizeof(out)), 0);
	assert_string_equal(out, "/");
	/* an input longer than LXP_PATH_MAX has no NUL in range → rejected, not overrun */
	char big[LXP_PATH_MAX + 64];
	memset(big, 'x', sizeof(big) - 1);
	big[0] = '/';
	big[sizeof(big) - 1] = '\0';
	assert_true(lxp_resolve_path(&p, big, out, sizeof(out)) < 0);
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
		lxp_wnode_t *w = lxp_wnode_at(i);
		if (w->used)
			lxp_wfs_free(i);
	}
}

static void test_tmpfs_nodes(void **s)
{
	(void)s;
	wfs_reset();

	assert_int_equal(lxp_wfs_find("/tmp/a"), -1);
	int a = lxp_wfs_create("/tmp/a", LXP_S_IFREG | 0644u);
	assert_true(a >= 0);
	assert_int_equal(lxp_wfs_find("/tmp/a"), a);
	assert_int_equal(lxp_wnode_at(a)->mode, LXP_S_IFREG | 0644u);

	int d = lxp_wfs_create("/tmp/d", LXP_S_IFDIR | 0755u);
	assert_true(d >= 0);
	assert_int_not_equal(d, a); /* distinct paths → distinct nodes */
	assert_int_equal(lxp_wnode_at(d)->mode, LXP_S_IFDIR | 0755u);

	/* reserve grows capacity from the pool; the node can then hold the bytes */
	assert_int_equal(lxp_wfs_reserve(a, 100), 0);
	assert_true(lxp_wnode_at(a)->cap >= 100);
	assert_non_null(lxp_wnode_at(a)->data);
	assert_int_equal(lxp_wfs_reserve(a, (size_t)LXP_WFS_POOL - LXP_ARENA_ALIGN + 1u), -1);
}

/* Renaming a directory carries its whole subtree; it cannot move into itself or
 * replace a directory that still has entries. */
static void test_tmpfs_rename_moves_children(void **s)
{
	(void)s;
	wfs_reset();
	int d = lxp_wfs_create("/tmp/d", LXP_S_IFDIR | 0755u);
	int a = lxp_wfs_create("/tmp/d/a", LXP_S_IFREG | 0644u);
	int sub = lxp_wfs_create("/tmp/d/s", LXP_S_IFDIR | 0755u);
	int b = lxp_wfs_create("/tmp/d/s/b", LXP_S_IFREG | 0644u);
	/* shares a prefix, not a parent */
	int other = lxp_wfs_create("/tmp/dx", LXP_S_IFREG | 0644u);
	assert_true(d >= 0 && a >= 0 && sub >= 0 && b >= 0 && other >= 0);

	assert_int_equal(lxp_wfs_rename(d, "/tmp/e"), 0);
	assert_int_equal(lxp_wfs_find("/tmp/e"), d);
	assert_int_equal(lxp_wfs_find("/tmp/e/a"), a);
	assert_int_equal(lxp_wfs_find("/tmp/e/s"), sub);
	assert_int_equal(lxp_wfs_find("/tmp/e/s/b"), b);
	assert_int_equal(lxp_wfs_find("/tmp/d/a"), -1);
	assert_int_equal(lxp_wfs_find("/tmp/dx"), other);

	assert_int_equal(lxp_wfs_rename(d, "/tmp/e/s/inner"), -LXP_EINVAL);
	int target = lxp_wfs_create("/tmp/t", LXP_S_IFDIR | 0755u);
	assert_true(target >= 0);
	assert_true(lxp_wfs_create("/tmp/t/keep", LXP_S_IFREG | 0644u) >= 0);
	assert_int_equal(lxp_wfs_rename(other, "/tmp/t"), -LXP_ENOTEMPTY);
	assert_int_equal(lxp_wfs_rename(other, "/tmp/e/s"), -LXP_ENOTEMPTY);
	assert_int_equal(lxp_wfs_find("/tmp/dx"), other); /* a refused rename changes nothing */
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
		int n = lxp_wfs_create("/tmp/big", LXP_S_IFREG | 0644u);
		assert_true(n >= 0);
		assert_int_equal(lxp_wfs_reserve(n, 8192), 0);
		assert_true(lxp_wnode_at(n)->cap >= 8192);
		lxp_wfs_free(n);
	}

	/* Growth reuses the adjacent free tail in place. Cross half the pool to prove
	 * capacity is not artificially limited by an old+new copy overlap. */
	int g = lxp_wfs_create("/tmp/grow", LXP_S_IFREG | 0644u);
	assert_true(g >= 0);
	for (size_t sz = 1024; sz <= 3u * LXP_WFS_POOL / 4u; sz += 1024)
		assert_int_equal(lxp_wfs_reserve(g, sz), 0);
	assert_true(lxp_wnode_at(g)->cap >= 3u * LXP_WFS_POOL / 4u);
	lxp_wfs_free(g);
	assert_null(lxp_wnode_at(g)->data); /* lxp_wfs_free clears the node */
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
	assert_int_equal(lxp_pipe_try_read(pi, buf, sizeof(buf)), 0);   /* EOF */
	assert_int_equal(lxp_pipe_try_write(pi, "abc", 3), -LXP_EPIPE); /* no readers */
}

/* ---- procfs: membership test, text builder, content generation ---------------- */
static void test_procfs(void **s)
{
	(void)s;
	assert_int_equal(lxp_proc_is("/proc"), 1);
	assert_int_equal(lxp_proc_is("/proc/meminfo"), 1);
	assert_int_equal(lxp_proc_is("/proctored"), 0); /* prefix must be exactly "/proc/" */
	assert_int_equal(lxp_proc_is("/etc/passwd"), 0);

	char b[32];
	lxp_text_t text = lxp_text_make(b, sizeof(b));
	lxp_text_u64(&text, 42);
	assert_int_equal((int)text.length, 2);
	assert_memory_equal(b, "42", 2);
	text = lxp_text_make(b, sizeof(b));
	lxp_text_u64(&text, 0);
	assert_int_equal((int)text.length, 1);
	assert_int_equal(b[0], '0');

	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	char out[512];
	long r = lxp_proc_gen("/proc/meminfo", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	assert_true((size_t)r < sizeof(out));
	out[r] = '\0';
	assert_non_null(strstr(out, "MemTotal:       6144 kB"));
	assert_non_null(strstr(out, "MemFree:        3840 kB"));
	assert_non_null(strstr(out, "MemAvailable:   3072 kB"));
	assert_non_null(strstr(out, "SReclaimable:      0 kB"));
	assert_non_null(strstr(out, "LxpSlotsTotal:  12"));
	assert_non_null(strstr(out, "LxpSlotsFree:   9"));
	assert_non_null(strstr(out, "LxpRegionsTotal: 8"));
	assert_non_null(strstr(out, "LxpRegionsFree: 5"));
	assert_non_null(strstr(out, "HostHeapTotal:  12288 kB"));
	assert_non_null(strstr(out, "HostHeapFree:   3072 kB"));

	r = lxp_proc_gen("/proc/lxp_resources", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	assert_true((size_t)r < sizeof(out));
	out[r] = '\0';
	assert_non_null(strstr(out, "slots_total 12\nslots_free 9\n"));
	assert_non_null(strstr(out, "regions_total 8\nregions_free 5\n"));
	assert_non_null(strstr(out, "program_region_bytes 262144\n"));
	assert_non_null(strstr(out, "dynamic_pool_bytes 524288\n"));
	assert_non_null(strstr(out, "guest_bytes_total 6291456\n"));
	assert_non_null(strstr(out, "guest_bytes_free 3932160\n"));
	assert_non_null(strstr(out, "guest_bytes_available 3145728\n"));
	assert_non_null(strstr(out, "host_heap_total 12582912\n"));
	assert_non_null(strstr(out, "host_heap_free 3145728\n"));

	r = lxp_proc_gen("/proc/rt_scope", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	out[r] = '\0';
	assert_string_equal(out, "available 0\n");

	r = lxp_proc_gen("/proc/version", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	assert_true((size_t)r < sizeof(out));
	out[r] = '\0';
	assert_string_equal(out, "Linux version 6.1.0 (TestRTOS 1.2.3 ove-abcdef0 lxp-1234567) "
				 "(uClibc)\n");

	lxp_proc_nice_set(&p, -7);
	r = lxp_proc_gen("/proc/self/stat", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	out[r] = '\0';
	assert_non_null(strstr(out, " 13 -7 0 0 0 0 0\n"));
	r = lxp_proc_gen("/proc/self/status", &p, out, sizeof(out) - 1);
	assert_true(r > 0);
	out[r] = '\0';
	assert_non_null(strstr(out, "Nice:\t-7\n"));
}

/* ---- pointer validators: lxp_guest_access_ok / lxp_guest_strnlen / lxp_file_mode ---- */
static void test_user_helpers(void **s)
{
	(void)s;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	int stackvar = 0;
	assert_int_equal(lxp_guest_access_ok(&p, NULL, 4, 0), 0); /* NULL rejected (region_lo=1) */
	assert_int_equal(lxp_guest_access_ok(&p, &stackvar, 4, 0),
			 1); /* in the all-permitting range */
	assert_int_equal(lxp_guest_access_ok(&p, &stackvar, 4, 1), 1); /* writable too */

	assert_int_equal((int)lxp_guest_strnlen(&p, "abc", 256), 3);
	assert_int_equal((int)lxp_guest_strnlen(&p, "", 256), 0);
	assert_true(lxp_guest_strnlen(&p, "abcdef", 3) < 0); /* no NUL within max → -EFAULT */

	const lxp_file_t reg = {"/f", NULL, 0, 0}; /* mode 0 → a regular file */
	const lxp_file_t dir = {"/d", NULL, 0, LXP_S_IFDIR | 0755u};
	assert_int_equal(lxp_file_mode(&reg), LXP_S_IFREG | 0644u);
	assert_int_equal(lxp_file_mode(&dir), LXP_S_IFDIR | 0755u);
}

int test_fs_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_path_normalize), cmocka_unit_test(test_path_rootfs_resolve),
		cmocka_unit_test(test_tmpfs_nodes),    cmocka_unit_test(test_tmpfs_reclaim),
		cmocka_unit_test(test_tmpfs_rename_moves_children),
		cmocka_unit_test(test_pipe_guards),    cmocka_unit_test(test_procfs),
		cmocka_unit_test(test_user_helpers),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
