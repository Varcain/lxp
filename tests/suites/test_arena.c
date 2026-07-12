/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fresh unit suite for the arena allocator (src/lxp_arena.c) — a self-contained,
 * free-list bump-region allocator the personality's per-process heaps sit on. Not
 * migrated: the vendored copy was previously untested. Also proves the harness can
 * host a non-"linux_" suite.
 */
#include "../framework/lxp_test.h"
#include "lxp/lxp_arena.h"

#include <stdint.h>
#include <string.h>

static uint8_t g_buf[8192] __attribute__((aligned(16)));

static int aligned16(const void *p)
{
	return ((uintptr_t)p % LXP_ARENA_ALIGN) == 0;
}
static int in_buf(const void *p, size_t n)
{
	uintptr_t a = (uintptr_t)p, lo = (uintptr_t)g_buf, hi = lo + sizeof(g_buf);
	return a >= lo && a + n <= hi;
}

/* init: fresh arena is empty, has capacity, and rejects bad inputs. */
static void test_arena_init(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	assert_int_equal(lxp_arena_used(&a), 0);
	assert_true(lxp_arena_capacity(&a) > 0);
	assert_true(lxp_arena_capacity(&a) <= sizeof(g_buf));
	assert_int_equal(lxp_arena_high_water(&a), 0);

	/* A region too small to hold even one header must fail, not corrupt memory. */
	uint8_t tiny[8];
	assert_int_not_equal(lxp_arena_init(&a, tiny, sizeof(tiny)), LXP_OK);
}

/* alloc: aligned, in-region, distinct, non-overlapping; used/high_water grow. */
static void test_arena_alloc(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);

	void *p = lxp_arena_alloc(&a, 100);
	assert_non_null(p);
	assert_true(aligned16(p));
	assert_true(in_buf(p, 100));
	size_t u1 = lxp_arena_used(&a);
	assert_true(u1 >= 100);
	assert_int_equal(lxp_arena_high_water(&a), u1);

	void *q = lxp_arena_alloc(&a, 200);
	assert_non_null(q);
	assert_true(aligned16(q));
	assert_ptr_not_equal(p, q);
	/* distinct 100- and 200-byte blocks must not overlap */
	assert_true((uintptr_t)q >= (uintptr_t)p + 100 || (uintptr_t)p >= (uintptr_t)q + 200);
	assert_true(lxp_arena_used(&a) > u1);

	/* payload is writable across its whole extent (no header clobber). */
	memset(p, 0xAB, 100);
	memset(q, 0xCD, 200);
	assert_int_equal(((uint8_t *)p)[99], 0xAB);
	assert_int_equal(((uint8_t *)q)[0], 0xCD);
}

/* calloc returns zeroed memory. */
static void test_arena_calloc(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	uint8_t *p = lxp_arena_alloc(&a, 64);
	memset(p, 0xFF, 64);
	lxp_arena_free(&a, p);
	uint8_t *z = lxp_arena_calloc(&a, 64);
	assert_non_null(z);
	for (int i = 0; i < 64; i++)
		assert_int_equal(z[i], 0);
}

/* An allocation larger than the region fails (NULL), leaving the arena usable. */
static void test_arena_exhaustion(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	assert_null(lxp_arena_alloc(&a, sizeof(g_buf) * 2));
	/* the failed alloc must not have consumed the arena */
	assert_int_equal(lxp_arena_used(&a), 0);
	assert_non_null(lxp_arena_alloc(&a, 128));
}

/* free + coalesce: freeing all blocks returns the arena to empty and lets a
 * subsequent large allocation reuse the whole region. */
static void test_arena_free_coalesce(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	void *p = lxp_arena_alloc(&a, 1000);
	void *q = lxp_arena_alloc(&a, 1000);
	void *r = lxp_arena_alloc(&a, 1000);
	assert_non_null(p);
	assert_non_null(q);
	assert_non_null(r);
	size_t peak = lxp_arena_high_water(&a);
	lxp_arena_free(&a, p);
	lxp_arena_free(&a, q);
	lxp_arena_free(&a, r);
	assert_int_equal(lxp_arena_used(&a), 0);
	/* high_water records the peak even after everything is freed */
	assert_int_equal(lxp_arena_high_water(&a), peak);
	/* coalesced back to one big free block: a single large alloc succeeds again */
	assert_non_null(lxp_arena_alloc(&a, 2500));
}

/* reset returns the arena to its initial empty state in one call. */
static void test_arena_reset(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	assert_non_null(lxp_arena_alloc(&a, 500));
	assert_non_null(lxp_arena_alloc(&a, 500));
	assert_true(lxp_arena_used(&a) > 0);
	lxp_arena_reset(&a);
	assert_int_equal(lxp_arena_used(&a), 0);
	assert_non_null(lxp_arena_alloc(&a, sizeof(g_buf) / 2));
}

int test_arena_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_arena_init),
		cmocka_unit_test(test_arena_alloc),
		cmocka_unit_test(test_arena_calloc),
		cmocka_unit_test(test_arena_exhaustion),
		cmocka_unit_test(test_arena_free_coalesce),
		cmocka_unit_test(test_arena_reset),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
