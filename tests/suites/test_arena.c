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

/* Mirror of the removed pointer-bearing header.  A hostile guest can place
 * these bytes anywhere in its allocation; free must never follow its links. */
struct legacy_forged_blk {
	struct legacy_forged_blk *next;
	struct legacy_forged_blk *prev;
	size_t payload;
	uint32_t is_free;
	uint32_t magic;
};

#define LEGACY_ARENA_MAGIC 0x4f415242u
#define LEGACY_ARENA_HDR                                                               \
	((sizeof(struct legacy_forged_blk) + (LXP_ARENA_ALIGN - 1)) &                    \
	 ~(size_t)(LXP_ARENA_ALIGN - 1))

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

/* An interior pointer preceded by a convincing legacy header must be ignored.
 * In the old allocator this made privileged free follow `next` and overwrite
 * the host-side guard block. */
static void test_arena_rejects_forged_links(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	uint8_t *p = lxp_arena_alloc(&a, 512);
	assert_non_null(p);
	size_t used = lxp_arena_used(&a);

	struct legacy_forged_blk guard = {
		.next = NULL,
		.prev = NULL,
		.payload = 16,
		.is_free = 1,
		.magic = LEGACY_ARENA_MAGIC,
	};
	struct legacy_forged_blk guard_before = guard;
	struct legacy_forged_blk forged = {
		.next = &guard,
		.prev = NULL,
		.payload = 16,
		.is_free = 0,
		.magic = LEGACY_ARENA_MAGIC,
	};
	uint8_t *interior = p + 128;
	memcpy(interior - LEGACY_ARENA_HDR, &forged, sizeof(forged));

	lxp_arena_free(&a, interior);
	assert_memory_equal(&guard, &guard_before, sizeof(guard));
	assert_int_equal(lxp_arena_used(&a), used);
	lxp_arena_free(&a, p);
	assert_int_equal(lxp_arena_used(&a), 0);
}

/* Corrupted in-band topology fails closed and reset remains a privileged
 * recovery operation. No allocator operation may walk beyond the arena. */
static void test_arena_corruption_fails_closed(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	void *p = lxp_arena_alloc(&a, 64);
	assert_non_null(p);
	size_t used = lxp_arena_used(&a);

	memset(a.first, 0, LXP_ARENA_ALIGN);
	assert_null(lxp_arena_alloc(&a, 64));
	lxp_arena_free(&a, p);
	assert_int_equal(lxp_arena_used(&a), used);

	lxp_arena_reset(&a);
	assert_int_equal(lxp_arena_used(&a), 0);
	assert_non_null(lxp_arena_alloc(&a, 64));
}

/* Tracked extents require an exact live address/length pair. */
static void test_arena_tracked_extent(void **s)
{
	(void)s;
	lxp_arena_t a;
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);
	uint8_t *p = lxp_arena_alloc_tracked(&a, 100);
	assert_non_null(p);
	size_t used = lxp_arena_used(&a);

	assert_false(lxp_arena_free_tracked(&a, p + LXP_ARENA_ALIGN,
					    100 - LXP_ARENA_ALIGN));
	assert_false(lxp_arena_free_tracked(&a, p, 99));
	assert_int_equal(lxp_arena_used(&a), used);
	assert_true(lxp_arena_free_tracked(&a, p, 100));
	assert_int_equal(lxp_arena_used(&a), 0);
	assert_false(lxp_arena_free_tracked(&a, p, 100));
}

/* The privileged tracking table is deliberately fixed-size. Exhaustion must
 * return NULL without consuming another arena block, and every recorded block
 * must remain reclaimable. */
static void test_arena_tracked_extent_limit(void **s)
{
	(void)s;
	lxp_arena_t a;
	void *blocks[LXP_ARENA_MAX_MAPPINGS];
	assert_int_equal(lxp_arena_init(&a, g_buf, sizeof(g_buf)), LXP_OK);

	for (size_t i = 0; i < LXP_ARENA_MAX_MAPPINGS; i++) {
		blocks[i] = lxp_arena_alloc_tracked(&a, 1);
		assert_non_null(blocks[i]);
	}
	size_t used = lxp_arena_used(&a);
	assert_null(lxp_arena_alloc_tracked(&a, 1));
	assert_int_equal(lxp_arena_used(&a), used);
	for (size_t i = 0; i < LXP_ARENA_MAX_MAPPINGS; i++)
		assert_true(lxp_arena_free_tracked(&a, blocks[i], 1));
	assert_int_equal(lxp_arena_used(&a), 0);
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
		cmocka_unit_test(test_arena_rejects_forged_links),
		cmocka_unit_test(test_arena_corruption_fails_closed),
		cmocka_unit_test(test_arena_tracked_extent),
		cmocka_unit_test(test_arena_tracked_extent_limit),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
