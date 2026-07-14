/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#include "lxp/lxp_config.h"

#include "lxp/lxp_arena.h"

#include <string.h>

/*
 * First-fit physical-block region allocator.
 *
 * The managed region is tiled exactly by variable-size blocks.  Block headers
 * deliberately contain no pointers: program arenas are guest-writable, so a
 * guest can corrupt a header, but it must never be able to supply a privileged
 * next/previous pointer.  Every operation first walks and validates the whole
 * layout using bounded integer arithmetic.  Corruption therefore fails closed
 * without dereferencing or writing outside the managed region.
 */

#define ARENA_MAGIC 0x4f415242u /* "OARB" */

struct lxp_arena_blk {
	size_t payload; /* usable bytes after the header */
	uint32_t is_free;
	uint32_t magic;
};

/* Header size rounded up so the payload that follows stays aligned. */
#define ARENA_HDR \
	((sizeof(struct lxp_arena_blk) + (LXP_ARENA_ALIGN - 1)) & ~(size_t)(LXP_ARENA_ALIGN - 1))

static inline size_t arena_align(size_t n)
{
	if (n > SIZE_MAX - (LXP_ARENA_ALIGN - 1))
		return 0; /* rounding would wrap a (near-)SIZE_MAX request; 0 => "no fit" */
	return (n + (LXP_ARENA_ALIGN - 1)) & ~(size_t)(LXP_ARENA_ALIGN - 1);
}

static inline void *blk_payload(struct lxp_arena_blk *b)
{
	return (uint8_t *)b + ARENA_HDR;
}

static void arena_clear_mappings(lxp_arena_t *arena)
{
	memset(arena->mappings, 0, sizeof(arena->mappings));
}

static void arena_lay_first(lxp_arena_t *arena)
{
	struct lxp_arena_blk *first = (struct lxp_arena_blk *)arena->base;
	first->payload = arena->size - ARENA_HDR;
	first->is_free = 1;
	first->magic = ARENA_MAGIC;
	arena->first = first;
	arena->used = 0;
}

/* Validate the complete physical tiling before trusting any header field.
 * `used` is privileged metadata; matching it also catches ordinary single-
 * header free/allocated flag corruption. */
static bool arena_layout_valid(const lxp_arena_t *arena)
{
	if (!arena || !arena->base || arena->first != arena->base ||
	    arena->size < ARENA_HDR + LXP_ARENA_ALIGN ||
	    (arena->size & (LXP_ARENA_ALIGN - 1)) != 0)
		return false;

	uintptr_t base = (uintptr_t)arena->base;
	if ((base & (LXP_ARENA_ALIGN - 1)) != 0 || base > UINTPTR_MAX - arena->size)
		return false;

	uintptr_t end = base + arena->size;
	uintptr_t cur = base;
	size_t used = 0;
	while (cur < end) {
		size_t remain = (size_t)(end - cur);
		if (remain < ARENA_HDR)
			return false;

		const struct lxp_arena_blk *b = (const struct lxp_arena_blk *)cur;
		if (b->magic != ARENA_MAGIC || b->is_free > 1 ||
		    b->payload < LXP_ARENA_ALIGN ||
		    (b->payload & (LXP_ARENA_ALIGN - 1)) != 0 ||
		    b->payload > remain - ARENA_HDR)
			return false;

		size_t footprint = ARENA_HDR + b->payload;
		if (!b->is_free) {
			if (used > arena->size - footprint)
				return false;
			used += footprint;
		}
		cur += footprint;
	}

	return cur == end && used == arena->used;
}

/* Find only an exact payload start.  The caller must have validated the
 * layout, so each computed successor is aligned, forward-moving and in-range. */
static struct lxp_arena_blk *arena_find_payload(lxp_arena_t *arena, const void *ptr,
						struct lxp_arena_blk **prev_out)
{
	uintptr_t cur = (uintptr_t)arena->base;
	uintptr_t end = cur + arena->size;
	uintptr_t target = (uintptr_t)ptr;
	struct lxp_arena_blk *prev = NULL;

	while (cur < end) {
		struct lxp_arena_blk *b = (struct lxp_arena_blk *)cur;
		if ((uintptr_t)blk_payload(b) == target) {
			if (prev_out)
				*prev_out = prev;
			return b;
		}
		cur += ARENA_HDR + b->payload;
		prev = b;
	}
	return NULL;
}

int lxp_arena_init(lxp_arena_t *arena, void *buf, size_t size)
{
	if (!arena || !buf)
		return LXP_ERR_INVALID_PARAM;

	uintptr_t raw = (uintptr_t)buf;
	if (raw > UINTPTR_MAX - (LXP_ARENA_ALIGN - 1))
		return LXP_ERR_INVALID_PARAM;
	uintptr_t start = (raw + (LXP_ARENA_ALIGN - 1)) & ~(uintptr_t)(LXP_ARENA_ALIGN - 1);
	size_t adjust = (size_t)(start - raw);
	if (size <= adjust)
		return LXP_ERR_INVALID_PARAM;

	size_t usable = (size - adjust) & ~(size_t)(LXP_ARENA_ALIGN - 1);
	if (usable < ARENA_HDR + LXP_ARENA_ALIGN)
		return LXP_ERR_NO_MEMORY;

	arena->base = (uint8_t *)buf + adjust; /* == aligned `start`, via ptr arithmetic */
	arena->size = usable;
	arena->high_water = 0;
	arena_clear_mappings(arena);
	arena_lay_first(arena);
	return LXP_OK;
}

void *lxp_arena_alloc(lxp_arena_t *arena, size_t size)
{
	if (!arena || !arena->first || !arena_layout_valid(arena))
		return NULL;

	size_t need = arena_align(size == 0 ? 1 : size);
	if (need == 0)
		return NULL; /* the size request overflowed the alignment rounding */

	uintptr_t cur = (uintptr_t)arena->base;
	uintptr_t end = cur + arena->size;
	struct lxp_arena_blk *b = NULL;
	while (cur < end) {
		struct lxp_arena_blk *candidate = (struct lxp_arena_blk *)cur;
		if (candidate->is_free && candidate->payload >= need) {
			b = candidate;
			break;
		}
		cur += ARENA_HDR + candidate->payload;
	}
	if (!b)
		return NULL;

	/* Split when the tail can host another header plus a minimum slot. */
	if (b->payload - need >= ARENA_HDR + LXP_ARENA_ALIGN) {
		struct lxp_arena_blk *rem =
			(struct lxp_arena_blk *)((uint8_t *)b + ARENA_HDR + need);
		rem->payload = b->payload - need - ARENA_HDR;
		rem->is_free = 1;
		rem->magic = ARENA_MAGIC;
		b->payload = need;
	}

	size_t footprint = ARENA_HDR + b->payload;
	if (arena->used > arena->size - footprint)
		return NULL; /* unreachable after validation; retain fail-closed arithmetic */
	b->is_free = 0;
	arena->used += footprint;
	if (arena->used > arena->high_water)
		arena->high_water = arena->used;
	return blk_payload(b);
}

void *lxp_arena_calloc(lxp_arena_t *arena, size_t size)
{
	size_t need = arena_align(size == 0 ? 1 : size);
	if (need == 0)
		return NULL;
	void *p = lxp_arena_alloc(arena, size);
	if (p)
		memset(p, 0, need);
	return p;
}

static bool arena_free_block(lxp_arena_t *arena, void *ptr)
{
	if (!arena || !ptr || !arena_layout_valid(arena))
		return false;

	struct lxp_arena_blk *prev = NULL;
	struct lxp_arena_blk *b = arena_find_payload(arena, ptr, &prev);
	if (!b || b->is_free)
		return false; /* interior pointer, foreign pointer or double free */

	size_t footprint = ARENA_HDR + b->payload;
	if (arena->used < footprint)
		return false;
	b->is_free = 1;
	arena->used -= footprint;

	/* Coalesce forward. */
	uintptr_t end = (uintptr_t)arena->base + arena->size;
	uintptr_t next_addr = (uintptr_t)b + ARENA_HDR + b->payload;
	if (next_addr < end) {
		struct lxp_arena_blk *next = (struct lxp_arena_blk *)next_addr;
		if (next->is_free) {
			b->payload += ARENA_HDR + next->payload;
			next->magic = 0;
		}
	}

	/* Coalesce backward. */
	if (prev && prev->is_free) {
		prev->payload += ARENA_HDR + b->payload;
		b->magic = 0;
	}
	return true;
}

void lxp_arena_free(lxp_arena_t *arena, void *ptr)
{
	if (!arena_free_block(arena, ptr))
		return;

	/* Generic callers may release a tracked block during teardown/error
	 * cleanup. Do not leave a stale record that could later free a reused
	 * address. */
	uintptr_t addr = (uintptr_t)ptr;
	for (size_t i = 0; i < LXP_ARENA_MAX_MAPPINGS; i++) {
		if (arena->mappings[i].addr == addr) {
			arena->mappings[i].addr = 0;
			arena->mappings[i].len = 0;
		}
	}
}

void *lxp_arena_alloc_tracked(lxp_arena_t *arena, size_t size)
{
	if (!arena)
		return NULL;

	size_t slot = LXP_ARENA_MAX_MAPPINGS;
	for (size_t i = 0; i < LXP_ARENA_MAX_MAPPINGS; i++) {
		if (arena->mappings[i].addr == 0) {
			slot = i;
			break;
		}
	}
	if (slot == LXP_ARENA_MAX_MAPPINGS)
		return NULL;

	void *ptr = lxp_arena_alloc(arena, size);
	if (!ptr)
		return NULL;
	arena->mappings[slot].addr = (uintptr_t)ptr;
	arena->mappings[slot].len = size;
	return ptr;
}

bool lxp_arena_free_tracked(lxp_arena_t *arena, void *ptr, size_t size)
{
	if (!arena || !ptr)
		return false;

	uintptr_t addr = (uintptr_t)ptr;
	for (size_t i = 0; i < LXP_ARENA_MAX_MAPPINGS; i++) {
		if (arena->mappings[i].addr != addr || arena->mappings[i].len != size)
			continue;
		if (!arena_free_block(arena, ptr))
			return false;
		arena->mappings[i].addr = 0;
		arena->mappings[i].len = 0;
		return true;
	}
	return false;
}

void lxp_arena_reset(lxp_arena_t *arena)
{
	if (!arena || !arena->base)
		return;
	arena_clear_mappings(arena);
	arena_lay_first(arena);
}

bool lxp_arena_owns(const lxp_arena_t *arena, const void *ptr)
{
	if (!arena || !ptr)
		return false;
	uintptr_t base = (uintptr_t)arena->base;
	uintptr_t p = (uintptr_t)ptr;
	if (base > UINTPTR_MAX - arena->size)
		return false;
	return p >= base && p < base + arena->size;
}

size_t lxp_arena_used(const lxp_arena_t *arena)
{
	return arena ? arena->used : 0;
}

size_t lxp_arena_capacity(const lxp_arena_t *arena)
{
	return arena ? arena->size : 0;
}

size_t lxp_arena_high_water(const lxp_arena_t *arena)
{
	return arena ? arena->high_water : 0;
}
