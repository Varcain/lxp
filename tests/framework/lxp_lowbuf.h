/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Guarded low-memory buffers for host tests and fuzz harnesses that model 32-bit target
 * memory. Header-only.
 */
#ifndef LXP_LOWBUF_H
#define LXP_LOWBUF_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* MAP_32BIT */
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* A working buffer for the targets that model 32-bit-target memory (the FDPIC loader
 * stores segment runtime addresses in the loadmap as uint32). `cap` usable bytes are
 * mapped in the low 4 GiB so those (uintptr_t->uint32) truncations round-trip exactly
 * as they do on the Cortex-M target — otherwise a truncated 64-bit host pointer is a
 * spurious wild deref that buries real findings. A PROT_NONE guard page sits right
 * after the usable span, so a read/write one byte past it faults precisely (a target
 * OOB is still caught; only benign truncation is not). MAP_32BIT is best-effort: if the
 * low region is exhausted we fall back to an ordinary mapping (fine for the committed
 * seeds, which never reach a loadmap deref). */
typedef struct lxp_lowbuf {
	uint8_t *base; /* start of the usable span */
	size_t cap;    /* usable bytes; base[cap] is the guard page */
} lxp_lowbuf_t;

static inline lxp_lowbuf_t lxp_lowbuf_map(size_t cap)
{
	lxp_lowbuf_t b = {NULL, 0};
	long pg = sysconf(_SC_PAGESIZE);
	if (pg <= 0)
		pg = 4096;
	size_t usable = (cap + (size_t)pg - 1) & ~((size_t)pg - 1);
	size_t total = usable + (size_t)pg;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_32BIT
	uint8_t *m = (uint8_t *)mmap(NULL, total, PROT_READ | PROT_WRITE, flags | MAP_32BIT, -1, 0);
	if (m == MAP_FAILED)
#endif
		m = (uint8_t *)mmap(NULL, total, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (m == MAP_FAILED)
		return b;
	if (mprotect(m + usable, (size_t)pg, PROT_NONE) != 0) {
		munmap(m, total);
		return b;
	}
	b.base = m;
	b.cap = usable;
	return b;
}

/* Copy up to buf.cap bytes RIGHT-aligned against the guard page and return the
 * pointer to pass as the image: a read at image+size lands on the guard, so an
 * off-by-one past the declared image_size faults exactly. */
static inline const uint8_t *lxp_lowbuf_place(lxp_lowbuf_t buf, const uint8_t *data, size_t *size)
{
	size_t n = *size < buf.cap ? *size : buf.cap;
	uint8_t *dst = buf.base + (buf.cap - n);
	if (n)
		memcpy(dst, data, n);
	*size = n;
	return dst;
}

#endif /* LXP_LOWBUF_H */
