/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Shared helpers for the coverage-guided fuzz harnesses. Each harness is its own
 * executable exporting LLVMFuzzerTestOneInput(); the driver (libFuzzer, AFL++, or
 * the gcc replay main) supplies the loop. Everything here is header-only so no
 * extra TU is added to the module set.
 */
#ifndef LXP_FUZZ_COMMON_H
#define LXP_FUZZ_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* MAP_32BIT (lxp_lowbuf.h) */
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Copy up to dstsz-1 fuzzer bytes into dst and NUL-terminate — turns a raw
 * (data,size) buffer into a bounded C string for the string-consuming targets
 * (lxp_resolve_path, …) without ever reading past the input. Returns dst. */
static inline char *fuzz_cstr(char *dst, size_t dstsz, const uint8_t *data, size_t size)
{
	if (dstsz == 0)
		return dst;
	size_t n = size < dstsz - 1 ? size : dstsz - 1;
	if (n)
		memcpy(dst, data, n);
	dst[n] = '\0';
	return dst;
}

/* A little consume-front cursor for the structured harnesses (syscall): pull a
 * fixed-width LE scalar off the head of the input, advancing the cursor. Returns
 * 0 (and leaves *val = 0) once the input is exhausted, so a short input degrades
 * gracefully instead of reading OOB. */
typedef struct fuzz_cursor {
	const uint8_t *p;
	size_t n;
} fuzz_cursor_t;

static inline uint8_t fuzz_u8(fuzz_cursor_t *c)
{
	if (c->n == 0)
		return 0;
	c->n--;
	return *c->p++;
}

static inline uint32_t fuzz_u32(fuzz_cursor_t *c)
{
	uint32_t v = 0;
	for (int i = 0; i < 4; i++)
		v |= (uint32_t)fuzz_u8(c) << (8 * i);
	return v;
}

#endif /* LXP_FUZZ_COMMON_H */
