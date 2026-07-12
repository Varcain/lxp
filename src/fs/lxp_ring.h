/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Byte-ring primitive: the two-memcpy-across-wrap read/write the pipe used, factored
 * out so the pipe and the pty (both byte rings for stream data) share one wrap-correct
 * implementation instead of hand-rolling it — and so the pty's drain stops copying byte
 * by byte. Header-only static inline (no new TU): it operates on the caller's own buffer
 * + cursors, so each backend keeps its existing struct layout.
 *
 * (The evdev input ring is a fixed-slot ELEMENT ring keyed by a monotonic head, and the
 * 9P netfs g_tx/g_rx are linear message buffers, not byte rings — neither uses this.)
 */
#ifndef LXP_FS_RING_H
#define LXP_FS_RING_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Drain up to @p len bytes from the ring [@p buf, @p cap) at *@p rpos (with *@p count
 * bytes buffered) into @p dst. Advances *@p rpos and decrements *@p count. Returns the
 * byte count copied (min(len, *count)). */
static inline size_t lxp_ring_read(const uint8_t *buf, size_t cap, size_t *rpos, size_t *count,
				   void *dst, size_t len)
{
	if (len > *count)
		len = *count;
	uint8_t *out = (uint8_t *)dst;
	size_t n1 = cap - *rpos; /* contiguous bytes to the ring end */
	if (n1 > len)
		n1 = len;
	memcpy(out, &buf[*rpos], n1);
	memcpy(out + n1, &buf[0], len - n1); /* wrapped tail (len-n1 may be 0 = no-op) */
	*rpos = (*rpos + len) % cap;
	*count -= len;
	return len;
}

/* Append up to @p len bytes from @p src into the ring [@p buf, @p cap) at *@p wpos (with
 * *@p count bytes buffered). Advances *@p wpos and increments *@p count. Returns the byte
 * count copied (min(len, cap - *count)). */
static inline size_t lxp_ring_write(uint8_t *buf, size_t cap, size_t *wpos, size_t *count,
				    const void *src, size_t len)
{
	size_t space = cap - *count;
	if (len > space)
		len = space;
	const uint8_t *in = (const uint8_t *)src;
	size_t n1 = cap - *wpos; /* contiguous space to the ring end */
	if (n1 > len)
		n1 = len;
	memcpy(&buf[*wpos], in, n1);
	memcpy(&buf[0], in + n1, len - n1); /* wrapped tail (len-n1 may be 0 = no-op) */
	*wpos = (*wpos + len) % cap;
	*count += len;
	return len;
}

#endif /* LXP_FS_RING_H */
