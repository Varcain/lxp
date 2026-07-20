/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Host run-loop hook stubs. The unit tests drive lxp_syscall() directly and do NOT
 * link the coordinator (src/lxp_run.c), which normally defines these OS-service
 * symbols by routing through the engine ops. On the host we back the clock with
 * clock_gettime and make the cache/flush hooks no-ops (a coherent host has no cache
 * maintenance to do).
 */
#include "lxp/lxp_syscall.h"

#include <stdint.h>
#include <string.h>
#include <time.h>

int g_lxp_test_random_result = LXP_OK;
size_t g_lxp_test_random_calls;
size_t g_lxp_test_random_len;
size_t g_lxp_test_random_clean_calls_on_entry;
size_t g_lxp_test_cache_clean_calls;
const void *g_lxp_test_cache_clean_base;
size_t g_lxp_test_cache_clean_len;
size_t g_lxp_test_cache_invalidate_calls;
const void *g_lxp_test_cache_invalidate_base;
size_t g_lxp_test_cache_invalidate_len;

int lxp_random_fill(void *buf, size_t len)
{
	g_lxp_test_random_calls++;
	g_lxp_test_random_len = len;
	g_lxp_test_random_clean_calls_on_entry = g_lxp_test_cache_clean_calls;
	if (g_lxp_test_random_result != LXP_OK)
		return g_lxp_test_random_result;
	uint8_t *out = buf;
	for (size_t i = 0; i < len; i++)
		out[i] = (uint8_t)(0xa5u ^ (uint8_t)i);
	return LXP_OK;
}

int lxp_time_us(uint64_t *out)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	*out = (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
	return 0;
}
int lxp_time_ns(uint64_t *out)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	*out = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	return 0;
}
void lxp_guest_flush(const void *base, size_t len)
{
	(void)base;
	(void)len;
}
void lxp_guest_invalidate(const void *base, size_t len)
{
	(void)base;
	(void)len;
}
void lxp_cache_clean(const void *base, size_t len)
{
	g_lxp_test_cache_clean_calls++;
	g_lxp_test_cache_clean_base = base;
	g_lxp_test_cache_clean_len = len;
}
void lxp_cache_invalidate(const void *base, size_t len)
{
	g_lxp_test_cache_invalidate_calls++;
	g_lxp_test_cache_invalidate_base = base;
	g_lxp_test_cache_invalidate_len = len;
}

#if LXP_ENABLE_DEV_FB
/* A mock display port so the /dev/fb0 driver (src/dev/lxp_dev_fb.c) links + runs on the
 * host. g_lxp_disp_ops is normally published by lxp_run() (excluded here); back it with a
 * small static RGB565 framebuffer so the fbdev ioctls/mmap/pan paths are exercisable. */
#include "lxp/lxp_disp_ops.h"

static uint8_t g_mock_fb[64 * 64 * 2];
static int mock_fb_init(void)
{
	return 0;
}
static int mock_fb_get_info(lxp_fb_info_t *i)
{
	i->width = 64;
	i->height = 64;
	i->stride_bytes = 64 * 2;
	i->fmt = 0; /* RGB565 */
	i->smem_len = (uint32_t)sizeof(g_mock_fb);
	return 0;
}
static void *mock_fb_get_buffer(void)
{
	return g_mock_fb;
}
/* Recorded args of the last fb_flush, so a suite can assert the driver's dirty-rect math. */
int g_mock_fb_flush_x, g_mock_fb_flush_y, g_mock_fb_flush_w, g_mock_fb_flush_h;
int g_mock_fb_flush_calls;
static void mock_fb_flush(int x, int y, int w, int h)
{
	g_mock_fb_flush_x = x;
	g_mock_fb_flush_y = y;
	g_mock_fb_flush_w = w;
	g_mock_fb_flush_h = h;
	g_mock_fb_flush_calls++;
}
static void mock_fb_present(void)
{
}
/* Recorded last dma2d_submit, so a suite can assert /dev/dma2d validated + forwarded a
 * descriptor (bad descriptors are rejected by the device before reaching here). */
lxp_dma2d_op_t g_mock_dma2d_op;
int g_mock_dma2d_calls;
static int mock_dma2d_submit(const lxp_dma2d_op_t *op)
{
	g_mock_dma2d_op = *op;
	g_mock_dma2d_calls++;
	return 0;
}
static const lxp_display_ops_t g_mock_disp = {
	.fb_init = mock_fb_init,
	.fb_get_info = mock_fb_get_info,
	.fb_get_buffer = mock_fb_get_buffer,
	.fb_flush = mock_fb_flush,
	.fb_present = mock_fb_present,
	.dma2d_submit = mock_dma2d_submit,
};
const lxp_display_ops_t *g_lxp_disp_ops = &g_mock_disp;
#endif
