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
#include "lxp_internal.h"

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
int g_lxp_test_mem_stats_result = LXP_OK;
struct lxp_mem_stats g_lxp_test_mem_stats = {
	.total = 12u * 1024u * 1024u,
	.free = 3u * 1024u * 1024u,
	.used = 9u * 1024u * 1024u,
	.peak_used = 10u * 1024u * 1024u,
};
static const struct lxp_resource_stats g_lxp_test_resource_stats = {
	.program_region_bytes = 256u * 1024u,
	.dynamic_pool_bytes = 512u * 1024u,
	.total_bytes = 6u * 1024u * 1024u,
	.free_bytes = 3840u * 1024u,
	.available_bytes = 3072u * 1024u,
	.slots_total = 12,
	.slots_free = 9,
	.regions_total = 8,
	.regions_free = 5,
	.processes = 1,
};

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
int lxp_mem_stats(struct lxp_mem_stats *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	if (g_lxp_test_mem_stats_result != LXP_OK) {
		memset(out, 0, sizeof(*out));
		return g_lxp_test_mem_stats_result;
	}
	*out = g_lxp_test_mem_stats;
	return LXP_OK;
}
void lxp_get_resource_stats(struct lxp_resource_stats *out)
{
	if (out)
		*out = g_lxp_test_resource_stats;
}
const char *lxp_system_version(void)
{
	return "TestRTOS 1.2.3 ove-abcdef0 lxp-1234567";
}

long lxp_rt_scope_read(char *buf, size_t cap)
{
	(void)buf;
	(void)cap;
	return -1;
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

/* Console tty foreground process group: lxp_run.c owns this in the coordinator; the
 * isolated syscall tests (no lxp_run.c) just need a definition. A file-static gives
 * the TIOCSPGRP/TIOCGPGRP round-trip real behavior on the host. */
static int g_stub_console_fg_pgrp;
void lxp_console_set_fg_pgrp(int pgrp)
{
	g_stub_console_fg_pgrp = pgrp;
}
int lxp_console_fg_pgrp(void)
{
	return g_stub_console_fg_pgrp;
}
uint8_t lxp_console_input_xlate(uint8_t ch)
{
	return ch;
}

#if LXP_ENABLE_DEV_FB
/* A mock display port so the /dev/fb0 driver (src/dev/lxp_dev_fb.c) links + runs on the
 * host. The test entry point publishes it through the same private provider seam
 * lxp_run() uses. */
#include "lxp/lxp_display_ops.h"

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
/* Recorded args of the last coalesced present, so a suite can assert the
 * driver's dirty-rectangle math. */
int g_mock_fb_present_x, g_mock_fb_present_y, g_mock_fb_present_w, g_mock_fb_present_h;
int g_mock_fb_present_calls;
static void mock_fb_present(int x, int y, int w, int h)
{
	g_mock_fb_present_x = x;
	g_mock_fb_present_y = y;
	g_mock_fb_present_w = w;
	g_mock_fb_present_h = h;
	g_mock_fb_present_calls++;
}
/* Recorded last dma2d_submit, so a suite can assert /dev/dma2d validated + forwarded a
 * descriptor (bad descriptors are rejected by the device before reaching here). */
lxp_dma2d_op_t g_mock_dma2d_op;
int g_mock_dma2d_calls;
static int mock_dma2d_init(void)
{
	return 0;
}
static int mock_dma2d_submit(const lxp_dma2d_op_t *op)
{
	g_mock_dma2d_op = *op;
	g_mock_dma2d_calls++;
	return 0;
}
static const lxp_display_ops_t g_mock_disp = {
	.abi_version = LXP_DISPLAY_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_display_ops_t),
	.fb_init = mock_fb_init,
	.fb_get_info = mock_fb_get_info,
	.fb_get_buffer = mock_fb_get_buffer,
	.fb_present = mock_fb_present,
	.dma2d_init = mock_dma2d_init,
	.dma2d_submit = mock_dma2d_submit,
};
const lxp_display_ops_t *lxp_test_display_ops(void)
{
	return &g_mock_disp;
}
#endif
