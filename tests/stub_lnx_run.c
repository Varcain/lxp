/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Host run-loop stubs. The unit tests drive lxp_syscall() directly and do NOT link the
 * coordinator (src/lxp_run.c). The OS services (clock, entropy, cache maintenance, exec
 * staging, memory statistics) go through the real wrappers in src/lxp_provider.c, which
 * route to the mock engine published below: a monotonic host clock, deterministic entropy
 * and cache hooks that only count their calls (a coherent host has nothing to maintain).
 * The coordinator's own services are stubbed further down.
 */
#include "lxp_syscall.h"
#include "lxp_internal.h"
#include "lxp_provider.h"

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

/* The engine's exec staging RAM (on target the STM32 backend puts it in SDRAM): netfs
 * exec fetches and tmpfs execs copy their image into it. */
static uint8_t g_lxp_test_exec_stage[64 * 1024];
static uint8_t *mock_exec_stage(size_t *cap)
{
	if (cap)
		*cap = sizeof(g_lxp_test_exec_stage);
	return g_lxp_test_exec_stage;
}

static int mock_random_fill(void *buf, size_t len)
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

static int mock_time_us(uint64_t *out)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	*out = (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
	return 0;
}

static int mock_time_ns(uint64_t *out)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	*out = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	return 0;
}

static int mock_mem_stats(struct lxp_mem_stats *out)
{
	if (g_lxp_test_mem_stats_result != LXP_OK)
		return g_lxp_test_mem_stats_result;
	*out = g_lxp_test_mem_stats;
	return LXP_OK;
}

void lxp_get_resource_stats(struct lxp_resource_stats *out)
{
	if (out)
		*out = g_lxp_test_resource_stats;
}
static const char *mock_system_version(void)
{
	return "TestRTOS 1.2.3 ove-abcdef0 lxp-1234567";
}

lxp_identity_t lxp_identity(void)
{
	return (lxp_identity_t){LXP_DEFAULT_NODENAME, LXP_DEFAULT_FB_ID, LXP_DEFAULT_INPUT_NAME};
}

long lxp_rt_scope_read(char *buf, size_t cap)
{
	(void)buf;
	(void)cap;
	return -1;
}
static void mock_cache_clean(const void *base, size_t len)
{
	g_lxp_test_cache_clean_calls++;
	g_lxp_test_cache_clean_base = base;
	g_lxp_test_cache_clean_len = len;
}

static void mock_cache_invalidate(const void *base, size_t len)
{
	g_lxp_test_cache_invalidate_calls++;
	g_lxp_test_cache_invalidate_base = base;
	g_lxp_test_cache_invalidate_len = len;
}

/* Only the OS-service hooks: nothing here runs a task, so the lifecycle ops stay NULL. */
static const lxp_os_ops_t g_lxp_test_engine = {
	.time_us = mock_time_us,
	.time_ns = mock_time_ns,
	.random_fill = mock_random_fill,
	.exec_stage = mock_exec_stage,
	.mem_stats = mock_mem_stats,
	.system_version = mock_system_version,
	.cache_clean = mock_cache_clean,
	.cache_invalidate = mock_cache_invalidate,
};

/* Every test and fuzz binary that links these stubs runs with the mock engine. */
__attribute__((constructor)) static void publish_test_engine(void)
{
	lxp_os_publish(&g_lxp_test_engine);
}

/* The coordinator's process table is absent: record process-group signal
 * requests so terminal signal routing can be asserted. */
int g_lxp_test_signal_calls;
int g_lxp_test_signal_pgid;
int g_lxp_test_signal_number;
int lxp_signal_process_group(int pgid, int sig)
{
	g_lxp_test_signal_calls++;
	g_lxp_test_signal_pgid = pgid;
	g_lxp_test_signal_number = sig;
	return 1;
}

/* No shared executable rootfs window: user pointers must fall in the guest's own
 * regions. */
void lxp_rootfs_bounds(uintptr_t *lo, uintptr_t *hi)
{
	*lo = 0;
	*hi = 0;
}

/* Console input without the coordinator: no ^C/^Z check runs, so there is never
 * typeahead and reads go straight to the transport. */
int lxp_console_input_ready(const lxp_proc_t *proc)
{
	return proc && proc->console_poll && proc->console_poll(proc->io_ctx) > 0;
}
long lxp_console_read(lxp_proc_t *proc, int fd, void *buf, size_t len)
{
	return proc->read_fn ? proc->read_fn(proc->io_ctx, fd, buf, len) : 0;
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
static const lxp_fb_ops_t g_mock_fb_ops = {
	.init = mock_fb_init,
	.get_info = mock_fb_get_info,
	.get_buffer = mock_fb_get_buffer,
	.present = mock_fb_present,
};
static const lxp_dma2d_ops_t g_mock_dma2d_ops = {
	.init = mock_dma2d_init,
	.submit = mock_dma2d_submit,
};
static const lxp_display_ops_t g_mock_disp = {
	.fb = &g_mock_fb_ops,
	.dma2d = &g_mock_dma2d_ops,
};
const lxp_display_ops_t *lxp_test_display_ops(void)
{
	return &g_mock_disp;
}
#endif
