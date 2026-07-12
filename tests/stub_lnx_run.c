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
#include <time.h>

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
	(void)base;
	(void)len;
}
void lxp_cache_invalidate(const void *base, size_t len)
{
	(void)base;
	(void)len;
}
