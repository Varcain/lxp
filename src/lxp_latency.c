/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Bounded coordinator latency counters. See include/lxp/lxp_latency.h for what
 * is measured and why there is no threshold here.
 */

#include "lxp/lxp_latency.h"

#if LXP_ENABLE_LATENCY

#include "lxp/lxp_config.h"

static lxp_lat_stat_t g_service[LXP_LAT_CLASSES];
static lxp_lat_stat_t g_wake[LXP_NSLOT];

/* Same list as the enum, so index N is always the name of class N. */
static const char *const g_class_name[LXP_LAT_CLASSES] = {
	"none",
#define LXP_LAT_X(n) #n,
	LXP_LAT_CLASS_LIST(LXP_LAT_X)
#undef LXP_LAT_X
};

/* Bucket by magnitude: 0 -> <1us, 1 -> <2us, ... 7 -> >=64us. The shift loop
 * runs at most LXP_LAT_BUCKETS-1 (7) times whatever the input, which is the
 * property that matters here — this runs on the coordinator's own path, so its
 * cost must not be a function of the value a guest produced. */
static unsigned bucket_of(uint64_t ns)
{
	uint64_t us = ns / 1000u;
	unsigned b = 0;
	while (us && b < LXP_LAT_BUCKETS - 1u) {
		us >>= 1;
		b++;
	}
	return b;
}

void lxp_lat_record(lxp_lat_stat_t *s, uint64_t ns)
{
	s->count++;
	/* Saturate rather than wrap: a 32-bit ns max tops out at ~4.29 s, and a
	 * wrapped maximum would read as a small number — the opposite of the
	 * outlier it actually is. */
	uint32_t n = (ns > 0xffffffffu) ? 0xffffffffu : (uint32_t)ns;
	if (n > s->max_ns)
		s->max_ns = n;
	s->buckets[bucket_of(ns)]++;
}

void lxp_lat_reset(void)
{
	for (int i = 0; i < LXP_LAT_CLASSES; i++)
		g_service[i] = (lxp_lat_stat_t){0};
	for (int i = 0; i < LXP_NSLOT; i++)
		g_wake[i] = (lxp_lat_stat_t){0};
}

void lxp_lat_service(int cls, uint64_t ns)
{
	if (cls < 0 || cls >= LXP_LAT_CLASSES)
		return;
	lxp_lat_record(&g_service[cls], ns);
}

void lxp_lat_wake(int slot, uint64_t ns)
{
	if (slot < 0 || slot >= LXP_NSLOT)
		return;
	lxp_lat_record(&g_wake[slot], ns);
}

const lxp_lat_stat_t *lxp_lat_service_get(int cls)
{
	return (cls < 0 || cls >= LXP_LAT_CLASSES) ? 0 : &g_service[cls];
}

const lxp_lat_stat_t *lxp_lat_wake_get(int slot)
{
	return (slot < 0 || slot >= LXP_NSLOT) ? 0 : &g_wake[slot];
}

const char *lxp_lat_class_name(int cls)
{
	return (cls < 0 || cls >= LXP_LAT_CLASSES) ? "?" : g_class_name[cls];
}

#endif /* LXP_ENABLE_LATENCY */
