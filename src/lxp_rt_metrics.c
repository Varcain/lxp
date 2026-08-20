/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_linux_uapi.h"
#include "lxp/lxp_rt_metrics.h"

#if LXP_ENABLE_RT_METRICS
/* The SVC path is the sole writer on supported single-core targets. Switching
 * the active window first leaves the retired bucket quiescent. The lifetime
 * sequence protects its 64-bit sum from a torn task-context read. */
static volatile uint32_t g_active;
static lxp_rt_svc_metrics_t g_window[2] = {
	{.min_cycles = UINT32_MAX},
	{.min_cycles = UINT32_MAX},
};
static volatile uint32_t g_total_seq;
static lxp_rt_svc_metrics_t g_total = {
	.min_cycles = UINT32_MAX,
};

static void metrics_add(lxp_rt_svc_metrics_t *metrics, uint32_t syscall_nr, uint32_t cycles)
{
	if (metrics->calls == 0u || cycles < metrics->min_cycles)
		metrics->min_cycles = cycles;
	if (metrics->calls == 0u || cycles > metrics->max_cycles) {
		metrics->max_cycles = cycles;
		metrics->max_syscall = syscall_nr;
	}
	metrics->calls++;
	metrics->total_cycles += cycles;
}
#endif

void lxp_rt_svc_metrics_record(uint32_t syscall_nr, uint32_t cycles)
{
#if LXP_ENABLE_RT_METRICS
	uint32_t active = g_active;
	metrics_add(&g_window[active], syscall_nr, cycles);

	g_total_seq++;
	__asm__ volatile("" ::: "memory");
	metrics_add(&g_total, syscall_nr, cycles);
	__asm__ volatile("" ::: "memory");
	g_total_seq++;
#else
	(void)syscall_nr;
	(void)cycles;
#endif
}

void lxp_rt_svc_metrics_snapshot(lxp_rt_svc_metrics_t *total)
{
	if (!total)
		return;
#if LXP_ENABLE_RT_METRICS
	uint32_t before;
	uint32_t after;
	do {
		before = g_total_seq;
		__asm__ volatile("" ::: "memory");
		*total = g_total;
		__asm__ volatile("" ::: "memory");
		after = g_total_seq;
	} while (before != after || (after & 1u) != 0u);
#else
	*total = (lxp_rt_svc_metrics_t){0};
#endif
}

void lxp_rt_svc_metrics_take(lxp_rt_svc_metrics_t *window, lxp_rt_svc_metrics_t *total)
{
	if (!window || !total)
		return;
#if LXP_ENABLE_RT_METRICS
	uint32_t old_active = g_active;
	g_active = old_active ^ 1u;
	__asm__ volatile("" ::: "memory");

	*window = g_window[old_active];
	g_window[old_active] = (lxp_rt_svc_metrics_t){.min_cycles = UINT32_MAX};
	lxp_rt_svc_metrics_snapshot(total);
#else
	*window = (lxp_rt_svc_metrics_t){0};
	*total = (lxp_rt_svc_metrics_t){0};
#endif
}

const char *lxp_rt_syscall_name(uint32_t syscall_nr)
{
	struct syscall_name {
		uint32_t nr;
		const char *name;
	};
#define LXP_RT_NAME(name) {LXP_NR_##name, #name}
	static const struct syscall_name names[] = {
		LXP_RT_NAME(exit),
		LXP_RT_NAME(exit_group),
		LXP_RT_NAME(fork),
		LXP_RT_NAME(vfork),
		LXP_RT_NAME(clone),
		LXP_RT_NAME(read),
		LXP_RT_NAME(write),
		LXP_RT_NAME(writev),
		LXP_RT_NAME(pread64),
		LXP_RT_NAME(pwrite64),
		LXP_RT_NAME(open),
		LXP_RT_NAME(openat),
		LXP_RT_NAME(close),
		LXP_RT_NAME(ioctl),
		LXP_RT_NAME(brk),
		LXP_RT_NAME(mmap2),
		LXP_RT_NAME(munmap),
		LXP_RT_NAME(mprotect),
		LXP_RT_NAME(getpid),
		LXP_RT_NAME(getppid),
		LXP_RT_NAME(gettid),
		LXP_RT_NAME(sched_yield),
		LXP_RT_NAME(futex),
		LXP_RT_NAME(futex_time64),
		LXP_RT_NAME(nanosleep),
		LXP_RT_NAME(clock_gettime),
		LXP_RT_NAME(clock_gettime64),
		LXP_RT_NAME(gettimeofday),
		LXP_RT_NAME(poll),
		LXP_RT_NAME(ppoll_time64),
		LXP_RT_NAME(pselect6_time64),
		LXP_RT_NAME(rt_sigaction),
		LXP_RT_NAME(rt_sigprocmask),
		LXP_RT_NAME(rt_sigsuspend),
		LXP_RT_NAME(sigreturn),
		LXP_RT_NAME(rt_sigreturn),
		LXP_RT_NAME(kill),
		LXP_RT_NAME(tkill),
		LXP_RT_NAME(tgkill),
		LXP_RT_NAME(socket),
		LXP_RT_NAME(bind),
		LXP_RT_NAME(connect),
		LXP_RT_NAME(listen),
		LXP_RT_NAME(accept),
		LXP_RT_NAME(accept4),
		LXP_RT_NAME(send),
		LXP_RT_NAME(sendto),
		LXP_RT_NAME(sendmsg),
		LXP_RT_NAME(recv),
		LXP_RT_NAME(recvfrom),
		LXP_RT_NAME(recvmsg),
		LXP_RT_NAME(shutdown),
		LXP_RT_NAME(getsockname),
		LXP_RT_NAME(getpeername),
		LXP_RT_NAME(setsockopt),
		LXP_RT_NAME(getsockopt),
	};
#undef LXP_RT_NAME
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
		if (names[i].nr == syscall_nr)
			return names[i].name;
	}
	return "?";
}
