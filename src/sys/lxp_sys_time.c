/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Time syscalls: clocks, gettimeofday, the sleeps (a timer wait the coordinator
 * resumes), the real-time interval timer behind alarm(), and times().
 */
#include "sys/lxp_sys.h"
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"

/* There is no RTC: wall-clock time is a fixed base epoch (~2026-06-23) + uptime. */
#define LXP_BOOT_EPOCH 1782172800ull

static void now_sec_nsec(int clockid, uint64_t *sec, uint32_t *nsec)
{
	uint64_t ns = 0;
	lxp_time_ns(&ns);
	uint64_t up = ns / 1000000000ull;
	*nsec = (uint32_t)(ns % 1000000000ull);
	/* CLOCK_MONOTONIC(1)/_RAW(4)/BOOTTIME(7) → uptime; REALTIME(0) → wall clock. */
	*sec = (clockid == 0) ? (LXP_BOOT_EPOCH + up) : up;
}

/* Record a wake deadline and ask the run loop to park + delay this proc (the trap
 * context cannot block). The run loop aborts the slot for the duration so the RTOS
 * idle/kernel/other threads run and real time + CPU stats advance — which is what
 * top needs between its two samples. @p reqp is a time32 or (time64) time64 timespec. */
static long sleep_for(lxp_proc_t *proc, uintptr_t reqp, int time64)
{
	uint64_t sec, nsec;
	if (time64) {
		int64_t t[2]; /* time64 {sec, nsec} */
		if (lxp_copy_from_guest(proc, t, reqp, sizeof(t)) != 0)
			return -LXP_EFAULT;
		sec = (uint64_t)t[0];
		nsec = (uint64_t)t[1];
	} else {
		int32_t t[2]; /* time32 {sec, nsec} */
		if (lxp_copy_from_guest(proc, t, reqp, sizeof(t)) != 0)
			return -LXP_EFAULT;
		sec = (uint64_t)(uint32_t)t[0];
		nsec = (uint64_t)(uint32_t)t[1];
	}
	uint64_t dur_us = sec * 1000000ull + nsec / 1000ull;
	if (dur_us > 100000000ull)
		dur_us = 100000000ull; /* clamp to 100 s */
	/* The coordinator evaluates deadlines with lxp_time_us(), so construct
	 * them in that same cross-idle clock domain. */
	uint64_t now_us = 0;
	lxp_time_us(&now_us);
	lxp_wait_t wait = {
		.kind = LXP_WAIT_TIMER,
		.data.timer.deadline_us = now_us + dur_us,
	};
	if (lxp_wait_begin(proc, &wait) != 0)
		return -LXP_EAGAIN;
	return 0;
}

/* (clockid, struct timespec*) — 32-bit time_t */
long lxp_sys_clock_gettime(lxp_proc_t *proc, const long a[6])
{
	uint64_t sec;
	uint32_t nsec;
	now_sec_nsec((int)a[0], &sec, &nsec);
	const int32_t ts[2] = {(int32_t)sec, (int32_t)nsec};
	return lxp_copy_to_guest(proc, (uintptr_t)a[1], ts, sizeof(ts)) != 0 ? -LXP_EFAULT : 0;
}

/* (clockid, struct __kernel_timespec*) — 64-bit */
long lxp_sys_clock_gettime64(lxp_proc_t *proc, const long a[6])
{
	uint64_t sec;
	uint32_t nsec;
	now_sec_nsec((int)a[0], &sec, &nsec);
	const int64_t ts[2] = {(int64_t)sec, (int64_t)nsec};
	return lxp_copy_to_guest(proc, (uintptr_t)a[1], ts, sizeof(ts)) != 0 ? -LXP_EFAULT : 0;
}

/* (struct timeval*, tz) */
long lxp_sys_gettimeofday(lxp_proc_t *proc, const long a[6])
{
	uint64_t sec;
	uint32_t nsec;
	now_sec_nsec(0, &sec, &nsec);
	const int32_t tv[2] = {(int32_t)sec, (int32_t)(nsec / 1000u)};
	return lxp_copy_to_guest(proc, (uintptr_t)a[0], tv, sizeof(tv)) != 0 ? -LXP_EFAULT : 0;
}

/* (req, rem) */
long lxp_sys_nanosleep(lxp_proc_t *proc, const long a[6])
{
	return sleep_for(proc, (uintptr_t)a[0], 0);
}

/* (clockid, flags, req, rem) */
long lxp_sys_clock_nanosleep(lxp_proc_t *proc, const long a[6])
{
	return sleep_for(proc, (uintptr_t)a[2], 0);
}

long lxp_sys_clock_nanosleep_time64(lxp_proc_t *proc, const long a[6])
{
	return sleep_for(proc, (uintptr_t)a[2], 1);
}

/* (which, new, old) — ITIMER_REAL -> SIGALRM (alarm()) */
long lxp_sys_setitimer(lxp_proc_t *proc, const long a[6])
{
	int which = (int)a[0];
	const void *unew = (const void *)(uintptr_t)a[1];
	void *uold = (void *)(uintptr_t)a[2];
	if (which != LXP_ITIMER_REAL)
		return 0; /* only the real-time timer (login timeout, ping interval) */
	/* struct itimerval { timeval it_interval; timeval it_value; }; ARM32 long=4,
	 * so it is 4 x u32: [interval_sec, interval_usec, value_sec, value_usec]. */
	uint64_t now = 0;
	lxp_time_us(&now);
	if (uold) {
		uint32_t ov[4] = {0, 0, 0, 0};
		uint64_t rem = (proc->alarm_deadline_us && proc->alarm_deadline_us > now)
				       ? proc->alarm_deadline_us - now
				       : 0;
		ov[0] = (uint32_t)(proc->alarm_interval_us / 1000000u);
		ov[1] = (uint32_t)(proc->alarm_interval_us % 1000000u);
		ov[2] = (uint32_t)(rem / 1000000u);
		ov[3] = (uint32_t)(rem % 1000000u);
		if (lxp_copy_to_guest(proc, (uintptr_t)uold, ov, sizeof(ov)) != 0)
			return -LXP_EFAULT;
	}
	if (!unew)
		return 0;
	uint32_t nv[4];
	if (lxp_copy_from_guest(proc, nv, (uintptr_t)unew, sizeof(nv)) != 0)
		return -LXP_EFAULT;
	proc->alarm_interval_us = (uint64_t)nv[0] * 1000000u + nv[1];
	uint64_t val_us = (uint64_t)nv[2] * 1000000u + nv[3];
	proc->alarm_deadline_us = val_us ? now + val_us : 0; /* it_value 0 disarms */
	return 0;
}

/* (struct tms*) — CPU-time accounting; dropbear mixes it into its RNG pool. Report
 * uptime ticks (100 Hz) + zero the per-proc breakdown (not tracked here). Must be >= 0
 * (glibc treats -1 as error). */
long lxp_sys_times(lxp_proc_t *proc, const long a[6])
{
	uint64_t us = 0;
	lxp_time_us(&us);
	long ticks = (long)(us / 10000u); /* CLK_TCK = 100 */
	if (a[0]) {
		const long tms[4] = {ticks, 0, 0, 0}; /* utime, stime, cutime, cstime */
		if (lxp_copy_to_guest(proc, (uintptr_t)a[0], tms, sizeof(tms)) != 0)
			return -LXP_EFAULT;
	}
	return ticks;
}
