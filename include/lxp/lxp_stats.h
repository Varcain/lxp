/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Unified process/CPU snapshot for the Linux personality's synthetic /proc
 * (ps/top). The run-loop thread builds it each refresh from the live Linux slots
 * plus the host's @c lxp_os_ops_t.thread_list snapshot; the
 * /proc generator (svc-handler context) only READS it via the accessors. Holding
 * the table here (rather than reaching into the run loop) keeps the engine-agnostic
 * syscall layer free of run-loop symbols, so the host syscall tests link cleanly.
 */

#ifndef LXP_STATS_H
#define LXP_STATS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_types.h"

/* One bounded snapshot must hold every configured guest plus an explicit host
 * allowance. The extra pentry is reserved for a visible overflow marker. */
#ifndef LXP_HOST_THREAD_ALLOWANCE
#define LXP_HOST_THREAD_ALLOWANCE 16
#endif
#define LXP_MAX_KTHREAD (LXP_NSLOT + LXP_HOST_THREAD_ALLOWANCE)
#define LXP_MAX_PENT (LXP_MAX_KTHREAD + 1)
#define LXP_KPID_BASE 1000 /* kernel pids start here; Linux pids are 1..~16 */

/* One entry shown by ps/top: a Linux process or an RTOS kernel thread. */
struct lxp_pentry {
	int pid;
	int ppid;
	char comm[16];	 /* program name; rendered "[name]" when is_kernel */
	char state;	 /* 'R' running, 'S' sleeping */
	uint64_t cpu_us; /* cumulative CPU time (µs) */
	int nice;        /* Linux nice value; zero for host kernel threads */
	int is_kernel;
	int live;
};

/* ---- written by the run-loop thread only ---------------------------------- */
void lxp_stats_reset(void); /* clear everything (at lxp_run start) */
/* Reclaim cumulative-CPU records whose Linux PID was absent from the previous
 * completed snapshot. Call once at the start of each refresh. */
void lxp_stats_prune(void);
void lxp_stats_begin(void); /* start a refresh: mark all entries not-live */
/* Add/update one entry (matched by pid). */
int lxp_stats_add(int pid, int ppid, const char *comm, char state, uint64_t cpu_us,
		      int nice, int is_kernel);
/* Charge a slice of a Linux process's CPU: accumulate (thread_running_us - baseline)
 * across native-task replacement during exec, and return the process total. */
uint64_t lxp_stats_charge(int pid, uint64_t thread_running_us);
/* Read a Linux pid's accumulated CPU without charging (for parked procs). */
uint64_t lxp_proc_cpu_us(int pid);
/* Classify a host-thread name: idle (->1), else 0. Guest ownership is explicit. */
int lxp_stats_classify(const char *name);
/* Stable synthetic pid for a kernel thread name, or -1 if the registry is full. */
int lxp_kpid_for(const char *name);
void lxp_stats_set_cpu(uint64_t idle_us, uint64_t busy_us);

/* ---- read by the /proc generator (any context) ---------------------------- */
int lxp_pent_count(void);			     /* live entries */
const struct lxp_pentry *lxp_pent_at(int i); /* i-th LIVE entry */
const struct lxp_pentry *lxp_pent_find(int pid);
void lxp_cpu_totals(uint64_t *idle_us, uint64_t *busy_us);

#endif /* LXP_STATS_H */
