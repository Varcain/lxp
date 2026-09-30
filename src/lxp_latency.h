/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Bounded coordinator latency instrumentation — measurement only, no policy.
 *
 * The design bounds a guest's influence on the coordinator (a parked guest
 * cannot submit again; a mailbox collision fails closed). This measures how long
 * the coordinator actually holds an event, recording the two quantities that
 * bound rests on:
 *
 *   service  — how long the coordinator spends dispatching one event. A guest
 *              picks the class (a 64K file copy and a getpid are both one
 *              event), so this is where a guest could hold the coordinator.
 *   wake     — how long an event waits between the guest publishing it and the
 *              coordinator claiming it. This is what a syscall flood from one
 *              guest would inflate for another.
 *
 * Deliberately NOT here: any threshold. Nothing fails, warns, or is enforced —
 * the numbers come first and the limit is a decision to be taken from them.
 *
 * Off unless LXP_ENABLE_LATENCY=1, and then it costs one lxp_time_ns() per
 * event plus a fixed-size counter update. No allocation, no unbounded work, and
 * every path compiles to nothing when disabled.
 */
#ifndef LXP_LATENCY_H
#define LXP_LATENCY_H

#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_observe.h"
#include "lxp/lxp_types.h"

/*
 * The coordinator's event classes, in dispatch order.
 *
 * Declared here rather than beside the dispatch switch so that the enum, the
 * counter array's bound and the names a port prints all expand from one list:
 * adding an event class cannot leave a stats row unlabelled or the array one
 * short. The coordinator's event-class enum is built from this, so the list is
 * needed whether or not the counters are compiled in — keep it outside the gate.
 */
#define LXP_LAT_CLASS_LIST(X)                                                  \
	X(EXIT)                                                                \
	X(EXEC)                                                                \
	X(FORK)                                                                \
	X(DEFER)                                                               \
	X(STOP)                                                                \
	X(SLEEP)                                                               \
	X(FUTEXWAIT)                                                           \
	X(WAITPARK)                                                            \
	X(PIPE)                                                                \
	X(DEVWAIT)                                                             \
	X(SOCKWAIT)                                                            \
	X(NETFSWAIT)                                                           \
	X(PTYWAIT)                                                             \
	X(SIGSUSPEND)                                                          \
	X(CONSOLEWAIT)

enum lxp_ev_class {
	LXP_EV_NONE = 0, /**< no event in flight; not a countable class */
#define LXP_LAT_X(n) LXP_EV_##n,
	LXP_LAT_CLASS_LIST(LXP_LAT_X)
#undef LXP_LAT_X
	LXP_LAT_CLASSES /**< count, counting LXP_EV_NONE — the array bound */
};
LXP_STATIC_ASSERT(LXP_LAT_CLASSES - 1 == LXP_LAT_SERVICE_ROWS,
		  "an observation holds one service row per event class");

#if LXP_ENABLE_LATENCY

/** Clear every counter. Called from lxp_run() start. */
void lxp_lat_reset(void);

/** Record one coordinator dispatch of class @p cls taking @p ns nanoseconds. */
void lxp_lat_service(int cls, uint64_t ns);

/** Record one publish-to-claim wait of @p ns nanoseconds for slot @p slot. */
void lxp_lat_wake(int slot, uint64_t ns);

/** Read a class's service stats, or NULL if @p cls is out of range. */
const lxp_lat_stat_t *lxp_lat_service_get(int cls);

/** Read a slot's wake stats, or NULL if @p slot is out of range. */
const lxp_lat_stat_t *lxp_lat_wake_get(int slot);

#else /* compile to nothing */

static inline void lxp_lat_reset(void)
{
}
static inline void lxp_lat_service(int cls, uint64_t ns)
{
	(void)cls;
	(void)ns;
}
static inline void lxp_lat_wake(int slot, uint64_t ns)
{
	(void)slot;
	(void)ns;
}
static inline const lxp_lat_stat_t *lxp_lat_service_get(int cls)
{
	(void)cls;
	return 0;
}
static inline const lxp_lat_stat_t *lxp_lat_wake_get(int slot)
{
	(void)slot;
	return 0;
}

#endif /* LXP_ENABLE_LATENCY */

#endif /* LXP_LATENCY_H */
