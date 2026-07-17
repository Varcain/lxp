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
 * cannot submit again; a mailbox collision fails closed) but nothing measured
 * how long the coordinator actually holds an event, so "no unbounded
 * guest-controlled path" was an argument rather than a number. This records the
 * two quantities that argument rests on:
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

#ifndef LXP_ENABLE_LATENCY
#define LXP_ENABLE_LATENCY 0
#endif

/*
 * The coordinator's event classes, in dispatch order.
 *
 * Declared here rather than beside the dispatch switch so that the enum, the
 * counter array's bound and the names a port prints all expand from one list:
 * adding an event class cannot leave a stats row unlabelled or the array one
 * short. lxp_run.c builds its dispatch enum from this, so the list is needed
 * whether or not the counters are compiled in — keep it outside the gate.
 */
#define LXP_LAT_CLASS_LIST(X)                                                  \
	X(EXIT)                                                                \
	X(EXEC)                                                                \
	X(FORK)                                                                \
	X(DEFER)                                                               \
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
/* Exponential buckets: [0]<1us, [1]<2us, [2]<4us ... [7]>=64us. The top bucket
 * is open-ended, so a max_ns far above 64us reads as an outlier rather than
 * being lost in it. */
#define LXP_LAT_BUCKETS 8

typedef struct lxp_lat_stat {
	uint32_t count;			  /**< events recorded */
	uint32_t max_ns;		  /**< worst observed, nanoseconds */
	uint32_t buckets[LXP_LAT_BUCKETS]; /**< distribution, see LXP_LAT_BUCKETS */
} lxp_lat_stat_t;

#if LXP_ENABLE_LATENCY

/** Clear every counter. Called from lxp_run() start. */
void lxp_lat_reset(void);

/**
 * Record @p ns into a caller-owned @p s.
 *
 * The module's own counters are kept with this. It is public so a port can
 * measure a host-side quantity (e.g. how late a periodic task woke while the
 * coordinator held a critical section) into the same buckets — those numbers
 * are only meaningful against the coordinator's if both are binned identically,
 * and a second copy of the bucket rule is a second thing to drift.
 */
void lxp_lat_record(lxp_lat_stat_t *s, uint64_t ns);

/** Record one coordinator dispatch of class @p cls taking @p ns nanoseconds. */
void lxp_lat_service(int cls, uint64_t ns);

/** Record one publish-to-claim wait of @p ns nanoseconds for slot @p slot. */
void lxp_lat_wake(int slot, uint64_t ns);

/** Read a class's service stats, or NULL if @p cls is out of range. */
const lxp_lat_stat_t *lxp_lat_service_get(int cls);

/** Read a slot's wake stats, or NULL if @p slot is out of range. */
const lxp_lat_stat_t *lxp_lat_wake_get(int slot);

/** Name of event class @p cls ("EXIT", "DEFER", ...), or "?" if out of range. */
const char *lxp_lat_class_name(int cls);

#else /* compile to nothing */

static inline void lxp_lat_reset(void)
{
}
static inline void lxp_lat_record(lxp_lat_stat_t *s, uint64_t ns)
{
	(void)s;
	(void)ns;
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
static inline const char *lxp_lat_class_name(int cls)
{
	(void)cls;
	return "?";
}

#endif /* LXP_ENABLE_LATENCY */

#endif /* LXP_LATENCY_H */
