/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator event-publication and fair-claim module. Unity-included
 * by lxp_run.c; see src/run/lxp_lifecycle.c.
 */

struct lxp_claimed_event {
	int slot;
	int type;
};

static void primary_slot_mark(int slot)
{
	if (slot < 0 || slot >= LXP_NSLOT)
		return;
	unsigned word = (unsigned)slot / LXP_EVENT_WORD_BITS;
	uint32_t bit = (uint32_t)1u << ((unsigned)slot % LXP_EVENT_WORD_BITS);
	__atomic_fetch_or(&g_primary_pending[word], bit, __ATOMIC_RELEASE);
}

static int primary_slot_pending(int slot)
{
	unsigned word = (unsigned)slot / LXP_EVENT_WORD_BITS;
	uint32_t bit = (uint32_t)1u << ((unsigned)slot % LXP_EVENT_WORD_BITS);
	return (__atomic_load_n(&g_primary_pending[word], __ATOMIC_ACQUIRE) & bit) != 0;
}

static void primary_slot_clear(int slot)
{
	unsigned word = (unsigned)slot / LXP_EVENT_WORD_BITS;
	uint32_t bit = (uint32_t)1u << ((unsigned)slot % LXP_EVENT_WORD_BITS);
	__atomic_fetch_and(&g_primary_pending[word], ~bit, __ATOMIC_RELAXED);
}

/* Publish a primary per-slot event and wake the coordinator. Ports use this for
 * contained guest faults; normal syscall/signal parking reaches it through
 * park_frame(). Safe when the slot is stale: the coordinator simply clears a
 * hint that fails revalidation. */
static void lxp_event_post_slot(int slot)
{
	primary_slot_mark(slot);
	if (g_eng && g_eng->event_post)
		g_eng->event_post();
}

/* Inspect one slot's highest-priority event. The caller holds the engine
 * critical section, so a program SVC cannot change a flag between test and
 * clear. */
static int claim_slot_event(int s)
{
	lxp_proc_t *p = &g_lxp_slots[s].proc;

	if (!p->alive)
		return LXP_EV_NONE;
	if (p->intent.kind == LXP_INTENT_EXIT)
		return LXP_EV_EXIT;
	if (p->intent.kind == LXP_INTENT_EXEC)
		return LXP_EV_EXEC;
	if (p->intent.kind == LXP_INTENT_FORK)
		return LXP_EV_FORK;
	if (p->intent.kind == LXP_INTENT_DEFERRED_SYSCALL && deferred_state_load(s) == DEFER_READY)
		return LXP_EV_DEFER;
	if (!slot_runnable_load(s))
		return LXP_EV_NONE;
	switch (p->wait.kind) {
	case LXP_WAIT_TIMER:
		return LXP_EV_SLEEP;
	case LXP_WAIT_FUTEX:
		return LXP_EV_FUTEXWAIT;
	case LXP_WAIT_CHILD:
		return LXP_EV_WAITPARK;
	case LXP_WAIT_PIPE:
		return LXP_EV_PIPE;
	case LXP_WAIT_DEVICE:
		return LXP_EV_DEVWAIT;
	case LXP_WAIT_SOCKET:
		return LXP_EV_SOCKWAIT;
#if LXP_ENABLE_NETFS
	case LXP_WAIT_NETFS:
		return LXP_EV_NETFSWAIT;
#endif
#if LXP_ENABLE_PTY
	case LXP_WAIT_PTY:
		return LXP_EV_PTYWAIT;
#endif
	case LXP_WAIT_SIGSUSPEND:
		return LXP_EV_SIGSUSPEND;
	case LXP_WAIT_CONSOLE:
		return LXP_EV_CONSOLEWAIT;
	default:
		return LXP_EV_NONE;
	}
}

/* Claim at most one event. Cursor rotation is part of the API so fairness is
 * directly testable independently of the coordinator loop. Handler work stays
 * outside the bounded critical section. */
static struct lxp_claimed_event coordinator_claim_event(const lxp_os_ops_t *eng, unsigned *cursor)
{
	struct lxp_claimed_event claimed = {
		.slot = -1,
		.type = LXP_EV_NONE,
	};
	if (!eng || !cursor)
		return claimed;

	for (int i = 0; i < LXP_NSLOT; i++) {
		int s = (int)((*cursor + (unsigned)i) % LXP_NSLOT);
		if (!primary_slot_pending(s))
			continue;
		eng->crit_enter();
		primary_slot_clear(s);
		int type = claim_slot_event(s);
		eng->crit_exit();
		if (type == LXP_EV_NONE)
			continue;
		claimed.slot = s;
		claimed.type = type;
		*cursor = ((unsigned)s + 1u) % LXP_NSLOT;
		break;
	}
	return claimed;
}
