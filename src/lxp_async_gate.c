/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lxp/lxp_async_gate.h"

#include <string.h>

enum lxp_async_gate_state {
	LXP_ASYNC_IDLE = 0,
	LXP_ASYNC_ACTIVE,
	LXP_ASYNC_COMPLETE,
	/* Cancellation owns the transition until the worker or coordinator has
	 * cleared the request identity and republishes IDLE. */
	LXP_ASYNC_RETIRING,
};

static void gate_retire(lxp_async_gate_t *gate)
{
	gate->request_owner = 0u;
	gate->request_tag = 0u;
	__atomic_store_n(&gate->state, LXP_ASYNC_IDLE, __ATOMIC_RELEASE);
}

void lxp_async_gate_init(lxp_async_gate_t *gate)
{
	if (gate)
		memset(gate, 0, sizeof(*gate));
}

void lxp_async_gate_select(lxp_async_gate_t *gate, uint64_t owner)
{
	if (gate)
		gate->selected_owner = owner;
}

uint64_t lxp_async_gate_selected(const lxp_async_gate_t *gate)
{
	return gate ? gate->selected_owner : 0u;
}

lxp_async_gate_action_t lxp_async_gate_enter(lxp_async_gate_t *gate, uint32_t tag)
{
	if (!gate || gate->selected_owner == 0u)
		return LXP_ASYNC_GATE_SYNC;

	uint32_t state = __atomic_load_n(&gate->state, __ATOMIC_ACQUIRE);
	if (state == LXP_ASYNC_COMPLETE)
		return gate->request_owner == gate->selected_owner && gate->request_tag == tag
			       ? LXP_ASYNC_GATE_COLLECT
			       : LXP_ASYNC_GATE_BLOCK;
	if (state != LXP_ASYNC_IDLE)
		return LXP_ASYNC_GATE_BLOCK;

	/* Only the coordinator enters requests. Publish identity before ACTIVE so
	 * cancellation observes one complete transaction key. */
	gate->request_owner = gate->selected_owner;
	gate->request_tag = tag;
	__atomic_store_n(&gate->state, LXP_ASYNC_ACTIVE, __ATOMIC_RELEASE);
	return LXP_ASYNC_GATE_SUBMIT;
}

void lxp_async_gate_abort(lxp_async_gate_t *gate)
{
	if (!gate)
		return;
	uint32_t expected = LXP_ASYNC_ACTIVE;
	if (__atomic_compare_exchange_n(&gate->state, &expected, LXP_ASYNC_RETIRING, 0,
					__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		gate_retire(gate);
}

lxp_async_gate_publish_t lxp_async_gate_complete(lxp_async_gate_t *gate)
{
	if (!gate)
		return LXP_ASYNC_GATE_DROP;
	uint32_t expected = LXP_ASYNC_ACTIVE;
	if (__atomic_compare_exchange_n(&gate->state, &expected, LXP_ASYNC_COMPLETE, 0,
					__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return LXP_ASYNC_GATE_WAKE;
	return LXP_ASYNC_GATE_DROP;
}

void lxp_async_gate_dropped(lxp_async_gate_t *gate)
{
	if (gate && __atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) == LXP_ASYNC_RETIRING)
		gate_retire(gate);
}

void lxp_async_gate_collected(lxp_async_gate_t *gate)
{
	if (!gate)
		return;
	uint32_t expected = LXP_ASYNC_COMPLETE;
	if (__atomic_compare_exchange_n(&gate->state, &expected, LXP_ASYNC_RETIRING, 0,
					__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		gate_retire(gate);
}

lxp_async_gate_cancel_t lxp_async_gate_cancel(lxp_async_gate_t *gate, uint64_t owner)
{
	if (!gate || owner == 0u)
		return LXP_ASYNC_GATE_CANCEL_NONE;

	for (;;) {
		uint32_t state = __atomic_load_n(&gate->state, __ATOMIC_ACQUIRE);
		if ((state != LXP_ASYNC_ACTIVE && state != LXP_ASYNC_COMPLETE) ||
		    gate->request_owner != owner)
			return LXP_ASYNC_GATE_CANCEL_NONE;
		uint32_t expected = state;
		if (!__atomic_compare_exchange_n(&gate->state, &expected, LXP_ASYNC_RETIRING, 0,
						 __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			continue;
		if (state == LXP_ASYNC_COMPLETE)
			return LXP_ASYNC_GATE_CANCEL_COMPLETE;
		return LXP_ASYNC_GATE_CANCEL_ACTIVE;
	}
}
