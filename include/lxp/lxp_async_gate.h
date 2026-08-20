/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Generation-qualified completion gate for asynchronous host providers.
 */

#ifndef LXP_ASYNC_GATE_H
#define LXP_ASYNC_GATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Result of entering a provider operation. */
typedef enum lxp_async_gate_action {
	/** Owner zero: execute synchronously without changing the gate. */
	LXP_ASYNC_GATE_SYNC = 0,
	/** Snapshot the request and submit it to the provider worker. */
	LXP_ASYNC_GATE_SUBMIT,
	/** Another request owns the provider; the caller must remain parked. */
	LXP_ASYNC_GATE_BLOCK,
	/** The selected owner may collect its saved completion. */
	LXP_ASYNC_GATE_COLLECT,
} lxp_async_gate_action_t;

/** Result of publishing worker completion. */
typedef enum lxp_async_gate_publish {
	LXP_ASYNC_GATE_DROP = 0,
	LXP_ASYNC_GATE_WAKE,
} lxp_async_gate_publish_t;

/** Result of cancelling one generation-qualified owner. */
typedef enum lxp_async_gate_cancel {
	LXP_ASYNC_GATE_CANCEL_NONE = 0,
	LXP_ASYNC_GATE_CANCEL_ACTIVE,
	LXP_ASYNC_GATE_CANCEL_COMPLETE,
} lxp_async_gate_cancel_t;

/**
 * Zero-heap state shared by one serialized provider worker and the LXP
 * coordinator. Fields are public only to permit static allocation; callers
 * must use the operations below rather than modifying them directly.
 */
typedef struct lxp_async_gate {
	uint64_t selected_owner;
	uint64_t request_owner;
	uint32_t request_tag;
	uint32_t state;
} lxp_async_gate_t;

void lxp_async_gate_init(lxp_async_gate_t *gate);

/** Select the generation-qualified owner for the next provider call. */
void lxp_async_gate_select(lxp_async_gate_t *gate, uint64_t owner);
uint64_t lxp_async_gate_selected(const lxp_async_gate_t *gate);

/** Correlate a retry by both owner and provider-defined operation tag. */
lxp_async_gate_action_t lxp_async_gate_enter(lxp_async_gate_t *gate, uint32_t tag);

/** Roll back a SUBMIT decision when snapshotting or queueing fails. */
void lxp_async_gate_abort(lxp_async_gate_t *gate);

/** Publish worker completion, or report that a cancelled result must be dropped. */
lxp_async_gate_publish_t lxp_async_gate_complete(lxp_async_gate_t *gate);

/** Publish IDLE after provider-specific cleanup of a dropped completion. */
void lxp_async_gate_dropped(lxp_async_gate_t *gate);

/** Retire the completion after its result has been copied to the retrying caller. */
void lxp_async_gate_collected(lxp_async_gate_t *gate);

/** Cancel only the request owned by the exact generation-qualified identity. */
lxp_async_gate_cancel_t lxp_async_gate_cancel(lxp_async_gate_t *gate, uint64_t owner);

#ifdef __cplusplus
}
#endif

#endif /* LXP_ASYNC_GATE_H */
