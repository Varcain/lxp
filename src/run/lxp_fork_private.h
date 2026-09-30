/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private fork transaction. Included only by the fork owner and its white-box
 * tests; other coordinator policies see only lxp_handle_fork().
 */
#ifndef LXP_FORK_PRIVATE_H
#define LXP_FORK_PRIVATE_H

#include "run/lxp_coordinator.h"

enum fork_txn_phase {
	FORK_TXN_EMPTY,
	FORK_TXN_PREPARING,
	FORK_TXN_PREPARED,
	FORK_TXN_PUBLISHED,
	FORK_TXN_COMMITTED,
	FORK_TXN_ABORTED,
};

struct fork_txn {
	lxp_proc_t *parent;
	lxp_proc_t *child;
	lxp_slot_ref_t parent_ref;
	lxp_slot_ref_t child_ref;
	lxp_region_ref_t parent_region;
	enum fork_txn_phase phase;
	uint8_t region_acquired;
	uint8_t child_constructed;
	uint8_t maps_touched;
	uint8_t child_counted;
};

int lxp_fork_txn_prepare(struct fork_txn *tx, int parent_slot, int child_slot,
					  uint32_t clone_flags, int child_pid);
int lxp_fork_txn_count_child(struct fork_txn *tx);
int lxp_fork_txn_snapshot(struct fork_txn *tx, uintptr_t parent_sp);
int lxp_fork_txn_publish(struct fork_txn *tx);
void lxp_fork_txn_abort(struct fork_txn *tx);
int lxp_fork_txn_commit(struct fork_txn *tx);

#endif /* LXP_FORK_PRIVATE_H */
