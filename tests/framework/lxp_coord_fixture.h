/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Shared set-up for the coordinator tests (tests/framework/lxp_coord_fixture.c): the
 * per-test reset and helpers that build coordinator states several suites start from.
 */
#ifndef LXP_COORD_FIXTURE_H
#define LXP_COORD_FIXTURE_H

#include "lxp_mock_engine.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_exec_private.h"
#include "run/lxp_image.h"

/* cmocka setup for every coordinator test: empty process pools, slots, regions, signal
 * stacks and diagnostics; the mock engine's memory and record cleared and the engine
 * published; no run configuration, a closed trap gate, no failpoint and a fresh console. */
int reset_state(void **state);

/* Make @p slot a live, running process whose address space is region @p region. */
void make_valid_running_slot(int slot, int region);

/* An image transaction for @p slot with region @p region reserved and a live process image
 * prepared in it, ready to publish. */
void prepare_mock_image_txn(struct image_txn *tx, int slot, int region);

/* Park @p p in wait4() for @p pid with @p options, reporting the status to @p status. */
void set_child_wait(lxp_proc_t *p, int pid, int options, int *status);

#endif /* LXP_COORD_FIXTURE_H */
