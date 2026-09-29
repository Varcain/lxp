/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator diagnostics (src/run/lxp_diag.c): what the run loop tells them, and the
 * state they keep between its calls.
 */
#ifndef LXP_RUN_DIAG_H
#define LXP_RUN_DIAG_H

#include <stdint.h>

#include "lxp/lxp_config.h"
#include "lxp/lxp_diag.h"

struct lxp_diag_state {
	/* The native-task census taken by the last lxp_diag_refresh(): whether it is known,
	 * which slots had a live host task, and the lifecycle epoch it describes. */
	uint8_t native_known;
	uint8_t native_present[LXP_NSLOT];
	uint32_t lifecycle_epoch;
	uint32_t native_epoch;
	lxp_diag_health_t health;
};

/* Start a run with no census and a clean health record. */
void lxp_diag_run_begin(void);
/* Drop the census (the host tasks it described are gone). */
void lxp_diag_forget_natives(void);
/* A slot changed hands: a census taken before is stale. */
void lxp_diag_lifecycle_changed(void);
/* Rebuild the ps/top snapshot and the native-task census (run-loop thread only). */
void lxp_diag_refresh(void);
/* Validate the world and record the outcome in the health record. */
void lxp_diag_checkpoint(void);
void lxp_diag_reset_health(void);

#endif /* LXP_RUN_DIAG_H */
