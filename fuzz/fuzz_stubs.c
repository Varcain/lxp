/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator stubs for the fuzz build. The harnesses link the module set minus
 * the coordinator (src/lxp_run.c), exactly like the host test stub. Most of the
 * coordinator surface the module references (clock, cache, process-group
 * signaling, rootfs bounds, device wakeups) comes from tests/stub_lnx_run.c; the
 * only symbols left undefined are the three lxp_signal.c reaches into the
 * coordinator for. Mirror
 * tests/suites/test_signal.c's stubs so lxp_signal.c links and any signal path a
 * harness happens to reach behaves predictably (single-slot, no real parking).
 */
#include "lxp/lxp_seam.h"
#include "lxp_syscall.h"
#include "lxp_run_internal.h" /* signal-save stack + LXP_NSLOT */

#include <stdint.h>

struct sig_save_stack_s g_sig_save[LXP_NSLOT];

int slot_of(const lxp_proc_t *p)
{
	(void)p;
	return 0;
}

void park_frame(struct lxp_frame *f, lxp_proc_t *proc)
{
	(void)f;
	(void)proc;
}

