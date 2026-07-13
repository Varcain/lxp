/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Coordinator stubs for the fuzz build. The harnesses link the module set minus
 * the coordinator (src/lxp_run.c), exactly like the host test stub. Most of the
 * coordinator surface the module references has weak fallbacks in the module
 * itself (lxp_proc_table / lxp_proc_nslot / lxp_rootfs_bounds / lxp_dev_kick) and
 * the clock/cache hooks come from tests/stub_lnx_run.c; the only symbols left
 * undefined are the three lxp_signal.c reaches into the coordinator for. Mirror
 * tests/suites/test_signal.c's stubs so lxp_signal.c links and any signal path a
 * harness happens to reach behaves predictably (single-slot, no real parking).
 */
#include "lxp/lxp_seam.h"
#include "lxp/lxp_syscall.h"
#include "lxp_run_internal.h" /* struct sig_save_s + LXP_NSLOT */

#include <stdint.h>

struct sig_save_s g_sig_save[LXP_NSLOT];

int slot_of(const lxp_proc_t *p)
{
	(void)p;
	return 0;
}

void park_frame(struct lxp_frame *f)
{
	(void)f;
}

#if LXP_ENABLE_NETFS_EXEC
#include "lxp/lxp_netfs.h"
/* Engine staging buffer for a fetched remote ELF (on target the STM32 backend puts
 * this in SDRAM). The 9P exec-fetch path stages into it; give it real backing so the
 * netfs harness can drive a fetch without the coordinator. */
static uint8_t g_fuzz_exec_stage[64 * 1024];
uint8_t *lxp_netfs_exec_stage(size_t *cap)
{
	if (cap)
		*cap = sizeof(g_fuzz_exec_stage);
	return g_fuzz_exec_stage;
}
#endif
