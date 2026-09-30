/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The debugger interface: what a source-level debugger reads from a running LXP image to
 * find a guest program's symbols. An FDPIC program runs where its loadmap placed each
 * segment, not at its link addresses, so a debugger needs the program's runtime bases and,
 * to walk its shared libraries through the ld.so rendezvous, its _DYNAMIC and ld.so's base.
 *
 * LXP keeps one record per slot in g_lxp_dbg[] and calls lxp_debug_state() after every
 * change, the way ld.so calls _dl_debug_state() after changing its link map: a debugger
 * breaks on lxp_debug_state and reads the record of the slot it was passed. A record
 * describes the program its slot's process exec'd and has a NULL comm while the slot runs
 * none. Forked children and threads run their parent's program and are not listed
 * separately. When a run ends every record is cleared without a call.
 */
#ifndef LXP_DEBUG_H
#define LXP_DEBUG_H

#include <stdint.h>

#include "lxp/lxp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One slot's program, as a debugger reads it. */
typedef struct lxp_debug_image {
	const char *comm;      /**< Program name (argv[0] basename); NULL: no program. */
	uintptr_t text_base;   /**< Runtime base of the text segment. */
	uintptr_t data_base;   /**< Runtime base of the data segment. */
	uintptr_t entry;       /**< The program's entry point (AT_ENTRY). */
	uintptr_t dynamic;     /**< Its _DYNAMIC; 0 for a static program. */
	uintptr_t interp_base; /**< ld.so's load base (AT_BASE); 0 without an interpreter. */
} lxp_debug_image_t;

/** The program records, indexed by slot. */
extern lxp_debug_image_t g_lxp_dbg[LXP_NSLOT];

/** Called with a slot index after g_lxp_dbg[slot] changes. It does nothing and is never
 *  inlined: it exists to be broken on. */
void lxp_debug_state(int slot);

#ifdef __cplusplus
}
#endif

#endif /* LXP_DEBUG_H */
