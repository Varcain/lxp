/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fuzz target: the 9P2000.L reply parser (handle_reply / parse_getattr in
 * src/netfs/lxp_netfs.c) — the untrusted bytes a (possibly hostile) 9P server sends
 * back. Unlike the pure parsers this is a stateful protocol machine over ~20 file-scope
 * statics, so it is driven through the gated LXP_FUZZ shim: reset the module to a known
 * state, then feed one R-message as if it completed an in-flight request of a
 * fuzzer-chosen (op, step). Exercises the Stage-3 blen<4 read/getdents underflow guards
 * and parse_getattr's 97-byte-span guard, with ASan on the guest marshal buffer.
 *
 * Structured input: [op][step][type][is64][statkind] header byte-per-field, then the
 * rest is the R-message body.
 */
#include "fuzz_common.h"

#include "lxp/lxp_arena.h"
#include "lxp/lxp_netfs.h" /* LXP_NETFSW_* */
#include "lxp/lxp_syscall.h"

#include <stdint.h>

/* the LXP_FUZZ shim, defined in src/netfs/lxp_netfs.c */
void lxp_netfs_fuzz_reset(void);
void lxp_netfs_fuzz_feed(lxp_proc_t *owner, uintptr_t ubuf, size_t ulen, unsigned op,
			 unsigned step, int is64, int statkind, uint8_t type, const uint8_t *body,
			 size_t blen);

static uint8_t g_pool[64 * 1024] __attribute__((aligned(16)));
static uint8_t g_guest[8192]; /* the parked guest's marshal buffer (ubuf) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_cursor_t c = {data, size};
	unsigned op_sel = fuzz_u8(&c);
	unsigned step = fuzz_u8(&c) % 3u; /* the parser's steps are 0..2 */
	uint8_t type = fuzz_u8(&c);	  /* 9P reply type (P9_R*) — fuzzer-controlled */
	int is64 = fuzz_u8(&c) & 1;
	int statkind = (int)fuzz_u8(&c);
	const uint8_t *body = c.p; /* remainder = the R-message body */
	size_t blen = c.n;

	static const unsigned ops[] = {LXP_NETFSW_OPEN, LXP_NETFSW_READ, LXP_NETFSW_GETDENTS,
				       LXP_NETFSW_STAT};
	unsigned op = ops[op_sel % (sizeof(ops) / sizeof(ops[0]))];

	lxp_arena_t arena;
	lxp_proc_t p;
	if (lxp_arena_init(&arena, g_pool, sizeof(g_pool)) != LXP_OK)
		return 0;
	if (lxp_proc_init(&p, &arena, 4096) != LXP_OK)
		return 0;
	p.region_lo = 1;
	p.region_hi = UINTPTR_MAX;
	p.pool_lo = p.pool_hi = 0;

	lxp_netfs_fuzz_reset();
	lxp_netfs_fuzz_feed(&p, (uintptr_t)g_guest, sizeof(g_guest), op, step, is64, statkind, type,
			    body, blen);
	return 0;
}
