/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fuzz target: the path resolver, resolve_path (src/fs/lxp_path.c) — "." / ".." /
 * duplicate-slash normalization + cwd join + the LXP_PATH_MAX bound — and the rootfs
 * lookup + symlink follow, lxp_rootfs_resolve. The fuzzer bytes become the untrusted
 * path string; a small fixed rootfs with a symlink drives the follow loop. ASan (stack
 * redzones on out[]/in[]) catches an over-run past LXP_PATH_MAX that the length guard
 * should have refused. Mirrors tests/suites/test_fs.c setup_proc().
 */
#include "fuzz_common.h"

#include "lxp/lxp_arena.h"
#include "lxp/lxp_syscall.h"

#include "fs/lxp_path.h"

#include <stdint.h>
#include <string.h>

static uint8_t g_pool[64 * 1024] __attribute__((aligned(16)));

/* A tiny rootfs with a symlink so lxp_rootfs_resolve's follow path is reachable from a
 * fuzzed lookup key. */
static const uint8_t k_file_x[] = "x";
static const char k_link_tgt[] = "/real";
static const lxp_file_t k_fs[] = {
	{"/real", k_file_x, sizeof(k_file_x) - 1, 0},
	{"/link", (const uint8_t *)k_link_tgt, sizeof(k_link_tgt) - 1, LXP_S_IFLNK},
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lxp_arena_t arena;
	lxp_proc_t p;
	if (lxp_arena_init(&arena, g_pool, sizeof(g_pool)) != LXP_OK)
		return 0;
	if (lxp_proc_init(&p, &arena, 4096) != LXP_OK)
		return 0;
	p.region_lo = 1;
	p.region_hi = UINTPTR_MAX;
	p.pool_lo = p.pool_hi = 0;
	strcpy(p.cwd, "/"); /* relative inputs join onto a valid absolute cwd */

	/* Bound the fuzzer bytes to a NUL-terminated string a bit longer than LXP_PATH_MAX so
	 * the "no NUL in range" rejection is itself exercised, never overrun. */
	char in[LXP_PATH_MAX + 64];
	fuzz_cstr(in, sizeof(in), data, size);

	char out[LXP_PATH_MAX];
	(void)resolve_path(&p, in, out, sizeof(out));

	const uint8_t *d = NULL;
	size_t n = 0;
	(void)lxp_rootfs_resolve(k_fs, (int)(sizeof(k_fs) / sizeof(k_fs[0])), in, &d, &n);
	return 0;
}
