/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fuzz target: the FDPIC program loader (lxp_loader_load_fdpic) — the production
 * entry for loading a guest exec, and the path a remote (netfs-exec) image takes.
 * It is a pure function over the (image, region) buffer pair, so the fuzzer bytes
 * ARE the untrusted ELF. Runs both text-placement modes: copy_text=0 (XIP text,
 * shared in place from the image) and copy_text=1 (the remote/RAM exec path that
 * copies program text INTO the region).
 *
 * The loader models 32-bit-target memory (its FDPIC loadmap stores segment runtime
 * addresses as uint32), so image + region are backed by low-4-GiB guarded buffers
 * (fuzz_lowbuf): the uint32 truncations round-trip as on the Cortex-M target, while
 * a guard page one byte past image_size/region_size still faults a genuine OOB.
 */
#include "fuzz_common.h"
#include "lxp/lxp_loader.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Region generous enough to lay out a well-formed mutated image's segments (past the
 * "too small" rejection into the reloc / copy_text write paths). Image staging is
 * larger than any real exec so the fuzzer is bounded by declared image_size, not the
 * buffer. */
#define FDPIC_REGION_SZ (256u * 1024u)
#define FDPIC_IMAGE_CAP (1024u * 1024u)

static fuzz_lowbuf_t g_region;
static fuzz_lowbuf_t g_image;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	g_region = fuzz_lowbuf_map(FDPIC_REGION_SZ);
	g_image = fuzz_lowbuf_map(FDPIC_IMAGE_CAP);
	if (!g_region.base || !g_image.base)
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!g_region.base)
		LLVMFuzzerInitialize(NULL, NULL);

	size_t n = size;
	const uint8_t *img = fuzz_lowbuf_place(g_image, data, &n);
	lxp_flat_t prog;

	memset(&prog, 0, sizeof(prog));
	lxp_loader_load_fdpic(&prog, img, n, g_region.base, FDPIC_REGION_SZ, 0, 0);

	memset(&prog, 0, sizeof(prog));
	lxp_loader_load_fdpic(&prog, img, n, g_region.base, FDPIC_REGION_SZ, 0, 1);

	return 0;
}
