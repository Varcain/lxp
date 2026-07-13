/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fuzz target: the relocatable-object (ET_REL) loader, lxp_loader_load — the x86-64
 * host path plus the ELFCLASS32/EM_ARM reloc path. Pure over the (image, region)
 * pair. Unlike the FDPIC loader it stores section runtime bases as native void* (no
 * uint32 loadmap), and relocated values are only WRITTEN into the region (never
 * dereferenced by the loader), so the raw fuzzer buffer (ASan-guarded by libFuzzer)
 * is passed straight in as the image and the region is a plain ASan-instrumented
 * global — a missing e_shoff / section-extent / r_offset bound reads or writes OOB
 * and aborts here. Exercises the Stage-3 ld_oob + sec_size[] r_offset guards.
 */
#include "lxp/lxp_loader.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static uint8_t g_region[128 * 1024] __attribute__((aligned(16)));

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lxp_module_t mod;
	memset(&mod, 0, sizeof(mod));
	if (lxp_loader_load(&mod, data, size, g_region, sizeof(g_region), NULL, 0) == LXP_OK) {
		/* a loaded module is queried by name — walk its (image-resident) sym/str tables */
		(void)lxp_loader_sym(&mod, "foo");
		(void)lxp_loader_sym(&mod, "");
	}
	return 0;
}
