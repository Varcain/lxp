/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fuzz target: the newc cpio parser, lxp_cpio_to_rootfs — the boot path that turns an
 * initramfs image into the read-only rootfs table. Pure over the input buffer; the out
 * entries point IN-PLACE into it, and names are copied into a caller namebuf. So the
 * fuzzer bytes ARE the untrusted cpio; ASan (input buffer + the stack out[]/namebuf
 * redzones) catches a missing header-span / namesize / data-extent bound. Exercises the
 * Stage-3 pos+110<=len, namesize NUL-termination, and data_off+fsize<=len guards.
 */
#include "lxp/lxp_syscall.h"

#include <stddef.h>
#include <stdint.h>

#define CPIO_MAX_ENTRIES 64
#define CPIO_NAMEBUF 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lxp_file_t out[CPIO_MAX_ENTRIES];
	char namebuf[CPIO_NAMEBUF];

	(void)lxp_cpio_to_rootfs(data, size, out, CPIO_MAX_ENTRIES, namebuf, sizeof(namebuf));
	return 0;
}
