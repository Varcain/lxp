/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Immutable rootfs ingestion and initial guest-stack construction.
 */

#ifndef LXP_BOOTSTRAP_H
#define LXP_BOOTSTRAP_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_program.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Parse a newc CPIO archive into a caller-owned flat rootfs table. */
int lxp_cpio_to_rootfs(const uint8_t *cpio, size_t len, lxp_file_t *out,
		       int max_entries, char *namebuf, size_t namebuf_len);

/* ELF auxiliary-vector types emitted into the startup block. */
#define LXP_AT_NULL 0
#define LXP_AT_PHDR 3
#define LXP_AT_PHENT 4
#define LXP_AT_PHNUM 5
#define LXP_AT_PAGESZ 6
#define LXP_AT_BASE 7
#define LXP_AT_ENTRY 9
#define LXP_AT_RANDOM 25

/**
 * Build the initial uClinux/FDPIC process stack. Returns the aligned initial
 * stack pointer, or NULL for invalid input, insufficient room, or unavailable
 * host entropy.
 */
void *lxp_setup_stack(void *stack, size_t stack_size, int argc,
		      const char *const argv[], const char *const envp[], int fdpic,
		      uintptr_t phdr, int phnum, uintptr_t entry, uintptr_t at_base);

#ifdef __cplusplus
}
#endif

#endif /* LXP_BOOTSTRAP_H */
