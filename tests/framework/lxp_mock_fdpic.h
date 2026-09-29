/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The smallest FDPIC executable the loader's validator accepts: an ARM ELF32 ET_DYN with
 * one executable and one writable PT_LOAD. Suites that exec a program from netfs or tmpfs
 * store these bytes there.
 */
#ifndef LXP_MOCK_FDPIC_H
#define LXP_MOCK_FDPIC_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define LXP_MOCK_FDPIC_SIZE 128u

static inline void lxp_mock_fdpic_put(uint8_t *image, size_t off, uint32_t value, int bytes)
{
	for (int i = 0; i < bytes; i++)
		image[off + (size_t)i] = (uint8_t)(value >> (8 * i));
}

static inline void lxp_mock_fdpic(uint8_t image[LXP_MOCK_FDPIC_SIZE])
{
	memset(image, 0, LXP_MOCK_FDPIC_SIZE);
	memcpy(image, "\x7f" "ELF", 4);
	image[4] = 1;			       /* ELFCLASS32 */
	image[7] = 65;			       /* ELFOSABI_ARM_FDPIC */
	lxp_mock_fdpic_put(image, 16, 3, 2);   /* ET_DYN */
	lxp_mock_fdpic_put(image, 18, 40, 2);  /* EM_ARM */
	lxp_mock_fdpic_put(image, 24, 0, 4);   /* entry */
	lxp_mock_fdpic_put(image, 28, 52, 4);  /* phoff */
	lxp_mock_fdpic_put(image, 42, 32, 2);  /* phentsize */
	lxp_mock_fdpic_put(image, 44, 2, 2);   /* phnum */
	lxp_mock_fdpic_put(image, 52, 1, 4);   /* PT_LOAD text */
	lxp_mock_fdpic_put(image, 68, 16, 4);  /* filesz */
	lxp_mock_fdpic_put(image, 72, 16, 4);  /* memsz */
	lxp_mock_fdpic_put(image, 76, 1, 4);   /* PF_X */
	lxp_mock_fdpic_put(image, 84, 1, 4);   /* PT_LOAD data */
	lxp_mock_fdpic_put(image, 88, 116, 4); /* file offset */
	lxp_mock_fdpic_put(image, 92, 0x1000, 4);
	lxp_mock_fdpic_put(image, 100, 8, 4);  /* filesz */
	lxp_mock_fdpic_put(image, 104, 16, 4); /* memsz */
	lxp_mock_fdpic_put(image, 108, 6, 4);  /* PF_R | PF_W */
}

#endif /* LXP_MOCK_FDPIC_H */
