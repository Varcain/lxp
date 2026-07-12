/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * FDPIC program-loader tests: drive lxp_loader_load_fdpic() — the production entry
 * for loading a guest exec, and the path a remote (netfs-exec) image takes — with a
 * minimal valid image and with malformed images that exercise the Stage-3 bounds.
 * Under the ASan/UBSan build a missing bound reads/writes OOB while parsing the
 * hostile image, so a regression aborts here rather than silently mis-loading.
 */
#include "../framework/lxp_test.h"
#include "lxp/lxp_loader.h"
#include "lxp/lxp_types.h"

#include <stdint.h>
#include <string.h>

static void w16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}
static void w32(uint8_t *p, uint32_t v)
{
	for (int i = 0; i < 4; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

/* Build a minimal but well-formed static FDPIC ELF (Ehdr + text Phdr + data Phdr +
 * a little data) into @p buf; returns the image size. The loader accepts it as-is;
 * each rejection test rebuilds it and corrupts exactly one field. */
#define IMG_SZ 128u
static size_t build_fdpic(uint8_t *buf)
{
	memset(buf, 0, IMG_SZ);
	buf[0] = 0x7f;
	buf[1] = 'E';
	buf[2] = 'L';
	buf[3] = 'F';
	buf[4] = 1;  /* ELFCLASS32 */
	buf[7] = 65; /* ELFOSABI_ARM_FDPIC */
	w16(buf + 16, 3);  /* e_type = ET_DYN */
	w16(buf + 18, 40); /* e_machine = EM_ARM */
	w32(buf + 24, 0);  /* e_entry */
	w32(buf + 28, 52); /* e_phoff (phdrs right after the 52-byte Ehdr) */
	w16(buf + 42, 32); /* e_phentsize */
	w16(buf + 44, 2);  /* e_phnum */
	uint8_t *p0 = buf + 52; /* text segment, shared in-place, PF_X */
	w32(p0 + 0, 1);		/* PT_LOAD */
	w32(p0 + 16, 16);	/* p_filesz */
	w32(p0 + 20, 16);	/* p_memsz */
	w32(p0 + 24, 1);	/* PF_X */
	uint8_t *p1 = buf + 84; /* data segment, copied into the region, PF_R|PF_W */
	w32(p1 + 0, 1);		 /* PT_LOAD */
	w32(p1 + 4, 116);	 /* p_offset (data bytes live at 116) */
	w32(p1 + 8, 0x1000);	 /* p_vaddr */
	w32(p1 + 16, 8);	 /* p_filesz */
	w32(p1 + 20, 16);	 /* p_memsz (>= filesz) */
	w32(p1 + 24, 6);	 /* PF_R | PF_W */
	return IMG_SZ;
}

static uint8_t g_region[512] __attribute__((aligned(16)));

static long load(const uint8_t *img, size_t sz)
{
	lxp_flat_t prog;
	memset(&prog, 0, sizeof(prog));
	return lxp_loader_load_fdpic(&prog, img, sz, g_region, sizeof(g_region), 0, 0);
}

static void test_fdpic_valid_loads(void **st)
{
	(void)st;
	uint8_t img[IMG_SZ];
	size_t sz = build_fdpic(img);
	assert_int_equal(load(img, sz), LXP_OK);
}

static void test_fdpic_reject_truncated(void **st)
{
	(void)st;
	uint8_t img[IMG_SZ];
	build_fdpic(img);
	assert_int_equal(load(img, 40), LXP_ERR_INVALID_PARAM); /* < Elf32_Ehdr */
}

static void test_fdpic_reject_bad_magic(void **st)
{
	(void)st;
	uint8_t img[IMG_SZ];
	size_t sz = build_fdpic(img);
	img[1] = 'X';
	assert_int_equal(load(img, sz), LXP_ERR_INVALID_PARAM);
}

static void test_fdpic_reject_small_phentsize(void **st)
{
	(void)st;
	uint8_t img[IMG_SZ];
	size_t sz = build_fdpic(img);
	w16(img + 42, 8); /* < 32: the ph+N field reads would spill into the next entry */
	assert_int_equal(load(img, sz), LXP_ERR_INVALID_PARAM);
}

static void test_fdpic_reject_phdr_table_oob(void **st)
{
	(void)st;
	uint8_t img[IMG_SZ];
	size_t sz = build_fdpic(img);
	w32(img + 28, 200); /* e_phoff: 200 + 2*32 > image_size */
	assert_int_equal(load(img, sz), LXP_ERR_INVALID_PARAM);
}

static void test_fdpic_reject_filesz_gt_memsz(void **st)
{
	(void)st;
	uint8_t img[IMG_SZ];
	size_t sz = build_fdpic(img);
	w32(img + 84 + 16, 32); /* data p_filesz(32) > p_memsz(16): an OOB write into the region */
	assert_int_equal(load(img, sz), LXP_ERR_INVALID_PARAM);
}

int test_loader_fdpic_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_fdpic_valid_loads),
		cmocka_unit_test(test_fdpic_reject_truncated),
		cmocka_unit_test(test_fdpic_reject_bad_magic),
		cmocka_unit_test(test_fdpic_reject_small_phentsize),
		cmocka_unit_test(test_fdpic_reject_phdr_table_oob),
		cmocka_unit_test(test_fdpic_reject_filesz_gt_memsz),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
