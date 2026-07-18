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
#define _GNU_SOURCE /* MAP_32BIT (low-4GiB region) via fuzz_common.h */

#include "../framework/lxp_test.h"
#include "lxp/lxp_loader.h"
#include "lxp/lxp_types.h"

#include "fuzz_common.h" /* fuzz_lowbuf_map: a low-4GiB region so loadmap u32 addrs deref */

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

/* Build a static FDPIC image with a large text segment plus a dynamic table declaring a
 * FUNCDESC-descriptor pool (DT_RELSZ/DT_RELENT), sized so the pool fits the region WITHOUT
 * the copied-text reservation but overflows it WITH it. Reaches the pool-bound check at a
 * point where only the text_a term decides accept vs reject. */
#define POOL_IMG_SZ 724u
static size_t build_fdpic_pool(uint8_t *buf)
{
	memset(buf, 0, POOL_IMG_SZ);
	buf[0] = 0x7f;
	buf[1] = 'E';
	buf[2] = 'L';
	buf[3] = 'F';
	buf[4] = 1;  /* ELFCLASS32 */
	buf[7] = 65; /* ELFOSABI_ARM_FDPIC */
	w16(buf + 16, 3);  /* e_type = ET_DYN */
	w16(buf + 18, 40); /* e_machine = EM_ARM */
	w32(buf + 24, 0);  /* e_entry */
	w32(buf + 28, 52); /* e_phoff */
	w16(buf + 42, 32); /* e_phentsize */
	w16(buf + 44, 3);  /* e_phnum: text, RW (holds the dynamic table), dynamic */

	uint8_t *pt = buf + 52; /* text: PT_LOAD, PF_X, filesz==memsz, copied on copy_text */
	w32(pt + 0, 1);		/* PT_LOAD */
	w32(pt + 4, 212);	/* p_offset (text bytes at 212) */
	w32(pt + 8, 0);		/* p_vaddr */
	w32(pt + 16, 512);	/* p_filesz -> text_a = 512 on a copy_text load */
	w32(pt + 20, 512);	/* p_memsz == p_filesz (PF_X requires equal) */
	w32(pt + 24, 1);	/* PF_X */

	uint8_t *pr = buf + 84; /* RW segment: holds the dynamic table */
	w32(pr + 0, 1);		/* PT_LOAD */
	w32(pr + 4, 180);	/* p_offset (dyn table bytes live at 180) */
	w32(pr + 8, 0x1000);	/* p_vaddr */
	w32(pr + 16, 32);	/* p_filesz */
	w32(pr + 20, 32);	/* p_memsz */
	w32(pr + 24, 6);	/* PF_R | PF_W */

	uint8_t *pd = buf + 116; /* dynamic-table segment descriptor */
	w32(pd + 0, 2);		 /* PT_DYNAMIC */
	w32(pd + 8, 0x1000);	 /* p_vaddr = dyn_off (inside the RW segment) */
	w32(pd + 20, 32);	 /* p_memsz = dyn_sz */

	uint8_t *dyn = buf + 180; /* 4 x Elf32_Dyn {tag, val} */
	w32(dyn + 0, 17);
	w32(dyn + 4, 0x5000); /* DT_REL -> unresolvable vaddr (no reloc writes performed) */
	w32(dyn + 8, 18);
	w32(dyn + 12, 800); /* DT_RELSZ -> max_fd = 800/8 = 100 descriptors */
	w32(dyn + 16, 19);
	w32(dyn + 20, 8); /* DT_RELENT = 8 */
	w32(dyn + 24, 0);
	w32(dyn + 28, 0); /* DT_NULL */
	/* text bytes [212,724) stay zero */
	return POOL_IMG_SZ;
}

/* Regression (src/lxp_loader.c pool-capacity check): the FUNCDESC pool is written at
 * region + text_a + pool_off, so its capacity check must include text_a. Here
 * pool_off(64) + max_fd*8(800) = 864 <= region(1024), but text_a(512) + 864 = 1376 > 1024:
 * a copy_text (netfs-exec) load must be rejected, while the shared-text load (text_a = 0)
 * still fits. Before the fix the copy_text load was wrongly accepted (would write
 * synthesized descriptors past the region). The region is a low-4GiB mapping so the
 * loadmap's u32 segment addresses can be dereferenced (the dynamic-table walk). */
static void test_fdpic_copytext_pool_bounds_region(void **st)
{
	(void)st;
	uint8_t img[POOL_IMG_SZ];
	size_t sz = build_fdpic_pool(img);
	fuzz_lowbuf_t reg = fuzz_lowbuf_map(1024);
	assert_non_null(reg.base);
	lxp_flat_t prog;
	memset(&prog, 0, sizeof(prog));
	assert_int_equal(lxp_loader_load_fdpic(&prog, img, sz, reg.base, 1024, 0, 1),
			 LXP_ERR_NO_MEMORY);
	memset(&prog, 0, sizeof(prog));
	assert_int_equal(lxp_loader_load_fdpic(&prog, img, sz, reg.base, 1024, 0, 0), LXP_OK);
	munmap(reg.base, reg.cap + (size_t)sysconf(_SC_PAGESIZE));
}

/* Build a static FDPIC image whose dynamic table declares a relocation table with a
 * resolvable DT_REL but DT_RELENT = 0 (@p relent lets a caller vary the stride). The RW
 * segment holds the dynamic table (at 0x1000) followed by the rel table (at 0x1020). */
#define RELENT_IMG_SZ 212u
static size_t build_fdpic_relent(uint8_t *buf, uint32_t relent)
{
	memset(buf, 0, RELENT_IMG_SZ);
	buf[0] = 0x7f;
	buf[1] = 'E';
	buf[2] = 'L';
	buf[3] = 'F';
	buf[4] = 1;  /* ELFCLASS32 */
	buf[7] = 65; /* ELFOSABI_ARM_FDPIC */
	w16(buf + 16, 3);  /* ET_DYN */
	w16(buf + 18, 40); /* EM_ARM */
	w32(buf + 28, 52); /* e_phoff */
	w16(buf + 42, 32); /* e_phentsize */
	w16(buf + 44, 3);  /* e_phnum: text, RW, dynamic */

	uint8_t *pt = buf + 52; /* text: PT_LOAD, PF_X, filesz==memsz */
	w32(pt + 0, 1);
	w32(pt + 4, 196); /* p_offset */
	w32(pt + 16, 16); /* p_filesz */
	w32(pt + 20, 16); /* p_memsz */
	w32(pt + 24, 1);  /* PF_X */

	uint8_t *pr = buf + 84; /* RW: dynamic table + rel table */
	w32(pr + 0, 1);
	w32(pr + 4, 148);    /* p_offset (RW bytes at 148) */
	w32(pr + 8, 0x1000); /* p_vaddr */
	w32(pr + 16, 48);    /* p_filesz */
	w32(pr + 20, 48);    /* p_memsz -> RW spans [0x1000,0x1030) */
	w32(pr + 24, 6);     /* PF_R | PF_W */

	uint8_t *pd = buf + 116;
	w32(pd + 0, 2);      /* PT_DYNAMIC */
	w32(pd + 8, 0x1000); /* dyn_off */
	w32(pd + 20, 32);    /* dyn_sz */

	uint8_t *dyn = buf + 148; /* dynamic table (vaddr 0x1000) */
	w32(dyn + 0, 17);
	w32(dyn + 4, 0x1020); /* DT_REL -> resolvable (inside the RW segment) */
	w32(dyn + 8, 18);
	w32(dyn + 12, 16); /* DT_RELSZ = 16 (two 8-byte entries) */
	w32(dyn + 16, 19);
	w32(dyn + 20, relent); /* DT_RELENT (the stride under test) */
	w32(dyn + 24, 0);
	w32(dyn + 28, 0); /* DT_NULL */
	/* rel table at vaddr 0x1020 (image offset 180): two zeroed entries */
	return RELENT_IMG_SZ;
}

/* Regression (src/lxp_loader.c reloc walk): DT_RELENT is the loop stride, so RELENT = 0
 * makes the walk never advance while its bound (o + rel_ent <= rel_sz) stays true — an
 * infinite loop parsing an untrusted binary. The loader must reject RELENT < 8 up front.
 * BEFORE THE FIX this call never returns (the suite hangs); after it, INVALID_PARAM. */
static void test_fdpic_reject_relent_zero(void **st)
{
	(void)st;
	uint8_t img[RELENT_IMG_SZ];
	size_t sz = build_fdpic_relent(img, 0);
	fuzz_lowbuf_t reg = fuzz_lowbuf_map(1024);
	assert_non_null(reg.base);
	lxp_flat_t prog;
	memset(&prog, 0, sizeof(prog));
	assert_int_equal(lxp_loader_load_fdpic(&prog, img, sz, reg.base, 1024, 0, 0),
			 LXP_ERR_INVALID_PARAM);
	munmap(reg.base, reg.cap + (size_t)sysconf(_SC_PAGESIZE));
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
		cmocka_unit_test(test_fdpic_copytext_pool_bounds_region),
		cmocka_unit_test(test_fdpic_reject_relent_zero),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
