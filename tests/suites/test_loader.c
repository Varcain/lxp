/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fresh unit suite for the ELF object loader's x86-64 host path (src/lxp_loader.c,
 * load64 — "for host dev"). Not migrated: the vendored copy was previously untested.
 * Two concerns: (1) it loads a well-formed ET_REL object and resolves a global symbol,
 * and (2) it rejects malformed/hostile images without an out-of-bounds read — the
 * ld_oob() bounds guards on e_shoff / section offsets. Builds the images in memory
 * with the host <elf.h> (ABI-identical to what the loader parses byte-for-byte).
 */
#include "../framework/lxp_test.h"
#include "lxp/lxp_loader.h"

#include <elf.h>
#include <stddef.h>
#include <string.h>

#define IMG_CAP 512

/* Build a minimal valid x86-64 ET_REL object into img[IMG_CAP]: one SHF_ALLOC .text
 * byte (0xc3 = ret) and a global symbol "foo" -> .text+0. Returns the image size.
 * Layout (8-aligned): [Ehdr][.text][.strtab][.symtab][shdr table]. */
static size_t a8(size_t n)
{
	return (n + 7u) & ~(size_t)7u;
}

static size_t build_obj(uint8_t *img)
{
	memset(img, 0, IMG_CAP);

	size_t text_off = sizeof(Elf64_Ehdr);
	img[text_off] = 0xc3;

	size_t str_off = a8(text_off + 1);
	static const char strtab[] = "\0foo"; /* {0,'f','o','o','\0'} — "foo" at index 1 */
	size_t str_sz = sizeof(strtab);
	memcpy(img + str_off, strtab, str_sz);

	size_t sym_off = a8(str_off + str_sz);
	Elf64_Sym syms[2];
	memset(syms, 0, sizeof(syms));
	syms[1].st_name = 1; /* "foo" */
	syms[1].st_info = (STB_GLOBAL << 4) | STT_FUNC;
	syms[1].st_shndx = 1; /* .text */
	syms[1].st_value = 0;
	memcpy(img + sym_off, syms, sizeof(syms));

	size_t sh_off = a8(sym_off + sizeof(syms));
	Elf64_Shdr sh[4];
	memset(sh, 0, sizeof(sh));
	sh[1].sh_type = SHT_PROGBITS; /* .text */
	sh[1].sh_flags = SHF_ALLOC;
	sh[1].sh_offset = text_off;
	sh[1].sh_size = 1;
	sh[1].sh_addralign = 1;
	sh[2].sh_type = SHT_SYMTAB; /* .symtab */
	sh[2].sh_offset = sym_off;
	sh[2].sh_size = sizeof(syms);
	sh[2].sh_link = 3; /* -> .strtab */
	sh[2].sh_entsize = sizeof(Elf64_Sym);
	sh[3].sh_type = SHT_STRTAB; /* .strtab */
	sh[3].sh_offset = str_off;
	sh[3].sh_size = str_sz;
	memcpy(img + sh_off, sh, sizeof(sh));

	Elf64_Ehdr eh;
	memset(&eh, 0, sizeof(eh));
	eh.e_ident[EI_MAG0] = 0x7f;
	eh.e_ident[EI_MAG1] = 'E';
	eh.e_ident[EI_MAG2] = 'L';
	eh.e_ident[EI_MAG3] = 'F';
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_type = ET_REL;
	eh.e_machine = EM_X86_64;
	eh.e_version = EV_CURRENT;
	eh.e_shoff = sh_off;
	eh.e_shnum = 4;
	eh.e_shentsize = sizeof(Elf64_Shdr);
	memcpy(img, &eh, sizeof(eh));

	return sh_off + sizeof(sh);
}

/* Overwrite a little-endian field of `n` bytes at absolute image offset `off`. */
static void poke(uint8_t *img, size_t off, uint64_t val, size_t n)
{
	for (size_t i = 0; i < n; i++)
		img[off + i] = (uint8_t)(val >> (8 * i));
}

/* A well-formed object loads and its global symbol resolves to the placed .text. */
static void test_loader_loads_object(void **s)
{
	(void)s;
	uint8_t img[IMG_CAP];
	uint8_t region[4096];
	lxp_module_t mod;
	size_t sz = build_obj(img);

	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0), LXP_OK);
	void *foo = lxp_loader_sym(&mod, "foo");
	assert_non_null(foo);
	assert_ptr_equal(foo, region);	       /* sec_addr[.text]=region+0, st_value 0 */
	assert_int_equal(*(uint8_t *)foo, 0xc3);
	assert_null(lxp_loader_sym(&mod, "nonexistent"));
}

/* Basic argument + ELF-identity rejection (no OOB, clean error codes). */
static void test_loader_rejects_bad_identity(void **s)
{
	(void)s;
	uint8_t img[IMG_CAP];
	uint8_t region[4096];
	lxp_module_t mod;
	size_t sz = build_obj(img);

	assert_int_equal(lxp_loader_load(NULL, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);
	assert_int_equal(lxp_loader_load(&mod, NULL, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);
	/* shorter than even an ELF32 header → rejected before any field read */
	assert_int_equal(lxp_loader_load(&mod, img, 8, region, sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);
	/* class is ELF64 but the image is shorter than an ELF64 header */
	assert_int_equal(lxp_loader_load(&mod, img, sizeof(Elf64_Ehdr) - 1, region,
					 sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);

	build_obj(img);
	img[EI_MAG1] = 'X'; /* corrupt magic */
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);

	build_obj(img);
	img[EI_DATA] = ELFDATA2MSB; /* big-endian unsupported */
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_NOT_SUPPORTED);

	build_obj(img);
	img[EI_CLASS] = ELFCLASSNONE; /* neither 32 nor 64 */
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_NOT_SUPPORTED);

	build_obj(img);
	poke(img, offsetof(Elf64_Ehdr, e_machine), EM_AARCH64, sizeof(Elf64_Half));
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_NOT_SUPPORTED);

	build_obj(img);
	poke(img, offsetof(Elf64_Ehdr, e_type), ET_EXEC, sizeof(Elf64_Half));
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_NOT_SUPPORTED);
}

/* The ld_oob() bounds guards: a crafted section-header table or section extent that
 * runs past the image must be refused, not read out of bounds. */
static void test_loader_rejects_oob_sections(void **s)
{
	(void)s;
	uint8_t img[IMG_CAP];
	uint8_t region[4096];
	lxp_module_t mod;
	size_t sz = build_obj(img);

	build_obj(img);
	poke(img, offsetof(Elf64_Ehdr, e_shnum), 0, sizeof(Elf64_Half)); /* no sections */
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);

	build_obj(img);
	poke(img, offsetof(Elf64_Ehdr, e_shnum), LXP_LOADER_MAX_SECTIONS + 1,
	     sizeof(Elf64_Half)); /* more sections than the control block holds */
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_NO_MEMORY);

	build_obj(img);
	/* section-header table offset past the end: e_shoff + shnum*shentsize > image_size */
	poke(img, offsetof(Elf64_Ehdr, e_shoff), sz, sizeof(Elf64_Off));
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);

	/* a .text section whose file extent runs past the image (in-loop ld_oob) */
	size_t shoff = build_obj(img) - 4 * sizeof(Elf64_Shdr);
	size_t text_shdr = shoff + 1 * sizeof(Elf64_Shdr);
	poke(img, text_shdr + offsetof(Elf64_Shdr, sh_offset), (uint64_t)sz, sizeof(Elf64_Off));
	assert_int_equal(lxp_loader_load(&mod, img, sz, region, sizeof(region), NULL, 0),
			 LXP_ERR_INVALID_PARAM);
}

int test_loader_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_loader_loads_object),
		cmocka_unit_test(test_loader_rejects_bad_identity),
		cmocka_unit_test(test_loader_rejects_oob_sections),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
