/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Immutable rootfs ingestion and initial guest-stack construction.
 */

#include "lxp/lxp_bootstrap.h"

#include <string.h>

#include "lxp/lxp_proc.h" /* lxp_random_fill */
#include "lxp/lxp_types.h"

static uint32_t cpio_hex(const char *s)
{
	uint32_t value = 0;
	for (int i = 0; i < 8; i++) {
		char c = s[i];
		uint32_t digit = (c >= '0' && c <= '9')   ? (uint32_t)(c - '0')
				 : (c >= 'a' && c <= 'f') ? (uint32_t)(c - 'a' + 10)
				 : (c >= 'A' && c <= 'F') ? (uint32_t)(c - 'A' + 10)
							 : 0u;
		value = (value << 4) | digit;
	}
	return value;
}

int lxp_cpio_to_rootfs(const uint8_t *cpio, size_t len, lxp_file_t *out, int max,
		       char *namebuf, size_t namebuf_len)
{
	if (!cpio || !out || !namebuf)
		return -1;

	size_t pos = 0;
	size_t namebuf_used = 0;
	int count = 0;
	while (pos + 110 <= len) {
		const char *header = (const char *)(cpio + pos);
		if (memcmp(header, "070701", 6) != 0)
			return -1;
		uint32_t mode = cpio_hex(header + 14);
		uint32_t file_size = cpio_hex(header + 54);
		uint32_t name_size = cpio_hex(header + 94);
		if (pos + 110 + name_size > len)
			return -1;
		const char *name = header + 110;
		if (name_size == 0 || name[name_size - 1] != '\0')
			return -1;
		if (strcmp(name, "TRAILER!!!") == 0)
			break;

		size_t data_offset = (pos + 110 + name_size + 3u) & ~(size_t)3u;
		if (file_size && data_offset + file_size > len)
			return -1;
		if (count >= max)
			return -1;

		const char *relative = name;
		if (relative[0] == '.' && relative[1] == '/')
			relative += 2;
		else if (relative[0] == '.' && relative[1] == '\0')
			relative++;
		size_t path_len = strlen(relative);
		if (namebuf_used + 2 + path_len > namebuf_len)
			return -1;

		char *path = namebuf + namebuf_used;
		path[0] = '/';
		memcpy(path + 1, relative, path_len + 1);
		namebuf_used += 2 + path_len;
		out[count].path = path;
		out[count].data = file_size ? cpio + data_offset : NULL;
		out[count].size = file_size;
		out[count].mode = mode;
		count++;
		pos = (data_offset + file_size + 3u) & ~(size_t)3u;
	}
	return count;
}

#define LXP_MAX_VEC 32

void *lxp_setup_stack(void *stack, size_t stack_size, int argc,
		      const char *const argv[], const char *const envp[], int fdpic,
		      uintptr_t phdr, int phnum, uintptr_t entry, uintptr_t at_base)
{
	if (!stack || !argv || argc < 0 || argc > LXP_MAX_VEC)
		return NULL;

	int envc = 0;
	while (envp && envp[envc])
		envc++;
	if (envc > LXP_MAX_VEC)
		return NULL;

	uintptr_t argp[LXP_MAX_VEC];
	uintptr_t envpp[LXP_MAX_VEC];
	uint8_t *sp = (uint8_t *)stack + stack_size;
	uint8_t *floor = (uint8_t *)stack;

	for (int i = envc - 1; i >= 0; i--) {
		size_t n = strlen(envp[i]) + 1;
		if (sp - n < floor)
			return NULL;
		sp -= n;
		memcpy(sp, envp[i], n);
		envpp[i] = (uintptr_t)sp;
	}
	for (int i = argc - 1; i >= 0; i--) {
		size_t n = strlen(argv[i]) + 1;
		if (sp - n < floor)
			return NULL;
		sp -= n;
		memcpy(sp, argv[i], n);
		argp[i] = (uintptr_t)sp;
	}

	/* AT_RANDOM must fail closed when the host lacks trustworthy entropy. */
	if (sp - 16 < floor)
		return NULL;
	sp -= 16;
	uint8_t *random = sp;
	if (lxp_random_fill(random, 16u) != LXP_OK)
		return NULL;

	if (fdpic) {
		size_t words = 1 + (size_t)argc + 1 + (size_t)envc + 1 + 16;
		uintptr_t *header = (uintptr_t *)((uintptr_t)(sp - words * sizeof(uintptr_t)) &
						 ~(uintptr_t)7);
		if ((uint8_t *)header < floor)
			return NULL;
		size_t index = 0;
		header[index++] = (uintptr_t)argc;
		for (int i = 0; i < argc; i++)
			header[index++] = argp[i];
		header[index++] = 0;
		for (int i = 0; i < envc; i++)
			header[index++] = envpp[i];
		header[index++] = 0;
		header[index++] = LXP_AT_PHDR;
		header[index++] = phdr;
		header[index++] = LXP_AT_PHENT;
		header[index++] = 32;
		header[index++] = LXP_AT_PHNUM;
		header[index++] = (uintptr_t)phnum;
		header[index++] = LXP_AT_BASE;
		header[index++] = at_base;
		header[index++] = LXP_AT_ENTRY;
		header[index++] = entry;
		header[index++] = LXP_AT_PAGESZ;
		header[index++] = 4096;
		header[index++] = LXP_AT_RANDOM;
		header[index++] = (uintptr_t)random;
		header[index++] = LXP_AT_NULL;
		header[index++] = 0;
		return header;
	}

	/* bFLT uses argc/argv-pointer/envp-pointer before the arrays and auxv. */
	size_t words = 3 + (size_t)argc + 1 + (size_t)envc + 1 + 6;
	uintptr_t *header = (uintptr_t *)((uintptr_t)(sp - words * sizeof(uintptr_t)) &
					 ~(uintptr_t)7);
	if ((uint8_t *)header < floor)
		return NULL;
	uintptr_t *argv_array = header + 3;
	uintptr_t *envp_array = argv_array + (size_t)argc + 1;
	uintptr_t *auxv = envp_array + (size_t)envc + 1;
	header[0] = (uintptr_t)argc;
	header[1] = (uintptr_t)argv_array;
	header[2] = (uintptr_t)envp_array;
	for (int i = 0; i < argc; i++)
		argv_array[i] = argp[i];
	argv_array[argc] = 0;
	for (int i = 0; i < envc; i++)
		envp_array[i] = envpp[i];
	envp_array[envc] = 0;
	auxv[0] = LXP_AT_PAGESZ;
	auxv[1] = 4096;
	auxv[2] = LXP_AT_RANDOM;
	auxv[3] = (uintptr_t)random;
	auxv[4] = LXP_AT_NULL;
	auxv[5] = 0;
	return header;
}
