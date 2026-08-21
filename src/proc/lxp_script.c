/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "proc/lxp_script.h"

#include <string.h>

#include "lxp/lxp_proc.h"

static int copy_token(const uint8_t **cursor, const uint8_t *end, char *dst, size_t capacity)
{
	size_t used = 0;
	while (*cursor < end && **cursor != ' ' && **cursor != '\t' && **cursor != '\n') {
		if (used + 1u >= capacity)
			return -LXP_ENOEXEC;
		dst[used++] = (char)*(*cursor)++;
	}
	dst[used] = '\0';
	return used != 0u ? 0 : -LXP_ENOEXEC;
}

int lxp_script_parse(const uint8_t *data, size_t size, lxp_script_spec_t *out)
{
	if (!out)
		return -LXP_ENOEXEC;
	memset(out, 0, sizeof(*out));
	if (!data || size < 2u || data[0] != '#' || data[1] != '!')
		return LXP_SCRIPT_NOT_PRESENT;

	const uint8_t *cursor = data + 2;
	const uint8_t *end = data + size;
	while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
		cursor++;
	int rc = copy_token(&cursor, end, out->interpreter, sizeof(out->interpreter));
	if (rc != 0)
		return rc;
	while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
		cursor++;
	if (cursor < end && *cursor != '\n') {
		rc = copy_token(&cursor, end, out->argument, sizeof(out->argument));
		if (rc != 0)
			return rc;
		out->has_argument = 1;
	}
	return LXP_SCRIPT_PRESENT;
}
