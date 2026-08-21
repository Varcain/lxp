/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bounded interpreter-script parsing shared by initial launch and execve.
 */
#ifndef LXP_SCRIPT_H
#define LXP_SCRIPT_H

#include <stddef.h>
#include <stdint.h>

#define LXP_SCRIPT_TOKEN_CAPACITY 64

typedef struct lxp_script_spec {
	char interpreter[LXP_SCRIPT_TOKEN_CAPACITY];
	char argument[LXP_SCRIPT_TOKEN_CAPACITY];
	int has_argument;
} lxp_script_spec_t;

enum {
	LXP_SCRIPT_NOT_PRESENT = 0,
	LXP_SCRIPT_PRESENT = 1,
};

/** Parse a #! line without retaining pointers into the source image.
 *
 * Returns LXP_SCRIPT_NOT_PRESENT, LXP_SCRIPT_PRESENT, or -ENOEXEC for a
 * malformed or unrepresentable interpreter line.
 */
int lxp_script_parse(const uint8_t *data, size_t size, lxp_script_spec_t *out);

#endif /* LXP_SCRIPT_H */
