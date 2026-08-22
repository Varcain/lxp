/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bounded text construction for synthetic kernel files. Output truncates at
 * capacity and never requires a trailing NUL.
 */
#ifndef LXP_TEXT_H
#define LXP_TEXT_H

#include <stddef.h>
#include <stdint.h>

typedef struct lxp_text {
	char *data;
	size_t length;
	size_t capacity;
} lxp_text_t;

static inline lxp_text_t lxp_text_make(char *data, size_t capacity)
{
	return (lxp_text_t){.data = data, .capacity = capacity};
}

static inline void lxp_text_putc(lxp_text_t *text, char value)
{
	if (text->length < text->capacity)
		text->data[text->length++] = value;
}

static inline void lxp_text_puts(lxp_text_t *text, const char *value)
{
	while (*value && text->length < text->capacity)
		text->data[text->length++] = *value++;
}

static inline void lxp_text_u64(lxp_text_t *text, uint64_t value)
{
	char digits[20];
	size_t count = 0;
	if (value == 0u)
		digits[count++] = '0';
	while (value != 0u) {
		digits[count++] = (char)('0' + value % 10u);
		value /= 10u;
	}
	while (count)
		lxp_text_putc(text, digits[--count]);
}

static inline void lxp_text_s64(lxp_text_t *text, int64_t value)
{
	if (value < 0) {
		lxp_text_putc(text, '-');
		lxp_text_u64(text, (uint64_t)(-(value + 1)) + 1u);
	} else {
		lxp_text_u64(text, (uint64_t)value);
	}
}

#endif /* LXP_TEXT_H */
