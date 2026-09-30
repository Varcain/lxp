/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lxp/lxp.h"

static int (*const lxp_embed_entry)(const lxp_providers_t *, const lxp_run_config_t *,
				    const char *, int, const char *const[]) = lxp_run;

int main(void)
{
	return lxp_embed_entry == 0;
}
