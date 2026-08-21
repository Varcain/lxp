/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Initial rootfs launch resolution, including interpreter scripts.
 */
#ifndef LXP_INITIAL_H
#define LXP_INITIAL_H

#include "lxp/lxp_exec.h"
#include "lxp/lxp_run.h"
#include "proc/lxp_script.h"

struct lxp_initial_image {
	const uint8_t *data;
	size_t size;
	int file_index;
	int argc;
	const char *argv[LXP_EXEC_MAXARGS + 1];
	lxp_script_spec_t script;
};

int lxp_initial_resolve(const lxp_run_config_t *config, const char *path, int argc,
			const char *const argv[], struct lxp_initial_image *out);

#endif /* LXP_INITIAL_H */
