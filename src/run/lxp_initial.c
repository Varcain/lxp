/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "run/lxp_initial.h"

#include <string.h>

#include "fs/lxp_path.h"
#include "lxp_internal.h"

int lxp_initial_resolve(const lxp_run_config_t *config, const char *path, int argc,
			const char *const argv[], struct lxp_initial_image *out)
{
	if (!config || !config->rootfs || !path || !argv || argc < 1 || argc > LXP_EXEC_MAXARGS ||
	    !out)
		return -LXP_EINVAL;
	memset(out, 0, sizeof(*out));

	int image_index = lxp_rootfs_resolve_index(config->rootfs, config->rootfs_count, path);
	if (image_index < 0 || !config->rootfs[image_index].data ||
	    (file_mode(&config->rootfs[image_index]) & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_ENOENT;

	int script = lxp_script_parse(config->rootfs[image_index].data,
				      config->rootfs[image_index].size, &out->script);
	if (script < 0)
		return script;
	if (script == LXP_SCRIPT_NOT_PRESENT) {
		out->argc = argc;
		for (int i = 0; i < argc; i++)
			out->argv[i] = argv[i];
	} else {
		char interpreter[LXP_PATH_MAX];
		if (resolve_path_trusted(out->script.interpreter, interpreter,
					 sizeof(interpreter)) != 0)
			return -LXP_ENOEXEC;
		image_index =
			lxp_rootfs_resolve_index(config->rootfs, config->rootfs_count, interpreter);
		if (image_index < 0 || !config->rootfs[image_index].data ||
		    (file_mode(&config->rootfs[image_index]) & LXP_S_IFMT) == LXP_S_IFDIR)
			return -LXP_ENOENT;

		const int prefix_count = out->script.has_argument ? 3 : 2;
		const int tail_count = argc - 1;
		if (prefix_count + tail_count > LXP_EXEC_MAXARGS)
			return -LXP_E2BIG;
		int n = 0;
		out->argv[n++] = out->script.interpreter;
		if (out->script.has_argument)
			out->argv[n++] = out->script.argument;
		out->argv[n++] = path;
		for (int i = 1; i < argc; i++)
			out->argv[n++] = argv[i];
		out->argc = n;
	}

	out->argv[out->argc] = NULL;
	out->file_index = image_index;
	out->data = config->rootfs[image_index].data;
	out->size = config->rootfs[image_index].size;
	return 0;
}
