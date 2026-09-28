/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Directory listings of the local namespace (src/fs/lxp_dir.c).
 */
#ifndef LXP_FS_DIR_H
#define LXP_FS_DIR_H

#include "fs/lxp_dirent.h"
#include "proc/lxp_proc.h"

/* List directory @p dirpath for @p s into @p sink, resuming after the s->offset
 * entries earlier calls returned: bytes written, 0 at the end, -EINVAL when the
 * buffer cannot hold the next record, or -EFAULT. */
long lxp_dir_list(lxp_proc_t *p, lxp_ofd_t *s, const char *dirpath, lxp_dirent_sink_t *sink);

#endif /* LXP_FS_DIR_H */
