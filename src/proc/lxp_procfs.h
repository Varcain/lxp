/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Private interface of the synthetic /proc filesystem (src/proc/lxp_procfs.c): the
 * content generator used by the path syscalls and the FD_PROC descriptors.
 */
#ifndef LXP_PROC_PROCFS_H
#define LXP_PROC_PROCFS_H

#include <stddef.h>

#include "proc/lxp_proc.h"

/* True iff `abs` names something under /proc (which shadows the rootfs). */
int proc_is(const char *abs);

/* The stat mode of /proc node `abs` (S_IFREG/S_IFDIR/S_IFLNK | perms), or 0 if absent. */
uint32_t proc_mode(const char *abs, const lxp_proc_t *p);

/* Generate the read-only content of the /proc file `abs` into buf[cap]; returns the
 * byte count or a negative errno. */
long proc_gen(const char *abs, const lxp_proc_t *p, char *buf, size_t cap);

/* --- helpers the dispatcher's /proc getdents/readlink glue also uses --------- */

/* If `abs` is /proc/<pid> or /proc/<pid>/<file>, return the pid and set *file to the
 * trailing component (NULL for the dir itself); 0 if `abs` is not a /proc/<pid> path. */
int proc_pid(const char *abs, const lxp_proc_t *p, const char **file);

/* True iff `pid` is a live/known process (pid 1, self, or a ps/top snapshot entry). */
int proc_pid_known(const lxp_proc_t *p, int pid);

/* NULL-terminated list of top-level /proc file names (for the /proc dir listing). */
extern const char *const g_proc_files[];

/* Open /proc node `abs` (already resolved): a generated-content file fd, or a
 * directory fd for getdents. Returns the fd or a negative errno. */
long lxp_procfs_open(lxp_proc_t *p, const char *abs);

/* The path of FD_PROC backing `idx` if it is a directory, else NULL. */
const char *lxp_procfs_dir_path(int idx);

#endif /* LXP_PROC_PROCFS_H */
