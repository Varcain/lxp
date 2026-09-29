/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The syscall handlers the table in src/lxp_syscall.c dispatches to, grouped by the
 * unit under src/sys/ (or subsystem) that implements them. Every handler takes the
 * calling process and its six argument registers and returns the Linux result.
 */
#ifndef LXP_SYS_H
#define LXP_SYS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"
#include "proc/lxp_proc.h"

/* ---- descriptors (src/sys/lxp_sys_fd.c) ---- */
int lxp_sys_fd_alloc(lxp_proc_t *p, uint8_t kind, int idx, size_t off, int flags);
long lxp_sys_fd_pread(lxp_proc_t *p, int fd, void *buf, size_t len, uint64_t off);
long lxp_sys_read(lxp_proc_t *proc, const long a[6]);
long lxp_sys_write(lxp_proc_t *proc, const long a[6]);
long lxp_sys_writev(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pread64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pwrite64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_close(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pipe(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pipe2(lxp_proc_t *proc, const long a[6]);
long lxp_sys_dup(lxp_proc_t *proc, const long a[6]);
long lxp_sys_dup2(lxp_proc_t *proc, const long a[6]);
long lxp_sys_dup3(lxp_proc_t *proc, const long a[6]);
long lxp_sys_lseek(lxp_proc_t *proc, const long a[6]);
long lxp_sys_llseek(lxp_proc_t *proc, const long a[6]);
long lxp_sys_ftruncate64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fsync(lxp_proc_t *proc, const long a[6]);
long lxp_sys_sync(lxp_proc_t *proc, const long a[6]);
long lxp_sys_syncfs(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fcntl(lxp_proc_t *proc, const long a[6]);
long lxp_sys_ioctl(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getdents(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getdents64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_eventfd2(lxp_proc_t *proc, const long a[6]);

#endif /* LXP_SYS_H */
