/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_FD_PRIVATE_H
#define LXP_FD_PRIVATE_H

#include "proc/lxp_proc.h"

/** Allocate the lowest descriptor and its open-file description. */
int lxp_fd_open(lxp_proc_t *proc, uint8_t kind, int backing, size_t offset);
/** Set open-description direction and nonblocking state. */
int lxp_fd_set_status(lxp_proc_t *proc, int fd, int direction, int nonblock);
/** Set or query the descriptor-local close-on-exec flag. */
int lxp_fd_set_cloexec(lxp_proc_t *proc, int fd, int enabled);
int lxp_fd_get_cloexec(const lxp_proc_t *proc, int fd);
/** Count descriptor slots that are currently available. */
int lxp_fd_free_count(const lxp_proc_t *proc);
/** Close every descriptor marked close-on-exec. */
void lxp_fd_close_on_exec(lxp_proc_t *proc);
/** Duplicate onto an exact descriptor or the first descriptor at/above minfd. */
int lxp_fd_dup_to(lxp_proc_t *proc, int oldfd, int newfd, int cloexec);
int lxp_fd_dup_min(lxp_proc_t *proc, int oldfd, int minfd, int cloexec);
/*
 * Retain every open-file description referenced by proc->files. Validation is
 * transactional: failure leaves all reference counts unchanged.
 */
int lxp_fd_table_retain(lxp_proc_t *proc);

#endif /* LXP_FD_PRIVATE_H */
