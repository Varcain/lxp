/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The exec staging buffer (src/proc/lxp_exec_stage.c): engine RAM that execve copies a
 * program into when it cannot be loaded in place -- one fetched from netfs or stored in
 * tmpfs -- and that the coordinator's exec commit loads it from. There is one buffer,
 * owned by the process waiting for the image in it: parked on the netfs fetch, or with
 * an exec intent naming the buffer. Once that process moves on (the commit starts, the
 * exec fails or is cancelled, the process exits) the buffer is free again.
 */
#ifndef LXP_PROC_EXEC_STAGE_H
#define LXP_PROC_EXEC_STAGE_H

#include <stddef.h>
#include <stdint.h>

#include "proc/lxp_proc.h"

/** exec_file_idx of a program whose image is in the staging buffer. */
#define LXP_EXEC_STAGED (-2)

/** The engine's staging RAM and its capacity, or NULL on a build without one. */
uint8_t *lxp_exec_stage(size_t *cap);

/** Take the buffer for @p p's exec: 0 with @p buf and @p cap set, -ENOMEM on a build
 *  without one, or -EAGAIN while another process's image is waiting in it. */
long lxp_exec_stage_claim(lxp_proc_t *p, uint8_t **buf, size_t *cap);

/** The staged image is @p size bytes. */
void lxp_exec_stage_publish(const lxp_proc_t *p, size_t size);

/** The staged image for the exec commit, or NULL with *size 0. */
const uint8_t *lxp_exec_stage_image(size_t *size);

/** Forget any claim: its owner belongs to the process runtime being reset. */
void lxp_exec_stage_reset(void);

#endif /* LXP_PROC_EXEC_STAGE_H */
