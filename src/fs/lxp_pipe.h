/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Private interface of the pipe subsystem (src/fs/lxp_pipe.c), used by the syscall
 * dispatcher's read/write/poll handlers. lxp_pipe_retry (the coordinator entry) is
 * public in lxp_syscall.h.
 */
#ifndef LXP_FS_PIPE_H
#define LXP_FS_PIPE_H

#include <stddef.h>

/* Claim a free pipe slot (no live proc holds either end) and initialise it.
 * Returns the pipe index, or -1 if the pool is exhausted. */
int lxp_pipe_alloc(void);

/* Drain up to len bytes: >0 = bytes read; 0 = EOF (empty, no writers); -EAGAIN =
 * empty but a writer is open (caller blocks). */
long pipe_try_read(int pi, void *buf, size_t len);

/* Append up to len bytes: >0 = bytes written; -EPIPE = no readers (broken pipe);
 * -EAGAIN = full but a reader is open (caller blocks). */
long pipe_try_write(int pi, const void *buf, size_t len);

/* poll/select readiness for a pipe end (rw = fd.rw: 0 read end, 1 write end). */
unsigned pipe_poll(int pi, int rw);

#endif /* LXP_FS_PIPE_H */
