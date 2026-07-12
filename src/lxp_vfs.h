/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * VFS file-operation vtable — per-fd-kind dispatch for the fd syscalls, the Linux
 * struct file_operations / gVisor FileDescriptionImpl pattern. Each open fd
 * (lxp_fd_t) carries a pointer to its kind's ops, set at fd creation via
 * ops_for_kind(); the fd syscalls call through it instead of switching on
 * lxp_fd_t.kind. A NULL method means the operation is unsupported for that kind,
 * and the syscall returns the kind's conventional errno (e.g. EBADF for a
 * wrong-direction read/write on a read-only kind). A blocking backend parks the
 * proc (sets the coordinator park state) and returns 0, exactly as the former
 * inline handlers did.
 */

#ifndef LXP_VFS_H
#define LXP_VFS_H

#include <stddef.h>

#include "lxp/lxp_syscall.h" /* lxp_proc_t, lxp_fd_t */

struct lxp_file_ops {
	/** read up to @p len bytes into @p buf (the kernel WRITES buf): bytes read,
	 *  0 (EOF), a negated errno, or 0 after parking the proc. */
	long (*read)(lxp_proc_t *p, lxp_fd_t *f, void *buf, size_t len);
	/** write @p len bytes from @p buf (the kernel READS buf): bytes written,
	 *  a negated errno, or 0 after parking the proc. */
	long (*write)(lxp_proc_t *p, lxp_fd_t *f, const void *buf, size_t len);
	/** reposition the fd offset (lseek/_llseek): the new absolute offset, or a
	 *  negated errno. NULL means the kind is not seekable (the syscall returns
	 *  -ESPIPE). */
	long (*lseek)(lxp_proc_t *p, lxp_fd_t *f, long off, int whence);
	/** fill @p statbuf (a struct kstat64) for fstat64(2): 0, a negated errno, or
	 *  0 after parking (netfs). NULL means the kind has no backing object and the
	 *  syscall reports a bare character device (console/pipe/eventfd). */
	long (*fstat)(lxp_proc_t *p, lxp_fd_t *f, void *statbuf);
	/** release the fd's backing object at close(2) (drop a refcount / free a pool
	 *  slot). NULL means the kind holds nothing to release (console/file/tmpfs/
	 *  pipe/pty — the slot is simply freed). Cannot fail. */
	void (*close)(lxp_proc_t *p, lxp_fd_t *f);
	/** ioctl(2): the result, or a negated errno. NULL means the kind is not a
	 *  character device / socket (the syscall returns -ENOTTY). @p arg is the raw
	 *  third argument (a pointer for the tty ioctls). */
	long (*ioctl)(lxp_proc_t *p, lxp_fd_t *f, unsigned long cmd, unsigned long arg);
};

typedef struct lxp_file_ops lxp_file_ops_t;

#endif /* LXP_VFS_H */
