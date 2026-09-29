/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * VFS file-operation vtable — per-fd-kind dispatch for the fd syscalls, the Linux
 * struct file_operations / gVisor FileDescriptionImpl pattern. The immutable fd
 * kind indexes one shared vtable instead of storing a redundant pointer in every
 * open-file description. A NULL method means the operation is unsupported for that kind,
 * and the syscall returns the kind's conventional errno (e.g. EBADF for a
 * wrong-direction read/write on a read-only kind). A blocking backend parks the
 * proc, sets the coordinator wait state, and returns 0 for deferred completion.
 *
 * Each fd kind's table is defined by the subsystem that owns the kind;
 * src/fs/lxp_vfs.c indexes them by kind.
 */

#ifndef LXP_FS_VFS_H
#define LXP_FS_VFS_H

#include <stddef.h>
#include <stdint.h>

#include "fs/lxp_dirent.h"
#include "lxp/lxp_config.h"
#include "proc/lxp_proc.h" /* lxp_proc_t, lxp_ofd_t */

struct lxp_stat;
struct lxp_statfs64;

struct lxp_file_ops {
	/** read up to @p len bytes into @p buf (the kernel WRITES buf): bytes read,
	 *  0 (EOF), a negated errno, or 0 after parking the proc. */
	long (*read)(lxp_proc_t *p, lxp_ofd_t *f, void *buf, size_t len);
	/** write @p len bytes from @p buf (the kernel READS buf): bytes written,
	 *  a negated errno, or 0 after parking the proc. */
	long (*write)(lxp_proc_t *p, lxp_ofd_t *f, const void *buf, size_t len);
	/** pread64(2): read at @p off without moving the fd offset: bytes read, 0 (EOF),
	 *  or a negated errno. NULL means the kind is a stream (the syscall returns
	 *  -ESPIPE). */
	long (*pread)(lxp_proc_t *p, lxp_ofd_t *f, void *buf, size_t len, uint64_t off);
	/** pwrite64(2): write at @p off without moving the fd offset: bytes written or a
	 *  negated errno. NULL means the kind is not positioned-writable (-ESPIPE). */
	long (*pwrite)(lxp_proc_t *p, lxp_ofd_t *f, const void *buf, size_t len, uint64_t off);
	/** reposition the fd offset (lseek/_llseek) by the 64-bit @p off: the new
	 *  absolute offset, or a negated errno (lseek(2) narrows it to 32 bits). NULL
	 *  means the kind is not seekable (the syscall returns -ESPIPE). */
	int64_t (*lseek)(lxp_proc_t *p, lxp_ofd_t *f, int64_t off, int whence);
	/** getdents/getdents64: write the directory's next records into @p sink: bytes
	 *  written, 0 at the end, a negated errno, or 0 after parking the proc (netfs).
	 *  NULL means the kind is not a directory (the syscall returns -ENOTDIR). */
	long (*getdents)(lxp_proc_t *p, lxp_ofd_t *f, lxp_dirent_sink_t *sink);
	/** the absolute path of this open directory, into @p out[@p cap], for the *at()
	 *  calls relative to it: 0 or a negated errno. NULL means the kind cannot name its
	 *  directories (lxp_vfs_dir_path answers EOPNOTSUPP for one, ENOTDIR otherwise). */
	long (*dir_path)(lxp_proc_t *p, lxp_ofd_t *f, char *out, size_t cap);
	/** fstat64(2) and statx(2) on the fd: fill @p st, 0 or a negated errno. NULL
	 *  means the kind has no backing object and reports a bare character device
	 *  (console/pipe/eventfd). */
	long (*fstat)(lxp_proc_t *p, lxp_ofd_t *f, struct lxp_stat *st);
	/** fstatfs64(2): fill @p st for the filesystem holding the fd: 0 or a negated
	 *  errno. NULL means the in-memory namespace's synthetic values. */
	long (*fstatfs)(lxp_proc_t *p, lxp_ofd_t *f, struct lxp_statfs64 *st);
	/** ftruncate64(2): set the file's size to @p length: 0 or a negated errno. NULL
	 *  means the kind cannot be truncated (the syscall returns -EINVAL). */
	long (*ftruncate)(lxp_proc_t *p, lxp_ofd_t *f, uint64_t length);
	/** fsync/fdatasync(2): flush the fd's pending writes: 0 or a negated errno. NULL
	 *  means there is nothing to flush (success). */
	long (*fsync)(lxp_proc_t *p, lxp_ofd_t *f);
	/** release the fd's backing object at close(2) (drop a refcount / free a pool
	 *  slot). NULL means the kind holds nothing to release (console/rootfs).
	 *  Cannot fail. */
	void (*close)(lxp_proc_t *p, lxp_ofd_t *f);
	/** ioctl(2): the result, or a negated errno. NULL means the kind is not a
	 *  character device / socket (the syscall returns -ENOTTY). @p arg is the raw
	 *  third argument (a pointer for the tty ioctls). */
	long (*ioctl)(lxp_proc_t *p, lxp_ofd_t *f, unsigned long cmd, unsigned long arg);
	/** poll/select readiness: the ready bits (LXP_POLLIN | LXP_POLLOUT) for this fd
	 *  right now. NULL means the kind is always ready (a regular file). */
	unsigned (*poll)(lxp_proc_t *p, lxp_ofd_t *f);
	/** mmap2(2) of the fd's object mapped directly (no copy): the guest address, 0
	 *  after parking (the coordinator resumes with the address), a negated errno, or
	 *  -ENODEV to fall back to a private arena copy filled by pread. NULL means every
	 *  mapping is such a copy — including MAP_SHARED of a tmpfs file, whose pool
	 *  block may move when the file grows. */
	long (*mmap)(lxp_proc_t *p, lxp_ofd_t *f, size_t len, int prot, uint32_t pgoff);
	/** fcntl(F_SETFL) changed @p f->nonblock: mirror it into state the kind keeps
	 *  itself. NULL means the open-file description's flag is the only state. */
	void (*setfl)(lxp_proc_t *p, lxp_ofd_t *f);
};

typedef struct lxp_file_ops lxp_file_ops_t;

/* LXP_FD_HOSTFS is the highest fixed descriptor kind. Keep the table dense so
 * resolving an OFD remains one checked indexed load rather than a switch. */
#define LXP_FD_KIND_COUNT (LXP_FD_HOSTFS + 1u)
extern const lxp_file_ops_t *const g_lxp_file_ops[LXP_FD_KIND_COUNT];

static inline const lxp_file_ops_t *lxp_vfs_ops(const lxp_ofd_t *ofd)
{
	return ofd && ofd->kind < LXP_FD_KIND_COUNT ? g_lxp_file_ops[ofd->kind] : NULL;
}

/* The access mode recorded at open: whether the description may be read or written
 * (read, pread and ftruncate/write, pwrite check these before the kind's operation). */
static inline int lxp_vfs_readable(const lxp_ofd_t *ofd)
{
	return (ofd->accmode & LXP_O_ACCMODE) != LXP_O_WRONLY;
}

static inline int lxp_vfs_writable(const lxp_ofd_t *ofd)
{
	return (ofd->accmode & LXP_O_ACCMODE) != LXP_O_RDONLY;
}

/* Per-kind operation tables. */
extern const lxp_file_ops_t lxp_console_fops;
extern const lxp_file_ops_t lxp_rootfs_fops;
extern const lxp_file_ops_t lxp_pipe_fops;
extern const lxp_file_ops_t lxp_tmpfs_fops;
extern const lxp_file_ops_t lxp_procfs_fops;
extern const lxp_file_ops_t lxp_eventfd_fops;
#if LXP_ENABLE_DEV
extern const lxp_file_ops_t lxp_dev_fops;
#endif
#if LXP_ENABLE_NET
extern const lxp_file_ops_t lxp_socket_fops;
#endif
#if LXP_ENABLE_NETFS
extern const lxp_file_ops_t lxp_netfs_fops;
#endif
#if LXP_ENABLE_FS
extern const lxp_file_ops_t lxp_hostfs_fops;
#endif
#if LXP_ENABLE_PTY
extern const lxp_file_ops_t lxp_pty_fops;
#endif

/** Copy up to @p len bytes of the in-memory object @p data[0, @p size) starting at @p off
 *  to guest @p buf: bytes copied, 0 at or past the end, or -EFAULT. */
long lxp_vfs_read_mem(lxp_proc_t *p, const void *data, size_t size, void *buf, size_t len,
		      uint64_t off);

/** SEEK_SET/CUR/END arithmetic for @p ofd over an object of logical size @p end:
 *  stores and returns the new offset, -EINVAL for a negative one or -EOVERFLOW
 *  past what the descriptor's offset can hold. */
int64_t lxp_vfs_seek(lxp_ofd_t *ofd, int64_t end, int64_t off, int whence);

/** Copy the directory path @p path into @p out[@p cap]: 0 or -ENAMETOOLONG. */
long lxp_vfs_copy_path(const char *path, char *out, size_t cap);

/** The absolute path of the directory open on @p fd, into @p out[@p cap]: 0, -EBADF,
 *  -ENOTDIR, or -EOPNOTSUPP for a directory its kind cannot name (hostfs, netfs). */
long lxp_vfs_dir_path(lxp_proc_t *p, int fd, char *out, size_t cap);

#endif /* LXP_FS_VFS_H */
