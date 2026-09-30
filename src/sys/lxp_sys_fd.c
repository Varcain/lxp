/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Descriptor syscalls: I/O, positioned I/O, seek, duplication, pipes, fcntl, ioctl,
 * truncate, sync and directory reads, dispatched through the file operations.
 */
#include "sys/lxp_sys.h"
#include "fs/lxp_dirent.h"
#include "fs/lxp_eventfd.h"
#include "fs/lxp_fd_private.h"
#include "fs/lxp_pipe.h"
#include "fs/lxp_tmpfs.h"
#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"
#if LXP_ENABLE_FS
#include "fs/lxp_hostfs.h"
#endif

#include <string.h>

static long sys_write(lxp_proc_t *p, int fd, const void *buf, size_t len)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, len,
				 0)) /* the kernel READS buf → reject a bad source pointer */
		return -LXP_EFAULT;
	if (!lxp_vfs_writable(s))
		return -LXP_EBADF;
	/* A guest may write this buffer through a cacheable MPU view while the privileged host reads
	 * the same SDRAM through an uncached background view.  Publish dirty guest lines before any
	 * console/filesystem/device backend dereferences the payload.  Socket sends use the same hook
	 * internally; the duplicate clean is harmless and keeps this boundary correct for every fd. */
	if (len)
		lxp_cache_clean(buf, len);
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (ops && ops->write)
		return ops->write(p, s, buf, len);
	return -LXP_EBADF; /* read-only kind (rootfs/proc) or wrong-direction console */
}

static long sys_writev(lxp_proc_t *p, int fd, const lxp_iovec *iov, int iovcnt)
{
	/* Any fd sys_write accepts: console, socket (uClibc stdio flushes a socket via
	 * writev — this is how wget sends its HTTP request), device, file. sys_write
	 * validates the fd (EBADF) and routes by kind. */
	if (iovcnt < 0 || iovcnt > LXP_SYSCALL_MAX_IOV)
		return -LXP_EINVAL;
	if (iovcnt && !lxp_guest_access_ok(p, iov, (size_t)iovcnt * sizeof(*iov), 0))
		return -LXP_EFAULT; /* the iov array itself; each iov_base is checked in sys_write */
	/* Publish the descriptors before the host reads their bases and lengths.  sys_write() below
	 * publishes each referenced payload independently. */
	if (iovcnt)
		lxp_cache_clean(iov, (size_t)iovcnt * sizeof(*iov));
	lxp_ofd_t *slot = lxp_fd_description(p, fd);
	if (!slot)
		return -LXP_EBADF;
	/* The retry records describe one buffer, not an iovec cursor. Stop after one
	 * segment for fd kinds that may park; the legal short write lets libc retry
	 * the tail without losing an earlier byte count or orphaning backend state. */
	int single_segment = slot->kind == LXP_FD_PIPE || slot->kind == LXP_FD_DEV ||
			     slot->kind == LXP_FD_SOCKET || slot->kind == LXP_FD_PTY ||
			     slot->kind == LXP_FD_NET;

	long total = 0;
	size_t budget = LXP_SYSCALL_QUANTUM_BYTES;
	for (int i = 0; i < iovcnt; i++) {
		lxp_iovec entry;
		if (lxp_copy_from_guest(p, &entry, (uintptr_t)&iov[i], sizeof(entry)) != 0)
			return total ? total : -LXP_EFAULT;
		if (entry.iov_len == 0)
			continue;
		size_t len = entry.iov_len < budget ? entry.iov_len : budget;
		long r = sys_write(p, fd, entry.iov_base, len);
		if (r < 0)
			return total ? total : r;
		if ((size_t)r > len)
			return total ? total
				     : -LXP_EIO; /* host backend violated the write contract */
		total += r;
		budget -= (size_t)r;
		if (single_segment || (size_t)r < len || len < entry.iov_len || budget == 0)
			break; /* short write */
	}
	return total;
}

static long sys_read(lxp_proc_t *p, int fd, void *buf, size_t len)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, len,
				 1)) /* the kernel WRITES buf → reject a bad destination pointer */
		return -LXP_EFAULT;
	if (!lxp_vfs_readable(s))
		return -LXP_EBADF;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (ops && ops->read)
		return ops->read(p, s, buf, len);
	return -LXP_EBADF;
}

/*
 * pwrite64(fd, buf, count, offset): a positioned write that does NOT move the fd offset.
 * LVGL's fbdev driver (LV_LINUX_FBDEV_MMAP=0) writes each framebuffer scanline this way.
 * Device fds route to the driver; the writable overlay writes at the offset. Streams
 * return ESPIPE; a descriptor not open for writing (e.g. any rootfs file) is EBADF.
 */
static long sys_pwrite(lxp_proc_t *p, int fd, const void *buf, size_t len, uint64_t off)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, len, 0))
		return -LXP_EFAULT;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!ops || (!ops->pread && !ops->pwrite))
		return -LXP_ESPIPE; /* a stream: console, pipe, eventfd, socket, pty, 9P */
	if (!lxp_vfs_writable(s) || !ops->pwrite)
		return -LXP_EBADF;
	return ops->pwrite(p, s, buf, len, off);
}

static long sys_close(lxp_proc_t *p, int fd)
{
	return lxp_fd_close(p, fd);
}

/* pipe(2)/pipe2(2): allocate a pipe object + a read-end / write-end fd pair. @p flags
 * carries O_CLOEXEC for pipe2 (dropbear's exec-status pipe is a CLOEXEC pipe2). */
static long sys_pipe(lxp_proc_t *p, int *fds, int flags)
{
	if (!lxp_guest_access_ok(p, fds, 2 * sizeof(int), 1)) /* the kernel writes fds[0],fds[1] */
		return -LXP_EFAULT;
	/* pipe2(O_NONBLOCK / O_CLOEXEC) applies to both ends. */
	int shared = flags & (LXP_O_NONBLOCK | LXP_O_CLOEXEC);
	/* Reserve a pipe object; endpoint ownership is published as each open-file
	 * description is installed and released by its final close hook. */
	int pi = lxp_pipe_alloc();
	if (pi < 0)
		return -LXP_EMFILE;
	if (lxp_fd_free_count(p) < 2) {
		lxp_pipe_discard(pi);
		return -LXP_EMFILE;
	}
	int rfd = lxp_sys_fd_alloc(p, LXP_FD_PIPE, pi, 0, LXP_O_RDONLY | shared);
	if (rfd < 0) {
		lxp_pipe_discard(pi);
		return -LXP_EMFILE;
	}
	lxp_pipe_end_open(pi, 0);
	int wfd = lxp_sys_fd_alloc(p, LXP_FD_PIPE, pi, 0, LXP_O_WRONLY | shared);
	if (wfd < 0) {
		(void)sys_close(p, rfd);
		return -LXP_EMFILE;
	}
	(void)lxp_fd_set_end(p, wfd, 1);
	lxp_pipe_end_open(pi, 1);
	const int result[2] = {rfd, wfd};
	if (lxp_copy_to_guest(p, (uintptr_t)fds, result, sizeof(result)) != 0) {
		(void)sys_close(p, rfd);
		(void)sys_close(p, wfd);
		return -LXP_EFAULT;
	}
	return 0;
}

/* dup2/dup3: make newfd alias oldfd's target (the pipe wiring the shell does). */
static long sys_dup2(lxp_proc_t *p, int oldfd, int newfd)
{
	return lxp_fd_dup_to(p, oldfd, newfd, 0);
}

/* dup(2): alias oldfd onto the lowest free fd. */
static long sys_dup(lxp_proc_t *p, int oldfd)
{
	return lxp_fd_dup_min(p, oldfd, 0, 0);
}

/* The new offset of @p fd moved by the 64-bit @p off, or a negated errno. */
static int64_t fd_seek(lxp_proc_t *p, int fd, int64_t off, int whence)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!ops || !ops->lseek)
		return -LXP_ESPIPE; /* console/pipe/eventfd/pty/socket are not seekable */
	return ops->lseek(p, s, off, whence);
}

/* lseek(2): the guest's off_t is 32-bit, so a result beyond it is EOVERFLOW (the
 * offset has still moved, as on Linux). */
static long sys_lseek(lxp_proc_t *p, int fd, long off, int whence)
{
	int64_t pos = fd_seek(p, fd, (int64_t)(int32_t)off, whence);
	if (pos > INT32_MAX)
		return -LXP_EOVERFLOW;
	return (long)pos;
}

/* _llseek(2): a 64-bit offset from two registers, the result stored at @p result. */
static long sys_llseek(lxp_proc_t *p, int fd, unsigned long off_hi, unsigned long off_lo,
		       uint64_t *result, unsigned int whence)
{
	int64_t offset = (int64_t)((uint64_t)(uint32_t)off_lo | ((uint64_t)(uint32_t)off_hi << 32));
	int64_t pos = fd_seek(p, fd, offset, (int)whence);
	if (pos < 0)
		return (long)pos;
	uint64_t position = (uint64_t)pos;
	if (result && lxp_copy_to_guest(p, (uintptr_t)result, &position, sizeof(*result)) != 0)
		return -LXP_EFAULT;
	return 0;
}

/* ftruncate64(fd, length): a negative length, a descriptor not open for writing and
 * kinds without a truncate file operation (streams) are EINVAL, as on Linux. */
static long sys_ftruncate(lxp_proc_t *p, int fd, uint64_t length)
{
	if ((int64_t)length < 0)
		return -LXP_EINVAL;
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!lxp_vfs_writable(s) || !ops || !ops->ftruncate)
		return -LXP_EINVAL; /* not open for writing, or not truncatable (console/pipe) */
	return ops->ftruncate(p, s, length);
}

static long sys_sync_fd(lxp_proc_t *p, int fd)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	/* tmpfs/rootfs have no backing write queue. Other open descriptors report
	 * success, which small libc utilities expect. */
	return ops && ops->fsync ? ops->fsync(p, s) : 0;
}

/* ── Larger syscall handlers. Raw argument names mirror the dispatcher ABI
 *    and make each handler unit-testable. ── */
static long sys_fcntl(lxp_proc_t *proc, long a0, long a1, long a2)
{
	lxp_ofd_t *s = lxp_fd_description(proc, (int)a0);
	if (!s)
		return -LXP_EBADF;
	if ((int)a1 == LXP_F_DUPFD || (int)a1 == LXP_F_DUPFD_CLOEXEC) {
		/* Duplicate to the lowest free fd >= arg. The shell asks for a high
			 * fd (>=255) for its interactive fd; our table is small, so a too-high
			 * arg falls back to any free fd (the shell tolerates a low one and
			 * relocates it if needed). */
		int from = (int)a2;
		if (from < 0 || from >= LXP_MAX_FDS)
			from = 0;
		return lxp_fd_dup_min(proc, (int)a0, from, (int)a1 == LXP_F_DUPFD_CLOEXEC);
	}
	/* F_SETFL changes only O_NONBLOCK here (the access mode is fixed at open); kinds
	 * that park on their own copy of the flag mirror it (LVGL's evdev opens blocking,
	 * then sets O_NONBLOCK; dropbear drives its pty master and SIGCHLD self-pipe
	 * non-blocking). */
	if ((int)a1 == LXP_F_SETFL) {
		s->nonblock = ((int)a2 & LXP_O_NONBLOCK) ? 1 : 0;
		const lxp_file_ops_t *ops = lxp_vfs_ops(s);
		if (ops && ops->setfl)
			ops->setfl(proc, s);
		return 0;
	}
	/* F_GETFL reports the access mode recorded at open. uClibc's fdopen() validates the
	 * FILE* mode against it, so a writable fd reported read-only fails fdopen(fd, "w")
	 * (dropbearkey's .pub write) and a socket must report O_RDWR (wget's fdopen). */
	if ((int)a1 == LXP_F_GETFL)
		return s->accmode | (s->nonblock ? LXP_O_NONBLOCK : 0);
	/* F_SETFD/F_GETFD track close-on-exec (dropbear sets FD_CLOEXEC on its exec-status
		 * pipe and detects a successful shell exec by that fd closing on execve). */
	if ((int)a1 == LXP_F_SETFD) {
		return lxp_fd_set_cloexec(proc, (int)a0, ((int)a2 & LXP_FD_CLOEXEC) != 0);
	}
	if ((int)a1 == LXP_F_GETFD) {
		int cloexec = lxp_fd_get_cloexec(proc, (int)a0);
		return cloexec > 0 ? LXP_FD_CLOEXEC : cloexec;
	}
	return 0;
}

static long sys_ioctl(lxp_proc_t *proc, long a0, long a1, long a2)
{
	lxp_ofd_t *s = lxp_fd_description(proc, (int)a0);
	if (!s)
		return -LXP_ENOTTY;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (ops && ops->ioctl)
		return ops->ioctl(proc, s, (unsigned long)a1, (unsigned long)a2);
	return -LXP_ENOTTY; /* not a tty / char device / socket */
}

/* getdents/getdents64: emit the directory's next records as linux_dirent (is64=0) or
 * linux_dirent64 (is64=1). uClibc's readdir on this FDPIC target uses the 32-bit
 * getdents(2) for some callers (e.g. dropbear's pty session setup), so both are
 * supported. */
static long sys_getdents64(lxp_proc_t *p, int fd, void *buf, size_t count, int is64)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, count, 1))
		return -LXP_EFAULT;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!ops || !ops->getdents)
		return -LXP_ENOTDIR;
	lxp_dirent_sink_t sink = {.proc = p, .ubuf = (uintptr_t)buf, .cap = count, .is64 = is64};
	return ops->getdents(p, s, &sink);
}

/* Install for subsystems that own their object pools (sockets, /proc, eventfd, 9P). */
int lxp_fd_install(lxp_proc_t *p, uint8_t kind, int idx, int flags)
{
	return lxp_sys_fd_alloc(p, kind, idx, 0, flags);
}

/* Claim the lowest free fd for (kind, idx, off) opened with @p flags; -EMFILE if the
 * table is full. */
int lxp_sys_fd_alloc(lxp_proc_t *p, uint8_t kind, int idx, size_t off, int flags)
{
	if (kind == LXP_FD_TMPFS && lxp_wfs_open(idx) != 0)
		return -LXP_EMFILE;
	int fd = lxp_fd_open(p, kind, idx, off, flags);
	if (fd < 0 && kind == LXP_FD_TMPFS)
		lxp_wfs_close(idx);
	return fd;
}

/*
 * pread64(fd, buf, count, offset): a positioned read that does NOT move the fd offset.
 * ld.so uses it to pull each PT_LOAD of a .so out of the rootfs into the anonymous memory
 * it mapped (the NOMMU path: MAP_FIXED-file mmap fails, so it mmaps anon + preads). Kinds
 * without a pread file operation are streams and return ESPIPE; a descriptor not open
 * for reading is EBADF.
 */
long lxp_sys_fd_pread(lxp_proc_t *p, int fd, void *buf, size_t len, uint64_t off)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, len, 1))
		return -LXP_EFAULT;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!ops || !ops->pread)
		return -LXP_ESPIPE; /* a stream: console, pipe, eventfd, socket, pty, 9P */
	if (!lxp_vfs_readable(s))
		return -LXP_EBADF;
	return ops->pread(p, s, buf, len, off);
}

long lxp_sys_read(lxp_proc_t *proc, const long a[6])
{
	return sys_read(proc, (int)a[0], (void *)(uintptr_t)a[1], (size_t)a[2]);
}

long lxp_sys_write(lxp_proc_t *proc, const long a[6])
{
	return sys_write(proc, (int)a[0], (const void *)(uintptr_t)a[1], (size_t)a[2]);
}

long lxp_sys_writev(lxp_proc_t *proc, const long a[6])
{
	return sys_writev(proc, (int)a[0], (const lxp_iovec *)(uintptr_t)a[1], (int)a[2]);
}

/* (fd, buf, count, [pad a3], off_lo a4, off_hi a5) */
long lxp_sys_pread64(lxp_proc_t *proc, const long a[6])
{
	return lxp_sys_fd_pread(proc, (int)a[0], (void *)(uintptr_t)a[1], (size_t)a[2],
			 (uint64_t)(uint32_t)a[4] | ((uint64_t)(uint32_t)a[5] << 32));
}

/* (fd, buf, count, [pad a3], off_lo a4, off_hi a5) */
long lxp_sys_pwrite64(lxp_proc_t *proc, const long a[6])
{
	return sys_pwrite(proc, (int)a[0], (const void *)(uintptr_t)a[1], (size_t)a[2],
			  (uint64_t)(uint32_t)a[4] | ((uint64_t)(uint32_t)a[5] << 32));
}

long lxp_sys_close(lxp_proc_t *proc, const long a[6])
{
	return sys_close(proc, (int)a[0]);
}

long lxp_sys_pipe(lxp_proc_t *proc, const long a[6])
{
	return sys_pipe(proc, (int *)(uintptr_t)a[0], 0);
}

/* (fds, flags) — flags carries O_CLOEXEC and/or O_NONBLOCK */
long lxp_sys_pipe2(lxp_proc_t *proc, const long a[6])
{
	return sys_pipe(proc, (int *)(uintptr_t)a[0], (int)a[1]);
}

long lxp_sys_dup(lxp_proc_t *proc, const long a[6])
{
	return sys_dup(proc, (int)a[0]);
}

long lxp_sys_dup2(lxp_proc_t *proc, const long a[6])
{
	return sys_dup2(proc, (int)a[0], (int)a[1]);
}

/* (old, new, flags) — flags carries O_CLOEXEC on the new fd */
long lxp_sys_dup3(lxp_proc_t *proc, const long a[6])
{
	if ((int)a[0] == (int)a[1]) /* dup3 (unlike dup2) rejects oldfd == newfd */
		return -LXP_EINVAL;
	return lxp_fd_dup_to(proc, (int)a[0], (int)a[1], ((int)a[2] & LXP_O_CLOEXEC) != 0);
}

long lxp_sys_lseek(lxp_proc_t *proc, const long a[6])
{
	return sys_lseek(proc, (int)a[0], a[1], (int)a[2]);
}

long lxp_sys_llseek(lxp_proc_t *proc, const long a[6])
{
	return sys_llseek(proc, (int)a[0], (unsigned long)a[1], (unsigned long)a[2],
			  (uint64_t *)(uintptr_t)a[3], (unsigned int)a[4]);
}

long lxp_sys_ftruncate64(lxp_proc_t *proc, const long a[6])
{
	/* 64-bit length is register-pair aligned on ARM: fd=a[0], len=(a[2],a[3]). */
	return sys_ftruncate(proc, (int)a[0],
			     (uint64_t)(uint32_t)a[2] | ((uint64_t)(uint32_t)a[3] << 32));
}

long lxp_sys_fsync(lxp_proc_t *proc, const long a[6])
{
	return sys_sync_fd(proc, (int)a[0]);
}

long lxp_sys_sync(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	(void)proc;
#if LXP_ENABLE_FS
	(void)lxp_hostfs_sync_all();
#endif
	return 0;
}

long lxp_sys_syncfs(lxp_proc_t *proc, const long a[6])
{
	lxp_ofd_t *slot = lxp_fd_description(proc, (int)a[0]);
	if (!slot)
		return -LXP_EBADF;
#if LXP_ENABLE_FS
	if (slot->kind == LXP_FD_HOSTFS)
		return lxp_hostfs_sync_all();
#endif
	return 0;
}

/* old 32-bit fcntl: same dispatch as fcntl64 here */
long lxp_sys_fcntl(lxp_proc_t *proc, const long a[6])
{
	return sys_fcntl(proc, a[0], a[1], a[2]);
}

long lxp_sys_ioctl(lxp_proc_t *proc, const long a[6])
{
	return sys_ioctl(proc, a[0], a[1], a[2]);
}

/* 32-bit linux_dirent (uClibc readdir on this target) */
long lxp_sys_getdents(lxp_proc_t *proc, const long a[6])
{
	return sys_getdents64(proc, (int)a[0], (void *)(uintptr_t)a[1], (size_t)a[2], 0);
}

long lxp_sys_getdents64(lxp_proc_t *proc, const long a[6])
{
	return sys_getdents64(proc, (int)a[0], (void *)(uintptr_t)a[1], (size_t)a[2], 1);
}

/* (initval, flags) — curl's threaded-resolver wakeup */
long lxp_sys_eventfd2(lxp_proc_t *proc, const long a[6])
{
	return lxp_eventfd_open(proc, (unsigned)a[0], (int)a[1]);
}
