/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#include "lxp/lxp_config.h"
#include "lxp_loader.h" /* lxp_loader_abi_incompatible — refuse a wrong-ABI execve up front */

#include "lxp/lxp_stats.h"
#include "lxp_syscall.h"
#include "lxp/lxp_types.h"

#include "lxp_internal.h" /* lxp_guest_access_ok / lxp_guest_strnlen / file_mode / lxp_encode_wstatus */
#include "lxp_text.h"	  /* bounded text construction for synthetic names */
#include "fs/lxp_vfs.h"	  /* per-fd-kind file-operation vtable (dispatch by kind) */

#include "fs/lxp_dirent.h"      /* getdents record output */
#include "fs/lxp_eventfd.h"     /* eventfd2(2) counters (FD_EVENTFD) */
#include "fs/lxp_fd_private.h" /* descriptor-table reference transaction */
#if LXP_ENABLE_FS
#include "fs/lxp_hostfs.h" /* writable host mount (FD_HOSTFS, /data) */
#endif
#include "fs/lxp_path.h"     /* path resolution (resolve_path / fs_lookup / fs_follow) */
#include "fs/lxp_pipe.h"     /* pipe ring ops (FD_PIPE) */
#include "fs/lxp_stat.h"     /* ARM struct stat64 record */
#include "fs/lxp_tmpfs.h"    /* writable VFS overlay nodes (FD_TMPFS) */
#include "proc/lxp_procfs.h" /* synthetic /proc content generation (FD_PROC) */
#include "proc/lxp_script.h" /* bounded #! parsing shared with initial launch */
#if LXP_ENABLE_DEV
#include "dev/lxp_dev.h" /* /dev character-device routing (FD_DEV) */
#endif
#if LXP_ENABLE_NET
#include "net/lxp_net.h" /* socket routing (FD_SOCKET) */
#endif
#if LXP_ENABLE_NETFS
#include "netfs/lxp_netfs.h" /* remote-fs routing (FD_NET, /mnt/pi) */
#endif
#if LXP_ENABLE_PTY
#include "pty/lxp_pty.h" /* pseudo-terminal routing (FD_PTY) */
#endif

#include <limits.h>
#include <string.h>

/* Kept in the syscall core so isolated syscall tests do not need the run loop.
 * Accessors keep this coordinator policy out of the public RTOS seam. */
static uint8_t g_halt_requested;

void lxp_request_halt(void)
{
	g_halt_requested = 1;
}

void lxp_reset_halt_request(void)
{
	g_halt_requested = 0;
}

int lxp_halt_requested(void)
{
	return g_halt_requested != 0;
}

/* ABI pins for the tty/poll uapi structs (lxp_proc.h). Fixed-width fields → these
 * hold on the 32-bit target and the 64-bit host build; a drift fails the build. */
LXP_STATIC_ASSERT(sizeof(struct lxp_termios) == 36, "termios ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_termios, c_cc) == 17, "termios c_cc offset drifted");
LXP_STATIC_ASSERT(sizeof(struct lxp_winsize) == 8, "winsize ABI size drifted");
LXP_STATIC_ASSERT(sizeof(struct lxp_pollfd) == 8, "pollfd ABI size drifted");

/*
 * Linux syscall personality — engine-agnostic dispatch.
 *
 * Translates the Linux syscall ABI into host-agnostic module primitives. The trap frame is
 * decoded by the per-engine SVC seam, which calls lxp_syscall() with the
 * register arguments; this file holds the dispatcher and most syscall handlers.
 * Pointer arguments are program addresses — in the flat (NOMMU) model the
 * program shares our address space, so they are used directly once
 * lxp_guest_access_ok() has checked them against the process's memory.
 */

/* fd kinds (lxp_ofd_t.kind) live in lxp_proc.h and are shared with subsystem TUs. */

static int fd_alloc(lxp_proc_t *p, uint8_t kind, int idx, size_t off);

#if LXP_ENABLE_NET
/* pselect6(2): select() over the poll machinery (busybox inetd + dropbear are
 * select-based). Defined with the poll retry below; the dispatch calls it earlier. */
#define LXP_SEL_MAXFDS 32 /* max nfds handled (fd_set = one 32-bit word here) */
static long sys_pselect6(lxp_proc_t *p, int nfds, uintptr_t urfds, uintptr_t uwfds, uintptr_t uefds,
			 uintptr_t utimeout);
#endif

/* The pipe subsystem (ring buffer + read/write/poll ops) lives in src/fs/lxp_pipe.c;
 * this dispatcher calls it via fs/lxp_pipe.h. */

#if LXP_ENABLE_NET
/* Resolve @p fd to its socket open-pool index, or -1 if @p fd is not a socket. Collapses
 * descriptor lookup + kind check that the socket syscalls all repeat. */
static int sock_slot(lxp_proc_t *p, int fd)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	return (s && s->kind == LXP_FD_SOCKET) ? s->file_idx : -1;
}

/* sendmsg(2): gather the message's iovec segments out over the socket. Ancillary data
 * (msg_control) is not interpreted — SCM_RIGHTS fd-passing is unsupported — so only the
 * ordinary payload is sent. Mirrors sys_writev: each segment goes through lxp_sock_send,
 * accumulating; a short segment ends the gather (a short sendmsg is legal). msg_name, when
 * present, is the datagram destination. If a later segment would block after earlier ones
 * were sent, the accumulated count is returned rather than parking mid-gather (the single-
 * buffer park cannot resume a partially-gathered message); a first-segment block parks as
 * usual and the coordinator retry completes it. */
static long sys_sendmsg(lxp_proc_t *p, int oi, const lxp_msghdr *umsg, int flags)
{
	lxp_msghdr m;
	if (lxp_copy_from_guest(p, &m, (uintptr_t)umsg, sizeof(m)) != 0)
		return -LXP_EFAULT;
	if (m.msg_iovlen > LXP_SYSCALL_MAX_IOV) /* bound before iovlen*sizeof(iovec) overflows */
		return -LXP_EINVAL;
	const lxp_iovec *iov = m.msg_iov;
	if (m.msg_iovlen && !lxp_guest_access_ok(p, iov, m.msg_iovlen * sizeof(*iov), 0))
		return -LXP_EFAULT; /* the iov array; each iov_base is checked in lxp_sock_send */
	const void *dest = (m.msg_name && m.msg_namelen) ? m.msg_name : NULL;

	/* A datagram is one message: gather every segment into a single packet, or a per-segment
	 * send would fragment it into several datagrams. Stream sockets keep the per-segment loop
	 * below (byte-stream, so segment boundaries don't matter). */
	if (m.msg_iovlen > 1 && lxp_sock_is_dgram(oi))
		return lxp_sock_sendmsg(p, oi, iov, (int)m.msg_iovlen, flags, dest, m.msg_namelen);

	long total = 0;
	size_t budget = LXP_SYSCALL_QUANTUM_BYTES;
	for (size_t i = 0; i < m.msg_iovlen; i++) {
		lxp_iovec entry;
		if (lxp_copy_from_guest(p, &entry, (uintptr_t)&iov[i], sizeof(entry)) != 0)
			return -LXP_EFAULT;
		if (entry.iov_len == 0)
			continue;
		size_t len = entry.iov_len < budget ? entry.iov_len : budget;
		long r = lxp_sock_send(p, oi, entry.iov_base, len, flags, dest, m.msg_namelen);
		if (r < 0)
			return total ? total : r;
		if ((size_t)r > len)
			return total ? total
				     : -LXP_EIO; /* host backend violated the write contract */
		if (p->wait.kind == LXP_WAIT_SOCKET) { /* this segment parked */
			if (total >
			    0) { /* earlier segments already sent: short send, do not park */
				(void)lxp_wait_cancel(p);
				return total;
			}
			return 0; /* first segment: let the coordinator retry complete it */
		}
		total += r;
		budget -= (size_t)r;
		if ((size_t)r < len || len < entry.iov_len || budget == 0)
			break; /* short send */
	}
	return total;
}

/* recvmsg(2): scatter received bytes into the message's iovec. A single underlying recv
 * fills the first non-empty segment — a short read is always legal, and it keeps the
 * blocking recv's single-buffer park valid on the resume. No ancillary data is produced
 * (msg_controllen/msg_flags are cleared); msg_name, when present, is filled with the
 * source address (and msg_namelen updated) as recvfrom does. */
static long sys_recvmsg(lxp_proc_t *p, int oi, lxp_msghdr *umsg, int flags)
{
	lxp_msghdr m;
	if (lxp_copy_from_guest(p, &m, (uintptr_t)umsg, sizeof(m)) != 0)
		return -LXP_EFAULT;
	if (m.msg_iovlen > LXP_SYSCALL_MAX_IOV)
		return -LXP_EINVAL;
	const lxp_iovec *iov = m.msg_iov;
	if (m.msg_iovlen && !lxp_guest_access_ok(p, iov, m.msg_iovlen * sizeof(*iov), 0))
		return -LXP_EFAULT;
	m.msg_controllen = 0; /* no ancillary data is ever produced */
	m.msg_flags = 0;
	if (lxp_copy_to_guest(p, (uintptr_t)umsg, &m, sizeof(m)) != 0)
		return -LXP_EFAULT;

	/* Receive into the first non-empty segment only. A blocking recv parks with a single
	 * guest buffer, so a multi-segment scatter cannot be resumed after a park — and the
	 * transport does not report a datagram's true length, so MSG_TRUNC cannot be set. This is
	 * a legal short read for a stream socket; for a datagram it means the tail of a message
	 * larger than the first segment is lost. Callers that need the whole datagram should pass
	 * a single sufficiently large segment. */
	void *src = (m.msg_name && m.msg_namelen) ? m.msg_name : NULL;
	void *srclen = src ? &umsg->msg_namelen : NULL;
	for (size_t i = 0; i < m.msg_iovlen; i++) {
		lxp_iovec entry;
		if (lxp_copy_from_guest(p, &entry, (uintptr_t)&iov[i], sizeof(entry)) != 0)
			return -LXP_EFAULT;
		if (entry.iov_len == 0)
			continue;
		size_t len = entry.iov_len;
		if (len > LXP_SYSCALL_QUANTUM_BYTES)
			len = LXP_SYSCALL_QUANTUM_BYTES;
		return lxp_sock_recv(p, oi, entry.iov_base, len, flags, src, srclen);
	}
	return 0; /* no buffer space in the iov: nothing received */
}
#endif

static long sys_write(lxp_proc_t *p, int fd, const void *buf, size_t len)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, len,
				 0)) /* the kernel READS buf → reject a bad source pointer */
		return -LXP_EFAULT;
#if LXP_ENABLE_FS
	if (s->kind == LXP_FD_HOSTFS && s->accmode == LXP_O_RDONLY)
		return -LXP_EBADF;
#endif
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
#if LXP_ENABLE_FS
	if (s->kind == LXP_FD_HOSTFS && s->accmode == LXP_O_WRONLY)
		return -LXP_EBADF;
#endif
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (ops && ops->read)
		return ops->read(p, s, buf, len);
	return -LXP_EBADF;
}

/*
 * pread64(fd, buf, count, offset): a positioned read that does NOT move the fd offset.
 * ld.so uses it to pull each PT_LOAD of a .so out of the rootfs into the anonymous memory
 * it mapped (the NOMMU path: MAP_FIXED-file mmap fails, so it mmaps anon + preads). Kinds
 * without a pread file operation are streams and return ESPIPE.
 */
static long sys_pread(lxp_proc_t *p, int fd, void *buf, size_t len, uint64_t off)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, len, 1))
		return -LXP_EFAULT;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!ops || !ops->pread)
		return -LXP_ESPIPE; /* a stream: console, pipe, eventfd, socket, pty, 9P */
	return ops->pread(p, s, buf, len, off);
}

/*
 * pwrite64(fd, buf, count, offset): a positioned write that does NOT move the fd offset.
 * LVGL's fbdev driver (LV_LINUX_FBDEV_MMAP=0) writes each framebuffer scanline this way.
 * Device fds route to the driver; the writable overlay writes at the offset; kinds
 * without a pwrite file operation (streams, the read-only rootfs) return ESPIPE.
 */
static long sys_pwrite(lxp_proc_t *p, int fd, const void *buf, size_t len, uint64_t off)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, buf, len, 0))
		return -LXP_EFAULT;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!ops || !ops->pwrite)
		return -LXP_ESPIPE; /* a stream, or the read-only rootfs */
	return ops->pwrite(p, s, buf, len, off);
}

/*
 * mprotect: a no-op on NOMMU (there is no per-page protection). ld.so calls it to apply
 * PT_GNU_RELRO hardening; it must succeed rather than fault the loader.
 */
static long sys_mprotect(uintptr_t addr, size_t len, int prot)
{
	(void)addr;
	(void)len;
	(void)prot;
	return 0;
}

static long sys_brk(lxp_proc_t *p, uintptr_t addr)
{
	/* Linux brk: move the break to addr if valid, then return the (possibly
	 * unchanged) break. uClibc's sbrk detects failure by ret != requested. */
	if (!p || !p->mm)
		return 0;
	if (addr >= p->mm->brk_base && addr <= p->mm->brk_max)
		p->mm->brk_cur = addr;
	return (long)p->mm->brk_cur;
}

static long sys_exit(lxp_proc_t *p, int status, int group)
{
	(void)lxp_intent_exit(p, group);
	p->exit_status = status & 0xff;
	if (group && p->group) {
		p->group->exiting = 1;
		p->group->exit_status = p->exit_status;
	}
	p->exit_reason = LXP_EXIT_REASON_NORMAL;
	p->exit_signal = 0;
	p->exit_detail = 0;
	p->exit_address = 0;
	return 0;
}

/*
 * mmap: anonymous and private file mappings are backed by the process arena
 * (uClibc's malloc uses anonymous maps for larger allocations; ld.so maps .so
 * segments). Read-only maps of a rootfs file share the file in place, and a
 * device with an mmap op maps its own memory.
 */
static long sys_mmap2(lxp_proc_t *p, uintptr_t addr, size_t len, int prot, int flags, int fd,
		      uint32_t pgoff)
{
	(void)addr;
	if (!p || !p->mm || !p->mm->arena || len == 0)
		return -LXP_EINVAL;

	/* Text-sharing: a read-only file map of a rootfs file whose whole extent lies within the file
	 * is returned IN-PLACE (zero-copy). FDPIC text is pure PIC — its relocations land in the
	 * per-process GOT/data, never the shared text — so every dynamic process shares ONE libc.so
	 * text copy (the cpio bytes) instead of its own ~358K arena copy. Every engine exposes the
	 * backing span to its unprivileged guest as RO+X: a static or per-task window on FreeRTOS,
	 * Zephyr's user-RX text/QSPI region, or the NuttX port's raw MPU region. */
	if (!(flags & LXP_MAP_ANONYMOUS) && fd >= 0 && !(prot & 0x2 /* PROT_WRITE */)) {
		lxp_ofd_t *s = lxp_fd_description(p, fd);
		if (s && s->kind == LXP_FD_FILE) {
			const lxp_file_t *f = &p->fs[s->file_idx];
			size_t foff =
				(size_t)pgoff * 4096u; /* guard the *4096 and +len wraps (32-bit) */
			if (foff / 4096u == (size_t)pgoff && foff <= f->size &&
			    f->size - foff >= len)
				return (long)(uintptr_t)(f->data + foff);
		}
	}

#if LXP_ENABLE_DEV
	/* A real /dev fd with a driver .mmap op (e.g. /dev/fb0) is mapped to
	 * the device's own buffer — lxp_dev_mmap parks on DEVW_MMAP and the coordinator
	 * installs the unprivileged MPU region + resumes with the mapped address. Devices
	 * without an .mmap op return -ENODEV and fall through to the anonymous-arena copy. */
	if (fd >= 0 && !(flags & LXP_MAP_ANONYMOUS)) {
		lxp_ofd_t *s = lxp_fd_description(p, fd);
		if (s && s->kind == LXP_FD_DEV) {
			long r = lxp_dev_mmap(p, s->file_idx, len, pgoff);
			if (r != -LXP_ENODEV)
				return r;
		}
	}
#endif

	void *m = lxp_arena_alloc_tracked(p->mm->arena, len);
	if (!m)
		return -LXP_ENOMEM;
	memset(m, 0, len); /* anon reads as zero; also zero-fills a file map's bss tail */
	if (!(flags & LXP_MAP_ANONYMOUS) && fd >= 0) {
		/* File-backed mapping: ld.so loads a .so's read-only segment (the symtab/hash/
		 * text) this way on NOMMU — read the file's bytes at the page offset into the
		 * freshly-allocated block. (Anonymous maps ignore the fd.) */
		long r = sys_pread(p, fd, m, len, pgoff * 4096u);
		if (r < 0) {
			(void)lxp_arena_free_tracked(p->mm->arena, m, len);
			return r;
		}
	}
	return (long)(uintptr_t)m;
}

/*
 * Arena-backed mappings are reclaimed only when both address and original
 * length match a privileged live-extent record.  Guest-writable arena headers
 * are not mapping authority: interior, stale, partial, brk and double unmaps
 * fail without changing allocator state.  Rootfs zero-copy and device mappings
 * live outside the arena and remain successful no-ops on this NOMMU target.
 */
static long sys_munmap(lxp_proc_t *p, uintptr_t addr, size_t len)
{
	if (!p || !p->mm || !p->mm->arena || len == 0)
		return -LXP_EINVAL;
	if (!lxp_arena_owns(p->mm->arena, (void *)addr))
		return 0;
	return lxp_arena_free_tracked(p->mm->arena, (void *)addr, len) ? 0 : -LXP_EINVAL;
}

/* Claim the lowest free fd for (kind, idx, off); -EMFILE if the table is full. */
static int fd_alloc(lxp_proc_t *p, uint8_t kind, int idx, size_t off)
{
	if (kind == LXP_FD_TMPFS && wfs_open(idx) != 0)
		return -LXP_EMFILE;
	int fd = lxp_fd_open(p, kind, idx, off);
	if (fd < 0 && kind == LXP_FD_TMPFS)
		wfs_close(idx);
	return fd;
}

/* Public wrapper so the socket bridge can mint an accept(2) fd (the fd table is
 * owned by lxp_fd.c; the bridge owns the socket pool). */
int lxp_fd_install(lxp_proc_t *p, uint8_t kind, int idx)
{
	return fd_alloc(p, kind, idx, 0);
}

/* eventfd(2): a 64-bit counter fd used to wake a poller from another thread — curl's
 * threaded resolver (AsynchDNS) writes it when a name resolves. Descriptor aliases
 * share the refcounted open-file description and counter pool index. */

static long sys_openat(lxp_proc_t *p, int dirfd, const char *path, int flags)
{
	(void)dirfd; /* dirfd is AT_FDCWD; relative paths resolve against p->fs_context->cwd */
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	path = abspath;
	if (proc_is(path)) /* synthetic /proc shadows everything */
		return lxp_procfs_open(p, path);
#if LXP_ENABLE_FS
	/* The mount boundary is exact: /data and descendants route to the host
	 * provider, while /database remains part of the ordinary rootfs/tmpfs. */
	if (lxp_hostfs_match(path)) {
		long hi = lxp_hostfs_open(p, path, flags);
		if (hi < 0)
			return hi;
		int fd = fd_alloc(p, LXP_FD_HOSTFS, (int)hi, 0);
		if (fd < 0)
			lxp_hostfs_close((int)hi);
		else {
			(void)lxp_fd_set_status(p, fd, flags & LXP_O_ACCMODE,
						(flags & LXP_O_NONBLOCK) != 0);
			(void)lxp_fd_set_cloexec(p, fd, (flags & LXP_O_CLOEXEC) != 0);
		}
		return fd;
	}
#endif
	/* The synthetic console/null/random nodes all open as an FD_CONSOLE; file_idx selects
	 * the behaviour (2 = r/w console, 3 = /dev/null → EOF/discard, 4 = host entropy,
	 * 5 = /dev/zero → zero-fill/discard). A small name→idx table instead of a strcmp chain
	 * (smaller .text). getty opens /dev/console + dups it to fds 0/1/2; dropbear/mbedTLS open
	 * /dev/urandom for entropy. */
	static const struct {
		const char *path;
		uint8_t idx;
	} console_dev[] = {
		{"/dev/console", 2}, {"/dev/tty", 2},	  {"/dev/tty0", 2},   {"/dev/ttyS0", 2},
		{"/dev/null", 3},    {"/dev/urandom", 4}, {"/dev/random", 4}, {"/dev/zero", 5},
	};
	for (size_t k = 0; k < sizeof(console_dev) / sizeof(console_dev[0]); k++)
		if (strcmp(path, console_dev[k].path) == 0)
			return fd_alloc(p, LXP_FD_CONSOLE, console_dev[k].idx, 0);
#if LXP_ENABLE_PTY
	/* Unix98 pty: each open of /dev/ptmx mints a fresh pair (the master, rw=1); the
	 * slave is /dev/pts/N (rw=0), N = the pool index from TIOCGPTN/ptsname. */
	if (strcmp(path, "/dev/ptmx") == 0) {
		long idx = lxp_pty_open_master(flags);
		if (idx < 0)
			return idx;
		int fd = fd_alloc(p, LXP_FD_PTY, (int)idx, 0);
		if (fd >= 0) {
			(void)lxp_fd_set_status(p, fd, 1, 0); /* master end */
			lxp_pty_end_open((int)idx, 1);
		} else {
			lxp_pty_discard((int)idx);
		}
		return fd;
	}
	if (strncmp(path, "/dev/pts/", 9) == 0) {
		int num = 0;
		const char *d = path + 9;
		if (*d < '0' || *d > '9')
			return -LXP_ENOENT;
		for (; *d >= '0' && *d <= '9'; d++)
			num = num * 10 + (*d - '0');
		if (*d != '\0')
			return -LXP_ENOENT;
		long idx = lxp_pty_open_slave(num, flags);
		if (idx < 0)
			return idx;
		int fd = fd_alloc(p, LXP_FD_PTY, (int)idx, 0); /* slave end (rw=0) */
		if (fd >= 0)
			lxp_pty_end_open((int)idx, 0);
		return fd;
	}
#endif
#if LXP_ENABLE_DEV
	/* Registered character devices (/dev/fb0, /dev/input/event0, ...). A hit opens
	 * an FD_DEV whose file_idx is the device open-pool index; a miss falls through. */
	{
		int di = lxp_dev_lookup(path);
		if (di >= 0) {
			long oi = lxp_dev_open_new(p, di, flags);
			if (oi < 0)
				return oi;
			int fd = fd_alloc(p, LXP_FD_DEV, (int)oi, 0);
			if (fd < 0)
				lxp_dev_close((int)oi);
			return fd;
		}
	}
#endif
#if LXP_ENABLE_NETFS
	/* Remote 9P mount (/mnt/pi): read-only browse. Shadows the RO rootfs; the open
	 * parks (walk+getattr+lopen round-trips) and the coordinator installs the fd. */
	if (lxp_netfs_lookup(path) >= 0)
		return lxp_netfs_open(p, path, flags);
#endif
	int wr = (flags & LXP_O_ACCMODE) != LXP_O_RDONLY;
	int wi = wfs_find(path);

	/* A writable open (or O_CREAT) goes to the writable VFS overlay. */
	if (wr || (flags & LXP_O_CREAT)) {
		if (wi < 0) {
			if (!(flags & LXP_O_CREAT)) {
				if (fs_lookup(p, path) >= 0)
					return -LXP_EROFS; /* RO rootfs file */
				return -LXP_ENOENT;
			}
			wi = wfs_create(path, LXP_S_IFREG | 0644u);
			if (wi < 0)
				return -LXP_EMFILE;
		} else {
			if ((wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR)
				return -LXP_EISDIR;
			if (flags & LXP_O_TRUNC)
				wnode_at(wi)->size = 0;
		}
		return fd_alloc(p, LXP_FD_TMPFS, wi,
				(flags & LXP_O_APPEND) ? wnode_at(wi)->size : 0);
	}

	/* Read: a writable node shadows the rootfs; else the read-only rootfs. */
	if (wi >= 0)
		return fd_alloc(p, LXP_FD_TMPFS, wi, 0);
	/* Follow symlinks so a read open of e.g. /lib/libc.so.0 -> libuClibc.so returns the
	 * target ELF (ld.so opens its .so deps by their symlinked SONAMEs). */
	int idx = fs_follow(p, fs_lookup(p, path));
	if (idx >= 0)
		return fd_alloc(p, LXP_FD_FILE, idx, 0);
	return -LXP_ENOENT;
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
	uint8_t cx = (flags & LXP_O_CLOEXEC) ? 1 : 0;
	uint8_t nb = (flags & LXP_O_NONBLOCK) ? 1
					      : 0; /* pipe2(O_NONBLOCK): both ends non-blocking */
	/* Reserve a pipe object; endpoint ownership is published as each open-file
	 * description is installed and released by its final close hook. */
	int pi = lxp_pipe_alloc();
	if (pi < 0)
		return -LXP_EMFILE;
	if (lxp_fd_free_count(p) < 2) {
		lxp_pipe_discard(pi);
		return -LXP_EMFILE;
	}
	int rfd = fd_alloc(p, LXP_FD_PIPE, pi, 0);
	if (rfd < 0) {
		lxp_pipe_discard(pi);
		return -LXP_EMFILE;
	}
	(void)lxp_fd_set_status(p, rfd, 0, nb);
	lxp_pipe_end_open(pi, 0);
	int wfd = fd_alloc(p, LXP_FD_PIPE, pi, 0);
	if (wfd < 0) {
		(void)sys_close(p, rfd);
		return -LXP_EMFILE;
	}
	(void)lxp_fd_set_status(p, wfd, 1, nb);
	lxp_pipe_end_open(pi, 1);
	(void)lxp_fd_set_cloexec(p, rfd, cx);
	(void)lxp_fd_set_cloexec(p, wfd, cx);
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

static long sys_lseek(lxp_proc_t *p, int fd, long off, int whence)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (ops && ops->lseek)
		return ops->lseek(p, s, off, whence);
	return -LXP_ESPIPE; /* console/pipe/proc/eventfd/pty/socket not seekable */
}

/* _llseek(fd, offset_high, offset_low, loff_t *result, whence): signed 64-bit
 * offsets are mandatory for block media above 2 GiB. */
static long sys_llseek(lxp_proc_t *p, int fd, unsigned long off_hi, unsigned long off_lo,
		       uint64_t *result, unsigned int whence)
{
	lxp_ofd_t *slot = lxp_fd_description(p, fd);
	if (!slot)
		return -LXP_EBADF;
	int64_t offset = (int64_t)((uint64_t)(uint32_t)off_lo | ((uint64_t)(uint32_t)off_hi << 32));
	uint64_t position;
#if LXP_ENABLE_DEV
	if (slot->kind == LXP_FD_DEV) {
		int rc = lxp_dev_llseek(slot->file_idx, offset, (int)whence, &position);
		if (rc < 0)
			return rc;
	} else
#endif
	{
		if (offset < LONG_MIN || offset > LONG_MAX)
			return -LXP_EOVERFLOW;
		long pos = sys_lseek(p, fd, (long)offset, (int)whence);
		if (pos < 0)
			return pos;
		position = (uint64_t)pos;
	}
	if (result && lxp_copy_to_guest(p, (uintptr_t)result, &position, sizeof(*result)) != 0)
		return -LXP_EFAULT;
	return 0;
}

/* ftruncate64(fd, length): a negative length, and kinds without a truncate file
 * operation (the read-only rootfs, streams), are EINVAL. */
static long sys_ftruncate(lxp_proc_t *p, int fd, uint64_t length)
{
	if ((int64_t)length < 0)
		return -LXP_EINVAL;
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (!ops || !ops->ftruncate)
		return -LXP_EINVAL; /* the rootfs is read-only; console/pipe N/A */
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

/* Linux mount flags which have meaningful or intrinsically satisfied semantics
 * in the bounded hostfs namespace. Unsupported flags are rejected explicitly. */
#define LXP_MS_RDONLY 0x00000001ul
#define LXP_MS_NOSUID 0x00000002ul
#define LXP_MS_NODEV 0x00000004ul
#define LXP_MS_NOEXEC 0x00000008ul
#define LXP_MS_REMOUNT 0x00000020ul
#define LXP_MS_NOATIME 0x00000400ul
#define LXP_MS_NODIRATIME 0x00000800ul
#define LXP_MS_SILENT 0x00008000ul
#define LXP_MS_RELATIME 0x00200000ul
#define LXP_MS_MGC_MSK 0xffff0000ul
#define LXP_MS_MGC_VAL 0xc0ed0000ul

static long mount_copy_string(lxp_proc_t *p, const char *guest, char *out, size_t capacity)
{
	if (!guest) {
		out[0] = '\0';
		return 0;
	}
	size_t length = 0;
	return lxp_copy_string_from_guest(p, out, capacity, (uintptr_t)guest, &length);
}

#if LXP_ENABLE_FS && LXP_ENABLE_BLOCK
static int mount_type_supported(const char *type)
{
	return type[0] == '\0' || strcmp(type, "auto") == 0 || strcmp(type, "vfat") == 0 ||
	       strcmp(type, "msdos") == 0 || strcmp(type, "fat") == 0;
}

static long mount_parse_options(char *options, unsigned long *flags)
{
	char *cursor = options;
	while (*cursor) {
		char *option = cursor;
		char *comma = strchr(cursor, ',');
		if (comma) {
			*comma = '\0';
			cursor = comma + 1;
		} else {
			cursor += strlen(cursor);
		}
		if (option[0] == '\0' || strcmp(option, "defaults") == 0 ||
		    strcmp(option, "rw") == 0) {
			if (strcmp(option, "rw") == 0)
				*flags &= ~LXP_MS_RDONLY;
		} else if (strcmp(option, "ro") == 0) {
			*flags |= LXP_MS_RDONLY;
		} else if (strcmp(option, "nosuid") == 0) {
			*flags |= LXP_MS_NOSUID;
		} else if (strcmp(option, "nodev") == 0) {
			*flags |= LXP_MS_NODEV;
		} else if (strcmp(option, "noexec") == 0) {
			*flags |= LXP_MS_NOEXEC;
		} else if (strcmp(option, "noatime") == 0) {
			*flags |= LXP_MS_NOATIME;
		} else if (strcmp(option, "nodiratime") == 0) {
			*flags |= LXP_MS_NODIRATIME;
		} else if (strcmp(option, "relatime") == 0) {
			*flags |= LXP_MS_RELATIME;
		} else if (strcmp(option, "remount") == 0) {
			*flags |= LXP_MS_REMOUNT;
		} else {
			return -LXP_EOPNOTSUPP;
		}
	}
	return 0;
}

static int mount_target_is_dir(lxp_proc_t *p, const char *target)
{
	if (strcmp(target, LXP_HOSTFS_DEFAULT_MOUNT) == 0)
		return 1;
	int wi = wfs_find(target);
	if (wi >= 0)
		return (wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR;
	int fi = fs_follow(p, fs_lookup(p, target));
	return fi >= 0 && (file_mode(&p->fs[fi]) & LXP_S_IFMT) == LXP_S_IFDIR;
}
#endif

static long sys_mount(lxp_proc_t *p, const char *source, const char *target,
		      const char *filesystem_type, unsigned long flags, const char *data)
{
	if (!target)
		return -LXP_EFAULT;
	char target_path[LXP_PATH_MAX];
	long rc = resolve_path(p, target, target_path, sizeof(target_path));
	if (rc < 0)
		return rc;
	if (strcmp(target_path, "/proc") == 0) {
		char type[16];
		rc = mount_copy_string(p, filesystem_type, type, sizeof(type));
		return rc < 0 ? rc
			      : (type[0] == '\0' || strcmp(type, "proc") == 0 ? 0 : -LXP_ENODEV);
	}
#if LXP_ENABLE_FS && LXP_ENABLE_BLOCK
	char type[16];
	char options[128];
	rc = mount_copy_string(p, filesystem_type, type, sizeof(type));
	if (rc < 0)
		return rc;
	rc = mount_copy_string(p, data, options, sizeof(options));
	if (rc < 0)
		return rc;
	if ((flags & LXP_MS_MGC_MSK) == LXP_MS_MGC_VAL)
		flags &= ~LXP_MS_MGC_MSK;
	rc = mount_parse_options(options, &flags);
	if (rc < 0)
		return rc;
	const unsigned long supported = LXP_MS_RDONLY | LXP_MS_NOSUID | LXP_MS_NODEV |
					LXP_MS_NOEXEC | LXP_MS_REMOUNT | LXP_MS_NOATIME |
					LXP_MS_NODIRATIME | LXP_MS_SILENT | LXP_MS_RELATIME;
	if ((flags & ~supported) != 0u)
		return -LXP_EOPNOTSUPP;
	if (!mount_type_supported(type))
		return -LXP_ENODEV;
	if ((flags & LXP_MS_REMOUNT) != 0u) {
		if (strcmp(target_path, lxp_hostfs_mount_path()) != 0)
			return -LXP_EINVAL;
		return lxp_hostfs_remount(p, (flags & LXP_MS_RDONLY) != 0u);
	}
	if (!source)
		return -LXP_EINVAL;
	if (strcmp(target_path, "/") == 0 || !mount_target_is_dir(p, target_path))
		return -LXP_ENOTDIR;
	char source_path[LXP_PATH_MAX];
	rc = resolve_path(p, source, source_path, sizeof(source_path));
	if (rc < 0)
		return rc;
	return lxp_hostfs_mount(p, source_path, target_path, (flags & LXP_MS_RDONLY) != 0u);
#else
	(void)source;
	(void)filesystem_type;
	(void)flags;
	(void)data;
#endif
	return -LXP_ENODEV;
}

static long sys_umount(lxp_proc_t *p, const char *target, int flags)
{
	if (!target)
		return -LXP_EFAULT;
	if (flags != 0)
		return -LXP_EOPNOTSUPP;
	char target_path[LXP_PATH_MAX];
	long rc = resolve_path(p, target, target_path, sizeof(target_path));
	if (rc < 0)
		return rc;
	if (strcmp(target_path, "/proc") == 0)
		return 0;
#if LXP_ENABLE_FS
	if (strcmp(target_path, lxp_hostfs_mount_path()) == 0)
		return lxp_hostfs_unmount(p, target_path);
#endif
	return -LXP_EINVAL;
}

/* The stat record of an open descriptor, for fstat64 and statx(AT_EMPTY_PATH). */
static long fd_stat(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (ops && ops->fstat)
		return ops->fstat(p, s, st);
	/* console/pipe/eventfd: a bare character device (S_IFCHR) so isatty()/stdio behaves. */
	lxp_stat_init(st, LXP_INO_DEV + (uint32_t)s->file_idx, LXP_S_IFCHR | 0620u, 0);
	return 0;
}

static long sys_fstat64(lxp_proc_t *p, int fd, void *statbuf)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, statbuf, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT;
	struct lxp_stat st;
	long rc = fd_stat(p, s, &st);
	return rc < 0 ? rc : lxp_stat_copyout(p, (uintptr_t)statbuf, 0, &st);
}

enum lxp_path_stat_result {
	LXP_PATH_STAT_LOCAL,
	LXP_PATH_STAT_NETFS,
};

/* Resolve all local pathname namespaces in their authoritative precedence.
 * Remote 9P metadata retains its asynchronous guest-buffer path, so identify
 * that boundary without duplicating the rest of the lookup ladder. */
static long path_stat_lookup(lxp_proc_t *p, const char *abspath, int follow,
			     struct lxp_stat *out)
{
	lxp_stat_init(out, 0, 0, 0);
	if (proc_is(abspath)) {
		out->mode = proc_mode(abspath, p);
		if (out->mode == 0)
			return -LXP_ENOENT;
		out->ino = LXP_INO_PROC;
		return LXP_PATH_STAT_LOCAL;
	}
#if LXP_ENABLE_DEV
	if (lxp_dev_stat_path(abspath, &out->mode, &out->rdev) == 0) {
		out->ino = LXP_INO_DEV;
		return LXP_PATH_STAT_LOCAL;
	}
#endif
#if LXP_ENABLE_NETFS
	if (lxp_netfs_lookup(abspath) >= 0)
		return LXP_PATH_STAT_NETFS;
#endif
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		long rc = lxp_hostfs_path_stat(p, abspath, &stat);
		if (rc < 0)
			return rc;
		lxp_hostfs_stat_record(out, lxp_hostfs_path_inode(abspath), &stat);
		return LXP_PATH_STAT_LOCAL;
	}
#endif
	int index = wfs_find(abspath);
	if (index >= 0) {
		lxp_stat_init(out, LXP_INO_TMPFS + (uint32_t)index, wnode_at(index)->mode,
			      wnode_at(index)->size);
		return LXP_PATH_STAT_LOCAL;
	}
	index = fs_lookup(p, abspath);
	if (index < 0)
		return -LXP_ENOENT;
	if (follow) {
		index = fs_follow(p, index);
		if (index < 0)
			return -LXP_ENOENT;
	}
	lxp_stat_init(out, LXP_INO_ROOTFS + (uint32_t)index, file_mode(&p->fs[index]),
		      p->fs[index].size);
	return LXP_PATH_STAT_LOCAL;
}

/* path-based stat: resolve, optionally follow a trailing symlink, fill kstat64. */
static long sys_stat_path(lxp_proc_t *p, const char *path, int follow, void *statbuf)
{
	if (!lxp_guest_access_ok(p, statbuf, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	struct lxp_stat stat;
	long source = path_stat_lookup(p, abspath, follow, &stat);
#if LXP_ENABLE_NETFS
	if (source == LXP_PATH_STAT_NETFS)
		return lxp_netfs_stat(p, abspath, (uintptr_t)statbuf, 0); /* parks */
#endif
	if (source < 0)
		return source;
	return lxp_stat_copyout(p, (uintptr_t)statbuf, 0, &stat);
}

/* readlink: write the symlink target (not NUL-terminated) + return its length. */
static long sys_readlink(lxp_proc_t *p, const char *path, char *buf, size_t bufsiz)
{
	if (!lxp_guest_access_ok(p, buf, bufsiz, 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (strcmp(abspath, "/proc/self") == 0) { /* -> the running process's pid */
		char tmp[12];
		lxp_text_t pid_text = lxp_text_make(tmp, sizeof(tmp));
		lxp_text_u64(&pid_text, (uint64_t)p->pid);
		size_t n = pid_text.length;
		if (n > bufsiz)
			n = bufsiz;
		if (lxp_copy_to_guest(p, (uintptr_t)buf, tmp, n) != 0)
			return -LXP_EFAULT;
		return (long)n;
	}
	if (strcmp(abspath, "/proc/self/exe") == 0) { /* -> the running program's path */
		/* Same running image execve re-runs for "/proc/self/exe" (exec_file_idx). Programs
		 * readlink() this to learn where they were launched from; without it they got ENOENT. */
		int ei = p->exec_file_idx;
		if (ei < 0 || ei >= p->fs_count)
			return -LXP_ENOENT;
		const char *exe = p->fs[ei].path;
		size_t n = strlen(exe);
		if (n > bufsiz)
			n = bufsiz;
		if (lxp_copy_to_guest(p, (uintptr_t)buf, exe, n) != 0)
			return -LXP_EFAULT;
		return (long)n;
	}
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath))
		return -LXP_EINVAL; /* The FAT-backed provider cannot contain symlinks. */
#endif
	int wi = wfs_find(abspath); /* a writable symlink (ln -s) shadows the rootfs */
	if (wi >= 0) {
		lxp_wnode_t *w = wnode_at(wi);
		if ((w->mode & LXP_S_IFMT) != LXP_S_IFLNK || !w->data)
			return -LXP_EINVAL;
		size_t n = w->size > bufsiz ? bufsiz : w->size;
		if (lxp_copy_to_guest(p, (uintptr_t)buf, w->data, n) != 0)
			return -LXP_EFAULT;
		return (long)n;
	}
	int idx = fs_lookup(p, abspath);
	if (idx < 0)
		return -LXP_ENOENT;
	const lxp_file_t *lnk = &p->fs[idx];
	if ((file_mode(lnk) & LXP_S_IFMT) != LXP_S_IFLNK || !lnk->data)
		return -LXP_EINVAL;
	size_t n = lnk->size > bufsiz ? bufsiz : lnk->size;
	if (lxp_copy_to_guest(p, (uintptr_t)buf, lnk->data, n) != 0)
		return -LXP_EFAULT;
	return (long)n;
}

/* access/faccessat: permissions are synthetic, but read-only/noexec hostfs
 * policy must not claim that an operation can succeed when it cannot. */
static long sys_access(lxp_proc_t *p, const char *path, int mode)
{
	if (!path)
		return -LXP_EFAULT;
	if ((mode & ~7) != 0)
		return -LXP_EINVAL;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (abspath[0] == '/' && abspath[1] == '\0')
		return 0; /* root */
	if (proc_is(abspath))
		return proc_mode(abspath, p) ? 0 : -LXP_ENOENT;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		long result = lxp_hostfs_path_stat(p, abspath, &stat);
		if (result < 0)
			return result;
		if ((mode & 2) != 0 && lxp_hostfs_is_read_only())
			return -LXP_EROFS;
		if ((mode & 1) != 0 && stat.type != LXP_FS_TYPE_DIR)
			return -LXP_EACCES;
		return 0;
	}
#endif
	if (wfs_find(abspath) >= 0 || fs_lookup(p, abspath) >= 0)
		return 0;
	return -LXP_ENOENT;
}

static long sys_mkdir(lxp_proc_t *p, const char *path, uint32_t mode)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath))
		return lxp_hostfs_mkdir(p, abspath);
#endif
	if (wfs_find(abspath) >= 0 || fs_lookup(p, abspath) >= 0)
		return -LXP_EEXIST;
	if (wfs_create(abspath, LXP_S_IFDIR | (mode & 0777u)) < 0)
		return -LXP_ENOSPC;
	return 0;
}

/* unlink (is_rmdir=0) / rmdir (is_rmdir=1) on a writable node. */
static long sys_unlink(lxp_proc_t *p, const char *path, int is_rmdir)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath))
		return is_rmdir ? lxp_hostfs_rmdir(p, abspath) : lxp_hostfs_unlink(p, abspath);
#endif
	int wi = wfs_find(abspath);
	if (wi < 0)
		return (fs_lookup(p, abspath) >= 0) ? -LXP_EROFS : -LXP_ENOENT;
	int isdir = (wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR;
	if (is_rmdir && !isdir)
		return -LXP_ENOTDIR;
	if (!is_rmdir && isdir)
		return -LXP_EISDIR;
	if (isdir) {
		for (int j = 0; j < LXP_NWNODE; j++)
			if (wnode_at(j)->used && lxp_path_child_name(abspath, wnode_at(j)->path))
				return -LXP_ENOTEMPTY;
	}
	wfs_free(wi); /* reclaim the node + its pool bytes */
	return 0;
}

static long sys_rename(lxp_proc_t *p, const char *oldp, const char *newp, unsigned flags)
{
	if (!oldp || !newp)
		return -LXP_EFAULT;
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	long r1 = resolve_path(p, oldp, oldabs, sizeof(oldabs));
	if (r1 < 0)
		return r1;
	long r2 = resolve_path(p, newp, newabs, sizeof(newabs));
	if (r2 < 0)
		return r2;
	if (flags != 0)
		return -LXP_EINVAL;
#if LXP_ENABLE_FS
	int old_host = lxp_hostfs_match(oldabs);
	int new_host = lxp_hostfs_match(newabs);
	if (old_host != new_host)
		return -LXP_EXDEV;
	if (old_host)
		return lxp_hostfs_rename(p, oldabs, newabs);
#endif
	int wi = wfs_find(oldabs);
	if (wi < 0)
		return (fs_lookup(p, oldabs) >= 0) ? -LXP_EROFS : -LXP_ENOENT;
	if (strlen(newabs) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	int di = wfs_find(newabs); /* replace an existing destination node */
	if (di >= 0 && di != wi)
		wfs_free(di); /* reclaim the replaced destination's bytes */
	strcpy(wnode_at(wi)->path, newabs);
	return 0;
}

static long sys_symlink(lxp_proc_t *p, const char *target, const char *linkp)
{
	if (!target || !linkp)
		return -LXP_EFAULT;
	if (lxp_guest_strnlen(p, target, LXP_PATH_MAX) < 0)
		return -LXP_EFAULT; /* target is stored verbatim (strlen'd) — bound it in guest memory */
	char linkabs[LXP_PATH_MAX];
	long rr = resolve_path(p, linkp, linkabs, sizeof(linkabs));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(linkabs))
		return -LXP_EOPNOTSUPP; /* FAT provider contract has no symlink primitive. */
#endif
	if (wfs_find(linkabs) >= 0 || fs_lookup(p, linkabs) >= 0)
		return -LXP_EEXIST;
	int wi = wfs_create(linkabs, LXP_S_IFLNK | 0777u);
	if (wi < 0)
		return -LXP_ENOSPC;
	size_t tl = strlen(target);
	if (wfs_reserve(wi, tl) < 0) {
		wfs_free(wi); /* roll back the just-created node (its data is still NULL) */
		return -LXP_ENOSPC;
	}
	memcpy(wnode_at(wi)->data, target, tl);
	wnode_at(wi)->size = tl;
	return 0;
}

/*
 * link(oldpath, newpath): make newpath name oldpath's file.
 *
 * The writable overlay has no shared-inode / link-count model (st_nlink is always
 * reported as 1), so a true hard link is not representable. We satisfy the call by
 * creating newpath as an independent writable copy of oldpath's current bytes — enough
 * for the only realistic uses on this read-only-rootfs target: `ln a b`, and the
 * write-temp / link / unlink-temp atomic-replace idiom (dropbear host-key generation,
 * mkstemp-based writers, editors). oldpath may live in the RO rootfs or the overlay;
 * directories are rejected with EPERM, matching Linux. The final path component is not
 * dereferenced — link() does not follow a symlink at oldpath.
 */
static long sys_link(lxp_proc_t *p, const char *oldp, const char *newp)
{
	if (!oldp || !newp)
		return -LXP_EFAULT;
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	long r1 = resolve_path(p, oldp, oldabs, sizeof(oldabs));
	if (r1 < 0)
		return r1;
	long r2 = resolve_path(p, newp, newabs, sizeof(newabs));
	if (r2 < 0)
		return r2;
#if LXP_ENABLE_FS
	int old_host = lxp_hostfs_match(oldabs);
	int new_host = lxp_hostfs_match(newabs);
	if (old_host != new_host)
		return -LXP_EXDEV;
	if (old_host)
		return -LXP_EOPNOTSUPP; /* Host provider intentionally exposes no hard links. */
#endif
	if (strlen(newabs) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	if (wfs_find(newabs) >= 0 || fs_lookup(p, newabs) >= 0)
		return -LXP_EEXIST;

	/* Source bytes: writable overlay first, then the RO rootfs. */
	const uint8_t *src;
	size_t srclen;
	uint32_t srcmode;
	int wi = wfs_find(oldabs);
	if (wi >= 0) {
		src = wnode_at(wi)->data;
		srclen = wnode_at(wi)->size;
		srcmode = wnode_at(wi)->mode;
	} else {
		int idx = fs_lookup(p, oldabs);
		if (idx < 0)
			return -LXP_ENOENT;
		src = p->fs[idx].data;
		srclen = p->fs[idx].size;
		srcmode = file_mode(&p->fs[idx]);
	}
	if ((srcmode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EPERM; /* hard links to directories are not permitted */

	int ni = wfs_create(newabs, LXP_S_IFREG | (srcmode & 0777u));
	if (ni < 0)
		return -LXP_ENOSPC;
	if (srclen > 0) {
		if (wfs_reserve(ni, srclen) < 0) {
			wfs_free(ni); /* roll back the just-created node (its data is still NULL) */
			return -LXP_ENOSPC;
		}
		memcpy(wnode_at(ni)->data, src,
		       srclen); /* the arena never moves the source block */
		wnode_at(ni)->size = srclen;
	}
	return 0;
}

static long sys_chmod(lxp_proc_t *p, const char *path, uint32_t mode)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		if (lxp_hostfs_is_read_only())
			return -LXP_EROFS;
		return lxp_hostfs_path_stat(p, abspath, &stat); /* FAT mode bits are inert. */
	}
#endif
	int wi = wfs_find(abspath);
	if (wi >= 0) {
		wnode_at(wi)->mode = (wnode_at(wi)->mode & LXP_S_IFMT) | (mode & 0777u);
		return 0;
	}
	return (fs_lookup(p, abspath) >= 0) ? 0 : -LXP_ENOENT; /* rootfs: accept, inert */
}

/* utimensat: times are not tracked, but the existence check must be honest —
 * `touch` probes with utimensat first and only creates the file on -ENOENT. */
static long sys_utimensat(lxp_proc_t *p, const char *path)
{
	if (!path) /* futimens(fd): operate on the open fd — accept */
		return 0;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		if (lxp_hostfs_is_read_only())
			return -LXP_EROFS;
		return lxp_hostfs_path_stat(p, abspath,
					    &stat); /* Provider does not expose timestamps. */
	}
#endif
	if ((abspath[0] == '/' && abspath[1] == '\0') || wfs_find(abspath) >= 0 ||
	    fs_lookup(p, abspath) >= 0)
		return 0;
	return -LXP_ENOENT;
}

/* Fill a guest buffer through the active host entropy provider. The port contract
 * is all-or-error: it returns LXP_OK only after writing every requested byte.
 * Missing entropy is ENOSYS for getrandom(2), but an already-open random device
 * reports EIO. A transient non-blocking provider maps to EAGAIN. */
long lxp_random_fill_guest(void *buf, size_t count, int unavailable_errno)
{
	if (count == 0u)
		return 0;
	/* The host can write through an uncached alias while the first/last cache
	 * line contains unrelated dirty guest bytes.  Publish those complete lines
	 * before the write so the post-write invalidate cannot discard adjacent
	 * guest data. */
	lxp_cache_clean(buf, count);
	int r = lxp_random_fill(buf, count);
	if (r == LXP_OK) {
		/* A Cortex-M host may write through a privileged uncached view while the
		 * guest maps the same RAM cacheable. Drop stale guest lines before resume. */
		lxp_cache_invalidate(buf, count);
		return (long)count;
	}
	if (r == LXP_ERR_WOULD_BLOCK)
		return -LXP_EAGAIN;
	if (r == LXP_ERR_NOT_SUPPORTED || r == LXP_ERR_NOT_REGISTERED)
		return -unavailable_errno;
	return -LXP_EIO;
}

/* getrandom: validate Linux flags and fill from the host entropy provider. */
static long sys_getrandom(lxp_proc_t *p, void *buf, size_t count, unsigned flags)
{
	const unsigned valid = LXP_GRND_NONBLOCK | LXP_GRND_RANDOM | LXP_GRND_INSECURE;
	if ((flags & ~valid) != 0u || (flags & (LXP_GRND_RANDOM | LXP_GRND_INSECURE)) ==
					      (LXP_GRND_RANDOM | LXP_GRND_INSECURE))
		return -LXP_EINVAL;
	if (count == 0u)
		return 0;
	if (!lxp_guest_access_ok(p, buf, count, 1))
		return -LXP_EFAULT;
	return lxp_random_fill_guest(buf, count, LXP_ENOSYS);
}

static void statfs_synthetic(struct lxp_statfs64 *st)
{
	memset(st, 0, sizeof(*st));
	st->f_type = LXP_TMPFS_MAGIC;
	st->f_bsize = 4096;
	st->f_frsize = 4096;
	st->f_blocks = 256;
	st->f_bfree = 192;
	st->f_bavail = 192;
	st->f_files = 64;
	st->f_ffree = 48;
	st->f_namelen = 255;
}

static long statfs_copy(lxp_proc_t *p, size_t size, void *buf, const struct lxp_statfs64 *st)
{
	if (size < sizeof(*st))
		return -LXP_EINVAL;
	if (!lxp_guest_access_ok(p, buf, sizeof(*st), 1))
		return -LXP_EFAULT;
	return lxp_copy_to_guest(p, (uintptr_t)buf, st, sizeof(*st));
}

static long sys_statfs_path(lxp_proc_t *p, const char *path, size_t size, void *buf)
{
	if (!lxp_guest_access_ok(p, buf, sizeof(struct lxp_statfs64), 1))
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rc = resolve_path(p, path, abspath, sizeof(abspath));
	if (rc < 0)
		return rc;
	struct lxp_statfs64 st;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		rc = lxp_hostfs_statfs(p, &st);
		return rc < 0 ? rc : statfs_copy(p, size, buf, &st);
	}
#endif
	statfs_synthetic(&st);
	return statfs_copy(p, size, buf, &st);
}

static long sys_fstatfs(lxp_proc_t *p, int fd, size_t size, void *buf)
{
	if (!lxp_guest_access_ok(p, buf, sizeof(struct lxp_statfs64), 1))
		return -LXP_EFAULT;
	lxp_ofd_t *slot = lxp_fd_description(p, fd);
	if (!slot)
		return -LXP_EBADF;
	struct lxp_statfs64 st;
	const lxp_file_ops_t *ops = lxp_vfs_ops(slot);
	if (ops && ops->fstatfs) {
		long rc = ops->fstatfs(p, slot, &st);
		return rc < 0 ? rc : statfs_copy(p, size, buf, &st);
	}
	statfs_synthetic(&st);
	return statfs_copy(p, size, buf, &st);
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

/*
 * statx: the stat() uClibc-ng actually issues. With AT_EMPTY_PATH (or an empty
 * path) it stats the open dirfd (fstat); otherwise it resolves a rootfs path.
 */
static long sys_statx(lxp_proc_t *p, int dirfd, const char *path, int flags, void *buf)
{
	if (!lxp_guest_access_ok(p, buf, sizeof(struct lxp_statx), 1))
		return -LXP_EFAULT;
	/* Validate the path pointer before the path[0] empty-check deref below — resolve_path
	 * validates it too, but only after this reads path[0] (a bad pointer would fault here). */
	if (path && lxp_guest_strnlen(p, path, LXP_PATH_MAX) < 0)
		return -LXP_EFAULT;
	struct lxp_stat st;
	if (path && path[0] && !(flags & LXP_AT_EMPTY_PATH)) {
		char abspath[LXP_PATH_MAX];
		long rr = resolve_path(p, path, abspath, sizeof(abspath));
		if (rr < 0)
			return rr;
		long source =
			path_stat_lookup(p, abspath, !(flags & LXP_AT_SYMLINK_NOFOLLOW), &st);
#if LXP_ENABLE_NETFS
		if (source == LXP_PATH_STAT_NETFS)
			return lxp_netfs_stat(p, abspath, (uintptr_t)buf, 1); /* parks */
#endif
		if (source < 0)
			return source;
	} else {
		lxp_ofd_t *s = lxp_fd_description(p, dirfd);
		if (!s)
			return -LXP_EBADF;
		long rc = fd_stat(p, s, &st);
		if (rc < 0)
			return rc;
	}
	return lxp_stat_copyout(p, (uintptr_t)buf, 1, &st);
}

/*
 * execve: resolve the program in the rootfs and capture its argument vector,
 * then flag the request. The per-engine seam (privileged) does the actual image
 * replacement — reload the bFLT, rebuild the MPU domain + stack, and relaunch
 * the thread — because that is engine-specific. We never truly return: on
 * success the old image is gone; on failure we report a negated errno.
 */
/* Snapshot an untrusted guest argv/envp into coordinator-owned storage. The guest is parked,
 * but another CLONE_VM thread can still mutate its memory, so each pointer is loaded once and no
 * raw vector is revisited after this copy. */
static long exec_copy_vec(lxp_proc_t *p, char *const uvec[], uint16_t *vec, char *buf, size_t bufsz,
			  int max, int *count, size_t *used)
{
	*count = 0;
	if (used)
		*used = 0;
	/* Leave no plausible offset behind from the image this slot ran before. */
	for (int j = 0; j < max; j++)
		vec[j] = LXP_EXEC_OFF_NONE;
	if (!uvec)
		return 0;
	size_t off = 0;
	for (int j = 0; j <= max; j++) {
		const char *us;
		if (lxp_copy_from_guest(p, &us, (uintptr_t)&uvec[j], sizeof(us)) != 0)
			return -LXP_EFAULT;
		if (!us)
			return 0;
		if (j == max || off == bufsz)
			return -LXP_E2BIG;
		size_t room = bufsz - off;
		/* Copy each byte once and decide termination from the copied value. A
		 * co-running CLONE_VM thread may mutate the source: a separate strnlen +
		 * memcpy could observe a NUL during the scan and then copy a non-terminated
		 * string, making the later trusted-buffer strlen walk out of bounds. */
		size_t len;
		long rc = lxp_copy_string_from_guest(p, buf + off, room, (uintptr_t)us, &len);
		if (rc != 0)
			return rc;
		vec[j] = (uint16_t)off;
		off += len + 1;
		*count = j + 1;
		if (used)
			*used = off;
	}
	return -LXP_E2BIG;
}

/* Rewrite an already-snapshotted script argv in place. Keeping the snapshot in privileged
 * slot storage avoids a second argument buffer on the coordinator task's embedded stack. */
static long exec_rewrite_script_argv(lxp_exec_capture_t *cap, int old_argc, size_t old_bytes,
				     const char *interp, const char *iarg, int have_iarg,
				     const char *script, int *new_argc)
{
	const int prefix_count = have_iarg ? 3 : 2;
	const int tail_count = old_argc > 1 ? old_argc - 1 : 0;
	if (prefix_count + tail_count > LXP_EXEC_MAXARGS)
		return -LXP_E2BIG;

	size_t tail_off = old_bytes;
	if (tail_count)
		tail_off = cap->argv[1];
	if (tail_off > old_bytes)
		return -LXP_EFAULT; /* internal snapshot invariant */
	size_t tail_bytes = old_bytes - tail_off;

	const char *prefix[3] = {interp, script, NULL};
	if (have_iarg) {
		prefix[1] = iarg;
		prefix[2] = script;
	}
	size_t prefix_bytes = 0;
	for (int j = 0; j < prefix_count; j++) {
		size_t len = strlen(prefix[j]) + 1;
		if (prefix_bytes > sizeof(cap->argv_buf) ||
		    len > sizeof(cap->argv_buf) - prefix_bytes)
			return -LXP_E2BIG;
		prefix_bytes += len;
	}
	if (tail_bytes > sizeof(cap->argv_buf) - prefix_bytes)
		return -LXP_E2BIG;

	memmove(cap->argv_buf + prefix_bytes, cap->argv_buf + tail_off, tail_bytes);
	size_t off = 0;
	for (int j = 0; j < prefix_count; j++) {
		size_t len = strlen(prefix[j]) + 1;
		cap->argv[j] = (uint16_t)off;
		memcpy(cap->argv_buf + off, prefix[j], len);
		off += len;
	}
	for (int j = 0; j < tail_count; j++) {
		cap->argv[prefix_count + j] = (uint16_t)off;
		off += strlen(cap->argv_buf + off) + 1;
	}
	/* The rewrite shortens the vector when the script took no arguments; leave
	 * nothing from the pre-rewrite capture readable as a valid offset. */
	for (int j = prefix_count + tail_count; j < LXP_EXEC_MAXARGS; j++)
		cap->argv[j] = LXP_EXEC_OFF_NONE;
	*new_argc = prefix_count + tail_count;
	return 0;
}

static long sys_execve(lxp_proc_t *p, const char *path, char *const argv[], char *const envp[])
{
	if (!path)
		return -LXP_EFAULT;
	lxp_exec_capture_t *cap = p->exec_capture;
	if (!cap)
		return -LXP_ENOMEM;
	/* Snapshot both vectors before path resolution. This bounds work to the actual storage the
	 * relaunch can preserve instead of scanning and silently dropping hundreds of strings. */
	int raw_argc = 0, envc = 0;
	size_t raw_argbytes = 0;
	long vr = exec_copy_vec(p, argv, cap->argv, cap->argv_buf, sizeof(cap->argv_buf),
				LXP_EXEC_MAXARGS, &raw_argc, &raw_argbytes);
	if (vr < 0)
		return vr;
	vr = exec_copy_vec(p, envp, cap->env, cap->env_buf, sizeof(cap->env_buf), LXP_EXEC_MAXENVS,
			   &envc, NULL);
	if (vr < 0)
		return vr;
	cap->envc = envc;
	char execabs[LXP_PATH_MAX];
	long rr = resolve_path(p, path, execabs, sizeof(execabs));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_NETFS_EXEC
	/* Exec a program off the remote mount (/mnt/pi/prog): capture argv and
	 * park the ELF fetch. CLOEXEC is deliberately deferred until the fetched
	 * image reaches the coordinator's exec commit point. */
	if (lxp_netfs_lookup(execabs) >= 0) {
		cap->argc = raw_argc;
		return lxp_netfs_exec_fetch(p, execabs); /* parks, or a negative errno inline */
	}
#endif
	int idx;
	if (strcmp(execabs, "/proc/self/exe") == 0) {
		/* BusyBox re-execs its own image via execv("/proc/self/exe", argv) on NOMMU
		 * — httpd (and any vfork+re-exec server) does this per connection. Re-run the
		 * caller's current program image (kept in exec_file_idx across relaunches). */
		idx = p->exec_file_idx;
		if (idx < 0 || idx >= p->fs_count)
			return -LXP_ENOENT;
	} else {
		/* Follow symlinks, e.g. /bin/echo -> busybox (Buildroot installs applets as
		 * symlinks). The argv (argv[0] = "echo") is kept, so busybox runs that applet. */
		idx = fs_follow(p, fs_lookup(p, execabs));
		if (idx < 0)
			return -LXP_ENOENT;
	}
	if ((file_mode(&p->fs[idx]) & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EACCES;

	/* Interpreter scripts: a "#!interp [arg]" first line re-targets the exec to
	 * the interpreter, with argv = [interp, arg?, scriptpath, original argv[1:]].
	 * init runs /etc/init.d/rcS (a #!/bin/sh script) this way. */
	const lxp_file_t *f = &p->fs[idx];
	lxp_script_spec_t script;
	int script_rc = lxp_script_parse(f->data, f->size, &script);
	if (script_rc < 0)
		return script_rc;
	int interp_idx = -1;
	if (script_rc == LXP_SCRIPT_PRESENT) {
		char interpabs[LXP_PATH_MAX];
		/* _trusted, not resolve_path(): interp was copied out of the script's
		 * own bytes into this stack buffer, so it is not a guest pointer and
		 * resolve_path()'s lxp_guest_strnlen guard rejects it -EFAULT. That made
		 * every #! script unrunnable — BusyBox init's /etc/init.d/rcS included. */
		if (resolve_path_trusted(script.interpreter, interpabs, sizeof(interpabs)) < 0)
			return -LXP_ENOENT;
		interp_idx = fs_follow(p, fs_lookup(p, interpabs));
		if (interp_idx < 0)
			return -LXP_ENOENT;
	}

	int argc = raw_argc;
	if (interp_idx >= 0) {
		long ar = exec_rewrite_script_argv(cap, raw_argc, raw_argbytes, script.interpreter,
						   script.argument, script.has_argument, execabs,
						   &argc);
		if (ar < 0)
			return ar;
		idx = interp_idx;
	}
	/* Refuse a wrong-ABI (hard-float) image before committing, so the caller gets a clean ENOEXEC
	 * and its shell keeps running — the loader would otherwise reject it only at launch, which
	 * terminates the caller. idx is the image that actually runs (the interpreter for a #! script);
	 * a remote-mount exec took the early netfs path above and is caught by the loader instead. */
	if (lxp_loader_abi_incompatible(p->fs[idx].data, p->fs[idx].size))
		return -LXP_ENOEXEC;
	/* close-on-exec: the fd table survives execve (the run loop preserves it), so drop the
	 * FD_CLOEXEC fds here — the exec is committed past every error check. dropbear confirms
	 * the shell exec'd by its exec-status pipe (FD_CLOEXEC) closing this way. */
	if (lxp_proc_files_unshare(p) != 0)
		return -LXP_ENOMEM;
	lxp_fd_close_on_exec(p);
	cap->argc = argc;
	p->exec_file_idx = idx;
	if (lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}) != 0)
		return -LXP_EAGAIN;
	return 0;
}

/* There is no RTC: wall-clock time is a fixed base epoch (~2026-06-23) + uptime. */
#define LXP_BOOT_EPOCH 1782172800ull

static void now_sec_nsec(int clockid, uint64_t *sec, uint32_t *nsec)
{
	uint64_t ns = 0;
	lxp_time_ns(&ns);
	uint64_t up = ns / 1000000000ull;
	*nsec = (uint32_t)(ns % 1000000000ull);
	/* CLOCK_MONOTONIC(1)/_RAW(4)/BOOTTIME(7) → uptime; REALTIME(0) → wall clock. */
	*sec = (clockid == 0) ? (LXP_BOOT_EPOCH + up) : up;
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
#if LXP_ENABLE_DEV
	/* A device fd honours F_SETFL/F_GETFL so O_NONBLOCK takes effect (LVGL's
		 * evdev opens blocking, then fcntl(F_SETFL, O_NONBLOCK)). */
	if (s->kind == LXP_FD_DEV) {
		if ((int)a1 == LXP_F_SETFL) {
			lxp_dev_setfl(s->file_idx, (int)a2);
			return 0;
		}
		if ((int)a1 == LXP_F_GETFL)
			return lxp_dev_getfl(s->file_idx);
	}
#endif
#if LXP_ENABLE_NET
	/* A socket fd honours F_SETFL/F_GETFL so O_NONBLOCK gates parking. */
	if (s->kind == LXP_FD_SOCKET) {
		if ((int)a1 == LXP_F_SETFL) {
			lxp_sock_setfl(s->file_idx, (int)a2);
			return 0;
		}
		if ((int)a1 == LXP_F_GETFL)
			return lxp_sock_getfl(s->file_idx);
	}
#endif
#if LXP_ENABLE_PTY
	/* A pty fd honours F_SETFL/F_GETFL so O_NONBLOCK gates parking (dropbear sets
		 * the master non-blocking and drives it with select). */
	if (s->kind == LXP_FD_PTY) {
		if ((int)a1 == LXP_F_SETFL) {
			lxp_pty_setfl(s->file_idx, s->rw, (int)a2);
			return 0;
		}
		if ((int)a1 == LXP_F_GETFL)
			return lxp_pty_getfl(s->file_idx, s->rw);
	}
#endif
	/* A pipe fd honours F_SETFL/F_GETFL so O_NONBLOCK gates parking (dropbear sets its
		 * SIGCHLD self-pipe non-blocking and drains it with a read-until-EAGAIN loop). */
	if (s->kind == LXP_FD_PIPE) {
		if ((int)a1 == LXP_F_SETFL) {
			s->nonblock = ((int)a2 & LXP_O_NONBLOCK) ? 1 : 0;
			return 0;
		}
		if ((int)a1 == LXP_F_GETFL)
			return (s->rw ? LXP_O_WRONLY : LXP_O_RDONLY) |
			       (s->nonblock ? LXP_O_NONBLOCK : 0);
	}
#if LXP_ENABLE_FS
	if (s->kind == LXP_FD_HOSTFS) {
		if ((int)a1 == LXP_F_SETFL) {
			s->nonblock = ((int)a2 & LXP_O_NONBLOCK) ? 1 : 0;
			return 0;
		}
		if ((int)a1 == LXP_F_GETFL)
			return s->accmode | (s->nonblock ? LXP_O_NONBLOCK : 0);
	}
#endif
	/* F_SETFD/F_GETFD track close-on-exec (dropbear sets FD_CLOEXEC on its exec-status
		 * pipe and detects a successful shell exec by that fd closing on execve). */
	if ((int)a1 == LXP_F_SETFD) {
		return lxp_fd_set_cloexec(proc, (int)a0, ((int)a2 & LXP_FD_CLOEXEC) != 0);
	}
	if ((int)a1 == LXP_F_GETFD) {
		int cloexec = lxp_fd_get_cloexec(proc, (int)a0);
		return cloexec > 0 ? LXP_FD_CLOEXEC : cloexec;
	}
	/* F_GETFL must report a truthful access mode. uClibc's fdopen() validates
		 * the FILE* mode against it, so answering O_RDONLY (0) for a writable fd
		 * fails fdopen(fd, "w") with EINVAL — which is how dropbearkey's .pub
		 * write died while the key itself generated fine. The remaining kinds do not
		 * record their open flags, so report what the kind can actually do; that is
		 * enough for fdopen, which only checks the access mode. */
	if ((int)a1 == LXP_F_GETFL) {
		int acc;
		switch (s->kind) {
		case LXP_FD_TMPFS:   /* the writable overlay */
		case LXP_FD_CONSOLE: /* stdin/stdout/stderr */
			acc = LXP_O_RDWR;
			break;
		default: /* read-only rootfs file, and anything not handled above */
			acc = LXP_O_RDONLY;
			break;
		}
		return acc | (s->nonblock ? LXP_O_NONBLOCK : 0);
	}
	/* F_SETFL on a stdio/other fd: benign. */
	return 0;
}

static long sys_poll(lxp_proc_t *proc, long nr, long a0, long a1, long a2)
{
	lxp_pollfd *pfds = (lxp_pollfd *)(uintptr_t)a0;
	unsigned nfds = (unsigned)a1;
	if (nfds > LXP_MAX_FDS) /* bound before nfds*sizeof(pollfd) wraps a 32-bit size_t */
		return -LXP_EINVAL;
	if (nfds && !lxp_guest_access_ok(proc, pfds, (size_t)nfds * sizeof(lxp_pollfd), 1))
		return -LXP_EFAULT;
	/* Timeout: poll(2) passes ms in a2 (<0 = block); ppoll passes a struct
		 * timespec* (NULL = block). A SHORT finite timeout means the caller is
		 * probing for input that might *immediately* follow — e.g. vi/hush's
		 * read_key polling ~50 ms after ESC to tell a lone ESC from an escape
		 * sequence. We keep no read-ahead, so honestly report "no data yet" for
		 * such probes: a lone ESC then stays ESC (Esc then :q works in vi). vi
		 * also uses poll(timeout 0) as "is input pending? if not, repaint the
		 * screen" — reporting ready there made it never repaint while inserting
		 * (edits stayed invisible). A blocking/long poll reports ready and the
		 * caller blocks in read() for the real byte (the console read blocks
		 * until a key arrives). */
	long tmo_ms;
	if (nr == LXP_NR_poll) {
		tmo_ms = (long)(int32_t)a2;
	} else {
		const int64_t *ts = (const int64_t *)(uintptr_t)a2; /* {sec, nsec} */
		if (ts && !lxp_guest_access_ok(proc, ts, 2 * sizeof(int64_t), 0))
			return -LXP_EFAULT;
		tmo_ms = ts ? (long)(ts[0] * 1000 + ts[1] / 1000000) : -1;
	}
	/* With a console_poll callback (UART console) we report the console fd's REAL
		 * readiness, enabling interactive top's `q` quit; without one a short finite
		 * timeout is a read_key probe (vi/hush ESC + "input pending?") reported
		 * not-ready (no read-ahead), and a longer/blocking poll reports ready so the
		 * caller blocks in read() for the byte. */
	int probe = (tmo_ms >= 0 && tmo_ms <= 100);
	int key = lxp_console_input_ready(proc);
	int ready = 0;
#if LXP_ENABLE_NET
	int has_socket = 0, has_eventfd = 0, has_pty = 0;
#endif
	for (unsigned i = 0; i < nfds; i++) {
		pfds[i].revents = 0;
		lxp_ofd_t *s = lxp_fd_description(proc, pfds[i].fd);
		if (!s)
			continue;
		int avail;
		if (s->kind == LXP_FD_CONSOLE)
			avail = (tmo_ms < 0) ? 1 : (proc->console_poll ? key : !probe);
#if LXP_ENABLE_DEV
		else if (s->kind == LXP_FD_DEV) {
			/* Report the driver's real readiness bits (fb POLLOUT, evdev
				 * POLLIN when the event ring is non-empty). */
			unsigned pb = lxp_dev_poll(s->file_idx);
			pfds[i].revents = (short)(pfds[i].events & pb & (LXP_POLLIN | LXP_POLLOUT));
			if (pfds[i].revents)
				ready++;
			continue;
		}
#endif
#if LXP_ENABLE_NET
		else if (s->kind == LXP_FD_SOCKET) {
			unsigned pb = lxp_sock_poll(s->file_idx);
			pfds[i].revents = (short)(pfds[i].events & pb & (LXP_POLLIN | LXP_POLLOUT));
			if (pfds[i].revents)
				ready++;
			has_socket = 1;
			continue;
		} else if (s->kind == LXP_FD_EVENTFD) {
			/* Readable once the counter is non-zero (the resolver thread
				 * wrote it); always writable. Park like a socket poll so the
				 * coordinator re-checks on its tick. */
			unsigned pb = lxp_vfs_ops(s)->poll(proc, s);
			pfds[i].revents = (short)(pfds[i].events & pb & (LXP_POLLIN | LXP_POLLOUT));
			if (pfds[i].revents)
				ready++;
			has_eventfd = 1;
			continue;
		}
#if LXP_ENABLE_PTY
		else if (s->kind == LXP_FD_PTY) {
			unsigned pb = lxp_pty_poll(s->file_idx, s->rw);
			pfds[i].revents = (short)(pfds[i].events & pb & (LXP_POLLIN | LXP_POLLOUT));
			if (pfds[i].revents)
				ready++;
			has_pty = 1; /* park via SOCKW_POLL; the re-scan re-checks the pty */
			continue;
		}
#endif
#endif
		else if (s->kind == LXP_FD_PIPE) {
			/* Real pipe readiness — NOT "always ready", or a select on an empty
				 * self-pipe wrongly reports readable (dropbear then blocks forever). */
			unsigned pb = pipe_poll(s->file_idx, s->rw);
			pfds[i].revents = (short)(pfds[i].events & pb & (LXP_POLLIN | LXP_POLLOUT));
			if (pfds[i].revents)
				ready++;
			continue;
		} else
			avail = 1; /* regular files: always readable/writable */
		if (avail) {
			pfds[i].revents = pfds[i].events & (LXP_POLLIN | LXP_POLLOUT);
			if (pfds[i].revents)
				ready++;
		}
	}
	if (ready > 0 || tmo_ms == 0)
		return ready;
#if LXP_ENABLE_NET
	/* A blocking poll whose set includes a socket parks on SOCKW_POLL: the
		 * coordinator re-scans readiness on its <=5 ms socket-retry tick (via
		 * lxp_poll_retry) and resumes us when an fd becomes ready or the timeout
		 * elapses. Without this a socket poll would sleep the whole timeout and return
		 * 0, breaking the uClibc DNS resolver (poll(POLLIN) then recv(MSG_DONTWAIT)). */
	if (has_socket || has_eventfd || has_pty) {
		lxp_wait_t wait = {
			.kind = LXP_WAIT_SOCKET,
			.op = LXP_SOCKW_POLL,
			.data.socket.object = -1,
			.data.socket.buffer = (uintptr_t)pfds,
			.data.socket.length = nfds,
		};
		if (tmo_ms > 0) {
			uint64_t now_us = 0;
			lxp_time_us(&now_us);
			wait.data.socket.deadline_us = now_us + (uint64_t)tmo_ms * 1000ull;
		} else {
			wait.data.socket.deadline_us = UINT64_MAX; /* poll(-1): block forever */
		}
		if (lxp_wait_begin(proc, &wait) != 0)
			return -LXP_EAGAIN;
		return 0; /* parked; coordinator resumes with the ready count / 0 */
	}
#endif
	/* Nothing ready + a real timeout: with the UART console, park for the timeout
		 * (paces interactive top's refresh, returns 0); a buffered keystroke is caught
		 * at the next poll. Without console_poll a long timeout already reported ready
		 * above, so we only reach here on a no-callback probe → return 0. */
	if (proc->console_poll && tmo_ms > 0) {
		/* Use the same cross-idle microsecond clock as the coordinator deadline
		 * scan. Mixing clock domains here makes poll refresh and input drift. */
		uint64_t now_us = 0;
		lxp_time_us(&now_us);
		lxp_wait_t wait = {
			.kind = LXP_WAIT_TIMER,
			.data.timer.deadline_us = now_us + (uint64_t)tmo_ms * 1000ull,
		};
		if (lxp_wait_begin(proc, &wait) != 0)
			return -LXP_EAGAIN;
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

long lxp_syscall(lxp_proc_t *proc, long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
#if LXP_ENABLE_FS
	lxp_hostfs_syscall_enter(proc, nr, a0, a1, a2, a3, a4, a5);
#endif
	if (!proc)
		return -LXP_EINVAL;

	/* A guest controls these byte counts. Normalise them before any pointer-range
	 * validation or host callback: each interface permits a short result, and the
	 * finite quantum keeps one deferred request preemptible and bounded. Cast via
	 * uint32_t because this is the 32-bit ARM syscall ABI even in host tests. */
	switch (nr) {
	case LXP_NR_read:
	case LXP_NR_write:
	case LXP_NR_getdents:
	case LXP_NR_getdents64:
	case LXP_NR_send:
	case LXP_NR_sendto:
	case LXP_NR_recv:
	case LXP_NR_recvfrom:
		if ((uint32_t)a2 > LXP_SYSCALL_QUANTUM_BYTES)
			a2 = LXP_SYSCALL_QUANTUM_BYTES;
		break;
	case LXP_NR_pread64:
	case LXP_NR_pwrite64:
		if ((uint32_t)a2 > LXP_SYSCALL_FILE_QUANTUM_BYTES)
			a2 = LXP_SYSCALL_FILE_QUANTUM_BYTES;
		break;
	case LXP_NR_getrandom:
		if ((uint32_t)a1 > LXP_SYSCALL_QUANTUM_BYTES)
			a1 = LXP_SYSCALL_QUANTUM_BYTES;
		break;
	default:
		break;
	}

	switch (nr) {
	case LXP_NR_read:
		return sys_read(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2);
	case LXP_NR_write:
		return sys_write(proc, (int)a0, (const void *)(uintptr_t)a1, (size_t)a2);
	case LXP_NR_writev:
		return sys_writev(proc, (int)a0, (const lxp_iovec *)(uintptr_t)a1, (int)a2);
	case LXP_NR_brk:
		return sys_brk(proc, (uintptr_t)a0);
	case LXP_NR_mmap2:
		return sys_mmap2(proc, (uintptr_t)a0, (size_t)a1, (int)a2, (int)a3, (int)a4,
				 (uint32_t)a5);
	case LXP_NR_munmap:
		return sys_munmap(proc, (uintptr_t)a0, (size_t)a1);
	case LXP_NR_mprotect: /* NOMMU: RELRO/protection is a no-op */
		return sys_mprotect((uintptr_t)a0, (size_t)a1, (int)a2);
	case LXP_NR_pread64: /* (fd, buf, count, [pad a3], off_lo a4, off_hi a5) */
		return sys_pread(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2,
				 (uint64_t)(uint32_t)a4 | ((uint64_t)(uint32_t)a5 << 32));
	case LXP_NR_pwrite64: /* (fd, buf, count, [pad a3], off_lo a4, off_hi a5) */
		return sys_pwrite(proc, (int)a0, (const void *)(uintptr_t)a1, (size_t)a2,
				  (uint64_t)(uint32_t)a4 | ((uint64_t)(uint32_t)a5 << 32));
	case LXP_NR_open: { /* legacy open(path, flags, mode): dirfd = cwd */
		long f = sys_openat(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a0, (int)a1);
		if (f >= 0 && ((int)a1 & LXP_O_CLOEXEC))
			(void)lxp_fd_set_cloexec(proc, (int)f, 1);
		return f;
	}
	case LXP_NR_execve: /* (path, argv, envp) */
		return sys_execve(proc, (const char *)(uintptr_t)a0, (char *const *)(uintptr_t)a1,
				  (char *const *)(uintptr_t)a2);
	case LXP_NR_openat: {
		long f = sys_openat(proc, (int)a0, (const char *)(uintptr_t)a1, (int)a2);
		if (f >= 0 && ((int)a2 & LXP_O_CLOEXEC))
			(void)lxp_fd_set_cloexec(proc, (int)f, 1);
		return f;
	}
	case LXP_NR_close:
		return sys_close(proc, (int)a0);
	case LXP_NR_pipe:
		return sys_pipe(proc, (int *)(uintptr_t)a0, 0);
	case LXP_NR_pipe2: /* (fds, flags) — flags carries O_CLOEXEC and/or O_NONBLOCK */
		return sys_pipe(proc, (int *)(uintptr_t)a0, (int)a1);
	case LXP_NR_dup:
		return sys_dup(proc, (int)a0);
	case LXP_NR_dup2:
		return sys_dup2(proc, (int)a0, (int)a1);
	case LXP_NR_dup3: { /* (old, new, flags) — flags carries O_CLOEXEC on the new fd */
		if ((int)a0 == (int)a1) /* dup3 (unlike dup2) rejects oldfd == newfd */
			return -LXP_EINVAL;
		return lxp_fd_dup_to(proc, (int)a0, (int)a1, ((int)a2 & LXP_O_CLOEXEC) != 0);
	}
	case LXP_NR_lseek:
		return sys_lseek(proc, (int)a0, a1, (int)a2);
	case LXP_NR__llseek:
		return sys_llseek(proc, (int)a0, (unsigned long)a1, (unsigned long)a2,
				  (uint64_t *)(uintptr_t)a3, (unsigned int)a4);
	case LXP_NR_ftruncate64:
		/* 64-bit length is register-pair aligned on ARM: fd=a0, len=(a2,a3). */
		return sys_ftruncate(proc, (int)a0,
				     (uint64_t)(uint32_t)a2 | ((uint64_t)(uint32_t)a3 << 32));
	case LXP_NR_fsync:
	case LXP_NR_fdatasync:
		return sys_sync_fd(proc, (int)a0);
	case LXP_NR_sync:
#if LXP_ENABLE_FS
		(void)lxp_hostfs_sync_all();
#endif
		return 0;
	case LXP_NR_syncfs: {
		lxp_ofd_t *slot = lxp_fd_description(proc, (int)a0);
		if (!slot)
			return -LXP_EBADF;
#if LXP_ENABLE_FS
		if (slot->kind == LXP_FD_HOSTFS)
			return lxp_hostfs_sync_all();
#endif
		return 0;
	}
	case LXP_NR_fstat64:
		return sys_fstat64(proc, (int)a0, (void *)(uintptr_t)a1);
	case LXP_NR_stat64: /* (path, statbuf) — follows symlinks */
		return sys_stat_path(proc, (const char *)(uintptr_t)a0, 1, (void *)(uintptr_t)a1);
	case LXP_NR_lstat64: /* (path, statbuf) — does NOT follow */
		return sys_stat_path(proc, (const char *)(uintptr_t)a0, 0, (void *)(uintptr_t)a1);
	case LXP_NR_fstatat64: /* (dirfd, path, statbuf, flags) */
		return sys_stat_path(proc, (const char *)(uintptr_t)a1,
				     !((int)a3 & LXP_AT_SYMLINK_NOFOLLOW), (void *)(uintptr_t)a2);
	case LXP_NR_readlink: /* (path, buf, bufsiz) */
		return sys_readlink(proc, (const char *)(uintptr_t)a0, (char *)(uintptr_t)a1,
				    (size_t)a2);
	case LXP_NR_readlinkat: /* (dirfd, path, buf, bufsiz) */
		return sys_readlink(proc, (const char *)(uintptr_t)a1, (char *)(uintptr_t)a2,
				    (size_t)a3);
	case LXP_NR_access: /* (path, mode) */
		return sys_access(proc, (const char *)(uintptr_t)a0, (int)a1);
	case LXP_NR_faccessat:	/* (dirfd, path, mode) */
	case LXP_NR_faccessat2: /* (dirfd, path, mode, flags) */
		return sys_access(proc, (const char *)(uintptr_t)a1, (int)a2);
	case LXP_NR_mkdir: /* (path, mode) */
		return sys_mkdir(proc, (const char *)(uintptr_t)a0, (uint32_t)a1);
	case LXP_NR_mkdirat: /* (dirfd, path, mode) */
		return sys_mkdir(proc, (const char *)(uintptr_t)a1, (uint32_t)a2);
	case LXP_NR_rmdir: /* (path) */
		return sys_unlink(proc, (const char *)(uintptr_t)a0, 1);
	case LXP_NR_unlink: /* (path) */
		return sys_unlink(proc, (const char *)(uintptr_t)a0, 0);
	case LXP_NR_unlinkat: /* (dirfd, path, flags) */
		if (((int)a2 & ~LXP_AT_REMOVEDIR) != 0)
			return -LXP_EINVAL;
		return sys_unlink(proc, (const char *)(uintptr_t)a1,
				  ((int)a2 & LXP_AT_REMOVEDIR) ? 1 : 0);
	case LXP_NR_rename: /* (oldpath, newpath) */
		return sys_rename(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a1,
				  0);
	case LXP_NR_renameat: /* (olddirfd, old, newdirfd, new) */
		return sys_rename(proc, (const char *)(uintptr_t)a1, (const char *)(uintptr_t)a3,
				  0);
	case LXP_NR_renameat2: /* (olddirfd, old, newdirfd, new, flags) */
		return sys_rename(proc, (const char *)(uintptr_t)a1, (const char *)(uintptr_t)a3,
				  (unsigned)a4);
	case LXP_NR_symlink: /* (target, linkpath) */
		return sys_symlink(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a1);
	case LXP_NR_symlinkat: /* (target, newdirfd, linkpath) */
		return sys_symlink(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a2);
	case LXP_NR_link: /* (oldpath, newpath) */
		return sys_link(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a1);
	case LXP_NR_linkat: /* (olddirfd, oldpath, newdirfd, newpath, flags) */
		return sys_link(proc, (const char *)(uintptr_t)a1, (const char *)(uintptr_t)a3);
	case LXP_NR_chmod: /* (path, mode) */
		return sys_chmod(proc, (const char *)(uintptr_t)a0, (uint32_t)a1);
	case LXP_NR_fchmodat: /* (dirfd, path, mode) */
		return sys_chmod(proc, (const char *)(uintptr_t)a1, (uint32_t)a2);
	case LXP_NR_utimensat:	      /* (dirfd, path, times, flags) — times not tracked */
	case LXP_NR_utimensat_time64: /* time64 variant uClibc-ng issues for touch */
		return sys_utimensat(proc, (const char *)(uintptr_t)a1);
	case LXP_NR_mount:
		return sys_mount(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a1,
				 (const char *)(uintptr_t)a2, (unsigned long)a3,
				 (const char *)(uintptr_t)a4);
	case LXP_NR_umount2:
		return sys_umount(proc, (const char *)(uintptr_t)a0, (int)a1);
	case LXP_NR_statfs64: /* (path, sz, buf) */
		return sys_statfs_path(proc, (const char *)(uintptr_t)a0, (size_t)a1,
				       (void *)(uintptr_t)a2);
	case LXP_NR_fstatfs64: /* (fd, sz, buf) */
		return sys_fstatfs(proc, (int)a0, (size_t)a1, (void *)(uintptr_t)a2);
	case LXP_NR_getrandom: /* (buf, count, flags) */
		return sys_getrandom(proc, (void *)(uintptr_t)a0, (size_t)a1, (unsigned)a2);
	case LXP_NR_eventfd2: /* (initval, flags) — curl's threaded-resolver wakeup */
		return lxp_eventfd_open(proc, (unsigned)a0, (int)a1);
	case LXP_NR_sysinfo: { /* uptime + ram totals (uptime/free read this) */
		struct lxp_sysinfo {
			int32_t uptime;
			uint32_t loads[3];
			uint32_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
			uint16_t procs, pad;
			uint32_t totalhigh, freehigh, mem_unit;
			char _f[8];
		} *si = (void *)(uintptr_t)a0;
		LXP_STATIC_ASSERT(sizeof(struct lxp_sysinfo) == 64, "sysinfo ABI size drifted");
		if (!lxp_guest_access_ok(proc, si, sizeof(*si), 1))
			return -LXP_EFAULT;
		memset(si, 0, sizeof(*si));
		uint64_t ns = 0;
		lxp_time_ns(&ns);
		si->uptime = (int32_t)(ns / 1000000000ull);
		struct lxp_resource_stats resources;
		lxp_get_resource_stats(&resources);
		/* ARM's sysinfo fields are 32-bit. Pick the smallest power-of-two
		 * byte unit that represents the guest capacity. freeram is the
		 * effective capacity remaining after both slot and region limits. */
		uint64_t largest = resources.total_bytes > resources.available_bytes
					   ? resources.total_bytes
					   : resources.available_bytes;
		uint32_t unit = 1;
		while (largest / unit > UINT32_MAX && unit <= UINT32_MAX / 2u)
			unit *= 2u;
		uint64_t total_units = resources.total_bytes / unit;
		uint64_t free_units = resources.available_bytes / unit;
		si->totalram = (uint32_t)(total_units > UINT32_MAX ? UINT32_MAX : total_units);
		si->freeram = (uint32_t)(free_units > UINT32_MAX ? UINT32_MAX : free_units);
		si->mem_unit = unit;
		/* The coordinator contributes its aggregate without exposing the
		 * writable process table to syscall subsystems. Direct host tests
		 * have no coordinator, so retain one for the caller. */
		unsigned live = resources.processes;
		si->procs = (uint16_t)(live > UINT16_MAX ? UINT16_MAX : (live ? live : 1u));
		return 0;
	}
	case LXP_NR_fcntl: /* old 32-bit fcntl: same dispatch as fcntl64 here */
	case LXP_NR_fcntl64:
		return sys_fcntl(proc, a0, a1, a2);
	case LXP_NR_getdents: /* 32-bit linux_dirent (uClibc readdir on this target) */
		return sys_getdents64(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2, 0);
	case LXP_NR_getdents64:
		return sys_getdents64(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2, 1);
	case LXP_NR_statx: /* (dirfd, path, flags, mask, buf); mask ignored */
		return sys_statx(proc, (int)a0, (const char *)(uintptr_t)a1, (int)a2,
				 (void *)(uintptr_t)a4);
	case LXP_NR_exit:
		return sys_exit(proc, (int)a0, 0);
	case LXP_NR_exit_group:
		return sys_exit(proc, (int)a0, 1);
	/* libc-init / identity stubs: enough for a static uClibc program to start. */
	case LXP_NR_getpid:
		return proc->group ? proc->group->tgid : proc->pid;
	case LXP_NR_nice: {
		int64_t requested = (int64_t)lxp_proc_nice_get(proc) + (int32_t)a0;
		lxp_proc_nice_set(proc, requested < -20	 ? -20
					: requested > 19 ? 19
							 : (int)requested);
		/* Linux's raw nice(2) syscall returns zero on success. Returning the
		 * resulting negative nice value would cross the -errno ABI boundary and
		 * make libc report a successful priority raise as an error. */
		return 0;
	}
	case LXP_NR_getpriority:
		if ((int)a0 != 0 || ((int)a1 != 0 && (int)a1 != proc->pid))
			return (int)a0 < 0 || (int)a0 > 2 || (int)a1 < 0 ? -LXP_EINVAL : -LXP_ESRCH;
		return 20 - lxp_proc_nice_get(proc); /* raw Linux syscall encoding */
	case LXP_NR_setpriority:
		if ((int)a0 != 0 || ((int)a1 != 0 && (int)a1 != proc->pid))
			return (int)a0 < 0 || (int)a0 > 2 || (int)a1 < 0 ? -LXP_EINVAL : -LXP_ESRCH;
		lxp_proc_nice_set(proc, (int)a2);
		return 0;
	case LXP_NR_getppid:
		return proc->group ? proc->group->ppid : 0;
	case LXP_NR_getcwd: {
		/* getcwd(buf, size): write the cwd; the raw syscall returns the length
		 * including the NUL terminator. */
		char *buf = (char *)(uintptr_t)a0;
		if (!buf)
			return -LXP_EFAULT;
		size_t len = strlen(proc->fs_context->cwd) + 1;
		if ((size_t)a1 < len)
			return -LXP_ERANGE;
		if (lxp_copy_to_guest(proc, (uintptr_t)buf, proc->fs_context->cwd, len) != 0)
			return -LXP_EFAULT;
		return (long)len;
	}
	case LXP_NR_chdir: {
		const char *path = (const char *)(uintptr_t)a0;
		if (!path)
			return -LXP_EFAULT;
		char abspath[LXP_PATH_MAX];
		long r = resolve_path(proc, path, abspath, sizeof(abspath));
		if (r < 0)
			return r;
		/* "/" is always valid; else require an existing directory in either the
		 * writable overlay or the read-only rootfs. */
		if (!(abspath[0] == '/' && abspath[1] == '\0')) {
#if LXP_ENABLE_FS
			if (lxp_hostfs_match(abspath)) {
				lxp_fs_stat_t stat;
				long sr = lxp_hostfs_path_stat(proc, abspath, &stat);
				if (sr < 0)
					return sr;
				if (stat.type != LXP_FS_TYPE_DIR)
					return -LXP_ENOTDIR;
				strcpy(proc->fs_context->cwd, abspath);
				return 0;
			}
#endif
			int wi = wfs_find(abspath);
			if (wi >= 0) {
				if ((wnode_at(wi)->mode & LXP_S_IFMT) != LXP_S_IFDIR)
					return -LXP_ENOTDIR;
			} else {
				int idx = fs_lookup(proc, abspath);
				if (idx < 0)
					return -LXP_ENOENT;
				if ((file_mode(&proc->fs[idx]) & LXP_S_IFMT) != LXP_S_IFDIR)
					return -LXP_ENOTDIR;
			}
		}
		strcpy(proc->fs_context->cwd, abspath);
		return 0;
	}
	case LXP_NR_umask: { /* set the file-creation mask, return the previous (per-proc, inherited) */
		int old = proc->fs_context->umask;
		proc->fs_context->umask = (unsigned short)(a0 & 0777);
		return old;
	}
	case LXP_NR_setpgid: { /* (pid, pgid) — job control: put a process into a group */
		int tpid = (int)a0, tpgid = (int)a1;
		/* Only a self-target is tracked here (pid 0, or my own pid); pgid 0 means "use my
		 * pid" (become group leader). A child sets its OWN group via setpgid(0, …) after
		 * fork, so a cross-proc setpgid is accepted inert (no proc table at this layer). */
		if (tpid == 0 || tpid == proc->pid)
			proc->group->pgid = (tpgid == 0) ? proc->pid : tpgid;
		return 0;
	}
	case LXP_NR_prctl:
	case LXP_NR_sched_yield: /* accepted hint; host preemption/admission owns fairness */
	case LXP_NR_fchmod:	 /* modes/ownership not tracked (login chmods the tty) */
	case LXP_NR_fchown32:
	case LXP_NR_chown32: /* dropbear chowns the pty over SSH; ownership not enforced (inert) */
	case LXP_NR_setgroups32: /* uid/gid policy is not implemented (login's credential drop is */
	case LXP_NR_setuid32: /* accepted inert; CPU privilege remains engine-enforced nPRIV/user) */
	case LXP_NR_setgid32:
	case LXP_NR_setreuid32: /* dropbear's post-auth privilege drop: accept (inert) so it */
	case LXP_NR_setregid32: /* does not abort — a failed drop is fatal to an SSH server */
	case LXP_NR_setresuid32:
	case LXP_NR_setresgid32:
		return 0;	 /* process-control / fs-mode setup accepted (inert) */
	case LXP_NR_getresuid32: /* (ruid*, euid*, suid*) — all root (0) on this tier */
	case LXP_NR_getresgid32: {
		uint32_t *r = (uint32_t *)(uintptr_t)a0, *e = (uint32_t *)(uintptr_t)a1,
			 *s = (uint32_t *)(uintptr_t)a2;
		if ((r && !lxp_guest_access_ok(proc, r, sizeof(*r), 1)) ||
		    (e && !lxp_guest_access_ok(proc, e, sizeof(*e), 1)) ||
		    (s && !lxp_guest_access_ok(proc, s, sizeof(*s), 1)))
			return -LXP_EFAULT;
		if (r)
			*r = 0;
		if (e)
			*e = 0;
		if (s)
			*s = 0;
		return 0;
	}
	case LXP_NR_prlimit64: { /* (pid, resource, new_limit, old_limit) — report a sane
				     * finite limit; a "new" limit is accepted (inert). getty/login
				     * and dropbear query RLIMIT_NOFILE etc. */
		void *uold = (void *)(uintptr_t)a3;
		if (uold) {
			if (!lxp_guest_access_ok(proc, uold, 2 * sizeof(uint64_t), 1))
				return -LXP_EFAULT;
			/* Report the TRUTH for RLIMIT_NOFILE: the fd table is LXP_MAX_FDS, so
			 * advertising more just hands a guest a lie that turns into a surprise
			 * EMFILE at the (LXP_MAX_FDS)th open. Other resources keep a finite,
			 * never-RLIM_INFINITY default (a close-all-fds loop would else spin to 2^64). */
			uint64_t v = ((int)a1 == 7 /* RLIMIT_NOFILE */) ? LXP_MAX_FDS : 1024;
			uint64_t *lim = (uint64_t *)uold; /* rlim_cur, rlim_max */
			lim[0] = lim[1] = v;
		}
		return 0;
	}
	case LXP_NR_times: { /* (struct tms*) — CPU-time accounting; dropbear mixes it into
				 * its RNG pool. Report uptime ticks (100 Hz) + zero the per-proc
				 * breakdown (not tracked here). Must be >=0 (glibc treats -1 as error). */
		void *ubuf = (void *)(uintptr_t)a0;
		uint64_t us = 0;
		lxp_time_us(&us);
		long ticks = (long)(us / 10000u); /* CLK_TCK = 100 */
		if (ubuf) {
			if (!lxp_guest_access_ok(proc, ubuf, 4 * sizeof(long), 1))
				return -LXP_EFAULT;
			long *tms = (long *)ubuf; /* tms_utime, tms_stime, tms_cutime, tms_cstime */
			tms[0] = ticks;
			tms[1] = tms[2] = tms[3] = 0;
		}
		return ticks;
	}
	case LXP_NR_setitimer: { /* (which, new, old) — ITIMER_REAL -> SIGALRM (alarm()) */
		int which = (int)a0;
		const void *unew = (const void *)(uintptr_t)a1;
		void *uold = (void *)(uintptr_t)a2;
		if (which != LXP_ITIMER_REAL)
			return 0; /* only the real-time timer (login timeout, ping interval) */
		/* struct itimerval { timeval it_interval; timeval it_value; }; ARM32 long=4,
		 * so it is 4 x u32: [interval_sec, interval_usec, value_sec, value_usec]. */
		uint64_t now = 0;
		lxp_time_us(&now);
		if (uold) {
			uint32_t ov[4] = {0, 0, 0, 0};
			uint64_t rem = (proc->alarm_deadline_us && proc->alarm_deadline_us > now)
					       ? proc->alarm_deadline_us - now
					       : 0;
			ov[0] = (uint32_t)(proc->alarm_interval_us / 1000000u);
			ov[1] = (uint32_t)(proc->alarm_interval_us % 1000000u);
			ov[2] = (uint32_t)(rem / 1000000u);
			ov[3] = (uint32_t)(rem % 1000000u);
			if (lxp_copy_to_guest(proc, (uintptr_t)uold, ov, sizeof(ov)) != 0)
				return -LXP_EFAULT;
		}
		if (!unew)
			return 0;
		uint32_t nv[4];
		if (lxp_copy_from_guest(proc, nv, (uintptr_t)unew, sizeof(nv)) != 0)
			return -LXP_EFAULT;
		proc->alarm_interval_us = (uint64_t)nv[0] * 1000000u + nv[1];
		uint64_t val_us = (uint64_t)nv[2] * 1000000u + nv[3];
		proc->alarm_deadline_us = val_us ? now + val_us : 0; /* it_value 0 disarms */
		return 0;
	}
	case LXP_NR_getpgrp: /* shell job control: the caller's process group */
		return proc->group->pgid;
	case LXP_NR_setsid: /* getty/login start a new session: the caller leads its own group */
		proc->group->pgid = proc->pid;
		return proc->pid;
	case LXP_NR_reboot: { /* reboot(magic1, magic2, cmd, arg) — cmd is a2 */
		unsigned cmd = (unsigned)a2;
		/* Only an actual halt/poweroff/restart stops the system; init calls
		 * reboot(CAD_OFF=0) at startup to disable Ctrl-Alt-Del — a no-op here. */
		if (cmd == 0x01234567u /* RESTART */ || cmd == 0xcdef0123u /* HALT */ ||
		    cmd == 0x4321fedcu /* POWER_OFF */ || cmd == 0xa1b2c3d4u /* RESTART2 */) {
			lxp_request_halt();
			(void)lxp_intent_exit(proc, 0);
			proc->exit_status = 0;
			proc->exit_reason = LXP_EXIT_REASON_NORMAL;
		}
		return 0;
	}
	case LXP_NR_gettid:
		return proc->pid;
	case LXP_NR_clock_gettime: { /* (clockid, struct timespec*) — 32-bit time_t */
		int32_t *ts = (int32_t *)(uintptr_t)a1;
		if (!lxp_guest_access_ok(proc, ts, 2 * sizeof(int32_t), 1))
			return -LXP_EFAULT;
		uint64_t sec;
		uint32_t nsec;
		now_sec_nsec((int)a0, &sec, &nsec);
		ts[0] = (int32_t)sec;
		ts[1] = (int32_t)nsec;
		return 0;
	}
	case LXP_NR_clock_gettime64: { /* (clockid, struct __kernel_timespec*) — 64-bit */
		int64_t *ts = (int64_t *)(uintptr_t)a1;
		if (!lxp_guest_access_ok(proc, ts, 2 * sizeof(int64_t), 1))
			return -LXP_EFAULT;
		uint64_t sec;
		uint32_t nsec;
		now_sec_nsec((int)a0, &sec, &nsec);
		ts[0] = (int64_t)sec;
		ts[1] = (int64_t)nsec;
		return 0;
	}
	case LXP_NR_gettimeofday: { /* (struct timeval*, tz) */
		int32_t *tv = (int32_t *)(uintptr_t)a0;
		if (!lxp_guest_access_ok(proc, tv, 2 * sizeof(int32_t), 1))
			return -LXP_EFAULT;
		uint64_t sec;
		uint32_t nsec;
		now_sec_nsec(0, &sec, &nsec);
		tv[0] = (int32_t)sec;
		tv[1] = (int32_t)(nsec / 1000u);
		return 0;
	}
	case LXP_NR_nanosleep:	     /* (req, rem) */
	case LXP_NR_clock_nanosleep: /* (clockid, flags, req, rem) */
	case LXP_NR_clock_nanosleep_time64: {
		/* Record a wake deadline and ask the run loop to park + delay this proc
		 * (the trap context cannot block). The run loop aborts the slot for the
		 * duration so the RTOS idle/kernel/other threads run and real time + CPU
		 * stats advance — which is what top needs between its two samples. */
		uintptr_t reqp = (nr == LXP_NR_nanosleep) ? (uintptr_t)a0 : (uintptr_t)a2;
		if (!lxp_guest_access_ok(proc, (const void *)reqp,
					 (nr == LXP_NR_clock_nanosleep_time64) ? 16u : 8u, 0))
			return -LXP_EFAULT;
		uint64_t sec, nsec;
		if (nr == LXP_NR_clock_nanosleep_time64) {
			const int64_t *t = (const int64_t *)reqp; /* time64 {sec, nsec} */
			sec = (uint64_t)t[0];
			nsec = (uint64_t)t[1];
		} else {
			const int32_t *t = (const int32_t *)reqp; /* time32 {sec, nsec} */
			sec = (uint64_t)(uint32_t)t[0];
			nsec = (uint64_t)(uint32_t)t[1];
		}
		uint64_t dur_us = sec * 1000000ull + nsec / 1000ull;
		if (dur_us > 100000000ull)
			dur_us = 100000000ull; /* clamp to 100 s */
		/* The coordinator evaluates deadlines with lxp_time_us(), so construct
		 * them in that same cross-idle clock domain. */
		uint64_t now_us = 0;
		lxp_time_us(&now_us);
		lxp_wait_t wait = {
			.kind = LXP_WAIT_TIMER,
			.data.timer.deadline_us = now_us + dur_us,
		};
		if (lxp_wait_begin(proc, &wait) != 0)
			return -LXP_EAGAIN;
		return 0;
	}
	case LXP_NR_uname: {
		/* struct utsname: 6 fixed 65-byte fields (sysname, nodename, release,
		 * version, machine, domainname). The shell reads these at startup. */
		char *u = (char *)(uintptr_t)a0;
		if (!lxp_guest_access_ok(proc, u, 6 * 65, 1))
			return -LXP_EFAULT;
		const char *const f[6] = {"Linux",  "overtos", "6.1.0", lxp_system_version(),
					  "armv7l", "(none)"};
		memset(u, 0, 6 * 65);
		for (int i = 0; i < 6; i++) {
			size_t l = 0;
			while (l < 64 && f[i][l])
				l++;
			memcpy(u + i * 65, f[i], l);
		}
		return 0;
	}
	case LXP_NR_rt_sigaction: {
		/* Record the per-signal disposition; the engine seam delivers it.
		 * struct sigaction: sa_handler@0, sa_flags@4, sa_restorer@8. */
		int sig = (int)a0;
		if (sig < 1 || sig >= LXP_NSIG)
			return -LXP_EINVAL;
		const uint32_t *act = (const uint32_t *)(uintptr_t)a1;
		uint32_t *oact = (uint32_t *)(uintptr_t)a2;
		if (act && !lxp_guest_access_ok(proc, act, 3 * sizeof(uint32_t), 0))
			return -LXP_EFAULT;
		if (oact && !lxp_guest_access_ok(proc, oact, 3 * sizeof(uint32_t), 1))
			return -LXP_EFAULT;
		if (oact) {
			oact[0] = (uint32_t)lxp_sig_handler_get(proc, sig);
			oact[2] = (uint32_t)lxp_sig_restorer_get(proc);
		}
		if (act) {
			proc->sighand->handler[sig] = act[0];
			proc->sighand->restorer = act[2];
		}
		return 0;
	}
#if LXP_ENABLE_NET
	case LXP_NR_pselect6_time64: /* (nfds, readfds, writefds, exceptfds, timeout, sigmask) */
		return sys_pselect6(proc, (int)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3,
				    (uintptr_t)a4);
#endif
	case LXP_NR_poll:
	case LXP_NR_ppoll_time64:
		return sys_poll(proc, nr, a0, a1, a2);
	case LXP_NR_wait4: {
		if (a1 && !lxp_guest_access_ok(proc, (void *)(uintptr_t)a1, sizeof(int), 1))
			return -LXP_EFAULT; /* the kernel WRITES *status */
		int options = (int)a2;
		int wpid = (int)a0;
		int *status = (int *)(uintptr_t)a1;
		/* Report the first queued child state-change this call is allowed to see (FIFO):
		 * an exited zombie always; a STOPPED notification only with WUNTRACED (job control).
		 * A pid filter (wpid > 0) must match. A STOPPED entry leaves live_children intact —
		 * the child is alive, only the notice is consumed. Else, if children are still live,
		 * block in a CHILD wait until the coordinator observes a change. None → -ECHILD. */
		lxp_thread_group_t *group = proc->group;
		if (!group)
			return -LXP_ECHILD;
		for (int i = 0; i < group->child_count; i++) {
			if (wpid > 0 && group->child_pid[i] != wpid)
				continue;
			if (group->child_kind[i] == LXP_CHILD_STOPPED && !(options & LXP_WUNTRACED))
				continue;
			int pid = group->child_pid[i];
			int code = group->child_status[i];
			int kind = group->child_kind[i];
			for (int j = i + 1; j < group->child_count; j++) {
				group->child_pid[j - 1] = group->child_pid[j];
				group->child_status[j - 1] = group->child_status[j];
				group->child_kind[j - 1] = group->child_kind[j];
			}
			group->child_count--;
			if (status)
				*status = (kind == LXP_CHILD_STOPPED) ? lxp_encode_wstopped(code)
								      : lxp_encode_wstatus(code);
			return pid;
		}
		if (group->live_children == 0)
			return -LXP_ECHILD;
		if (options & LXP_WNOHANG) /* children live but none ready */
			return 0;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_CHILD,
			.data.child.pid = wpid,
			.data.child.options = options,
			.data.child.status = (uintptr_t)a1,
		};
		if (lxp_wait_begin(proc, &wait) != 0)
			return -LXP_EAGAIN;
		return 0; /* dispatch parks; the coordinator's resume supplies the real r0 */
	}
	case LXP_NR_getuid32:
	case LXP_NR_geteuid32:
	case LXP_NR_getgid32:
	case LXP_NR_getegid32:
		return 0; /* run as root */
	case LXP_NR_ioctl:
		return sys_ioctl(proc, a0, a1, a2);
	case LXP_NR_rt_sigsuspend: { /* (unewset, sigsetsize) */
		/* LinuxThreads suspend(): block until a signal (the restart) is delivered. If one is
		 * already pending (a restart that beat us here), fall through so the dispatch delivers
		 * it now; otherwise ask the run loop to park us — the coordinator runs the handler on
		 * the restart kill() and resumes us. sigsuspend always "returns" -EINTR.
		 *
		 * INSTALL the mask arg (POSIX: atomically set the signal mask for the wait): the whole
		 * point of the restart protocol is that the caller BLOCKS the restart signal normally and
		 * sigsuspend UNBLOCKS it only while waiting. If we ignore the mask, the restart stays
		 * blocked, the coordinator's pending_deliverable skips it, and the parked thread is never
		 * woken (deadlock — curl's LinuxThreads resolver: manager, main, and a sigwait thread all
		 * stuck). The prior mask is restored when the delivered handler returns (sig_restore). */
		const uint32_t *uset = (const uint32_t *)(uintptr_t)a0;
		size_t sz = (size_t)a1;
		if (sz != 8)
			return -LXP_EINVAL; /* Linux: sigsetsize must equal sizeof(kernel sigset_t) */
		if (!uset || !lxp_guest_access_ok(proc, uset, sz, 0))
			return -LXP_EFAULT; /* validate the whole 8-byte mask before reading either word */
		uint64_t m = (uint64_t)uset[0] | ((uint64_t)uset[1] << 32);
		m &= ~(lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGSTOP)); /* never blockable */
		proc->sigsuspend_saved_mask = proc->sig_blocked;
		proc->sig_blocked = m;
		proc->sigsuspend_active = 1;
		/* Park unless a signal that is deliverable UNDER THE NEW MASK is already pending — then
		 * fall through so the dispatch delivers it now. A signal pending but blocked by the new
		 * mask must NOT keep us running (it stays pending until the mask is restored). Mirrors
		 * the run loop's pending_deliverable, which is static there. */
		int deliverable = 0;
		for (int sig = 1; sig < LXP_NSIG; sig++)
			if ((proc->pending_sigs & lxp_sig_bit(sig)) &&
			    !lxp_sig_blocked(proc, sig)) {
				deliverable = 1;
				break;
			}
		if (!deliverable) {
			lxp_wait_t wait = {.kind = LXP_WAIT_SIGSUSPEND};
			if (lxp_wait_begin(proc, &wait) != 0)
				return -LXP_EAGAIN;
		}
		return -LXP_EINTR;
	}
	case LXP_NR_rt_sigtimedwait_time64: { /* (set, info, timeout, sigsetsize) */
		/* Poll variant: return a pending signal that is in `set` (dequeuing it), else report
		 * a timeout. Blocking for the timeout is not modeled — this is enough for libc/shell
		 * startup, which drains pending signals with sigtimedwait and must see -EAGAIN (not
		 * -ENOSYS) to finish and continue to the interactive read. */
		const uint32_t *uset = (const uint32_t *)(uintptr_t)a0;
		size_t sz = (size_t)a3;
		if (sz > 8)
			return -LXP_EINVAL;
		uint64_t set = 0;
		if (uset) {
			if (!lxp_guest_access_ok(proc, uset, sz, 0))
				return -LXP_EFAULT;
			if (sz >= 4)
				set |= (uint64_t)uset[0];
			if (sz >= 8)
				set |= (uint64_t)uset[1] << 32;
		}
		uint64_t ready = proc->pending_sigs & set;
		if (ready) {
			int sig = __builtin_ctzll(ready) + 1; /* lowest pending signal in the set */
			proc->pending_sigs &= ~lxp_sig_bit(sig);
			(void)a1; /* siginfo output omitted; the return value carries the signo */
			return sig;
		}
		return -LXP_EAGAIN;
	}
	case LXP_NR_rt_sigprocmask: { /* (how, set, oldset, sigsetsize) */
		int how = (int)a0;
		const uint32_t *uset = (const uint32_t *)(uintptr_t)a1;
		uint32_t *uold = (uint32_t *)(uintptr_t)a2;
		size_t sz = (size_t)a3; /* bytes of the guest sigset_t (8 for the 64-bit mask) */
		if (sz > 8)
			return -LXP_EINVAL;
		if (uset && !lxp_guest_access_ok(proc, uset, sz, 0))
			return -LXP_EFAULT;
		if (uold && !lxp_guest_access_ok(proc, uold, sz, 1))
			return -LXP_EFAULT;
		/* Read the new set BEFORE writing oldset — the guest may alias them, the legal
		 * sigprocmask(SIG_SETMASK, &m, &m) swap — and validate `how` up front so an invalid
		 * value has no side effects. */
		uint64_t nv = 0;
		if (uset) {
			if (how != LXP_SIG_BLOCK && how != LXP_SIG_UNBLOCK &&
			    how != LXP_SIG_SETMASK)
				return -LXP_EINVAL;
			if (sz >= 4)
				nv |= (uint64_t)uset[0];
			if (sz >= 8)
				nv |= (uint64_t)uset[1] << 32;
		}
		uint64_t old = proc->sig_blocked;
		if (uold) { /* report the previous mask, low word then high, within sigsetsize */
			if (sz >= 4)
				uold[0] = (uint32_t)old;
			if (sz >= 8)
				uold[1] = (uint32_t)(old >> 32);
		}
		if (uset) {
			proc->sig_blocked = how == LXP_SIG_BLOCK     ? old | nv
					    : how == LXP_SIG_UNBLOCK ? old & ~nv
								     : nv; /* LXP_SIG_SETMASK */
			/* SIGKILL and SIGSTOP can never be blocked. */
			proc->sig_blocked &= ~(lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGSTOP));
		}
		return 0;
	}
	case LXP_NR_set_tid_address:
		return 1; /* our single thread's tid */
	case LXP_NR_set_robust_list:
		return 0;
		/* futex / futex_time64 are intercepted by the coordinator (src/lxp_run.c, lxp_futex):
	 * a co-running thread's WAIT parks on the uaddr and a peer's WAKE resumes it. They
	 * never reach this switch. */
#if LXP_ENABLE_NET
	case LXP_NR_socket: { /* (domain, type, protocol) */
		long oi = lxp_sock_new((int)a0, (int)a1, (int)a2);
		if (oi < 0)
			return oi;
		int fd = fd_alloc(proc, LXP_FD_SOCKET, (int)oi, 0);
		if (fd < 0) {
			lxp_sock_close((int)oi);
			return -LXP_EMFILE;
		}
		return fd;
	}
	case LXP_NR_connect: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_connect(proc, oi, (const void *)(uintptr_t)a1, (unsigned)a2);
	}
	case LXP_NR_send:     /* (fd, buf, len, flags) */
	case LXP_NR_sendto: { /* (fd, buf, len, flags, dest, destlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		const void *dest = (nr == LXP_NR_sendto) ? (const void *)(uintptr_t)a4 : NULL;
		return lxp_sock_send(proc, oi, (const void *)(uintptr_t)a1, (size_t)a2, (int)a3,
				     dest, (unsigned)a5);
	}
	case LXP_NR_recv:	/* (fd, buf, len, flags) */
	case LXP_NR_recvfrom: { /* (fd, buf, len, flags, src, srclen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		void *src = (nr == LXP_NR_recvfrom) ? (void *)(uintptr_t)a4 : NULL;
		void *srclen = (nr == LXP_NR_recvfrom) ? (void *)(uintptr_t)a5 : NULL;
		return lxp_sock_recv(proc, oi, (void *)(uintptr_t)a1, (size_t)a2, (int)a3, src,
				     srclen);
	}
	case LXP_NR_shutdown: { /* (fd, how) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_shutdown(oi, (int)a1);
	}
	case LXP_NR_getsockname: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_getsockname(proc, oi, (void *)(uintptr_t)a1, (void *)(uintptr_t)a2);
	}
	case LXP_NR_getpeername: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_getpeername(proc, oi, (void *)(uintptr_t)a1, (void *)(uintptr_t)a2);
	}
	case LXP_NR_setsockopt: { /* (fd, level, optname, optval, optlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_setsockopt(proc, oi, (int)a1, (int)a2, (const void *)(uintptr_t)a3,
					   (unsigned)a4);
	}
	case LXP_NR_getsockopt: { /* (fd, level, optname, optval, optlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_getsockopt(proc, oi, (int)a1, (int)a2, (void *)(uintptr_t)a3,
					   (void *)(uintptr_t)a4);
	}
	case LXP_NR_bind: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_bind(proc, oi, (const void *)(uintptr_t)a1, (unsigned)a2);
	}
	case LXP_NR_listen: { /* (fd, backlog) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_listen(oi, (int)a1);
	}
	case LXP_NR_accept:    /* (fd, addr, addrlen) */
	case LXP_NR_accept4: { /* (fd, addr, addrlen, flags) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		int flags = (nr == LXP_NR_accept4) ? (int)a3 : 0;
		return lxp_sock_accept(proc, oi, (void *)(uintptr_t)a1, (void *)(uintptr_t)a2,
				       flags);
	}
	case LXP_NR_sendmsg: { /* (fd, msghdr, flags) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return sys_sendmsg(proc, oi, (const lxp_msghdr *)(uintptr_t)a1, (int)a2);
	}
	case LXP_NR_recvmsg: { /* (fd, msghdr, flags) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return sys_recvmsg(proc, oi, (lxp_msghdr *)(uintptr_t)a1, (int)a2);
	}
	case LXP_NR_socketpair: /* fd-passing (SCM_RIGHTS) unsupported */
		return -LXP_EOPNOTSUPP;
#endif
	default:
		return -LXP_ENOSYS;
	}
}

#if LXP_ENABLE_NET
/* Re-evaluate a parked poll(2)'s fd set for readiness (socket + device + console).
 * Mirrors the initial sys_poll scan but in blocking mode — a console fd reports its
 * real key readiness rather than the vi/top ESC-probe heuristic. */
static int lxp_poll_scan(lxp_proc_t *proc, lxp_pollfd *pfds, unsigned nfds)
{
	int ready = 0;
	for (unsigned i = 0; i < nfds; i++) {
		pfds[i].revents = 0;
		lxp_ofd_t *s = lxp_fd_description(proc, pfds[i].fd);
		if (!s)
			continue;
		/* Dispatch readiness through the fd's ops; a kind with no poll fop
		 * (regular file / tmpfs / proc / netfs) is always ready. */
		const lxp_file_ops_t *ops = lxp_vfs_ops(s);
		unsigned pb = ops && ops->poll ? ops->poll(proc, s)
					       : (unsigned)(LXP_POLLIN | LXP_POLLOUT);
		pfds[i].revents = (short)(pfds[i].events & pb & (LXP_POLLIN | LXP_POLLOUT));
		if (pfds[i].revents)
			ready++;
	}
	return ready;
}

/* ── pselect6(2): select() bridged onto the poll machinery ─────────────────────
 * An fd_set here is one 32-bit word (nfds capped at LXP_SEL_MAXFDS). We derive a
 * pollfd set from the caller's readfds/writefds, scan it with lxp_poll_scan, and
 * write the ready fds back into the fd_sets. A blocking select parks on SOCKW_POLL and
 * the retry re-derives the set from the (still-unmodified) fd_sets each pass. */
static int sel_isset(const uint32_t *set, int fd)
{
	return set && ((set[fd >> 5] >> (fd & 31)) & 1u);
}

/* Build a pollfd array from the fd_sets; returns the count. */
static int sel_build(const lxp_wait_t *wait, lxp_pollfd *pf)
{
	const uint32_t *r = (const uint32_t *)wait->data.socket.readfds;
	const uint32_t *w = (const uint32_t *)wait->data.socket.writefds;
	int n = 0;
	for (int fd = 0; fd < wait->data.socket.nfds && n < LXP_SEL_MAXFDS; fd++) {
		unsigned ev = 0;
		if (sel_isset(r, fd))
			ev |= LXP_POLLIN;
		if (sel_isset(w, fd))
			ev |= LXP_POLLOUT;
		if (ev) {
			pf[n].fd = fd;
			pf[n].events = (short)ev;
			pf[n].revents = 0;
			n++;
		}
	}
	return n;
}

/* Write the scanned pollfd revents back into the caller's fd_sets; returns select()'s
 * count (a fd ready for both read and write counts twice). Zeroes the sets first. */
static long sel_writeback(const lxp_wait_t *wait, const lxp_pollfd *pf, int npf)
{
	uint32_t *r = (uint32_t *)wait->data.socket.readfds;
	uint32_t *w = (uint32_t *)wait->data.socket.writefds;
	uint32_t *e = (uint32_t *)wait->data.socket.exceptfds;
	if (r)
		r[0] = 0;
	if (w)
		w[0] = 0;
	if (e)
		e[0] = 0;
	long ready = 0;
	for (int i = 0; i < npf; i++) {
		int fd = pf[i].fd;
		if ((pf[i].revents & LXP_POLLIN) && r) {
			r[fd >> 5] |= (1u << (fd & 31));
			ready++;
		}
		if ((pf[i].revents & LXP_POLLOUT) && w) {
			w[fd >> 5] |= (1u << (fd & 31));
			ready++;
		}
	}
	return ready; /* exceptfds left cleared (no out-of-band data on this tier) */
}

static long sys_pselect6(lxp_proc_t *p, int nfds, uintptr_t urfds, uintptr_t uwfds, uintptr_t uefds,
			 uintptr_t utimeout)
{
	if (nfds < 0)
		return -LXP_EINVAL;
	if (nfds > LXP_SEL_MAXFDS)
		nfds = LXP_SEL_MAXFDS; /* one fd_set word; higher fds are not selectable here */
	size_t setb = sizeof(uint32_t);
	if ((urfds && !lxp_guest_access_ok(p, (void *)urfds, setb, 1)) ||
	    (uwfds && !lxp_guest_access_ok(p, (void *)uwfds, setb, 1)) ||
	    (uefds && !lxp_guest_access_ok(p, (void *)uefds, setb, 1)))
		return -LXP_EFAULT;
	long tmo_ms = -1; /* NULL timeout = block forever */
	if (utimeout) {
		if (!lxp_guest_access_ok(p, (void *)utimeout, 2 * sizeof(int64_t), 0))
			return -LXP_EFAULT;
		const int64_t *ts = (const int64_t *)utimeout; /* time64: tv_sec, tv_nsec */
		int64_t ms = ts[0] * 1000 + ts[1] / 1000000;
		tmo_ms = ms < 0 ? 0 : (long)ms;
	}
	lxp_wait_t wait = {
		.kind = LXP_WAIT_SOCKET,
		.op = LXP_SOCKW_POLL,
		.flags = 1,
		.data.socket.object = -1,
		.data.socket.nfds = nfds,
		.data.socket.readfds = urfds,
		.data.socket.writefds = uwfds,
		.data.socket.exceptfds = uefds,
	};
	lxp_pollfd pf[LXP_SEL_MAXFDS];
	int npf = sel_build(&wait, pf);
	int ready = lxp_poll_scan(p, pf, (unsigned)npf);
	if (ready > 0 || tmo_ms == 0)
		return sel_writeback(&wait, pf, npf);
	/* Park on the poll machinery; lxp_poll_retry re-derives + completes it. */
	if (tmo_ms > 0) {
		uint64_t now = 0;
		lxp_time_us(&now);
		wait.data.socket.deadline_us = now + (uint64_t)tmo_ms * 1000ull;
	} else {
		wait.data.socket.deadline_us = UINT64_MAX;
	}
	if (lxp_wait_begin(p, &wait) != 0)
		return -LXP_EAGAIN;
	return 0;
}

long lxp_poll_retry(lxp_proc_t *proc)
{
	if (!proc || proc->wait.kind != LXP_WAIT_SOCKET || proc->wait.op != LXP_SOCKW_POLL)
		return -LXP_EINVAL;
	if (proc->wait.flags & 1u) { /* parked pselect6: re-derive from fd_sets */
		lxp_pollfd pf[LXP_SEL_MAXFDS];
		int npf = sel_build(&proc->wait, pf);
		int ready = lxp_poll_scan(proc, pf, (unsigned)npf);
		int timedout = 0;
		if (proc->wait.data.socket.deadline_us != UINT64_MAX) {
			uint64_t now_us = 0;
			lxp_time_us(&now_us);
			timedout = (now_us >= proc->wait.data.socket.deadline_us);
		}
		if (ready > 0 || timedout)
			return sel_writeback(&proc->wait, pf, npf);
		return -LXP_EAGAIN;
	}
	lxp_pollfd *pfds = (lxp_pollfd *)(uintptr_t)proc->wait.data.socket.buffer;
	int ready = lxp_poll_scan(proc, pfds, (unsigned)proc->wait.data.socket.length);
	if (ready > 0)
		return ready;
	if (proc->wait.data.socket.deadline_us != UINT64_MAX) {
		uint64_t now_us = 0;
		lxp_time_us(&now_us);
		if (now_us >= proc->wait.data.socket.deadline_us)
			return 0; /* timed out */
	}
	return -LXP_EAGAIN; /* still waiting */
}
#endif /* LXP_ENABLE_NET */
