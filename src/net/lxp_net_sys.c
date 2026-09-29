/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The socket syscalls: each resolves its descriptor to a socket and calls the
 * socket layer (src/net/lxp_net.c).
 */
#include "lxp/lxp_config.h"

#if LXP_ENABLE_NET

#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_linux_uapi.h"
#include "net/lxp_net.h"
#include "sys/lxp_sys.h"

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

/* send/sendto on socket fd a[0]; @p dest/@p destlen are sendto's address. */
static long sock_send_common(lxp_proc_t *proc, const long a[6], const void *dest,
			     unsigned destlen)
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_send(proc, oi, (const void *)(uintptr_t)a[1], (size_t)a[2], (int)a[3], dest,
			     destlen);
}

/* recv/recvfrom on socket fd a[0]; @p src/@p srclen are recvfrom's address out. */
static long sock_recv_common(lxp_proc_t *proc, const long a[6], void *src, void *srclen)
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_recv(proc, oi, (void *)(uintptr_t)a[1], (size_t)a[2], (int)a[3], src,
			     srclen);
}

/* accept/accept4 on socket fd a[0] with accept4's @p flags. */
static long sock_accept_common(lxp_proc_t *proc, const long a[6], int flags)
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_accept(proc, oi, (void *)(uintptr_t)a[1], (void *)(uintptr_t)a[2], flags);
}

/* (domain, type, protocol) */
long lxp_sys_socket(lxp_proc_t *proc, const long a[6])
{
	long oi = lxp_sock_new((int)a[0], (int)a[1], (int)a[2]);
	if (oi < 0)
		return oi;
	/* SOCK_NONBLOCK / SOCK_CLOEXEC share O_NONBLOCK / O_CLOEXEC's values. */
	int fd = lxp_sys_fd_alloc(proc, LXP_FD_SOCKET, (int)oi, 0,
			  LXP_O_RDWR | ((int)a[1] & (LXP_O_NONBLOCK | LXP_O_CLOEXEC)));
	if (fd < 0) {
		lxp_sock_close((int)oi);
		return -LXP_EMFILE;
	}
	return fd;
}

/* (fd, addr, addrlen) */
long lxp_sys_connect(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_connect(proc, oi, (const void *)(uintptr_t)a[1], (unsigned)a[2]);
}

/* (fd, buf, len, flags) */
long lxp_sys_send(lxp_proc_t *proc, const long a[6])
{
	return sock_send_common(proc, a, NULL, (unsigned)a[5]);
}

/* (fd, buf, len, flags, dest, destlen) */
long lxp_sys_sendto(lxp_proc_t *proc, const long a[6])
{
	return sock_send_common(proc, a, (const void *)(uintptr_t)a[4], (unsigned)a[5]);
}

/* (fd, buf, len, flags) */
long lxp_sys_recv(lxp_proc_t *proc, const long a[6])
{
	return sock_recv_common(proc, a, NULL, NULL);
}

/* (fd, buf, len, flags, src, srclen) */
long lxp_sys_recvfrom(lxp_proc_t *proc, const long a[6])
{
	return sock_recv_common(proc, a, (void *)(uintptr_t)a[4], (void *)(uintptr_t)a[5]);
}

/* (fd, how) */
long lxp_sys_shutdown(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_shutdown(oi, (int)a[1]);
}

/* (fd, addr, addrlen) */
long lxp_sys_getsockname(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_getsockname(proc, oi, (void *)(uintptr_t)a[1], (void *)(uintptr_t)a[2]);
}

/* (fd, addr, addrlen) */
long lxp_sys_getpeername(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_getpeername(proc, oi, (void *)(uintptr_t)a[1], (void *)(uintptr_t)a[2]);
}

/* (fd, level, optname, optval, optlen) */
long lxp_sys_setsockopt(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_setsockopt(proc, oi, (int)a[1], (int)a[2], (const void *)(uintptr_t)a[3],
				   (unsigned)a[4]);
}

/* (fd, level, optname, optval, optlen) */
long lxp_sys_getsockopt(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_getsockopt(proc, oi, (int)a[1], (int)a[2], (void *)(uintptr_t)a[3],
				   (void *)(uintptr_t)a[4]);
}

/* (fd, addr, addrlen) */
long lxp_sys_bind(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_bind(proc, oi, (const void *)(uintptr_t)a[1], (unsigned)a[2]);
}

/* (fd, backlog) */
long lxp_sys_listen(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_listen(oi, (int)a[1]);
}

/* (fd, addr, addrlen) */
long lxp_sys_accept(lxp_proc_t *proc, const long a[6])
{
	return sock_accept_common(proc, a, 0);
}

/* (fd, addr, addrlen, flags) */
long lxp_sys_accept4(lxp_proc_t *proc, const long a[6])
{
	return sock_accept_common(proc, a, (int)a[3]);
}

/* (fd, msghdr, flags) */
long lxp_sys_sendmsg(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return sys_sendmsg(proc, oi, (const lxp_msghdr *)(uintptr_t)a[1], (int)a[2]);
}

/* (fd, msghdr, flags) */
long lxp_sys_recvmsg(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return sys_recvmsg(proc, oi, (lxp_msghdr *)(uintptr_t)a[1], (int)a[2]);
}

/* fd-passing (SCM_RIGHTS) unsupported */
long lxp_sys_socketpair(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	(void)proc;
	return -LXP_EOPNOTSUPP;
}

#endif /* LXP_ENABLE_NET */
