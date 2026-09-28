/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Linux-personality socket core: a pooled per-open socket table backed by the
 * handle-based network provider, and the routing the
 * FD_SOCKET branches of the syscall handlers call into. It mirrors the /dev device
 * layer (src/dev/lxp_dev.c): the fd's file_idx indexes a refcounted open
 * pool; a generic open-file description owns fork/dup aliases, and its last
 * close closes the socket.
 *
 * Blocking is deferred, never inline: the backing provider socket is non-blocking,
 * so every op returns at once; a would-block (LXP_ERR_TIMEOUT) parks the caller
 * (LXP_WAIT_SOCKET) and the run-loop coordinator retries via lxp_sock_retry —
 * the same park/retry the pipe and device layers use.
 */

#include "lxp/lxp_config.h"

#if LXP_ENABLE_NET

#include "net/lxp_net.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_vfs.h"
#include "lxp/lxp_net_ops.h"
#include "proc/lxp_proc.h"
#include "lxp_provider.h"

#include <string.h>

/** Per-open socket state. A generic open-file description owns descriptor
 * aliases; its last close closes the backing socket. */
struct sock_open {
	uint8_t used;
	uint8_t connecting;  /* a non-blocking connect is in flight */
	uint8_t type;	     /* lxp_sock_type_t: STREAM / DGRAM / RAW (for sendmsg gathering) */
	uint16_t oflags;     /* guest fd status flags (O_NONBLOCK gates parking) */
	uintptr_t rx_src;    /* parked recvfrom: user sockaddr* to fill (0 => recv) */
	uintptr_t rx_srclen; /* parked recvfrom: user socklen_t* */
	lxp_socket_t sock;   /* host-owned handle; the adapter owns the storage */
};

static struct sock_open g_sock[LXP_NSOCK];

static struct sock_open *open_slot(int oi)
{
	if (oi < 0 || oi >= LXP_NSOCK || !g_sock[oi].used)
		return NULL;
	return &g_sock[oi];
}

/* ---- byte-order + address / errno translation ------------------------------ */

static inline uint16_t bswap16(uint16_t v)
{
	return (uint16_t)((v >> 8) | (v << 8));
}

/* Guest sockaddr_in (sin_port/sin_addr network order) -> lxp_sockaddr_t
 * (port host order, addr[] the raw network-order bytes). */
static void guest_sin_to_addr(const lxp_sockaddr_in *sin, lxp_sockaddr_t *oa)
{
	memset(oa, 0, sizeof(*oa));
	oa->family = LXP_AF_INET;
	oa->port = bswap16(sin->sin_port);
	memcpy(oa->addr, &sin->sin_addr, 4);
}

static void addr_to_guest_sin(const lxp_sockaddr_t *oa, lxp_sockaddr_in *sin)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = LXP_AF_INET;
	sin->sin_port = bswap16(oa->port);
	memcpy(&sin->sin_addr, oa->addr, 4);
}

/* Provider error -> negated Linux errno. LXP_ERR_TIMEOUT is the "would block"
 * signal from a non-blocking op and is handled by the caller before this. */
static long net_errno_to_lnx(int e)
{
	switch (e) {
	case LXP_OK:
		return 0;
	case LXP_ERR_NET_REFUSED:
		return -LXP_ECONNREFUSED;
	case LXP_ERR_NET_UNREACHABLE:
		return -LXP_ENETUNREACH;
	case LXP_ERR_NET_ADDR_IN_USE:
		return -LXP_EADDRINUSE;
	case LXP_ERR_NET_ADDR_NOT_AVAILABLE:
		return -LXP_EADDRNOTAVAIL;
	case LXP_ERR_NET_RESET:
		return -LXP_ECONNRESET;
	case LXP_ERR_NET_CLOSED:
		return -LXP_EPIPE;
	case LXP_ERR_TIMEOUT:
		return -LXP_EAGAIN;
	case LXP_ERR_INVALID_PARAM:
		return -LXP_EINVAL;
	case LXP_ERR_NO_MEMORY:
		return -LXP_ENOMEM;
	case LXP_ERR_NET_DNS_FAIL:
	case LXP_ERR_NOT_SUPPORTED:
	default:
		return -LXP_EOPNOTSUPP;
	}
}

/* Copy an lxp_sockaddr_t out to a guest (sockaddr*, socklen_t*) pair, honouring
 * the caller's buffer cap and writing back the untruncated size (Linux semantics). */
static long copy_sockaddr_out(lxp_proc_t *p, void *uaddr, void *uaddrlen, const lxp_sockaddr_t *oa)
{
	if (!uaddr || !uaddrlen)
		return 0;
	uint32_t cap;
	if (lxp_guest_get_u32(p, (uintptr_t)uaddrlen, &cap) != 0)
		return -LXP_EFAULT;
	lxp_sockaddr_in sin;
	addr_to_guest_sin(oa, &sin);
	uint32_t n = cap < sizeof(sin) ? cap : (uint32_t)sizeof(sin);
	if (lxp_copy_to_guest(p, (uintptr_t)uaddr, &sin, n) != 0)
		return -LXP_EFAULT;
	return lxp_guest_put_u32(p, (uintptr_t)uaddrlen, (uint32_t)sizeof(sin));
}

/* ---- socket(2) + open-pool lifecycle --------------------------------------- */

long lxp_sock_new(int domain, int type, int protocol)
{
	if (domain != LXP_AF_INET)
		return -LXP_EAFNOSUPPORT;
	int base = type & LXP_SOCK_TYPE_MASK;
	lxp_sock_type_t ot;
	int proto = 0; /* default protocol for the type */
	if (base == LXP_SOCK_STREAM) {
		ot = LXP_SOCK_STREAM;
	} else if (base == LXP_SOCK_DGRAM) {
		ot = LXP_SOCK_DGRAM;
	} else if (base == LXP_SOCK_RAW) {
		ot = LXP_SOCK_RAW;
		proto = protocol; /* e.g. IPPROTO_ICMP (1) for busybox ping */
	} else {
		return -LXP_EPROTONOSUPPORT;
	}

	int oi = -1;
	for (int i = 0; i < LXP_NSOCK; i++)
		if (!g_sock[i].used) {
			oi = i;
			break;
		}
	if (oi < 0)
		return -LXP_EMFILE;

	struct sock_open *o = &g_sock[oi];
	memset(o, 0, sizeof(*o));
	int r = g_lxp_net_ops->sock_open(LXP_AF_INET, ot, proto, &o->sock);
	if (r != LXP_OK)
		return net_errno_to_lnx(r);
	/* Drive blocking via the coordinator's park/retry: keep the backing socket
	 * non-blocking so every op returns at once (a 0 timeout is NOT uniformly
	 * non-blocking — some backends map it to SO_RCVTIMEO = block-forever). */
	r = g_lxp_net_ops->sock_set_nonblock(o->sock, 1);
	if (r != LXP_OK) {
		g_lxp_net_ops->sock_close(o->sock);
		memset(o, 0, sizeof(*o));
		return net_errno_to_lnx(r);
	}
	o->used = 1;
	o->type = (uint8_t)ot;
	if (type & LXP_SOCK_NONBLOCK)
		o->oflags |= LXP_O_NONBLOCK;
	return oi;
}

/* Whether socket @p oi is a datagram socket — sendmsg gathers a multi-segment message into
 * one datagram for these (a per-segment send would fragment it into several). */
int lxp_sock_is_dgram(int oi)
{
	struct sock_open *o = open_slot(oi);
	return o && o->type == LXP_SOCK_DGRAM;
}

void lxp_sock_close(int oi)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return;
	g_lxp_net_ops->sock_close(o->sock);
	o->used = 0;
}

void lxp_sock_setfl(int oi, int flags)
{
	struct sock_open *o = open_slot(oi);
	if (o)
		o->oflags = (uint16_t)flags;
}

int lxp_sock_getfl(int oi)
{
	struct sock_open *o = open_slot(oi);
	/* A socket is bidirectional → O_RDWR. uClibc fdopen(fd,"r+") checks F_GETFL's
	 * access mode and returns EINVAL (which busybox wget reports as "out of memory")
	 * if it looks read-only — so the access bits must be present, not just oflags. */
	return o ? (LXP_O_RDWR | (int)o->oflags) : -LXP_EBADF;
}

/* ---- connect / send / recv (with deferred-block park) ---------------------- */

long lxp_sock_connect(lxp_proc_t *p, int oi, const void *uaddr, unsigned addrlen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;

	/* Re-entrant probe of an in-flight connect (a non-blocking guest that calls
	 * connect() again to poll for completion): report via SO_ERROR, don't
	 * re-initiate. */
	if (o->connecting) {
		unsigned rev = 0;
		g_lxp_net_ops->sock_poll(o->sock, LXP_SOCK_POLLOUT, &rev, 0);
		if (!(rev & (LXP_SOCK_POLLOUT | LXP_SOCK_POLLERR | LXP_SOCK_POLLHUP))) {
			if (o->oflags & LXP_O_NONBLOCK)
				return -LXP_EALREADY;
			lxp_wait_t wait = {
				.kind = LXP_WAIT_SOCKET,
				.op = LXP_SOCKW_CONNECT,
				.data.socket.object = oi,
			};
			if (lxp_wait_begin(p, &wait) != 0)
				return -LXP_EAGAIN;
			return 0;
		}
		int se = g_lxp_net_ops->sock_get_error(o->sock);
		o->connecting = 0;
		return se == LXP_OK ? -LXP_EISCONN : net_errno_to_lnx(se);
	}

	lxp_sockaddr_in sin;
	if (!uaddr || addrlen < sizeof(sin) ||
	    lxp_copy_from_guest(p, &sin, (uintptr_t)uaddr, sizeof(sin)) != 0)
		return -LXP_EFAULT;
	if (sin.sin_family != LXP_AF_INET)
		return -LXP_EAFNOSUPPORT;
	lxp_sockaddr_t oa;
	guest_sin_to_addr(&sin, &oa);

	/* A 0 timeout initiates the connect and probes readiness once. */
	int r = g_lxp_net_ops->sock_connect(o->sock, &oa, 0);
	if (r == LXP_OK)
		return 0;
	if (r == LXP_ERR_TIMEOUT) { /* connection in progress */
		o->connecting = 1;
		if (o->oflags & LXP_O_NONBLOCK)
			return -LXP_EINPROGRESS;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_SOCKET,
			.op = LXP_SOCKW_CONNECT,
			.data.socket.object = oi,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0; /* parked */
	}
	return net_errno_to_lnx(r);
}

long lxp_sock_bind(lxp_proc_t *p, int oi, const void *uaddr, unsigned addrlen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	lxp_sockaddr_in sin;
	if (!uaddr || addrlen < sizeof(sin) ||
	    lxp_copy_from_guest(p, &sin, (uintptr_t)uaddr, sizeof(sin)) != 0)
		return -LXP_EFAULT;
	if (sin.sin_family != LXP_AF_INET)
		return -LXP_EAFNOSUPPORT;
	lxp_sockaddr_t oa;
	guest_sin_to_addr(&sin, &oa);
	return net_errno_to_lnx(g_lxp_net_ops->sock_bind(o->sock, &oa));
}

long lxp_sock_listen(int oi, int backlog)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	return net_errno_to_lnx(g_lxp_net_ops->sock_listen(o->sock, backlog));
}

/* Accept one pending connection on listen slot @lo into a fresh pool slot + fd.
 * Returns the new guest fd, -EAGAIN if none is pending yet (the caller parks or
 * reports would-block), or a negative errno. Runs both from accept(2) and, on a
 * parked accept, from the coordinator's retry — so it owns the whole mint. */
static long do_accept(lxp_proc_t *p, struct sock_open *lo, void *uaddr, void *uaddrlen, int flags)
{
	int ci = -1;
	for (int i = 0; i < LXP_NSOCK; i++)
		if (!g_sock[i].used) {
			ci = i;
			break;
		}
	if (ci < 0)
		return -LXP_EMFILE; /* socket pool full */
	struct sock_open *co = &g_sock[ci];
	memset(co, 0, sizeof(*co));
	int r = g_lxp_net_ops->sock_accept(lo->sock, &co->sock, LXP_WAIT_FOREVER);
	if (r == LXP_ERR_TIMEOUT)
		return -LXP_EAGAIN; /* no pending connection (non-blocking listen socket) */
	if (r != LXP_OK)
		return net_errno_to_lnx(r);
	r = g_lxp_net_ops->sock_set_nonblock(co->sock, 1);
	if (r != LXP_OK) {
		g_lxp_net_ops->sock_close(co->sock);
		memset(co, 0, sizeof(*co));
		return net_errno_to_lnx(r);
	}
	co->used = 1;
	if (flags & LXP_SOCK_NONBLOCK)
		co->oflags |= LXP_O_NONBLOCK;
	if (uaddr) {
		lxp_sockaddr_t pa;
		if (g_lxp_net_ops->sock_getpeername(co->sock, &pa) == LXP_OK)
			(void)copy_sockaddr_out(p, uaddr, uaddrlen, &pa);
	}
	int fd = lxp_fd_install(p, LXP_FD_SOCKET, ci);
	if (fd < 0) {
		g_lxp_net_ops->sock_close(co->sock);
		co->used = 0;
		return -LXP_EMFILE;
	}
	return fd;
}

long lxp_sock_accept(lxp_proc_t *p, int oi, void *uaddr, void *uaddrlen, int flags)
{
	struct sock_open *lo = open_slot(oi);
	if (!lo)
		return -LXP_EBADF;
	if (uaddr && (!uaddrlen || !lxp_guest_access_ok(p, uaddrlen, sizeof(uint32_t), 1)))
		return -LXP_EFAULT;
	long r = do_accept(p, lo, uaddr, uaddrlen, flags);
	if (r == -LXP_EAGAIN) {
		if (lo->oflags & LXP_O_NONBLOCK)
			return -LXP_EAGAIN;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_SOCKET,
			.op = LXP_SOCKW_ACCEPT,
			.data.socket.object = oi,
			.data.socket.buffer = (uintptr_t)uaddr,
			.data.socket.length = (size_t)(uintptr_t)uaddrlen,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0; /* parked */
	}
	return r; /* new fd, or a negative errno */
}

long lxp_sock_send(lxp_proc_t *p, int oi, const void *ubuf, size_t len, int flags,
		   const void *udest, unsigned destlen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	if (len && (!ubuf || !lxp_guest_access_ok(p, ubuf, len, 0)))
		return -LXP_EFAULT;

	size_t sent = 0;
	int r;
	lxp_sockaddr_t oa;
	if (udest) {
		lxp_sockaddr_in sin;
		if (destlen < sizeof(sin) ||
		    lxp_copy_from_guest(p, &sin, (uintptr_t)udest, sizeof(sin)) != 0)
			return -LXP_EFAULT;
		guest_sin_to_addr(&sin, &oa);
	}
	/* The engine transport (lwIP copy) runs in the privileged coordinator, which reads this guest
	 * buffer from physical memory through an uncached view; flush the guest's dirty D-cache lines
	 * first so it does not copy stale bytes (a no-op except on the D-cache-on STM32F746). */
	lxp_cache_clean(ubuf, len);
	if (udest)
		r = g_lxp_net_ops->sock_sendto(o->sock, ubuf, len, &sent, &oa);
	else
		r = g_lxp_net_ops->sock_send(o->sock, ubuf, len, &sent);
	if (r == LXP_OK)
		return (long)sent;
	if (r == LXP_ERR_TIMEOUT) {
		/* A blocked stream send parks; a datagram sendto returns EAGAIN (the
		 * park would need to remember its dest — added when needed). */
		if (udest || (o->oflags & LXP_O_NONBLOCK) || (flags & LXP_MSG_DONTWAIT))
			return -LXP_EAGAIN;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_SOCKET,
			.op = LXP_SOCKW_SEND,
			.data.socket.object = oi,
			.data.socket.buffer = (uintptr_t)ubuf,
			.data.socket.length = len,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0; /* parked */
	}
	return net_errno_to_lnx(r);
}

/* sendmsg on a datagram socket: gather all iovec segments into ONE datagram and send it as a
 * single packet (a per-segment send would put each segment on the wire as its own datagram,
 * corrupting message boundaries). Bounded — a message larger than the gather buffer is
 * -EMSGSIZE. Datagram sends never park, so a kernel-side gather buffer is safe here. */
long lxp_sock_sendmsg(lxp_proc_t *p, int oi, const lxp_iovec *iov, int iovcnt, int flags,
		      const void *udest, unsigned destlen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	char buf[1024];
	size_t off = 0;
	for (int i = 0; i < iovcnt; i++) {
		lxp_iovec entry;
		if (lxp_copy_from_guest(p, &entry, (uintptr_t)&iov[i], sizeof(entry)) != 0)
			return -LXP_EFAULT;
		size_t n = entry.iov_len;
		if (n == 0)
			continue;
		if (off + n > sizeof(buf))
			return -LXP_EMSGSIZE;
		if (!entry.iov_base ||
		    lxp_copy_from_guest(p, buf + off, (uintptr_t)entry.iov_base, n) != 0)
			return -LXP_EFAULT;
		off += n;
	}
	size_t sent = 0;
	lxp_sockaddr_t oa;
	if (udest) {
		lxp_sockaddr_in sin;
		if (destlen < sizeof(sin) ||
		    lxp_copy_from_guest(p, &sin, (uintptr_t)udest, sizeof(sin)) != 0)
			return -LXP_EFAULT;
		guest_sin_to_addr(&sin, &oa);
	}
	lxp_cache_clean(buf, off);
	int r = udest ? g_lxp_net_ops->sock_sendto(o->sock, buf, off, &sent, &oa)
		      : g_lxp_net_ops->sock_send(o->sock, buf, off, &sent);
	(void)flags;
	if (r == LXP_OK)
		return (long)sent;
	if (r == LXP_ERR_TIMEOUT)
		return -LXP_EAGAIN; /* a datagram send does not park */
	return net_errno_to_lnx(r);
}

long lxp_sock_recv(lxp_proc_t *p, int oi, void *ubuf, size_t len, int flags, void *usrc,
		   void *usrclen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	if (len && (!ubuf || !lxp_guest_access_ok(p, ubuf, len, 1)))
		return -LXP_EFAULT;

	size_t got = 0;
	lxp_sockaddr_t src;
	int r;
	if (usrc)
		r = g_lxp_net_ops->sock_recvfrom(o->sock, ubuf, len, &got, &src, LXP_WAIT_FOREVER);
	else
		r = g_lxp_net_ops->sock_recv(o->sock, ubuf, len, &got, LXP_WAIT_FOREVER);

	if (r == LXP_OK) {
		if (usrc)
			(void)copy_sockaddr_out(p, usrc, usrclen, &src);
		return (long)got;
	}
	if (r == LXP_ERR_NET_CLOSED)
		return 0; /* EOF: peer performed an orderly shutdown */
	if (r == LXP_ERR_TIMEOUT) {
		if ((o->oflags & LXP_O_NONBLOCK) || (flags & LXP_MSG_DONTWAIT))
			return -LXP_EAGAIN;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_SOCKET,
			.op = LXP_SOCKW_RECV,
			.data.socket.object = oi,
			.data.socket.buffer = (uintptr_t)ubuf,
			.data.socket.length = len,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		o->rx_src = (uintptr_t)usrc; /* non-zero => recvfrom on the retry */
		o->rx_srclen = (uintptr_t)usrclen;
		return 0; /* parked */
	}
	return net_errno_to_lnx(r);
}

long lxp_sock_shutdown(int oi, int how)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	int oh = (how == 0) ? LXP_SHUT_RD : (how == 1) ? LXP_SHUT_WR : LXP_SHUT_RDWR;
	return net_errno_to_lnx(g_lxp_net_ops->sock_shutdown(o->sock, oh));
}

long lxp_sock_getsockname(lxp_proc_t *p, int oi, void *uaddr, void *uaddrlen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	lxp_sockaddr_t oa;
	int r = g_lxp_net_ops->sock_getsockname(o->sock, &oa);
	if (r != LXP_OK)
		return net_errno_to_lnx(r);
	return copy_sockaddr_out(p, uaddr, uaddrlen, &oa);
}

long lxp_sock_getpeername(lxp_proc_t *p, int oi, void *uaddr, void *uaddrlen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	lxp_sockaddr_t oa;
	int r = g_lxp_net_ops->sock_getpeername(o->sock, &oa);
	if (r != LXP_OK)
		return net_errno_to_lnx(r);
	return copy_sockaddr_out(p, uaddr, uaddrlen, &oa);
}

long lxp_sock_getsockopt(lxp_proc_t *p, int oi, int level, int optname, void *uval, void *ulen)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	uint32_t cap;
	if (!uval || !ulen || lxp_guest_get_u32(p, (uintptr_t)ulen, &cap) != 0)
		return -LXP_EFAULT;
	int val = 0;
	if (level == LXP_SOL_SOCKET && optname == LXP_SO_ERROR) {
		int se = g_lxp_net_ops->sock_get_error(o->sock);
		val = (int)(-net_errno_to_lnx(se)); /* positive Linux errno, or 0 */
	}
	/* Other accepted options report their emulated zero value. */
	uint32_t n = cap < sizeof(int) ? cap : (uint32_t)sizeof(int);
	if (lxp_copy_to_guest(p, (uintptr_t)uval, &val, n) != 0)
		return -LXP_EFAULT;
	return lxp_guest_put_u32(p, (uintptr_t)ulen, (uint32_t)sizeof(int));
}

long lxp_sock_setsockopt(lxp_proc_t *p, int oi, int level, int optname, const void *uval,
			 unsigned len)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	(void)level;
	(void)optname;
	if (len && (!uval || !lxp_guest_access_ok(p, uval, len, 0)))
		return -LXP_EFAULT;
	/* Accept-and-ignore: the socket is driven non-blocking with coordinator
	 * park/retry, so SO_RCVTIMEO / SO_REUSEADDR / TCP_NODELAY are emulated
	 * no-ops here. */
	return 0;
}

unsigned lxp_sock_poll(int oi)
{
	struct sock_open *o = open_slot(oi);
	if (!o)
		return 0;
	unsigned rev = 0, out = 0;
	if (g_lxp_net_ops->sock_poll(o->sock, LXP_SOCK_POLLIN | LXP_SOCK_POLLOUT, &rev, 0) !=
	    LXP_OK)
		return LXP_POLLIN; /* surface the condition via a read */
	if (rev & (LXP_SOCK_POLLIN | LXP_SOCK_POLLERR | LXP_SOCK_POLLHUP))
		out |= LXP_POLLIN;
	if (rev & LXP_SOCK_POLLOUT)
		out |= LXP_POLLOUT;
	return out;
}

void lxp_sock_fstat(int oi, uint32_t *mode, uint64_t *size)
{
	(void)oi;
	if (mode)
		*mode = LXP_S_IFSOCK | 0666u;
	if (size)
		*size = 0;
}

/* ---- interface config (ifconfig / route) ioctls ---------------------------- */

static lxp_netif_t g_lnx_netif; /* the interface the SIOC* ioctls act on (one eth0) */

void lxp_sock_run_begin(lxp_netif_t netif)
{
	g_lnx_netif = netif;
}

void lxp_sock_run_end(void)
{
	g_lnx_netif = NULL;
}

/* Snapshot the registered interface for the /proc/net/{dev,route} generators (which live
 * in src/proc/lxp_procfs.c). Any out param may be NULL. Returns 0, or -1 if no interface. */
int lxp_sock_ifsnapshot(uint8_t ip[4], uint8_t gw[4], uint8_t nm[4], uint8_t mac[6],
			unsigned *flags)
{
	if (!g_lnx_netif)
		return -1;
	lxp_sockaddr_t sip = {0}, sgw = {0}, snm = {0};
	g_lxp_net_ops->netif_get_addr(g_lnx_netif, &sip, &sgw, &snm);
	if (ip)
		memcpy(ip, sip.addr, 4);
	if (gw)
		memcpy(gw, sgw.addr, 4);
	if (nm)
		memcpy(nm, snm.addr, 4);
	if (mac)
		g_lxp_net_ops->netif_get_hwaddr(g_lnx_netif, mac);
	if (flags) {
		unsigned f = 0;
		g_lxp_net_ops->netif_get_flags(g_lnx_netif, &f);
		*flags = f;
	}
	return 0;
}

/* Map the provider's LXP_NETIF_FLAG_* bitmask to the guest's IFF_* value. */
static int16_t iff_from_provider(unsigned f)
{
	int16_t v = 0;
	if (f & LXP_NETIF_FLAG_UP)
		v |= LXP_IFF_UP;
	if (f & LXP_NETIF_FLAG_BROADCAST)
		v |= LXP_IFF_BROADCAST;
	if (f & LXP_NETIF_FLAG_LOOPBACK)
		v |= LXP_IFF_LOOPBACK;
	if (f & LXP_NETIF_FLAG_RUNNING)
		v |= LXP_IFF_RUNNING;
	if (f & LXP_NETIF_FLAG_MULTICAST)
		v |= LXP_IFF_MULTICAST;
	return v;
}

/* SIOCGIFCONF: report the single interface (eth0) into the caller's ifreq[]. */
static long sock_ifconf(lxp_proc_t *p, unsigned long arg)
{
	lxp_ifconf ifc;
	if (lxp_copy_from_guest(p, &ifc, (uintptr_t)arg, sizeof(ifc)) != 0)
		return -LXP_EFAULT;
	if (!ifc.ifc_buf || ifc.ifc_len < (int)sizeof(lxp_ifreq)) {
		ifc.ifc_len = sizeof(lxp_ifreq); /* the space one interface needs */
		return lxp_copy_to_guest(p, (uintptr_t)arg, &ifc, sizeof(ifc));
	}
	lxp_ifreq request;
	memset(&request, 0, sizeof(request));
	request.ifr_name[0] = 'e';
	request.ifr_name[1] = 't';
	request.ifr_name[2] = 'h';
	request.ifr_name[3] = '0';
	lxp_sockaddr_t ip = {0};
	if (g_lnx_netif && g_lxp_net_ops->netif_get_addr(g_lnx_netif, &ip, NULL, NULL) == LXP_OK) {
		request.ifr_ifru.ifru_addr.sin_family = LXP_AF_INET;
		memcpy(&request.ifr_ifru.ifru_addr.sin_addr, ip.addr, 4);
	}
	if (lxp_copy_to_guest(p, (uintptr_t)ifc.ifc_buf, &request, sizeof(request)) != 0)
		return -LXP_EFAULT;
	ifc.ifc_len = sizeof(lxp_ifreq);
	return lxp_copy_to_guest(p, (uintptr_t)arg, &ifc, sizeof(ifc));
}

/* SIOCADDRT / SIOCDELRT: the only route op we honour is setting/clearing the default
 * gateway (rt_dst == 0.0.0.0). Others are accepted as a no-op so `route` doesn't error. */
static long sock_route(lxp_proc_t *p, unsigned long req, unsigned long arg)
{
	lxp_rtentry route;
	if (lxp_copy_from_guest(p, &route, (uintptr_t)arg, sizeof(route)) != 0)
		return -LXP_EFAULT;
	if (!g_lnx_netif)
		return -LXP_ENODEV;
	int is_default = (route.rt_dst.sin_addr == 0);
	if (is_default && (route.rt_flags & LXP_RTF_GATEWAY)) {
		lxp_sockaddr_t gw = {0};
		gw.family = LXP_AF_INET;
		if (req == LXP_SIOCADDRT)
			memcpy(gw.addr, &route.rt_gateway.sin_addr, 4); /* set gw */
		/* SIOCDELRT leaves gw all-zero (clears it). */
		int r = g_lxp_net_ops->netif_set_addr(g_lnx_netif, NULL, NULL, &gw);
		return r == LXP_OK ? 0 : net_errno_to_lnx(r);
	}
	return 0; /* non-default routes: accept, nothing to program on a one-hop link */
}

long lxp_sock_ioctl(lxp_proc_t *p, unsigned long req, unsigned long arg)
{
	if (req == LXP_SIOCGIFCONF)
		return sock_ifconf(p, arg);
	if (req == LXP_SIOCADDRT || req == LXP_SIOCDELRT)
		return sock_route(p, req, arg);

	/* All the SIOC*IF* ops take a struct ifreq*. */
	lxp_ifreq request;
	if (lxp_copy_from_guest(p, &request, (uintptr_t)arg, sizeof(request)) != 0)
		return -LXP_EFAULT;
	lxp_netif_t nif = g_lnx_netif;
	if (!nif)
		return -LXP_ENODEV;
	int copy_out = 0;
	long result = 0;

	switch (req) {
	case LXP_SIOCGIFFLAGS: {
		unsigned f = 0;
		g_lxp_net_ops->netif_get_flags(nif, &f);
		request.ifr_ifru.ifru_flags = iff_from_provider(f);
		copy_out = 1;
		break;
	}
	case LXP_SIOCSIFFLAGS:
		result = g_lxp_net_ops->netif_set_up(
				 nif, (request.ifr_ifru.ifru_flags & LXP_IFF_UP) ? 1 : 0) == LXP_OK
				 ? 0
				 : -LXP_EINVAL;
		break;
	case LXP_SIOCGIFADDR:
	case LXP_SIOCGIFNETMASK:
	case LXP_SIOCGIFBRDADDR: {
		lxp_sockaddr_t ip = {0}, gw = {0}, nm = {0};
		if (g_lxp_net_ops->netif_get_addr(nif, &ip, &gw, &nm) != LXP_OK)
			return -LXP_ENODEV;
		lxp_sockaddr_in *out = &request.ifr_ifru.ifru_addr;
		memset(out, 0, sizeof(*out));
		out->sin_family = LXP_AF_INET;
		if (req == LXP_SIOCGIFNETMASK) {
			memcpy(&out->sin_addr, nm.addr, 4);
		} else if (req == LXP_SIOCGIFBRDADDR) {
			uint8_t *b = (uint8_t *)&out->sin_addr;
			for (int i = 0; i < 4; i++)
				b[i] = (uint8_t)(ip.addr[i] | (uint8_t)~nm.addr[i]);
		} else {
			memcpy(&out->sin_addr, ip.addr, 4);
		}
		copy_out = 1;
		break;
	}
	case LXP_SIOCSIFADDR:
	case LXP_SIOCSIFNETMASK: {
		lxp_sockaddr_in *in = &request.ifr_ifru.ifru_addr;
		if (in->sin_family != LXP_AF_INET)
			return -LXP_EINVAL;
		lxp_sockaddr_t sa = {0};
		sa.family = LXP_AF_INET;
		memcpy(sa.addr, &in->sin_addr, 4);
		int r = (req == LXP_SIOCSIFADDR)
				? g_lxp_net_ops->netif_set_addr(nif, &sa, NULL, NULL)
				: g_lxp_net_ops->netif_set_addr(nif, NULL, &sa, NULL);
		result = r == LXP_OK ? 0 : net_errno_to_lnx(r);
		break;
	}
	case LXP_SIOCGIFHWADDR: {
		uint8_t mac[6] = {0};
		g_lxp_net_ops->netif_get_hwaddr(nif, mac);
		/* ifr_hwaddr is a struct sockaddr: sa_family (ARPHRD_ETHER) then the 6-byte MAC. */
		memset(request.ifr_ifru.ifru_raw, 0, sizeof(request.ifr_ifru.ifru_raw));
		request.ifr_ifru.ifru_raw[0] = (uint8_t)LXP_ARPHRD_ETHER;
		memcpy(request.ifr_ifru.ifru_raw + 2, mac, 6);
		copy_out = 1;
		break;
	}
	case LXP_SIOCGIFINDEX:
		request.ifr_ifru.ifru_ivalue = 1;
		copy_out = 1;
		break;
	case LXP_SIOCGIFMTU:
		request.ifr_ifru.ifru_ivalue = 1500;
		copy_out = 1;
		break;
	default:
		return -LXP_EOPNOTSUPP;
	}
	if (result != 0 || !copy_out)
		return result;
	return lxp_copy_to_guest(p, (uintptr_t)arg, &request, sizeof(request));
}

/* ---- coordinator: retry a parked socket op --------------------------------- */

long lxp_sock_retry(lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_SOCKET)
		return -LXP_EINVAL;
	/* A parked poll() waits on a whole fd set, not one open; the syscall TU owns the
	 * fd table + per-kind readiness probes, so re-scan there. */
	if (p->wait.op == LXP_SOCKW_POLL)
		return lxp_poll_retry(p);

	struct sock_open *o = open_slot(p->wait.data.socket.object);
	if (!o)
		return -LXP_EBADF;
	switch (p->wait.op) {
	case LXP_SOCKW_CONNECT: {
		unsigned rev = 0;
		g_lxp_net_ops->sock_poll(o->sock, LXP_SOCK_POLLOUT, &rev, 0);
		if (!(rev & (LXP_SOCK_POLLOUT | LXP_SOCK_POLLERR | LXP_SOCK_POLLHUP)))
			return -LXP_EAGAIN; /* still connecting */
		int se = g_lxp_net_ops->sock_get_error(o->sock);
		o->connecting = 0;
		return se == LXP_OK ? 0 : net_errno_to_lnx(se);
	}
	case LXP_SOCKW_SEND: {
		size_t sent = 0;
		int r = g_lxp_net_ops->sock_send(o->sock, (const void *)p->wait.data.socket.buffer,
						 p->wait.data.socket.length, &sent);
		if (r == LXP_OK)
			return (long)sent;
		if (r == LXP_ERR_TIMEOUT)
			return -LXP_EAGAIN;
		return net_errno_to_lnx(r);
	}
	case LXP_SOCKW_RECV: {
		size_t got = 0;
		lxp_sockaddr_t src;
		int r;
		if (o->rx_src)
			r = g_lxp_net_ops->sock_recvfrom(o->sock,
							 (void *)p->wait.data.socket.buffer,
							 p->wait.data.socket.length, &got, &src,
							 LXP_WAIT_FOREVER);
		else
			r = g_lxp_net_ops->sock_recv(o->sock, (void *)p->wait.data.socket.buffer,
						     p->wait.data.socket.length, &got,
						     LXP_WAIT_FOREVER);
		if (r == LXP_OK) {
			if (o->rx_src)
				(void)copy_sockaddr_out(p, (void *)o->rx_src, (void *)o->rx_srclen,
							&src);
			return (long)got;
		}
		if (r == LXP_ERR_NET_CLOSED)
			return 0;
		if (r == LXP_ERR_TIMEOUT)
			return -LXP_EAGAIN;
		return net_errno_to_lnx(r);
	}
	case LXP_SOCKW_ACCEPT:
		/* Re-run the mint: a new fd when a client is now pending, -EAGAIN to stay
		 * parked, or a negative errno. The wait payload holds the user addr/len. */
		return do_accept(p, o, (void *)p->wait.data.socket.buffer,
				 (void *)(uintptr_t)p->wait.data.socket.length, 0);
	default:
		return -LXP_EINVAL;
	}
}

/* ---- FD_SOCKET file operations ---- */
static long fop_read_socket(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	return lxp_sock_recv(p, s->file_idx, buf, len, 0, NULL, NULL);
}

static long fop_write_socket(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	return lxp_sock_send(p, s->file_idx, buf, len, 0, NULL, 0);
}

static long fop_fstat_socket(lxp_proc_t *p, lxp_ofd_t *s, void *statbuf)
{
	(void)p;
	uint32_t mode;
	uint64_t size;
	lxp_sock_fstat(s->file_idx, &mode, &size);
	lxp_fill_kstat64(statbuf, 0x400000u + (uint32_t)s->file_idx, mode, size);
	return 0;
}

static void fop_close_socket(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_sock_close(s->file_idx); /* close the backing socket owned by this OFD */
}

static long fop_ioctl_socket(lxp_proc_t *p, lxp_ofd_t *s, unsigned long cmd, unsigned long arg)
{
	(void)s;
	return lxp_sock_ioctl(p, cmd, arg); /* SIOC* interface config (ifconfig/route) */
}

static unsigned fop_poll_socket(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	return (unsigned)lxp_sock_poll(s->file_idx);
}

const lxp_file_ops_t lxp_socket_fops = {
	.read = fop_read_socket,
	.write = fop_write_socket,
	.fstat = fop_fstat_socket,
	.close = fop_close_socket,
	.ioctl = fop_ioctl_socket,
	.poll = fop_poll_socket,
};

#endif /* LXP_ENABLE_NET */
