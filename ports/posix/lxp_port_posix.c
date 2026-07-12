/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * A reference POSIX host port: the module's network port (lxp_net_ops_t) implemented
 * over real BSD sockets, plus a synthetic netif for the SIOC* ioctls, published as
 * g_lxp_net_ops. This is what -DLXP_PORT_POSIX builds and what the host net/netfs
 * unit tests link. It does NOT run an ARM guest — the process model is exercised on
 * target (ports/qemu-mps2). The clock + cache hooks live in the test stub.
 */
#include "lxp/lxp_net_ops.h"
#include "lxp/lxp_port.h"
#include "lxp/lxp_types.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- socket handle pool (lxp_socket_t is an opaque host handle) ------------- */
struct lxp_socket {
	int fd;
	uint8_t used;
};
static struct lxp_socket g_pool[LXP_NSOCK + 4];

static struct lxp_socket *pool_alloc(int fd)
{
	for (unsigned i = 0; i < sizeof(g_pool) / sizeof(g_pool[0]); i++)
		if (!g_pool[i].used) {
			g_pool[i].fd = fd;
			g_pool[i].used = 1;
			return &g_pool[i];
		}
	return NULL;
}

/* ---- POSIX errno -> lxp_err_t (lxp_net.c maps lxp_err_t -> guest errno) ----- */
static int to_lxp_err(int e)
{
	switch (e) {
	case 0:
		return LXP_OK;
	case ECONNREFUSED:
		return LXP_ERR_NET_REFUSED;
	case ENETUNREACH:
	case EHOSTUNREACH:
		return LXP_ERR_NET_UNREACHABLE;
	case EADDRINUSE:
		return LXP_ERR_NET_ADDR_IN_USE;
	case ECONNRESET:
		return LXP_ERR_NET_RESET;
	case EPIPE:
		return LXP_ERR_NET_CLOSED;
	case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
	case EINPROGRESS:
		return LXP_ERR_TIMEOUT; /* the module's "would block" signal */
	case EINVAL:
		return LXP_ERR_INVALID_PARAM;
	case ENOMEM:
	case ENOBUFS:
		return LXP_ERR_NO_MEMORY;
	default:
		return LXP_ERR_NOT_SUPPORTED;
	}
}

/* ---- sockaddr conversion (lxp_sockaddr_t: port host-order, addr[] net-order) */
static void to_sin(const lxp_sockaddr_t *a, struct sockaddr_in *sin)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(a->port);
	memcpy(&sin->sin_addr, a->addr, 4);
}
static void from_sin(const struct sockaddr_in *sin, lxp_sockaddr_t *a)
{
	memset(a, 0, sizeof(*a));
	a->family = LXP_AF_INET;
	a->port = ntohs(sin->sin_port);
	memcpy(a->addr, &sin->sin_addr, 4);
}

/* ---- the 16 socket ops ----------------------------------------------------- */
static int p_open(lxp_af_t af, lxp_sock_type_t type, int proto, lxp_socket_t *out)
{
	(void)af;
	int st = (type == LXP_SOCK_DGRAM) ? SOCK_DGRAM : (type == LXP_SOCK_RAW) ? SOCK_RAW
										: SOCK_STREAM;
	int fd = socket(AF_INET, st, proto);
	if (fd < 0)
		return to_lxp_err(errno);
	struct lxp_socket *s = pool_alloc(fd);
	if (!s) {
		close(fd);
		return LXP_ERR_NO_MEMORY;
	}
	*out = s;
	return LXP_OK;
}
static void p_close(lxp_socket_t s)
{
	if (s) {
		close(s->fd);
		s->used = 0;
		s->fd = -1;
	}
}
static int p_connect(lxp_socket_t s, const lxp_sockaddr_t *a, uint64_t to)
{
	(void)to;
	struct sockaddr_in sin;
	to_sin(a, &sin);
	if (connect(s->fd, (struct sockaddr *)&sin, sizeof(sin)) == 0)
		return LXP_OK;
	return to_lxp_err(errno);
}
static int p_bind(lxp_socket_t s, const lxp_sockaddr_t *a)
{
	struct sockaddr_in sin;
	to_sin(a, &sin);
	return bind(s->fd, (struct sockaddr *)&sin, sizeof(sin)) == 0 ? LXP_OK : to_lxp_err(errno);
}
static int p_listen(lxp_socket_t s, int backlog)
{
	return listen(s->fd, backlog) == 0 ? LXP_OK : to_lxp_err(errno);
}
static int p_accept(lxp_socket_t listener, lxp_socket_t *out, uint64_t to)
{
	(void)to;
	int fd = accept(listener->fd, NULL, NULL);
	if (fd < 0)
		return to_lxp_err(errno);
	struct lxp_socket *s = pool_alloc(fd);
	if (!s) {
		close(fd);
		return LXP_ERR_NO_MEMORY;
	}
	*out = s;
	return LXP_OK;
}
static int p_send(lxp_socket_t s, const void *d, size_t n, size_t *sent)
{
	ssize_t r = send(s->fd, d, n, MSG_NOSIGNAL);
	if (r < 0)
		return to_lxp_err(errno);
	if (sent)
		*sent = (size_t)r;
	return LXP_OK;
}
static int p_recv(lxp_socket_t s, void *b, size_t n, size_t *got, uint64_t to)
{
	(void)to;
	ssize_t r = recv(s->fd, b, n, 0);
	if (r < 0)
		return to_lxp_err(errno);
	if (got)
		*got = (size_t)r; /* 0 => peer closed (EOF), reported as a 0-length recv */
	return LXP_OK;
}
static int p_sendto(lxp_socket_t s, const void *d, size_t n, size_t *sent,
		    const lxp_sockaddr_t *dst)
{
	struct sockaddr_in sin;
	to_sin(dst, &sin);
	ssize_t r = sendto(s->fd, d, n, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(sin));
	if (r < 0)
		return to_lxp_err(errno);
	if (sent)
		*sent = (size_t)r;
	return LXP_OK;
}
static int p_recvfrom(lxp_socket_t s, void *b, size_t n, size_t *got, lxp_sockaddr_t *src,
		      uint64_t to)
{
	(void)to;
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	ssize_t r = recvfrom(s->fd, b, n, 0, (struct sockaddr *)&sin, &sl);
	if (r < 0)
		return to_lxp_err(errno);
	if (got)
		*got = (size_t)r;
	if (src)
		from_sin(&sin, src);
	return LXP_OK;
}
static int p_set_nonblock(lxp_socket_t s, int nb)
{
	int fl = fcntl(s->fd, F_GETFL, 0);
	if (fl < 0)
		return to_lxp_err(errno);
	fl = nb ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK);
	return fcntl(s->fd, F_SETFL, fl) == 0 ? LXP_OK : to_lxp_err(errno);
}
static int p_poll(lxp_socket_t s, unsigned events, unsigned *revents, uint64_t timeout_ns)
{
	struct pollfd pfd = {.fd = s->fd, .events = 0, .revents = 0};
	if (events & LXP_SOCK_POLLIN)
		pfd.events |= POLLIN;
	if (events & LXP_SOCK_POLLOUT)
		pfd.events |= POLLOUT;
	int r = poll(&pfd, 1, timeout_ns ? (int)(timeout_ns / 1000000ull) : 0);
	if (r < 0)
		return to_lxp_err(errno);
	unsigned rv = 0;
	if (pfd.revents & POLLIN)
		rv |= LXP_SOCK_POLLIN;
	if (pfd.revents & POLLOUT)
		rv |= LXP_SOCK_POLLOUT;
	if (revents)
		*revents = rv;
	return LXP_OK;
}
static int p_shutdown(lxp_socket_t s, int how)
{
	return shutdown(s->fd, how) == 0 ? LXP_OK : to_lxp_err(errno);
}
static int p_getsockname(lxp_socket_t s, lxp_sockaddr_t *a)
{
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	if (getsockname(s->fd, (struct sockaddr *)&sin, &sl) != 0)
		return to_lxp_err(errno);
	from_sin(&sin, a);
	return LXP_OK;
}
static int p_getpeername(lxp_socket_t s, lxp_sockaddr_t *a)
{
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	if (getpeername(s->fd, (struct sockaddr *)&sin, &sl) != 0)
		return to_lxp_err(errno);
	from_sin(&sin, a);
	return LXP_OK;
}
static int p_get_error(lxp_socket_t s)
{
	int e = 0;
	socklen_t sl = sizeof(e);
	if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &e, &sl) != 0)
		return to_lxp_err(errno);
	return to_lxp_err(e);
}

/* ---- synthetic netif (eth0 the SIOC* ioctls act on) ------------------------ */
struct lxp_netif {
	uint8_t ip[4], nm[4], gw[4];
	int up;
};
static struct lxp_netif g_posix_netif = {.ip = {127, 0, 0, 1}, .nm = {255, 0, 0, 0}, .up = 1};

/* Handle a host test passes to lxp_sock_set_netif() before the SIOC* ioctls. */
lxp_netif_t lxp_posix_netif(void)
{
	return &g_posix_netif;
}

static int nif_get_addr(lxp_netif_t nif, lxp_sockaddr_t *ip, lxp_sockaddr_t *gw, lxp_sockaddr_t *nm)
{
	struct lxp_netif *n = (struct lxp_netif *)nif;
	if (ip) {
		memset(ip, 0, sizeof(*ip));
		ip->family = LXP_AF_INET;
		memcpy(ip->addr, n->ip, 4);
	}
	if (gw) {
		memset(gw, 0, sizeof(*gw));
		gw->family = LXP_AF_INET;
		memcpy(gw->addr, n->gw, 4);
	}
	if (nm) {
		memset(nm, 0, sizeof(*nm));
		nm->family = LXP_AF_INET;
		memcpy(nm->addr, n->nm, 4);
	}
	return LXP_OK;
}
static int nif_get_hwaddr(lxp_netif_t nif, uint8_t mac[6])
{
	(void)nif;
	static const uint8_t m[6] = {0x02, 0x00, 0x00, 0xDE, 0xAD, 0x01};
	memcpy(mac, m, 6);
	return LXP_OK;
}
static int nif_get_flags(lxp_netif_t nif, unsigned *flags)
{
	struct lxp_netif *n = (struct lxp_netif *)nif;
	/* Port-side flag format (lxp_net.c's iff_from_ove maps these to the guest IFF_*). */
	unsigned f = LXP_NETIF_FLAG_BROADCAST | LXP_NETIF_FLAG_MULTICAST;
	if (n->up)
		f |= LXP_NETIF_FLAG_UP | LXP_NETIF_FLAG_RUNNING;
	if (flags)
		*flags = f;
	return LXP_OK;
}
static int nif_set_addr(lxp_netif_t nif, const lxp_sockaddr_t *ip, const lxp_sockaddr_t *nm,
			const lxp_sockaddr_t *gw)
{
	struct lxp_netif *n = (struct lxp_netif *)nif;
	if (ip)
		memcpy(n->ip, ip->addr, 4);
	if (nm)
		memcpy(n->nm, nm->addr, 4);
	if (gw)
		memcpy(n->gw, gw->addr, 4);
	return LXP_OK; /* host owns addressing; accept + record */
}
static int nif_set_up(lxp_netif_t nif, int up)
{
	((struct lxp_netif *)nif)->up = up;
	return LXP_OK;
}

/* ---- the net-ops vtable, published to the module --------------------------- */
static const lxp_net_ops_t g_posix_net_ops = {
	.sock_open = p_open,
	.sock_accept = p_accept,
	.sock_close = p_close,
	.sock_connect = p_connect,
	.sock_bind = p_bind,
	.sock_listen = p_listen,
	.sock_send = p_send,
	.sock_recv = p_recv,
	.sock_sendto = p_sendto,
	.sock_recvfrom = p_recvfrom,
	.sock_set_nonblock = p_set_nonblock,
	.sock_poll = p_poll,
	.sock_shutdown = p_shutdown,
	.sock_getsockname = p_getsockname,
	.sock_getpeername = p_getpeername,
	.sock_get_error = p_get_error,
	.netif_get_addr = nif_get_addr,
	.netif_get_hwaddr = nif_get_hwaddr,
	.netif_get_flags = nif_get_flags,
	.netif_set_addr = nif_set_addr,
	.netif_set_up = nif_set_up,
	.netif = &g_posix_netif,
};
const struct lxp_net_ops *g_lxp_net_ops = &g_posix_net_ops;
