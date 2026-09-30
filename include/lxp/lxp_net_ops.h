/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The handle-based network port for the Linux personality. The personality's
 * socket + remote-fs cores reach the host TCP/IP stack only through these ops:
 * the host owns socket storage and returns an opaque lxp_socket_t handle, so
 * the personality never embeds a backend-sized socket by value. Each host
 * supplies an adapter over its own stack and owns the backing storage pool.
 */

#ifndef LXP_NET_OPS_H
#define LXP_NET_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Host-owned opaque handles: the module holds these, while the provider owns
 * their backing storage. */
typedef struct lxp_socket *lxp_socket_t;
typedef struct lxp_netif *lxp_netif_t;

typedef uint8_t lxp_af_t;
#define LXP_AF_INET ((lxp_af_t)2)
#define LXP_AF_INET6 ((lxp_af_t)10)

typedef uint8_t lxp_sock_type_t;
#define LXP_SOCK_STREAM ((lxp_sock_type_t)1)
#define LXP_SOCK_DGRAM ((lxp_sock_type_t)2)
#define LXP_SOCK_RAW ((lxp_sock_type_t)3)

typedef struct {
	lxp_af_t family;  /**< LXP_AF_INET / LXP_AF_INET6. */
	uint16_t port;	  /**< Host byte order. */
	uint8_t addr[16]; /**< 4 bytes IPv4, 16 IPv6. */
} lxp_sockaddr_t;

#define LXP_SOCK_POLLIN 0x01u
#define LXP_SOCK_POLLOUT 0x04u
#define LXP_SOCK_POLLERR 0x08u
#define LXP_SOCK_POLLHUP 0x10u

#define LXP_SHUT_RD 0
#define LXP_SHUT_WR 1
#define LXP_SHUT_RDWR 2

#define LXP_NETIF_FLAG_UP 0x01u
#define LXP_NETIF_FLAG_BROADCAST 0x02u
#define LXP_NETIF_FLAG_LOOPBACK 0x04u
#define LXP_NETIF_FLAG_RUNNING 0x08u
#define LXP_NETIF_FLAG_MULTICAST 0x10u

/*
 * A provider advertising this capability invokes the run-scoped readiness
 * callback whenever network activity may change socket readiness. This lets
 * the coordinator sleep on its event instead of polling parked
 * recv/connect/accept/poll operations every 5 ms.
 */
#define LXP_NET_CAP_SOCKET_READY_EVENT 0x01u

typedef void (*lxp_net_ready_fn)(const void *context);

/* Handle-based network port. All socket calls run on the serialized
 * coordinator thread, so a provider does not need internal locking. A
 * readiness callback may run in the provider's native network context. */
typedef struct lxp_net_ops {
	/** Acquire/release the provider's run-scoped socket storage. A provider
	 * advertising LXP_NET_CAP_SOCKET_READY_EVENT retains ready/context only
	 * between a successful run_begin() and the matching run_end(), and stops
	 * invoking ready before run_end() returns. Other providers may ignore them.
	 * run_begin() must leave prior state unchanged on failure; run_end() closes
	 * any provider handles still owned after core teardown. */
	int (*run_begin)(lxp_net_ready_fn ready, const void *context);
	void (*run_end)(void);

	int (*sock_open)(lxp_af_t af, lxp_sock_type_t type, int proto, lxp_socket_t *out);
	int (*sock_accept)(lxp_socket_t listener, lxp_socket_t *out, uint64_t timeout_ns);
	void (*sock_close)(lxp_socket_t s);
	int (*sock_connect)(lxp_socket_t s, const lxp_sockaddr_t *a, uint64_t timeout_ns);
	int (*sock_bind)(lxp_socket_t s, const lxp_sockaddr_t *a);
	int (*sock_listen)(lxp_socket_t s, int backlog);
	int (*sock_send)(lxp_socket_t s, const void *d, size_t n, size_t *sent);
	int (*sock_recv)(lxp_socket_t s, void *b, size_t n, size_t *got, uint64_t timeout_ns);
	int (*sock_sendto)(lxp_socket_t s, const void *d, size_t n, size_t *sent,
			   const lxp_sockaddr_t *dst);
	int (*sock_recvfrom)(lxp_socket_t s, void *b, size_t n, size_t *got, lxp_sockaddr_t *src,
			     uint64_t timeout_ns);
	/* Every socket handed to LXP must accept nonblocking mode. LXP publishes
	 * neither a newly opened nor accepted socket until this call succeeds. */
	int (*sock_set_nonblock)(lxp_socket_t s, int nb);
	int (*sock_poll)(lxp_socket_t s, unsigned events, unsigned *revents, uint64_t timeout_ns);
	int (*sock_shutdown)(lxp_socket_t s, int how);
	int (*sock_getsockname)(lxp_socket_t s, lxp_sockaddr_t *a);
	int (*sock_getpeername)(lxp_socket_t s, lxp_sockaddr_t *a);
	int (*sock_get_error)(lxp_socket_t s);

	int (*netif_get_addr)(lxp_netif_t nif, lxp_sockaddr_t *ip, lxp_sockaddr_t *gw,
			      lxp_sockaddr_t *nm);
	int (*netif_get_hwaddr)(lxp_netif_t nif, uint8_t mac[6]);
	int (*netif_get_flags)(lxp_netif_t nif, unsigned *flags);
	int (*netif_set_addr)(lxp_netif_t nif, const lxp_sockaddr_t *ip, const lxp_sockaddr_t *nm,
			      const lxp_sockaddr_t *gw);
	int (*netif_set_up)(lxp_netif_t nif, int up);

	/* LXP_NET_CAP_* bits. Kept last so older designated initializers default to
	 * the polling fallback without moving existing members. */
	unsigned capabilities;
} lxp_net_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* LXP_NET_OPS_H */
