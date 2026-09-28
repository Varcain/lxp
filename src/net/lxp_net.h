/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_NET_H
#define LXP_NET_H

/**
 * @file net.h
 * @defgroup lxp_linux_net Linux personality socket layer
 * @ingroup lxp_linux
 * @brief BSD sockets for the Linux personality, backed by a host network provider.
 *
 * The socket-family syscalls (socket/connect/send/recv/...) of a loaded FDPIC
 * program are routed to a small in-kernel socket model that uses the
 * handle-based @c lxp_net_ops_t contract. It mirrors
 * the /dev device layer (@ref lxp_linux_dev): a refcounted per-open pool, and a
 * park/retry deferral for blocking I/O.
 *
 * Blocking model: socket entry points run on the privileged coordinator thread
 * and must remain bounded. Every backing provider socket is non-blocking, so an
 * operation returns promptly; a would-block (@c LXP_ERR_TIMEOUT) publishes
 * @c LXP_WAIT_SOCKET and the coordinator retries after readiness notification
 * — the same park/retry the pipe and device layers use.
 *
 * @note Requires @c LXP_ENABLE_NET.
 * @{
 */

#include <stddef.h>
#include <stdint.h>

#include "lxp_guest.h"
#include "lxp/lxp_net_ops.h"
#include "proc/lxp_proc_fwd.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Socket-wait op codes stored in @c proc->wait.op.
 *  Shared with the run loop (src/lxp_run.c). */
#define LXP_SOCKW_CONNECT 1u
#define LXP_SOCKW_SEND 2u
#define LXP_SOCKW_RECV 3u
#define LXP_SOCKW_ACCEPT 4u /**< A blocked accept(2). */
#define LXP_SOCKW_POLL 5u   /**< A blocking poll(2)/select over a set that includes a socket. */

/* Guest socket ABI. LXP_AF_* and LXP_SOCK_STREAM/DGRAM/RAW are the provider
 * types from lxp_net_ops.h (identical Linux values); these bits are guest-only. */
#define LXP_SOCK_NONBLOCK 0x800	 /**< ORed into the type arg. */
#define LXP_SOCK_CLOEXEC 0x80000 /**< ORed into the type arg (ignored: no exec close). */
#define LXP_SOCK_TYPE_MASK 0xff	 /**< Base type after masking the flag bits. */
#define LXP_IPPROTO_ICMP 1
#define LXP_IPPROTO_TCP 6
#define LXP_IPPROTO_UDP 17
#define LXP_SOL_SOCKET 1
#define LXP_SO_ERROR 4
#define LXP_MSG_DONTWAIT 0x40 /**< Per-call non-blocking hint for send/recv. */

/** @c struct sockaddr_in (Linux/ARM, 16 bytes). @c sin_port / @c sin_addr are
 *  in network byte order. */
typedef struct lxp_sockaddr_in {
	uint16_t sin_family;
	uint16_t sin_port;
	uint32_t sin_addr;
	uint8_t sin_zero[8];
} lxp_sockaddr_in;

/* ---- interface configuration ioctls (ifconfig/route) --------------------- */
#define LXP_SIOCADDRT 0x890b	  /* add a routing table entry */
#define LXP_SIOCDELRT 0x890c	  /* delete a routing table entry */
#define LXP_SIOCGIFCONF 0x8912	  /* list interfaces */
#define LXP_SIOCGIFFLAGS 0x8913	  /* get flags */
#define LXP_SIOCSIFFLAGS 0x8914	  /* set flags (up/down) */
#define LXP_SIOCGIFADDR 0x8915	  /* get IPv4 address */
#define LXP_SIOCSIFADDR 0x8916	  /* set IPv4 address */
#define LXP_SIOCGIFBRDADDR 0x8919 /* get broadcast address */
#define LXP_SIOCGIFNETMASK 0x891b /* get netmask */
#define LXP_SIOCSIFNETMASK 0x891c /* set netmask */
#define LXP_SIOCGIFMTU 0x8921	  /* get MTU */
#define LXP_SIOCGIFHWADDR 0x8927  /* get MAC */
#define LXP_SIOCGIFINDEX 0x8933	  /* get interface index */

/* Linux interface flags (SIOC[GS]IFFLAGS ifr_flags). */
#define LXP_IFF_UP 0x1
#define LXP_IFF_BROADCAST 0x2
#define LXP_IFF_LOOPBACK 0x8
#define LXP_IFF_POINTOPOINT 0x10
#define LXP_IFF_RUNNING 0x40
#define LXP_IFF_MULTICAST 0x1000

#define LXP_ARPHRD_ETHER 1 /* ifr_hwaddr.sa_family for an ethernet MAC */
#define LXP_IFNAMSIZ 16

/** @c struct ifreq (Linux/ARM32): a 16-byte name + a 16-byte union (== 32 bytes). */
typedef struct lxp_ifreq {
	char ifr_name[LXP_IFNAMSIZ];
	union {
		lxp_sockaddr_in ifru_addr; /* SIOC[GS]IF{ADDR,NETMASK,BRDADDR} */
		int16_t ifru_flags;	   /* SIOC[GS]IFFLAGS */
		int32_t ifru_ivalue;	   /* SIOCGIFINDEX / SIOCGIFMTU */
		uint8_t ifru_raw[16];	   /* SIOCGIFHWADDR: sockaddr{sa_family, sa_data[14]} */
	} ifr_ifru;
} lxp_ifreq;

/** @c struct ifconf (Linux/ARM32) for SIOCGIFCONF: len + a user pointer to ifreq[]. */
typedef struct lxp_ifconf {
	int32_t ifc_len;  /* buffer size in bytes (in), used bytes (out) */
	uint32_t ifc_buf; /* user pointer to a struct ifreq array */
} lxp_ifconf;

#define LXP_RTF_UP 0x0001
#define LXP_RTF_GATEWAY 0x0002

/** @c struct rtentry prefix (Linux/ARM32) for SIOC[AD]DRT — only the leading fields
 *  needed to read a default route's gateway; trailing rt_dev/rt_mtu/... are ignored. */
typedef struct lxp_rtentry {
	uint32_t rt_pad1;
	lxp_sockaddr_in rt_dst;
	lxp_sockaddr_in rt_gateway;
	lxp_sockaddr_in rt_genmask;
	uint16_t rt_flags;
} lxp_rtentry;

/* ---- syscall-layer <-> socket-core interface (called from lxp_syscall.c) ---- */
/* Compiled only when LXP_ENABLE_NET is set (the FD_SOCKET branches are #if'd),
 * so no weak fallbacks are needed — the core is always linked when the feature is on
 * (firmware) or under test (host cmocka). */

/** socket(2): allocate a socket open slot + open the backing provider socket.
 *  @return the open-pool index (the fd's file_idx) or a negative Linux errno. */
long lxp_sock_new(int domain, int type, int protocol);
/** Drop a reference on open @p oi (close/exit); close the provider handle at the last. */
void lxp_sock_close(int oi);
/** fcntl F_SETFL / F_GETFL: the open's status flags (O_NONBLOCK gates parking). */
void lxp_sock_setfl(int oi, int flags);
int lxp_sock_getfl(int oi);

/** connect(2). @p uaddr / @p addrlen are the guest's sockaddr. Returns 0, a
 *  negative Linux errno, or parks in an @c LXP_WAIT_SOCKET state. */
long lxp_sock_connect(lxp_proc_t *p, int oi, const void *uaddr, unsigned addrlen);
/** bind(2). Binds the pool socket to the guest's sockaddr. Returns 0 or -errno. */
long lxp_sock_bind(lxp_proc_t *p, int oi, const void *uaddr, unsigned addrlen);
/** listen(2). Marks the socket passive. Returns 0 or -errno. */
long lxp_sock_listen(int oi, int backlog);
/** accept(2)/accept4(2). Mints a fresh pool slot + fd for the next connection and
 *  fills @p uaddr / @p uaddrlen (if non-NULL). Returns the new fd, a negative Linux
 *  errno, or parks in an @c LXP_WAIT_SOCKET state with @c LXP_SOCKW_ACCEPT. */
long lxp_sock_accept(lxp_proc_t *p, int oi, void *uaddr, void *uaddrlen, int flags);
/** send(2)/sendto(2). @p udest NULL => send; non-NULL => sendto. Returns bytes
 *  sent, a negative Linux errno, or parks. */
long lxp_sock_send(lxp_proc_t *p, int oi, const void *ubuf, size_t len, int flags,
		   const void *udest, unsigned destlen);
/** Whether socket @p oi is a datagram socket (SOCK_DGRAM). */
int lxp_sock_is_dgram(int oi);
/** sendmsg on a datagram socket: gather @p iov into one datagram (bounded; -EMSGSIZE if too
 *  large). @p udest NULL => send; non-NULL => sendto. Returns bytes sent, errno; never parks. */
long lxp_sock_sendmsg(lxp_proc_t *p, int oi, const lxp_iovec *iov, int iovcnt, int flags,
		      const void *udest, unsigned destlen);
/** recv(2)/recvfrom(2). @p usrc NULL => recv; non-NULL => recvfrom (fills
 *  @p usrc / @p usrclen). Returns bytes received, 0 (peer closed), errno, or parks. */
long lxp_sock_recv(lxp_proc_t *p, int oi, void *ubuf, size_t len, int flags, void *usrc,
		   void *usrclen);
long lxp_sock_shutdown(int oi, int how);
long lxp_sock_getsockname(lxp_proc_t *p, int oi, void *uaddr, void *uaddrlen);
long lxp_sock_getpeername(lxp_proc_t *p, int oi, void *uaddr, void *uaddrlen);
long lxp_sock_getsockopt(lxp_proc_t *p, int oi, int level, int optname, void *uval, void *ulen);
long lxp_sock_setsockopt(lxp_proc_t *p, int oi, int level, int optname, const void *uval,
			 unsigned len);
/** poll(2)/select: current readiness (LXP_POLLIN|LXP_POLLOUT); never blocks. */
unsigned lxp_sock_poll(int oi);
/** Fill @c S_IFSOCK mode (+ size 0) for fstat/statx of a socket fd. */
void lxp_sock_fstat(int oi, uint32_t *mode, uint64_t *size);

/* SIOC* interface-config ioctls (ifconfig/route) issued on a socket fd and
 * routed through lxp_net_ops_t. The op targets the interface, not one socket,
 * so no open index. */
long lxp_sock_ioctl(lxp_proc_t *p, unsigned long req, unsigned long arg);

/** Bind/clear the interface handle for exactly one lxp_run() lifecycle.
 * These are coordinator-owned lifecycle hooks, not application configuration. */
void lxp_sock_run_begin(lxp_netif_t netif);
void lxp_sock_run_end(void);

/* Snapshot the registered interface for the /proc/net/{dev,route} generators. Any out
 * param may be NULL. Returns 0, or -1 if no interface is registered. */
int lxp_sock_ifsnapshot(uint8_t ip[4], uint8_t gw[4], uint8_t nm[4], uint8_t mac[6],
			unsigned *flags);

/** Retry a parked socket op for the coordinator; result or -EAGAIN (still blocked). */
long lxp_sock_retry(lxp_proc_t *p);

/* Re-scan a parked poll(2)/select's fd set for readiness (called from lxp_sock_retry
 * for LXP_SOCKW_POLL). Implemented in the syscall TU, which owns the fd table + the
 * per-kind readiness probes. Returns the ready count (>0), 0 at the deadline, or -EAGAIN. */
long lxp_poll_retry(lxp_proc_t *p);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* LXP_NET_H */
