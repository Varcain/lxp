/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Linux-personality remote filesystem: a coordinator-owned 9P2000.L client over a
 * single non-blocking TCP connection to a 9P server (diod), exposed as an FD_NET
 * provider the syscall handlers route /mnt/pi opens to. It supports read-only
 * browsing and remote execution. Like net/lxp_net.c, it uses a bounded per-open
 * pool (each entry owns a 9P fid); generic open-file descriptions own fork/dup
 * aliases and the last close clunks the fid.
 *
 * Blocking is deferred, never inline: every op that needs a Pi round-trip submits a
 * 9P request, publishes an LXP_WAIT_NETFS state, and returns 0 (parked);
 * the run-loop coordinator
 * pumps the transport each pass via lxp_netfs_retry and resumes the guest. The
 * transport is serialized — one 9P message in flight, a FIFO of the rest.
 */

#include "lxp/lxp_config.h"

#if LXP_ENABLE_NETFS

#include "netfs/lxp_netfs.h"
#include "fs/lxp_dirent.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_loader.h"
#include "lxp/lxp_net_ops.h"
#include "proc/lxp_proc.h"
#include "lxp/lxp_types.h"
#include "lxp_provider.h"

#include <string.h>

/* ---- tunables -------------------------------------------------------------- */
/* These sit in scarce internal SRAM, so keep the footprint small: msize 2K (two 2K
 * transport buffers) is plenty for read-only browse (reads/readdir just page in more
 * chunks). A future optimization relocates the buffers to SDRAM for larger msize. */
#define NETFS_MSIZE 2048u	      /* negotiated max 9P message; two buffers of this. */
#define NETFS_NFID 32		      /* max concurrent 9P fids (root + opens + temp). */
#define NETFS_NOPEN 16		      /* max concurrent guest opens (pooled). */
#define NETFS_NREQ 8		      /* max in-flight+queued requests (parked procs). */
#define NETFS_NCLUNK 24		      /* pending background-clunk fid queue. */
#define NETFS_RECONNECT_US 2000000ull /* backoff between reconnect attempts. */
#define NETFS_MAXWELEM 16	      /* 9P Twalk max name components per message. */

#define P9_NOTAG 0xffffu
#define P9_NOFID 0xffffffffu
#define P9_TAG 1u /* one request in flight → a single fixed tag. */
#define P9_ROOT_FID 0u
#define P9_GETATTR_BASIC \
	0x000007ffull /* mode,nlink,uid,gid,rdev,atime,mtime,ctime,ino,size,blocks */

/* 9P2000.L message types. */
enum {
	P9_RLERROR = 7,
	P9_TLOPEN = 12,
	P9_RLOPEN = 13,
	P9_TLGETATTR = 24,
	P9_RLGETATTR = 25,
	P9_TREADDIR = 40,
	P9_RREADDIR = 41,
	P9_TVERSION = 100,
	P9_RVERSION = 101,
	P9_TATTACH = 104,
	P9_RATTACH = 105,
	P9_TWALK = 110,
	P9_RWALK = 111,
	P9_TREAD = 116,
	P9_RREAD = 117,
	P9_TCLUNK = 120,
	P9_RCLUNK = 121,
};

/* qid.type bits. */
#define P9_QTDIR 0x80u

/* ---- mount config + connection state --------------------------------------- */

static struct {
	char mp[LXP_NETFS_MOUNTPOINT_CAP]; /* mount point, e.g. "/mnt/pi" */
	size_t mplen;
	uint8_t ip[4];
	uint16_t port;
	char aname[LXP_NETFS_ANAME_CAP];
	char uname[LXP_NETFS_UNAME_CAP];
	int configured;
} g_mnt;

enum {
	CONN_DOWN = 0,
	CONN_CONNECTING,
	CONN_VERSION_SEND,
	CONN_VERSION_RECV,
	CONN_ATTACH_SEND,
	CONN_ATTACH_RECV,
	CONN_UP,
};
static lxp_socket_t g_sk; /* host-owned handle; the adapter owns the storage */
static int g_conn;
static uint32_t g_msize = NETFS_MSIZE;
static uint32_t g_generation;	    /* bumped on every (re)connect; opens carry theirs. */
static uint64_t g_reconnect_at_us;  /* next reconnect attempt (backoff). */
static uint64_t g_conn_deadline_us; /* connect or current handshake-step deadline. */

/* ---- fid allocator (bitmap; fid 0 = attached root) ------------------------- */
static uint32_t g_fid_bm[(NETFS_NFID + 31) / 32];

static int fid_alloc(void)
{
	for (int f = 1; f < NETFS_NFID; f++)
		if (!(g_fid_bm[f >> 5] & (1u << (f & 31)))) {
			g_fid_bm[f >> 5] |= (1u << (f & 31));
			return f;
		}
	return -1;
}

static void fid_free(int f)
{
	if (f > 0 && f < NETFS_NFID)
		g_fid_bm[f >> 5] &= ~(1u << (f & 31));
}

/* ---- open pool ------------------------------------------------------------- */
struct netfs_open {
	uint8_t used;
	uint8_t is_dir;
	uint8_t stale; /* fid invalidated by a reconnect → read/getdents give -ESTALE. */
	int fid;
	uint32_t generation;
	uint32_t mode; /* cached st_mode (from Rlgetattr at open). */
	uint64_t size;
	uint64_t mtime;	  /* seconds. */
	uint64_t ino;	  /* qid.path — stable + unique on the server. */
	uint64_t rd_off;  /* file read cursor (shared across dup/fork — POSIX open-file offset). */
	uint64_t dir_off; /* Treaddir resume cursor. */
};
static struct netfs_open g_open[NETFS_NOPEN];

static struct netfs_open *open_slot(int oi)
{
	if (oi < 0 || oi >= NETFS_NOPEN || !g_open[oi].used)
		return NULL;
	return &g_open[oi];
}

/* ---- background clunk queue (close never parks) ---------------------------- */
static int g_clunk_fid[NETFS_NCLUNK];
static int g_clunk_head, g_clunk_tail;

static void clunk_enqueue(int fid)
{
	int nt = (g_clunk_tail + 1) % NETFS_NCLUNK;
	if (fid <= 0)
		return;
	if (nt == g_clunk_head) {
		fid_free(fid); /* queue full: drop the fid locally (server GCs on disconnect). */
		return;
	}
	g_clunk_fid[g_clunk_tail] = fid;
	g_clunk_tail = nt;
}

/* ---- request pool ---------------------------------------------------------- */
enum { REQ_FREE = 0, REQ_QUEUED, REQ_INFLIGHT, REQ_DONE };
#define REQ_OP_CLUNK 0xffu /* internal (owner.index<0) background-clunk request. */
struct netfs_req {
	uint8_t state;
	uint8_t op; /* NETFSW_* (owner set) or REQ_OP_CLUNK (owner none). */
	uint8_t step;
	lxp_slot_ref_t owner; /* generation-qualified guest, or none for an internal request. */
	uint32_t seq;	      /* FIFO ordering. */
	int oi;		      /* open-pool slot (open reserves it; read/getdents use it). */
	int fid;	      /* working fid (walk target / temp). */
	uint64_t off;	      /* read / readdir offset. */
	uintptr_t ubuf;	      /* guest buffer (read/getdents) or stat-out. */
	size_t ulen;	      /* length / capacity. */
	int flags;	      /* open flags. */
	int statkind;
	int is64;
	char path[LXP_PATH_MAX]; /* remote path (open/stat). */
	long result;
};
static struct netfs_req g_req[NETFS_NREQ];
static uint32_t g_req_seq;
static int g_inflight = -1; /* request whose message is being sent / awaiting reply. */

#if LXP_ENABLE_NETFS_EXEC
static uint8_t *g_exec_buf; /* the engine's RAM staging buffer for a fetched remote ELF */
static size_t g_exec_cap;   /* staging capacity */
static size_t g_exec_size;  /* bytes fetched so far (the valid image size on completion) */
#endif

/* ---- TX/RX transport buffers ----------------------------------------------- */
static uint8_t g_tx[NETFS_MSIZE];
static size_t g_txlen, g_txoff; /* current outgoing message [g_txoff, g_txlen). */
static uint8_t g_rx[NETFS_MSIZE];
static size_t g_rxlen; /* accumulated bytes of the incoming reply. */

/* ---- little-endian 9P codec ------------------------------------------------ */
static void put8(size_t *o, uint8_t v)
{
	g_tx[(*o)++] = v;
}
static void put16(size_t *o, uint16_t v)
{
	put8(o, (uint8_t)v);
	put8(o, (uint8_t)(v >> 8));
}
static void put32(size_t *o, uint32_t v)
{
	put16(o, (uint16_t)v);
	put16(o, (uint16_t)(v >> 16));
}
static void put64(size_t *o, uint64_t v)
{
	put32(o, (uint32_t)v);
	put32(o, (uint32_t)(v >> 32));
}
static void putstr(size_t *o, const char *s, size_t n)
{
	put16(o, (uint16_t)n);
	memcpy(g_tx + *o, s, n);
	*o += n;
}

static uint8_t get8(const uint8_t *b, size_t *o)
{
	return b[(*o)++];
}
static uint16_t get16(const uint8_t *b, size_t *o)
{
	uint16_t v = (uint16_t)(b[*o] | (b[*o + 1] << 8));
	*o += 2;
	return v;
}
static uint32_t get32(const uint8_t *b, size_t *o)
{
	uint32_t v = get16(b, o);
	v |= (uint32_t)get16(b, o) << 16;
	return v;
}
static uint64_t get64(const uint8_t *b, size_t *o)
{
	uint64_t v = get32(b, o);
	v |= (uint64_t)get32(b, o) << 32;
	return v;
}

/* Start building a 9P message: reserve size[4]+type[1]+tag[2]; returns the body offset. */
static size_t msg_begin(uint8_t type, uint16_t tag)
{
	size_t o = 0;
	put32(&o, 0); /* size, patched by msg_end */
	put8(&o, type);
	put16(&o, tag);
	return o;
}
static void msg_end(size_t o)
{
	size_t p = 0;
	put32(&p, (uint32_t)o); /* patch the size prefix */
	g_txlen = o;
	g_txoff = 0;
}

/* ---- path splitting -------------------------------------------------------- */
/* Split a remote path (mount-relative, absolute, e.g. "/a/b") into components.
 * Returns the count, or -1 if >NETFS_MAXWELEM. */
static int path_split(const char *path, const char **comp, size_t *len, int max)
{
	int n = 0;
	const char *s = path;
	while (*s == '/')
		s++;
	while (*s) {
		if (n >= max)
			return -1;
		const char *start = s;
		while (*s && *s != '/')
			s++;
		comp[n] = start;
		len[n] = (size_t)(s - start);
		n++;
		while (*s == '/')
			s++;
	}
	return n;
}

static void msg_fid(uint8_t type, int fid)
{
	size_t offset = msg_begin(type, P9_TAG);
	put32(&offset, (uint32_t)fid);
	msg_end(offset);
}

static void msg_io(uint8_t type, int fid, uint64_t offset, uint32_t count)
{
	size_t cursor = msg_begin(type, P9_TAG);
	put32(&cursor, (uint32_t)fid);
	put64(&cursor, offset);
	put32(&cursor, count);
	msg_end(cursor);
}

static long msg_walk(struct netfs_req *request)
{
	const char *component[NETFS_MAXWELEM];
	size_t length[NETFS_MAXWELEM];
	int count = path_split(request->path, component, length, NETFS_MAXWELEM);
	if (count < 0)
		return -LXP_ENAMETOOLONG;
	request->fid = fid_alloc();
	if (request->fid < 0)
		return -LXP_EMFILE;

	size_t offset = msg_begin(P9_TWALK, P9_TAG);
	put32(&offset, P9_ROOT_FID);
	put32(&offset, (uint32_t)request->fid);
	put16(&offset, (uint16_t)count);
	for (int index = 0; index < count; index++)
		putstr(&offset, component[index], length[index]);
	msg_end(offset);
	return 0;
}

/* ---- low-level socket flush / drain (non-blocking) ------------------------- */
/* Returns 1 if the whole pending TX message is flushed, 0 if more to send later,
 * -1 on a transport error (caller drops the connection). */
static int tx_flush(void)
{
	while (g_txoff < g_txlen) {
		size_t sent = 0;
		int r = g_lxp_net_ops->sock_send(g_sk, g_tx + g_txoff, g_txlen - g_txoff, &sent);
		if (r == LXP_OK) {
			g_txoff += sent;
			if (sent == 0)
				return 0; /* nothing accepted now */
			continue;
		}
		if (r == LXP_ERR_TIMEOUT)
			return 0; /* send buffer full → retry next pump */
		return -1;
	}
	return 1;
}

/* Read available bytes into g_rx. Returns 1 if progress, 0 if would-block, -1 on
 * error/peer-close. */
static int rx_fill(void)
{
	int progress = 0;
	while (g_rxlen < sizeof(g_rx)) {
		size_t got = 0;
		int r = g_lxp_net_ops->sock_recv(g_sk, g_rx + g_rxlen, sizeof(g_rx) - g_rxlen, &got,
						 LXP_WAIT_FOREVER);
		if (r == LXP_OK) {
			if (got == 0)
				return -1; /* orderly close */
			g_rxlen += got;
			progress = 1;
			continue;
		}
		if (r == LXP_ERR_TIMEOUT)
			return progress;
		return -1;
	}
	return progress;
}

/* Extract one complete 9P reply from g_rx if present. Returns the message length
 * (with the 7-byte header), or 0 if incomplete. On return the message occupies
 * g_rx[0..len); the caller consumes it via rx_consume(). */
static size_t rx_message(void)
{
	if (g_rxlen < 7)
		return 0;
	size_t o = 0;
	uint32_t size = get32(g_rx, &o);
	if (size < 7 || size > sizeof(g_rx))
		return (size_t)-1; /* framing error → reconnect */
	if (g_rxlen < size)
		return 0;
	return size;
}
static void rx_consume(size_t len)
{
	if (len && len <= g_rxlen) {
		memmove(g_rx, g_rx + len, g_rxlen - len);
		g_rxlen -= len;
	}
}

/* ---- connection teardown / (re)connect ------------------------------------- */
static void conn_drop(void)
{
	if (g_sk)
		g_lxp_net_ops->sock_close(g_sk);
	g_sk = NULL;
	g_conn = CONN_DOWN;
	g_conn_deadline_us = 0;
	g_txlen = g_txoff = g_rxlen = 0;
	/* Fail every outstanding request; opens become stale. A cancelled request (owner
	 * detached) has no proc to retrieve its result, so reclaim it rather than leak the slot. */
	for (int i = 0; i < NETFS_NREQ; i++)
		if (g_req[i].state == REQ_QUEUED || g_req[i].state == REQ_INFLIGHT) {
			if (g_req[i].owner.index < 0) {
				g_req[i].state = REQ_FREE;
				continue;
			}
			g_req[i].result = -LXP_EIO;
			g_req[i].state = REQ_DONE;
		}
	g_inflight = -1;
	for (int i = 0; i < NETFS_NOPEN; i++)
		if (g_open[i].used)
			g_open[i].stale = 1;
}

/* A failed best-effort connection attempt leaves queued requests intact so the
 * lazy reconnect can service them later. An established-connection failure
 * instead goes through conn_drop(), which completes their waits with EIO. */
static void conn_attempt_failed(uint64_t now_us)
{
	if (g_sk)
		g_lxp_net_ops->sock_close(g_sk);
	g_sk = NULL;
	g_conn = CONN_DOWN;
	g_conn_deadline_us = 0;
	g_txlen = g_txoff = g_rxlen = 0;
	g_reconnect_at_us = now_us + NETFS_RECONNECT_US;
}

static void conn_begin_version(uint64_t now_us)
{
	/* Tversion(msize, "9P2000.L") */
	static const char VER[] = "9P2000.L";
	size_t o = msg_begin(P9_TVERSION, P9_NOTAG);
	put32(&o, NETFS_MSIZE);
	putstr(&o, VER, sizeof(VER) - 1);
	msg_end(o);
	g_conn = CONN_VERSION_SEND;
	g_conn_deadline_us = now_us + 3000000ull;
}

static void conn_begin_attach(uint64_t now_us)
{
	/* Tattach(root_fid, NOFID, uname, aname, n_uname=0) */
	size_t o = msg_begin(P9_TATTACH, P9_TAG);
	put32(&o, P9_ROOT_FID);
	put32(&o, P9_NOFID);
	putstr(&o, g_mnt.uname, strlen(g_mnt.uname));
	putstr(&o, g_mnt.aname, strlen(g_mnt.aname));
	put32(&o, 0); /* n_uname (numeric uid) */
	msg_end(o);
	g_conn = CONN_ATTACH_SEND;
	g_conn_deadline_us = now_us + 3000000ull;
}

/* Build an IPv4 lxp_sockaddr_t (host-order port) locally so the netfs client
 * depends only on the network-provider contract. */
static void netfs_sockaddr_ipv4(lxp_sockaddr_t *a, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3,
				uint16_t port)
{
	memset(a, 0, sizeof(*a));
	a->family = LXP_AF_INET;
	a->port = port;
	a->addr[0] = b0;
	a->addr[1] = b1;
	a->addr[2] = b2;
	a->addr[3] = b3;
}

static void conn_start(uint64_t now_us)
{
	if (!g_mnt.configured)
		return;
	if (now_us < g_reconnect_at_us)
		return;
	g_reconnect_at_us = now_us + NETFS_RECONNECT_US;

	if (g_lxp_net_ops->sock_open(LXP_AF_INET, LXP_SOCK_STREAM, 0, &g_sk) != LXP_OK) {
		g_sk = NULL;
		return;
	}
	if (g_lxp_net_ops->sock_set_nonblock(g_sk, 1) != LXP_OK) {
		conn_attempt_failed(now_us);
		return;
	}
	lxp_sockaddr_t peer;
	netfs_sockaddr_ipv4(&peer, g_mnt.ip[0], g_mnt.ip[1], g_mnt.ip[2], g_mnt.ip[3], g_mnt.port);
	int rc = g_lxp_net_ops->sock_connect(g_sk, &peer, 0);
	if (rc == LXP_ERR_TIMEOUT) {
		g_conn = CONN_CONNECTING;
		g_conn_deadline_us = now_us + 5000000ull;
		return;
	}
	if (rc != LXP_OK) {
		conn_attempt_failed(now_us);
		return;
	}
	memset(g_fid_bm, 0, sizeof(g_fid_bm));
	g_txlen = g_txoff = g_rxlen = 0;
	conn_begin_version(now_us);
}

/* Advance at most the small, fixed number of connect/handshake phases without
 * waiting in the coordinator. Socket readiness wakes event-driven ports; the
 * normal coordinator timeout remains the portable fallback. */
static void conn_advance(uint64_t now_us)
{
	if (g_conn == CONN_DOWN) {
		conn_start(now_us);
		if (g_conn == CONN_DOWN)
			return;
	}
	if (g_conn_deadline_us && now_us >= g_conn_deadline_us) {
		conn_attempt_failed(now_us);
		return;
	}

	for (unsigned step = 0; step < 5; step++) {
		switch (g_conn) {
		case CONN_CONNECTING: {
			unsigned rev = 0;
			int rc = g_lxp_net_ops->sock_poll(
				g_sk, LXP_SOCK_POLLOUT | LXP_SOCK_POLLERR | LXP_SOCK_POLLHUP, &rev,
				0);
			if (rc != LXP_OK) {
				conn_attempt_failed(now_us);
				return;
			}
			if (!(rev & (LXP_SOCK_POLLOUT | LXP_SOCK_POLLERR | LXP_SOCK_POLLHUP)))
				return;
			if (g_lxp_net_ops->sock_get_error(g_sk) != LXP_OK) {
				conn_attempt_failed(now_us);
				return;
			}
			memset(g_fid_bm, 0, sizeof(g_fid_bm));
			g_txlen = g_txoff = g_rxlen = 0;
			conn_begin_version(now_us);
			continue;
		}
		case CONN_VERSION_SEND:
		case CONN_ATTACH_SEND: {
			int rc = tx_flush();
			if (rc < 0) {
				conn_attempt_failed(now_us);
				return;
			}
			if (rc == 0)
				return;
			g_conn = (g_conn == CONN_VERSION_SEND) ? CONN_VERSION_RECV
							       : CONN_ATTACH_RECV;
			continue;
		}
		case CONN_VERSION_RECV:
		case CONN_ATTACH_RECV: {
			if (rx_fill() < 0) {
				conn_attempt_failed(now_us);
				return;
			}
			size_t len = rx_message();
			if (len == (size_t)-1) {
				conn_attempt_failed(now_us);
				return;
			}
			if (!len)
				return;
			if (g_conn == CONN_VERSION_RECV) {
				if (len < 13 || g_rx[4] != P9_RVERSION) {
					conn_attempt_failed(now_us);
					return;
				}
				size_t p = 7;
				uint32_t sm = get32(g_rx, &p);
				g_msize = sm < NETFS_MSIZE ? sm : NETFS_MSIZE;
				if (g_msize < 512) {
					conn_attempt_failed(now_us);
					return;
				}
				rx_consume(len);
				conn_begin_attach(now_us);
				continue;
			}
			if (g_rx[4] != P9_RATTACH) {
				conn_attempt_failed(now_us);
				return;
			}
			rx_consume(len);
			g_conn = CONN_UP;
			g_conn_deadline_us = 0;
			g_generation++;
			return;
		}
		case CONN_UP:
		case CONN_DOWN:
		default:
			return;
		}
	}
}

/* ---- request build for the current step ------------------------------------ */
/* Build the message for req's current (op, step) into g_tx. Returns 0 on success,
 * or a negative errno that completes the request. */
static long req_build(struct netfs_req *r)
{
	size_t o;

	switch (r->op) {
	case LXP_NETFSW_OPEN:
	case LXP_NETFSW_STAT:
#if LXP_ENABLE_NETFS_EXEC
	case LXP_NETFSW_EXECFETCH:
#endif
		if (r->step == 0) /* Twalk(root -> fid, components) */
			return msg_walk(r);
		if (r->step == 1) { /* Tlgetattr(fid) */
			o = msg_begin(P9_TLGETATTR, P9_TAG);
			put32(&o, (uint32_t)r->fid);
			put64(&o, P9_GETATTR_BASIC);
			msg_end(o);
			return 0;
		}
		if (r->step == 2) {
			if (r->op == LXP_NETFSW_STAT) { /* stat: clunk the temp fid */
				msg_fid(P9_TCLUNK, r->fid);
				return 0;
			}
			/* OPEN + EXECFETCH: Tlopen(fid, O_RDONLY). Always O_RDONLY — files read via Tread,
			 * directories via Treaddir on the same open fid. NB: do NOT send O_DIRECTORY: its
			 * ARM value is 0x4000 (0x10000 is O_DIRECT on ARM), and a diod dir opened O_DIRECT
			 * fails Treaddir with -EIO. A plain O_RDONLY dir open reads fine. */
			o = msg_begin(P9_TLOPEN, P9_TAG);
			put32(&o, (uint32_t)r->fid);
			put32(&o, 0u);
			msg_end(o);
			return 0;
		}
#if LXP_ENABLE_NETFS_EXEC
		if (r->step == 3) { /* EXECFETCH: Tread the next chunk into the staging buffer */
			uint32_t cnt = (uint32_t)(g_msize - 24);
			if (r->off + cnt > g_exec_cap) /* never overflow the staging buffer */
				cnt = (uint32_t)(g_exec_cap - r->off);
			msg_io(P9_TREAD, r->fid, r->off, cnt);
			return 0;
		}
		if (r->step == 4) { /* EXECFETCH: clunk after EOF */
			msg_fid(P9_TCLUNK, r->fid);
			return 0;
		}
#endif
		return -LXP_EINVAL;

	case LXP_NETFSW_READ: {
		struct netfs_open *op = open_slot(r->oi);
		if (!op)
			return -LXP_EBADF;
		uint32_t cnt = (uint32_t)r->ulen;
		if (cnt > g_msize - 24)
			cnt = g_msize - 24;
		msg_io(P9_TREAD, op->fid, op->rd_off, cnt);
		return 0;
	}
	case LXP_NETFSW_GETDENTS: {
		struct netfs_open *op = open_slot(r->oi);
		if (!op)
			return -LXP_EBADF;
		/* Treaddir count must leave room for the 9P read header (P9_IOHDRSZ = 24) within msize,
		 * else diod Rlerrors — same cap as Tread above (a bigger count here = an empty ls). */
		uint32_t cnt = (uint32_t)(g_msize - 24);
		msg_io(P9_TREADDIR, op->fid, op->dir_off, cnt);
		return 0;
	}
	default: /* REQ_OP_CLUNK */
		msg_fid(P9_TCLUNK, r->fid);
		return 0;
	}
}

/* The stat record of a remote object. 9P objects number from LXP_INO_NETFS by qid
 * path and report a distinct synthetic st_dev, so ld.so's (st_dev, st_ino) dedup
 * never collides with the local rootfs. */
static void netfs_stat_record(struct lxp_stat *st, uint32_t mode, uint64_t size, uint64_t mtime,
			      uint64_t ino)
{
	lxp_stat_init(st, LXP_INO_NETFS + (uint32_t)ino, mode, size);
	st->dev_minor = 0xfeu;
	st->mtime = (int64_t)mtime;
}

/* Map a 9P readdir entry type (a qid.type byte) to a Linux d_type. */
static uint8_t dtype_from_qid(uint8_t qt)
{
	if (qt & P9_QTDIR)
		return LXP_DT_DIR;
	if (qt & 0x02u /* QTSYMLINK */)
		return LXP_DT_LNK;
	return LXP_DT_REG;
}

/* ---- reply handling (advances or completes the in-flight request) ---------- */
static void req_complete(struct netfs_req *r, long result)
{
	r->result = result;
	r->state = REQ_DONE;
	g_inflight = -1;
}

static void req_fail(struct netfs_req *request, long result)
{
	if (request->op == REQ_OP_CLUNK) {
		fid_free(request->fid);
		request->fid = -1;
		request->state = REQ_FREE;
		g_inflight = -1;
		return;
	}
	if (request->fid > 0) {
		clunk_enqueue(request->fid);
		request->fid = -1;
	}
	if (request->op == LXP_NETFSW_OPEN && request->oi >= 0)
		g_open[request->oi].used = 0;
	req_complete(request, result);
}

static uint8_t req_expected_reply(const struct netfs_req *request)
{
	if (request->op == REQ_OP_CLUNK)
		return P9_RCLUNK;
	if (request->op == LXP_NETFSW_READ)
		return P9_RREAD;
	if (request->op == LXP_NETFSW_GETDENTS)
		return P9_RREADDIR;
	if (request->step == 0)
		return P9_RWALK;
	if (request->step == 1)
		return P9_RLGETATTR;
	if (request->op == LXP_NETFSW_STAT)
		return request->step == 2 ? P9_RCLUNK : 0;
	if (request->step == 2)
		return P9_RLOPEN;
#if LXP_ENABLE_NETFS_EXEC
	if (request->op == LXP_NETFSW_EXECFETCH)
		return request->step == 3 ? P9_RREAD : request->step == 4 ? P9_RCLUNK : 0;
#endif
	return 0;
}

static int reply_walk_advance(struct netfs_req *request, const uint8_t *body, size_t length)
{
	if (length < 2) {
		req_fail(request, -LXP_EIO);
		return 0;
	}
	size_t offset = 0;
	uint16_t walked = get16(body, &offset);
	const char *component[NETFS_MAXWELEM];
	size_t component_length[NETFS_MAXWELEM];
	int requested = path_split(request->path, component, component_length, NETFS_MAXWELEM);
	if (requested < 0 || walked != (uint16_t)requested) {
		req_fail(request,
			 requested >= 0 && walked < (uint16_t)requested ? -LXP_ENOENT : -LXP_EIO);
		return 0;
	}
	request->step++;
	return 1;
}

static uint32_t reply_data_count(const uint8_t *body, size_t length, size_t *offset)
{
	if (length < 4)
		return 0;
	uint32_t count = get32(body, offset);
	return count > length - *offset ? (uint32_t)(length - *offset) : count;
}

/* Parse Rlgetattr body (cursor at first field after the 7-byte header) into attrs. */
static int parse_getattr(const uint8_t *b, size_t o, size_t blen, uint32_t *mode, uint64_t *size,
			 uint64_t *mtime, uint64_t *ino)
{
	*mode = 0;
	*size = 0;
	*mtime = 0;
	*ino = 0;
	if (o + 97 > blen) /* the Rgetattr fields read below span 97 bytes from o */
		return 0;
	(void)get64(b, &o); /* valid */
	uint8_t qtype = get8(b, &o);
	(void)get32(b, &o); /* qid.version */
	uint64_t qpath = get64(b, &o);
	uint32_t m = get32(b, &o);
	(void)get32(b, &o); /* uid */
	(void)get32(b, &o); /* gid */
	(void)get64(b, &o); /* nlink */
	(void)get64(b, &o); /* rdev */
	uint64_t sz = get64(b, &o);
	(void)get64(b, &o); /* blksize */
	(void)get64(b, &o); /* blocks */
	(void)get64(b, &o); /* atime_sec */
	(void)get64(b, &o); /* atime_nsec */
	uint64_t mt = get64(b, &o);
	*mode = m;
	*size = sz;
	*mtime = mt;
	*ino = qpath;
	(void)qtype;
	return 1;
}

static void handle_reply(struct netfs_req *r, lxp_proc_t *owner, uint8_t type, const uint8_t *body,
			 size_t blen)
{
	size_t o = 0;
	(void)blen;

	/* The guest that issued this op was signalled while parked (lxp_netfs_cancel detached
	 * the owner). Never marshal the reply into its — now gone or reused — buffer: drop it,
	 * release the working fid, and reclaim the slot. (An owner-less CLUNK is the internal
	 * background clunk, handled by its own path below.) */
	if (r->owner.index < 0 && r->op != REQ_OP_CLUNK) {
		if (r->fid > 0) {
			clunk_enqueue(r->fid);
			r->fid = -1;
		}
		if (r->op == LXP_NETFSW_OPEN && r->oi >= 0)
			g_open[r->oi].used = 0;
		r->state = REQ_FREE;
		g_inflight = -1;
		return;
	}

	if (type == P9_RLERROR) {
		uint32_t ecode = (blen < 4) ? (uint32_t)LXP_EIO
					    : get32(body, &o); /* truncated Rlerror */
		req_fail(r, -(long)ecode);
		return;
	}
	if (type != req_expected_reply(r)) {
		req_fail(r, -LXP_EIO);
		return;
	}

	switch (r->op) {
	case LXP_NETFSW_OPEN:
		if (r->step == 0) { /* Rwalk: nwqid must equal the requested component count */
			(void)reply_walk_advance(r, body, blen);
			return; /* stay inflight; pump rebuilds Tlgetattr */
		}
		if (r->step == 1) { /* Rlgetattr */
			uint32_t mode;
			uint64_t size, mtime, ino;
			if (!parse_getattr(body, o, blen, &mode, &size, &mtime, &ino)) {
				req_fail(r, -LXP_EIO);
				return;
			}
			struct netfs_open *op = &g_open[r->oi];
			op->is_dir = (mode & LXP_S_IFMT) == LXP_S_IFDIR;
			op->mode = mode;
			op->size = size;
			op->mtime = mtime;
			op->ino = ino;
			r->step = 2;
			return;
		}
		if (r->step == 2) { /* Rlopen → open is ready */
			struct netfs_open *op = &g_open[r->oi];
			op->used = 1;
			op->stale = 0;
			op->fid = r->fid;
			op->generation = g_generation;
			op->dir_off = 0;
			req_complete(r, r->oi); /* retry installs the fd */
			return;
		}
		break;

	case LXP_NETFSW_READ: {
		uint32_t cnt = reply_data_count(body, blen, &o);
		if (cnt > r->ulen)
			cnt = (uint32_t)r->ulen;
		if (cnt && lxp_copy_to_guest(owner, r->ubuf, body + o, cnt) != 0) {
			req_complete(r, -LXP_EFAULT);
			return;
		}
		struct netfs_open *op = open_slot(r->oi);
		if (op)
			op->rd_off += cnt; /* advance the shared file cursor */
		req_complete(r, (long)cnt);
		return;
	}
	case LXP_NETFSW_GETDENTS: {
		uint32_t cnt = reply_data_count(body, blen, &o);
		size_t end = o + cnt;
		lxp_dirent_sink_t sink = {
			.proc = owner, .ubuf = r->ubuf, .cap = r->ulen, .is64 = r->is64};
		struct netfs_open *op = open_slot(r->oi);
		uint64_t last_off = op ? op->dir_off : 0;
		while (o < end && o + 13 + 8 + 1 + 2 <= blen) {
			/* entry := qid[13] offset[8] type[1] name[s]; qid := type[1] ver[4] path[8] */
			uint8_t qt = body[o];
			uint64_t qpath = 0;
			for (int i = 0; i < 8; i++)
				qpath |= (uint64_t)body[o + 5 + i] << (8 * i);
			o += 13;
			uint64_t doff = get64(body, &o);
			uint8_t dt9 = get8(body, &o); /* the Linux d_type (DT_*), 0 = unknown */
			uint16_t nlen = get16(body, &o);
			if (o + nlen > blen)
				break;
			const char *nm = (const char *)(body + o);
			o += nlen;
			uint8_t dtype = dt9 ? dt9 : dtype_from_qid(qt);
			if (!lxp_dirent_put(&sink, qpath, doff, dtype, nm, nlen)) {
				if (sink.error) {
					req_complete(r, sink.error);
					return;
				}
				break; /* record didn't fit; resume here next call */
			}
			last_off = doff;
		}
		if (op)
			op->dir_off = last_off; /* resume cursor (EOF when cnt==0 → filled 0) */
		req_complete(r, (long)sink.filled);
		return;
	}
	case LXP_NETFSW_STAT:
		if (r->step == 0) { /* Rwalk: walked to the temp fid (or a component missing) */
			(void)reply_walk_advance(r, body, blen);
			return; /* stay inflight; pump rebuilds Tlgetattr */
		}
		if (r->step == 1) { /* Rlgetattr → fill guest stat, then clunk */
			uint32_t mode;
			uint64_t size, mtime, ino;
			if (!parse_getattr(body, o, blen, &mode, &size, &mtime, &ino)) {
				req_fail(r, -LXP_EIO);
				return;
			}
			struct lxp_stat st;
			netfs_stat_record(&st, mode, size, mtime, ino);
			r->result = lxp_stat_copyout(owner, r->ubuf, r->statkind, &st);
			r->step = 2; /* send Tclunk(fid) */
			return;
		}
		if (r->step == 2) { /* Rclunk → done */
			fid_free(r->fid);
			r->fid = -1;
			req_complete(r, r->result);
			return;
		}
		break;

#if LXP_ENABLE_NETFS_EXEC
	case LXP_NETFSW_EXECFETCH:
		if (r->step == 0) { /* Rwalk */
			(void)reply_walk_advance(r, body, blen);
			return;
		}
		if (r->step == 1) { /* Rlgetattr → capture the file size (regular files only) */
			uint32_t mode;
			uint64_t size, mtime, ino;
			if (!parse_getattr(body, o, blen, &mode, &size, &mtime, &ino)) {
				req_fail(r, -LXP_EIO);
				return;
			}
			if ((mode & LXP_S_IFMT) != LXP_S_IFREG) {
				r->result = -LXP_EACCES;
				r->step = 4; /* skip open/read → just clunk the walked fid */
				return;
			}
			r->ulen = (size_t)size; /* total bytes to fetch */
			r->step = 2;
			return;
		}
		if (r->step == 2) { /* Rlopen → begin chunked reads */
			r->off = 0;
			g_exec_size = 0;
			r->step = 3;
			return;
		}
		if (r->step == 3) { /* Rread → copy a chunk into staging */
			uint32_t cnt = reply_data_count(body, blen, &o);
			if (r->off + cnt > g_exec_cap)
				cnt = (uint32_t)(g_exec_cap - r->off);
			if (cnt)
				memcpy(g_exec_buf + r->off, body + o, cnt);
			r->off += cnt;
			g_exec_size = r->off;
			int eof = (cnt == 0) || (r->off >= r->ulen);
			int full = (r->off >= g_exec_cap);
			if (full && !eof)
				r->result = -LXP_ENOEXEC; /* image exceeds the staging buffer */
			if (eof || full)
				r->step = 4; /* clunk */
			return;		     /* else stay step 3 and read more */
		}
		if (r->step == 4) { /* Rclunk → done (result 0, or an error latched above) */
			fid_free(r->fid);
			r->fid = -1;
			req_complete(r, r->result);
			return;
		}
		break;
#endif

	default: /* REQ_OP_CLUNK: Rclunk */
		fid_free(r->fid);
		r->state = REQ_FREE;
		g_inflight = -1;
		return;
	}
	/* Unexpected reply for the step: fail the op. */
	req_fail(r, -LXP_EIO);
}

/* ---- the pump: advance the transport one step ------------------------------ */
static int req_owned_by(const struct netfs_req *r, const lxp_proc_t *proc)
{
	lxp_slot_ref_t active;
	return r->owner.index >= 0 && lxp_guest_view_slot(proc, &active) == LXP_OK &&
	       lxp_slot_ref_equal(r->owner, active);
}

static void pump(lxp_proc_t *active_owner, uint64_t now_us)
{
	if (g_conn != CONN_UP) {
		conn_advance(now_us);
		if (g_conn != CONN_UP)
			return;
	}

	/* Flush any pending outgoing message. */
	int f = tx_flush();
	if (f < 0) {
		conn_drop();
		return;
	}
	if (f == 0)
		return; /* still sending; come back next pass */

	/* Drain replies for the in-flight request. */
	if (g_inflight >= 0) {
		struct netfs_req *inflight = &g_req[g_inflight];
		if (inflight->op != REQ_OP_CLUNK && inflight->owner.index >= 0 &&
		    !req_owned_by(inflight, active_owner))
			return;
		int rf = rx_fill();
		if (rf < 0) {
			conn_drop();
			return;
		}
		for (;;) {
			size_t len = rx_message();
			if (len == (size_t)-1) {
				conn_drop();
				return;
			}
			if (!len)
				break;
			struct netfs_req *r = &g_req[g_inflight];
			uint8_t type = g_rx[4];
			handle_reply(r, active_owner, type, g_rx + 7, len - 7);
			rx_consume(len);
			/* If the reply advanced a step (still INFLIGHT), rebuild + send it. */
			if (r->state == REQ_INFLIGHT && g_inflight >= 0) {
				long e = req_build(r);
				if (e < 0) {
					req_complete(r, e);
				} else {
					if (tx_flush() < 0) {
						conn_drop();
						return;
					}
				}
			}
			if (g_inflight < 0)
				break;
		}
	}

	/* Start the next request: prefer a queued guest request (lowest seq), else a
	 * background clunk. */
	if (g_inflight < 0 && g_txoff == g_txlen) {
		int best = -1;
		uint32_t bseq = 0xffffffffu;
		for (int i = 0; i < NETFS_NREQ; i++)
			if (g_req[i].state == REQ_QUEUED && g_req[i].seq < bseq) {
				bseq = g_req[i].seq;
				best = i;
			}
		if (best >= 0) {
			struct netfs_req *r = &g_req[best];
			if (!req_owned_by(r, active_owner))
				return;
			long e = req_build(r);
			if (e < 0) {
				req_complete(r, e);
			} else {
				r->state = REQ_INFLIGHT;
				g_inflight = best;
				if (tx_flush() < 0) {
					conn_drop();
					return;
				}
			}
		} else if (g_clunk_head != g_clunk_tail) {
			/* fire a background clunk through a throwaway internal request */
			for (int i = 0; i < NETFS_NREQ; i++)
				if (g_req[i].state == REQ_FREE) {
					struct netfs_req *r = &g_req[i];
					memset(r, 0, sizeof(*r));
					r->op = REQ_OP_CLUNK;
					r->owner = lxp_slot_ref_none();
					r->fid = g_clunk_fid[g_clunk_head];
					g_clunk_head = (g_clunk_head + 1) % NETFS_NCLUNK;
					r->state = REQ_INFLIGHT;
					g_inflight = i;
					if (req_build(r) == 0 && tx_flush() < 0)
						conn_drop();
					break;
				}
		}
	}
}

/* ---- request allocation + submit ------------------------------------------- */
static struct netfs_req *req_new(lxp_proc_t *p, uint8_t op)
{
	lxp_slot_ref_t owner;
	if (lxp_guest_view_slot(p, &owner) != LXP_OK)
		return NULL;
	for (int i = 0; i < NETFS_NREQ; i++)
		if (g_req[i].state == REQ_FREE) {
			struct netfs_req *r = &g_req[i];
			memset(r, 0, sizeof(*r));
			r->state = REQ_QUEUED;
			r->op = op;
			r->owner = owner;
			r->oi = -1;
			r->fid = -1;
			r->seq = g_req_seq++;
			lxp_wait_t wait = {
				.kind = LXP_WAIT_NETFS,
				.op = op,
				.data.io.object = -1,
				.data.io.request = i,
			};
			if (lxp_wait_begin(p, &wait) != 0) {
				r->state = REQ_FREE;
				return NULL;
			}
			return r;
		}
	return NULL;
}

/* ---- mount config + init --------------------------------------------------- */
int lxp_netfs_init(const lxp_netfs_config_t *config)
{
	/* A run always starts from an empty transport and topology, including when
	 * its predecessor used netfs and this run does not. */
	lxp_netfs_shutdown();
	if (!config)
		return LXP_OK;
	if (!lxp_netfs_config_valid(config))
		return LXP_ERR_INVALID_PARAM;

	memset(&g_mnt, 0, sizeof(g_mnt));
	g_mnt.mplen = strlen(config->mountpoint);
	memcpy(g_mnt.mp, config->mountpoint, g_mnt.mplen + 1u);
	memcpy(g_mnt.ip, config->server_ip, sizeof(g_mnt.ip));
	g_mnt.port = config->port;
	if (config->aname) {
		size_t n = strlen(config->aname);
		memcpy(g_mnt.aname, config->aname, n + 1u);
	}
	{
		const char *u = (config->uname && config->uname[0]) ? config->uname : "root";
		size_t n = strlen(u);
		memcpy(g_mnt.uname, u, n + 1u);
	}
	g_mnt.configured = 1;
	uint64_t now = 0;
	lxp_time_us(&now);
	g_reconnect_at_us = 0;
	conn_advance(now); /* initiate only; connect and handshake never block the coordinator */
	return LXP_OK;
}

void lxp_netfs_shutdown(void)
{
	/* Do not turn outstanding requests into DONE requests as conn_drop() does:
	 * every owner has already been stopped, so nobody remains to consume them. */
	if (g_sk && g_lxp_net_ops && g_lxp_net_ops->sock_close)
		g_lxp_net_ops->sock_close(g_sk);
	g_sk = NULL;
	g_conn = CONN_DOWN;
	g_msize = NETFS_MSIZE;
	g_reconnect_at_us = 0;
	g_conn_deadline_us = 0;
	g_txlen = g_txoff = g_rxlen = 0;
	g_inflight = -1;
	g_req_seq = 0;
	g_clunk_head = g_clunk_tail = 0;
	memset(g_fid_bm, 0, sizeof(g_fid_bm));
	memset(g_open, 0, sizeof(g_open));
	memset(g_req, 0, sizeof(g_req));
	memset(g_clunk_fid, 0, sizeof(g_clunk_fid));
	memset(&g_mnt, 0, sizeof(g_mnt));
#if LXP_ENABLE_NETFS_EXEC
	g_exec_buf = NULL;
	g_exec_cap = g_exec_size = 0;
#endif
}

/* ---- provider entry points (called from the syscall handlers) -------------- */
int lxp_netfs_lookup(const char *abspath)
{
	if (!g_mnt.configured || !g_mnt.mplen)
		return -1;
	if (strncmp(abspath, g_mnt.mp, g_mnt.mplen) != 0)
		return -1;
	char c = abspath[g_mnt.mplen];
	if (c == '\0' || c == '/')
		return 0; /* the mount point itself or something under it */
	return -1;
}

/* Return the mount-relative remote path ("/" for the mount root). */
static const char *relpath(const char *abspath)
{
	const char *rp = abspath + g_mnt.mplen;
	return (*rp == '\0') ? "/" : rp;
}

long lxp_netfs_open(lxp_proc_t *p, const char *abspath, int flags)
{
	if (flags & (LXP_O_WRONLY | LXP_O_RDWR | LXP_O_CREAT | LXP_O_TRUNC))
		return -LXP_EROFS;
	const char *rp = relpath(abspath);
	if (strlen(rp) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	int oi = -1;
	for (int i = 0; i < NETFS_NOPEN; i++)
		if (!g_open[i].used) {
			oi = i;
			break;
		}
	if (oi < 0)
		return -LXP_EMFILE;
	struct netfs_req *r = req_new(p, LXP_NETFSW_OPEN);
	if (!r)
		return -LXP_EMFILE;
	memset(&g_open[oi], 0, sizeof(g_open[oi]));
	g_open[oi].used = 1; /* reserve; finalized on Rlopen (or freed on error) */
	r->oi = oi;
	r->flags = flags;
	strcpy(r->path, rp);
	p->wait.data.io.object = oi;
	return 0; /* parked */
}

long lxp_netfs_read(lxp_proc_t *p, int oi, void *ubuf, size_t len)
{
	struct netfs_open *op = open_slot(oi);
	if (!op)
		return -LXP_EBADF;
	if (op->stale)
		return -LXP_ESTALE;
	if (op->is_dir)
		return -LXP_EISDIR;
	if (len == 0)
		return 0;
	if (!lxp_guest_access_ok(p, ubuf, len, 1))
		return -LXP_EFAULT;
	struct netfs_req *r = req_new(p, LXP_NETFSW_READ);
	if (!r)
		return -LXP_EMFILE;
	r->oi = oi;
	r->ubuf = (uintptr_t)ubuf;
	r->ulen = len;
	p->wait.data.io.object = oi;
	return 0; /* parked */
}

/* lseek(2) on an FD_NET fd: cursor math against the shared open offset + cached size.
 * Returns the new absolute offset, or a negative Linux errno. */
long lxp_netfs_lseek(int oi, long off, int whence)
{
	struct netfs_open *op = open_slot(oi);
	if (!op)
		return -LXP_EBADF;
	if (op->is_dir)
		return -LXP_EISDIR;
	uint64_t base = (whence == LXP_SEEK_CUR)   ? op->rd_off
			: (whence == LXP_SEEK_END) ? op->size
						   : 0;
	long long np = (long long)base + off;
	if (np < 0)
		return -LXP_EINVAL;
	op->rd_off = (uint64_t)np;
	return (long)np;
}

long lxp_netfs_getdents(lxp_proc_t *p, int oi, uintptr_t ubuf, size_t cap, int is64)
{
	struct netfs_open *op = open_slot(oi);
	if (!op)
		return -LXP_EBADF;
	if (op->stale)
		return -LXP_ESTALE;
	if (!op->is_dir)
		return -LXP_ENOTDIR;
	if (!lxp_guest_access_ok(p, (void *)ubuf, cap, 1))
		return -LXP_EFAULT;
	struct netfs_req *r = req_new(p, LXP_NETFSW_GETDENTS);
	if (!r)
		return -LXP_EMFILE;
	r->oi = oi;
	r->ubuf = ubuf;
	r->ulen = cap;
	r->is64 = is64;
	p->wait.data.io.object = oi;
	return 0; /* parked */
}

long lxp_netfs_stat(lxp_proc_t *p, const char *abspath, uintptr_t ustat, int statkind)
{
	const char *rp = relpath(abspath);
	if (strlen(rp) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	struct netfs_req *r = req_new(p, LXP_NETFSW_STAT);
	if (!r)
		return -LXP_EMFILE;
	r->ubuf = ustat;
	r->statkind = statkind;
	strcpy(r->path, rp);
	p->wait.data.io.object = -1;
	return 0; /* parked */
}

int lxp_netfs_fstat(int oi, uint32_t *mode, uint64_t *size, uint64_t *mtime, uint64_t *ino)
{
	struct netfs_open *op = open_slot(oi);
	if (!op)
		return -1;
	if (mode)
		*mode = op->mode;
	if (size)
		*size = op->size;
	if (mtime)
		*mtime = op->mtime;
	if (ino)
		*ino = op->ino;
	return 0;
}

void lxp_netfs_close(int oi)
{
	struct netfs_open *op = open_slot(oi);
	if (!op)
		return;
	if (!op->stale && op->fid > 0)
		clunk_enqueue(op->fid);
	else
		fid_free(op->fid);
	op->used = 0;
}

/* Abandon a proc's in-flight netfs op after it was signalled while parked (the run loop's
 * parked-signal delivery calls this). The op's reply may still be on the wire, so we detach
 * the owner + guest buffer instead of freeing blindly: a queued/finished request is reclaimed
 * now, while an in-flight one is left for the pump — handle_reply drops an owner-less reply.
 * A reserved-but-unfinished OPEN slot is released so it cannot leak. */
void lxp_netfs_cancel(lxp_proc_t *p)
{
	lxp_slot_ref_t owner;
	if (lxp_guest_view_slot(p, &owner) != LXP_OK)
		return;
	int ri = (p && p->wait.kind == LXP_WAIT_NETFS) ? p->wait.data.io.request : -1;
	if (p && p->wait.kind == LXP_WAIT_NETFS)
		p->wait.data.io.request = -1;
	if (ri < 0 || ri >= NETFS_NREQ)
		return;
	struct netfs_req *r = &g_req[ri];
	if (!lxp_slot_ref_equal(r->owner, owner))
		return; /* the slot was already reclaimed / reused for another proc */
	r->owner = lxp_slot_ref_none(); /* a late reply cannot target a recycled guest */
	r->ubuf = 0;
	if (r->state != REQ_INFLIGHT) {
		/* not on the wire (QUEUED or DONE): reclaim now, releasing any walked fid. */
		if (r->fid > 0)
			clunk_enqueue(r->fid);
		if (r->op == LXP_NETFSW_OPEN && r->oi >= 0)
			g_open[r->oi].used = 0;
		r->fid = -1;
		r->state = REQ_FREE;
	}
}

#if LXP_ENABLE_NETFS_EXEC
/* ---- exec off the mount: fetch the whole ELF into the engine staging buffer ---- */
long lxp_netfs_exec_fetch(lxp_proc_t *p, const char *abspath)
{
	const char *rp = relpath(abspath);
	if (strlen(rp) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	size_t cap = 0;
	g_exec_buf = lxp_exec_stage(&cap);
	if (!g_exec_buf || cap == 0)
		return -LXP_ENOMEM; /* no staging buffer on this build */
	g_exec_cap = cap;
	g_exec_size = 0;
	struct netfs_req *r = req_new(p, LXP_NETFSW_EXECFETCH);
	if (!r)
		return -LXP_EMFILE;
	strcpy(r->path, rp);
	r->off = 0;
	p->wait.data.io.object = -1;
	return 0; /* parked */
}

const uint8_t *lxp_netfs_exec_image(size_t *size)
{
	if (size)
		*size = g_exec_size;
	return g_exec_buf;
}
#endif /* LXP_ENABLE_NETFS_EXEC */

/* ---- coordinator: retry a parked op / periodic pump ------------------------ */
long lxp_netfs_retry(lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_NETFS)
		return -LXP_EINVAL;
	lxp_slot_ref_t owner;
	if (lxp_guest_view_slot(p, &owner) != LXP_OK)
		return -LXP_ESRCH;
	int ri = p->wait.data.io.request;
	if (ri < 0 || ri >= NETFS_NREQ)
		return -LXP_EBADF;
	struct netfs_req *r = &g_req[ri];
	if (!lxp_slot_ref_equal(r->owner, owner))
		return -LXP_ESTALE;
	uint64_t now = 0;
	lxp_time_us(&now);
	pump(p, now);

	if (r->state != REQ_DONE)
		return -LXP_EAGAIN; /* still in flight */

	long result = r->result;
	uint8_t op = r->op;
	int oi = r->oi;
	int flags = r->flags;
	r->state = REQ_FREE;
	p->wait.data.io.request = -1;

	if (op == LXP_NETFSW_OPEN && result >= 0) {
		int fd = lxp_fd_install(p, LXP_FD_NET, oi, flags);
		if (fd < 0) {
			lxp_netfs_close(oi);
			return -LXP_EMFILE;
		}
		return fd;
	}
#if LXP_ENABLE_NETFS_EXEC
	if (op == LXP_NETFSW_EXECFETCH && result >= 0) {
		/* Preflight the complete staged image while the old program and fd table
		 * are still intact. A malformed fetch returns ENOEXEC to execve; only a
		 * loadable image may advance to the coordinator's commit point. */
		if (lxp_loader_validate_fdpic(g_exec_buf, g_exec_size, LXP_PROG_REGION_SIZE, 1) !=
		    LXP_OK)
			return -LXP_ENOEXEC;
		/* The ELF is staged and validated: complete this wait before publishing
		 * the EXEC intent. Returning 0 with that intent tells the run loop not
		 * to resume the old image. */
		(void)lxp_wait_complete(p, LXP_WAIT_NETFS);
		if (lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}) != 0)
			return -LXP_EAGAIN;
		p->exec_file_idx = LXP_NETFS_EXEC_SENTINEL;
		return 0;
	}
#endif
	return result;
}

void lxp_netfs_tick(uint64_t now_us)
{
	/*
	 * A guest-owned reply may marshal data. It is pumped only by
	 * lxp_netfs_retry(), while that owner's coordinator dispatch view is active.
	 * The periodic path remains responsible for reconnect and owner-less clunks.
	 */
	if (g_inflight >= 0 && g_req[g_inflight].owner.index >= 0)
		return;
	for (int i = 0; i < NETFS_NREQ; i++)
		if (g_req[i].state == REQ_QUEUED && g_req[i].owner.index >= 0)
			return;
	pump(NULL, now_us);
}

int lxp_netfs_busy(void)
{
	if (g_inflight >= 0 || g_clunk_head != g_clunk_tail)
		return 1;
	for (int i = 0; i < NETFS_NREQ; i++)
		if (g_req[i].state == REQ_QUEUED)
			return 1;
	return 0;
}

#ifdef LXP_FUZZ
/* ---- fuzz hooks (LXP_FUZZ only; never defined in production builds) --------
 * The 9P client holds ~20 file-scope statics with no single wholesale-reset entry, so an
 * in-process fuzzer would carry state across inputs. These two hooks let fuzz/harness_9p.c
 * (a) return the module to a known state between inputs and (b) drive one untrusted
 * R-message straight into the reply parser (handle_reply / parse_getattr, which bound
 * every field of an untrusted reply) without standing up a live connection + transport. */
void lxp_netfs_fuzz_reset(void)
{
	memset(g_fid_bm, 0, sizeof(g_fid_bm));
	memset(g_open, 0, sizeof(g_open));
	memset(g_req, 0, sizeof(g_req));
	memset(g_clunk_fid, 0, sizeof(g_clunk_fid));
	g_clunk_head = g_clunk_tail = 0;
	g_req_seq = 0;
	g_inflight = -1;
	g_generation = 1;
	g_msize = NETFS_MSIZE;
	g_conn = CONN_DOWN;
	g_reconnect_at_us = 0;
	g_conn_deadline_us = 0;
	g_txlen = g_txoff = g_rxlen = 0;
	memset(&g_mnt, 0, sizeof(g_mnt));
#if LXP_ENABLE_NETFS_EXEC
	g_exec_buf = 0;
	g_exec_cap = g_exec_size = 0;
#endif
}

/* Feed one untrusted R-message (type, body[blen]) into the reply parser as if it completed
 * an in-flight request of (op, step). @owner + @ubuf/@ulen model the parked guest the parser
 * marshals results into (caller-owned storage). */
void lxp_netfs_fuzz_feed(lxp_proc_t *owner, uintptr_t ubuf, size_t ulen, unsigned op, unsigned step,
			 int is64, int statkind, uint8_t type, const uint8_t *body, size_t blen)
{
	struct netfs_req r;
	memset(&r, 0, sizeof(r));
	r.state = REQ_INFLIGHT;
	r.op = (uint8_t)op;
	r.step = (uint8_t)step;
	r.owner = (lxp_slot_ref_t){.index = 0, .generation = 1};
	r.oi = 0;
	r.fid = 1;
	r.ubuf = ubuf;
	r.ulen = ulen;
	r.is64 = is64;
	r.statkind = statkind;
	r.path[0] = '/'; /* a plausible remote path for an Rwalk step's path_split */
	r.path[1] = 'a';
	r.path[2] = '\0';
	/* OPEN/READ/GETDENTS steps consult g_open[oi]; mark it live so open_slot() resolves. */
	g_open[0].used = 1;
	g_open[0].fid = 1;
	g_inflight = 0;
	handle_reply(&r, owner, type, body, blen);
}
#endif /* LXP_FUZZ */

/* ---- FD_NET file operations ---- */
static long fop_read_netfs(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	return lxp_netfs_read(p, s->file_idx, buf, len);
}

static long fop_write_netfs(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	(void)p;
	(void)s;
	(void)buf;
	(void)len;
	return -LXP_EROFS; /* read-only remote mount */
}

static long fop_lseek_netfs(lxp_proc_t *p, lxp_ofd_t *s, long off, int whence)
{
	(void)p;
	return lxp_netfs_lseek(s->file_idx, off, whence);
}

/* A Treaddir round-trip: parks, and the completion emits the records. */
static long fop_getdents_netfs(lxp_proc_t *p, lxp_ofd_t *s, lxp_dirent_sink_t *sink)
{
	return lxp_netfs_getdents(p, s->file_idx, sink->ubuf, sink->cap, sink->is64);
}

static long fop_fstat_netfs(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	(void)p;
	uint32_t mode;
	uint64_t size, mtime, ino;
	if (lxp_netfs_fstat(s->file_idx, &mode, &size, &mtime, &ino) != 0)
		return -LXP_EBADF;
	netfs_stat_record(st, mode, size, mtime, ino);
	return 0;
}

static void fop_close_netfs(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_netfs_close(s->file_idx); /* enqueue Tclunk for the backing fid */
}

/* Read-only mount: write is an explicit -EROFS rather than NULL (-EBADF). */
const lxp_file_ops_t lxp_netfs_fops = {
	.read = fop_read_netfs,
	.write = fop_write_netfs,
	.lseek = fop_lseek_netfs,
	.getdents = fop_getdents_netfs,
	.fstat = fop_fstat_netfs,
	.close = fop_close_netfs,
};

#endif /* LXP_ENABLE_NETFS */
