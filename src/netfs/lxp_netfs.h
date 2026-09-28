/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_NETFS_H
#define LXP_NETFS_H

/**
 * @file lxp_netfs.h
 * @defgroup lxp_linux_netfs Linux personality remote filesystem (9P2000.L)
 * @ingroup lxp_linux
 * @brief A read-only remote filesystem mounted under a path (e.g. /mnt/pi).
 *
 * A single mount over a coordinator-owned, non-blocking TCP connection to a 9P
 * server (diod on a Raspberry Pi). The guest browses it transparently — the
 * FD_NET branches of the syscall handlers route open/read/lseek/close/stat/
 * getdents on a /mnt/pi path to this layer, which speaks 9P2000.L and returns
 * Linux-ABI results. It mirrors the socket layer (src/net/lxp_net.c): a
 * refcounted per-open pool (each = a 9P fid + cursor), fork/dup share an open,
 * and the last close clunks the fid.
 *
 * Blocking model: every remote-touching op needs a Pi round-trip, while syscall
 * handlers run on the privileged coordinator and must remain bounded. An op
 * submits a 9P request, publishes @c LXP_WAIT_NETFS, and returns 0 (parked); the
 * coordinator pumps the transport via lxp_netfs_retry and resumes the guest via
 * spawn_resume(...,result). Ops answerable from cached open-state (fstat,
 * lseek) complete during the same coordinator dispatch. The transport is
 * serialized: one 9P request in flight, a FIFO of the rest.
 *
 * @note Requires @c LXP_ENABLE_NETFS.
 * @{
 */

#include <stddef.h>
#include <stdint.h>

#include "lxp_guest.h"
#include "lxp/lxp_netfs_config.h"
#include "proc/lxp_proc_fwd.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Netfs-wait op codes stored in @c proc->wait.op.
 *  Shared with the run loop (src/lxp_run.c). */
#define LXP_NETFSW_OPEN 1u     /**< open: Twalk -> Tlgetattr -> Tlopen -> install fd. */
#define LXP_NETFSW_READ 2u     /**< read: Tread -> copy to guest. */
#define LXP_NETFSW_GETDENTS 3u /**< getdents64: Treaddir -> emit dirent64 records. */
#define LXP_NETFSW_STAT 4u     /**< path stat: Twalk -> Tlgetattr -> Tclunk -> fill guest stat. */
#define LXP_NETFSW_EXECFETCH \
	5u /**< Read a whole remote ELF into the exec staging buffer. */

/* ---- boot: mount config + connection init (coordinator thread) ------------- */

/** @brief Copy this run's optional topology and initiate a non-blocking connection.
 * Coordinator thread only. NULL disables the mount. A down server is non-fatal:
 * the configured mount reconnects lazily and boot never waits for the server. */
int lxp_netfs_init(const lxp_netfs_config_t *config);

/** @brief Close the transport and discard all per-run requests, opens and fids.
 *
 * Called after every guest has been stopped and its descriptors closed. The
 * Mount topology is discarded as well, so a later run cannot inherit it.
 */
void lxp_netfs_shutdown(void);

/* ---- syscall-layer <-> netfs-core interface (called from lxp_syscall.c) ---- */

/** @return mount id (>=0) if @p abspath is at or under the mount point, else -1. */
int lxp_netfs_lookup(const char *abspath);

/** open(2): submit Twalk->Tlgetattr->Tlopen for the /mnt path; parks in an
 *  @c LXP_WAIT_NETFS state with @c LXP_NETFSW_OPEN, or returns a negative
 *  Linux errno inline (path too long, no mount). */
long lxp_netfs_open(lxp_proc_t *p, const char *abspath, int flags);

/** read(2)/pread(2): submit Tread at @p off (SIZE_MAX off => use the fd cursor); parks. */
long lxp_netfs_read(lxp_proc_t *p, int oi, void *ubuf, size_t len);

/** getdents64(2): submit Treaddir from the open's dir cursor; parks. @p is64 selects the
 *  64-bit dirent layout (getdents64) vs the 32-bit one (getdents). */
long lxp_netfs_getdents(lxp_proc_t *p, int oi, uintptr_t ubuf, size_t cap, int is64);

/** stat/lstat/fstatat/statx on a /mnt path: submit Twalk->Tlgetattr->Tclunk; parks. On
 *  completion the retry marshals the attrs into the guest buffer via lxp_netfs_fill_stat.
 *  @p statkind: 0 = stat64/newfstatat kstat, 1 = statx. */
long lxp_netfs_stat(lxp_proc_t *p, const char *abspath, uintptr_t ustat, int statkind);

/** Cached open attributes for fstat/statx(fd) + lseek(SEEK_END) — no round-trip.
 *  Fills any non-NULL out param. @return 0, or -1 if @p oi is not a live open. */
int lxp_netfs_fstat(int oi, uint32_t *mode, uint64_t *size, uint64_t *mtime, uint64_t *ino);

/** lseek(2) on an FD_NET fd: cursor math against the shared open offset + cached size.
 *  No round-trip. @return the new absolute offset, or a negative Linux errno. */
long lxp_netfs_lseek(int oi, long off, int whence);

/** Drop a reference on open @p oi (close/exit); the last ref enqueues a background Tclunk.
 *  Never parks — close(2) always completes at once. */
void lxp_netfs_close(int oi);

/** Retry a parked netfs op for the coordinator: pump the transport once, advance the
 *  in-flight request, and return the completed Linux-ABI result or -LXP_EAGAIN. */
long lxp_netfs_retry(lxp_proc_t *p);

/** Abandon @p p's in-flight netfs op after a signal interrupts the parked guest (called from
 *  the run loop's parked-signal delivery). Detaches the owner + guest buffer so a late 9P
 *  reply is dropped rather than marshaled into a gone/resumed process and the
 *  request index in the typed wait is invalidated. */
void lxp_netfs_cancel(lxp_proc_t *p);

/* ---- run-loop <-> netfs interface ------------------------------------------ */

/** Coordinator periodic work: pump the transport (drain background clunks, service the
 *  reconnect backoff) even when no proc is parked. Called from the run loop each pass. */
void lxp_netfs_tick(uint64_t now_us);

/** 1 if any netfs request is outstanding (so the run loop holds its ≤5 ms retry tick). */
int lxp_netfs_busy(void);

/* ---- implemented in lxp_syscall.c, called by the netfs retry --------- */

/** Marshal remote attributes into the guest's stat/statx buffer (the netfs retry owns the
 *  9P transport; the syscall TU owns the kstat/statx layout + lxp_guest_access_ok). @return 0 or -errno. */
long lxp_netfs_fill_stat(lxp_proc_t *p, uintptr_t ustat, int statkind, uint32_t mode, uint64_t size,
			 uint64_t mtime, uint64_t ino);

/* ---- remote executable staging (LXP_ENABLE_NETFS_EXEC) --------------- */
#if LXP_ENABLE_NETFS_EXEC
/** exec_file_idx marker: the image to launch lives in the netfs exec staging buffer (RAM),
 *  not the rootfs table. The run loop's EV_EXEC sources it via lxp_netfs_exec_image. */
#define LXP_NETFS_EXEC_SENTINEL (-2)

/** execve of a /mnt path: submit walk/getattr/open + chained Tread of the whole ELF into the
 *  staging buffer; parks with @c LXP_NETFSW_EXECFETCH. On completion the retry publishes an
 *  @c LXP_INTENT_EXEC plus @c exec_file_idx=SENTINEL and the run loop launches the staged image.
 *  Returns 0 (parked) or a negative Linux errno inline. */
long lxp_netfs_exec_fetch(lxp_proc_t *p, const char *abspath);
/** The staged remote ELF after a completed EXECFETCH: bytes + size for launch(). */
const uint8_t *lxp_netfs_exec_image(size_t *size);

/** Internal adapter to the active lxp_os_ops_t::exec_stage provider. */
uint8_t *lxp_exec_stage(size_t *cap);
#endif

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* LXP_NETFS_H */
