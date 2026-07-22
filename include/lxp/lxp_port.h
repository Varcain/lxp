/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * THE PORT INTERFACE. A host (any RTOS or bare-metal) runs the Linux personality
 * by filling three ops-structs — the OS/engine port, the net port, and the
 * display/input port — and passing them to lxp_run(). This is the lwIP sys_arch /
 * LVGL / FatFs diskio pattern: the module is host-agnostic C; everything that
 * differs per OS lives behind these function pointers.
 *
 * The module is single-instance (one run at a time). The ops are plain vtables
 * with no per-call context pointer: a port keeps whatever state it needs in its
 * own file-scope storage, exactly as an embedded host naturally would. (This
 * mirrors the proven per-engine vtable the personality has always used.)
 */

#ifndef LXP_PORT_H
#define LXP_PORT_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Incomplete types owned by the module's own headers (loader / run config /
 * saved register context). The port only ever passes pointers to these. */
typedef struct lxp_flat lxp_flat_t;             /* full def in lxp_loader.h  */
typedef struct lxp_run_config lxp_run_config_t; /* full def in lxp_run.h     */
typedef struct lxp_exec_capture lxp_exec_capture_t; /* full def in lxp_syscall.h */
struct lxp_resume_ctx;                          /* full def in lxp_run_internal.h */

/* Host-owned opaque handles: the module holds these, the port allocates the
 * backing storage. This is what removes the compile-time backend-storage
 * coupling — the module never embeds a backend-sized socket by value. */
typedef struct lxp_socket *lxp_socket_t;
typedef struct lxp_netif *lxp_netif_t;

/* ---- module-owned net value types (same numeric values as the OVE originals) */
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

/* Device-mmap attribute selectors for lxp_os_ops.map_device. */
#define LXP_MAP_NC 0u  /**< Non-cacheable. */
#define LXP_MAP_WT 1u  /**< Write-through. */
#define LXP_MAP_DEV 2u /**< Device / strongly-ordered. */

/* ─────────────────────────────────────────────────────────────────────────
 * (1) OS / engine port — the process-model substrate.
 *
 * The first 11 entries are the per-engine "how do I place program memory, spawn
 * a task, take a critical section" primitives the run loop drives on its hot
 * path. The trailing entries are genuine OS services (monotonic time, thread
 * introspection) and optional cache / rootfs / remote-exec hooks (NULL => the
 * feature quietly degrades, matching the old weak-symbol stubs).
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct lxp_os_ops {
	/* The engine owns prog_regions[]; return region `ridx`'s base. */
	uint8_t *(*region)(int ridx);
	/* Spawn slot `sidx` running the freshly-loaded `prog` at (entry, sp). */
	int (*spawn_launch)(int sidx, int ridx, const lxp_flat_t *prog, void *entry, void *sp,
			    void *stack_lo);
	/* Spawn slot `sidx` resuming at captured context `c` with r0 = r0val. */
	void (*spawn_resume)(int sidx, int ridx, const struct lxp_resume_ctx *c, long r0val);
	/* Abort (delete) slot `sidx`'s task. */
	void (*abort_slot)(int sidx);
	/* Sleep the run-loop task for `ms` milliseconds. */
	void (*sleep_ms)(unsigned ms);
	/* Coordinator critical section: mask the program svc exception. */
	void (*crit_enter)(void);
	void (*crit_exit)(void);
	/* Run-loop wakeup: dispatch posts when a program parks; the coordinator
	 * blocks in event_wait (ms timeout for sleeper deadlines / snapshot). */
	void (*event_post)(void);
	void (*event_wait)(unsigned ms);
	/* FDPIC dynamic-linking scratch pool for region `ridx` (ld.so mmaps libc
	 * here). NULL => dynamic execs can't launch on that engine. */
	uint8_t *(*dyn_pool)(int ridx, size_t *size);
	/* Privileged cold storage for slot `sidx`'s transient execve argv/env
	 * capture. Required by the coordinator; ports may place it in external RAM. */
	lxp_exec_capture_t *(*exec_capture)(int sidx);
	/* Map [addr,addr+size) RW into slot sidx's view with attrs (LXP_MAP_*).
	 * NULL => a device mmap returns -ENODEV. */
	int (*map_device)(int sidx, uintptr_t addr, size_t size, unsigned attrs);

	/* Monotonic clock (required). *out = microseconds / nanoseconds since boot. */
	int (*time_us)(uint64_t *out);
	int (*time_ns)(uint64_t *out);
	/* Host kernel-thread snapshot for the ps/top /proc view. NULL => omitted. */
	int (*thread_list)(struct lxp_thread_info *out, size_t max, size_t *n);

	/* Guest-memory cache maintenance (NULL => no-op; a coherent host needs none). */
	void (*cache_clean)(const void *base, size_t len);
	void (*cache_invalidate)(const void *base, size_t len);
	/* Give the coordinator a coherent (cacheable) view of guest region `ridx`
	 * (its program region + dyn_pool) before it services that guest's DEFERRED
	 * syscalls / parked-op retries, so the coordinator's reads and writes of the
	 * guest's buffers are coherent with the guest's own cached view (no per-call
	 * clean/invalidate needed). Only the single active region need be mapped; the
	 * coordinator services one slot at a time. On a host whose coordinator already
	 * shares the guest's cacheable mapping this is a no-op (NULL). */
	void (*coord_map)(int ridx);
	/* Tell the engine where the (XIP) rootfs image lives, for PC discrimination. */
	void (*rootfs_window)(const void *base, size_t len);
	/* Staging buffer for fetching a remote exec image. NULL => no remote exec. */
	uint8_t *(*exec_stage)(size_t *cap);

	/* Optional per-run bring-up / teardown, invoked by lxp_run() around the run
	 * loop. A host homes its engine-specific setup here — create the coordinator
	 * semaphore, enable Bus/UsageFault, program the MPU, attach the svc IRQ — and
	 * its restore in teardown. NULL => skipped. prepare() returning < 0 aborts the
	 * run (lxp_run returns LXP_RUN_ELAUNCH); teardown() runs after the loop exits. */
	int (*prepare)(void);
	void (*teardown)(void);

	/* Fill every byte in [buf, buf+len) from a host entropy source. The callback
	 * runs on the privileged coordinator task, must have a finite host-defined
	 * deadline, and returns LXP_OK only when the entire buffer is valid. A port
	 * without trustworthy entropy leaves this NULL; the guest then fails closed
	 * instead of receiving a predictable in-core fallback. Kept at the end so
	 * extending the source-level vtable does not move existing members. */
	int (*random_fill)(void *buf, size_t len);

	/* Host system-heap snapshot for sysinfo(2) and /proc/meminfo. NULL reports
	 * zero memory rather than inventing a fixed total. Kept at the end so source
	 * initializers for older ports remain valid. */
	int (*mem_stats)(struct lxp_mem_stats *out);

	/* Immutable host identity for the utsname.version field and /proc/version,
	 * e.g. "Zephyr 4.4.0 ove-1a2b3c4 lxp-5d6e7f8". The returned string must
	 * remain valid for the run; lxp truncates it to Linux's 64-byte field. */
	const char *(*system_version)(void);
} lxp_os_ops_t;

/* ─────────────────────────────────────────────────────────────────────────
 * (2) Net port — handle-based sockets. The host owns the socket storage; the
 * module holds only opaque handles. Covers the full 17 socket + 5 netif calls.
 * All calls happen on the coordinator thread (serialized), so a port needs no
 * internal locking.
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct lxp_net_ops {
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

	lxp_netif_t netif; /**< eth0 the SIOC* ioctls act on; host sets it before the run. */
} lxp_net_ops_t;

/* ─────────────────────────────────────────────────────────────────────────
 * (3) Display / input port — framebuffer + touch. Geometry is injected via
 * lxp_config_t (no board_desc.h). touch_* NULL => no touch device.
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct lxp_fb_info {
	uint16_t width, height, stride_bytes;
	uint32_t fmt; /**< pixel format selector (0 => RGB565). */
	uint32_t smem_len;
} lxp_fb_info_t;

/* A validated DMA2D fill/blit/blend, filled by the /dev/dma2d device from a guest
 * descriptor AFTER every plane address was bounds-checked against the guest region.
 * Addresses are absolute (coordinator-side); scalars are the validated ABI enums
 * (LXP_DMA2D_* in lxp_uapi.h). The board's dma2d_submit maps enums to DMA2D
 * registers + owns cache coherency. */
typedef struct lxp_dma2d_op {
	uint32_t mode, w, h;
	uintptr_t out_addr;
	uint32_t out_offset, out_cf, out_color;
	uintptr_t fg_addr;
	uint32_t fg_offset, fg_cf, fg_color, fg_alpha_mode, fg_alpha;
	uintptr_t bg_addr;
	uint32_t bg_offset, bg_cf, bg_color, bg_alpha_mode, bg_alpha;
} lxp_dma2d_op_t;

typedef struct lxp_display_ops {
	int (*fb_init)(void);
	int (*fb_get_info)(lxp_fb_info_t *info);
	void *(*fb_get_buffer)(void);
	void (*fb_flush)(int x, int y, int w, int h);
	void (*fb_present)(void);
	/* Optional 2D-accelerator submit (/dev/dma2d); NULL if the board has no DMA2D
	 * -> the device returns -ENOSYS and the guest falls back to software render. */
	int (*dma2d_submit)(const lxp_dma2d_op_t *op);
	int (*touch_init)(void);
	int (*touch_read)(int *x, int *y, int *pressed);
} lxp_display_ops_t;

/* ─────────────────────────────────────────────────────────────────────────
 * (4) Run config — geometry + optional sizing overrides (0 => lxp_config.h).
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct lxp_config {
	uint16_t display_width, display_height; /**< 0 => defaults. */
	uint32_t prog_region_size, dyn_pool_size;
	uint16_t nreg, nslot, npipe, pipe_buf, pty_buf;
} lxp_config_t;

/* ---- entry points ------------------------------------------------------------
 * The personality's actual run entry (lxp_run), lxp_net_set_netif, and
 * lxp_netfs_mount_config are declared in the module's own API headers (lxp_run.h,
 * lxp_net.h, lxp_netfs.h). The current host binding fills the ops via the module
 * globals (g_lxp_net_ops / g_lxp_disp_ops + the per-engine lxp_engine vtable) set
 * before the run, rather than passing them to lxp_run(); the ops structs above are
 * the contract those bindings implement. */

#ifdef __cplusplus
}
#endif

#endif /* LXP_PORT_H */
