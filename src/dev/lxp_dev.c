/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Linux-personality character-device core: a registry of /dev nodes + a pooled
 * per-open state table, and the routing the FD_DEV branches of the syscall
 * handlers call into. Class drivers register an lxp_dev and use the provider
 * contract appropriate to their device family.
 *
 * Blocking is deferred, never inline: a driver op that would block returns
 * -EAGAIN; this core parks the caller (LXP_WAIT_DEVICE) and the run-loop
 * coordinator retries via lxp_dev_retry — mirroring the pipe park/retry.
 */

#include "lxp/lxp_config.h"

#if LXP_ENABLE_DEV

#include "dev/lxp_dev.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_vfs.h"
#include "lxp/lxp_display_ops.h"
#include "proc/lxp_proc.h"
#include "lxp_provider.h"

#include <limits.h>
#include <string.h>

/* Device wait operations (LXP_DEVW_*) live in lxp_dev.h, shared with
 * the run loop so it can special-case DEVW_MMAP (needs the engine map_device seam). */

#define LXP_NDEV 16	/* max registered device nodes */
#define LXP_NDEVOPEN 16 /* max concurrent device opens (pooled) */
#define LXP_NDEVTICK 4	/* max coordinator-tick callbacks (fb flush, touch poll) */

static struct lxp_dev g_lnx_devs[LXP_NDEV];
static int g_lnx_ndev;
static struct lxp_dev_open g_lnx_devopen[LXP_NDEVOPEN];
static void (*g_lnx_devtick[LXP_NDEVTICK])(uint64_t now_us);
static int g_lnx_ndevtick;

#if LXP_ENABLE_DEV_INPUT
void lxp_dev_input_run_end(void);
#endif

static uint32_t dev_mode(const struct lxp_dev *dev)
{
	return dev->mode ? dev->mode : (LXP_S_IFCHR | 0666u);
}

static int dev_present(struct lxp_dev *dev)
{
	return !dev->ops->present || dev->ops->present(dev);
}

static uint64_t dev_size(struct lxp_dev *dev)
{
	return dev->ops->size ? dev->ops->size(dev) : dev->size;
}

/* ---- registration ---------------------------------------------------------- */
int lxp_dev_register(const struct lxp_dev *dev)
{
	if (!dev || !dev->path || !dev->ops)
		return -LXP_EINVAL;
	if (g_lnx_ndev >= LXP_NDEV)
		return -LXP_EMFILE;
	/* A re-register of the same path replaces the entry (idempotent autoreg). */
	for (int i = 0; i < g_lnx_ndev; i++)
		if (strcmp(g_lnx_devs[i].path, dev->path) == 0) {
			g_lnx_devs[i] = *dev;
			return 0;
		}
	g_lnx_devs[g_lnx_ndev++] = *dev;
	return 0;
}

/* Register a coordinator-tick callback (fb flush @ ~30 Hz, touch poll @ ~60 Hz).
 * Called from a class driver's autoreg. */
void lxp_dev_tick_register(void (*fn)(uint64_t now_us))
{
	if (!fn)
		return;
	/* Autoregistration runs once per lxp_run(). Keep the persistent registry
	 * idempotent too: otherwise every restart adds another invocation of the
	 * same framebuffer/touch callback until the table fills. */
	for (int i = 0; i < g_lnx_ndevtick; i++)
		if (g_lnx_devtick[i] == fn)
			return;
	if (g_lnx_ndevtick < LXP_NDEVTICK)
		g_lnx_devtick[g_lnx_ndevtick++] = fn;
}

int lxp_dev_lookup(const char *abspath)
{
	for (int i = 0; i < g_lnx_ndev; i++)
		if (dev_present(&g_lnx_devs[i]) && strcmp(g_lnx_devs[i].path, abspath) == 0)
			return i;
	return -1;
}

int lxp_dev_count(void)
{
	return g_lnx_ndev;
}

const char *lxp_dev_path(int i, uint32_t *mode)
{
	if (i < 0 || i >= g_lnx_ndev)
		return NULL;
	if (!dev_present(&g_lnx_devs[i]))
		return NULL;
	if (mode)
		*mode = dev_mode(&g_lnx_devs[i]);
	return g_lnx_devs[i].path;
}

/* ---- open pool ------------------------------------------------------------- */
static struct lxp_dev_open *open_slot(int oi)
{
	if (oi < 0 || oi >= LXP_NDEVOPEN || !g_lnx_devopen[oi].used)
		return NULL;
	return &g_lnx_devopen[oi];
}

long lxp_dev_open_new(lxp_proc_t *p, int devidx, int flags)
{
	(void)p;
	if (devidx < 0 || devidx >= g_lnx_ndev)
		return -LXP_ENOENT;
	int oi = -1;
	for (int i = 0; i < LXP_NDEVOPEN; i++)
		if (!g_lnx_devopen[i].used) {
			oi = i;
			break;
		}
	if (oi < 0)
		return -LXP_EMFILE;
	struct lxp_dev_open *o = &g_lnx_devopen[oi];
	memset(o, 0, sizeof(*o));
	o->used = 1;
	o->dev = (uint8_t)devidx;
	o->oflags = (uint16_t)flags;
	struct lxp_dev *d = &g_lnx_devs[devidx];
	if (!dev_present(d)) {
		o->used = 0;
		return -LXP_ENODEV;
	}
	if (d->ops->open) {
		long r = d->ops->open(d, o, flags);
		if (r < 0) {
			o->used = 0;
			return r;
		}
	}
	return oi;
}

void lxp_dev_close(int oi)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (d->ops->release)
		d->ops->release(d, o);
	o->used = 0;
}

/* ---- read / write / ioctl (with deferred-block park) ----------------------- */
long lxp_dev_read(lxp_proc_t *p, int oi, void *buf, size_t len)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	if ((o->oflags & LXP_O_ACCMODE) == LXP_O_WRONLY)
		return -LXP_EBADF; /* a write-only fd is not readable */
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (!d->ops->read)
		return -LXP_EINVAL;
	long r = d->ops->read(d, o, p, buf, len);
	if (r == -LXP_EAGAIN) {
		if (o->oflags & LXP_O_NONBLOCK)
			return -LXP_EAGAIN;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_DEVICE,
			.op = LXP_DEVW_READ,
			.data.io.object = oi,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0;
	}
	return r;
}

long lxp_dev_write(lxp_proc_t *p, int oi, const void *buf, size_t len)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	if ((o->oflags & LXP_O_ACCMODE) == LXP_O_RDONLY)
		return -LXP_EBADF; /* a read-only fd is not writable */
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (!d->ops->write)
		return -LXP_EINVAL;
	long r = d->ops->write(d, o, p, buf, len);
	if (r == -LXP_EAGAIN) {
		if (o->oflags & LXP_O_NONBLOCK)
			return -LXP_EAGAIN;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_DEVICE,
			.op = LXP_DEVW_WRITE,
			.data.io.object = oi,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0;
	}
	return r;
}

long lxp_dev_ioctl(lxp_proc_t *p, int oi, unsigned long cmd, unsigned long arg)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (!d->ops->ioctl)
		return -LXP_ENOTTY;
	long r = d->ops->ioctl(d, o, p, cmd, arg);
	if (r == -LXP_EAGAIN) {
		if (o->oflags & LXP_O_NONBLOCK)
			return -LXP_EAGAIN;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_DEVICE,
			.op = LXP_DEVW_IOCTL,
			.data.io.object = oi,
			.data.io.buffer = arg,
			.data.io.command = cmd,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0;
	}
	return r;
}

/* mmap(2) a device buffer: the driver's .mmap op resolves the physical range +
 * cache attrs (e.g. /dev/fb0 -> the LTDC framebuffer, Normal-NC), then we PARK on
 * DEVW_MMAP. Adding the unprivileged MPU region over that range is a domain/TCB edit
 * that is not safe from the svc-exception dispatch, so the run-loop coordinator does
 * it (eng->map_device) and resumes the proc with r0 = the mapped address. */
long lxp_dev_mmap(lxp_proc_t *p, int oi, size_t len, uint32_t pgoff)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (!d->ops->mmap)
		return -LXP_ENODEV; /* not mappable -> caller falls back to the write path */
	uintptr_t phys = 0;
	unsigned attrs = LXP_MAP_NC;
	long r = d->ops->mmap(d, o, p, len, pgoff, &phys, &attrs);
	if (r < 0)
		return r;
	lxp_wait_t wait = {
		.kind = LXP_WAIT_DEVICE,
		.op = LXP_DEVW_MMAP,
		.data.io.object = oi,
		.data.io.buffer = phys,
		.data.io.length = len,
		.data.io.command = attrs,
	};
	if (lxp_wait_begin(p, &wait) != 0)
		return -LXP_EAGAIN;
	return 0;
}

/* Positioned I/O drives the same operation with a temporary cursor. Async
 * devices retain the 64-bit offset in the typed wait record for retry. */
static long dev_positioned(lxp_proc_t *p, int oi, void *buf, size_t len, uint64_t off,
			   int write)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if ((write && !d->ops->write) || (!write && !d->ops->read))
		return -LXP_EINVAL;
	uint64_t save = o->pos;
	o->pos = off;
	long r = write ? d->ops->write(d, o, p, buf, len)
		       : d->ops->read(d, o, p, buf, len);
	o->pos = save;
	if (r == -LXP_EAGAIN) {
		if (o->oflags & LXP_O_NONBLOCK)
			return r;
		lxp_wait_t wait = {
			.kind = LXP_WAIT_DEVICE,
			.op = write ? LXP_DEVW_PWRITE : LXP_DEVW_PREAD,
			.data.io.object = oi,
			.data.io.buffer = (uintptr_t)buf,
			.data.io.length = len,
			.data.io.offset = off,
		};
		if (lxp_wait_begin(p, &wait) != 0)
			return -LXP_EAGAIN;
		return 0;
	}
	return r;
}

long lxp_dev_pread(lxp_proc_t *p, int oi, void *buf, size_t len, uint64_t off)
{
	return dev_positioned(p, oi, buf, len, off, 0);
}

long lxp_dev_pwrite(lxp_proc_t *p, int oi, const void *buf, size_t len, uint64_t off)
{
	return dev_positioned(p, oi, (void *)buf, len, off, 1);
}

unsigned lxp_dev_poll(int oi)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return 0;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	return d->ops->poll ? d->ops->poll(d, o) : (LXP_POLLIN | LXP_POLLOUT);
}

long lxp_dev_lseek(int oi, long off, int whence)
{
	uint64_t position = 0;
	int rc = lxp_dev_llseek(oi, off, whence, &position);
	if (rc < 0)
		return rc;
	if (position > (uint64_t)LONG_MAX)
		return -LXP_EOVERFLOW;
	return (long)position;
}

int lxp_dev_llseek(int oi, int64_t off, int whence, uint64_t *position)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o || !position)
		return -LXP_EBADF;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	uint64_t extent = dev_size(d);
	if (extent == 0)
		return -LXP_ESPIPE; /* a non-seekable device (no fixed extent) */
	uint64_t base;
	switch (whence) {
	case LXP_SEEK_SET:
		base = 0;
		break;
	case LXP_SEEK_CUR:
		base = o->pos;
		break;
	case LXP_SEEK_END:
		base = extent;
		break;
	default:
		return -LXP_EINVAL;
	}
	uint64_t pos;
	if (off < 0) {
		uint64_t magnitude = (uint64_t)(-(off + 1)) + 1u;
		if (magnitude > base)
			return -LXP_EINVAL;
		pos = base - magnitude;
	} else {
		if ((uint64_t)off > UINT64_MAX - base)
			return -LXP_EOVERFLOW;
		pos = base + (uint64_t)off;
	}
	if (pos > extent)
		return -LXP_EINVAL;
	o->pos = pos;
	*position = pos;
	return 0;
}

long lxp_dev_sync(lxp_proc_t *p, int oi)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (!d->ops->sync)
		return 0;
	long r = d->ops->sync(d, o, p);
	if (r != -LXP_EAGAIN)
		return r;
	if (o->oflags & LXP_O_NONBLOCK)
		return r;
	lxp_wait_t wait = {.kind = LXP_WAIT_DEVICE,
			   .op = LXP_DEVW_SYNC,
			   .data.io.object = oi};
	if (lxp_wait_begin(p, &wait) != 0)
		return -LXP_EAGAIN;
	return 0;
}

void lxp_dev_cancel(lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_DEVICE)
		return;
	struct lxp_dev_open *o = open_slot(p->wait.data.io.object);
	if (!o)
		return;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (d->ops->cancel)
		d->ops->cancel(d, o, p);
}

int lxp_dev_defer_caught_signal(const lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_DEVICE)
		return 0;
	struct lxp_dev_open *o = open_slot(p->wait.data.io.object);
	if (!o)
		return 0;
	return (dev_mode(&g_lnx_devs[o->dev]) & LXP_S_IFMT) == LXP_S_IFBLK;
}

/* ---- stat / getdents helpers ----------------------------------------------- */
void lxp_dev_fstat(int oi, uint32_t *mode, uint64_t *rdev, uint64_t *size)
{
	struct lxp_dev_open *o = open_slot(oi);
	if (!o) {
		if (mode)
			*mode = LXP_S_IFCHR | 0666u;
		if (rdev)
			*rdev = 0;
		if (size)
			*size = 0;
		return;
	}
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	if (mode)
		*mode = dev_mode(d);
	if (rdev)
		*rdev = ((uint64_t)d->major << 8) | d->minor;
	if (size)
		*size = dev_size(d);
}

int lxp_dev_stat_path(const char *abspath, uint32_t *mode, uint64_t *rdev)
{
	int di = lxp_dev_lookup(abspath);
	if (di < 0)
		return -1;
	struct lxp_dev *d = &g_lnx_devs[di];
	if (mode)
		*mode = dev_mode(d);
	if (rdev)
		*rdev = ((uint64_t)d->major << 8) | d->minor;
	return di;
}

/* ---- coordinator: retry parked device I/O + periodic tick ------------------ */
long lxp_dev_retry(lxp_proc_t *p)
{
	if (!p || p->wait.kind != LXP_WAIT_DEVICE)
		return -LXP_EINVAL;
	int oi = p->wait.data.io.object;
	struct lxp_dev_open *o = open_slot(oi);
	if (!o)
		return -LXP_EBADF;
	struct lxp_dev *d = &g_lnx_devs[o->dev];
	switch (p->wait.op) {
	case LXP_DEVW_READ:
		return d->ops->read ? d->ops->read(d, o, p, (void *)p->wait.data.io.buffer,
						   p->wait.data.io.length)
				    : -LXP_EINVAL;
	case LXP_DEVW_WRITE:
		return d->ops->write ? d->ops->write(d, o, p, (const void *)p->wait.data.io.buffer,
						     p->wait.data.io.length)
				     : -LXP_EINVAL;
	case LXP_DEVW_IOCTL:
		return d->ops->ioctl ? d->ops->ioctl(d, o, p, p->wait.data.io.command,
						     p->wait.data.io.buffer)
					     : -LXP_ENOTTY;
	case LXP_DEVW_PREAD: {
		uint64_t save = o->pos;
		o->pos = p->wait.data.io.offset;
		long rc = d->ops->read
				  ? d->ops->read(d, o, p, (void *)p->wait.data.io.buffer,
						 p->wait.data.io.length)
				  : -LXP_EINVAL;
		o->pos = save;
		return rc;
	}
	case LXP_DEVW_PWRITE: {
		uint64_t save = o->pos;
		o->pos = p->wait.data.io.offset;
		long rc = d->ops->write
				  ? d->ops->write(d, o, p, (const void *)p->wait.data.io.buffer,
						  p->wait.data.io.length)
				  : -LXP_EINVAL;
		o->pos = save;
		return rc;
	}
	case LXP_DEVW_SYNC:
		return d->ops->sync ? d->ops->sync(d, o, p) : 0;
	default:
		return -LXP_EINVAL;
	}
}

void lxp_dev_tick(uint64_t now_us)
{
	for (int i = 0; i < g_lnx_ndevtick; i++)
		g_lnx_devtick[i](now_us);
}

void lxp_dev_run_begin(void)
{
	/* Static registrations deliberately survive sequential runs. Open instances
	 * and provider-driven ticks do not: they refer to the active provider table. */
	memset(g_lnx_devopen, 0, sizeof(g_lnx_devopen));
	memset(g_lnx_devtick, 0, sizeof(g_lnx_devtick));
	g_lnx_ndevtick = 0;
}

void lxp_dev_run_end(void)
{
	/* Normal process teardown has already closed these. Keep this bounded sweep
	 * as the provider-lifecycle backstop for launch/fault paths. */
	for (int i = 0; i < LXP_NDEVOPEN; i++)
		while (g_lnx_devopen[i].used)
			lxp_dev_close(i);
#if LXP_ENABLE_DEV_INPUT
	lxp_dev_input_run_end();
#endif
	memset(g_lnx_devtick, 0, sizeof(g_lnx_devtick));
	g_lnx_ndevtick = 0;
}

/* ---- Kconfig-auto class registration --------------------------------------- */
/* Each class driver (fb, input, ...) provides lxp_dev_autoreg_<c>() behind its
 * LXP_ENABLE_DEV_<C>. Gate the CALLS on the same config rather than relying on
 * weak no-op fallbacks: a weak fallback here would be bound to the same-TU definition
 * by GCC's default -fno-semantic-interposition, and the class object — reachable only
 * through this hook — would never be pulled from the archive (so /dev/fb0 /
 * /dev/input/event0 would silently not register on an archive+GC link, e.g. NuttX).
 * Gating makes the call a direct reference to the compiled class's strong definition.
 * Run once on the coordinator thread, where bounded provider initialization is
 * legal. */
#if LXP_ENABLE_DEV_FB
void lxp_dev_autoreg_fb(void);
#endif
#if LXP_ENABLE_DEV_DMA2D
void lxp_dev_autoreg_dma2d(void);
#endif
#if LXP_ENABLE_DEV_INPUT
void lxp_dev_autoreg_input(void);
#endif
#if LXP_ENABLE_BLOCK
void lxp_dev_autoreg_block(void);
#endif

void lxp_dev_autoreg_all(void)
{
#if LXP_ENABLE_DEV_FB
	lxp_dev_autoreg_fb();
#endif
#if LXP_ENABLE_DEV_DMA2D
	lxp_dev_autoreg_dma2d();
#endif
#if LXP_ENABLE_DEV_INPUT
	lxp_dev_autoreg_input();
#endif
#if LXP_ENABLE_BLOCK
	lxp_dev_autoreg_block();
#endif
}

/* ---- FD_DEV file operations ---- */
static long fop_read_dev(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	return lxp_dev_read(p, s->file_idx, buf, len);
}

static long fop_write_dev(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len)
{
	return lxp_dev_write(p, s->file_idx, buf, len);
}

static long fop_pread_dev(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len, uint64_t off)
{
	return lxp_dev_pread(p, s->file_idx, buf, len, off);
}

static long fop_pwrite_dev(lxp_proc_t *p, lxp_ofd_t *s, const void *buf, size_t len,
			   uint64_t off)
{
	return lxp_dev_pwrite(p, s->file_idx, buf, len, off);
}

static long fop_lseek_dev(lxp_proc_t *p, lxp_ofd_t *s, long off, int whence)
{
	(void)p;
	return lxp_dev_lseek(s->file_idx, off, whence);
}

static long fop_fstat_dev(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	(void)p;
	uint32_t mode;
	uint64_t rdev, size;
	lxp_dev_fstat(s->file_idx, &mode, &rdev, &size);
	/* Number the node by its registry entry, as stat(path) and readdir do. */
	const struct lxp_dev_open *o = open_slot(s->file_idx);
	lxp_stat_init(st, LXP_INO_DEV + (uint32_t)(o ? o->dev : s->file_idx), mode, size);
	st->rdev = rdev;
	return 0;
}

/* A driver with an .mmap op maps its own buffer (/dev/fb0): lxp_dev_mmap parks and
 * the coordinator installs the unprivileged MPU region, then resumes with the
 * address. Without one it returns -ENODEV and the caller copies instead. */
static long fop_mmap_dev(lxp_proc_t *p, lxp_ofd_t *s, size_t len, int prot, uint32_t pgoff)
{
	(void)prot;
	return lxp_dev_mmap(p, s->file_idx, len, pgoff);
}

static long fop_fsync_dev(lxp_proc_t *p, lxp_ofd_t *s)
{
	return lxp_dev_sync(p, s->file_idx);
}

/* F_SETFL: only O_NONBLOCK changes; the access mode recorded at open stays. */
static void fop_setfl_dev(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	struct lxp_dev_open *o = open_slot(s->file_idx);
	if (o)
		o->oflags = (uint16_t)((o->oflags & ~LXP_O_NONBLOCK) |
				       (s->nonblock ? LXP_O_NONBLOCK : 0));
}

static void fop_close_dev(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	lxp_dev_close(s->file_idx); /* release the backing object owned by this OFD */
}

static long fop_ioctl_dev(lxp_proc_t *p, lxp_ofd_t *s, unsigned long cmd, unsigned long arg)
{
	return lxp_dev_ioctl(p, s->file_idx, cmd, arg);
}

static unsigned fop_poll_dev(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	return (unsigned)lxp_dev_poll(s->file_idx);
}

const lxp_file_ops_t lxp_dev_fops = {
	.read = fop_read_dev,
	.write = fop_write_dev,
	.pread = fop_pread_dev,
	.pwrite = fop_pwrite_dev,
	.lseek = fop_lseek_dev,
	.fstat = fop_fstat_dev,
	.fsync = fop_fsync_dev,
	.mmap = fop_mmap_dev,
	.close = fop_close_dev,
	.ioctl = fop_ioctl_dev,
	.poll = fop_poll_dev,
	.setfl = fop_setfl_dev,
};

#endif /* LXP_ENABLE_DEV */
