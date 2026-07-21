/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * /dev/dma2d — a 2D-accelerator (STM32 DMA2D / Chrom-ART) submit device. A guest
 * ioctl(LXP_DMA2D_SUBMIT, &desc) offloads one fill/blit/blend; the PRIVILEGED
 * coordinator programs the hardware through the display port's dma2d_submit op.
 *
 * SECURITY: DMA2D is a DMA engine that reads/writes whatever address it is given.
 * The descriptor comes from an UNPRIVILEGED guest, so every plane's full byte
 * extent (h lines of w pixels with an inter-line gap) is validated with user_ok()
 * to lie ENTIRELY within the submitting guest's own region before the address ever
 * reaches the hardware — a guest can only ever make DMA2D touch its own memory.
 */

#include "lxp/lxp_config.h"

#if LXP_ENABLE_DEV_DMA2D

#include "lxp/lxp_port.h"
#include "lxp/lxp_dev.h"
#include "lxp/lxp_disp_ops.h"
#include "lxp/lxp_syscall.h" /* user_ok */
#include "lxp/lxp_types.h"
#include "lxp_uapi.h"

#include <stdint.h>
#include <string.h>

/* Bytes per pixel, rounded UP (over-estimating the span is safe for a bounds
 * check). 0 marks an invalid colour format. */
static uint32_t dma2d_bpp(uint32_t cf)
{
	switch (cf) {
	case LXP_DMA2D_CF_ARGB8888:
		return 4;
	case LXP_DMA2D_CF_RGB888:
		return 3;
	case LXP_DMA2D_CF_RGB565:
	case LXP_DMA2D_CF_ARGB1555:
	case LXP_DMA2D_CF_ARGB4444:
		return 2;
	case LXP_DMA2D_CF_A8:
	case LXP_DMA2D_CF_A4: /* A4 over-estimated at 1 B/px — conservative */
		return 1;
	default:
		return 0;
	}
}

/* A plane can't legitimately exceed a large panel area; these ceilings also keep
 * the span arithmetic far below uint64 overflow. */
#define DMA2D_MAX_DIM 4096u
#define DMA2D_MAX_SPAN (16u * 1024u * 1024u)

/* Validate that the bytes DMA2D would touch for one plane, [base, base+span), lie
 * inside the guest region. @offset is the inter-line gap in pixels (stride - w);
 * @write is non-zero for the destination plane. On success writes the absolute
 * (coordinator-side) address to *out_abs. */
static long dma2d_check_plane(lxp_proc_t *p, uint32_t base, uint32_t w, uint32_t h,
			      uint32_t offset, uint32_t cf, int write, uintptr_t *out_abs)
{
	uint32_t bpp = dma2d_bpp(cf);
	if (bpp == 0 || w == 0 || h == 0 || w > DMA2D_MAX_DIM || h > DMA2D_MAX_DIM ||
	    offset > DMA2D_MAX_DIM)
		return -LXP_EINVAL;
	uint64_t line = (uint64_t)w + offset;			 /* pixels per line incl. gap */
	uint64_t span = ((uint64_t)(h - 1) * line + w) * bpp;	 /* bytes DMA2D touches */
	if (span == 0 || span > DMA2D_MAX_SPAN)
		return -LXP_EINVAL;
	if (!user_ok(p, (const void *)(uintptr_t)base, (size_t)span, write))
		return -LXP_EFAULT;
	*out_abs = (uintptr_t)base;
	return 0;
}

/* Validate one guest descriptor (already copied out of guest memory) and fill the
 * coordinator-side op: check the enum fields, then bounds-check every plane the
 * mode touches against the guest region. Used by the single-submit ioctl. */
static long dma2d_prepare_op(lxp_proc_t *p, const struct lxp_dma2d_submit *s, lxp_dma2d_op_t *op)
{
	if (s->mode > LXP_DMA2D_MODE_MAX || s->output_cf > LXP_DMA2D_CF_ARGB4444 ||
	    s->fg_alpha_mode > LXP_DMA2D_AM_MAX || s->bg_alpha_mode > LXP_DMA2D_AM_MAX)
		return -LXP_EINVAL;

	memset(op, 0, sizeof(*op));
	op->mode = s->mode;
	op->w = s->w;
	op->h = s->h;
	op->out_offset = s->output_offset;
	op->out_cf = s->output_cf;
	op->out_color = s->reg_to_mem_color;
	op->fg_offset = s->fg_offset;
	op->fg_cf = s->fg_cf;
	op->fg_color = s->fg_color;
	op->fg_alpha_mode = s->fg_alpha_mode;
	op->fg_alpha = s->fg_alpha;
	op->bg_offset = s->bg_offset;
	op->bg_cf = s->bg_cf;
	op->bg_color = s->bg_color;
	op->bg_alpha_mode = s->bg_alpha_mode;
	op->bg_alpha = s->bg_alpha;

	long r;
	/* output plane is always WRITTEN. */
	r = dma2d_check_plane(p, s->output_address, s->w, s->h, s->output_offset, s->output_cf, 1,
			      &op->out_addr);
	if (r)
		return r;
	/* fg plane is READ for every mode except a solid register→memory fill. */
	if (s->mode != LXP_DMA2D_R2M) {
		r = dma2d_check_plane(p, s->fg_address, s->w, s->h, s->fg_offset, s->fg_cf, 0,
				      &op->fg_addr);
		if (r)
			return r;
	}
	/* bg plane is READ for the blending modes. */
	if (s->mode == LXP_DMA2D_M2M_BLEND || s->mode == LXP_DMA2D_M2M_BLEND_FG) {
		r = dma2d_check_plane(p, s->bg_address, s->w, s->h, s->bg_offset, s->bg_cf, 0,
				      &op->bg_addr);
		if (r)
			return r;
	}
	return 0;
}

static long dma2d_ioctl(struct lxp_dev *d, struct lxp_dev_open *o, lxp_proc_t *p,
			unsigned long cmd, unsigned long arg)
{
	(void)d;
	(void)o;
	if (LXP_DMA2D_IOC_TYPE(cmd) != LXP_DMA2D_IOC_D)
		return -LXP_ENOTTY;
	if (!g_lxp_disp_ops || !g_lxp_disp_ops->dma2d_submit)
		return -LXP_ENOSYS; /* no DMA2D on this board → guest renders in software */

	unsigned long nr = LXP_DMA2D_IOC_NR(cmd);

	if (nr == LXP_DMA2D_SUBMIT_NR) {
		struct lxp_dma2d_submit *u = (void *)arg;
		if (!user_ok(p, u, sizeof(*u), 0))
			return -LXP_EFAULT;
		struct lxp_dma2d_submit s = *u; /* copy in once; never re-read guest memory */
		lxp_dma2d_op_t op;
		long r = dma2d_prepare_op(p, &s, &op);
		if (r)
			return r;
		return g_lxp_disp_ops->dma2d_submit(&op);
	}

	return -LXP_ENOTTY;
}

static const struct lxp_dev_ops dma2d_ops = {
	.ioctl = dma2d_ioctl,
};

void lxp_dev_autoreg_dma2d(void)
{
	if (!g_lxp_disp_ops || !g_lxp_disp_ops->dma2d_submit)
		return; /* board has no DMA2D accelerator */
	struct lxp_dev dev = {
		.path = "/dev/dma2d",
		.ops = &dma2d_ops,
		.major = 242, /* local/experimental major */
		.minor = 0,
		.size = 0,
	};
	(void)lxp_dev_register(&dev);
}

#endif /* LXP_ENABLE_DEV_DMA2D */
