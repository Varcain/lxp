/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The display/input port for the Linux personality. The /dev/fb0, /dev/dma2d and
 * /dev/input/event0 class drivers reach the panel, the 2D accelerator and the touch
 * controller only through these ops, so the personality carries no direct dependency
 * on a particular framebuffer, accelerator or touch HAL. Touch coordinates are in
 * framebuffer pixels: LXP clamps and reports them in the framebuffer's size, or
 * 480x272 without one.
 */

#ifndef LXP_DISPLAY_OPS_H
#define LXP_DISPLAY_OPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lxp_fb_info {
	uint16_t width, height, stride_bytes;
	uint32_t fmt; /**< pixel format selector (0 => RGB565). */
	uint32_t smem_len;
} lxp_fb_info_t;

/* A validated DMA2D fill/blit/blend, filled by the /dev/dma2d device from a guest
 * descriptor after every plane was bounds-checked against the guest region.
 * Addresses are absolute (coordinator-side); scalars are the validated ABI enums
 * (LXP_DMA2D_* in lxp_uapi.h). */
typedef struct lxp_dma2d_op {
	uint32_t mode, w, h;
	uintptr_t out_addr;
	uint32_t out_offset, out_cf, out_color;
	uintptr_t fg_addr;
	uint32_t fg_offset, fg_cf, fg_color, fg_alpha_mode, fg_alpha;
	uintptr_t bg_addr;
	uint32_t bg_offset, bg_cf, bg_color, bg_alpha_mode, bg_alpha;
} lxp_dma2d_op_t;

/** The framebuffer behind /dev/fb0. */
typedef struct lxp_fb_ops {
	int (*init)(void);
	int (*get_info)(lxp_fb_info_t *info);
	void *(*get_buffer)(void);
	/** Present one LXP-coalesced dirty rectangle. The provider owns any cache
	 * publication and physical scanout/update required by the panel. */
	void (*present)(int x, int y, int w, int h);
} lxp_fb_ops_t;

/** The 2D accelerator behind /dev/dma2d and the framebuffer blit ioctl. */
typedef struct lxp_dma2d_ops {
	int (*init)(void);
	int (*submit)(const lxp_dma2d_op_t *op);
} lxp_dma2d_ops_t;

/** The touch controller behind /dev/input/event0. */
typedef struct lxp_touch_ops {
	int (*init)(void);
	int (*read)(int *x, int *y, int *pressed);
	void (*deinit)(void);
} lxp_touch_ops_t;

/** The display hardware a run offers its guests. Each piece is optional: without a
 * framebuffer there is no /dev/fb0, without an accelerator guests render in software,
 * and without a touch panel a build with the test pad synthesizes input. A piece that is
 * present fills every member of its table. */
typedef struct lxp_display_ops {
	const lxp_fb_ops_t *fb;
	const lxp_dma2d_ops_t *dma2d;
	const lxp_touch_ops_t *touch;
} lxp_display_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* LXP_DISPLAY_OPS_H */
