/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The display/input port for the Linux personality. The /dev/fb0 and
 * /dev/input/event0 class drivers reach the panel + touch controller ONLY through
 * these ops, so the personality carries no direct dependency on a particular
 * framebuffer / touch HAL. On oveRTOS the ops are filled by
 * backends/common/lxp_ove_display_adapter.c (bridging to ove_fb_* / ove_ft5336_*).
 * Display geometry is run-scoped policy injected through
 * lxp_display_set_geometry().
 */

#ifndef LXP_DISPLAY_OPS_H
#define LXP_DISPLAY_OPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LXP_DISPLAY_OPS_ABI_VERSION 2u

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

/* fb_* are required when /dev/fb0 is built; touch_* may be NULL when no touch
 * controller is present. */
typedef struct lxp_display_ops {
	uint32_t abi_version; /**< Must be LXP_DISPLAY_OPS_ABI_VERSION. */
	uint32_t struct_size; /**< Must be sizeof(lxp_display_ops_t). */

	int (*fb_init)(void);
	int (*fb_get_info)(lxp_fb_info_t *info);
	void *(*fb_get_buffer)(void);
	/** Present one LXP-coalesced dirty rectangle. The provider owns any cache
	 * publication and physical scanout/update required by the panel. */
	void (*fb_present)(int x, int y, int w, int h);
	/* Optional 2D-accelerator submit (/dev/dma2d); NULL if the board has no
	 * DMA2D, in which case the guest falls back to software rendering. */
	int (*dma2d_init)(void);
	int (*dma2d_submit)(const lxp_dma2d_op_t *op);
	int (*touch_init)(void);
	int (*touch_read)(int *x, int *y, int *pressed);
	void (*touch_deinit)(void);
} lxp_display_ops_t;

/* Set the display geometry used to clamp / report touch coordinates.
 * Non-positive dimensions reset to the 480x272 default independently.
 * lxp_run() seeds it from lxp_run_config_t. */
void lxp_display_set_geometry(int width, int height);

#ifdef __cplusplus
}
#endif

#endif /* LXP_DISPLAY_OPS_H */
