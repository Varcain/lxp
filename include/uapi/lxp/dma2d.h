/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Guest ABI: the LXP 2D-accelerator device /dev/dma2d. Not a Linux uapi; a guest
 * program built against LXP includes this header instead of copying it. It needs only
 * <stdint.h>, so any C99 guest toolchain can use it.
 *
 * The guest submits one fill/blit/blend descriptor; the coordinator validates every
 * plane address against the guest's own region (a DMA engine driven by guest addresses
 * is a confused deputy otherwise) and runs it on the host accelerator. Field order
 * mirrors LVGL's lv_draw_dma2d_configuration_t, so a guest shim is a field copy.
 */
#ifndef LXP_UAPI_DMA2D_H
#define LXP_UAPI_DMA2D_H

#include <stdint.h>

/* Transfer mode. Values are the ABI (validated), NOT raw DMA2D register bits. */
#define LXP_DMA2D_M2M 0		 /* memory-to-memory copy (blit)                 */
#define LXP_DMA2D_M2M_PFC 1	 /* + pixel-format convert                       */
#define LXP_DMA2D_M2M_BLEND 2	 /* fg over bg -> output (alpha blend)           */
#define LXP_DMA2D_M2M_BLEND_FG 3 /* blend with fixed-color fg (A8 alpha map)     */
#define LXP_DMA2D_R2M 4		 /* register-to-memory (solid fill)              */
#define LXP_DMA2D_MODE_MAX 4

/* Colour formats. Output supports 0..4; fg/bg additionally the alpha formats. */
#define LXP_DMA2D_CF_ARGB8888 0
#define LXP_DMA2D_CF_RGB888 1
#define LXP_DMA2D_CF_RGB565 2
#define LXP_DMA2D_CF_ARGB1555 3
#define LXP_DMA2D_CF_ARGB4444 4
#define LXP_DMA2D_CF_A8 9  /* fg/bg only (8-bit alpha; glyph coverage)     */
#define LXP_DMA2D_CF_A4 10 /* fg/bg only                                   */
#define LXP_DMA2D_CF_MAX 10

/* Per-plane alpha mode: use the pixel's alpha, replace it, or combine with it. */
#define LXP_DMA2D_AM_NONE 0
#define LXP_DMA2D_AM_REPLACE 1
#define LXP_DMA2D_AM_COMBINE 2
#define LXP_DMA2D_AM_MAX 2

/* Offsets are in PIXELS (line stride - width). */
struct lxp_dma2d_submit {
	uint32_t mode; /* LXP_DMA2D_* */
	uint32_t w, h; /* transfer size in pixels (both > 0) */
	/* output (destination) plane — WRITTEN */
	uint32_t output_address, output_offset;
	uint32_t output_cf;	   /* LXP_DMA2D_CF_ARGB8888..ARGB4444 */
	uint32_t reg_to_mem_color; /* ARGB8888 fill colour (LXP_DMA2D_R2M) */
	/* foreground source plane — READ */
	uint32_t fg_address, fg_offset;
	uint32_t fg_cf;
	uint32_t fg_color; /* fixed-colour fg (A8 glyph / alpha fill) */
	uint32_t fg_alpha_mode, fg_alpha;
	/* background source plane — READ (blend; usually == output) */
	uint32_t bg_address, bg_offset;
	uint32_t bg_cf;
	uint32_t bg_color;
	uint32_t bg_alpha_mode, bg_alpha;
};

/* _IOW('D', 1, struct lxp_dma2d_submit): write direction, the struct's 76-byte size,
 * type 'D', number 1. The device matches type and number only, so a guest's own
 * _IOW() spelling of the command is accepted too. */
#define LXP_DMA2D_SUBMIT 0x404c4401ul

#endif /* LXP_UAPI_DMA2D_H */
