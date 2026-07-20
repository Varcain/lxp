/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Private uapi mirrors for the Linux-personality device classes: the ioctl
 * command numbers and struct layouts the guest programs pass, spelled with
 * fixed-width types so the binary layout matches the ARM 32-bit kernel (and the
 * host cmocka build). Guest test programs compile against the REAL buildroot
 * linux-headers — that is the layout-drift enforcement.
 */

#ifndef LXP_UAPI_H
#define LXP_UAPI_H

#include <stdint.h>

/* ---- framebuffer (linux/fb.h) ---------------------------------------------- */
#define LXP_FBIOGET_VSCREENINFO 0x4600ul
#define LXP_FBIOPUT_VSCREENINFO 0x4601ul
#define LXP_FBIOGET_FSCREENINFO 0x4602ul
#define LXP_FBIOPAN_DISPLAY 0x4606ul
#define LXP_FBIOBLANK 0x4611ul

/* fb_fix_screeninfo.type / .visual */
#define LXP_FB_TYPE_PACKED_PIXELS 0
#define LXP_FB_VISUAL_TRUECOLOR 2

/* One color channel's position within a pixel. */
struct lxp_fb_bitfield {
	uint32_t offset;    /* bit position of the LSB */
	uint32_t length;    /* number of bits */
	uint32_t msb_right; /* != 0 if the MSB is on the right */
};

/* struct fb_var_screeninfo — 160 bytes on ARM32 (all fields u32). */
struct lxp_fb_var_screeninfo {
	uint32_t xres, yres;
	uint32_t xres_virtual, yres_virtual;
	uint32_t xoffset, yoffset;
	uint32_t bits_per_pixel;
	uint32_t grayscale;
	struct lxp_fb_bitfield red, green, blue, transp;
	uint32_t nonstd;
	uint32_t activate;
	uint32_t height, width; /* physical size in mm (0 = unknown) */
	uint32_t accel_flags;
	uint32_t pixclock;
	uint32_t left_margin, right_margin, upper_margin, lower_margin;
	uint32_t hsync_len, vsync_len;
	uint32_t sync, vmode, rotate, colorspace;
	uint32_t reserved[4];
};

/* struct fb_fix_screeninfo — 68 bytes on ARM32 (unsigned long = u32). */
struct lxp_fb_fix_screeninfo {
	char id[16];
	uint32_t smem_start; /* physical start of the framebuffer */
	uint32_t smem_len;   /* length of the framebuffer in bytes */
	uint32_t type;
	uint32_t type_aux;
	uint32_t visual;
	uint16_t xpanstep, ypanstep, ywrapstep;
	uint32_t line_length; /* bytes per scanline */
	uint32_t mmio_start;
	uint32_t mmio_len;
	uint32_t accel;
	uint16_t capabilities;
	uint16_t reserved[2];
};

/* FBIOBLANK arg. */
#define LXP_FB_BLANK_UNBLANK 0

/* ---- input / evdev (linux/input.h) ----------------------------------------- */
/* struct input_event on ARM32: the kernel uapi uses __kernel_ulong_t (32-bit)
 * for the timestamp even with a 64-bit-time_t libc, so this stays 16 bytes. */
struct lxp_input_event {
	uint32_t sec;
	uint32_t usec;
	uint16_t type;
	uint16_t code;
	int32_t value;
};

#define LXP_EV_SYN 0x00
#define LXP_EV_KEY 0x01
#define LXP_EV_ABS 0x03
#define LXP_SYN_REPORT 0
#define LXP_SYN_DROPPED 3
#define LXP_BTN_TOUCH 0x14a
#define LXP_ABS_X 0x00
#define LXP_ABS_Y 0x01

/* struct input_id (EVIOCGID). */
struct lxp_input_id {
	uint16_t bustype, vendor, product, version;
};
#define LXP_BUS_I2C 0x18

/* struct input_absinfo (EVIOCGABS). */
struct lxp_input_absinfo {
	int32_t value, minimum, maximum, fuzz, flat, resolution;
};

/* evdev ioctls (fixed-arg ones; the size-encoded EVIOCGNAME/GBIT are matched by
 * their 'E'-type + nr, ignoring the encoded length). */
#define LXP_EVIOCGVERSION 0x80044501ul     /* _IOR('E',0x01,int) */
#define LXP_EVIOCGID 0x80084502ul	       /* _IOR('E',0x02,input_id) */
#define LXP_EVIOCGRAB 0x40044590ul	       /* _IOW('E',0x90,int) */
#define LXP_EVIOC_TYPE(cmd) (((cmd) >> 8) & 0xff) /* 'E' == 0x45 for evdev */
#define LXP_EVIOC_NR(cmd) ((cmd) & 0xff)
#define LXP_EVIOC_SIZE(cmd) (((cmd) >> 16) & 0x3fffu) /* the caller's buffer length (_IOC_SIZE) */
#define LXP_EVIOC_E 0x45
#define LXP_EVIOCGNAME_NR 0x06
#define LXP_EVIOCGABS_BASE 0x40 /* EVIOCGABS(abs) nr = 0x40 + abs */

/* ---- DMA2D 2D-accelerator (/dev/dma2d) ------------------------------------- */
/* NOT a Linux uapi — an oveRTOS accelerator device. The guest submits one
 * fill/blit/blend descriptor; the PRIVILEGED coordinator validates every plane
 * address against the guest's own region (a DMA engine with guest-supplied
 * addresses is a confused-deputy risk) and programs the STM32 DMA2D. Field order
 * mirrors LVGL's lv_draw_dma2d_configuration_t so the guest shim is a field copy.
 * Matched by type+nr (ignoring _IOC_SIZE) so the two sides can't drift on sizeof. */
#define LXP_DMA2D_IOC_TYPE(cmd) (((cmd) >> 8) & 0xffu)
#define LXP_DMA2D_IOC_NR(cmd) ((cmd) & 0xffu)
#define LXP_DMA2D_IOC_D 0x44		/* 'D' */
#define LXP_DMA2D_SUBMIT_NR 0x01	/* _IOW('D',1,struct lxp_dma2d_submit)       */
#define LXP_DMA2D_SUBMIT_BATCH_NR 0x02	/* _IOW('D',2,struct lxp_dma2d_batch)        */
#define LXP_DMA2D_BATCH_MAX 256u	/* max descriptors per batched submit        */

/* Transfer mode. Values are the ABI (validated), NOT raw DMA2D register bits. */
#define LXP_DMA2D_M2M 0		    /* memory-to-memory copy (blit)            */
#define LXP_DMA2D_M2M_PFC 1	    /* + pixel-format convert                  */
#define LXP_DMA2D_M2M_BLEND 2	    /* fg over bg -> output (alpha blend)      */
#define LXP_DMA2D_M2M_BLEND_FG 3    /* blend with fixed-color fg (A8 glyph; Phase D) */
#define LXP_DMA2D_R2M 4		    /* register-to-memory (solid fill)         */
#define LXP_DMA2D_MODE_MAX 4

/* Colour formats — ABI values (validated + mapped to DMA2D xPFCCR.CM by the
 * coordinator). Output supports 0..4; fg/bg additionally the alpha formats. */
#define LXP_DMA2D_CF_ARGB8888 0
#define LXP_DMA2D_CF_RGB888 1
#define LXP_DMA2D_CF_RGB565 2
#define LXP_DMA2D_CF_ARGB1555 3
#define LXP_DMA2D_CF_ARGB4444 4
#define LXP_DMA2D_CF_A8 9    /* fg/bg only (8-bit alpha; glyph coverage)     */
#define LXP_DMA2D_CF_A4 10   /* fg/bg only                                   */
#define LXP_DMA2D_CF_MAX 10

/* Per-plane alpha mode (xPFCCR.AM): 0 = use pixel alpha, 1 = replace, 2 = combine. */
#define LXP_DMA2D_AM_NONE 0
#define LXP_DMA2D_AM_REPLACE 1
#define LXP_DMA2D_AM_COMBINE 2
#define LXP_DMA2D_AM_MAX 2

/* Offsets are in PIXELS (line stride - width), matching DMA2D's OOR/FGOR/BGOR. */
struct lxp_dma2d_submit {
	uint32_t mode;	/* LXP_DMA2D_* */
	uint32_t w, h;	/* transfer size in pixels (both > 0) */
	/* output (destination) plane — WRITTEN */
	uint32_t output_address, output_offset;
	uint32_t output_cf;	    /* LXP_DMA2D_CF_ARGB8888..ARGB4444 */
	uint32_t reg_to_mem_color;  /* ARGB8888 fill colour (LXP_DMA2D_R2M) */
	/* foreground source plane — READ */
	uint32_t fg_address, fg_offset;
	uint32_t fg_cf;
	uint32_t fg_color;	    /* fixed-colour fg (A8 glyph / alpha fill) */
	uint32_t fg_alpha_mode, fg_alpha;
	/* background source plane — READ (blend; usually == output) */
	uint32_t bg_address, bg_offset;
	uint32_t bg_cf;
	uint32_t bg_color;
	uint32_t bg_alpha_mode, bg_alpha;
};

/* Batched submit (Phase D, text): offload N descriptors through ONE ioctl so a
 * whole text run (a label = many glyphs) crosses the SVC boundary once instead of
 * per-glyph — the per-op round-trip, not the DMA2D transfer, is what makes tiny
 * glyphs unprofitable one at a time. The coordinator validates + programs each
 * descriptor in order; a rejected descriptor fails the batch fast (well-formed
 * guests never trip it, so earlier descriptors having drawn is benign). */
struct lxp_dma2d_batch {
	uint32_t count;	    /* number of descriptors, 1..LXP_DMA2D_BATCH_MAX */
	uint32_t _reserved; /* keep @ops 8-byte aligned + the layout identical on 32/64-bit */
	uint64_t ops;	    /* address of a struct lxp_dma2d_submit[count] array (guest ptr,
			     * zero-extended; the coordinator narrows it back via uintptr_t) */
};

#endif /* LXP_UAPI_H */
