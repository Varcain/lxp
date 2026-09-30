/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Guest ABI: the LXP framebuffer extension ioctl on /dev/fb0. Not a Linux uapi; a
 * guest program built against LXP includes this header instead of copying it. It
 * needs only <stdint.h>, so any C99 guest toolchain can use it.
 */
#ifndef LXP_UAPI_FBIO_H
#define LXP_UAPI_FBIO_H

#include <stdint.h>

/* Offload a rectangular framebuffer update to the 2D accelerator: one ioctl instead of a
 * pwrite per scanline. The coordinator validates the guest source rectangle, then copies
 * it into the framebuffer it owns. It fails with ENOSYS on a board without an
 * accelerator, and the guest keeps its pwrite path. */
#define LXP_FBIO_DMA2D_BLIT 0x46f0ul

struct lxp_fb_blit {
	uint32_t src;	     /* guest address of the source pixels (rect top-left)   */
	uint32_t src_stride; /* bytes per source row                                 */
	uint32_t x, y;	     /* destination top-left in the framebuffer (pixels)     */
	uint32_t w, h;	     /* rectangle size (pixels); RGB565, matches the fb      */
};

#endif /* LXP_UAPI_FBIO_H */
