/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of oveRTOS.
 *
 * Linux personality /dev device-layer tests: register a mock character device
 * and drive lxp_syscall() (no hardware SVC, no run loop) to check the
 * FD_DEV routing — open/read/write/ioctl/poll/lseek/close, stat + getdents,
 * fd refcounting across dup, and the deferred (block + coordinator-retry) path.
 */

#include "../framework/lxp_test.h"
#include "lxp/lxp_arena.h"
#include "lxp/lxp_dev.h"
#include "lxp/lxp_port.h"		/* lxp_dma2d_op_t */
#include "lxp/lxp_syscall.h"
#include "../../src/dev/lxp_uapi.h" /* struct lxp_dma2d_submit + LXP_DMA2D_* */

#include <stdint.h>
#include <string.h>

/* access_ok — non-static in ove_linux_syscall.c so a device ioctl handler can
 * validate its user pointer (the confused-deputy guard). */
int user_ok(const lxp_proc_t *p, const void *ptr, size_t len, int write);

/* The evdev class registers /dev/input/event0 (LXP_ENABLE_DEV_INPUT); not in the public
 * header (it is called from lxp_dev_autoreg_all on target). Declared here to test its ioctls. */
void lxp_dev_autoreg_input(void);

/* The framebuffer class registers /dev/fb0 over the stub's mock display. The stub records the
 * last fb_flush(x,y,w,h) so a suite can assert the driver's dirty-rectangle math. */
void lxp_dev_autoreg_fb(void);
extern int g_mock_fb_flush_x, g_mock_fb_flush_y, g_mock_fb_flush_w, g_mock_fb_flush_h;
extern int g_mock_fb_flush_calls;

/* The DMA2D accelerator class registers /dev/dma2d over the stub's mock dma2d_submit,
 * which records the last (already-validated) op so a suite can assert forwarding. */
void lxp_dev_autoreg_dma2d(void);
extern lxp_dma2d_op_t g_mock_dma2d_op;
extern int g_mock_dma2d_calls;
/* Matched by type 'D' + nr 1/2; the handler ignores _IOC_SIZE/dir. */
#define TEST_DMA2D_SUBMIT ((0x44ul << 8) | 1ul)
#define TEST_FBIO_DMA2D_BLIT 0x46f0ul

/* The evdev feeder: pushes one touch (4 events) into the shared input ring. */
void lxp_input_report_touch(int x, int y, int pressed);

/* EVIOCGNAME(len) on ARM: _IOC(_IOC_READ, 'E', 0x06, len) — size in bits 16..29. */
#define EVIOCGNAME_CMD(len) (0x80000000ul | ((unsigned long)(len) << 16) | 0x4506ul)

/* ---- a mock character device ----------------------------------------------- */
#define MOCK_IOC_GET 0x1001ul /* read g_mock_val into *arg */
#define MOCK_IOC_SET 0x1002ul /* write *arg into g_mock_val */

static uint8_t g_mock_rbuf[64]; /* bytes a read() returns */
static size_t g_mock_rlen;
static uint8_t g_mock_wbuf[64]; /* bytes the last write() captured */
static size_t g_mock_wlen;
static int g_mock_block;    /* while set, read() returns -EAGAIN (would block) */
static int g_mock_released; /* count of ops->release calls */
static int g_mock_opened;   /* count of ops->open calls */
static uint32_t g_mock_val; /* the MOCK_IOC_GET/SET register */

static long mock_open(struct lxp_dev *d, struct lxp_dev_open *o, int flags)
{
	(void)d;
	(void)o;
	(void)flags;
	g_mock_opened++;
	return 0;
}

static long mock_release(struct lxp_dev *d, struct lxp_dev_open *o)
{
	(void)d;
	(void)o;
	g_mock_released++;
	return 0;
}

static long mock_read(struct lxp_dev *d, struct lxp_dev_open *o, lxp_proc_t *p,
		      void *buf, size_t len)
{
	(void)d;
	(void)o;
	(void)p;
	if (g_mock_block)
		return -LXP_EAGAIN; /* would block → the core parks the caller */
	size_t n = g_mock_rlen < len ? g_mock_rlen : len;
	memcpy(buf, g_mock_rbuf, n);
	return (long)n;
}

static long mock_write(struct lxp_dev *d, struct lxp_dev_open *o, lxp_proc_t *p,
		       const void *buf, size_t len)
{
	(void)d;
	(void)o;
	(void)p;
	size_t n = len < sizeof(g_mock_wbuf) ? len : sizeof(g_mock_wbuf);
	memcpy(g_mock_wbuf, buf, n);
	g_mock_wlen = n;
	return (long)len;
}

static long mock_ioctl(struct lxp_dev *d, struct lxp_dev_open *o, lxp_proc_t *p,
		       unsigned long cmd, unsigned long arg)
{
	(void)d;
	(void)o;
	if (cmd == MOCK_IOC_GET) {
		if (!user_ok(p, (void *)arg, sizeof(uint32_t), 1)) /* kernel writes *arg */
			return -LXP_EFAULT;
		*(uint32_t *)arg = g_mock_val;
		return 0;
	}
	if (cmd == MOCK_IOC_SET) {
		if (!user_ok(p, (const void *)arg, sizeof(uint32_t), 0)) /* kernel reads *arg */
			return -LXP_EFAULT;
		g_mock_val = *(const uint32_t *)arg;
		return 0;
	}
	return -LXP_ENOTTY; /* unknown command */
}

static unsigned mock_poll(struct lxp_dev *d, struct lxp_dev_open *o)
{
	(void)d;
	(void)o;
	return LXP_POLLIN | LXP_POLLOUT;
}

/* mmap(2) (P3): hand back a fixed "device buffer" + a cache-attr hint, rejecting a
 * request past the device extent — the shape the /dev/fb0 driver's op has. */
static uint8_t g_mock_fb[256];
static long mock_mmap(struct lxp_dev *d, struct lxp_dev_open *o, lxp_proc_t *p,
		      size_t len, uint32_t pgoff, uintptr_t *phys, unsigned *attrs)
{
	(void)o;
	(void)p;
	if (pgoff != 0 || len > d->size)
		return -LXP_EINVAL;
	*phys = (uintptr_t)g_mock_fb;
	*attrs = LXP_MAP_NC;
	return 0;
}

static const struct lxp_dev_ops mock_ops = {
	.open = mock_open,
	.release = mock_release,
	.read = mock_read,
	.write = mock_write,
	.ioctl = mock_ioctl,
	.poll = mock_poll,
	.mmap = mock_mmap,
};

static const struct lxp_dev mock_dev = {
	.path = "/dev/mock",
	.ops = &mock_ops,
	.major = 42,
	.minor = 7,
	.size = 256, /* a seekable extent (like a framebuffer smem_len) */
};

static uint8_t g_pool[8192] __attribute__((aligned(16)));

/* A rootfs with just a /dev directory so getdents has a directory fd to list. */
static const lxp_file_t g_fs[] = {
	{.path = "/dev", .data = NULL, .size = 0, .mode = LXP_S_IFDIR | 0755u},
};

static void setup(lxp_proc_t *p, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_pool, sizeof(g_pool)), OVE_OK);
	assert_int_equal(lxp_proc_init(p, arena, 4096), OVE_OK);
	/* All-permitting access_ok range except NULL (region_lo = 1), matching the
	 * syscall-suite harness; a NULL ioctl arg still fails user_ok → -EFAULT. */
	p->region_lo = 1;
	p->region_hi = UINTPTR_MAX;
	p->pool_lo = p->pool_hi = 0;
	lxp_proc_set_rootfs(p, g_fs, 1);
	g_mock_rlen = g_mock_wlen = 0;
	g_mock_block = g_mock_released = g_mock_opened = 0;
	g_mock_val = 0;
	assert_int_equal(lxp_dev_register(&mock_dev), 0); /* idempotent across tests */
}

static long dev_open(lxp_proc_t *p, int flags)
{
	return lxp_syscall(p, LXP_NR_openat, LXP_AT_FDCWD,
			       (long)(uintptr_t) "/dev/mock", flags, 0, 0, 0);
}

/* ---- tests ----------------------------------------------------------------- */
static void test_dev_open_close(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	long fd = dev_open(&p, LXP_O_RDWR);
	assert_true(fd >= 3); /* a fresh fd past the std streams */
	assert_int_equal(p.fds[fd].kind, LXP_FD_DEV);
	assert_int_equal(g_mock_opened, 1);

	/* Opening a non-registered /dev path falls through to ENOENT. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
					 (long)(uintptr_t) "/dev/nope", LXP_O_RDWR, 0, 0, 0),
			 -LXP_ENOENT);

	assert_int_equal(lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0), 0);
	assert_int_equal(g_mock_released, 1);
	assert_int_equal(p.fds[fd].kind, 0 /* FD_FREE */);
}

static void test_dev_read_write(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	long fd = dev_open(&p, LXP_O_RDWR);
	assert_true(fd >= 3);

	/* write routes to the driver, which captures the bytes. */
	long w = lxp_syscall(&p, LXP_NR_write, fd, (long)(uintptr_t) "abcd", 4, 0, 0, 0);
	assert_int_equal(w, 4);
	assert_int_equal((int)g_mock_wlen, 4);
	assert_memory_equal(g_mock_wbuf, "abcd", 4);

	/* read returns the driver's canned bytes. */
	memcpy(g_mock_rbuf, "XY", 2);
	g_mock_rlen = 2;
	char rb[8] = {0};
	long r = lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)rb, sizeof(rb), 0, 0, 0);
	assert_int_equal(r, 2);
	assert_memory_equal(rb, "XY", 2);

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

static void test_dev_ioctl(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	long fd = dev_open(&p, LXP_O_RDWR);
	assert_true(fd >= 3);

	/* SET then GET round-trips the register through the driver. */
	uint32_t v = 0xdeadbeef;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, MOCK_IOC_SET,
					 (long)(uintptr_t)&v, 0, 0, 0),
			 0);
	uint32_t out = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, MOCK_IOC_GET,
					 (long)(uintptr_t)&out, 0, 0, 0),
			 0);
	assert_int_equal(out, 0xdeadbeef);

	/* An unknown command → -ENOTTY (not the console gate's blanket reject). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, 0x9999, 0, 0, 0, 0),
			 -LXP_ENOTTY);

	/* A bad user pointer (NULL) is rejected by the handler's user_ok → -EFAULT. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, MOCK_IOC_GET, 0, 0, 0, 0),
			 -LXP_EFAULT);

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

/* EVIOCGNAME must honor the buffer length encoded in the ioctl command (_IOC_SIZE), copying
 * at most that many bytes — like the real kernel's min(len, strlen+1). Before the fix it
 * always copied the full 14-byte name, scribbling past a smaller caller buffer. */
static void test_dev_input_eviocgname_size(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);
	lxp_dev_autoreg_input(); /* registers /dev/input/event0 (idempotent) */

	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
			      (long)(uintptr_t) "/dev/input/event0", LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);

	/* EVIOCGNAME(8): an 8-byte buffer — the handler must not write past byte 8. */
	char nm[16];
	memset(nm, 0x7f, sizeof(nm));
	long r = lxp_syscall(&p, LXP_NR_ioctl, fd, (long)EVIOCGNAME_CMD(8), (long)(uintptr_t)nm, 0,
			     0, 0);
	assert_true(r >= 0 && r <= 8);
	assert_int_equal((uint8_t)nm[8], 0x7f); /* untouched (pre-fix: 14 bytes copied -> clobbered) */

	/* EVIOCGNAME(64): a large buffer receives the full NUL-terminated name. */
	memset(nm, 0x7f, sizeof(nm));
	r = lxp_syscall(&p, LXP_NR_ioctl, fd, (long)EVIOCGNAME_CMD(64), (long)(uintptr_t)nm, 0, 0, 0);
	assert_true(r > 0);
	assert_string_equal(nm, "overtos-touch");

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

/* When the reader falls more than a ring behind, the dropped events must be flagged with a
 * SYN_DROPPED record so an evdev client discards its stale state and resyncs. Before the fix
 * the overrun set an internal flag that was never read — events vanished silently. */
static void test_dev_input_syn_dropped_on_overrun(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);
	lxp_dev_autoreg_input();

	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
			      (long)(uintptr_t) "/dev/input/event0", LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3); /* opens at the live head, so only the pushes below count */

	/* Overflow the 64-slot ring behind this reader: 17 touches = 68 events > 64. */
	for (int i = 0; i < 17; i++)
		lxp_input_report_touch(i, i, 1);

	uint8_t evs[128];
	memset(evs, 0xee, sizeof(evs));
	long r = lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)evs, sizeof(evs), 0, 0, 0);
	assert_true(r >= 16); /* at least one 16-byte input_event */
	/* input_event layout: sec[0..4] usec[4..8] type[8..10] code[10..12] value[12..16].
	 * The first record must be SYN_DROPPED: type = EV_SYN(0), code = SYN_DROPPED(3). */
	assert_int_equal(evs[8], 0);
	assert_int_equal(evs[9], 0);
	assert_int_equal(evs[10], 3);
	assert_int_equal(evs[11], 0);

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

/* Guest test tools may inject a canonical touch report by writing the normal
 * ARM32 input_event layout to event0.  The report is validated as a whole, then
 * re-timestamped and queued exactly like a physical FT5336 report. */
static void test_dev_input_write_injects_touch(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);
	lxp_dev_autoreg_input();

	long rfd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
			       (long)(uintptr_t) "/dev/input/event0",
			       LXP_O_RDONLY | LXP_O_NONBLOCK, 0, 0, 0);
	long wfd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
			       (long)(uintptr_t) "/dev/input/event0", LXP_O_WRONLY, 0, 0, 0);
	assert_true(rfd >= 3);
	assert_true(wfd >= 3);

	struct lxp_input_event report[4];
	memset(report, 0, sizeof(report));
	report[0].type = LXP_EV_ABS;
	report[0].code = LXP_ABS_X;
	report[0].value = 123;
	report[1].type = LXP_EV_ABS;
	report[1].code = LXP_ABS_Y;
	report[1].value = 45;
	report[2].type = LXP_EV_KEY;
	report[2].code = LXP_BTN_TOUCH;
	report[2].value = 1;
	report[3].type = LXP_EV_SYN;
	report[3].code = LXP_SYN_REPORT;

	assert_int_equal(lxp_syscall(&p, LXP_NR_write, wfd, (long)(uintptr_t)report,
				     sizeof(report), 0, 0, 0),
			 sizeof(report));

	struct lxp_input_event out[4];
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, rfd, (long)(uintptr_t)out,
				     sizeof(out), 0, 0, 0),
			 sizeof(out));
	assert_int_equal(out[0].type, LXP_EV_ABS);
	assert_int_equal(out[0].code, LXP_ABS_X);
	assert_int_equal(out[0].value, 123);
	assert_int_equal(out[1].type, LXP_EV_ABS);
	assert_int_equal(out[1].code, LXP_ABS_Y);
	assert_int_equal(out[1].value, 45);
	assert_int_equal(out[2].type, LXP_EV_KEY);
	assert_int_equal(out[2].code, LXP_BTN_TOUCH);
	assert_int_equal(out[2].value, 1);
	assert_int_equal(out[3].type, LXP_EV_SYN);
	assert_int_equal(out[3].code, LXP_SYN_REPORT);

	/* A partial report is rejected without appending anything to the ring. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, wfd, (long)(uintptr_t)report,
				     sizeof(report) - sizeof(report[0]), 0, 0, 0),
			 -LXP_EINVAL);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, rfd, (long)(uintptr_t)out,
				     sizeof(out), 0, 0, 0),
			 -LXP_EAGAIN);

	lxp_syscall(&p, LXP_NR_close, rfd, 0, 0, 0, 0, 0);
	lxp_syscall(&p, LXP_NR_close, wfd, 0, 0, 0, 0, 0);
}

/* A device fd must honor its open access mode: writing an O_RDONLY fd (or reading an O_WRONLY
 * one) is -EBADF, like Linux. Before the fix any device fd was both readable and writable
 * regardless of how it was opened (e.g. write to an O_RDONLY /dev/fb0 scribbled the panel). */
static void test_dev_accmode_enforced(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	char b[4] = {0};
	g_mock_rbuf[0] = 'x';
	g_mock_rlen = 1;

	/* O_RDONLY: read ok, write -> EBADF. */
	long rfd = dev_open(&p, LXP_O_RDONLY);
	assert_true(rfd >= 3);
	assert_true(lxp_syscall(&p, LXP_NR_read, rfd, (long)(uintptr_t)b, 1, 0, 0, 0) >= 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, rfd, (long)(uintptr_t) "z", 1, 0, 0, 0),
			 -LXP_EBADF);

	/* O_WRONLY: write ok, read -> EBADF. */
	long wfd = dev_open(&p, LXP_O_WRONLY);
	assert_true(wfd >= 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, wfd, (long)(uintptr_t) "z", 1, 0, 0, 0), 1);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, wfd, (long)(uintptr_t)b, 1, 0, 0, 0),
			 -LXP_EBADF);

	/* O_RDWR: both directions allowed. */
	long rwfd = dev_open(&p, LXP_O_RDWR);
	assert_true(rwfd >= 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, rwfd, (long)(uintptr_t) "z", 1, 0, 0, 0), 1);
	assert_true(lxp_syscall(&p, LXP_NR_read, rwfd, (long)(uintptr_t)b, 1, 0, 0, 0) >= 0);

	lxp_syscall(&p, LXP_NR_close, rfd, 0, 0, 0, 0, 0);
	lxp_syscall(&p, LXP_NR_close, wfd, 0, 0, 0, 0, 0);
	lxp_syscall(&p, LXP_NR_close, rwfd, 0, 0, 0, 0, 0);
}

/* fb_write's flush must cover every row the write touched. A write that starts mid-row and
 * crosses a row boundary spans two rows; before the fix the height was ceil(n/stride), which
 * dropped the second row (a stale scanline on a port whose fb_flush uploads only the rect). */
static void test_dev_fb_flush_spans_crossed_rows(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);
	lxp_dev_autoreg_fb(); /* /dev/fb0 over the stub's 64x64 RGB565 mock (stride 128) */

	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t) "/dev/fb0",
			      LXP_O_RDWR, 0, 0, 0);
	assert_true(fd >= 3);

	static uint8_t px[64];
	memset(px, 0xa5, sizeof(px));
	g_mock_fb_flush_calls = 0;
	/* pwrite64(fd, buf, count=50, [pad a3], off_lo=100, off_hi=0): bytes [100,150) with
	 * stride 128 touch row 0 ([0,128)) and row 1 ([128,256)). */
	long w = lxp_syscall(&p, LXP_NR_pwrite64, fd, (long)(uintptr_t)px, 50, 0, 100, 0);
	assert_int_equal(w, 50);
	assert_int_equal(g_mock_fb_flush_calls, 1);
	assert_int_equal(g_mock_fb_flush_y, 0); /* first touched row */
	assert_int_equal(g_mock_fb_flush_h, 2); /* rows 0 and 1 (pre-fix: only 1) */

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

/* The DMA2D fb-blit ioctl offloads a rectangular framebuffer update: the coordinator
 * validates the guest source rect + fb bounds, then issues one M2M DMA2D copy to the
 * fb it owns (replacing the per-scanline pwrite storm) and refreshes the panel. */
static void test_dev_fb_dma2d_blit(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);
	lxp_dev_autoreg_fb(); /* 64x64 RGB565 mock fb, stride 128 */
	lxp_dev_autoreg_dma2d();
	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t) "/dev/fb0",
			      LXP_O_RDWR, 0, 0, 0);
	assert_true(fd >= 3);

	static uint16_t src[16 * 8]; /* w=16 h=8, tight source stride 32 bytes */
	for (int i = 0; i < 16 * 8; i++)
		src[i] = (uint16_t)i;
	struct lxp_fb_blit b;
	b.src = (uint32_t)(uintptr_t)src;
	b.src_stride = 16 * 2;
	b.x = 4;
	b.y = 6;
	b.w = 16;
	b.h = 8;
	long a = (long)(uintptr_t)&b;

	g_mock_dma2d_calls = 0;
	g_mock_fb_flush_calls = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_FBIO_DMA2D_BLIT, a, 0, 0, 0), 0);
	assert_int_equal(g_mock_dma2d_calls, 1);
	assert_int_equal(g_mock_dma2d_op.mode, LXP_DMA2D_M2M);
	assert_int_equal(g_mock_dma2d_op.w, 16);
	assert_int_equal(g_mock_dma2d_op.h, 8);
	assert_int_equal((uint32_t)g_mock_dma2d_op.fg_addr, (uint32_t)(uintptr_t)src);
	assert_int_equal(g_mock_dma2d_op.fg_offset, 0);	       /* 32/2 - 16 */
	assert_int_equal(g_mock_dma2d_op.out_offset, 64 - 16); /* fb stride 128/2 - 16 */
	assert_int_equal(g_mock_fb_flush_calls, 1);
	assert_int_equal(g_mock_fb_flush_w, 16);

	/* Rejections — none reach DMA2D. */
	g_mock_dma2d_calls = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_FBIO_DMA2D_BLIT, 0, 0, 0, 0),
			 -LXP_EFAULT); /* NULL descriptor */
	b.x = 60; /* x+w = 76 > fb width 64 */
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_FBIO_DMA2D_BLIT, a, 0, 0, 0),
			 -LXP_EINVAL);
	b.x = 4;
	b.w = 0; /* empty rect */
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_FBIO_DMA2D_BLIT, a, 0, 0, 0),
			 -LXP_EINVAL);
	b.w = 16;
	b.src = 0; /* NULL source → EFAULT (region_lo rejects addr 0) */
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_FBIO_DMA2D_BLIT, a, 0, 0, 0),
			 -LXP_EFAULT);
	assert_int_equal(g_mock_dma2d_calls, 0);

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

/* mmap(2) of a device buffer (P3): sys_mmap2 routes a /dev fd with an .mmap op to it, which
 * PARKS on DEVW_MMAP — the run-loop coordinator (not present in this unit test) would then
 * install the MPU region + resume with r0 = the mapped address. Assert the deferral state the
 * coordinator consumes (dev_wait/dev_buf/dev_len/dev_cmd), and that a request past the device
 * extent is rejected by the driver op without parking. */
static void test_dev_mmap(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);
	long fd = dev_open(&p, LXP_O_RDWR);
	assert_true(fd >= 3);

	/* MAP_SHARED (0x1), NOT MAP_ANONYMOUS, PROT_READ|WRITE (0x3) — the fbdev shape. */
	long r = lxp_syscall(&p, LXP_NR_mmap2, 0, 256, 0x3, 0x1, fd, 0);
	assert_int_equal(r, 0); /* parked, not an immediate return */
	assert_int_equal(p.dev_wait, LXP_DEVW_MMAP);
	assert_int_equal(p.dev_buf, (uintptr_t)g_mock_fb);
	assert_int_equal(p.dev_len, 256);
	assert_int_equal(p.dev_cmd, LXP_MAP_NC);

	/* A length past the device extent is rejected by the driver op — no park. */
	p.dev_wait = 0;
	long r2 = lxp_syscall(&p, LXP_NR_mmap2, 0, 512, 0x3, 0x1, fd, 0);
	assert_int_equal(r2, -LXP_EINVAL);
	assert_int_equal(p.dev_wait, 0);

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

static void test_dev_stat_lseek_poll(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	long fd = dev_open(&p, LXP_O_RDWR);
	assert_true(fd >= 3);

	/* fstat: a character device with the driver's (major,minor) in st_rdev. */
	struct {
		uint64_t st_dev;
		uint8_t pad0[4];
		uint32_t __ino;
		uint32_t st_mode;
		uint32_t st_nlink;
		uint32_t st_uid, st_gid;
		uint64_t st_rdev;
		uint8_t rest[80];
	} st;
	memset(&st, 0, sizeof(st));
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_fstat64, fd, (long)(uintptr_t)&st, 0, 0, 0, 0), 0);
	assert_int_equal(st.st_mode & LXP_S_IFMT, LXP_S_IFCHR);
	assert_int_equal((int)st.st_rdev, (42 << 8) | 7);

	/* stat-by-path recognises the device node too. */
	memset(&st, 0, sizeof(st));
	assert_int_equal(lxp_syscall(&p, LXP_NR_stat64, (long)(uintptr_t) "/dev/mock",
					 (long)(uintptr_t)&st, 0, 0, 0, 0),
			 0);
	assert_int_equal(st.st_mode & LXP_S_IFMT, LXP_S_IFCHR);

	/* lseek within the device's fixed extent (size 256). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_lseek, fd, 10, LXP_SEEK_SET, 0, 0, 0),
			 10);
	assert_int_equal(lxp_syscall(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_END, 0, 0, 0),
			 256);
	assert_int_equal(lxp_syscall(&p, LXP_NR_lseek, fd, 300, LXP_SEEK_SET, 0, 0, 0),
			 -LXP_EINVAL); /* past the extent */

	/* poll reports the driver's readiness bits. */
	lxp_pollfd pfd = {.fd = (int)fd, .events = LXP_POLLIN | LXP_POLLOUT};
	long pr = lxp_syscall(&p, LXP_NR_poll, (long)(uintptr_t)&pfd, 1, 0, 0, 0, 0);
	assert_int_equal(pr, 1);
	assert_int_equal(pfd.revents & (LXP_POLLIN | LXP_POLLOUT),
			 LXP_POLLIN | LXP_POLLOUT);

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
}

static void test_dev_deferred_block(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	long fd = dev_open(&p, LXP_O_RDWR);
	assert_true(fd >= 3);

	/* A blocking read parks the proc (dev_wait set, syscall returns 0 = parked). */
	g_mock_block = 1;
	char rb[8] = {0};
	long r = lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)rb, sizeof(rb), 0, 0, 0);
	assert_int_equal(r, 0);
	assert_int_not_equal(p.dev_wait, 0); /* parked for the coordinator to retry */

	/* Still blocked → the coordinator's retry reports -EAGAIN (stay parked). */
	assert_int_equal(lxp_dev_retry(&p), -LXP_EAGAIN);

	/* Data arrives → the retry completes with the bytes (the run loop then resumes). */
	memcpy(g_mock_rbuf, "ok", 2);
	g_mock_rlen = 2;
	g_mock_block = 0;
	assert_int_equal(lxp_dev_retry(&p), 2);
	assert_memory_equal(rb, "ok", 2);

	/* O_NONBLOCK does NOT park — it returns -EAGAIN straight to the program. */
	p.dev_wait = 0;
	long fd2 = dev_open(&p, LXP_O_RDWR | LXP_O_NONBLOCK);
	assert_true(fd2 >= 3);
	g_mock_block = 1;
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_read, fd2, (long)(uintptr_t)rb, sizeof(rb), 0, 0, 0),
		-LXP_EAGAIN);
	assert_int_equal(p.dev_wait, 0);

	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);
	lxp_syscall(&p, LXP_NR_close, fd2, 0, 0, 0, 0, 0);
}

static void test_dev_dup_refcount(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	long fd = dev_open(&p, LXP_O_RDWR);
	assert_true(fd >= 3);
	long fd2 = lxp_syscall(&p, LXP_NR_dup, fd, 0, 0, 0, 0, 0);
	assert_true(fd2 >= 3 && fd2 != fd);
	assert_int_equal(p.fds[fd2].kind, LXP_FD_DEV);
	assert_int_equal(p.fds[fd2].file_idx, p.fds[fd].file_idx); /* share the open */

	/* Closing one dup keeps the open alive (refs 2 → 1, no release). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0), 0);
	assert_int_equal(g_mock_released, 0);
	/* Closing the last reference releases it. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, fd2, 0, 0, 0, 0, 0), 0);
	assert_int_equal(g_mock_released, 1);
}

static void test_dev_getdents(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup(&p, &arena);

	/* Open /dev as a directory and list it — the mock device appears as DT_CHR. */
	long dfd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
				   (long)(uintptr_t) "/dev", LXP_O_RDONLY, 0, 0, 0);
	assert_true(dfd >= 3);

	uint8_t buf[256];
	long n = lxp_syscall(&p, LXP_NR_getdents64, dfd, (long)(uintptr_t)buf, sizeof(buf),
				 0, 0, 0);
	assert_true(n > 0);

	int found = 0;
	for (long off = 0; off < n;) {
		/* linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name[] */
		uint16_t reclen;
		memcpy(&reclen, buf + off + 16, sizeof(reclen));
		uint8_t d_type = buf[off + 18];
		const char *name = (const char *)(buf + off + 19);
		if (strcmp(name, "mock") == 0) {
			found = 1;
			assert_int_equal(d_type, LXP_DT_CHR);
		}
		assert_true(reclen > 0);
		off += reclen;
	}
	assert_true(found);

	lxp_syscall(&p, LXP_NR_close, dfd, 0, 0, 0, 0, 0);
}

static long dma2d_open(lxp_proc_t *p)
{
	return lxp_syscall(p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t) "/dev/dma2d",
			   LXP_O_RDWR, 0, 0, 0);
}

/* A valid solid fill reaches the display port with the fields the guest submitted.
 * region_lo=1..MAX permits any nonzero plane address; the mock never derefs it. */
static void test_dev_dma2d_submit_ok(void **state)
{
	(void)state;
	lxp_proc_t p;
	lxp_arena_t arena;
	setup(&p, &arena);
	lxp_dev_autoreg_dma2d();
	long fd = dma2d_open(&p);
	assert_true(fd >= 0);
	g_mock_dma2d_calls = 0;
	struct lxp_dma2d_submit d;
	memset(&d, 0, sizeof(d));
	d.mode = LXP_DMA2D_R2M;
	d.w = 8;
	d.h = 8;
	d.output_address = 0x1000;
	d.output_cf = LXP_DMA2D_CF_RGB565;
	d.reg_to_mem_color = 0xf800; /* red */
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, (long)(uintptr_t)&d, 0, 0, 0), 0);
	assert_int_equal(g_mock_dma2d_calls, 1);
	assert_int_equal(g_mock_dma2d_op.mode, LXP_DMA2D_R2M);
	assert_int_equal(g_mock_dma2d_op.w, 8);
	assert_int_equal(g_mock_dma2d_op.h, 8);
	assert_int_equal((uint32_t)g_mock_dma2d_op.out_addr, 0x1000u);
}

/* Every malformed descriptor is rejected BEFORE any address reaches the hardware —
 * the confused-deputy guard (a DMA engine must never be handed guest garbage). */
static void test_dev_dma2d_rejects_bad_descriptor(void **state)
{
	(void)state;
	lxp_proc_t p;
	lxp_arena_t arena;
	setup(&p, &arena);
	lxp_dev_autoreg_dma2d();
	long fd = dma2d_open(&p);
	assert_true(fd >= 0);
	struct lxp_dma2d_submit d;
	long a = (long)(uintptr_t)&d;

	/* NULL descriptor pointer → EFAULT (region_lo=1 rejects addr 0). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, 0, 0, 0, 0),
			 -LXP_EFAULT);

#define BASE()                                                                 \
	do {                                                                   \
		memset(&d, 0, sizeof(d));                                      \
		d.mode = LXP_DMA2D_R2M;                                        \
		d.w = 8;                                                       \
		d.h = 8;                                                       \
		d.output_address = 0x1000;                                     \
		d.output_cf = LXP_DMA2D_CF_RGB565;                             \
	} while (0)

	/* NULL plane address → EFAULT (user_ok IS applied to the plane, not just the desc). */
	BASE();
	d.output_address = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, a, 0, 0, 0),
			 -LXP_EFAULT);
	/* illegal mode / output colour format → EINVAL. */
	BASE();
	d.mode = 99;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, a, 0, 0, 0),
			 -LXP_EINVAL);
	BASE();
	d.output_cf = 99;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, a, 0, 0, 0),
			 -LXP_EINVAL);
	/* oversized dimension / span → EINVAL (bounds the arithmetic below uint64 overflow). */
	BASE();
	d.w = 5000;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, a, 0, 0, 0),
			 -LXP_EINVAL);
	BASE();
	d.w = 4096;
	d.h = 4096;
	d.output_cf = LXP_DMA2D_CF_ARGB8888; /* ~64 MB > DMA2D_MAX_SPAN */
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, a, 0, 0, 0),
			 -LXP_EINVAL);
	/* a blit with an illegal fg colour format → EINVAL (the fg plane is validated too). */
	BASE();
	d.mode = LXP_DMA2D_M2M;
	d.fg_address = 0x2000;
	d.fg_cf = 99;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, fd, TEST_DMA2D_SUBMIT, a, 0, 0, 0),
			 -LXP_EINVAL);
#undef BASE
}

int test_linux_dev_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_dev_open_close),
		cmocka_unit_test(test_dev_read_write),
		cmocka_unit_test(test_dev_ioctl),
		cmocka_unit_test(test_dev_input_eviocgname_size),
		cmocka_unit_test(test_dev_input_syn_dropped_on_overrun),
		cmocka_unit_test(test_dev_input_write_injects_touch),
		cmocka_unit_test(test_dev_accmode_enforced),
		cmocka_unit_test(test_dev_fb_flush_spans_crossed_rows),
		cmocka_unit_test(test_dev_fb_dma2d_blit),
		cmocka_unit_test(test_dev_mmap),
		cmocka_unit_test(test_dev_stat_lseek_poll),
		cmocka_unit_test(test_dev_deferred_block),
		cmocka_unit_test(test_dev_dup_refcount),
		cmocka_unit_test(test_dev_getdents),
		cmocka_unit_test(test_dev_dma2d_submit_ok),
		cmocka_unit_test(test_dev_dma2d_rejects_bad_descriptor),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
