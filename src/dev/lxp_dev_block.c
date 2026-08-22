/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux-compatible raw block class over the run-scoped block provider.
 */

#include "lxp/lxp_config.h"

#if LXP_ENABLE_BLOCK

#include "dev/lxp_dev_block.h"
#include "lxp/lxp_block_ops.h"
#include "lxp/lxp_dev.h"
#include "lxp/lxp_proc.h"
#include "lxp_provider.h"
#include "lxp_text.h"

#include <limits.h>
#include <string.h>

#define LXP_MMC_MAJOR 179u
#define LXP_BLOCK_NODE_COUNT 5u
#define LXP_MBR_SIZE 512u

#define LXP_BLKRRPART 0x125fu
#define LXP_BLKGETSIZE 0x1260u
#define LXP_BLKSSZGET 0x1268u
#define LXP_BLKGETSIZE64_32 0x80041272u
#define LXP_BLKGETSIZE64_64 0x80081272u
#define LXP_HDIO_GETGEO 0x0301u

struct lxp_hd_geometry {
	uint8_t heads;
	uint8_t sectors;
	uint16_t cylinders;
	uint32_t start;
};

struct lxp_block_view {
	const char *path;
	uint64_t first_block;
	uint64_t block_count;
	uint32_t logical_block_size;
	uint8_t partition;
	uint8_t present;
	uint8_t open_count;
};

static struct lxp_block_view g_views[LXP_BLOCK_NODE_COUNT] = {
	{.path = "/dev/mmcblk0", .partition = 0},   {.path = "/dev/mmcblk0p1", .partition = 1},
	{.path = "/dev/mmcblk0p2", .partition = 2}, {.path = "/dev/mmcblk0p3", .partition = 3},
	{.path = "/dev/mmcblk0p4", .partition = 4},
};
static uint8_t g_mbr[LXP_MBR_SIZE];
static struct lxp_dev_open *g_reread_open;
static uint32_t g_run_generation = 1u;
static uint8_t g_provider_readers;
static uint8_t g_provider_writer;

static uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t block_owner(const lxp_proc_t *proc)
{
	return proc ? ((uint64_t)g_run_generation << 32) | (uint32_t)proc->pid : 0u;
}

static void block_select(lxp_proc_t *proc)
{
	if (g_lxp_block_ops && g_lxp_block_ops->request_owner)
		g_lxp_block_ops->request_owner(block_owner(proc));
}

static uint64_t view_size(const struct lxp_block_view *view)
{
	if (!view->present || view->logical_block_size == 0u ||
	    view->block_count > UINT64_MAX / view->logical_block_size)
		return 0u;
	return view->block_count * view->logical_block_size;
}

static void parse_mbr(void)
{
	for (size_t i = 1; i < LXP_BLOCK_NODE_COUNT; i++) {
		g_views[i].present = 0;
		g_views[i].first_block = 0;
		g_views[i].block_count = 0;
		g_views[i].logical_block_size = g_views[0].logical_block_size;
	}
	if (!g_views[0].present || g_mbr[510] != 0x55u || g_mbr[511] != 0xaau)
		return;
	for (size_t i = 0; i < 4; i++) {
		const uint8_t *entry = &g_mbr[446u + i * 16u];
		uint8_t type = entry[4];
		uint64_t first = get_le32(entry + 8);
		uint64_t count = get_le32(entry + 12);
		/* Extended containers are not data partitions. Supporting them requires
		 * walking an EBR chain, so omit them instead of exposing a misleading node. */
		if (type == 0u || type == 0x05u || type == 0x0fu || type == 0x85u || count == 0u ||
		    first >= g_views[0].block_count || count > g_views[0].block_count - first)
			continue;
		int overlaps = 0;
		for (size_t prior = 1; prior <= i; prior++) {
			if (!g_views[prior].present)
				continue;
			uint64_t prior_end =
				g_views[prior].first_block + g_views[prior].block_count;
			uint64_t end = first + count;
			if (first < prior_end && g_views[prior].first_block < end) {
				overlaps = 1;
				break;
			}
		}
		if (overlaps)
			continue;
		g_views[i + 1].first_block = first;
		g_views[i + 1].block_count = count;
		g_views[i + 1].present = 1;
	}
}

static int block_present(struct lxp_dev *dev)
{
	const struct lxp_block_view *view = dev->drv;
	return view && view->present;
}

static uint64_t block_size(struct lxp_dev *dev)
{
	const struct lxp_block_view *view = dev->drv;
	return view ? view_size(view) : 0u;
}

static long block_open(struct lxp_dev *dev, struct lxp_dev_open *open, int flags)
{
	struct lxp_block_view *view = dev->drv;
	if (!view || !view->present || !g_lxp_block_ops)
		return -LXP_ENODEV;
	if (view->open_count == UINT8_MAX)
		return -LXP_EMFILE;
	unsigned provider_flags = (flags & LXP_O_ACCMODE) == LXP_O_RDONLY ? 0u
									  : LXP_BLOCK_OPEN_WRITE;
	if (provider_flags != 0u) {
		if (g_provider_writer || g_provider_readers)
			return -LXP_EBUSY;
		int rc = g_lxp_block_ops->open(provider_flags);
		if (rc != LXP_OK)
			return lxp_provider_error(rc);
		g_provider_writer = 1u;
	} else {
		if (g_provider_writer || g_provider_readers == UINT8_MAX)
			return -LXP_EBUSY;
		if (g_provider_readers == 0u) {
			int rc = g_lxp_block_ops->open(0u);
			if (rc != LXP_OK)
				return lxp_provider_error(rc);
		}
		g_provider_readers++;
	}
	view->open_count++;
	open->u.block.write_lease = provider_flags != 0u;
	return 0;
}

static long block_release(struct lxp_dev *dev, struct lxp_dev_open *open)
{
	struct lxp_block_view *view = dev->drv;
	if (g_reread_open == open)
		g_reread_open = NULL;
	if (view && view->open_count)
		view->open_count--;
	if (!g_lxp_block_ops)
		return 0;
	if (open->u.block.write_lease) {
		if (g_provider_writer) {
			g_provider_writer = 0u;
			g_lxp_block_ops->close(LXP_BLOCK_OPEN_WRITE);
		}
	} else if (g_provider_readers && --g_provider_readers == 0u) {
		g_lxp_block_ops->close(0u);
	}
	return 0;
}

static long block_transfer(struct lxp_dev *dev, struct lxp_dev_open *open, lxp_proc_t *proc,
			   void *buffer, size_t count, int write)
{
	struct lxp_block_view *view = dev->drv;
	uint64_t extent = view_size(view);
	if (!view || !view->present || !g_lxp_block_ops)
		return -LXP_ENODEV;
	if (write && !open->u.block.write_lease)
		return -LXP_EBADF;
	if (open->pos >= extent)
		return write && count ? -LXP_ENOSPC : 0;
	if ((uint64_t)count > extent - open->pos)
		count = (size_t)(extent - open->pos);
	if (count == 0u)
		return 0;
	uint64_t base;
	if (view->first_block > UINT64_MAX / view->logical_block_size)
		return -LXP_EOVERFLOW;
	base = view->first_block * view->logical_block_size;
	if (open->pos > UINT64_MAX - base)
		return -LXP_EOVERFLOW;
	size_t done = 0;
	block_select(proc);
	int rc = write ? g_lxp_block_ops->write(base + open->pos, buffer, count, &done)
		       : g_lxp_block_ops->read(base + open->pos, buffer, count, &done);
	if (rc == LXP_ERR_WOULD_BLOCK)
		return -LXP_EAGAIN;
	if (done > count)
		return -LXP_EIO;
	if (rc != LXP_OK)
		return lxp_provider_error(rc);
	open->pos += done;
	return (long)done;
}

static long block_read(struct lxp_dev *dev, struct lxp_dev_open *open, lxp_proc_t *proc,
		       void *buffer, size_t count)
{
	return block_transfer(dev, open, proc, buffer, count, 0);
}

static long block_write(struct lxp_dev *dev, struct lxp_dev_open *open, lxp_proc_t *proc,
			const void *buffer, size_t count)
{
	return block_transfer(dev, open, proc, (void *)buffer, count, 1);
}

static int put_value(lxp_proc_t *proc, unsigned long arg, const void *value, size_t size)
{
	if (arg == 0u || !lxp_guest_access_ok(proc, (void *)(uintptr_t)arg, size, 1))
		return -LXP_EFAULT;
	return lxp_copy_to_guest(proc, (uintptr_t)arg, value, size) == 0 ? 0 : -LXP_EFAULT;
}

static int partitions_open(void)
{
	for (size_t i = 1; i < LXP_BLOCK_NODE_COUNT; i++)
		if (g_views[i].open_count)
			return 1;
	return 0;
}

static long block_reread(struct lxp_dev *dev, struct lxp_dev_open *open, lxp_proc_t *proc)
{
	struct lxp_block_view *view = dev->drv;
	if (!view || view->partition != 0u)
		return -LXP_EINVAL;
	if (partitions_open())
		return -LXP_EBUSY;
	if (g_reread_open && g_reread_open != open)
		return -LXP_EBUSY;
	g_reread_open = open;
	block_select(proc);
	if (open->u.block.reread_phase == 0u) {
		int rc = g_lxp_block_ops->sync();
		if (rc == LXP_ERR_WOULD_BLOCK)
			return -LXP_EAGAIN;
		if (rc != LXP_OK) {
			g_reread_open = NULL;
			return lxp_provider_error(rc);
		}
		open->u.block.reread_phase = 1u;
	}
	size_t done = 0;
	int rc = g_lxp_block_ops->read(0u, g_mbr, sizeof(g_mbr), &done);
	if (rc == LXP_ERR_WOULD_BLOCK)
		return -LXP_EAGAIN;
	open->u.block.reread_phase = 0u;
	g_reread_open = NULL;
	if (rc != LXP_OK)
		return lxp_provider_error(rc);
	if (done != sizeof(g_mbr))
		return -LXP_EIO;
	parse_mbr();
	return 0;
}

static long block_ioctl(struct lxp_dev *dev, struct lxp_dev_open *open, lxp_proc_t *proc,
			unsigned long command, unsigned long arg)
{
	struct lxp_block_view *view = dev->drv;
	uint64_t bytes = view_size(view);
	if (!view || !view->present)
		return -LXP_ENODEV;
	switch (command) {
	case LXP_BLKSSZGET: {
		uint32_t size = view->logical_block_size;
		return put_value(proc, arg, &size, sizeof(size));
	}
	case LXP_BLKGETSIZE: {
		uint32_t sectors = bytes / 512u > UINT32_MAX ? UINT32_MAX
							     : (uint32_t)(bytes / 512u);
		return put_value(proc, arg, &sectors, sizeof(sectors));
	}
	case LXP_BLKGETSIZE64_32:
	case LXP_BLKGETSIZE64_64:
		return put_value(proc, arg, &bytes, sizeof(bytes));
	case LXP_HDIO_GETGEO: {
		uint64_t cylinders = view->block_count / (255u * 63u);
		struct lxp_hd_geometry geometry = {
			.heads = 255,
			.sectors = 63,
			.cylinders = cylinders > UINT16_MAX ? UINT16_MAX : (uint16_t)cylinders,
			.start = view->first_block > UINT32_MAX ? UINT32_MAX
								: (uint32_t)view->first_block,
		};
		return put_value(proc, arg, &geometry, sizeof(geometry));
	}
	case LXP_BLKRRPART:
		return block_reread(dev, open, proc);
	default:
		return -LXP_ENOTTY;
	}
}

static long block_sync(struct lxp_dev *dev, struct lxp_dev_open *open, lxp_proc_t *proc)
{
	(void)dev;
	(void)open;
	block_select(proc);
	return lxp_provider_error(g_lxp_block_ops->sync());
}

static void block_cancel(struct lxp_dev *dev, struct lxp_dev_open *open, lxp_proc_t *proc)
{
	(void)dev;
	if (g_lxp_block_ops && g_lxp_block_ops->request_cancel)
		g_lxp_block_ops->request_cancel(block_owner(proc));
	if (g_reread_open == open) {
		open->u.block.reread_phase = 0u;
		g_reread_open = NULL;
	}
}

static const struct lxp_dev_ops g_block_dev_ops = {
	.open = block_open,
	.release = block_release,
	.read = block_read,
	.write = block_write,
	.ioctl = block_ioctl,
	.sync = block_sync,
	.cancel = block_cancel,
	.present = block_present,
	.size = block_size,
};

int lxp_block_resolve(const char *path, lxp_block_view_info_t *out)
{
	if (!path || !out)
		return -LXP_EINVAL;
	for (size_t i = 0; i < LXP_BLOCK_NODE_COUNT; i++) {
		if (g_views[i].present && strcmp(path, g_views[i].path) == 0) {
			out->first_block = g_views[i].first_block;
			out->block_count = g_views[i].block_count;
			out->logical_block_size = g_views[i].logical_block_size;
			out->partition = g_views[i].partition;
			return 0;
		}
	}
	return -LXP_ENODEV;
}

long lxp_block_proc_partitions(char *buffer, size_t capacity)
{
	if (!buffer && capacity)
		return -LXP_EINVAL;
	lxp_text_t text = lxp_text_make(buffer, capacity);
	lxp_text_puts(&text, "major minor  #blocks  name\n\n");
	for (size_t i = 0; i < LXP_BLOCK_NODE_COUNT; i++) {
		if (!g_views[i].present)
			continue;
		lxp_text_puts(&text, " 179        ");
		lxp_text_u64(&text, i);
		lxp_text_putc(&text, ' ');
		lxp_text_u64(&text, view_size(&g_views[i]) / 1024u);
		lxp_text_putc(&text, ' ');
		lxp_text_puts(&text, g_views[i].path + 5);
		lxp_text_putc(&text, '\n');
	}
	return (long)text.length;
}

void lxp_dev_autoreg_block(void)
{
	lxp_block_info_t info;
	memset(&info, 0, sizeof(info));
	memset(g_mbr, 0, sizeof(g_mbr));
	g_reread_open = NULL;
	g_provider_readers = 0u;
	g_provider_writer = 0u;
	if (++g_run_generation == 0u)
		g_run_generation = 1u;
	for (size_t i = 0; i < LXP_BLOCK_NODE_COUNT; i++) {
		g_views[i].first_block = 0;
		g_views[i].block_count = 0;
		g_views[i].logical_block_size = 0;
		g_views[i].present = 0;
		g_views[i].open_count = 0;
	}
	if (g_lxp_block_ops) {
		block_select(NULL);
		if (g_lxp_block_ops->get_info(&info) == LXP_OK &&
		    (info.flags & LXP_BLOCK_F_MEDIA_PRESENT) != 0u &&
		    info.logical_block_size >= LXP_MBR_SIZE && info.block_count != 0u) {
			g_views[0].block_count = info.block_count;
			g_views[0].logical_block_size = info.logical_block_size;
			g_views[0].present = 1;
			size_t done = 0;
			if (g_lxp_block_ops->read(0u, g_mbr, sizeof(g_mbr), &done) == LXP_OK &&
			    done == sizeof(g_mbr))
				parse_mbr();
		}
	}
	for (size_t i = 0; i < LXP_BLOCK_NODE_COUNT; i++) {
		struct lxp_dev node = {
			.path = g_views[i].path,
			.ops = &g_block_dev_ops,
			.drv = &g_views[i],
			.major = LXP_MMC_MAJOR,
			.minor = (uint16_t)i,
			.mode = LXP_S_IFBLK | 0600u,
		};
		(void)lxp_dev_register(&node);
	}
}

#endif /* LXP_ENABLE_BLOCK */
