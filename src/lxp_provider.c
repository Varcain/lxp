/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Core-owned active provider bindings. Host ports own immutable provider
 * tables; the personality owns which tables are active for a run, and routes its
 * OS services (clock, entropy, cache maintenance, exec staging) through the
 * engine's.
 */
#include "lxp_provider.h"

#include "lxp_linux_uapi.h"
#include "lxp_internal.h"

#include <string.h>

const lxp_os_ops_t *g_lxp_os_ops;
#if LXP_ENABLE_NET
const lxp_net_ops_t *g_lxp_net_ops;
#endif
#if LXP_ENABLE_DEV
const lxp_display_ops_t *g_lxp_display_ops;
#endif
#if LXP_ENABLE_FS
const lxp_fs_ops_t *g_lxp_fs_ops;
#endif
#if LXP_ENABLE_BLOCK
const lxp_block_ops_t *g_lxp_block_ops;
#endif

void lxp_os_publish(const lxp_os_ops_t *ops)
{
	g_lxp_os_ops = ops;
}

void lxp_providers_publish(const lxp_net_ops_t *net_ops, const lxp_display_ops_t *display_ops,
			   const lxp_fs_ops_t *fs_ops, const lxp_block_ops_t *block_ops)
{
#if LXP_ENABLE_NET
	g_lxp_net_ops = net_ops;
#else
	(void)net_ops;
#endif
#if LXP_ENABLE_DEV
	g_lxp_display_ops = display_ops;
#else
	(void)display_ops;
#endif
#if LXP_ENABLE_FS
	g_lxp_fs_ops = fs_ops;
#else
	(void)fs_ops;
#endif
#if LXP_ENABLE_BLOCK
	g_lxp_block_ops = block_ops;
#else
	(void)block_ops;
#endif
}

void lxp_providers_clear(void)
{
#if LXP_ENABLE_NET
	g_lxp_net_ops = NULL;
#endif
#if LXP_ENABLE_DEV
	g_lxp_display_ops = NULL;
#endif
#if LXP_ENABLE_FS
	g_lxp_fs_ops = NULL;
#endif
#if LXP_ENABLE_BLOCK
	g_lxp_block_ops = NULL;
#endif
}

long lxp_provider_error(int result)
{
	switch (result) {
	case LXP_OK:
	case LXP_ERR_EOF:
		return 0;
	case LXP_ERR_WOULD_BLOCK:
	case LXP_ERR_QUEUE_FULL:
	case LXP_ERR_QUEUE_EMPTY:
		return -LXP_EAGAIN;
	case LXP_ERR_NOT_REGISTERED:
		return -LXP_ENODEV;
	case LXP_ERR_INVALID_PARAM:
	case LXP_ERR_INVAL:
		return -LXP_EINVAL;
	case LXP_ERR_BUSY:
		return -LXP_EBUSY;
	case LXP_ERR_READ_ONLY:
		return -LXP_EROFS;
	case LXP_ERR_PERMISSION:
		return -LXP_EACCES;
	case LXP_ERR_NO_MEMORY:
		return -LXP_ENOMEM;
	case LXP_ERR_TIMEOUT:
		return -LXP_ETIMEDOUT;
	case LXP_ERR_NOT_SUPPORTED:
		return -LXP_EOPNOTSUPP;
	case LXP_ERR_NOT_FOUND:
		return -LXP_ENOENT;
	case LXP_ERR_ALREADY_EXISTS:
		return -LXP_EEXIST;
	case LXP_ERR_NO_SPACE:
		return -LXP_ENOSPC;
	case LXP_ERR_NOT_DIR:
		return -LXP_ENOTDIR;
	case LXP_ERR_IS_DIR:
		return -LXP_EISDIR;
	case LXP_ERR_NOT_EMPTY:
		return -LXP_ENOTEMPTY;
	case LXP_ERR_NAME_TOO_LONG:
		return -LXP_ENAMETOOLONG;
	case LXP_ERR_BAD_HANDLE:
		return -LXP_EBADF;
	case LXP_ERR_CROSS_DEVICE:
		return -LXP_EXDEV;
	default:
		return -LXP_EIO;
	}
}

/* ---- OS services routed through the engine ops -----------------------------
 * The personality core calls these instead of host clock/cache primitives, so
 * it carries no direct dependency on any particular OS. The seam
 * (host adapter) fills the ops; the engine is published for the duration of a run. */
int lxp_time_us(uint64_t *out)
{
	if (g_lxp_os_ops && g_lxp_os_ops->time_us)
		return g_lxp_os_ops->time_us(out);
	*out = 0;
	return LXP_ERR_NOT_SUPPORTED;
}
int lxp_time_ns(uint64_t *out)
{
	if (g_lxp_os_ops && g_lxp_os_ops->time_ns)
		return g_lxp_os_ops->time_ns(out);
	*out = 0;
	return LXP_ERR_NOT_SUPPORTED;
}
int lxp_random_fill(void *buf, size_t len)
{
	if ((!buf && len != 0u) || !g_lxp_os_ops || !g_lxp_os_ops->random_fill)
		return (!buf && len != 0u) ? LXP_ERR_INVALID_PARAM : LXP_ERR_NOT_SUPPORTED;
	return g_lxp_os_ops->random_fill(buf, len);
}
uint8_t *lxp_exec_stage(size_t *cap)
{
	if (cap)
		*cap = 0;
	if (!g_lxp_os_ops || !g_lxp_os_ops->exec_stage)
		return NULL;
	return g_lxp_os_ops->exec_stage(cap);
}
int lxp_mem_stats(struct lxp_mem_stats *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	memset(out, 0, sizeof(*out));
	if (!g_lxp_os_ops || !g_lxp_os_ops->mem_stats)
		return LXP_ERR_NOT_SUPPORTED;
	int rc = g_lxp_os_ops->mem_stats(out);
	if (rc != LXP_OK) {
		memset(out, 0, sizeof(*out));
		return rc;
	}
	/* Keep Linux's total/free view internally consistent even if a host port
	 * samples a changing allocator or only populates part of the snapshot. */
	if (out->free > out->total)
		out->free = out->total;
	if (out->used > out->total)
		out->used = out->total;
	if (out->peak_used > out->total)
		out->peak_used = out->total;
	return rc;
}
const char *lxp_system_version(void)
{
	if (g_lxp_os_ops && g_lxp_os_ops->system_version) {
		const char *version = g_lxp_os_ops->system_version();
		if (version && version[0])
			return version;
	}
	return "lxp";
}
void lxp_cache_clean(const void *base, size_t len)
{
	if (g_lxp_os_ops && g_lxp_os_ops->cache_clean)
		g_lxp_os_ops->cache_clean(base, len);
}
void lxp_cache_invalidate(const void *base, size_t len)
{
	if (g_lxp_os_ops && g_lxp_os_ops->cache_invalidate)
		g_lxp_os_ops->cache_invalidate(base, len);
}
int lxp_thread_list(struct lxp_thread_info *out, size_t max_count, size_t *actual_count)
{
	if (g_lxp_os_ops && g_lxp_os_ops->thread_list)
		return g_lxp_os_ops->thread_list(out, max_count, actual_count);
	if (actual_count)
		*actual_count = 0;
	return LXP_ERR_NOT_SUPPORTED;
}

#if LXP_ENABLE_DEV
/* Wake the coordinator so it retries parked device I/O at once (a driver calls this
 * from its data-ready path). */
void lxp_dev_kick(void)
{
	if (g_lxp_os_ops && g_lxp_os_ops->event_post)
		g_lxp_os_ops->event_post();
}
#endif
