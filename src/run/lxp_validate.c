/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The provider tables and run configuration lxp_run() accepts: each table carries the ABI
 * version and size it was built against and every operation this build calls, and the
 * configuration's rootfs entries all lie inside its image.
 */
#include "run/lxp_validate.h"

#include "lxp/lxp_config.h"
#if LXP_ENABLE_NETFS
#include "lxp/lxp_netfs_config.h"
#endif

static int cache_geometry_valid(uint32_t flags, uint32_t enabled_flag, uint32_t line_size,
				uint32_t cache_size)
{
	if ((flags & enabled_flag) == 0u)
		return line_size == 0u && cache_size == 0u;
	return line_size >= 16u && (line_size & (line_size - 1u)) == 0u &&
	       cache_size >= line_size && cache_size % line_size == 0u;
}

static int cpu_memory_contract_valid(const lxp_cpu_memory_contract_t *contract)
{
	if (!contract || (contract->flags & ~LXP_CPU_MEMORY_KNOWN_FLAGS) != 0u ||
	    !cache_geometry_valid(contract->flags, LXP_CPU_MEMORY_DCACHE_ENABLED,
				  contract->dcache_line_size, contract->dcache_size) ||
	    !cache_geometry_valid(contract->flags, LXP_CPU_MEMORY_ICACHE_ENABLED,
				  contract->icache_line_size, contract->icache_size))
		return 0;

	if (contract->model == LXP_CPU_MEM_UNCACHED)
		return contract->normal_attrs == LXP_CPU_MEM_ATTR_NORMAL_NC_NSH &&
		       (contract->flags & LXP_CPU_MEMORY_DCACHE_ENABLED) == 0u;
	if (contract->model == LXP_CPU_MEM_COHERENT_SAME_ATTRS)
		return contract->normal_attrs == LXP_CPU_MEM_ATTR_NORMAL_WBWA_NSH &&
		       (contract->flags & LXP_CPU_MEMORY_DCACHE_ENABLED) != 0u;
	return 0;
}

int lxp_os_ops_valid(const lxp_os_ops_t *ops)
{
	if (!ops || !ops->memory.region || !ops->task.spawn_launch ||
	    !ops->task.spawn_resume || !ops->task.abort_slot || !ops->task.park_entry ||
	    !ops->task.park_prepare || !ops->task.park_slot || !ops->core.crit_enter ||
	    !ops->core.crit_exit || !ops->core.event_post || !ops->core.event_wait ||
	    !ops->services.time_us || !ops->services.time_ns || !ops->memory.exec_capture ||
	    !ops->services.random_fill || !ops->memory.publish_executable ||
	    !ops->memory.validate_memory_contract ||
	    !cpu_memory_contract_valid(ops->memory.cpu_memory_contract))
		return 0;
#if LXP_ENABLE_NETFS_EXEC
	if (!ops->memory.exec_stage)
		return 0;
#endif
	for (int r = 0; r < LXP_NREG; r++)
		if (!ops->memory.region(r))
			return 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (!ops->memory.exec_capture(s))
			return 0;
	return 1;
}

int lxp_net_ops_valid(const lxp_net_ops_t *ops)
{
#if LXP_ENABLE_NET
	if (!ops || !ops->run_begin || !ops->run_end ||
	    !ops->sock_open || !ops->sock_accept || !ops->sock_close || !ops->sock_connect ||
	    !ops->sock_bind || !ops->sock_listen || !ops->sock_send || !ops->sock_recv ||
	    !ops->sock_sendto || !ops->sock_recvfrom || !ops->sock_set_nonblock ||
	    !ops->sock_poll || !ops->sock_shutdown || !ops->sock_getsockname ||
	    !ops->sock_getpeername || !ops->sock_get_error || !ops->netif_get_addr ||
	    !ops->netif_get_hwaddr || !ops->netif_get_flags || !ops->netif_set_addr ||
	    !ops->netif_set_up || (ops->capabilities & ~LXP_NET_CAP_SOCKET_READY_EVENT))
		return 0;
#else
	(void)ops;
#endif
	return 1;
}

int lxp_display_ops_valid(const lxp_display_ops_t *ops)
{
	/* Every piece is optional; one that is present must be complete. */
#if LXP_ENABLE_DEV_FB
	const lxp_fb_ops_t *fb = ops ? ops->fb : NULL;
	if (fb && (!fb->init || !fb->get_info || !fb->get_buffer || !fb->present))
		return 0;
#endif
#if LXP_ENABLE_DEV_DMA2D
	const lxp_dma2d_ops_t *dma2d = ops ? ops->dma2d : NULL;
	if (dma2d && (!dma2d->init || !dma2d->submit))
		return 0;
#endif
#if LXP_ENABLE_TOUCH
	const lxp_touch_ops_t *touch = ops ? ops->touch : NULL;
	if (touch && (!touch->init || !touch->read || !touch->deinit))
		return 0;
#endif
	(void)ops;
	return 1;
}

int lxp_fs_ops_valid(const lxp_fs_ops_t *ops)
{
#if LXP_ENABLE_FS
	if (!ops || !ops->run_begin || !ops->run_end ||
	    !ops->request_owner || !ops->request_cancel || !ops->mount || !ops->unmount ||
	    !ops->is_mounted || !ops->volume_stat || !ops->file_open || !ops->object_open ||
	    !ops->file_close || !ops->file_read || !ops->file_write || !ops->file_seek ||
	    !ops->file_stat || !ops->file_truncate || !ops->file_sync || !ops->file_pread ||
	    !ops->file_pwrite || !ops->dir_open || !ops->dir_read || !ops->dir_close ||
	    !ops->path_stat || !ops->path_mkdir || !ops->path_rmdir || !ops->path_unlink ||
	    !ops->path_rename || !ops->metrics)
		return 0;
#else
	(void)ops;
#endif
	return 1;
}

int lxp_providers_valid(const lxp_providers_t *providers)
{
	return providers && lxp_os_ops_valid(providers->os) && lxp_net_ops_valid(providers->net) &&
	       lxp_display_ops_valid(providers->display) && lxp_fs_ops_valid(providers->fs) &&
	       lxp_block_ops_valid(providers->block);
}

int lxp_block_ops_valid(const lxp_block_ops_t *ops)
{
#if LXP_ENABLE_BLOCK
	if (!ops || !ops->run_begin || !ops->run_end ||
	    !ops->request_owner || !ops->request_cancel || !ops->get_info || !ops->open ||
	    !ops->close || !ops->read || !ops->write || !ops->sync)
		return 0;
#else
	(void)ops;
#endif
	return 1;
}

int lxp_run_config_valid(const lxp_run_config_t *cfg)
{
	if (!cfg || !cfg->rootfs || cfg->rootfs_count <= 0 || !cfg->rootfs_image ||
	    cfg->rootfs_image_size == 0u)
		return 0;
	uintptr_t lo = (uintptr_t)cfg->rootfs_image;
	uintptr_t hi = lo + cfg->rootfs_image_size;
	if (hi < lo)
		return 0;
	for (int i = 0; i < cfg->rootfs_count; i++) {
		const lxp_file_t *f = &cfg->rootfs[i];
		if (!f->path || (!f->data && f->size != 0u))
			return 0;
		if (!f->data)
			continue;
		uintptr_t start = (uintptr_t)f->data;
		uintptr_t end = start + f->size;
		if (start < lo || end < start || end > hi)
			return 0;
	}
	const lxp_console_t *console = &cfg->launch.console;
	if (!!console->subscribe != !!console->unsubscribe ||
	    (console->subscribe && (!console->read || !console->poll)))
		return 0;
#if !LXP_ENABLE_NET
	if (cfg->netif)
		return 0;
#endif
#if LXP_ENABLE_NETFS
	if (cfg->netfs_config && !lxp_netfs_config_valid(cfg->netfs_config))
		return 0;
#else
	if (cfg->netfs_config)
		return 0;
#endif
	return 1;
}
