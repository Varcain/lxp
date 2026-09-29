/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Ownership of the exec staging buffer. The owner is the process whose own state says it
 * is waiting for the staged image, so no exit, failure or cancellation path has to hand
 * the buffer back.
 */
#include "proc/lxp_exec_stage.h"

#include "lxp/lxp_config.h"
#include "lxp_linux_uapi.h"
#if LXP_ENABLE_NETFS_EXEC
#include "netfs/lxp_netfs.h"
#endif

static struct {
	const lxp_proc_t *owner;
	size_t size;
} g_stage;

static int waits_for_stage(const lxp_proc_t *p)
{
	if (!p || !p->alive)
		return 0;
	if (p->intent.kind == LXP_INTENT_EXEC && p->exec_file_idx == LXP_EXEC_STAGED)
		return 1;
#if LXP_ENABLE_NETFS_EXEC
	if (p->wait.kind == LXP_WAIT_NETFS && p->wait.op == LXP_NETFSW_EXECFETCH)
		return 1;
#endif
	return 0;
}

long lxp_exec_stage_claim(lxp_proc_t *p, uint8_t **buf, size_t *cap)
{
	*buf = lxp_exec_stage(cap);
	if (!*buf || *cap == 0)
		return -LXP_ENOMEM;
	if (g_stage.owner && g_stage.owner != p && waits_for_stage(g_stage.owner))
		return -LXP_EAGAIN;
	g_stage.owner = p;
	g_stage.size = 0;
	return 0;
}

void lxp_exec_stage_publish(const lxp_proc_t *p, size_t size)
{
	if (g_stage.owner == p)
		g_stage.size = size;
}

const uint8_t *lxp_exec_stage_image(size_t *size)
{
	size_t cap;
	uint8_t *buf = lxp_exec_stage(&cap);
	*size = buf && g_stage.size <= cap ? g_stage.size : 0u;
	return *size ? buf : NULL;
}

void lxp_exec_stage_reset(void)
{
	g_stage.owner = NULL;
	g_stage.size = 0;
}
