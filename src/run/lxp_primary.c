/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private primary-event dispatcher.
 */

#include "run/lxp_coordinator.h"

struct lxp_primary_result lxp_handle_primary_event(const lxp_os_ops_t *eng,
						   const lxp_run_config_t *cfg, int slot,
						   int event, int *next_pid)
{
	struct lxp_primary_result result = {
		.flow = LXP_PRIMARY_HANDLED,
	};

	if ((unsigned int)slot >= LXP_NSLOT) {
		result.flow = LXP_PRIMARY_SCAN_BLOCKED;
		return result;
	}

	switch (event) {
	case LXP_EV_NONE:
		result.flow = LXP_PRIMARY_SCAN_BLOCKED;
		return result;

	case LXP_EV_DEFER:
		execute_deferred(eng, slot);
		return result;

	case LXP_EV_STOP: {
		lxp_proc_t *proc = lxp_slot_proc(slot);
		if (!proc || !proc->stopped || proc->stop_kind != LXP_STOP_READY) {
			result.flow = LXP_PRIMARY_SCAN_BLOCKED;
			return result;
		}
		if (coordinator_park_slot(eng, slot) == LXP_OK)
			notify_parent_stopped(eng, proc->group->ppid, proc->pid, proc->stop_sig);
		return result;
	}

	case LXP_EV_FORK:
		lxp_handle_fork(eng, slot, next_pid);
		return result;

	case LXP_EV_EXEC:
		lxp_handle_exec(eng, cfg, slot);
		return result;

	case LXP_EV_EXIT: {
		struct lxp_exit_result exited = lxp_handle_exit(eng, slot);
		if (exited.stop_coordinator) {
			result.flow = LXP_PRIMARY_STOP;
			result.status = exited.status;
		}
		return result;
	}

	case LXP_EV_SLEEP:
	case LXP_EV_FUTEXWAIT:
	case LXP_EV_WAITPARK:
	case LXP_EV_PIPE:
	case LXP_EV_DEVWAIT:
	case LXP_EV_SOCKWAIT:
#if LXP_ENABLE_NETFS
	case LXP_EV_NETFSWAIT:
#endif
#if LXP_ENABLE_PTY
	case LXP_EV_PTYWAIT:
#endif
	case LXP_EV_SIGSUSPEND:
	case LXP_EV_CONSOLEWAIT:
		(void)coordinator_park_slot(eng, slot);
		return result;

	default:
		/* Unknown/stale event classes cannot own a slot transition. Fall
		 * through to the ordinary blocked-operation scan. */
		result.flow = LXP_PRIMARY_SCAN_BLOCKED;
		return result;
	}
}
