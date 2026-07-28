/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private coordinator lifecycle module.
 */

#include "run/lxp_coordinator.h"

enum lxp_handler_outcome {
	LXP_OUTCOME_NO_CHANGE,
	LXP_OUTCOME_RESUME,
	LXP_OUTCOME_REMAIN_PARKED,
	LXP_OUTCOME_LAUNCH,
	LXP_OUTCOME_EXIT,
};

struct lxp_lifecycle_request {
	enum lxp_handler_outcome outcome;
	int slot;
	int region;
	union {
		struct {
			const struct lxp_resume_ctx *ctx;
			long r0;
		} resume;
		struct {
			const lxp_guest_launch_t *launch;
		} launch;
	} data;
};

static void slot_transition_failed(int sidx, int transition, int rc)
{
	if (sidx < 0 || sidx >= LXP_NSLOT)
		return;
	lxp_proc_t *p = lxp_slot_proc(sidx);
	if (!p || !p->alive)
		return;
	p->exit_status = 127;
	p->exit_reason = LXP_EXIT_REASON_HOST_TRANSITION;
	p->exit_signal = 0;
	p->exit_detail = ((uint32_t)(transition & 0xff) << 24) | (uint32_t)(-rc & 0x00ffffff);
	p->exit_address = 0;
	(void)lxp_intent_exit(p, 0);
	primary_slot_mark(sidx);
}

/* The sole applicator for native task lifecycle changes. Event handlers
 * describe the desired outcome; only this module invokes the RTOS callbacks
 * and publishes the resulting host/runnable state. */
static int lxp_lifecycle_apply(const lxp_os_ops_t *eng, const struct lxp_lifecycle_request *request)
{
	if (!eng || !request || request->slot < 0 || request->slot >= LXP_NSLOT)
		return -LXP_EINVAL;

	int sidx = request->slot;
	lxp_proc_t *proc = lxp_slot_proc(sidx);
	uint8_t old = lxp_slot_host_state(sidx);
	int rc;

	switch (request->outcome) {
	case LXP_OUTCOME_NO_CHANGE:
		return LXP_OK;

	case LXP_OUTCOME_EXIT:
		if (!eng->abort_slot)
			return -LXP_EINVAL;
		lxp_slot_set_host_state(sidx, SLOT_EXITING);
		rc = eng->abort_slot(sidx, slot_generation(sidx));
		if (rc == LXP_OK) {
			lxp_slot_set_host_state(sidx, SLOT_DEAD);
			slot_runnable_store(sidx, 0);
			return LXP_OK;
		}
		/* The callback contract says failure leaves the prior host state intact.
		 * Preserve its runnable view and retain all Linux resources until a later
		 * abort succeeds; releasing an mm under a live task would be unsafe. */
		lxp_slot_set_host_state(sidx, SLOT_FAILED);
		slot_runnable_store(sidx, old == SLOT_RUNNING);
		slot_transition_failed(sidx, SLOT_EXITING, rc);
		return rc;

	case LXP_OUTCOME_REMAIN_PARKED:
		if (!eng->park_slot)
			return -LXP_EINVAL;
		if (old == SLOT_PARKED)
			return LXP_OK;
		if (old != SLOT_RUNNING) {
			slot_transition_failed(sidx, SLOT_PARKING, -LXP_EINVAL);
			return -LXP_EINVAL;
		}
		lxp_slot_set_host_state(sidx, SLOT_PARKING);
		rc = eng->park_slot(sidx, slot_generation(sidx));
		if (rc == LXP_OK) {
			lxp_slot_set_host_state(sidx, SLOT_PARKED);
			slot_runnable_store(sidx, 0);
			return LXP_OK;
		}
		lxp_slot_set_host_state(sidx, SLOT_RUNNING);
		slot_runnable_store(sidx, 1);
		/* The guest is already redirected to the engine's park entry. A failed suspend
		 * cannot be rolled back into useful execution; synchronously terminate
		 * it and let the ordinary exit path release ownership. */
		(void)lxp_lifecycle_apply(eng, &(struct lxp_lifecycle_request){
						       .outcome = LXP_OUTCOME_EXIT,
						       .slot = sidx,
					       });
		slot_transition_failed(sidx, SLOT_PARKING, rc);
		return rc;

	case LXP_OUTCOME_RESUME:
		if (!eng->spawn_resume || !proc || !proc->alive ||
		    proc->intent.kind == LXP_INTENT_EXIT)
			return -LXP_EINVAL;
		if (old != SLOT_PARKED && old != SLOT_FREE && old != SLOT_DEAD)
			return -LXP_EAGAIN;
		lxp_spawn_resume_mode_t mode =
			old == SLOT_PARKED ? LXP_SPAWN_RESUME_PARKED : LXP_SPAWN_RESUME_START;
		lxp_slot_set_host_state(sidx, mode == LXP_SPAWN_RESUME_PARKED ? SLOT_RESUMING
									     : SLOT_STARTING);
		/* Publish the generation-qualified dispatch capability before the port
		 * can make the task runnable. A higher-priority guest may issue an SVC
		 * before spawn_resume() returns to the coordinator. */
		slot_runnable_store(sidx, 1);
		rc = eng->spawn_resume(sidx, slot_generation(sidx), request->region,
				       mode, request->data.resume.ctx, request->data.resume.r0);
		if (rc == LXP_OK) {
			lxp_slot_set_host_state(sidx, SLOT_RUNNING);
			return LXP_OK;
		}
		lxp_slot_set_host_state(sidx, old);
		slot_runnable_store(sidx, 0);
		/* A failed persistent resume leaves the old task parked; a failed
		 * initial resume leaves no task. Abort is idempotent in both cases. */
		(void)lxp_lifecycle_apply(eng, &(struct lxp_lifecycle_request){
						       .outcome = LXP_OUTCOME_EXIT,
						       .slot = sidx,
					       });
		slot_transition_failed(sidx, SLOT_RESUMING, rc);
		return rc;

	case LXP_OUTCOME_LAUNCH:
		if (!eng->spawn_launch)
			return -LXP_EINVAL;
		if (old != SLOT_FREE && old != SLOT_DEAD)
			return -LXP_EAGAIN;
		lxp_slot_set_host_state(sidx, SLOT_STARTING);
		/* As with resume, publish before spawn_launch can start a task which
		 * immediately traps back into the personality. */
		slot_runnable_store(sidx, 1);
		rc = eng->spawn_launch(sidx, slot_generation(sidx), request->region,
				       request->data.launch.launch);
		if (rc == LXP_OK) {
			lxp_slot_set_host_state(sidx, SLOT_RUNNING);
			return LXP_OK;
		}
		lxp_slot_set_host_state(sidx, SLOT_DEAD);
		slot_runnable_store(sidx, 0);
		slot_transition_failed(sidx, SLOT_STARTING, rc);
		return rc;
	}
	return -LXP_EINVAL;
}

void *lxp_lifecycle_prepare_park(const lxp_os_ops_t *eng, int sidx,
				 const struct lxp_resume_ctx *ctx)
{
	if (!eng || !eng->park_prepare || !eng->park_slot || sidx < 0 || sidx >= LXP_NSLOT)
		return NULL;
	return eng->park_prepare(sidx, slot_generation(sidx), ctx);
}

int coordinator_abort_slot(const lxp_os_ops_t *eng, int sidx)
{
	return lxp_lifecycle_apply(eng, &(struct lxp_lifecycle_request){
						.outcome = LXP_OUTCOME_EXIT,
						.slot = sidx,
					});
}

int coordinator_park_slot(const lxp_os_ops_t *eng, int sidx)
{
	return lxp_lifecycle_apply(eng, &(struct lxp_lifecycle_request){
						.outcome = LXP_OUTCOME_REMAIN_PARKED,
						.slot = sidx,
					});
}

int coordinator_resume_slot(const lxp_os_ops_t *eng, int sidx, int ridx,
			    const struct lxp_resume_ctx *ctx, long r0val)
{
	if (!ctx)
		return -LXP_ESRCH;
	/*
	 * The dispatch capability must be gone before the RTOS makes this guest
	 * runnable. A higher-priority resumed task may issue its next SVC before
	 * spawn_resume() returns to the coordinator.
	 */
	lxp_proc_t *proc = lxp_slot_proc(sidx);
	if (proc && proc->stopped)
		return -LXP_EAGAIN;
	if (proc && proc->guest_view)
		lxp_guest_view_end(proc->guest_view);
	return lxp_lifecycle_apply(eng, &(struct lxp_lifecycle_request){
						.outcome = LXP_OUTCOME_RESUME,
						.slot = sidx,
						.region = ridx,
						.data.resume =
							{
								.ctx = ctx,
								.r0 = r0val,
							},
					});
}

/* Complete work against a generation-qualified parked slot. Job-control stop
 * owns whether the native task may run: retain the result in the process until
 * SIGCONT if it is stopped, otherwise apply the native resume now. */
int coordinator_complete_slot(const lxp_os_ops_t *eng, lxp_slot_ref_t ref, long r0)
{
	if (!lxp_slot_ref_is_current(ref))
		return -LXP_ESRCH;
	lxp_proc_t *proc = lxp_slot_proc(ref.index);
	const struct lxp_resume_ctx *ctx = lxp_slot_resume_view(ref);
	if (!proc || !proc->alive || !proc->mm || !ctx)
		return -LXP_ESRCH;
	if (lxp_slot_host_state(ref.index) != SLOT_PARKED)
		return -LXP_EAGAIN;
	if (proc->stopped) {
		if (proc->stop_kind != LXP_STOP_PARKED)
			return -LXP_EAGAIN;
		proc->stop_kind = LXP_STOP_READY;
		proc->stop_r0 = r0;
		return LXP_OK;
	}
	return coordinator_resume_slot(eng, ref.index, proc->mm->region.index, ctx, r0);
}

int coordinator_launch_slot(const lxp_os_ops_t *eng, int sidx, int ridx,
			    const lxp_guest_launch_t *launch)
{
	return lxp_lifecycle_apply(eng, &(struct lxp_lifecycle_request){
						.outcome = LXP_OUTCOME_LAUNCH,
						.slot = sidx,
						.region = ridx,
						.data.launch =
							{
								.launch = launch,
							},
					});
}
