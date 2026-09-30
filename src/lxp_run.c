/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Engine-agnostic Linux-personality coordinator: the run loop, the SVC top half
 * and process-lifecycle policy, driven through the port's lxp_os_ops_t (see
 * lxp_port.h and lxp_seam.h). The NOMMU process model lives here once; each port
 * supplies the SVC trap, the program memory and the task lifecycle. Signal-frame
 * delivery is in lxp_signal.c and the fork/exec/exit transactions are in run/.
 *
 * Every live process occupies a slot and runs in one of the fixed program regions:
 *  - fork/vfork: the parent parks with its full resume context captured; the
 *    child resumes at that context with r0 = 0 in the parent's region, whose
 *    writable data is snapshotted. When the child execs or exits, the data is
 *    restored and the parent resumes with r0 = child pid.
 *  - clone(CLONE_VM): the child co-runs as a thread in the same address space.
 *  - execve: the new image is built in a second region before the old one is
 *    torn down.
 *  - exit: the status is queued on the parent for wait4.
 */

#include <string.h>

#include "lxp_arena.h"
#include "lxp/lxp_diag.h"
#include "lxp_syscall.h"
#include "lxp/lxp_types.h"
#include "lxp/lxp_seam.h"
#include "lxp/lxp_latency.h"
#include "lxp/lxp_run.h"
#include "lxp/lxp_stats.h"
#if LXP_ENABLE_DEV
#include "dev/lxp_dev.h" /* device-layer park/retry + autoreg + tick + kick */
#include "lxp/lxp_display_ops.h"
#include "dev/lxp_dev_input.h"
#endif
#if LXP_ENABLE_NET
#include "net/lxp_net.h" /* socket-layer park/retry + fork/exit fd lifecycle */
#include "lxp/lxp_net_ops.h"
#endif
#if LXP_ENABLE_NETFS
#include "netfs/lxp_netfs.h" /* remote-fs park/retry + init/pump + fork/exit lifecycle */
#include "proc/lxp_exec_stage.h"
#endif
#if LXP_ENABLE_PTY
#include "pty/lxp_pty.h" /* pty-layer park/retry (lxp_pty_retry) */
#endif

#include "lxp_internal.h"
#include "lxp_provider.h"
#include "lxp_run_internal.h" /* g_lxp_sig_save + slot_of/park_frame ↔ src/lxp_signal.c */
#include "fs/lxp_eventfd.h"
#include "fs/lxp_pipe.h"
#include "proc/lxp_procfs.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_image.h"
#include "run/lxp_initial.h"
#include "run/lxp_diag.h"
#include "run/lxp_runtime_store.h"
#include "run/lxp_validate.h"

struct lxp_runtime g_lxp_rt;

int slot_runnable_load(int slot)
{
	return __atomic_load_n(&g_lxp_rt.slots[slot].runnable, __ATOMIC_ACQUIRE) != 0;
}

void slot_runnable_store(int slot, int runnable)
{
	__atomic_store_n(&g_lxp_rt.slots[slot].runnable, runnable != 0, __ATOMIC_RELEASE);
}

/*
 * Lifecycle transactions expose deterministic boundaries to the coordinator
 * tests without carrying a diagnostic control surface into production builds.
 * A failpoint is single-shot: the transaction that observes it must either
 * roll back to the old image or contain the already-committed guest.
 */
#if defined(LXP_TEST_FAILPOINTS)
enum lxp_lifecycle_failpoint g_lxp_lifecycle_failpoint;

int lifecycle_failpoint(enum lxp_lifecycle_failpoint point)
{
	if (g_lxp_lifecycle_failpoint != point)
		return 0;
	g_lxp_lifecycle_failpoint = LXP_FAIL_NONE;
	return 1;
}
#else
int lifecycle_failpoint(enum lxp_lifecycle_failpoint point)
{
	(void)point;
	return 0;
}
#endif

/* ---- shared state ---------------------------------------------------------- */
/*
 * Linker-visible only because the FreeRTOS and standalone QEMU naked SVC
 * vectors load it by symbol name. C seams must use lxp_trap_active(), which
 * supplies the acquire side of this publication.
 */
uint32_t g_lxp_trap_gate;

void lxp_trap_publish(int active)
{
	__atomic_store_n(&g_lxp_trap_gate, active != 0, __ATOMIC_RELEASE);
}

int lxp_trap_active(void)
{
	return __atomic_load_n(&g_lxp_trap_gate, __ATOMIC_ACQUIRE) != 0;
}

long lxp_rt_scope_read(char *buf, size_t cap)
{
	if (!buf || !g_lxp_rt.cfg || !g_lxp_rt.cfg->rt_scope_read)
		return -1;
	return g_lxp_rt.cfg->rt_scope_read(g_lxp_rt.cfg->rt_scope_ctx, buf, cap);
}

int lxp_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t lease_owner);

void lxp_get_resource_stats(struct lxp_resource_stats *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->slots_total = LXP_NSLOT;
	out->regions_total = LXP_NREG;
	out->program_region_bytes = LXP_PROG_REGION_SIZE;
	if (g_lxp_os_ops && g_lxp_os_ops->dyn_pool) {
		size_t dyn_size = 0;
		if (g_lxp_os_ops->dyn_pool(0, &dyn_size))
			out->dynamic_pool_bytes = dyn_size;
	}

	unsigned slots_used = 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (g_lxp_rt.slots[s].proc.alive)
			slots_used++;
	out->slots_free = LXP_NSLOT - slots_used;
	out->processes = slots_used;

	unsigned regions_used = 0;
	for (int r = 0; r < LXP_NREG; r++)
		if (lxp_trap_active() && g_lxp_rt.regions[r].refs != 0)
			regions_used++;
	out->regions_free = LXP_NREG - regions_used;

	uint64_t region_bytes = (uint64_t)out->program_region_bytes + out->dynamic_pool_bytes;
	out->total_bytes = region_bytes * LXP_NREG;
	out->free_bytes = region_bytes * out->regions_free;
	unsigned allocatable = out->regions_free < out->slots_free ? out->regions_free
								   : out->slots_free;
	out->available_bytes = region_bytes * allocatable;
}
/* Map guest region `ridx` cacheable into the coordinator before it services that
 * slot's deferred syscall / parked-op retry (see lxp_os_ops_t.coord_map). Only the
 * run loop's coordinator-context paths call it, so it stays file-local. */
static void lxp_coord_map(int ridx)
{
	if (g_lxp_os_ops && g_lxp_os_ops->coord_map && ridx >= 0)
		g_lxp_os_ops->coord_map(ridx);
}

void guest_view_failure(int slot, int rc)
{
	if (slot < 0 || slot >= LXP_NSLOT || !g_lxp_rt.slots[slot].proc.alive)
		return;
	coordinator_exit_slot(slot, 0, 127, LXP_EXIT_REASON_STATE_CORRUPTION, (uint32_t)(-rc));
}

int coordinator_guest_view_begin(int slot, lxp_guest_view_t *view)
{
	lxp_slot_ref_t ref = slot_ref_at(slot);
	if (!lxp_slot_ref_is_current(ref) || !g_lxp_rt.slots[slot].proc.mm)
		return -LXP_ESRCH;
	lxp_coord_map(g_lxp_rt.slots[slot].proc.mm->region.index);
	return lxp_guest_view_begin(&g_lxp_rt.slots[slot].proc, ref,
				    &g_lxp_rt.slots[slot].generation, LXP_GUEST_READ_WRITE, view);
}

/* access_ok (lxp_guest.c) asks for the shared read-only rootfs span so a read-source user
 * pointer may point into a program's .rodata (shared in-place from the cpio). */
void lxp_rootfs_bounds(uintptr_t *lo, uintptr_t *hi)
{
	*lo = (uintptr_t)g_lxp_rt.rootfs_lo;
	*hi = (uintptr_t)g_lxp_rt.rootfs_hi;
}

/* Private coordinator policies address a process through the slot owner
 * without exposing the runtime table to syscall or backing-object layers. */
lxp_proc_t *lxp_slot_proc(int slot)
{
	return slot >= 0 && slot < LXP_NSLOT ? &g_lxp_rt.slots[slot].proc : NULL;
}

/* Run-scoped console-provider callback. The provider retains the immutable
 * engine table only until its matching unsubscribe returns. */
static void lxp_console_ready(const void *context)
{
	const lxp_os_ops_t *eng = context;
	if (eng && eng->event_post)
		eng->event_post();
}

#if LXP_ENABLE_NET
/* A run-scoped provider callback rather than a public core symbol: the network
 * adapter reports a possible readiness change and LXP chooses how to wake its
 * coordinator. The context is the immutable engine table for this run. */
static void lxp_socket_ready(const void *context)
{
	const lxp_os_ops_t *eng = context;
	if (eng && eng->event_post)
		eng->event_post();
}
#endif

#if LXP_ENABLE_FS
void lxp_fs_completion_ready(const void *context)
{
	__atomic_store_n(&g_lxp_rt.fs_completion_ready, 1, __ATOMIC_RELEASE);
	const lxp_os_ops_t *eng = context;
	if (eng && eng->event_post)
		eng->event_post();
}

int lxp_fs_completion_hint_take(void)
{
	return __atomic_exchange_n(&g_lxp_rt.fs_completion_ready, 0, __ATOMIC_ACQ_REL);
}
#endif

#if LXP_ENABLE_BLOCK
static void lxp_block_ready(const void *context)
{
	const lxp_os_ops_t *eng = context;
	if (eng && eng->event_post)
		eng->event_post();
}
#endif

/*
 * Socket and console waits only need the short retry timeout when their host
 * providers cannot publish readiness changes. Other wait classes retain their
 * polling fallback.
 */
unsigned coordinator_wait_timeout(uint32_t wait_policy, int socket_ready_events,
				  int console_ready_events)
{
	int socket_poll = (wait_policy & LXP_BLOCKED_WAIT_SOCKET) && !socket_ready_events;
	int console_poll = (wait_policy & LXP_BLOCKED_WAIT_CONSOLE) && !console_ready_events;
	return ((wait_policy & LXP_BLOCKED_WAIT_POLL) || socket_poll || console_poll) ? 5u : 50u;
}

#define LXP_COORDINATOR_EVENT_BURST 4u

static int coordinator_control_event(int event)
{
	return event == LXP_EV_EXIT || event == LXP_EV_EXEC || event == LXP_EV_FORK ||
	       event == LXP_EV_STOP;
}

uint8_t deferred_state_load(int slot)
{
	return __atomic_load_n(&g_lxp_rt.slots[slot].deferred.state, __ATOMIC_ACQUIRE);
}

void deferred_state_store(int slot, uint8_t state)
{
	__atomic_store_n(&g_lxp_rt.slots[slot].deferred.state, state, __ATOMIC_RELEASE);
}

void deferred_slot_reassign(int slot)
{
	deferred_state_store(slot, DEFER_IDLE);
	uint32_t next = __atomic_add_fetch(&g_lxp_rt.slots[slot].generation, 1u, __ATOMIC_ACQ_REL);
	if (next == 0) /* reserve zero for the static, never-assigned state */
		(void)__atomic_add_fetch(&g_lxp_rt.slots[slot].generation, 1u, __ATOMIC_ACQ_REL);
}

/* The debugger interface (lxp/lxp_debug.h). */
lxp_debug_image_t g_lxp_dbg[LXP_NSLOT];

__attribute__((noinline)) void lxp_debug_state(int slot)
{
	__asm__ volatile("" : : "r"(slot) : "memory"); /* keep the call and the writes before it */
}

static void slot_debug_set(int slot, const lxp_debug_image_t *image)
{
	g_lxp_dbg[slot] = *image;
	lxp_debug_state(slot);
}

void lxp_slot_debug_clear(int slot)
{
	const lxp_debug_image_t none = {0};
	slot_debug_set(slot, &none);
}

void lxp_slot_signal_reset(int slot)
{
	memset(&g_lxp_sig_save[slot], 0, sizeof(g_lxp_sig_save[slot]));
}

void lxp_slot_signal_clone(int child_slot, int parent_slot)
{
	g_lxp_sig_save[child_slot] = g_lxp_sig_save[parent_slot];
}

int lxp_slot_publish_image(int slot, lxp_proc_t *image, lxp_exec_capture_t *capture,
			   const lxp_debug_image_t *debug)
{
	if (slot < 0 || slot >= LXP_NSLOT || !image || !debug)
		return -LXP_EINVAL;
	lxp_proc_t *dest = &g_lxp_rt.slots[slot].proc;
	if (dest->alive || dest->mm || dest->files || dest->fs_context || dest->sighand ||
	    dest->group)
		return -LXP_EINVAL;

	/* This is an ownership move. Clear the source before a native callback can
	 * observe the now-published destination. */
	memcpy(dest, image, sizeof(*dest));
	memset(image, 0, sizeof(*image));
	image->snapshot = lxp_region_ref_none();
	image->vfork_parent = lxp_slot_ref_none();
	lxp_proc_bind_exec_capture(dest, capture);
	lxp_slot_signal_reset(slot);
	lxp_debug_image_t record = *debug;
	record.comm = dest->comm;
	slot_debug_set(slot, &record);

	/* A fresh image inherits no device capability from an older slot owner. */
	dest->mm->dev_map_lo[0] = dest->mm->dev_map_hi[0] = 0;
	dest->mm->dev_map_lo[1] = dest->mm->dev_map_hi[1] = 0;
	return LXP_OK;
}

int slot_of(const lxp_proc_t *p)
{
	uintptr_t a = (uintptr_t)p;
	uintptr_t base = (uintptr_t)&g_lxp_rt.slots[0];
	if (a < base + offsetof(struct lxp_slot_runtime, proc))
		return -1;
	uintptr_t record = a - offsetof(struct lxp_slot_runtime, proc);
	if (record < base || record >= (uintptr_t)&g_lxp_rt.slots[LXP_NSLOT] ||
	    (record - base) % sizeof(g_lxp_rt.slots[0]) != 0)
		return -1;
	int slot = (int)((record - base) / sizeof(g_lxp_rt.slots[0]));
	return p == &g_lxp_rt.slots[slot].proc ? slot : -1;
}

/* Bounded per-slot stacks of interrupted signal contexts. LinuxThreads can
 * deliver restart/timer signals to several slots concurrently, and a different
 * signal may interrupt an active handler within one slot. r4-r8/r10-r11 are not
 * stored because a C handler preserves them; r9 is explicit because FDPIC uses
 * it as the module GOT. Delivery/restore operations live in lxp_signal.c. The stacks sit
 * in their own section so a host linker script can place them (LXP_SIGNAL_STATE_SECTION). */
struct sig_save_stack_s g_lxp_sig_save[LXP_NSLOT]
	__attribute__((section(LXP_SIGNAL_STATE_SECTION)));

int lxp_signal_process_group(int pgid, int sig)
{
	if (pgid <= 0 || sig <= 0 || sig >= LXP_NSIG)
		return 0;
	int recipients = 0;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
		if (p->alive && p->pid > 1 && p->group && p->group->pgid == pgid) {
			lxp_signal_latch(p, sig);
			recipients++;
		}
	}
	if (recipients && g_lxp_os_ops && g_lxp_os_ops->event_post)
		g_lxp_os_ops->event_post();
	return recipients;
}

void lxp_run_health(lxp_run_health_t *out)
{
	if (!out)
		return;
	out->coord_iters = g_lxp_rt.coord_iters;
	out->active = lxp_trap_active();
}

/* Copy a captured argv/envp vector out of the proc into a static staging buffer (needed
 * because launch() re-inits the slot, clearing the bound capture), writing the
 * NUL-terminated pointers into ptrs[0..count] with a trailing NULL. The capture stores
 * offsets into @p src_buf, so the trusted pointer vector is rebuilt only here, for the
 * launch that consumes it. */
void flatten_vec(char *buf, const char **ptrs, const char *src_buf, const uint16_t *off_vec,
		 int count)
{
	size_t off = 0;
	for (int j = 0; j < count; j++) {
		const char *s = src_buf + off_vec[j];
		size_t n = strlen(s) + 1;
		memcpy(buf + off, s, n);
		ptrs[j] = buf + off;
		off += n;
	}
	ptrs[count] = NULL;
}

/* Tell the host about an unimplemented syscall, except one the guest probes for and
 * falls back from (LXP_SYS_QUIET_ENOSYS: socket() without networking). */
void coordinator_report_enosys(long nr, long result)
{
	if (result == -LXP_ENOSYS && g_lxp_rt.cfg && g_lxp_rt.cfg->on_enosys &&
	    !(lxp_syscall_flags(nr) & LXP_SYS_QUIET_ENOSYS))
		g_lxp_rt.cfg->on_enosys(nr);
}

uint32_t lxp_guest_sched_weight(int slot)
{
	if (slot < 0 || slot >= LXP_NSLOT || !slot_runnable_load(slot))
		return 0;
	return lxp_nice_weight(lxp_proc_nice_get(&g_lxp_rt.slots[slot].proc));
}

/* ---- host task lifecycle --------------------------------------------------- */
uint32_t slot_generation(int sidx)
{
	return __atomic_load_n(&g_lxp_rt.slots[sidx].generation, __ATOMIC_ACQUIRE);
}

lxp_slot_ref_t slot_ref_at(int slot)
{
	return (slot >= 0 && slot < LXP_NSLOT)
		       ? (lxp_slot_ref_t){
				 .index = (int16_t)slot,
				 .generation = slot_generation(slot),
			 }
		       : lxp_slot_ref_none();
}

uint8_t lxp_slot_host_state(int slot)
{
	return slot >= 0 && slot < LXP_NSLOT ? g_lxp_rt.slots[slot].host_state : SLOT_FAILED;
}

void lxp_slot_set_host_state(int slot, uint8_t state)
{
	if (slot >= 0 && slot < LXP_NSLOT && g_lxp_rt.slots[slot].host_state != state) {
		g_lxp_rt.slots[slot].host_state = state;
		lxp_diag_lifecycle_changed();
	}
}

void lxp_slot_proc_reset(int slot)
{
	if (slot < 0 || slot >= LXP_NSLOT)
		return;
	memset(&g_lxp_rt.slots[slot].proc, 0, sizeof(g_lxp_rt.slots[slot].proc));
	g_lxp_rt.slots[slot].proc.snapshot = lxp_region_ref_none();
	g_lxp_rt.slots[slot].proc.vfork_parent = lxp_slot_ref_none();
	lxp_slot_debug_clear(slot);
}

int lxp_slot_ref_current(int slot, lxp_slot_ref_t *out)
{
	if (!out || slot < 0 || slot >= LXP_NSLOT)
		return -LXP_EINVAL;
	uint32_t generation = slot_generation(slot);
	if (generation == 0 || !g_lxp_rt.slots[slot].proc.alive)
		return -LXP_ESRCH;
	*out = slot_ref_at(slot);
	return LXP_OK;
}

int lxp_slot_ref_is_current(lxp_slot_ref_t ref)
{
	return ref.index >= 0 && ref.index < LXP_NSLOT && ref.generation != 0 &&
	       slot_generation(ref.index) == ref.generation && g_lxp_rt.slots[ref.index].proc.alive;
}

const struct lxp_resume_ctx *lxp_slot_resume_view(lxp_slot_ref_t ref)
{
	return lxp_slot_ref_is_current(ref) ? &g_lxp_rt.slots[ref.index].resume : NULL;
}

int lxp_slot_resume_clone_for_fork(lxp_slot_ref_t child, lxp_slot_ref_t parent, uintptr_t child_sp)
{
	if (child.index < 0 || child.index >= LXP_NSLOT || child.generation == 0 ||
	    child.index == parent.index || slot_generation(child.index) != child.generation ||
	    g_lxp_rt.slots[child.index].proc.alive || !lxp_slot_ref_is_current(parent))
		return -LXP_ESRCH;
	g_lxp_rt.slots[child.index].resume = g_lxp_rt.slots[parent.index].resume;
	g_lxp_rt.slots[child.index].resume.sp = child_sp;
	return LXP_OK;
}

int lxp_slot_ref_is_runnable(lxp_slot_ref_t ref)
{
	if (ref.index < 0 || ref.index >= LXP_NSLOT || ref.generation == 0 ||
	    !slot_runnable_load(ref.index))
		return 0;
	return slot_generation(ref.index) == ref.generation && g_lxp_rt.slots[ref.index].proc.alive;
}

int lxp_slot_region_ref(lxp_slot_ref_t ref, lxp_region_ref_t *out)
{
	if (!out || !lxp_slot_ref_is_current(ref) || !g_lxp_rt.slots[ref.index].proc.mm)
		return -LXP_ESRCH;
	lxp_region_ref_t region = g_lxp_rt.slots[ref.index].proc.mm->region;
	if (region.index < 0 || region.index >= LXP_NREG || region.generation == 0 ||
	    g_lxp_rt.regions[region.index].generation != region.generation)
		return -LXP_EINVAL;
	*out = region;
	return LXP_OK;
}

int lxp_memory_policy_validate(const lxp_memory_policy_t *policy)
{
	if (!policy || policy->abi_version != LXP_MEMORY_POLICY_ABI_VERSION ||
	    policy->struct_size != sizeof(*policy) || policy->slot.index < 0 ||
	    policy->slot.index >= LXP_NSLOT || policy->slot.generation == 0 ||
	    policy->address_space.index < 0 || policy->address_space.index >= LXP_NREG ||
	    policy->address_space.generation == 0 || policy->device_generation == 0 ||
	    policy->exec_generation == 0 || policy->copied_text_executable > 1u ||
	    policy->device_count > LXP_MEMORY_DEVICE_MAX || policy->_pad != 0)
		return -LXP_EINVAL;
	if (policy->copied_text_executable) {
		if (policy->copied_text_base == 0 ||
		    policy->copied_text_size != LXP_PROG_REGION_SIZE / 2u ||
		    (policy->copied_text_base & (policy->copied_text_size - 1u)) != 0u ||
		    policy->copied_text_size > UINTPTR_MAX - policy->copied_text_base)
			return -LXP_EINVAL;
	} else if (policy->copied_text_base != 0 || policy->copied_text_size != 0) {
		return -LXP_EINVAL;
	}

	for (unsigned i = 0; i < LXP_MEMORY_DEVICE_MAX; i++) {
		const lxp_device_capability_t *cap = &policy->devices[i];
		if (i < policy->device_count) {
			if (cap->size == 0 || cap->size > UINTPTR_MAX - cap->base ||
			    cap->attrs > LXP_MAP_DEV)
				return -LXP_EINVAL;
		} else if (cap->base != 0 || cap->size != 0 || cap->attrs != 0) {
			return -LXP_EINVAL;
		}
	}
	return LXP_OK;
}

int lxp_slot_memory_policy(lxp_slot_ref_t ref, lxp_memory_policy_t *out)
{
	if (!out || !lxp_slot_ref_is_current(ref))
		return -LXP_ESRCH;
	const lxp_mm_t *mm = g_lxp_rt.slots[ref.index].proc.mm;
	if (!mm || mm->device_generation == 0 || mm->exec_generation == 0)
		return -LXP_EINVAL;
	lxp_region_ref_t region = mm->region;
	if (region.index < 0 || region.index >= LXP_NREG || region.generation == 0 ||
	    g_lxp_rt.regions[region.index].generation != region.generation)
		return -LXP_EINVAL;

	*out = (lxp_memory_policy_t){
		.abi_version = LXP_MEMORY_POLICY_ABI_VERSION,
		.struct_size = sizeof(*out),
		.slot = ref,
		.address_space = region,
		.device_generation = mm->device_generation,
		.exec_generation = mm->exec_generation,
		.copied_text_base = mm->copied_text_base,
		.copied_text_size = mm->copied_text_size,
		.copied_text_executable = mm->copied_text_executable,
	};
	if ((mm->copied_text_executable &&
	     (mm->copied_text_base != mm->region_lo || mm->copied_text_base >= mm->region_hi ||
	      mm->copied_text_size > mm->region_hi - mm->copied_text_base)) ||
	    (!mm->copied_text_executable &&
	     (mm->copied_text_base != 0 || mm->copied_text_size != 0)))
		return -LXP_EINVAL;
	for (unsigned i = 0; i < LXP_MEMORY_DEVICE_MAX; i++) {
		if (mm->dev_map_hi[i] <= mm->dev_map_lo[i])
			continue;
		lxp_device_capability_t *cap = &out->devices[out->device_count++];
		cap->base = mm->dev_map_lo[i];
		cap->size = mm->dev_map_hi[i] - mm->dev_map_lo[i];
		cap->attrs = mm->dev_map_attrs[i];
	}
	return lxp_memory_policy_validate(out);
}

int lxp_slot_report_memory_fault(lxp_slot_ref_t ref, const lxp_guest_fault_t *fault)
{
	if (!fault || !lxp_slot_ref_is_current(ref))
		return -LXP_ESRCH;
	lxp_proc_t *proc = &g_lxp_rt.slots[ref.index].proc;
	proc->exit_status = 139; /* 128 + SIGSEGV */
	proc->exit_reason = LXP_EXIT_REASON_MEMORY_FAULT;
	proc->exit_signal = LXP_SIGSEGV;
	proc->exit_detail = fault->detail;
	proc->exit_address = fault->address;
	(void)lxp_intent_exit(proc, 0);
	lxp_event_post_slot(ref.index);
	return LXP_OK;
}

/* Select one of the two device ranges represented in lxp_proc_t without
 * changing it. The backend map is installed first; only a successful host
 * transition commits the matching access_ok range below. */
#if LXP_ENABLE_DEV
int device_map_index(const lxp_proc_t *p, uintptr_t addr, size_t len)
{
	if (!p || !p->mm || len == 0 || addr > UINTPTR_MAX - len)
		return -LXP_EINVAL;
	int free_map = -1;
	for (int i = 0; i < 2; i++) {
		if (p->mm->dev_map_lo[i] == addr)
			return i;
		if (p->mm->dev_map_lo[i] == 0 && free_map < 0)
			free_map = i;
	}
	return free_map >= 0 ? free_map : -LXP_ENOMEM;
}
#endif

/* The logical mappings live in an mm object, while the hardware MPU entries
 * live in each engine task. Rebuild one slot from its mm after fork, rollback,
 * task replacement, or resume. A clear request (size == 0) removes every
 * device entry owned by the slot. */
int coordinator_restore_mm_maps(int sidx, const lxp_mm_t *mm)
{
	int has_maps = 0;
	for (int i = 0; mm && i < 2; i++)
		if (mm->dev_map_hi[i] > mm->dev_map_lo[i])
			has_maps = 1;
	if (!g_lxp_os_ops->map_device)
		return has_maps ? -LXP_ENODEV : 0;
	if (g_lxp_os_ops->map_device(sidx, 0, 0, 0) != 0)
		return -LXP_ENOMEM;
	for (int i = 0; mm && i < 2; i++) {
		if (mm->dev_map_hi[i] <= mm->dev_map_lo[i])
			continue;
		if (g_lxp_os_ops->map_device(sidx, mm->dev_map_lo[i],
					     mm->dev_map_hi[i] - mm->dev_map_lo[i],
					     mm->dev_map_attrs[i]) != 0) {
			(void)g_lxp_os_ops->map_device(sidx, 0, 0, 0);
			return -LXP_ENOMEM;
		}
	}
	return 0;
}

/* Install a new logical-mm mapping in every live task sharing that mm. Commit
 * the mm metadata only after every engine task accepted it. On failure, rebuild
 * all peers from the still-unmodified mm so a partial hardware update cannot
 * escape into userspace. */
#if LXP_ENABLE_DEV
int coordinator_map_mm_range(lxp_mm_t *mm, uintptr_t addr, size_t len, unsigned attrs)
{
	if (!g_lxp_os_ops->map_device)
		return -LXP_ENODEV;
	for (int s = 0; s < LXP_NSLOT; s++) {
		if (!g_lxp_rt.slots[s].proc.alive || g_lxp_rt.slots[s].proc.mm != mm)
			continue;
		if (g_lxp_os_ops->map_device(s, addr, len, attrs) != 0) {
			for (int r = 0; r < LXP_NSLOT; r++)
				if (g_lxp_rt.slots[r].proc.alive && g_lxp_rt.slots[r].proc.mm == mm)
					(void)coordinator_restore_mm_maps(r, mm);
			return -LXP_ENOMEM;
		}
	}
	return 0;
}
#endif

/* Report a stable snapshot before LXP_EV_EXIT clears/reuses the process slot. The
 * callback is deliberately outside exception context; an embedded host may log
 * it, increment retained counters, or leave it unset for zero runtime cost. */
void notify_guest_exit(int slot, const lxp_proc_t *proc)
{
	if (!g_lxp_rt.cfg || !g_lxp_rt.cfg->on_guest_exit)
		return;
	const lxp_guest_exit_info_t info = {
		.slot = slot,
		.pid = proc->pid,
		.ppid = proc->group->ppid,
		.status = proc->exit_status,
		.comm = proc->comm,
		.reason = proc->exit_reason,
		.signal = proc->exit_signal,
		.detail = proc->exit_detail,
		.address = proc->exit_address,
	};
	g_lxp_rt.cfg->on_guest_exit(g_lxp_rt.cfg->guest_exit_ctx, &info);
}

/* A parent's live children and queued zombies share one bounded accounting
 * budget. This prevents a later child status from being silently dropped. */
int fork_capacity_available(const lxp_proc_t *proc)
{
	if (!proc || !proc->group)
		return 0;
	return proc->group->child_count >= 0 && proc->group->child_count < LXP_MAX_CHILD &&
	       proc->group->live_children >= 0 &&
	       proc->group->live_children < LXP_MAX_CHILD - proc->group->child_count;
}

int thread_group_live_count(const lxp_thread_group_t *group)
{
	int live = 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (g_lxp_rt.slots[s].proc.alive && g_lxp_rt.slots[s].proc.group == group)
			live++;
	return live;
}

void thread_group_request_exit(int source_slot, int status)
{
	if (source_slot < 0 || source_slot >= LXP_NSLOT)
		return;
	lxp_thread_group_t *group = g_lxp_rt.slots[source_slot].proc.group;
	if (!group)
		return;
	group->exiting = 1;
	group->exit_status = status & 0xff;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
		if (!p->alive || p->group != group)
			continue;
		coordinator_exit_slot(s, 1, status & 0xff, LXP_EXIT_REASON_NORMAL, 0);
	}
}

/* execve replaces the entire process image. Once the coordinator reaches the
 * commit point, peer threads may no longer execute in the old shared address
 * space. Stop their host tasks immediately; their normal EV_EXIT teardown
 * releases per-task references on subsequent coordinator passes. */
int thread_group_stop_exec_peers(int source_slot, int failure_status)
{
	lxp_thread_group_t *group = g_lxp_rt.slots[source_slot].proc.group;
	int rc = LXP_OK;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
		if (s == source_slot || !p->alive || p->group != group)
			continue;
		if (coordinator_abort_slot(s) != LXP_OK)
			rc = -LXP_EAGAIN;
		coordinator_exit_slot(s, 0, failure_status & 0xff, LXP_EXIT_REASON_NORMAL, 0);
	}
	return rc;
}

/* Deliver `sig` to a proc PARKED in rt_sigsuspend (the LinuxThreads restart). There is no live
 * frame — the interrupted context is the slot's captured resume context. Save that as the
 * slot's sigreturn frame (to resume with `ret` = -EINTR), then resume the proc INTO its
 * handler; the handler's sa_restorer -> rt_sigreturn restores the saved frame and the syscall
 * returns -EINTR. SIG_IGN just resumes with `ret`; SIG_DFL terminates (the LXP_EV_EXIT pass
 * reaps it). */
void deliver_signal_parked(int slot, lxp_proc_t *proc, int sig, long ret)
{
	struct lxp_signal_delivery delivery;
	enum lxp_signal_action action = lxp_signal_prepare(proc, sig, &delivery);
	if (action == LXP_SIGNAL_IGNORE) {
		(void)coordinator_complete_slot(
			slot_ref_at(slot),
			ret); /* IGN or default-ignore (SIGCHLD/SIGCONT/...) */
		return;
	}
	/* A deferred completion is itself a signal-delivery boundary and the native
	 * task is already parked. Retain its result and let SIGCONT resume it. */
	if (action == LXP_SIGNAL_STOP) {
		proc->stopped = 1;
		proc->stop_kind = LXP_STOP_PARKED;
		proc->stop_sig = (uint8_t)sig;
		proc->stop_r0 = 0;
		(void)coordinator_complete_slot(slot_ref_at(slot), ret);
		notify_parent_stopped(proc->group->ppid, proc->pid, sig);
		return;
	}
	if (action == LXP_SIGNAL_TERMINATE) {
		primary_slot_mark(slot);
		return;
	}
	if (action != LXP_SIGNAL_HANDLER)
		return;
	struct lxp_resume_ctx *resume = &g_lxp_rt.slots[slot].resume;
	struct sig_save_s *sv = delivery.save;
	sv->r0 = (uint32_t)ret;
	sv->r1 = resume->r1;
	sv->r2 = resume->r2;
	sv->r3 = resume->r3;
	sv->r9 = resume->r4_11[5]; /* FDPIC GOT of the parked code — clobbered below (r4_11[5]=r9) */
	sv->r12 = resume->r12;
	sv->lr = resume->lr;
	sv->pc = resume->pc;		      /* the rt_sigsuspend resume point */
	sv->xpsr = resume->xpsr | (1u << 24); /* preserve APSR flags + Thumb */
#if LXP_ENABLE_FPU_CONTEXT
	sv->fp = resume->fp;
#endif
	/* Reuse the slot ctx as the handler-entry frame; sp + r4-r11 stay = the thread's, except r9
	 * (the handler's own GOT for FDPIC — resolve_handler derefs the {entry,GOT} funcdescs; the
	 * restart handler lives in libpthread, a different module than the interrupted libc). */
	if (proc->is_fdpic)
		resume->r4_11[5] = delivery.got;      /* r9 = handler's GOT */
	resume->lr = delivery.restorer | 1u;	      /* return -> sa_restorer entry -> sigreturn */
	resume->pc = delivery.entry | 1u;	      /* enter the handler (Thumb) */
	coordinator_resume_slot(slot, proc->mm->region.index, resume, sig); /* r0 = signo */
}

/* Execute one READY mailbox in privileged task context. The lower-priority guest
 * is suspended before its host syscall runs; immediate completion resumes that
 * same task, while a blocking syscall leaves it parked for the established wait
 * event. Host RT tasks above the coordinator can preempt all work performed here. */
void execute_deferred(int slot)
{
	uint8_t expected = DEFER_READY;
	if (!__atomic_compare_exchange_n(&g_lxp_rt.slots[slot].deferred.state, &expected,
					 DEFER_RUNNING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return;
	struct deferred_req *req = &g_lxp_rt.slots[slot].deferred;
	lxp_proc_t *proc = &g_lxp_rt.slots[slot].proc;
	if (!proc->alive || !lxp_slot_ref_equal(req->owner, slot_ref_at(slot))) {
		deferred_state_store(slot, DEFER_IDLE);
		if (proc->intent.kind == LXP_INTENT_DEFERRED_SYSCALL)
			(void)lxp_intent_complete(proc, LXP_INTENT_DEFERRED_SYSCALL);
		return;
	}
	if (coordinator_park_slot(slot) != LXP_OK) {
		deferred_state_store(slot, DEFER_IDLE);
		return;
	}
	lxp_guest_view_t view;
	int view_rc = coordinator_guest_view_begin(slot, &view);
	if (view_rc != LXP_OK) {
		deferred_state_store(slot, DEFER_IDLE);
		guest_view_failure(slot, view_rc);
		return;
	}
#if LXP_ENABLE_LATENCY
	{ /* publish -> claim. Recorded only for a live, generation-matched entry:
	   * a discarded one never waited on the coordinator. */
		uint64_t now = 0;
		lxp_time_ns(&now);
		if (now > req->pub_ns)
			lxp_lat_wake(slot, now - req->pub_ns);
	}
#endif

	/* A signal pending when the coordinator picks up a deferred syscall is NOT delivered
	 * here with a forced -EINTR: that spuriously interrupts a NON-restartable syscall the
	 * guest never expects to fail with EINTR (e.g. close(), whose -1 return busybox then
	 * dereferences as a pointer -> SIGSEGV — reproduced by a 4-stage pipe, where SIGCHLDs
	 * from the children race the shell's pipe-fd closes). Instead run the syscall now; if it
	 * blocks it sets a wait flag and the event loop delivers the pending signal against the
	 * parked op (with -EINTR, the correct restart point); if it completes, the tail below
	 * delivers the signal with the syscall's ACTUAL result. */
	long nr = (long)(int32_t)g_lxp_rt.slots[slot].resume.r4_11[3]; /* captured r7 */
	long a0 = (long)(int32_t)req->a0;
	long a1 = (long)(int32_t)g_lxp_rt.slots[slot].resume.r1;
	long a2 = (long)(int32_t)g_lxp_rt.slots[slot].resume.r2;
	long a3 = (long)(int32_t)g_lxp_rt.slots[slot].resume.r3;
	long a4 = (long)(int32_t)g_lxp_rt.slots[slot].resume.r4_11[0];
	long a5 = (long)(int32_t)g_lxp_rt.slots[slot].resume.r4_11[1];
	(void)lxp_intent_complete(proc, LXP_INTENT_DEFERRED_SYSCALL);
	long r = lxp_syscall(proc, nr, a0, a1, a2, a3, a4, a5);
	coordinator_report_enosys(nr, r);
	deferred_state_store(slot, DEFER_IDLE);

	/* Existing retry state owns completion from here and expects the parked host
	 * task to remain present; exec/exit are likewise consumed by higher-level events. The
	 * deferred event hint was consumed before entering this function, so publish
	 * the follow-on state before returning to the coordinator wait loop. */
	if (proc->wait.kind != LXP_WAIT_NONE || proc->intent.kind != LXP_INTENT_NONE) {
		primary_slot_mark(slot);
		lxp_guest_view_end(&view);
		return;
	}

	int psig = pending_take(proc);
	if (psig) {
		deliver_signal_parked(slot, proc, psig, r);
		lxp_guest_view_end(&view);
		return;
	}
	lxp_guest_view_end(&view);
	(void)coordinator_complete_slot(slot_ref_at(slot), r);
}

/* A failed abort leaves the native task and its Linux resources intact by
 * contract. Keep the trap route active and retry until every generation-
 * qualified native owner is synchronously gone. There is no safe recovery
 * which returns to the host while a guest can still execute; a permanent port
 * failure deliberately remains here for the host watchdog to contain. */
static void coordinator_quiesce_all(void)
{
	for (int s = 0; s < LXP_NSLOT; s++) {
		while (coordinator_abort_slot(s) != LXP_OK)
			g_lxp_os_ops->event_wait(1u);
	}
}

/* Stop every host task before releasing resource objects: descriptor close
 * hooks and request cancellation touch state a live guest could otherwise
 * still mutate. This is the common path for normal completion, halt, timeout
 * and launch failure, so a later lxp_run() never inherits the prior run. */
/* Every pool a process or open descriptor references: regions and vfork guards, process
 * objects, open-file descriptions (with the host files behind hostfs ones), pipes,
 * generated /proc contents, eventfd counters and ptys. */
static void coordinator_reset_pools(void)
{
	lxp_region_runtime_reset();
	lxp_proc_runtime_reset();
	lxp_fd_runtime_reset();
	lxp_pipe_runtime_reset();
	lxp_procfs_runtime_reset();
	lxp_eventfd_runtime_reset();
#if LXP_ENABLE_PTY
	lxp_pty_runtime_reset();
#endif
}

void coordinator_teardown_all(void)
{
	coordinator_quiesce_all();
	lxp_trap_publish(0);
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_rt.slots[s].proc;
		deferred_slot_reassign(s);
		primary_slot_clear(s);
#if LXP_ENABLE_NETFS
		if (p->wait.kind == LXP_WAIT_NETFS)
			lxp_netfs_cancel(p);
#endif
		lxp_proc_resources_put(p);
		if (g_lxp_os_ops->map_device)
			g_lxp_os_ops->map_device(s, 0, 0, 0);
		if (p->mm) {
			p->mm->dev_map_lo[0] = p->mm->dev_map_hi[0] = 0;
			p->mm->dev_map_lo[1] = p->mm->dev_map_hi[1] = 0;
		}
		if (p->snapshot.index >= 0)
			(void)region_release_if_owned(p->snapshot, slot_ref_at(s));
		proc_mm_put(p);
		lxp_proc_group_put(p);
		g_lxp_sig_save[s].depth = 0;
		slot_runnable_store(s, 0);
		memset(p, 0, sizeof(*p));
		p->snapshot = lxp_region_ref_none();
		p->vfork_parent = lxp_slot_ref_none();
	}

	/* Contain inconsistent ownership metadata as well as the ordinary
	 * reference-balanced case above. No guest survives this boundary. */
	coordinator_reset_pools();
	memset(g_lxp_dbg, 0, sizeof(g_lxp_dbg));
	lxp_diag_forget_natives();
#if LXP_ENABLE_NETFS
	lxp_netfs_shutdown();
#endif
}

static int lxp_run_common(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg,
			  int console_ready_events, const char *path, int argc,
			  const char *const argv[])
{
	if (!eng || !eng->exec_capture || !cfg || !cfg->rootfs || !cfg->rootfs_image ||
	    cfg->rootfs_image_size == 0u || !path || argc < 1 || !argv)
		return LXP_RUN_ELAUNCH;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (!eng->exec_capture(s))
			return LXP_RUN_ELAUNCH;
	g_lxp_rt.cfg = cfg;
	lxp_os_publish(eng);
	g_lxp_rt.rootfs_lo = cfg->rootfs_image;
	g_lxp_rt.rootfs_hi = g_lxp_rt.rootfs_lo + cfg->rootfs_image_size;
	for (int i = 0; i < LXP_NSLOT; i++) {
		slot_runnable_store(i, 0);
		lxp_slot_set_host_state(i, SLOT_FREE);
		g_lxp_rt.slots[i].proc.alive = 0;
		deferred_slot_reassign(i);
	}
	lxp_primary_events_reset();
	lxp_blocked_fair_reset();
	lxp_region_runtime_reset(); /* generations persist, so no earlier run's ref matches */
	lxp_console_reset();
	lxp_stats_reset();
	for (int i = 0; i < LXP_NSLOT; i++)
		g_lxp_sig_save[i].depth = 0;
#if LXP_ENABLE_DEV
	/* Register enabled /dev class drivers on the coordinator thread, where
	 * bounded provider initialization is legal. */
	lxp_dev_autoreg_all();
#endif
#if LXP_ENABLE_NETFS
	/* Copy this run's remote-fs topology and initiate its non-blocking 9P
	 * connection. A down server remains non-fatal and reconnects lazily. */
	if (lxp_netfs_init(cfg->netfs_config) != LXP_OK)
		goto launch_failed;
#endif

	struct lxp_initial_image initial;
	if (lxp_initial_resolve(cfg, path, argc, argv, &initial) != 0)
		goto launch_failed;

	/* Concurrent process model: the run loop COORDINATES the live process SET
	 * (g_lxp_rt.slots[*].proc.alive). Each live proc owns a region + an RTOS thread for
	 * its lifetime; a vfork parent resumes the instant its child execs into its own
	 * region (or exits) so the two co-run. The region table holds one reference
	 * per live task sharing an address space, plus reserved vfork
	 * snapshot/exec-handoff regions. */
	lxp_trap_publish(1);
	lxp_reset_halt_request();
	(void)region_reserve(0, slot_ref_at(0));
	lxp_region_ref_t initial_region = region_ref_at(0);
	lxp_slot_ref_t initial_owner = slot_ref_at(0);
	if (lxp_image_launch(0, initial_region, initial_owner, initial.data, initial.size,
			     1, 0, initial.argc, initial.argv, cfg->env, 0) != 0) {
		goto launch_failed;
	}
	/* Interpreter scripts name the interpreter's final non-symlink image here,
	 * so /proc/self/exe keeps re-execing the ELF which actually runs. */
	g_lxp_rt.slots[0].proc.exec_file_idx = initial.file_index;
	lxp_diag_refresh();
	lxp_diag_checkpoint();

	int rc = LXP_RUN_ETIMEOUT;
	int next_pid = 2;
	int idle = 0;
	unsigned event_cursor = 0;
	unsigned guest_event_burst = 0;
	uint64_t last_refresh_us = 0;
#if LXP_ENABLE_LATENCY
	/* The dispatch below leaves via `continue` from many arms, so the service
	 * time is closed here, at the top of the following iteration, rather than
	 * bracketing each arm and missing whichever one is added next. */
	uint64_t lat_t0 = 0;
	int lat_cls = 0;
#endif
	for (;;) {
		g_lxp_rt.coord_iters++; /* heartbeat: see lxp_run_health() */
#if LXP_ENABLE_LATENCY
		if (lat_cls) {
			uint64_t t = 0;
			lxp_time_ns(&t);
			if (t > lat_t0)
				lxp_lat_service(lat_cls, t - lat_t0);
			lat_cls = 0;
		}
#endif
		if (lxp_halt_requested()) { /* reboot(2)/poweroff: stop the whole system */
			rc = 0;
			break;
		}

		/* Claim ONE published event. The atomic bitmap finds a candidate without
		 * touching the proc table; one brief critical section revalidates and claims
		 * only that slot. Thus both lock duration and lock count are independent of
		 * LXP_NSLOT. Act OUTSIDE the crit — abort/spawn/launch may yield. */
		/* Event classes: enum lxp_ev_class, generated with the latency stats array
		 * and class names from LXP_LAT_CLASS_LIST in lxp_latency.h so they cannot
		 * fall out of step. LXP_EV_NONE (0) means "nothing claimed". */
		struct lxp_claimed_event claimed = coordinator_claim_event(&event_cursor);
		int es = claimed.slot;
		int et = claimed.type;
		/* Lifecycle/control work remains strict. Ordinary guest publications are
		 * capped so an always-runnable syscall producer cannot prevent parked
		 * service classes from reaching their weighted scan. */
		if (es >= 0 && et != LXP_EV_NONE && !coordinator_control_event(et) &&
		    guest_event_burst >= LXP_COORDINATOR_EVENT_BURST) {
			primary_slot_mark(es);
			es = -1;
			et = LXP_EV_NONE;
			guest_event_burst = 0;
		}
#if LXP_ENABLE_LATENCY
		if (es >= 0 && et) { /* dispatch starts here; closed at the loop top */
			lxp_time_ns(&lat_t0);
			lat_cls = et;
		}
#endif
		/* LXP_EV_NONE never consumes es. Normalize its sentinel so strict
		 * target compilers can also prove every event-table access in range. */
		if (es < 0)
			es = 0;

		struct lxp_primary_result primary =
			lxp_handle_primary_event(es, et, &next_pid);
		if (primary.flow == LXP_PRIMARY_STOP) {
			rc = primary.status;
			break;
		}
		if (primary.flow == LXP_PRIMARY_HANDLED) {
			if (coordinator_control_event(et))
				guest_event_burst = 0;
			else if (et != LXP_EV_NONE)
				guest_event_burst++;
			idle = 0;
			continue;
		}

		/* No pending event: resume any sleeper whose deadline passed; assess liveness. */
		uint64_t now = 0;
		lxp_time_us(&now);
		struct lxp_blocked_scan blocked = lxp_scan_blocked(now);
		if (!blocked.any_alive) {
			rc = 0;
			break;
		}
		if (blocked.progress) {
			guest_event_burst = 0;
			idle = 0;
			continue;
		}
		/* Idle watchdog: trip only when nothing is runnable (a true deadlock — all
		 * procs blocked with no waker); a running or sleeping proc resets it. */
		if (blocked.any_busy)
			idle = 0;
		else if (++idle > 20000) {
			rc = LXP_RUN_ETIMEOUT;
			break;
		}
		if (now - last_refresh_us >= 200000ull) {
			last_refresh_us = now;
			lxp_diag_refresh();
			lxp_diag_checkpoint();
		}
#if LXP_ENABLE_DEV
		lxp_dev_tick(now); /* coordinator-thread periodic work (fb flush, touch poll) */
#endif
#if LXP_ENABLE_NETFS
		lxp_netfs_tick(now); /* pump the 9P transport: background clunks + lazy reconnect */
#endif
		/* Block until a program parks (event_post) or the timeout. NOT a busy 1ms poll —
		 * that would preempt running programs every tick and reset their time-slice,
		 * starving a fg command while a CPU-bound background job runs. The timeout is the
		 * NEAREST sleeper deadline (so nanosleep wakes on time, not quantized to a fixed
		 * poll period), clamped to a short poll for wait classes without an event source.
		 * Socket waits use the run-scoped readiness callback when the port advertises it;
		 * portable ports keep the 5ms fallback. */
		int socket_ready_events = 0;
#if LXP_ENABLE_NET
		socket_ready_events = g_lxp_net_ops && (g_lxp_net_ops->capabilities &
							LXP_NET_CAP_SOCKET_READY_EVENT);
#endif
		unsigned to = coordinator_wait_timeout(blocked.wait_policy, socket_ready_events,
						       console_ready_events);
		if (blocked.next_deadline_us != UINT64_MAX && blocked.next_deadline_us > now) {
			uint64_t d_ms = (blocked.next_deadline_us - now + 999u) /
					1000u; /* round up, don't wake early */
			if (d_ms < 1u)
				d_ms = 1u;
			if (d_ms < (uint64_t)to)
				to = (unsigned)d_ms;
		}
		eng->event_wait(to);
	}
	coordinator_teardown_all();
	lxp_diag_refresh();
	lxp_diag_checkpoint();
	return rc;

launch_failed:
	coordinator_teardown_all();
	lxp_diag_refresh();
	lxp_diag_checkpoint();
	return LXP_RUN_ELAUNCH;
}

/* THE port entry (see lxp_run.h). Validate and publish this run's exact
 * providers, then bracket the coordinator with optional host setup/teardown. */
int lxp_run(const lxp_os_ops_t *os_ops, const lxp_net_ops_t *net_ops,
	    const lxp_display_ops_t *display_ops, const lxp_fs_ops_t *fs_ops,
	    const lxp_block_ops_t *block_ops, const lxp_run_config_t *run_config, const char *path,
	    int argc, const char *const argv[])
{
	int rc = LXP_RUN_ELAUNCH;
	int prepare_entered = 0;
	int net_entered = 0;
	int fs_entered = 0;
	int block_entered = 0;
	int dev_entered = 0;
	int console_entered = 0;
	lxp_lat_reset(); /* counters describe THIS run, not a previous one */
	lxp_diag_run_begin();
	if (!lxp_os_ops_valid(os_ops) || !lxp_net_ops_valid(net_ops) ||
	    !lxp_display_ops_valid(display_ops) || !lxp_fs_ops_valid(fs_ops) ||
	    !lxp_block_ops_valid(block_ops) || !lxp_run_config_valid(run_config) || !path ||
	    argc < 1 || !argv)
		return LXP_RUN_ELAUNCH;

	/* Assign even NULL providers so a later sequential run cannot inherit one. */
	lxp_providers_publish(net_ops, display_ops, fs_ops, block_ops);
#if LXP_ENABLE_DEV
	lxp_dev_run_begin();
	dev_entered = 1;
#endif
#if LXP_ENABLE_NET
	if (net_ops->run_begin(lxp_socket_ready, os_ops) != LXP_OK)
		goto out;
	net_entered = 1;
	lxp_sock_run_begin(run_config->netif);
#endif
#if LXP_ENABLE_FS
	if (fs_ops->run_begin(lxp_fs_completion_ready, os_ops) != LXP_OK)
		goto out;
	fs_entered = 1;
#endif
#if LXP_ENABLE_BLOCK
	if (block_ops->run_begin(lxp_block_ready, os_ops) != LXP_OK)
		goto out;
	block_entered = 1;
#endif
#if LXP_ENABLE_DEV_INPUT
	/* Publish this run's geometry including explicit zero-to-default semantics,
	 * so sequential runs cannot inherit a predecessor's panel dimensions. */
	lxp_display_set_geometry(run_config->display_width, run_config->display_height);
#endif

	if (os_ops->rootfs_window)
		os_ops->rootfs_window(run_config->rootfs_image, run_config->rootfs_image_size);

	if (os_ops->prepare) {
		prepare_entered = 1;
		if (os_ops->prepare() < 0)
			goto out;
	}
	if (os_ops->validate_memory_contract(os_ops->cpu_memory_contract) != LXP_OK)
		goto out;
	if (run_config->console_subscribe) {
		if (run_config->console_subscribe(run_config->io_ctx, lxp_console_ready, os_ops) !=
		    LXP_OK)
			goto out;
		console_entered = 1;
	}
	rc = lxp_run_common(os_ops, run_config, console_entered, path, argc, argv);

out:
	if (console_entered)
		run_config->console_unsubscribe(run_config->io_ctx);
#if LXP_ENABLE_DEV
	if (dev_entered)
		lxp_dev_run_end();
#else
	(void)dev_entered;
#endif
	if (prepare_entered && os_ops->teardown)
		os_ops->teardown();
#if LXP_ENABLE_BLOCK
	if (block_entered)
		block_ops->run_end();
#else
	(void)block_entered;
#endif
#if LXP_ENABLE_FS
	if (fs_entered)
		fs_ops->run_end();
#else
	(void)fs_entered;
#endif
#if LXP_ENABLE_NET
	if (net_entered) {
		lxp_sock_run_end();
		net_ops->run_end();
	}
#else
	(void)net_entered;
#endif
	lxp_os_publish(NULL);
	g_lxp_rt.cfg = NULL;
	g_lxp_rt.rootfs_lo = NULL;
	g_lxp_rt.rootfs_hi = NULL;
	lxp_providers_clear();
	return rc;
}
