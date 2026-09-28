/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Engine-agnostic Linux-personality run loop + svc dispatch + signal delivery,
 * shared by the Zephyr / FreeRTOS / NuttX ports (see lxp_run.h). The
 * NOMMU process model lives here once; each port supplies the svc trap, the
 * program memory, and the task spawn through a small vtable.
 *
 * Sequentialised vfork/exec/wait (observationally identical to vfork for the
 * shell pattern, since the parent waitpid()s anyway):
 *  - vfork: capture the parent's full resume context (r4-r11/r12/lr/sp/pc) and
 *    park it; the run loop spawns a CHILD resuming at that context with r0=0,
 *    sharing the parent's region until it execs.
 *  - execve: the run loop loads the new image into a SECOND region.
 *  - child exit: queue the status on the parent for wait4, then resume the
 *    parent at the captured context with r0 = child_pid.
 */

#include <string.h>

#include "lxp/lxp_arena.h"
#include "lxp/lxp_diag.h"
#include "lxp/lxp_syscall.h"
#include "lxp/lxp_types.h"
#include "lxp/lxp_seam.h"
#include "lxp/lxp_latency.h"
#include "lxp/lxp_run.h"
#include "lxp/lxp_stats.h"
#if LXP_ENABLE_DEV
#include "lxp/lxp_dev.h" /* device-layer park/retry + autoreg + tick + kick */
#include "lxp/lxp_display_ops.h"
#include "dev/lxp_dev_input.h"
#endif
#if LXP_ENABLE_NET
#include "lxp/lxp_net.h" /* socket-layer park/retry + fork/exit fd lifecycle */
#include "lxp/lxp_net_ops.h"
#endif
#if LXP_ENABLE_NETFS
#include "lxp/lxp_netfs.h" /* remote-fs park/retry + init/pump + fork/exit lifecycle */
#endif
#if LXP_ENABLE_PTY
#include "lxp/lxp_pty.h" /* pty-layer park/retry (lxp_pty_retry) */
#endif

#include "lxp_internal.h" /* lxp_encode_wstatus (shared with sys_wait4) */
#include "lxp_provider.h"
#include "lxp_run_internal.h" /* g_sig_save + slot_of/park_frame ↔ src/lxp_signal.c */
#include "fs/lxp_pipe.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_image.h"
#include "run/lxp_initial.h"
#include "run/lxp_runtime_store.h"
#if defined(LXP_TEST_INTERNALS)
#include "run/lxp_runtime_test.h"
#endif

static struct lxp_slot_runtime g_lxp_slots[LXP_NSLOT];

int slot_runnable_load(int slot)
{
	return __atomic_load_n(&g_lxp_slots[slot].runnable, __ATOMIC_ACQUIRE) != 0;
}

void slot_runnable_store(int slot, int runnable)
{
	__atomic_store_n(&g_lxp_slots[slot].runnable, runnable != 0, __ATOMIC_RELEASE);
}

/*
 * Lifecycle transactions expose deterministic boundaries to the coordinator
 * tests without carrying a diagnostic control surface into production builds.
 * A failpoint is single-shot: the transaction that observes it must either
 * roll back to the old image or contain the already-committed guest.
 */
#if defined(LXP_TEST_FAILPOINTS)
static enum lxp_lifecycle_failpoint g_lifecycle_failpoint;

int lifecycle_failpoint(enum lxp_lifecycle_failpoint point)
{
	if (g_lifecycle_failpoint != point)
		return 0;
	g_lifecycle_failpoint = LXP_FAIL_NONE;
	return 1;
}
#else
int lifecycle_failpoint(enum lxp_lifecycle_failpoint point)
{
	(void)point;
	return 0;
}
#endif

/* Latest native-task census collected by refresh_stats(). A separate known bit
 * distinguishes a clean "no task" result from an engine without introspection
 * or a truncated kernel-thread list. Diagnostic reads never invoke the engine
 * from an arbitrary caller context. */
static uint8_t g_diag_native_known;
static uint8_t g_diag_native_present[LXP_NSLOT];
static uint32_t g_diag_lifecycle_epoch;
static uint32_t g_diag_native_epoch;

static uint32_t diag_epoch_next(uint32_t epoch)
{
	epoch++;
	return epoch != 0 ? epoch : 1;
}

static int diag_native_census_current(void)
{
	return g_diag_native_known && g_diag_native_epoch == g_diag_lifecycle_epoch;
}

/* Rebuild the ps/top snapshot from the live process set + the host kernel threads.
 * Run-loop thread only (the host snapshot may lock its scheduler — unsafe from the svc
 * handler). The seam attaches an explicit slot ID to each guest thread; names
 * remain diagnostic only. The idle thread is folded into /proc/stat idle, not
 * shown as a process (else it crushes top's %CPU math). */
static void refresh_stats(void)
{
	/* Short-lived shell commands must not consume cumulative-CPU slots
	 * forever. The preceding completed snapshot is the safe liveness set. */
	lxp_stats_prune();

	struct lxp_thread_info ti[LXP_MAX_KTHREAD];
	size_t n = 0;
	int trc = lxp_thread_list(ti, LXP_MAX_KTHREAD, &n);
	int overflow = trc == LXP_ERR_QUEUE_FULL;
	if (trc != LXP_OK && trc != LXP_ERR_QUEUE_FULL)
		n = 0; /* no host introspection: /proc shows only the Linux procs */
	if (n > LXP_MAX_KTHREAD) {
		n = LXP_MAX_KTHREAD;
		overflow = 1;
	}
	memset(g_diag_native_present, 0, sizeof(g_diag_native_present));
	g_diag_native_known = trc == LXP_OK;
	g_diag_native_epoch = g_diag_lifecycle_epoch;
	for (size_t i = 0; i < n; i++)
		if (ti[i].lxp_slot >= 0 && ti[i].lxp_slot < LXP_NSLOT)
			g_diag_native_present[ti[i].lxp_slot] = 1;

	/* 1. Charge each live Linux thread's CPU to its explicitly assigned slot. */
	uint64_t idle = 0, busy = 0;
	for (size_t i = 0; i < n; i++) {
		const char *name = ti[i].name ? ti[i].name : "?";
		uint64_t rus = (ti[i].valid_fields & LXP_THREAD_INFO_VALID_RUNNING_TIME)
				       ? ti[i].state_times.running_us
				       : 0;
		int cls = lxp_stats_classify(name);
		if (cls == 1) {
			idle += rus;
			continue;
		}
		busy += rus;
		int s = ti[i].lxp_slot;
		if (s >= 0 && s < LXP_NSLOT && g_lxp_slots[s].proc.alive)
			lxp_stats_charge(g_lxp_slots[s].proc.pid, rus);
	}
	/* 2. Build the snapshot: the live Linux procs, then the kernel threads [name]. */
	lxp_stats_begin();
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_slots[s].proc;
		if (!p->alive)
			continue;
		char state = (slot_runnable_load(s) && p->wait.kind == LXP_WAIT_NONE) ? 'R' : 'S';
		if (lxp_stats_add(p->pid, p->group->ppid, p->comm, state, lxp_proc_cpu_us(p->pid),
				  lxp_proc_nice_get(p), 0) != LXP_OK)
			overflow = 1;
	}
	for (size_t i = 0; i < n; i++) {
		const char *name = ti[i].name ? ti[i].name : "?";
		if (lxp_stats_classify(name) != 0 || ti[i].lxp_slot != LXP_THREAD_SLOT_NONE)
			continue; /* idle or a Linux slot thread */
		int kpid = lxp_kpid_for(name);
		uint64_t running_us = (ti[i].valid_fields & LXP_THREAD_INFO_VALID_RUNNING_TIME)
					      ? ti[i].state_times.running_us
					      : 0;
		if (kpid < 0 || lxp_stats_add(kpid, 0, name, 'S', running_us, 0, 1) != LXP_OK)
			overflow = 1;
	}
	if (overflow)
		(void)lxp_stats_add(LXP_KPID_BASE + LXP_MAX_KTHREAD, 0, "threads-overflow", 'S', 0,
				    0, 1);
	lxp_stats_set_cpu(idle, busy);
}

/* ---- shared state ---------------------------------------------------------- */
/*
 * Linker-visible only because the FreeRTOS and standalone QEMU naked SVC
 * vectors load it by symbol name. C seams must use lxp_trap_active(), which
 * supplies the acquire side of this publication.
 */
uint32_t g_lxp_trap_gate;

static void lxp_trap_publish(int active)
{
	__atomic_store_n(&g_lxp_trap_gate, active != 0, __ATOMIC_RELEASE);
}

int lxp_trap_active(void)
{
	return __atomic_load_n(&g_lxp_trap_gate, __ATOMIC_ACQUIRE) != 0;
}
/* Coordinator heartbeat: bumped once per dispatch-loop iteration, read by a host
 * watchdog through lxp_run_health(). Free-running; a stalled value while active
 * is the wedge signal. volatile + aligned u32 => the cross-task read is atomic
 * without a lock (the reader only needs to observe change, not a precise count). */
static volatile uint32_t g_coord_iters;
static lxp_arena_t g_arenas[LXP_NREG];
/* Exact region reservations, including address spaces and temporary
 * snapshot/exec leases. A committed region belongs to the lxp_mm_t carrying
 * its generation-bearing reference; lease_owner is populated only until a
 * prepared image/snapshot is either committed or aborted. */
static struct lxp_region_runtime g_regions[LXP_NREG];
static struct vfork_snapshot_guard g_vfork_guard[LXP_NSLOT];
/* vfork data isolation: a snapshot of the shared arena's allocator metadata, taken when a vfork
 * child is spawned and restored when it execs/exits. The region+dyn_pool bytes and the
 * coordinator-owned allocator metadata all use the same reserved snapshot region: its
 * g_arenas[] entry is otherwise idle until the child either execs into or releases it. */
static const lxp_run_config_t *g_cfg;
static const lxp_os_ops_t *g_eng; /* for the dispatch to post coordinator events */

long lxp_rt_scope_read(char *buf, size_t cap)
{
	if (!buf || !g_cfg || !g_cfg->rt_scope_read)
		return -1;
	return g_cfg->rt_scope_read(g_cfg->rt_scope_ctx, buf, cap);
}

static lxp_region_ref_t region_ref_at(int region);
int lxp_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t lease_owner);

/* ---- OS-service hooks routed through the engine ops ------------------------
 * The personality core calls these instead of host clock/cache primitives, so
 * it carries no direct dependency on any particular OS. The seam
 * (host adapter) fills the ops; g_eng is live for the duration of a run. */
int lxp_time_us(uint64_t *out)
{
	if (g_eng && g_eng->time_us)
		return g_eng->time_us(out);
	*out = 0;
	return LXP_ERR_NOT_SUPPORTED;
}
int lxp_time_ns(uint64_t *out)
{
	if (g_eng && g_eng->time_ns)
		return g_eng->time_ns(out);
	*out = 0;
	return LXP_ERR_NOT_SUPPORTED;
}
int lxp_random_fill(void *buf, size_t len)
{
	if ((!buf && len != 0u) || !g_eng || !g_eng->random_fill)
		return (!buf && len != 0u) ? LXP_ERR_INVALID_PARAM : LXP_ERR_NOT_SUPPORTED;
	return g_eng->random_fill(buf, len);
}
uint8_t *lxp_exec_stage(size_t *cap)
{
	if (cap)
		*cap = 0;
	if (!g_eng || !g_eng->exec_stage)
		return NULL;
	return g_eng->exec_stage(cap);
}
int lxp_mem_stats(struct lxp_mem_stats *out)
{
	if (!out)
		return LXP_ERR_INVALID_PARAM;
	memset(out, 0, sizeof(*out));
	if (!g_eng || !g_eng->mem_stats)
		return LXP_ERR_NOT_SUPPORTED;
	int rc = g_eng->mem_stats(out);
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
void lxp_get_resource_stats(struct lxp_resource_stats *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->slots_total = LXP_NSLOT;
	out->regions_total = LXP_NREG;
	out->program_region_bytes = LXP_PROG_REGION_SIZE;
	if (g_eng && g_eng->dyn_pool) {
		size_t dyn_size = 0;
		if (g_eng->dyn_pool(0, &dyn_size))
			out->dynamic_pool_bytes = dyn_size;
	}

	unsigned slots_used = 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (g_lxp_slots[s].proc.alive)
			slots_used++;
	out->slots_free = LXP_NSLOT - slots_used;
	out->processes = slots_used;

	unsigned regions_used = 0;
	for (int r = 0; r < LXP_NREG; r++)
		if (lxp_trap_active() && g_regions[r].refs != 0)
			regions_used++;
	out->regions_free = LXP_NREG - regions_used;

	uint64_t region_bytes = (uint64_t)out->program_region_bytes + out->dynamic_pool_bytes;
	out->total_bytes = region_bytes * LXP_NREG;
	out->free_bytes = region_bytes * out->regions_free;
	unsigned allocatable = out->regions_free < out->slots_free ? out->regions_free
								   : out->slots_free;
	out->available_bytes = region_bytes * allocatable;
}
const char *lxp_system_version(void)
{
	if (g_eng && g_eng->system_version) {
		const char *version = g_eng->system_version();
		if (version && version[0])
			return version;
	}
	return "lxp";
}
void lxp_cache_clean(const void *base, size_t len)
{
	if (g_eng && g_eng->cache_clean)
		g_eng->cache_clean(base, len);
}
void lxp_cache_invalidate(const void *base, size_t len)
{
	if (g_eng && g_eng->cache_invalidate)
		g_eng->cache_invalidate(base, len);
}
/* Map guest region `ridx` cacheable into the coordinator before it services that
 * slot's deferred syscall / parked-op retry (see lxp_os_ops_t.coord_map). Only the
 * run loop's coordinator-context paths call it, so it stays file-local. */
static void lxp_coord_map(int ridx)
{
	if (g_eng && g_eng->coord_map && ridx >= 0)
		g_eng->coord_map(ridx);
}

void guest_view_failure(int slot, int rc)
{
	if (slot < 0 || slot >= LXP_NSLOT || !g_lxp_slots[slot].proc.alive)
		return;
	lxp_proc_t *proc = &g_lxp_slots[slot].proc;
	proc->exit_status = 127;
	proc->exit_reason = LXP_EXIT_REASON_STATE_CORRUPTION;
	proc->exit_detail = (uint32_t)(-rc);
	(void)lxp_intent_exit(proc, 0);
	primary_slot_mark(slot);
}

int coordinator_guest_view_begin(int slot, lxp_guest_view_t *view)
{
	lxp_slot_ref_t ref = slot_ref_at(slot);
	if (!lxp_slot_ref_is_current(ref) || !g_lxp_slots[slot].proc.mm)
		return -LXP_ESRCH;
	lxp_coord_map(g_lxp_slots[slot].proc.mm->region.index);
	return lxp_guest_view_begin(&g_lxp_slots[slot].proc, ref, &g_lxp_slots[slot].generation,
				    LXP_GUEST_READ_WRITE, view);
}
int lxp_thread_list(struct lxp_thread_info *out, size_t max_count, size_t *actual_count)
{
	if (g_eng && g_eng->thread_list)
		return g_eng->thread_list(out, max_count, actual_count);
	if (actual_count)
		*actual_count = 0;
	return LXP_ERR_NOT_SUPPORTED;
}

/* The rootfs cpio region [lo, hi). Dynamic FDPIC processes execute busybox.so, ld.so and libc.so
 * text shared in place from this backing store; engine MPU policies grant it user RO+X access.
 * NULL until a run starts. */
static const uint8_t *g_lxp_rootfs_lo;
static const uint8_t *g_lxp_rootfs_hi;

/* access_ok (lxp_syscall.c) asks for the shared read-only rootfs span so a read-source user
 * pointer may point into a program's .rodata (shared in-place from the cpio). Strong override of the
 * weak stub in the syscall layer. */
void lxp_rootfs_bounds(uintptr_t *lo, uintptr_t *hi)
{
	*lo = (uintptr_t)g_lxp_rootfs_lo;
	*hi = (uintptr_t)g_lxp_rootfs_hi;
}

/* Private coordinator policies address a process through the slot owner
 * without exposing the runtime table to syscall or backing-object layers. */
lxp_proc_t *lxp_slot_proc(int slot)
{
	return slot >= 0 && slot < LXP_NSLOT ? &g_lxp_slots[slot].proc : NULL;
}

#if LXP_ENABLE_DEV
/* Wake the coordinator so it retries parked device I/O at once (a driver calls this
 * from its data-ready path). Strong override of the weak no-op in the device core
 * — that stub is used only by the host test, which links no run loop. */
void lxp_dev_kick(void)
{
	if (g_eng && g_eng->event_post)
		g_eng->event_post();
}
#endif

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
static int g_fs_completion_ready;

void lxp_fs_completion_ready(const void *context)
{
	__atomic_store_n(&g_fs_completion_ready, 1, __ATOMIC_RELEASE);
	const lxp_os_ops_t *eng = context;
	if (eng && eng->event_post)
		eng->event_post();
}

int lxp_fs_completion_hint_take(void)
{
	return __atomic_exchange_n(&g_fs_completion_ready, 0, __ATOMIC_ACQ_REL);
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
static unsigned coordinator_wait_timeout(uint32_t wait_policy, int socket_ready_events,
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
	return __atomic_load_n(&g_lxp_slots[slot].deferred.state, __ATOMIC_ACQUIRE);
}

static void deferred_state_store(int slot, uint8_t state)
{
	__atomic_store_n(&g_lxp_slots[slot].deferred.state, state, __ATOMIC_RELEASE);
}

void deferred_slot_reassign(int slot)
{
	deferred_state_store(slot, DEFER_IDLE);
	uint32_t next = __atomic_add_fetch(&g_lxp_slots[slot].generation, 1u, __ATOMIC_ACQ_REL);
	if (next == 0) /* reserve zero for the static, never-assigned state */
		(void)__atomic_add_fetch(&g_lxp_slots[slot].generation, 1u, __ATOMIC_ACQ_REL);
}

/* Per-slot FDPIC runtime load addresses, exported (non-static) for SOURCE-LEVEL GDB DEBUGGING of
 * the userspace program. An FDPIC exec is loaded at runtime addresses (the loadmap relocates each
 * segment independently), so the on-disk ELF's link addresses don't match memory. A GDB helper
 * reads this table and `add-symbol-file <elf> -o <text_base>`s the
 * program, then walks the exec's _DYNAMIC[DT_DEBUG] rendezvous (populated by ld.so once it has run)
 * to auto-load ld.so + every shared library at its own FDPIC bias. The slot
 * runtime's comm[] names the program; text_base/data_base are the
 * loadmap-relocated bases of its text/data segments. */
/* The layout is private but linker-visible for source-level GDB helpers. */
struct lxp_dbg_s g_lxp_dbg[LXP_NSLOT];

lxp_arena_t *lxp_region_arena(int region)
{
	return region >= 0 && region < LXP_NREG ? &g_arenas[region] : NULL;
}

void lxp_slot_signal_reset(int slot)
{
	memset(&g_sig_save[slot], 0, sizeof(g_sig_save[slot]));
}

void lxp_slot_signal_clone(int child_slot, int parent_slot)
{
	g_sig_save[child_slot] = g_sig_save[parent_slot];
}

int lxp_slot_publish_image(int slot, lxp_proc_t *image, lxp_exec_capture_t *capture,
			   const struct lxp_dbg_s *debug)
{
	if (slot < 0 || slot >= LXP_NSLOT || !image || !debug)
		return -LXP_EINVAL;
	lxp_proc_t *dest = &g_lxp_slots[slot].proc;
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
	g_lxp_dbg[slot] = *debug;

	/* A fresh image inherits no device capability from an older slot owner. */
	dest->mm->dev_map_lo[0] = dest->mm->dev_map_hi[0] = 0;
	dest->mm->dev_map_lo[1] = dest->mm->dev_map_hi[1] = 0;
	return LXP_OK;
}

int slot_of(const lxp_proc_t *p)
{
	uintptr_t a = (uintptr_t)p;
	uintptr_t base = (uintptr_t)&g_lxp_slots[0];
	if (a < base + offsetof(struct lxp_slot_runtime, proc))
		return -1;
	uintptr_t record = a - offsetof(struct lxp_slot_runtime, proc);
	if (record < base || record >= (uintptr_t)&g_lxp_slots[LXP_NSLOT] ||
	    (record - base) % sizeof(g_lxp_slots[0]) != 0)
		return -1;
	int slot = (int)((record - base) / sizeof(g_lxp_slots[0]));
	return p == &g_lxp_slots[slot].proc ? slot : -1;
}

/* Capture the post-svc context of frame f into slot s's resume ctx. */
static void capture_ctx(int s, const struct lxp_frame *f)
{
	for (int i = 0; i < 8; i++)
		g_lxp_slots[s].resume.r4_11[i] = f->r[4 + i];
	g_lxp_slots[s].resume.r12 = f->r[12];
	g_lxp_slots[s].resume.lr = f->r[14];
	g_lxp_slots[s].resume.sp = f->r[13];	  /* the seam set r[13] = the pre-svc SP */
	g_lxp_slots[s].resume.pc = f->r[15] | 1u; /* resume after the svc (Thumb) */
	/* Preserve r1-r3 across the parking syscall (Linux preserves r1-r14; only r0 is
	 * the return, supplied by the resume). A guest may reuse an arg register after a
	 * syscall — so leaving these garbage on resume corrupts it (e.g. wait4's options). */
	g_lxp_slots[s].resume.r1 = f->r[1];
	g_lxp_slots[s].resume.r2 = f->r[2];
	g_lxp_slots[s].resume.r3 = f->r[3];
	g_lxp_slots[s].resume.xpsr = f->xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	if (f->fp)
		g_lxp_slots[s].resume.fp = *f->fp;
	else
		memset(&g_lxp_slots[s].resume.fp, 0, sizeof(g_lxp_slots[s].resume.fp));
#endif
}

/* Snapshot a normal syscall and park its guest. A second request for the same
 * slot is impossible while the first task is parked, but the CAS makes that
 * invariant fail closed instead of overwriting an in-flight mailbox. */
static void defer_syscall(struct lxp_frame *f, lxp_proc_t *proc)
{
	int slot = slot_of(proc);
	uint8_t expected = DEFER_IDLE;
	if (slot < 0 || slot >= LXP_NSLOT ||
	    !__atomic_compare_exchange_n(&g_lxp_slots[slot].deferred.state, &expected,
					 DEFER_FILLING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		f->r[0] = (uint32_t)-LXP_EAGAIN;
		return;
	}
	if (lxp_intent_begin(proc, &(lxp_intent_t){
					   .kind = LXP_INTENT_DEFERRED_SYSCALL,
				   }) != 0) {
		deferred_state_store(slot, DEFER_IDLE);
		f->r[0] = (uint32_t)-LXP_EAGAIN;
		return;
	}
	g_lxp_slots[slot].deferred.a0 = f->r[0];
	g_lxp_slots[slot].deferred.owner = (lxp_slot_ref_t){
		.index = (int16_t)slot,
		.generation = slot_generation(slot),
	};
#if LXP_ENABLE_LATENCY
	{ /* the only timer call on the svc top half, and only when instrumented */
		uint64_t t = 0;
		lxp_time_ns(&t);
		g_lxp_slots[slot].deferred.pub_ns = t;
	}
#endif
	deferred_state_store(slot, DEFER_READY);
	park_frame(f, proc);
}

/* Park the program frame until the coordinator reaps the event, and wake the
 * coordinator (it blocks in event_wait rather than busy-polling). Persistent
 * ports prepare a guest-readable resume token while the original svc frame is
 * still live; ports with a native saved-frame restore return NULL. */
void park_frame(struct lxp_frame *f, lxp_proc_t *proc)
{
	int slot = slot_of(proc);
	capture_ctx(slot, f);
	void *token = lxp_lifecycle_prepare_park(g_eng, slot, &g_lxp_slots[slot].resume);
	f->r[0] = (uint32_t)(uintptr_t)token;
	f->r[15] = (uint32_t)((uintptr_t)g_eng->park_entry & ~(uintptr_t)1u);
	f->xpsr |= (1u << 24);
	lxp_event_post_slot(g_eng, slot);
}

/* Bounded per-slot stacks of interrupted signal contexts. LinuxThreads can
 * deliver restart/timer signals to several slots concurrently, and a different
 * signal may interrupt an active handler within one slot. r4-r8/r10-r11 are not
 * stored because a C handler preserves them; r9 is explicit because FDPIC uses
 * it as the module GOT. Delivery/restore operations live in lxp_signal.c. */
struct sig_save_stack_s g_sig_save[LXP_NSLOT];

static lxp_diag_health_t g_diag_health;
static uint32_t diag_intent_mask(int slot)
{
	const lxp_proc_t *p = &g_lxp_slots[slot].proc;
	switch (p->intent.kind) {
	case LXP_INTENT_NONE:
		return LXP_DIAG_INTENT_NONE;
	case LXP_INTENT_DEFERRED_SYSCALL:
		return LXP_DIAG_INTENT_DEFERRED_SYSCALL;
	case LXP_INTENT_FORK:
		return LXP_DIAG_INTENT_FORK;
	case LXP_INTENT_EXEC:
		return LXP_DIAG_INTENT_EXEC;
	case LXP_INTENT_EXIT:
		return LXP_DIAG_INTENT_EXIT;
	default:
		return UINT32_MAX;
	}
}

static uint32_t diag_wait_mask(const lxp_proc_t *p)
{
	switch (p->wait.kind) {
	case LXP_WAIT_NONE:
		return LXP_DIAG_WAIT_NONE;
	case LXP_WAIT_TIMER:
		return LXP_DIAG_WAIT_TIMER;
	case LXP_WAIT_CHILD:
		return LXP_DIAG_WAIT_CHILD;
	case LXP_WAIT_FUTEX:
		return LXP_DIAG_WAIT_FUTEX;
	case LXP_WAIT_PIPE:
		return LXP_DIAG_WAIT_PIPE;
	case LXP_WAIT_CONSOLE:
		return LXP_DIAG_WAIT_CONSOLE;
	case LXP_WAIT_DEVICE:
		return LXP_DIAG_WAIT_DEVICE;
	case LXP_WAIT_SOCKET:
		return LXP_DIAG_WAIT_SOCKET;
	case LXP_WAIT_NETFS:
		return LXP_DIAG_WAIT_NETFS;
	case LXP_WAIT_HOSTFS:
		return LXP_DIAG_WAIT_HOSTFS;
	case LXP_WAIT_PTY:
		return LXP_DIAG_WAIT_PTY;
	case LXP_WAIT_SIGSUSPEND:
		return LXP_DIAG_WAIT_SIGSUSPEND;
	default:
		return UINT32_MAX;
	}
}

static uint8_t diag_task_status(const lxp_proc_t *p)
{
	if (!p->alive)
		return LXP_DIAG_TASK_FREE;
	if (p->intent.kind == LXP_INTENT_EXIT)
		return LXP_DIAG_TASK_ZOMBIE;
	if (p->stopped)
		return LXP_DIAG_TASK_STOPPED;
	return LXP_DIAG_TASK_LIVE;
}

int lxp_diag_slot_snapshot(int slot, lxp_diag_slot_t *out)
{
	if (!out || slot < 0 || slot >= LXP_NSLOT)
		return -LXP_EINVAL;
	const lxp_proc_t *p = &g_lxp_slots[slot].proc;
	memset(out, 0, sizeof(*out));
	out->abi_version = LXP_DIAG_ABI_VERSION;
	out->struct_size = sizeof(*out);
	out->slot = slot;
	out->generation = slot_generation(slot);
	out->pid = p->pid;
	out->tgid = p->group ? p->group->tgid : 0;
	out->ppid = p->group ? p->group->ppid : 0;
	out->region = p->mm ? p->mm->region.index : -1;
	out->vfork_parent_slot = p->vfork_parent.index;
	out->snapshot_region = p->snapshot.index;
	out->host_state = g_lxp_slots[slot].host_state;
	out->task_status = diag_task_status(p);
	out->deferred_state = deferred_state_load(slot);
	out->runnable = slot_runnable_load(slot);
	out->primary_pending = primary_slot_pending(slot);
	out->signal_depth = g_sig_save[slot].depth;
	out->native_task_known = diag_native_census_current();
	out->native_task_present = out->native_task_known ? g_diag_native_present[slot] : 0;
	out->intent_mask = diag_intent_mask(slot);
	out->wait_mask = diag_wait_mask(p);
	out->mm_identity = (uintptr_t)p->mm;
	out->files_identity = (uintptr_t)p->files;
	out->fs_identity = (uintptr_t)p->fs_context;
	out->sighand_identity = (uintptr_t)p->sighand;
	out->group_identity = (uintptr_t)p->group;
	out->mm_refs = p->mm ? p->mm->refs : 0;
	out->files_refs = p->files ? p->files->refs : 0;
	out->fs_refs = p->fs_context ? p->fs_context->refs : 0;
	out->sighand_refs = p->sighand ? p->sighand->refs : 0;
	out->group_refs = p->group ? p->group->refs : 0;
	if (out->region >= 0 && out->region < LXP_NREG) {
		out->region_generation = g_regions[out->region].generation;
		out->region_refs = g_regions[out->region].refs;
	}
	return LXP_OK;
}

int lxp_diag_region_snapshot(int region, lxp_diag_region_t *out)
{
	if (!out || region < 0 || region >= LXP_NREG)
		return -LXP_EINVAL;
	memset(out, 0, sizeof(*out));
	out->abi_version = LXP_DIAG_ABI_VERSION;
	out->struct_size = sizeof(*out);
	out->region = region;
	/* Kept as owner_slot in diagnostic ABI v1: it now reports only an
	 * uncommitted transaction lease. -1 means the address space owns it. */
	out->owner_slot = g_regions[region].lease_owner.index;
	out->refs = g_regions[region].refs;
	out->generation = g_regions[region].generation;
	for (int slot = 0; slot < LXP_NSLOT; slot++)
		if (g_lxp_slots[slot].proc.alive && g_lxp_slots[slot].proc.mm &&
		    g_lxp_slots[slot].proc.mm->region.index == region)
			out->live_users++;
	return LXP_OK;
}

static int diag_error(lxp_diag_error_t *error, lxp_diag_issue_t issue, int slot, int region,
		      uint32_t actual, uint32_t expected)
{
	if (error) {
		memset(error, 0, sizeof(*error));
		error->abi_version = LXP_DIAG_ABI_VERSION;
		error->struct_size = sizeof(*error);
		error->issue = issue;
		error->slot = slot;
		error->region = region;
		error->actual = actual;
		error->expected = expected;
	}
	return -LXP_EINVAL;
}

static unsigned diag_live_resource_users(const void *identity, int resource)
{
	unsigned users = 0;
	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		const lxp_proc_t *p = &g_lxp_slots[slot].proc;
		if (!p->alive)
			continue;
		const void *candidate = resource == 0	? (const void *)p->mm
					: resource == 1 ? (const void *)p->files
					: resource == 2 ? (const void *)p->fs_context
					: resource == 3 ? (const void *)p->sighand
							: (const void *)p->group;
		if (candidate == identity)
			users++;
	}
	return users;
}

int lxp_validate_world(lxp_diag_error_t *error)
{
	if (error) {
		memset(error, 0, sizeof(*error));
		error->abi_version = LXP_DIAG_ABI_VERSION;
		error->struct_size = sizeof(*error);
		error->slot = -1;
		error->region = -1;
	}

	for (int region = 0; region < LXP_NREG; region++) {
		lxp_slot_ref_t lease = g_regions[region].lease_owner;
		int owner = lease.index;
		uint16_t refs = g_regions[region].refs;
		unsigned live_users = 0;
		for (int slot = 0; slot < LXP_NSLOT; slot++)
			if (g_lxp_slots[slot].proc.alive && g_lxp_slots[slot].proc.mm &&
			    g_lxp_slots[slot].proc.mm->region.index == region)
				live_users++;
		if (refs == 0 && owner != -1)
			return diag_error(error, LXP_DIAG_REGION_OWNER_WITHOUT_REFS, owner, region,
					  (uint32_t)owner, UINT32_MAX);
		if (refs != 0 && g_regions[region].generation == 0)
			return diag_error(error, LXP_DIAG_REGION_REFS_WITHOUT_GENERATION, owner,
					  region, 0, 1);
		if (owner >= 0 && (owner >= LXP_NSLOT || lease.generation == 0 ||
				   !lxp_slot_ref_equal(lease, slot_ref_at(owner))))
			return diag_error(
				error, LXP_DIAG_REGION_LEASE_STALE, owner, region, lease.generation,
				owner >= 0 && owner < LXP_NSLOT ? slot_generation(owner) : 0);
		if (refs != 0 && owner < 0 && live_users == 0)
			return diag_error(error, LXP_DIAG_REGION_REFS_WITHOUT_OWNER, -1, region,
					  refs, 0);
	}

	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		const lxp_proc_t *p = &g_lxp_slots[slot].proc;
		uint8_t host = g_lxp_slots[slot].host_state;
		uint8_t deferred = deferred_state_load(slot);
		uint32_t intents = diag_intent_mask(slot);
		uint32_t waits = diag_wait_mask(p);

		if (host > SLOT_FAILED)
			return diag_error(error, LXP_DIAG_BAD_SLOT, slot, -1, host, SLOT_FAILED);
		if (deferred > DEFER_RUNNING)
			return diag_error(error, LXP_DIAG_DEFERRED_STATE_INVALID, slot, -1,
					  deferred, DEFER_RUNNING);
		if (host != SLOT_FREE && slot_generation(slot) == 0)
			return diag_error(error, LXP_DIAG_HOST_STATE_WITHOUT_GENERATION, slot, -1,
					  0, 1);
		if (p->alive && slot_generation(slot) == 0)
			return diag_error(error, LXP_DIAG_HOST_STATE_WITHOUT_GENERATION, slot, -1,
					  0, 1);
		if (deferred != DEFER_IDLE &&
		    (!lxp_slot_ref_is_current(g_lxp_slots[slot].deferred.owner) ||
		     g_lxp_slots[slot].deferred.owner.index != slot))
			return diag_error(error, LXP_DIAG_DEFERRED_GENERATION_STALE, slot, -1,
					  g_lxp_slots[slot].deferred.owner.generation,
					  slot_generation(slot));
		if (p->intent.kind >= LXP_INTENT_COUNT)
			return diag_error(error, LXP_DIAG_MULTIPLE_INTENTS, slot, -1, intents, 1);
		if (p->wait.kind >= LXP_WAIT_COUNT)
			return diag_error(error, LXP_DIAG_MULTIPLE_WAITS, slot, -1, waits, 1);
		if (deferred >= DEFER_READY && p->intent.kind != LXP_INTENT_DEFERRED_SYSCALL &&
		    p->intent.kind != LXP_INTENT_EXIT)
			return diag_error(error, LXP_DIAG_MULTIPLE_INTENTS, slot, -1, intents,
					  LXP_DIAG_INTENT_DEFERRED_SYSCALL);
		if (p->guest_view)
			return diag_error(error, LXP_DIAG_GUEST_VIEW_LEAKED, slot, -1, 1, 0);

		if (!p->alive) {
			if (slot_runnable_load(slot))
				return diag_error(error, LXP_DIAG_FREE_TASK_RUNNABLE, slot, -1, 1,
						  0);
			if (diag_native_census_current() && g_diag_native_present[slot] &&
			    (host == SLOT_FREE || host == SLOT_DEAD))
				return diag_error(error, LXP_DIAG_NATIVE_TASK_LEAKED, slot, -1,
						  host, SLOT_FREE);
			continue;
		}
		if (!p->mm || !p->files || !p->fs_context || !p->sighand || !p->group)
			return diag_error(error, LXP_DIAG_LIVE_TASK_WITHOUT_RESOURCES, slot, -1, 0,
					  5);
		int region = p->mm->region.index;
		if (region < 0 || region >= LXP_NREG)
			return diag_error(error, LXP_DIAG_LIVE_TASK_BAD_REGION, slot, region,
					  (uint32_t)region, LXP_NREG);
		if (g_regions[region].refs == 0)
			return diag_error(error, LXP_DIAG_LIVE_TASK_WITHOUT_REGION_REF, slot,
					  region, 0, 1);
		if (p->mm->region.generation == 0 ||
		    p->mm->region.generation != g_regions[region].generation)
			return diag_error(error, LXP_DIAG_LIVE_TASK_STALE_REGION_REF, slot, region,
					  p->mm->region.generation, g_regions[region].generation);
		unsigned region_users = 0;
		for (int peer = 0; peer < LXP_NSLOT; peer++)
			if (g_lxp_slots[peer].proc.alive && g_lxp_slots[peer].proc.mm &&
			    g_lxp_slots[peer].proc.mm->region.index == region)
				region_users++;
		if (g_regions[region].refs < region_users)
			return diag_error(error, LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL, slot, region,
					  g_regions[region].refs, region_users);

#define CHECK_RESOURCE_REFS(member, which)                                                   \
	do {                                                                                 \
		unsigned users = diag_live_resource_users(p->member, which);                 \
		if (p->member->refs < users)                                                 \
			return diag_error(error, LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL, slot, \
					  region, p->member->refs, users);                   \
	} while (0)
		CHECK_RESOURCE_REFS(mm, 0);
		CHECK_RESOURCE_REFS(files, 1);
		CHECK_RESOURCE_REFS(fs_context, 2);
		CHECK_RESOURCE_REFS(sighand, 3);
		CHECK_RESOURCE_REFS(group, 4);
#undef CHECK_RESOURCE_REFS

		if (slot_runnable_load(slot) && host != SLOT_RUNNING && host != SLOT_FAILED &&
		    host != SLOT_STARTING && host != SLOT_RESUMING)
			return diag_error(error, LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH, slot,
					  region, host, SLOT_RUNNING);
		if (host == SLOT_RUNNING && !slot_runnable_load(slot))
			return diag_error(error, LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH, slot,
					  region, 0, 1);
		if (host == SLOT_PARKED && slot_runnable_load(slot))
			return diag_error(error, LXP_DIAG_PARKED_TASK_RUNNABLE, slot, region, 1, 0);
		if (diag_native_census_current() &&
		    (host == SLOT_RUNNING || host == SLOT_PARKED || host == SLOT_FAILED) &&
		    !g_diag_native_present[slot])
			return diag_error(error, LXP_DIAG_NATIVE_TASK_MISSING, slot, region, 0, 1);
	}
	return LXP_OK;
}

void lxp_diag_size_report(lxp_diag_size_report_t *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->abi_version = LXP_DIAG_ABI_VERSION;
	out->struct_size = sizeof(*out);
	out->slots = LXP_NSLOT;
	out->regions = LXP_NREG;
	out->proc = sizeof(lxp_proc_t);
	out->mm = sizeof(lxp_mm_t);
	out->files = sizeof(lxp_files_t);
	out->fs = sizeof(lxp_fs_context_t);
	out->sighand = sizeof(lxp_sighand_t);
	out->thread_group = sizeof(lxp_thread_group_t);
	out->arena = sizeof(lxp_arena_t);
	out->exec_capture = sizeof(lxp_exec_capture_t);
	out->resume_context = sizeof(struct lxp_resume_ctx);
	out->deferred_request = sizeof(struct deferred_req);
	out->signal_save_stack = sizeof(struct sig_save_stack_s);
	out->vfork_guard = sizeof(struct vfork_snapshot_guard);
	out->debug_record = sizeof(struct lxp_dbg_s);
	out->per_slot_core = sizeof(g_lxp_slots[0]) + out->signal_save_stack + out->vfork_guard +
			     out->debug_record;
	out->per_region_core = out->arena + sizeof(g_regions[0]);
	out->slot_table = sizeof(g_lxp_slots);
	out->coordinator_static = sizeof(g_lxp_slots) + sizeof(g_arenas) + sizeof(g_regions) +
				  sizeof(g_vfork_guard) + lxp_primary_events_bytes() +
				  sizeof(g_lxp_dbg) + sizeof(g_sig_save) +
				  sizeof(g_diag_native_present) + sizeof(g_diag_health);
}

void lxp_diag_health(lxp_diag_health_t *out)
{
	if (out)
		*out = g_diag_health;
}

const char *lxp_diag_host_state_name(unsigned state)
{
	static const char *const names[LXP_DIAG_HOST_COUNT] = {
		[LXP_DIAG_HOST_FREE] = "free",	     [LXP_DIAG_HOST_STARTING] = "starting",
		[LXP_DIAG_HOST_RUNNING] = "running", [LXP_DIAG_HOST_PARKING] = "parking",
		[LXP_DIAG_HOST_PARKED] = "parked",   [LXP_DIAG_HOST_RESUMING] = "resuming",
		[LXP_DIAG_HOST_EXITING] = "exiting", [LXP_DIAG_HOST_DEAD] = "dead",
		[LXP_DIAG_HOST_FAILED] = "failed",
	};
	return state < LXP_DIAG_HOST_COUNT && names[state] ? names[state] : "invalid";
}

const char *lxp_diag_task_status_name(unsigned status)
{
	static const char *const names[LXP_DIAG_TASK_COUNT] = {
		[LXP_DIAG_TASK_FREE] = "free",
		[LXP_DIAG_TASK_LIVE] = "live",
		[LXP_DIAG_TASK_STOPPED] = "stopped",
		[LXP_DIAG_TASK_ZOMBIE] = "zombie",
	};
	return status < LXP_DIAG_TASK_COUNT && names[status] ? names[status] : "invalid";
}

const char *lxp_diag_issue_name(unsigned issue)
{
	static const char *const names[LXP_DIAG_ISSUE_COUNT] = {
		[LXP_DIAG_OK] = "ok",
		[LXP_DIAG_BAD_SLOT] = "bad-slot",
		[LXP_DIAG_BAD_REGION] = "bad-region",
		[LXP_DIAG_REGION_OWNER_WITHOUT_REFS] = "region-owner-without-refs",
		[LXP_DIAG_REGION_REFS_WITHOUT_OWNER] = "region-refs-without-owner",
		[LXP_DIAG_REGION_REFS_WITHOUT_GENERATION] = "region-refs-without-generation",
		[LXP_DIAG_LIVE_TASK_WITHOUT_RESOURCES] = "live-task-without-resources",
		[LXP_DIAG_LIVE_TASK_BAD_REGION] = "live-task-bad-region",
		[LXP_DIAG_LIVE_TASK_WITHOUT_REGION_REF] = "live-task-without-region-ref",
		[LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL] = "resource-refcount-too-small",
		[LXP_DIAG_FREE_TASK_RUNNABLE] = "free-task-runnable",
		[LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH] = "runnable-host-state-mismatch",
		[LXP_DIAG_PARKED_TASK_RUNNABLE] = "parked-task-runnable",
		[LXP_DIAG_NATIVE_TASK_MISSING] = "native-task-missing",
		[LXP_DIAG_NATIVE_TASK_LEAKED] = "native-task-leaked",
		[LXP_DIAG_HOST_STATE_WITHOUT_GENERATION] = "host-state-without-generation",
		[LXP_DIAG_DEFERRED_STATE_INVALID] = "deferred-state-invalid",
		[LXP_DIAG_DEFERRED_GENERATION_STALE] = "deferred-generation-stale",
		[LXP_DIAG_MULTIPLE_INTENTS] = "multiple-intents",
		[LXP_DIAG_MULTIPLE_WAITS] = "multiple-waits",
		[LXP_DIAG_REGION_LEASE_STALE] = "region-lease-stale",
		[LXP_DIAG_LIVE_TASK_STALE_REGION_REF] = "live-task-stale-region-ref",
		[LXP_DIAG_GUEST_VIEW_LEAKED] = "guest-view-leaked",
	};
	return issue < LXP_DIAG_ISSUE_COUNT && names[issue] ? names[issue] : "invalid";
}

static void lxp_diag_reset_health(void)
{
	memset(&g_diag_health, 0, sizeof(g_diag_health));
	g_diag_health.abi_version = LXP_DIAG_ABI_VERSION;
	g_diag_health.struct_size = sizeof(g_diag_health);
	g_diag_health.first_error.slot = -1;
	g_diag_health.first_error.region = -1;
	g_diag_health.last_error.slot = -1;
	g_diag_health.last_error.region = -1;
}

static void lxp_diag_checkpoint(void)
{
	lxp_diag_error_t error;
	g_diag_health.checks++;
	if (lxp_validate_world(&error) == LXP_OK)
		return;
	if (g_diag_health.failures++ == 0)
		g_diag_health.first_error = error;
	g_diag_health.last_error = error;
}

static volatile int g_tty_isig = 1;
/* Input translation advertised by the console's canonical termios.  The board
 * callback deliberately preserves CR for raw-mode line editors, so perform the
 * tty's ICRNL conversion here, after the byte enters the personality and only
 * while the guest has that flag enabled. */
static volatile int g_tty_icrnl = 1;
/* The console tty's foreground process group (job control): the pgid the shell put
 * in the foreground via tcsetpgrp(TIOCSPGRP). A console ^C (VINTR in cooked mode)
 * raises SIGINT on exactly this group — the shell (a different group) and background
 * jobs (their own groups) are left alone. 0 = unset (no ^C target). */
static volatile int g_console_fg_pgrp;

int lxp_tty_isig(void)
{
	return g_tty_isig;
}

void lxp_console_set_fg_pgrp(int pgrp)
{
	g_console_fg_pgrp = pgrp;
}

int lxp_console_fg_pgrp(void)
{
	return g_console_fg_pgrp;
}

int lxp_signal_process_group(int pgid, int sig)
{
	if (pgid <= 0 || sig <= 0 || sig >= LXP_NSIG)
		return 0;
	int recipients = 0;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_slots[s].proc;
		if (p->alive && p->pid > 1 && p->group && p->group->pgid == pgid) {
			lxp_signal_latch(p, sig);
			recipients++;
		}
	}
	if (recipients && g_eng && g_eng->event_post)
		g_eng->event_post();
	return recipients;
}

/* A console ^C (VINTR, cooked/ISIG mode) raises @p sig on the console's foreground
 * process group. Every live member takes the signal at its next syscall boundary
 * or coordinator retry. With no foreground group yet, this is a no-op. */
void console_signal_fg(int sig)
{
	(void)lxp_signal_process_group(g_console_fg_pgrp, sig);
}

void lxp_run_health(lxp_run_health_t *out)
{
	if (!out)
		return;
	out->coord_iters = g_coord_iters;
	out->active = lxp_trap_active();
}

/* Another live thread shares this proc's address space (a co-running CLONE_VM thread or its
 * creator) — the only case where a parked FUTEX_WAIT could ever be woken. Without one, the
 * wait would deadlock, so the futex handler returns -EAGAIN instead of parking (which keeps
 * single-threaded behaviour byte-identical to the old stub). */
static int futex_has_corunner(const lxp_proc_t *proc)
{
	if (!proc || !proc->mm)
		return 0;
	/* A suspended vfork parent shares our region but is frozen until we exec/exit, so it can
	 * never FUTEX_WAKE us — exclude it (proc->vfork_parent.index), or a vfork child's libc
	 * futex would park forever where the old stub returned -EAGAIN and made progress. */
	int vp = proc->vfork_parent.index;
	for (int s = 0; s < LXP_NSLOT; s++) {
		const lxp_proc_t *q = &g_lxp_slots[s].proc;
		if (q != proc && q->alive && q->mm == proc->mm && s != vp)
			return 1;
	}
	return 0;
}

/* futex(2): a uaddr-keyed wait/wake over the shared region of co-running threads. FUTEX_WAIT
 * parks the caller when *uaddr still equals the expected value AND a co-runner exists to wake
 * it (else -EAGAIN); FUTEX_WAKE marks up to `val` matching waiters and asks the coordinator to
 * resume them (with 0). Other ops are accepted inert. Intercepted here (not in the dispatch
 * switch) because the wake path needs the coordinator's proc table + event_post. */
static void lxp_futex(struct lxp_frame *f, lxp_proc_t *proc, int is_time64)
{
	uintptr_t uaddr = (uintptr_t)f->r[0];
	int op = (int)f->r[1] & 0x7f; /* mask FUTEX_PRIVATE_FLAG / FUTEX_CLOCK_REALTIME */
	uint32_t val = (uint32_t)f->r[2];

	if (op == 0 || op == 9) { /* FUTEX_WAIT / FUTEX_WAIT_BITSET */
		uint32_t observed;
		if (lxp_guest_get_u32(proc, uaddr, &observed) != 0) {
			f->r[0] = (uint32_t)-LXP_EFAULT;
			return;
		}
		if (observed != val) {
			f->r[0] = (uint32_t)-LXP_EAGAIN; /* value already moved: do not sleep */
			return;
		}
		if (!futex_has_corunner(proc)) {
			f->r[0] =
				(uint32_t)-LXP_EAGAIN; /* single-threaded: retry the userspace lock */
			return;
		}
		/* Optional timeout (arg4): FUTEX_WAIT is relative, FUTEX_WAIT_BITSET absolute (against
		 * our monotonic clock; a CLOCK_REALTIME absolute is approximated). Without it the wait
		 * is infinite. The coordinator resumes with -ETIMEDOUT once the deadline passes. */
		uint64_t deadline = 0;
		uintptr_t utimeout = (uintptr_t)f->r[3];
		if (utimeout) {
			uint64_t sec, nsec;
			if (is_time64) {
				int64_t t[2];
				if (lxp_copy_from_guest(proc, t, utimeout, sizeof(t)) != 0) {
					f->r[0] = (uint32_t)-LXP_EFAULT;
					return;
				}
				sec = (uint64_t)t[0];
				nsec = (uint64_t)t[1];
			} else {
				int32_t t[2];
				if (lxp_copy_from_guest(proc, t, utimeout, sizeof(t)) != 0) {
					f->r[0] = (uint32_t)-LXP_EFAULT;
					return;
				}
				sec = (uint64_t)(uint32_t)t[0];
				nsec = (uint64_t)(uint32_t)t[1];
			}
			uint64_t ts_us = sec * 1000000ull + nsec / 1000ull, now = 0;
			lxp_time_us(&now);
			deadline = (op == 0) ? now + ts_us : ts_us;
			if (!deadline)
				deadline = 1; /* 0 encodes "no timeout"; keep a nonzero deadline */
		}
		lxp_wait_t wait = {
			.kind = LXP_WAIT_FUTEX,
			.data.futex.uaddr = uaddr,
			.data.futex.deadline_us = deadline,
		};
		if (lxp_wait_begin(proc, &wait) != 0) {
			f->r[0] = (uint32_t)-LXP_EAGAIN;
			return;
		}
		park_frame(f, proc); /* the coordinator parks us; FUTEX_WAKE / timeout resumes us */
		return;
	}
	if (op == 1 || op == 10) { /* FUTEX_WAKE / FUTEX_WAKE_BITSET */
		uint32_t woken = 0;
		for (int s = 0; s < LXP_NSLOT && woken < val; s++) {
			lxp_proc_t *q = &g_lxp_slots[s].proc;
			/* !woken: a waiter already marked by an earlier WAKE (not yet resumed by
			 * the coordinator) must not be woken — or counted — twice. */
			if (q->alive && q->wait.kind == LXP_WAIT_FUTEX &&
			    !q->wait.data.futex.woken && q->wait.data.futex.uaddr == uaddr) {
				q->wait.data.futex.woken = 1;
				woken++;
			}
		}
		if (woken && g_eng && g_eng->event_post)
			g_eng->event_post();
		f->r[0] = woken;
		return;
	}
	f->r[0] = 0; /* REQUEUE / WAKE_OP / etc.: accepted, no queued waiter affected */
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

/* Lowest-numbered pending signal for @p p that is not currently blocked (SIGKILL/SIGSTOP are
 * never blocked), or 0 if none is deliverable. Does NOT clear it — the caller clears the bit
 * (pending_sigs &= ~lxp_sig_bit(sig)) once it commits to delivering. A blocked pending signal
 * is left set so it is delivered later, once the proc unblocks it. */
int pending_deliverable(const lxp_proc_t *p)
{
	if (!p->pending_sigs)
		return 0;
	for (int sig = 1; sig < LXP_NSIG; sig++)
		if ((p->pending_sigs & lxp_sig_bit(sig)) && !lxp_sig_blocked(p, sig))
			return sig;
	return 0;
}

/* Only constant-time, pointer-free operations may execute in the SVC top half.
 * The default is deliberately deferred: a newly added syscall cannot silently
 * inherit handler-mode execution merely because its number was added elsewhere. */
static int syscall_is_fast(long nr)
{
	switch (nr) {
	case LXP_NR_exit:
	case LXP_NR_exit_group:
	case LXP_NR_getpid:
	case LXP_NR_getppid:
	case LXP_NR_getuid32:
	case LXP_NR_getgid32:
	case LXP_NR_geteuid32:
	case LXP_NR_getegid32:
	case LXP_NR_gettid:
	case LXP_NR_umask:
	case LXP_NR_prctl:
	case LXP_NR_sched_yield:
	case LXP_NR_nice:
	case LXP_NR_getpriority:
	case LXP_NR_setpriority:
	case LXP_NR_setpgid:
	case LXP_NR_getpgrp:
	case LXP_NR_setsid:
	case LXP_NR_fchmod:
	case LXP_NR_fchown32:
	case LXP_NR_setgroups32:
	case LXP_NR_setuid32:
	case LXP_NR_setgid32:
	case LXP_NR_setreuid32:
	case LXP_NR_setregid32:
	case LXP_NR_setresuid32:
	case LXP_NR_setresgid32:
	case LXP_NR_set_tid_address:
	case LXP_NR_set_robust_list:
	case LXP_NR_mprotect: /* currently a pointer-free NOMMU no-op */
	case LXP_NR_reboot:
		return 1;
	default:
		return 0;
	}
}

/* ---- the syscall dispatch body --------------------------------------------- */
static void lxp_dispatch(struct lxp_frame *f, lxp_proc_t *proc)
{
	long nr = (long)(int32_t)f->r[7];
	if (nr == LXP_NR_getpriority || nr == LXP_NR_setpriority) {
		enum { PRIO_PROCESS = 0, PRIO_PGRP = 1, PRIO_USER = 2 };
		int which = (int)f->r[0];
		int who = (int)f->r[1];
		int caller_pgid = proc->group ? proc->group->pgid : proc->pid;
		int found = 0;
		int best = 19;
		int requested = (int)f->r[2];
		if (which < PRIO_PROCESS || which > PRIO_USER || who < 0) {
			f->r[0] = -LXP_EINVAL;
			return;
		}
		if (requested < -20)
			requested = -20;
		else if (requested > 19)
			requested = 19;
		for (int s = 0; s < LXP_NSLOT; s++) {
			lxp_proc_t *target = &g_lxp_slots[s].proc;
			if (!target->alive)
				continue;
			int match =
				(which == PRIO_PROCESS)
					? (who == 0 ? target == proc : target->pid == who)
				: (which == PRIO_PGRP)
					? (target->group &&
					   target->group->pgid == (who == 0 ? caller_pgid : who))
					: (who == 0); /* every guest has uid 0 */
			if (!match)
				continue;
			found = 1;
			if (nr == LXP_NR_setpriority)
				lxp_proc_nice_set(target, requested);
			else {
				int nice = lxp_proc_nice_get(target);
				if (nice < best)
					best = nice;
			}
		}
		if (!found) {
			f->r[0] = -LXP_ESRCH;
			return;
		}
		/* The raw syscall returns 40..1; libc translates that to nice -20..19. */
		f->r[0] = nr == LXP_NR_getpriority ? (uint32_t)(20 - best) : 0u;
		return;
	}
	if (nr == LXP_NR_kill || nr == LXP_NR_tkill || nr == LXP_NR_tgkill) {
		int sig = (nr == LXP_NR_tgkill) ? (int)f->r[2] : (int)f->r[1];
		int target = (int)f->r[0];
		/* Process-group target for a kill(pid<=0): pid==0 = the caller's group, pid<-1 = group |pid|. */
		int want_pgid = (target == 0) ? proc->group->pgid : (target < -1 ? -target : 0);
		if (sig < 0 ||
		    sig >= LXP_NSIG) { /* sig indexes sig_handler[]/pending_sig — reject OOB */
			f->r[0] = -LXP_EINVAL;
			return;
		}
		/* halt/poweroff/reboot signal a shutdown to init (pid 1) — SIGUSR1/SIGUSR2/
		 * SIGTERM respectively. init is parked and can't receive it, so honor a
		 * shutdown signal to pid 1 directly as a system halt. */
		if (nr == LXP_NR_kill && target == 1 && (sig == 10 || sig == 12 || sig == 15)) {
			lxp_request_halt();
			f->r[0] = 0; /* kill() succeeds; the run loop stops next iteration */
			return;
		}
		/* Self-signal (tkill/tgkill, or kill to own pid) is delivered inline. */
		if (nr != LXP_NR_kill || target == proc->pid) {
			deliver_signal(f, proc, sig, 0);
			return;
		}
		/* Latch a cross-process signal on the target proc(s); it is
		 * delivered at the target's next syscall boundary (running) or by the coordinator
		 * (parked in sleep/wait/pipe). Real Linux targeting: pid>0 = that process; pid==0 =
		 * the caller's process group; pid<-1 = process group |pid|; pid==-1 = broadcast to
		 * all (but init). Skips the sender + init; an explicit self-signal took the inline
		 * path above. This is the fix for `kill %job` no longer nuking unrelated procs. */
		f->r[0] = -LXP_ESRCH;
		for (int t = 0; t < LXP_NSLOT; t++) {
			lxp_proc_t *tp = &g_lxp_slots[t].proc;
			if (!tp->alive || tp == proc || tp->pid <= 1)
				continue;
			if (target > 0) {
				if (tp->pid != target)
					continue; /* a specific pid */
			} else if (target != -1) {
				if (tp->group->pgid != want_pgid)
					continue; /* a process group (the caller's, or |pid|) */
			} /* target == -1: broadcast to every live proc */
			lxp_signal_latch(tp, sig);
			f->r[0] = 0;
		}
		/* Wake the coordinator NOW so it delivers the signal at once (the LinuxThreads
		 * restart) instead of at its next ~poll-interval tick — otherwise every thread
		 * wakeup costs up to one event_wait timeout. */
		if (f->r[0] == 0 && g_eng && g_eng->event_post)
			g_eng->event_post();
		return;
	}
	if (nr == LXP_NR_rt_sigreturn || nr == LXP_NR_sigreturn) {
		sig_restore(f, proc);
		return;
	}
	/* fork/vfork/clone: capture the parent's resume context and ask the coordinator
	 * to spawn a child. The parent's host task stays parked through the vfork window
	 * (NOMMU shares the image) until the child execs into its own region or exits. */
	if (nr == LXP_NR_vfork || nr == LXP_NR_fork || nr == LXP_NR_clone) {
		/* CLONE_VM shares the address space for life and therefore co-runs on
		 * the supplied child stack. CLONE_THREAD additionally joins the
		 * caller's thread group; legacy LinuxThreads-style CLONE_VM children
		 * remain distinct, waitable processes. */
		uint32_t clone_flags = nr == LXP_NR_clone ? (uint32_t)f->r[0] : 0;
		if (((clone_flags & LXP_CLONE_SIGHAND) && !(clone_flags & LXP_CLONE_VM)) ||
		    ((clone_flags & LXP_CLONE_THREAD) &&
		     (clone_flags & (LXP_CLONE_VM | LXP_CLONE_SIGHAND)) !=
			     (LXP_CLONE_VM | LXP_CLONE_SIGHAND))) {
			f->r[0] = -LXP_EINVAL;
			return;
		}
		lxp_intent_t intent = {
			.kind = LXP_INTENT_FORK,
			.data.fork.flags = clone_flags,
			.data.fork.child_stack = (clone_flags & LXP_CLONE_VM) ? f->r[1] : 0,
		};
		if (lxp_intent_begin(proc, &intent) != 0) {
			f->r[0] = -LXP_EAGAIN;
			return;
		}
		park_frame(f, proc);
		return;
	}
	/* futex: a co-running thread's WAIT parks here / WAKE resumes peers (needs the proc
	 * table + event_post, so it is coordinator-handled, not a plain dispatch case). */
	if (nr == LXP_NR_futex || nr == LXP_NR_futex_time64) {
		lxp_futex(f, proc, nr == LXP_NR_futex_time64);
		return;
	}
	if (!syscall_is_fast(nr)) {
		defer_syscall(f, proc);
		return;
	}

	long r = lxp_syscall(proc, nr, (int32_t)f->r[0], (int32_t)f->r[1], (int32_t)f->r[2],
			     (int32_t)f->r[3], (int32_t)f->r[4], (int32_t)f->r[5]);
	/* Suppress the console diagnostic for syscalls we deliberately don't implement but the guest
	 * probes and gracefully falls back on: getdents(141)→getdents64, socket(281)→no networking. */
	if (r == -LXP_ENOSYS && g_cfg && g_cfg->on_enosys && nr != 141 && nr != 281)
		g_cfg->on_enosys(nr);
	/* A blocking syscall published a typed wait; capture the
	 * post-svc context (resume the SAME image after the svc) and park. The
	 * coordinator delays/wakes and resumes it through the explicit parked-resume
	 * port action. */
	if (proc->wait.kind != LXP_WAIT_NONE) {
		park_frame(f, proc);
		return;
	}
	if (proc->intent.kind != LXP_INTENT_NONE) {
		park_frame(f, proc);
		return;
	}
	/* Another proc's kill() latched a signal on us; deliver it at this syscall
	 * boundary (Linux at-the-boundary async delivery) unless the
	 * proc has blocked it (rt_sigprocmask) — a blocked signal stays latched and is delivered
	 * at a later boundary once unblocked. (The parked-thread and console-^C paths do not yet
	 * consult the mask; blocking those is uncommon.) */
	int psig = pending_deliverable(proc);
	if (psig) {
		proc->pending_sigs &= ~lxp_sig_bit(psig);
		deliver_signal(f, proc, psig, r);
		return;
	}
	f->r[0] = (uint32_t)r;
}

uint32_t lxp_guest_sched_weight(int slot)
{
	if (slot < 0 || slot >= LXP_NSLOT || !slot_runnable_load(slot))
		return 0;
	return lxp_nice_weight(lxp_proc_nice_get(&g_lxp_slots[slot].proc));
}

/* ---- host task lifecycle --------------------------------------------------- */
uint32_t slot_generation(int sidx)
{
	return __atomic_load_n(&g_lxp_slots[sidx].generation, __ATOMIC_ACQUIRE);
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
	return slot >= 0 && slot < LXP_NSLOT ? g_lxp_slots[slot].host_state : SLOT_FAILED;
}

void lxp_slot_set_host_state(int slot, uint8_t state)
{
	if (slot >= 0 && slot < LXP_NSLOT && g_lxp_slots[slot].host_state != state) {
		g_lxp_slots[slot].host_state = state;
		g_diag_lifecycle_epoch = diag_epoch_next(g_diag_lifecycle_epoch);
	}
}

void lxp_slot_proc_reset(int slot)
{
	if (slot < 0 || slot >= LXP_NSLOT)
		return;
	memset(&g_lxp_slots[slot].proc, 0, sizeof(g_lxp_slots[slot].proc));
	g_lxp_slots[slot].proc.snapshot = lxp_region_ref_none();
	g_lxp_slots[slot].proc.vfork_parent = lxp_slot_ref_none();
}

int lxp_slot_ref_current(int slot, lxp_slot_ref_t *out)
{
	if (!out || slot < 0 || slot >= LXP_NSLOT)
		return -LXP_EINVAL;
	uint32_t generation = slot_generation(slot);
	if (generation == 0 || !g_lxp_slots[slot].proc.alive)
		return -LXP_ESRCH;
	*out = slot_ref_at(slot);
	return LXP_OK;
}

int lxp_slot_ref_is_current(lxp_slot_ref_t ref)
{
	return ref.index >= 0 && ref.index < LXP_NSLOT && ref.generation != 0 &&
	       slot_generation(ref.index) == ref.generation && g_lxp_slots[ref.index].proc.alive;
}

const struct lxp_resume_ctx *lxp_slot_resume_view(lxp_slot_ref_t ref)
{
	return lxp_slot_ref_is_current(ref) ? &g_lxp_slots[ref.index].resume : NULL;
}

int lxp_slot_resume_clone_for_fork(lxp_slot_ref_t child, lxp_slot_ref_t parent, uintptr_t child_sp)
{
	if (child.index < 0 || child.index >= LXP_NSLOT || child.generation == 0 ||
	    child.index == parent.index || slot_generation(child.index) != child.generation ||
	    g_lxp_slots[child.index].proc.alive || !lxp_slot_ref_is_current(parent))
		return -LXP_ESRCH;
	g_lxp_slots[child.index].resume = g_lxp_slots[parent.index].resume;
	g_lxp_slots[child.index].resume.sp = child_sp;
	return LXP_OK;
}

int lxp_slot_ref_is_runnable(lxp_slot_ref_t ref)
{
	if (ref.index < 0 || ref.index >= LXP_NSLOT || ref.generation == 0 ||
	    !slot_runnable_load(ref.index))
		return 0;
	return slot_generation(ref.index) == ref.generation && g_lxp_slots[ref.index].proc.alive;
}

int lxp_slot_region_ref(lxp_slot_ref_t ref, lxp_region_ref_t *out)
{
	if (!out || !lxp_slot_ref_is_current(ref) || !g_lxp_slots[ref.index].proc.mm)
		return -LXP_ESRCH;
	lxp_region_ref_t region = g_lxp_slots[ref.index].proc.mm->region;
	if (region.index < 0 || region.index >= LXP_NREG || region.generation == 0 ||
	    g_regions[region.index].generation != region.generation)
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
	const lxp_mm_t *mm = g_lxp_slots[ref.index].proc.mm;
	if (!mm || mm->device_generation == 0 || mm->exec_generation == 0)
		return -LXP_EINVAL;
	lxp_region_ref_t region = mm->region;
	if (region.index < 0 || region.index >= LXP_NREG || region.generation == 0 ||
	    g_regions[region.index].generation != region.generation)
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

int lxp_dispatch_slot(lxp_slot_ref_t ref, struct lxp_frame *frame)
{
	if (!frame || !lxp_slot_ref_is_runnable(ref))
		return -LXP_ESRCH;
	lxp_guest_view_t view;
	int rc = lxp_guest_view_begin(&g_lxp_slots[ref.index].proc, ref,
				      &g_lxp_slots[ref.index].generation, LXP_GUEST_READ_WRITE,
				      &view);
	if (rc != LXP_OK)
		return rc;
	lxp_dispatch(frame, &g_lxp_slots[ref.index].proc);
	lxp_guest_view_end(&view);
	return LXP_OK;
}

int lxp_slot_report_memory_fault(lxp_slot_ref_t ref, const lxp_guest_fault_t *fault)
{
	if (!fault || !lxp_slot_ref_is_current(ref))
		return -LXP_ESRCH;
	lxp_proc_t *proc = &g_lxp_slots[ref.index].proc;
	proc->exit_status = 139; /* 128 + SIGSEGV */
	proc->exit_reason = LXP_EXIT_REASON_MEMORY_FAULT;
	proc->exit_signal = LXP_SIGSEGV;
	proc->exit_detail = fault->detail;
	proc->exit_address = fault->address;
	(void)lxp_intent_exit(proc, 0);
	lxp_event_post_slot(g_eng, ref.index);
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
int coordinator_restore_mm_maps(const lxp_os_ops_t *eng, int sidx, const lxp_mm_t *mm)
{
	int has_maps = 0;
	for (int i = 0; mm && i < 2; i++)
		if (mm->dev_map_hi[i] > mm->dev_map_lo[i])
			has_maps = 1;
	if (!eng->map_device)
		return has_maps ? -LXP_ENODEV : 0;
	if (eng->map_device(sidx, 0, 0, 0) != 0)
		return -LXP_ENOMEM;
	for (int i = 0; mm && i < 2; i++) {
		if (mm->dev_map_hi[i] <= mm->dev_map_lo[i])
			continue;
		if (eng->map_device(sidx, mm->dev_map_lo[i], mm->dev_map_hi[i] - mm->dev_map_lo[i],
				    mm->dev_map_attrs[i]) != 0) {
			(void)eng->map_device(sidx, 0, 0, 0);
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
int coordinator_map_mm_range(const lxp_os_ops_t *eng, lxp_mm_t *mm, uintptr_t addr, size_t len,
			     unsigned attrs)
{
	if (!eng->map_device)
		return -LXP_ENODEV;
	for (int s = 0; s < LXP_NSLOT; s++) {
		if (!g_lxp_slots[s].proc.alive || g_lxp_slots[s].proc.mm != mm)
			continue;
		if (eng->map_device(s, addr, len, attrs) != 0) {
			for (int r = 0; r < LXP_NSLOT; r++)
				if (g_lxp_slots[r].proc.alive && g_lxp_slots[r].proc.mm == mm)
					(void)coordinator_restore_mm_maps(eng, r, mm);
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
	if (!g_cfg || !g_cfg->on_guest_exit)
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
	g_cfg->on_guest_exit(g_cfg->guest_exit_ctx, &info);
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
		if (g_lxp_slots[s].proc.alive && g_lxp_slots[s].proc.group == group)
			live++;
	return live;
}

void thread_group_request_exit(int source_slot, int status)
{
	if (source_slot < 0 || source_slot >= LXP_NSLOT)
		return;
	lxp_thread_group_t *group = g_lxp_slots[source_slot].proc.group;
	if (!group)
		return;
	group->exiting = 1;
	group->exit_status = status & 0xff;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_slots[s].proc;
		if (!p->alive || p->group != group)
			continue;
		p->exit_status = status & 0xff;
		p->exit_reason = LXP_EXIT_REASON_NORMAL;
		p->exit_signal = 0;
		p->exit_detail = 0;
		p->exit_address = 0;
		(void)lxp_intent_exit(p, 1);
		primary_slot_mark(s);
	}
}

/* execve replaces the entire process image. Once the coordinator reaches the
 * commit point, peer threads may no longer execute in the old shared address
 * space. Stop their host tasks immediately; their normal EV_EXIT teardown
 * releases per-task references on subsequent coordinator passes. */
int thread_group_stop_exec_peers(const lxp_os_ops_t *eng, int source_slot, int failure_status)
{
	lxp_thread_group_t *group = g_lxp_slots[source_slot].proc.group;
	int rc = LXP_OK;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_slots[s].proc;
		if (s == source_slot || !p->alive || p->group != group)
			continue;
		if (coordinator_abort_slot(eng, s) != LXP_OK)
			rc = -LXP_EAGAIN;
		p->exit_status = failure_status & 0xff;
		p->exit_reason = LXP_EXIT_REASON_NORMAL;
		p->exit_signal = 0;
		(void)lxp_intent_exit(p, 0);
		primary_slot_mark(s);
	}
	return rc;
}

/* Deliver `sig` to a proc PARKED in rt_sigsuspend (the LinuxThreads restart). There is no live
 * frame — the interrupted context is the captured g_lxp_slots[slot].resume. Save that as the slot's sigreturn
 * frame (to resume with `ret` = -EINTR), then resume the proc INTO its handler; the handler's
 * sa_restorer -> rt_sigreturn restores the saved frame and the syscall returns -EINTR. SIG_IGN
 * just resumes with `ret`; SIG_DFL terminates (the LXP_EV_EXIT pass reaps it). */
void deliver_signal_parked(const lxp_os_ops_t *eng, int slot, lxp_proc_t *proc, int sig, long ret)
{
	struct lxp_signal_delivery delivery;
	enum lxp_signal_action action = lxp_signal_prepare(proc, sig, &delivery);
	if (action == LXP_SIGNAL_IGNORE) {
		(void)coordinator_complete_slot(
			eng, slot_ref_at(slot),
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
		(void)coordinator_complete_slot(eng, slot_ref_at(slot), ret);
		notify_parent_stopped(eng, proc->group->ppid, proc->pid, sig);
		return;
	}
	if (action == LXP_SIGNAL_TERMINATE) {
		primary_slot_mark(slot);
		return;
	}
	if (action != LXP_SIGNAL_HANDLER)
		return;
	struct sig_save_s *sv = delivery.save;
	sv->r0 = (uint32_t)ret;
	sv->r1 = g_lxp_slots[slot].resume.r1;
	sv->r2 = g_lxp_slots[slot].resume.r2;
	sv->r3 = g_lxp_slots[slot].resume.r3;
	sv->r9 =
		g_lxp_slots[slot]
			.resume
			.r4_11[5]; /* FDPIC GOT of the parked code — clobbered below (r4_11[5]=r9) */
	sv->r12 = g_lxp_slots[slot].resume.r12;
	sv->lr = g_lxp_slots[slot].resume.lr;
	sv->pc = g_lxp_slots[slot].resume.pc;		       /* the rt_sigsuspend resume point */
	sv->xpsr = g_lxp_slots[slot].resume.xpsr | (1u << 24); /* preserve APSR flags + Thumb */
#if LXP_ENABLE_FPU_CONTEXT
	sv->fp = g_lxp_slots[slot].resume.fp;
#endif
	/* Reuse the slot ctx as the handler-entry frame; sp + r4-r11 stay = the thread's, except r9
	 * (the handler's own GOT for FDPIC — resolve_handler derefs the {entry,GOT} funcdescs; the
	 * restart handler lives in libpthread, a different module than the interrupted libc). */
	if (proc->is_fdpic)
		g_lxp_slots[slot].resume.r4_11[5] = delivery.got; /* r9 = handler's GOT */
	g_lxp_slots[slot].resume.lr = delivery.restorer |
				      1u; /* return -> sa_restorer entry -> sigreturn */
	g_lxp_slots[slot].resume.pc = delivery.entry | 1u; /* enter the handler (Thumb) */
	coordinator_resume_slot(eng, slot, proc->mm->region.index, &g_lxp_slots[slot].resume,
				sig); /* r0 = signo */
}

/* Track the tty input/local modes from the coordinator, never from SVC handler mode.
 * The guest is parked and the termios payload is copied before use. */
static void deferred_track_tty(lxp_proc_t *proc, long nr, long a0, long a1, long a2)
{
	if (nr != LXP_NR_ioctl)
		return;
	int fd = (int)a0;
	unsigned long cmd = (unsigned long)a1;
	if (fd < 0 || fd >= LXP_MAX_FDS || lxp_fd_kind(proc, fd) != LXP_FD_CONSOLE ||
	    (cmd != LXP_TCSETS && cmd != LXP_TCSETSW && cmd != LXP_TCSETSF))
		return;
	const void *ut = (const void *)(uintptr_t)(uint32_t)a2;
	if (lxp_guest_access_ok(proc, ut, sizeof(lxp_termios), 0)) {
		lxp_termios t;
		memcpy(&t, ut, sizeof(t));
		g_tty_isig = (t.c_lflag & LXP_ISIG) ? 1 : 0;
		g_tty_icrnl = (t.c_iflag & LXP_ICRNL) ? 1 : 0;
	}
}

uint8_t lxp_console_input_xlate(uint8_t ch)
{
	return (g_tty_icrnl && ch == '\r') ? '\n' : ch;
}

/* Console bytes read by the ^C/^Z check while no guest was reading the console.
 * Coordinator-owned: every producer and consumer runs in coordinator context. */
static uint8_t g_console_typeahead[LXP_CONSOLE_TYPEAHEAD];
static unsigned g_console_typeahead_head;
static unsigned g_console_typeahead_count;

void lxp_console_typeahead_reset(void)
{
	g_console_typeahead_head = 0;
	g_console_typeahead_count = 0;
}

int lxp_console_input_ready(const lxp_proc_t *proc)
{
	return g_console_typeahead_count != 0 ||
	       (proc && proc->console_poll && proc->console_poll(proc->io_ctx) > 0);
}

long lxp_console_read(lxp_proc_t *proc, int fd, void *buf, size_t len)
{
	long rc;
	if (len != 0 && g_console_typeahead_count != 0) {
		((uint8_t *)buf)[0] = g_console_typeahead[g_console_typeahead_head];
		g_console_typeahead_head = (g_console_typeahead_head + 1u) % LXP_CONSOLE_TYPEAHEAD;
		g_console_typeahead_count--;
		rc = 1;
	} else {
		rc = proc->read_fn ? proc->read_fn(proc->io_ctx, fd, buf, len) : 0;
	}
	if (rc == 1)
		((uint8_t *)buf)[0] = lxp_console_input_xlate(((const uint8_t *)buf)[0]);
	return rc;
}

int lxp_console_poll_interrupts(const lxp_run_config_t *cfg)
{
	if (!g_tty_isig || !cfg || !cfg->read_fn || !cfg->console_poll ||
	    g_console_typeahead_count == LXP_CONSOLE_TYPEAHEAD || !cfg->console_poll(cfg->io_ctx))
		return 0;
	uint8_t ch = 0;
	if (cfg->read_fn(cfg->io_ctx, 0, &ch, 1) != 1)
		return 0;
	if (ch == 3 || ch == 26) {
		console_signal_fg(ch == 3 ? LXP_SIGINT : LXP_SIGTSTP);
		return 1;
	}
	unsigned tail = (g_console_typeahead_head + g_console_typeahead_count) % LXP_CONSOLE_TYPEAHEAD;
	g_console_typeahead[tail] = ch;
	g_console_typeahead_count++;
	return 0;
}

/* Execute one READY mailbox in privileged task context. The lower-priority guest
 * is suspended before its host syscall runs; immediate completion resumes that
 * same task, while a blocking syscall leaves it parked for the established wait
 * event. Host RT tasks above the coordinator can preempt all work performed here. */
void execute_deferred(const lxp_os_ops_t *eng, int slot)
{
	uint8_t expected = DEFER_READY;
	if (!__atomic_compare_exchange_n(&g_lxp_slots[slot].deferred.state, &expected,
					 DEFER_RUNNING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return;
	struct deferred_req *req = &g_lxp_slots[slot].deferred;
	lxp_proc_t *proc = &g_lxp_slots[slot].proc;
	if (!proc->alive || !lxp_slot_ref_equal(req->owner, slot_ref_at(slot))) {
		deferred_state_store(slot, DEFER_IDLE);
		if (proc->intent.kind == LXP_INTENT_DEFERRED_SYSCALL)
			(void)lxp_intent_complete(proc, LXP_INTENT_DEFERRED_SYSCALL);
		return;
	}
	if (coordinator_park_slot(eng, slot) != LXP_OK) {
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
	long nr = (long)(int32_t)g_lxp_slots[slot].resume.r4_11[3]; /* captured r7 */
	long a0 = (long)(int32_t)req->a0;
	long a1 = (long)(int32_t)g_lxp_slots[slot].resume.r1;
	long a2 = (long)(int32_t)g_lxp_slots[slot].resume.r2;
	long a3 = (long)(int32_t)g_lxp_slots[slot].resume.r3;
	long a4 = (long)(int32_t)g_lxp_slots[slot].resume.r4_11[0];
	long a5 = (long)(int32_t)g_lxp_slots[slot].resume.r4_11[1];
	(void)lxp_intent_complete(proc, LXP_INTENT_DEFERRED_SYSCALL);
	deferred_track_tty(proc, nr, a0, a1, a2);
	long r = lxp_syscall(proc, nr, a0, a1, a2, a3, a4, a5);
	if (r == -LXP_ENOSYS && g_cfg && g_cfg->on_enosys && nr != 141 && nr != 281)
		g_cfg->on_enosys(nr);
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

	int psig = pending_deliverable(proc);
	if (psig) {
		proc->pending_sigs &= ~lxp_sig_bit(psig);
		deliver_signal_parked(eng, slot, proc, psig, r);
		lxp_guest_view_end(&view);
		return;
	}
	lxp_guest_view_end(&view);
	(void)coordinator_complete_slot(eng, slot_ref_at(slot), r);
}

/* ---- vfork data isolation (NOMMU) ------------------------------------------ */
/* A region may be reused as vfork snapshot scratch (which then becomes the
 * child's exec image) or as a fresh exec region only after its generated
 * capability reaches zero references. A temporary lease also keeps prepared
 * but unpublished state unavailable. The live-mm scan is deliberate
 * fail-closed redundancy: corrupted accounting causes -ENOMEM rather than
 * copying over a live daemon's libc state. */
int region_free(int r)
{
	if (r < 0 || r >= LXP_NREG || g_regions[r].lease_owner.index >= 0 || g_regions[r].refs != 0)
		return 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (g_lxp_slots[s].proc.alive && g_lxp_slots[s].proc.mm &&
		    g_lxp_slots[s].proc.mm->region.index == r)
			return 0; /* live use despite zero refs — do not trample it */
	return 1;
}

static uint32_t region_generation_next(int r)
{
	uint32_t next = ++g_regions[r].generation;
	if (next == 0) /* reserve zero for never-assigned test/startup state */
		next = ++g_regions[r].generation;
	return next;
}

static lxp_region_ref_t region_ref_at(int r)
{
	return (r >= 0 && r < LXP_NREG && g_regions[r].refs != 0)
		       ? (lxp_region_ref_t){
				 .index = (int16_t)r,
				 .generation = g_regions[r].generation,
			 }
		       : lxp_region_ref_none();
}

lxp_region_ref_t region_reserve(int r, lxp_slot_ref_t owner)
{
	if (r < 0 || r >= LXP_NREG || owner.index < 0 || owner.index >= LXP_NSLOT ||
	    owner.generation == 0 || !lxp_slot_ref_equal(owner, slot_ref_at(owner.index)) ||
	    g_regions[r].refs != 0)
		return lxp_region_ref_none();
	g_regions[r].lease_owner = owner;
	g_regions[r].refs = 1;
	return (lxp_region_ref_t){
		.index = (int16_t)r,
		.generation = region_generation_next(r),
	};
}

/* Transfer an unpublished reservation to the address space that now carries
 * the same region capability. From this point onward the mm reference, not an
 * arbitrary task slot, is the ownership authority. */
int lxp_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t lease_owner)
{
	int r = ref.index;
	if (r < 0 || r >= LXP_NREG || ref.generation == 0 ||
	    g_regions[r].generation != ref.generation || g_regions[r].refs == 0 ||
	    !lxp_slot_ref_equal(g_regions[r].lease_owner, lease_owner))
		return -1;
	g_regions[r].lease_owner = lxp_slot_ref_none();
	return 0;
}

int region_get(lxp_region_ref_t ref)
{
	int r = ref.index;
	if (r < 0 || r >= LXP_NREG || ref.generation == 0 ||
	    g_regions[r].generation != ref.generation || g_regions[r].lease_owner.index >= 0 ||
	    g_regions[r].refs == 0 || g_regions[r].refs >= LXP_NSLOT)
		return -1;
	g_regions[r].refs++;
	return 0;
}

int region_put(lxp_region_ref_t ref)
{
	int r = ref.index;
	if (r < 0 || r >= LXP_NREG || ref.generation == 0 ||
	    g_regions[r].generation != ref.generation || g_regions[r].refs == 0)
		return -1;
	if (--g_regions[r].refs == 0) {
		g_regions[r].lease_owner = lxp_slot_ref_none();
		(void)region_generation_next(r);
	}
	return 0;
}

void proc_mm_put(lxp_proc_t *p)
{
	if (!p || !p->mm)
		return;
	(void)region_put(p->mm->region);
	lxp_proc_mm_put(p);
}

int region_release_if_owned(lxp_region_ref_t region, lxp_slot_ref_t owner)
{
	int r = region.index;
	if (r < 0 || r >= LXP_NREG || !lxp_slot_ref_equal(g_regions[r].lease_owner, owner) ||
	    g_regions[r].refs != 1 || g_regions[r].generation != region.generation)
		return -1;
	return region_put(region);
}

int lxp_region_lease_matches(lxp_region_ref_t region, lxp_slot_ref_t owner, unsigned refs)
{
	return region.index >= 0 && region.index < LXP_NREG && region.generation != 0 &&
	       g_regions[region.index].generation == region.generation &&
	       g_regions[region.index].refs == refs &&
	       lxp_slot_ref_equal(g_regions[region.index].lease_owner, owner);
}

int lxp_region_lease_reassign(lxp_region_ref_t region, lxp_slot_ref_t old_owner,
			      lxp_slot_ref_t new_owner)
{
	if (!lxp_region_lease_matches(region, old_owner, 1))
		return -LXP_EINVAL;
	g_regions[region.index].lease_owner = new_owner;
	return LXP_OK;
}

/* A failed abort leaves the native task and its Linux resources intact by
 * contract. Keep the trap route active and retry until every generation-
 * qualified native owner is synchronously gone. There is no safe recovery
 * which returns to the host while a guest can still execute; a permanent port
 * failure deliberately remains here for the host watchdog to contain. */
static void coordinator_quiesce_all(const lxp_os_ops_t *eng)
{
	for (int s = 0; s < LXP_NSLOT; s++) {
		while (coordinator_abort_slot(eng, s) != LXP_OK)
			eng->event_wait(1u);
	}
}

/* Stop every host task before releasing resource objects: descriptor close
 * hooks and request cancellation touch state a live guest could otherwise
 * still mutate. This is the common path for normal completion, halt, timeout
 * and launch failure, so a later lxp_run() never inherits the prior run. */
static void coordinator_teardown_all(const lxp_os_ops_t *eng)
{
	coordinator_quiesce_all(eng);
	lxp_trap_publish(0);
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_slots[s].proc;
		deferred_slot_reassign(s);
		primary_slot_clear(s);
#if LXP_ENABLE_NETFS
		if (p->wait.kind == LXP_WAIT_NETFS)
			lxp_netfs_cancel(p);
#endif
		lxp_proc_resources_put(p);
		if (eng->map_device)
			eng->map_device(s, 0, 0, 0);
		if (p->mm) {
			p->mm->dev_map_lo[0] = p->mm->dev_map_hi[0] = 0;
			p->mm->dev_map_lo[1] = p->mm->dev_map_hi[1] = 0;
		}
		if (p->snapshot.index >= 0)
			(void)region_release_if_owned(p->snapshot, slot_ref_at(s));
		proc_mm_put(p);
		lxp_proc_group_put(p);
		g_sig_save[s].depth = 0;
		slot_runnable_store(s, 0);
		memset(p, 0, sizeof(*p));
		p->snapshot = lxp_region_ref_none();
		p->vfork_parent = lxp_slot_ref_none();
	}

	/* Contain inconsistent ownership metadata as well as the ordinary
	 * reference-balanced case above. No guest survives this boundary. */
	for (int r = 0; r < LXP_NREG; r++) {
		g_regions[r].refs = 0;
		g_regions[r].lease_owner = lxp_slot_ref_none();
	}
	memset(g_vfork_guard, 0, sizeof(g_vfork_guard));
	for (int s = 0; s < LXP_NSLOT; s++) {
		g_vfork_guard[s].parent = lxp_slot_ref_none();
		g_vfork_guard[s].parent_region = lxp_region_ref_none();
		g_vfork_guard[s].snapshot = lxp_region_ref_none();
	}
	memset(g_diag_native_present, 0, sizeof(g_diag_native_present));
	g_diag_native_known = 0;
	lxp_proc_runtime_reset();
	lxp_fd_runtime_reset();
	lxp_pipe_runtime_reset();
#if LXP_ENABLE_PTY
	lxp_pty_runtime_reset();
#endif
#if LXP_ENABLE_NETFS
	lxp_netfs_shutdown();
#endif
}

/* Copy into storage that may retain cache lines from an earlier tenant. The
 * explicit pre-invalidate prevents a later clean from writing that tenant back
 * over an uncached copy; the final clean publishes cacheable coordinator writes. */
static void snapshot_copy_span(void *dst, const void *src, size_t len)
{
	lxp_cache_clean(src, len);
	lxp_cache_invalidate(dst, len);
	memcpy(dst, src, len);
	lxp_cache_clean(dst, len);
}

/* Restore into a region that the vfork child has modified. Preserve the copy
 * across both cacheable and uncached coordinator MPU views, then discard the
 * coordinator's view so the resumed parent refills the restored bytes. */
static void restore_copy_span(void *dst, const void *src, size_t len)
{
	lxp_cache_invalidate(dst, len);
	memcpy(dst, src, len);
	lxp_cache_clean(dst, len);
	lxp_cache_invalidate(dst, len);
}

/* NOMMU has no copy-on-write, so a vfork child SHARES the parent's region + dyn_pool. Correct vfork
 * usage restricts the child to exec/_exit, but real programs write shared data before exec (e.g.
 * dropbear's session child resets SIGCHLD to SIG_DFL, which uClibc-LinuxThreads records in a table in
 * the shared libc data) — corrupting the suspended parent. So we snapshot the parent's writable data
 * into a SPARE region at fork and restore it before the parent resumes. Storage is free: the spare
 * region's own region+dyn_pool exactly mirror the parent's (both LXP_PROG_*), and the child needs
 * that region for its eventual exec anyway. The writable image data [region, stack_lo), active
 * stack [captured_sp, region_hi), and dyn_pool are copied; g_arenas[] allocator metadata is saved
 * separately. Copying only the active stack bounds the work to live state rather than the full
 * reserved stack, while preserving NOMMU shell re-exec paths that modify vfork caller frames.
 * Returns the reserved scratch-region capability, or an invalid reference if
 * the parent cannot be isolated. */
lxp_region_ref_t vfork_snapshot(const lxp_os_ops_t *eng, lxp_proc_t *par, lxp_slot_ref_t child,
				uintptr_t sp)
{
	int parent_slot = slot_of(par);
	if (parent_slot < 0 || child.index < 0 || child.index >= LXP_NSLOT ||
	    child.generation == 0 || !par->alive || !par->mm || par->mm->region.index < 0 ||
	    par->mm->region.index >= LXP_NREG)
		return lxp_region_ref_none();
	int rsnap = -1;
	for (int r = 0; r < LXP_NREG; r++)
		if (region_free(r)) {
			rsnap = r;
			break;
		}
	if (rsnap < 0)
		return lxp_region_ref_none();
	uint8_t *pr = eng->region(par->mm->region.index);
	size_t dlen = par->stack_lo - (uintptr_t)pr; /* in-region writable data, below the stack */
	uint8_t *sr = eng->region(rsnap);
	if (sp < par->stack_lo || sp > par->mm->region_hi)
		return lxp_region_ref_none();
	lxp_region_ref_t snapshot = region_reserve(rsnap, child);
	if (snapshot.index < 0)
		return snapshot;
	snapshot_copy_span(sr, pr, dlen);
	size_t slen = par->mm->region_hi - sp;
	snapshot_copy_span(sr + (sp - (uintptr_t)pr), (const void *)sp, slen);
	if (par->mm->is_dynamic && eng->dyn_pool) {
		size_t ds = 0;
		uint8_t *pdp = eng->dyn_pool(par->mm->region.index, &ds);
		uint8_t *sdp = eng->dyn_pool(rsnap, NULL);
		snapshot_copy_span(sdp, pdp, ds);
	}
	g_arenas[rsnap] =
		g_arenas[par->mm->region.index]; /* allocator metadata (coordinator memory) */
	struct vfork_snapshot_guard *guard = &g_vfork_guard[child.index];
	guard->parent = slot_ref_at(parent_slot);
	guard->parent_region = par->mm->region;
	guard->snapshot = snapshot;
	return snapshot;
}

/* Undo a vfork child's writes to the shared region before the parent resumes: copy the snapshot back
 * over the parent's region + dyn_pool and restore its arena metadata. Every identity is checked
 * before the first write; failure leaves memory untouched so the caller can contain both processes. */
int vfork_restore(const lxp_os_ops_t *eng, lxp_proc_t *par, lxp_region_ref_t snapshot,
		  lxp_slot_ref_t child, uintptr_t sp)
{
	if (!lxp_slot_ref_is_current(child))
		return -1;
	struct vfork_snapshot_guard *guard = &g_vfork_guard[child.index];
	int parent_slot = slot_of(par);
	int rsnap = snapshot.index;
	if (parent_slot < 0 || !par->alive || !par->mm ||
	    !lxp_slot_ref_equal(slot_ref_at(parent_slot), guard->parent) ||
	    !lxp_region_ref_equal(par->mm->region, guard->parent_region) ||
	    !lxp_region_ref_equal(snapshot, guard->snapshot) || rsnap < 0 || rsnap >= LXP_NREG ||
	    !lxp_slot_ref_equal(g_regions[rsnap].lease_owner, child) ||
	    g_regions[rsnap].refs != 1 || g_regions[rsnap].generation != snapshot.generation)
		return -1;
	uint8_t *pr = eng->region(par->mm->region.index);
	size_t dlen = par->stack_lo - (uintptr_t)pr;
	uint8_t *sr = eng->region(rsnap);
	restore_copy_span(pr, sr, dlen);
	if (sp >= par->stack_lo && sp <= par->mm->region_hi) {
		size_t slen = par->mm->region_hi - sp;
		restore_copy_span((void *)sp, sr + (sp - (uintptr_t)pr), slen);
	}
	if (par->mm->is_dynamic && eng->dyn_pool) {
		size_t ds = 0;
		uint8_t *pdp = eng->dyn_pool(par->mm->region.index, &ds);
		restore_copy_span(pdp, eng->dyn_pool(rsnap, NULL), ds);
	}
	g_arenas[par->mm->region.index] = g_arenas[rsnap];
	memset(guard, 0, sizeof(*guard));
	guard->parent = lxp_slot_ref_none();
	guard->parent_region = lxp_region_ref_none();
	guard->snapshot = lxp_region_ref_none();
	return 0;
}

static int vfork_parent_is_current(lxp_slot_ref_t child)
{
	if (!lxp_slot_ref_is_current(child))
		return 0;
	const struct vfork_snapshot_guard *guard = &g_vfork_guard[child.index];
	int ps = guard->parent.index;
	return lxp_slot_ref_is_current(guard->parent) && g_lxp_slots[ps].proc.mm &&
	       lxp_region_ref_equal(g_lxp_slots[ps].proc.mm->region, guard->parent_region);
}

/* A stale snapshot is an internal ownership violation, not a recoverable guest
 * error. Never copy it. Terminate a still-current suspended parent (its shared
 * image may already be dirty), fail the child, and release only a reservation
 * that is still demonstrably ours. */
void vfork_contain_stale(lxp_slot_ref_t child_ref, lxp_proc_t *child)
{
	struct vfork_snapshot_guard *guard = &g_vfork_guard[child_ref.index];
	if (vfork_parent_is_current(child_ref)) {
		lxp_proc_t *par = &g_lxp_slots[guard->parent.index].proc;
		par->exit_status = 127;
		par->exit_reason = LXP_EXIT_REASON_STATE_CORRUPTION;
		par->exit_signal = 0;
		(void)lxp_intent_exit(par, 0);
		primary_slot_mark(guard->parent.index);
	}
	if (guard->snapshot.index >= 0)
		(void)region_release_if_owned(guard->snapshot, child_ref);
	memset(guard, 0, sizeof(*guard));
	guard->parent = lxp_slot_ref_none();
	guard->parent_region = lxp_region_ref_none();
	guard->snapshot = lxp_region_ref_none();
	child->vfork_parent = lxp_slot_ref_none();
	child->snapshot = lxp_region_ref_none();
	if (child->intent.kind == LXP_INTENT_EXEC)
		(void)lxp_intent_complete(child, LXP_INTENT_EXEC);
	child->exit_status = 127;
	child->exit_reason = LXP_EXIT_REASON_STATE_CORRUPTION;
	child->exit_signal = 0;
	(void)lxp_intent_exit(child, 0);
	primary_slot_mark(child_ref.index);
}

/* Clear the generation-qualified snapshot guard before a slot is reused. */
void fork_child_guard_reset(int child_slot)
{
	memset(&g_vfork_guard[child_slot], 0, sizeof(g_vfork_guard[child_slot]));
	g_vfork_guard[child_slot].parent = lxp_slot_ref_none();
	g_vfork_guard[child_slot].parent_region = lxp_region_ref_none();
	g_vfork_guard[child_slot].snapshot = lxp_region_ref_none();
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
	g_cfg = cfg;
	g_eng = eng;
	g_lxp_rootfs_lo = cfg->rootfs_image;
	g_lxp_rootfs_hi = g_lxp_rootfs_lo + cfg->rootfs_image_size;
	for (int i = 0; i < LXP_NSLOT; i++) {
		slot_runnable_store(i, 0);
		lxp_slot_set_host_state(i, SLOT_FREE);
		g_lxp_slots[i].proc.alive = 0;
		deferred_slot_reassign(i);
	}
	lxp_primary_events_reset();
	lxp_blocked_fair_reset();
	memset(g_regions, 0, sizeof(g_regions));
	for (int r = 0; r < LXP_NREG; r++)
		g_regions[r].lease_owner = lxp_slot_ref_none();
	memset(g_vfork_guard, 0, sizeof(g_vfork_guard));
	for (int i = 0; i < LXP_NSLOT; i++)
		fork_child_guard_reset(i);
	g_tty_isig = 1;
	g_tty_icrnl = 1;
	g_console_fg_pgrp = 0;
	lxp_console_typeahead_reset();
	lxp_stats_reset();
	for (int i = 0; i < LXP_NSLOT; i++)
		g_sig_save[i].depth = 0;
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
	 * (g_lxp_slots[*].proc.alive). Each live proc owns a region + an RTOS thread for
	 * its lifetime; a vfork parent resumes the instant its child execs into its own
	 * region (or exits) so the two co-run. The region table holds one reference
	 * per live task sharing an address space, plus reserved vfork
	 * snapshot/exec-handoff regions. */
	lxp_trap_publish(1);
	lxp_reset_halt_request();
	(void)region_reserve(0, slot_ref_at(0));
	lxp_region_ref_t initial_region = region_ref_at(0);
	lxp_slot_ref_t initial_owner = slot_ref_at(0);
	if (lxp_image_launch(eng, cfg, 0, initial_region, initial_owner, initial.data, initial.size,
			     1, 0, initial.argc, initial.argv, cfg->env, 0) != 0) {
		goto launch_failed;
	}
	/* Interpreter scripts name the interpreter's final non-symlink image here,
	 * so /proc/self/exe keeps re-execing the ELF which actually runs. */
	g_lxp_slots[0].proc.exec_file_idx = initial.file_index;
	refresh_stats();
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
		g_coord_iters++; /* heartbeat: see lxp_run_health() */
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
		/* Event classes: enum lxp_ev_class, expanded from LXP_LAT_CLASS_LIST in
		 * lxp_latency.h so the dispatch, the stats array and the names a port
		 * prints cannot fall out of step. LXP_EV_NONE (0) means "nothing claimed". */
		struct lxp_claimed_event claimed = coordinator_claim_event(eng, &event_cursor);
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
			lxp_handle_primary_event(eng, cfg, es, et, &next_pid);
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
		struct lxp_blocked_scan blocked = lxp_scan_blocked(eng, cfg, now);
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
			refresh_stats();
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
		 * NEAREST sleeper deadline (so nanosleep wakes on time, not quantized to the old
		 * fixed 50ms), clamped to a short poll for wait classes without an event source.
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
	coordinator_teardown_all(eng);
	refresh_stats();
	lxp_diag_checkpoint();
	return rc;

launch_failed:
	coordinator_teardown_all(eng);
	refresh_stats();
	lxp_diag_checkpoint();
	return LXP_RUN_ELAUNCH;
}

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
	if (!contract || contract->abi_version != LXP_CPU_MEMORY_CONTRACT_ABI_VERSION ||
	    contract->struct_size != sizeof(*contract) ||
	    (contract->flags & ~LXP_CPU_MEMORY_KNOWN_FLAGS) != 0u ||
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

static int os_ops_valid(const lxp_os_ops_t *ops)
{
	if (!ops || ops->abi_version != LXP_OS_OPS_ABI_VERSION ||
	    ops->struct_size != sizeof(*ops) || !ops->region || !ops->spawn_launch ||
	    !ops->spawn_resume || !ops->abort_slot || !ops->park_entry || !ops->park_prepare ||
	    !ops->park_slot || !ops->crit_enter || !ops->crit_exit || !ops->event_post ||
	    !ops->event_wait || !ops->time_us || !ops->time_ns || !ops->exec_capture ||
	    !ops->random_fill || !ops->publish_executable || !ops->validate_memory_contract ||
	    !cpu_memory_contract_valid(ops->cpu_memory_contract))
		return 0;
#if LXP_ENABLE_NETFS_EXEC
	if (!ops->exec_stage)
		return 0;
#endif
	for (int r = 0; r < LXP_NREG; r++)
		if (!ops->region(r))
			return 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (!ops->exec_capture(s))
			return 0;
	return 1;
}

static int net_ops_valid(const lxp_net_ops_t *ops)
{
#if LXP_ENABLE_NET
	if (!ops || ops->abi_version != LXP_NET_OPS_ABI_VERSION ||
	    ops->struct_size != sizeof(*ops) || !ops->run_begin || !ops->run_end ||
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

static int display_ops_valid(const lxp_display_ops_t *ops)
{
#if LXP_ENABLE_DEV_FB || LXP_ENABLE_DEV_DMA2D || LXP_ENABLE_TOUCH
	if (!ops || ops->abi_version != LXP_DISPLAY_OPS_ABI_VERSION ||
	    ops->struct_size != sizeof(*ops))
		return 0;
#endif
#if LXP_ENABLE_DEV_FB
	if (!ops->fb_init || !ops->fb_get_info || !ops->fb_get_buffer || !ops->fb_present)
		return 0;
#endif
#if LXP_ENABLE_DEV_DMA2D
	if (!ops->dma2d_init || !ops->dma2d_submit)
		return 0;
#endif
#if LXP_ENABLE_TOUCH
	if (!ops->touch_init || !ops->touch_read || !ops->touch_deinit)
		return 0;
#endif
	(void)ops;
	return 1;
}

static int fs_ops_valid(const lxp_fs_ops_t *ops)
{
#if LXP_ENABLE_FS
	if (!ops || ops->abi_version != LXP_FS_OPS_ABI_VERSION ||
	    ops->struct_size != sizeof(*ops) || !ops->run_begin || !ops->run_end ||
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

static int block_ops_valid(const lxp_block_ops_t *ops)
{
#if LXP_ENABLE_BLOCK
	if (!ops || ops->abi_version != LXP_BLOCK_OPS_ABI_VERSION ||
	    ops->struct_size != sizeof(*ops) || !ops->run_begin || !ops->run_end ||
	    !ops->request_owner || !ops->request_cancel || !ops->get_info || !ops->open ||
	    !ops->close || !ops->read || !ops->write || !ops->sync)
		return 0;
#else
	(void)ops;
#endif
	return 1;
}

static int run_config_valid(const lxp_run_config_t *cfg)
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
	if (!!cfg->console_subscribe != !!cfg->console_unsubscribe ||
	    (cfg->console_subscribe && (!cfg->read_fn || !cfg->console_poll)))
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
	lxp_diag_reset_health();
	g_diag_native_known = 0;
	memset(g_diag_native_present, 0, sizeof(g_diag_native_present));
	g_diag_lifecycle_epoch = 0;
	g_diag_native_epoch = 0;
	if (!os_ops_valid(os_ops) || !net_ops_valid(net_ops) || !display_ops_valid(display_ops) ||
	    !fs_ops_valid(fs_ops) || !block_ops_valid(block_ops) || !run_config_valid(run_config) ||
	    !path || argc < 1 || !argv)
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
	g_eng = NULL;
	g_cfg = NULL;
	g_lxp_rootfs_lo = NULL;
	g_lxp_rootfs_hi = NULL;
	lxp_providers_clear();
	return rc;
}

#if defined(LXP_TEST_INTERNALS)
struct lxp_runtime_test_fixture *lxp_runtime_test_fixture(void)
{
	static struct lxp_runtime_test_fixture fixture = {
		.slots = g_lxp_slots,
		.regions = g_regions,
		.vfork_guards = g_vfork_guard,
		.config = &g_cfg,
		.engine = &g_eng,
		.rootfs_lo = &g_lxp_rootfs_lo,
		.rootfs_hi = &g_lxp_rootfs_hi,
		.diag_native_known = &g_diag_native_known,
		.diag_native_present = g_diag_native_present,
		.diag_lifecycle_epoch = &g_diag_lifecycle_epoch,
		.diag_native_epoch = &g_diag_native_epoch,
		.tty_isig = &g_tty_isig,
		.tty_icrnl = &g_tty_icrnl,
#if defined(LXP_TEST_FAILPOINTS)
		.lifecycle_failpoint = &g_lifecycle_failpoint,
#endif
	};

	return &fixture;
}

lxp_region_ref_t lxp_test_region_ref_at(int region)
{
	return region_ref_at(region);
}

int lxp_test_region_commit_address_space(lxp_region_ref_t ref, lxp_slot_ref_t owner)
{
	return lxp_region_commit_address_space(ref, owner);
}

unsigned lxp_test_coordinator_wait_timeout(uint32_t wait_policy, int socket_ready_events,
					   int console_ready_events)
{
	return coordinator_wait_timeout(wait_policy, socket_ready_events, console_ready_events);
}

void lxp_test_coordinator_teardown_all(const lxp_os_ops_t *eng)
{
	coordinator_teardown_all(eng);
}

int lxp_test_futex_has_corunner(const lxp_proc_t *proc)
{
	return futex_has_corunner(proc);
}

void lxp_test_diag_reset_health(void)
{
	lxp_diag_reset_health();
}

void lxp_test_diag_checkpoint(void)
{
	lxp_diag_checkpoint();
}

void lxp_test_trap_publish(int active)
{
	lxp_trap_publish(active);
}

void lxp_test_deferred_state_store(int slot, uint8_t state)
{
	deferred_state_store(slot, state);
}

int lxp_test_os_ops_valid(const lxp_os_ops_t *ops)
{
	return os_ops_valid(ops);
}

int lxp_test_net_ops_valid(const lxp_net_ops_t *ops)
{
	return net_ops_valid(ops);
}

int lxp_test_run_config_valid(const lxp_run_config_t *cfg)
{
	return run_config_valid(cfg);
}

void lxp_test_futex(struct lxp_frame *frame, lxp_proc_t *proc, int is_time64)
{
	lxp_futex(frame, proc, is_time64);
}

void lxp_test_dispatch(struct lxp_frame *frame, lxp_proc_t *proc)
{
	lxp_dispatch(frame, proc);
}
#endif
