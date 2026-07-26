/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Engine-agnostic Linux-personality run loop + svc dispatch + signal delivery,
 * shared by the Zephyr / FreeRTOS / NuttX seams (see lxp_run.h). The
 * NOMMU process model lives here once; each seam supplies the svc trap, the
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
#include "lxp/lxp_types.h"
#include "lxp/lxp_seam.h"
#include "lxp/lxp_latency.h"
#include "lxp/lxp_stats.h"
#if LXP_ENABLE_DEV
#include "lxp/lxp_dev.h" /* device-layer park/retry + autoreg + tick + kick */
#include "lxp/lxp_disp_ops.h" /* g_lxp_disp_ops (published by lxp_run) + lxp_disp_set_geometry */
#endif
#if LXP_ENABLE_NET
#include "lxp/lxp_net.h" /* socket-layer park/retry + fork/exit fd lifecycle */
#include "lxp/lxp_net_ops.h" /* g_lxp_net_ops (published by lxp_run) */
#endif
#if LXP_ENABLE_NETFS
#include "lxp/lxp_netfs.h" /* remote-fs park/retry + init/pump + fork/exit lifecycle */
#endif
#if LXP_ENABLE_PTY
#include "lxp/lxp_pty.h" /* pty-layer park/retry (lxp_pty_retry) */
#endif

#include "lxp_internal.h" /* lxp_encode_wstatus (shared with sys_wait4) */
#include "lxp_run_internal.h" /* g_sig_save + slot_of/park_frame ↔ src/lxp_signal.c */

/* Latest native-task census collected by refresh_stats(). A separate known bit
 * distinguishes a clean "no task" result from an engine without introspection
 * or a truncated kernel-thread list. Diagnostic reads never invoke the engine
 * from an arbitrary caller context. */
static uint8_t g_diag_native_known;
static uint8_t g_diag_native_present[LXP_NSLOT];

/* Rebuild the ps/top snapshot from the live process SET + the RTOS kernel threads.
 * Run-loop thread only (ove_thread_list locks the scheduler — unsafe from the svc
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
	for (size_t i = 0; i < n; i++)
		if (ti[i].lxp_slot >= 0 && ti[i].lxp_slot < LXP_NSLOT)
			g_diag_native_present[ti[i].lxp_slot] = 1;

	/* 1. Charge each live Linux thread's CPU to its explicitly assigned slot. */
	uint64_t idle = 0, busy = 0;
	for (size_t i = 0; i < n; i++) {
		const char *name = ti[i].name ? ti[i].name : "?";
		uint64_t rus = ti[i].state_times.running_us;
		int cls = lxp_stats_classify(name);
		if (cls == 1) {
			idle += rus;
			continue;
		}
		busy += rus;
		int s = ti[i].lxp_slot;
		if (s >= 0 && s < LXP_NSLOT && g_lxp_proc[s].alive)
			lxp_stats_charge(g_lxp_proc[s].pid, rus);
	}
	/* 2. Build the snapshot: the live Linux procs, then the kernel threads [name]. */
	lxp_stats_begin();
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_proc[s];
		if (!p->alive)
			continue;
		char state = (g_lxp_used[s] && !p->sleeping && !p->wait_pending) ? 'R' : 'S';
		if (lxp_stats_add(p->pid, p->group->ppid, p->comm, state,
				  lxp_proc_cpu_us(p->pid), 0) != LXP_OK)
			overflow = 1;
	}
	for (size_t i = 0; i < n; i++) {
		const char *name = ti[i].name ? ti[i].name : "?";
		if (lxp_stats_classify(name) != 0 ||
		    ti[i].lxp_slot != LXP_THREAD_SLOT_NONE)
			continue; /* idle or a Linux slot thread */
		int kpid = lxp_kpid_for(name);
		if (kpid < 0 ||
		    lxp_stats_add(kpid, 0, name, 'S',
				  ti[i].state_times.running_us, 1) != LXP_OK)
			overflow = 1;
	}
	if (overflow)
		(void)lxp_stats_add(LXP_KPID_BASE + LXP_MAX_KTHREAD, 0,
				    "threads-overflow", 'S', 0, 1);
	lxp_stats_set_cpu(idle, busy);
}

/* ---- shared state ---------------------------------------------------------- */
struct lxp_resume_ctx g_lxp_vfork;
lxp_proc_t g_lxp_proc[LXP_NSLOT];
int g_lxp_used[LXP_NSLOT];
volatile int g_lxp_active;
/* Coordinator heartbeat: bumped once per dispatch-loop iteration, read by a host
 * watchdog through lxp_run_health(). Free-running; a stalled value while active
 * is the wedge signal. volatile + aligned u32 => the cross-task read is atomic
 * without a lock (the reader only needs to observe change, not a precise count). */
static volatile uint32_t g_coord_iters;
/* g_lxp_halt is defined in the syscall layer (reboot(2) sets it) so the
 * host syscall tests link without the run loop; the run loop only observes it. */

static lxp_arena_t g_arenas[LXP_NREG];
/* Exact region reservations, including shared address spaces and vfork
 * snapshot/exec handoff regions that do not yet appear as a distinct live task.
 * owner identifies the reservation incarnation; refs keeps a shared CLONE_VM or
 * vfork address space reserved until its last task releases it. */
static int g_region_owner[LXP_NREG];
static uint16_t g_region_refs[LXP_NREG];
/* Every reservation/release changes the generation as well as the owner. A
 * vfork snapshot records both generations so a delayed restore cannot copy
 * stale bytes after either slot or region has been recycled. */
static uint32_t g_region_generation[LXP_NREG];
struct vfork_snapshot_guard {
	uint32_t parent_slot_generation;
	uint32_t parent_region_generation;
	uint32_t snapshot_region_generation;
	int parent_slot;
	int parent_region;
	int snapshot_region;
};
static struct vfork_snapshot_guard g_vfork_guard[LXP_NSLOT];
/* vfork data isolation: a snapshot of the shared arena's allocator metadata, taken when a vfork
 * child is spawned (keyed by the child's slot) and restored when it execs/exits — the region+dyn_pool
 * BYTES are snapshotted into a spare region, but g_arenas[] lives in coordinator memory. */
static lxp_arena_t g_snap_arena[LXP_NSLOT];
static const lxp_run_config_t *g_cfg;
static const lxp_os_ops_t *g_eng; /* for the dispatch to post coordinator events */

#define LXP_EVENT_WORD_BITS 32u
#define LXP_EVENT_WORDS ((LXP_NSLOT + LXP_EVENT_WORD_BITS - 1u) / LXP_EVENT_WORD_BITS)
/* SVC/fault context publishes the slot it parked before waking the coordinator.
 * The bitmap lets the coordinator find primary work without locking and scanning
 * the whole process table. The selected slot is still revalidated and claimed
 * under the engine critical section. */
static uint32_t g_primary_pending[LXP_EVENT_WORDS];

/* ---- OS-service hooks routed through the engine ops ------------------------
 * The personality core calls these instead of the host's ove_time_* / cache
 * primitives, so it carries no direct dependency on any particular OS. The seam
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
		if (g_lxp_proc[s].alive)
			slots_used++;
	out->slots_free = LXP_NSLOT - slots_used;

	unsigned regions_used = 0;
	for (int r = 0; r < LXP_NREG; r++) {
		int occupied = g_lxp_active && g_region_owner[r] >= 0;
		for (int s = 0; !occupied && s < LXP_NSLOT; s++)
			if (g_lxp_proc[s].alive && g_lxp_proc[s].mm &&
			    g_lxp_proc[s].mm->region == r)
				occupied = 1;
		if (occupied)
			regions_used++;
	}
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
const uint8_t *g_lxp_rootfs_lo;
const uint8_t *g_lxp_rootfs_hi;

/* access_ok (lxp_syscall.c) asks for the shared read-only rootfs span so a read-source user
 * pointer may point into a program's .rodata (shared in-place from the cpio). Strong override of the
 * weak stub in the syscall layer. */
void lxp_rootfs_bounds(uintptr_t *lo, uintptr_t *hi)
{
	*lo = (uintptr_t)g_lxp_rootfs_lo;
	*hi = (uintptr_t)g_lxp_rootfs_hi;
}

/* Proc-table accessors so the pipe layer can scan all live procs' fds (count a pipe's
 * open read/write ends for EOF / EPIPE) without the syscall layer knowing LXP_NSLOT. */
lxp_proc_t *lxp_proc_table(void)
{
	return g_lxp_proc;
}
int lxp_proc_nslot(void)
{
	return LXP_NSLOT;
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

#if LXP_ENABLE_NET
/* Wake the coordinator so it retries parked socket I/O at once — the network RX task calls
 * this after delivering a batch of frames to the stack, so a parked recv/connect/accept
 * resumes the instant its data/ACK lands instead of on the next ≤5 ms retry tick. Mirrors
 * lxp_dev_kick; only ever called with LXP_ENABLE_NET set, so this
 * run loop is always linked and no weak no-op is needed. */
void lxp_sock_kick(void)
{
	if (g_eng && g_eng->event_post)
		g_eng->event_post();
}
#endif

#if LXP_ENABLE_NETFS
/* Wake the coordinator so it pumps the 9P transport at once — the eth RX task calls this
 * after delivering frames, so a parked netfs op resumes the instant its reply lands. */
void lxp_netfs_kick(void)
{
	if (g_eng && g_eng->event_post)
		g_eng->event_post();
}
#endif

/*
 * Socket waits only need the short retry timeout when the host cannot publish
 * readiness changes. Other wait classes retain their polling fallback.
 */
static unsigned coordinator_wait_timeout(int any_poll_wait, int any_sock_wait,
					 int socket_ready_events)
{
	return (any_poll_wait || (any_sock_wait && !socket_ready_events)) ? 5u : 50u;
}

/* Per-slot captured resume context (replaces the single global g_lxp_vfork +
 * the run-loop-local vctx[] — many forks/sleeps/waits can be outstanding at once
 * under the concurrent model). A proc is only ever in ONE of fork/sleep/wait at a
 * time, so one ctx per slot suffices; a vfork child resumes from its PARENT's ctx. */
static struct lxp_resume_ctx g_ctx[LXP_NSLOT];

/* One fixed deferred-syscall mailbox per process slot. The SVC top half owns
 * IDLE->FILLING->READY; the coordinator owns READY->RUNNING->IDLE. Only r0 is
 * stored here because capture_ctx() already snapshots r1-r5 and r7 (the syscall
 * number). A generation rejects a stale mailbox after exit/exec/slot reuse. */
enum deferred_state {
	DEFER_IDLE,
	DEFER_FILLING,
	DEFER_READY,
	DEFER_RUNNING,
};
struct deferred_req {
	uint32_t a0;
	uint32_t generation;
	uint8_t state;
	uint8_t _pad[3];
#if LXP_ENABLE_LATENCY
	/* Stamped where the guest publishes, read where the coordinator claims:
	 * the gap is how long a flood from one guest delays another's event. Lives
	 * in the mailbox, not lxp_proc_t, so it shares the entry's lifetime and a
	 * recycled slot cannot present a stale publish time as a fresh wait. */
	uint64_t pub_ns;
#endif
};
static struct deferred_req g_deferred[LXP_NSLOT];
static uint32_t g_slot_generation[LXP_NSLOT];

/* One coordinator-owned host lifecycle per slot. g_lxp_used remains the public
 * seam's cheap "currently runnable" view, but only the transition helpers below
 * may change it. This keeps Linux ownership and the RTOS task state in one
 * transaction instead of letting each backend publish half of a transition. */
enum slot_lifecycle {
	SLOT_FREE,
	SLOT_STARTING,
	SLOT_RUNNING,
	SLOT_PARKING,
	SLOT_PARKED,
	SLOT_RESUMING,
	SLOT_EXITING,
	SLOT_DEAD,
	SLOT_FAILED,
};
static uint8_t g_slot_lifecycle[LXP_NSLOT];

static uint8_t deferred_state_load(int slot)
{
	return __atomic_load_n(&g_deferred[slot].state, __ATOMIC_ACQUIRE);
}

static void deferred_state_store(int slot, uint8_t state)
{
	__atomic_store_n(&g_deferred[slot].state, state, __ATOMIC_RELEASE);
}

static void deferred_slot_reassign(int slot)
{
	deferred_state_store(slot, DEFER_IDLE);
	uint32_t next = __atomic_add_fetch(&g_slot_generation[slot], 1u, __ATOMIC_RELAXED);
	if (next == 0) /* reserve zero for the static, never-assigned state */
		(void)__atomic_add_fetch(&g_slot_generation[slot], 1u, __ATOMIC_RELAXED);
}

/* Per-slot FDPIC runtime load addresses, exported (non-static) for SOURCE-LEVEL GDB DEBUGGING of
 * the userspace program. An FDPIC exec is loaded at runtime addresses (the loadmap relocates each
 * segment independently), so the on-disk ELF's link addresses don't match memory. A GDB helper
 * reads this table and `add-symbol-file <elf> -o <text_base>`s the
 * program, then walks the exec's _DYNAMIC[DT_DEBUG] rendezvous (populated by ld.so once it has run)
 * to auto-load ld.so + every shared library at its own FDPIC bias. comm[] (in g_lxp_proc) names
 * the program; text_base/data_base are the loadmap-relocated bases of its text/data segments. */
struct lxp_dbg_s {
	uintptr_t text_base; /* runtime base of the program's text (shared in-place from the cpio) */
	uintptr_t data_base; /* runtime base of the program's RW data (in the slot's region) */
	uintptr_t entry;     /* the program's own entry (AT_ENTRY), not ld.so's */
	uintptr_t dynamic;   /* runtime addr of the exec's _DYNAMIC → DT_DEBUG → the ld.so link-map chain */
	uintptr_t interp_base; /* ld.so's text base (0 for a static exec); auto-solib loads ld.so there */
};
struct lxp_dbg_s g_lxp_dbg[LXP_NSLOT];

int slot_of(const lxp_proc_t *p)
{
	uintptr_t a = (uintptr_t)p, lo = (uintptr_t)&g_lxp_proc[0],
		  hi = (uintptr_t)&g_lxp_proc[LXP_NSLOT];
	if (a < lo || a >= hi || (a - lo) % sizeof(g_lxp_proc[0]) != 0)
		return -1;
	return (int)((a - lo) / sizeof(g_lxp_proc[0]));
}

static void primary_slot_mark(int slot)
{
	if (slot < 0 || slot >= LXP_NSLOT)
		return;
	unsigned word = (unsigned)slot / LXP_EVENT_WORD_BITS;
	uint32_t bit = (uint32_t)1u << ((unsigned)slot % LXP_EVENT_WORD_BITS);
	__atomic_fetch_or(&g_primary_pending[word], bit, __ATOMIC_RELEASE);
}

static int primary_slot_pending(int slot)
{
	unsigned word = (unsigned)slot / LXP_EVENT_WORD_BITS;
	uint32_t bit = (uint32_t)1u << ((unsigned)slot % LXP_EVENT_WORD_BITS);
	return (__atomic_load_n(&g_primary_pending[word], __ATOMIC_ACQUIRE) & bit) != 0;
}

static void primary_slot_clear(int slot)
{
	unsigned word = (unsigned)slot / LXP_EVENT_WORD_BITS;
	uint32_t bit = (uint32_t)1u << ((unsigned)slot % LXP_EVENT_WORD_BITS);
	__atomic_fetch_and(&g_primary_pending[word], ~bit, __ATOMIC_RELAXED);
}

/* Publish a primary per-slot event and wake the coordinator. Ports use this for
 * contained guest faults; normal syscall/signal parking reaches it through
 * park_frame(). Safe when the slot is stale: the coordinator simply clears a
 * hint that fails revalidation. */
void lxp_event_post_slot(int slot)
{
	primary_slot_mark(slot);
	if (g_eng && g_eng->event_post)
		g_eng->event_post();
}

/* Capture the post-svc context of frame f into slot s's resume ctx. */
static void capture_ctx(int s, const struct lxp_frame *f)
{
	for (int i = 0; i < 8; i++)
		g_ctx[s].r4_11[i] = f->r[4 + i];
	g_ctx[s].r12 = f->r[12];
	g_ctx[s].lr = f->r[14];
	g_ctx[s].sp = f->r[13];	     /* the seam set r[13] = the pre-svc SP */
	g_ctx[s].pc = f->r[15] | 1u; /* resume after the svc (Thumb) */
	/* Preserve r1-r3 across the parking syscall (Linux preserves r1-r14; only r0 is
	 * the return, supplied by the resume). A guest may reuse an arg register after a
	 * syscall — so leaving these garbage on resume corrupts it (e.g. wait4's options). */
	g_ctx[s].r1 = f->r[1];
	g_ctx[s].r2 = f->r[2];
	g_ctx[s].r3 = f->r[3];
	g_ctx[s].xpsr = f->xpsr;
#if LXP_ENABLE_FPU_CONTEXT
	if (f->fp)
		g_ctx[s].fp = *f->fp;
	else
		memset(&g_ctx[s].fp, 0, sizeof(g_ctx[s].fp));
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
	    !__atomic_compare_exchange_n(&g_deferred[slot].state, &expected, DEFER_FILLING, 0,
					 __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		f->r[0] = (uint32_t)-LXP_EAGAIN;
		return;
	}
	g_deferred[slot].a0 = f->r[0];
	g_deferred[slot].generation =
		__atomic_load_n(&g_slot_generation[slot], __ATOMIC_RELAXED);
#if LXP_ENABLE_LATENCY
	{ /* the only timer call on the svc top half, and only when instrumented */
		uint64_t t = 0;
		lxp_time_ns(&t);
		g_deferred[slot].pub_ns = t;
	}
#endif
	deferred_state_store(slot, DEFER_READY);
	park_frame(f, proc);
}

/* Park the program frame until the coordinator reaps the event, and wake the
 * coordinator (it blocks in event_wait rather than busy-polling). Persistent
 * ports prepare a guest-readable resume token while the original svc frame is
 * still live; legacy ports leave r0 NULL and retain abort/recreate behavior. */
void park_frame(struct lxp_frame *f, lxp_proc_t *proc)
{
	int slot = slot_of(proc);
	capture_ctx(slot, f);
	void *token = NULL;
	if (g_eng && g_eng->park_prepare && g_eng->park_slot)
		token = g_eng->park_prepare(
			slot, __atomic_load_n(&g_slot_generation[slot], __ATOMIC_RELAXED),
			&g_ctx[slot]);
	f->r[0] = (uint32_t)(uintptr_t)token;
	f->r[15] = (uint32_t)((uintptr_t)&lxp_park_loop & ~(uintptr_t)1u);
	f->xpsr |= (1u << 24);
	lxp_event_post_slot(slot);
}

/* Bounded per-slot stacks of interrupted signal contexts. LinuxThreads can
 * deliver restart/timer signals to several slots concurrently, and a different
 * signal may interrupt an active handler within one slot. r4-r8/r10-r11 are not
 * stored because a C handler preserves them; r9 is explicit because FDPIC uses
 * it as the module GOT. Delivery/restore operations live in lxp_signal.c. */
struct sig_save_stack_s g_sig_save[LXP_NSLOT];

static lxp_diag_health_t g_diag_health;
static uint32_t slot_generation(int sidx);

static uint32_t diag_intent_mask(int slot)
{
	const lxp_proc_t *p = &g_lxp_proc[slot];
	uint32_t mask = 0;
	if (deferred_state_load(slot) != DEFER_IDLE)
		mask |= LXP_DIAG_INTENT_DEFERRED_SYSCALL;
	if (p->fork_pending)
		mask |= LXP_DIAG_INTENT_FORK;
	if (p->exec_pending)
		mask |= LXP_DIAG_INTENT_EXEC;
	if (p->exited)
		mask |= LXP_DIAG_INTENT_EXIT;
	return mask;
}

static uint32_t diag_wait_mask(const lxp_proc_t *p)
{
	uint32_t mask = 0;
	if (p->sleep_pending || p->sleeping)
		mask |= LXP_DIAG_WAIT_TIMER;
	if (p->wait_pending)
		mask |= LXP_DIAG_WAIT_CHILD;
	if (p->futex_wait)
		mask |= LXP_DIAG_WAIT_FUTEX;
	if (p->pipe_wait)
		mask |= LXP_DIAG_WAIT_PIPE;
	if (p->console_wait)
		mask |= LXP_DIAG_WAIT_CONSOLE;
	if (p->dev_wait)
		mask |= LXP_DIAG_WAIT_DEVICE;
	if (p->sock_wait)
		mask |= LXP_DIAG_WAIT_SOCKET;
	if (p->netfs_wait)
		mask |= LXP_DIAG_WAIT_NETFS;
	if (p->pty_wait)
		mask |= LXP_DIAG_WAIT_PTY;
	if (p->sigsuspend_pending)
		mask |= LXP_DIAG_WAIT_SIGSUSPEND;
	return mask;
}

static uint8_t diag_task_status(const lxp_proc_t *p)
{
	if (!p->alive)
		return LXP_DIAG_TASK_FREE;
	if (p->exited)
		return LXP_DIAG_TASK_ZOMBIE;
	if (p->stopped)
		return LXP_DIAG_TASK_STOPPED;
	return LXP_DIAG_TASK_LIVE;
}

int lxp_diag_slot_snapshot(int slot, lxp_diag_slot_t *out)
{
	if (!out || slot < 0 || slot >= LXP_NSLOT)
		return -LXP_EINVAL;
	const lxp_proc_t *p = &g_lxp_proc[slot];
	memset(out, 0, sizeof(*out));
	out->abi_version = LXP_DIAG_ABI_VERSION;
	out->struct_size = sizeof(*out);
	out->slot = slot;
	out->generation = slot_generation(slot);
	out->pid = p->pid;
	out->tgid = p->group ? p->group->tgid : 0;
	out->ppid = p->group ? p->group->ppid : 0;
	out->region = p->mm ? p->mm->region : -1;
	out->vfork_parent_slot = p->vfork_parent_slot;
	out->snapshot_region = p->snap_region;
	out->host_state = g_slot_lifecycle[slot];
	out->task_status = diag_task_status(p);
	out->deferred_state = deferred_state_load(slot);
	out->runnable = g_lxp_used[slot] != 0;
	out->primary_pending = primary_slot_pending(slot);
	out->signal_depth = g_sig_save[slot].depth;
	out->native_task_known = g_diag_native_known;
	out->native_task_present = g_diag_native_present[slot];
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
		out->region_generation = g_region_generation[out->region];
		out->region_refs = g_region_refs[out->region];
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
	out->owner_slot = g_region_owner[region];
	out->refs = g_region_refs[region];
	out->generation = g_region_generation[region];
	for (int slot = 0; slot < LXP_NSLOT; slot++)
		if (g_lxp_proc[slot].alive && g_lxp_proc[slot].mm &&
		    g_lxp_proc[slot].mm->region == region)
			out->live_users++;
	return LXP_OK;
}

static int diag_error(lxp_diag_error_t *error, lxp_diag_issue_t issue,
		      int slot, int region, uint32_t actual, uint32_t expected)
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

static unsigned diag_popcount(uint32_t value)
{
	unsigned count = 0;
	while (value) {
		value &= value - 1u;
		count++;
	}
	return count;
}

static unsigned diag_live_resource_users(const void *identity, int resource)
{
	unsigned users = 0;
	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		const lxp_proc_t *p = &g_lxp_proc[slot];
		if (!p->alive)
			continue;
		const void *candidate = resource == 0   ? (const void *)p->mm
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
		int owner = g_region_owner[region];
		uint16_t refs = g_region_refs[region];
		if (refs == 0 && owner != -1)
			return diag_error(error, LXP_DIAG_REGION_OWNER_WITHOUT_REFS,
					  owner, region, (uint32_t)owner, UINT32_MAX);
		if (refs != 0 && (owner < 0 || owner >= LXP_NSLOT))
			return diag_error(error, LXP_DIAG_REGION_REFS_WITHOUT_OWNER,
					  owner, region, refs, 0);
		if (refs != 0 && g_region_generation[region] == 0)
			return diag_error(error, LXP_DIAG_REGION_REFS_WITHOUT_GENERATION,
					  owner, region, 0, 1);
	}

	for (int slot = 0; slot < LXP_NSLOT; slot++) {
		const lxp_proc_t *p = &g_lxp_proc[slot];
		uint8_t host = g_slot_lifecycle[slot];
		uint8_t deferred = deferred_state_load(slot);
		uint32_t intents = diag_intent_mask(slot);
		uint32_t waits = diag_wait_mask(p);

		if (host > SLOT_FAILED)
			return diag_error(error, LXP_DIAG_BAD_SLOT, slot, -1, host,
					  SLOT_FAILED);
		if (deferred > DEFER_RUNNING)
			return diag_error(error, LXP_DIAG_DEFERRED_STATE_INVALID,
					  slot, -1, deferred, DEFER_RUNNING);
		if (host != SLOT_FREE && slot_generation(slot) == 0)
			return diag_error(error, LXP_DIAG_HOST_STATE_WITHOUT_GENERATION,
					  slot, -1, 0, 1);
		if (deferred != DEFER_IDLE &&
		    g_deferred[slot].generation != slot_generation(slot))
			return diag_error(error, LXP_DIAG_DEFERRED_GENERATION_STALE,
					  slot, -1, g_deferred[slot].generation,
					  slot_generation(slot));
		if (diag_popcount(intents) > 1)
			return diag_error(error, LXP_DIAG_MULTIPLE_INTENTS, slot, -1,
					  intents, 1);
		if (diag_popcount(waits) > 1)
			return diag_error(error, LXP_DIAG_MULTIPLE_WAITS, slot, -1,
					  waits, 1);

		if (!p->alive) {
			if (g_lxp_used[slot])
				return diag_error(error, LXP_DIAG_FREE_TASK_RUNNABLE,
						  slot, -1, 1, 0);
			if (g_diag_native_known && g_diag_native_present[slot] &&
			    (host == SLOT_FREE || host == SLOT_DEAD))
				return diag_error(error, LXP_DIAG_NATIVE_TASK_LEAKED,
						  slot, -1, host, SLOT_FREE);
			continue;
		}
		if (!p->mm || !p->files || !p->fs_context || !p->sighand || !p->group)
			return diag_error(error, LXP_DIAG_LIVE_TASK_WITHOUT_RESOURCES,
					  slot, -1, 0, 5);
		int region = p->mm->region;
		if (region < 0 || region >= LXP_NREG)
			return diag_error(error, LXP_DIAG_LIVE_TASK_BAD_REGION,
					  slot, region, (uint32_t)region, LXP_NREG);
		if (g_region_refs[region] == 0)
			return diag_error(error, LXP_DIAG_LIVE_TASK_WITHOUT_REGION_REF,
					  slot, region, 0, 1);
		unsigned region_users = 0;
		for (int peer = 0; peer < LXP_NSLOT; peer++)
			if (g_lxp_proc[peer].alive && g_lxp_proc[peer].mm &&
			    g_lxp_proc[peer].mm->region == region)
				region_users++;
		if (g_region_refs[region] < region_users)
			return diag_error(error, LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL,
					  slot, region, g_region_refs[region], region_users);

#define CHECK_RESOURCE_REFS(member, which)                                              \
	do {                                                                             \
		unsigned users = diag_live_resource_users(p->member, which);               \
		if (p->member->refs < users)                                               \
			return diag_error(error, LXP_DIAG_RESOURCE_REFCOUNT_TOO_SMALL,      \
					  slot, region, p->member->refs, users);             \
	} while (0)
		CHECK_RESOURCE_REFS(mm, 0);
		CHECK_RESOURCE_REFS(files, 1);
		CHECK_RESOURCE_REFS(fs_context, 2);
		CHECK_RESOURCE_REFS(sighand, 3);
		CHECK_RESOURCE_REFS(group, 4);
#undef CHECK_RESOURCE_REFS

		if (g_lxp_used[slot] && host != SLOT_RUNNING && host != SLOT_FAILED)
			return diag_error(error, LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH,
					  slot, region, host, SLOT_RUNNING);
		if (host == SLOT_RUNNING && !g_lxp_used[slot])
			return diag_error(error, LXP_DIAG_RUNNABLE_HOST_STATE_MISMATCH,
					  slot, region, 0, 1);
		if (host == SLOT_PARKED && g_lxp_used[slot])
			return diag_error(error, LXP_DIAG_PARKED_TASK_RUNNABLE,
					  slot, region, 1, 0);
		if (g_diag_native_known &&
		    (host == SLOT_RUNNING || host == SLOT_PARKED || host == SLOT_FAILED) &&
		    !g_diag_native_present[slot])
			return diag_error(error, LXP_DIAG_NATIVE_TASK_MISSING,
					  slot, region, 0, 1);
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
	out->per_slot_core = out->proc + out->resume_context +
			     out->deferred_request + out->signal_save_stack +
			     out->vfork_guard + out->arena + out->debug_record;
	out->per_region_core = out->arena + sizeof(g_region_owner[0]) +
			       sizeof(g_region_refs[0]) +
			       sizeof(g_region_generation[0]);
	out->slot_table = sizeof(g_lxp_proc);
	out->coordinator_static =
		sizeof(g_lxp_proc) + sizeof(g_lxp_used) + sizeof(g_arenas) +
		sizeof(g_region_owner) + sizeof(g_region_refs) +
		sizeof(g_region_generation) + sizeof(g_vfork_guard) +
		sizeof(g_snap_arena) + sizeof(g_primary_pending) + sizeof(g_ctx) +
		sizeof(g_deferred) + sizeof(g_slot_generation) +
		sizeof(g_slot_lifecycle) + sizeof(g_lxp_dbg) + sizeof(g_sig_save) +
		sizeof(g_diag_native_present) + sizeof(g_diag_health);
}

void lxp_diag_health(lxp_diag_health_t *out)
{
	if (out)
		*out = g_diag_health;
}

const char *lxp_diag_host_state_name(unsigned state)
{
	static const char *const names[] = {
		"free", "starting", "running", "parking", "parked",
		"resuming", "exiting", "dead", "failed",
	};
	return state < sizeof(names) / sizeof(names[0]) ? names[state] : "invalid";
}

const char *lxp_diag_task_status_name(unsigned status)
{
	static const char *const names[] = {"free", "live", "stopped", "zombie"};
	return status < sizeof(names) / sizeof(names[0]) ? names[status] : "invalid";
}

const char *lxp_diag_issue_name(unsigned issue)
{
	static const char *const names[] = {
		"ok",
		"bad-slot",
		"bad-region",
		"region-owner-without-refs",
		"region-refs-without-owner",
		"region-refs-without-generation",
		"live-task-without-resources",
		"live-task-bad-region",
		"live-task-without-region-ref",
		"resource-refcount-too-small",
		"free-task-runnable",
		"runnable-host-state-mismatch",
		"parked-task-runnable",
		"native-task-missing",
		"native-task-leaked",
		"host-state-without-generation",
		"deferred-state-invalid",
		"deferred-generation-stale",
		"multiple-intents",
		"multiple-waits",
	};
	return issue < sizeof(names) / sizeof(names[0]) ? names[issue] : "invalid";
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
static volatile int g_pending_sig;
/* The console tty's foreground process group (job control): the pgid the shell put
 * in the foreground via tcsetpgrp(TIOCSPGRP). A console ^C (VINTR in cooked mode)
 * raises SIGINT on exactly this group — the shell (a different group) and background
 * jobs (their own groups) are left alone. 0 = unset (no ^C target). */
static volatile int g_console_fg_pgrp;

int lxp_tty_isig(void)
{
	return g_tty_isig;
}

void lxp_post_signal(int sig)
{
	if (sig > 0 && sig < LXP_NSIG)
		g_pending_sig = sig;
}

void lxp_console_set_fg_pgrp(int pgrp)
{
	g_console_fg_pgrp = pgrp;
}

int lxp_console_fg_pgrp(void)
{
	return g_console_fg_pgrp;
}

/* A console ^C (VINTR, cooked/ISIG mode) raises @p sig on the console's foreground
 * process group. Mirrors the kill(2) pgid fan-out in lxp_dispatch: every live process
 * whose pgid matches takes the signal (delivered at its next syscall boundary if
 * running, or by the coordinator if parked). The interactive shell sits in its own
 * group and is untouched, so it survives to re-prompt; a background job (its own group)
 * is likewise spared. With no foreground group yet (pre-first-tcsetpgrp) nothing is
 * signalled — the same no-op as before this path existed. */
static void console_signal_fg(int sig)
{
	int pg = g_console_fg_pgrp;
	if (pg <= 0)
		return;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_proc[s];
		if (p->alive && p->pid > 1 && p->group->pgid == pg)
			p->pending_sigs |= lxp_sig_bit(sig);
	}
}

void lxp_run_health(lxp_run_health_t *out)
{
	if (!out)
		return;
	out->coord_iters = g_coord_iters;
	out->active = g_lxp_active;
}

__attribute__((weak)) void lxp_park_loop(void *token)
{
	(void)token;
	for (;;) {
	}
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
	 * never FUTEX_WAKE us — exclude it (proc->vfork_parent_slot), or a vfork child's libc
	 * futex would park forever where the old stub returned -EAGAIN and made progress. */
	int vp = proc->vfork_parent_slot;
	for (int s = 0; s < LXP_NSLOT; s++) {
		const lxp_proc_t *q = &g_lxp_proc[s];
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
		if (!user_ok(proc, (const void *)uaddr, sizeof(uint32_t), 0)) {
			f->r[0] = (uint32_t)-LXP_EFAULT;
			return;
		}
		if (*(const volatile uint32_t *)uaddr != val) {
			f->r[0] = (uint32_t)-LXP_EAGAIN; /* value already moved: do not sleep */
			return;
		}
		if (!futex_has_corunner(proc)) {
			f->r[0] = (uint32_t)-LXP_EAGAIN; /* single-threaded: retry the userspace lock */
			return;
		}
		/* Optional timeout (arg4): FUTEX_WAIT is relative, FUTEX_WAIT_BITSET absolute (against
		 * our monotonic clock; a CLOCK_REALTIME absolute is approximated). Without it the wait
		 * is infinite. The coordinator resumes with -ETIMEDOUT once the deadline passes. */
		uint64_t deadline = 0;
		uintptr_t utimeout = (uintptr_t)f->r[3];
		if (utimeout) {
			if (!user_ok(proc, (const void *)utimeout, is_time64 ? 16u : 8u, 0)) {
				f->r[0] = (uint32_t)-LXP_EFAULT;
				return;
			}
			uint64_t sec, nsec;
			if (is_time64) {
				const int64_t *t = (const int64_t *)utimeout;
				sec = (uint64_t)t[0];
				nsec = (uint64_t)t[1];
			} else {
				const int32_t *t = (const int32_t *)utimeout;
				sec = (uint64_t)(uint32_t)t[0];
				nsec = (uint64_t)(uint32_t)t[1];
			}
			uint64_t ts_us = sec * 1000000ull + nsec / 1000ull, now = 0;
			lxp_time_us(&now);
			deadline = (op == 0) ? now + ts_us : ts_us;
			if (!deadline)
				deadline = 1; /* 0 encodes "no timeout"; keep a nonzero deadline */
		}
		proc->futex_uaddr = uaddr;
		proc->futex_wait = 1;
		proc->futex_deadline_us = deadline;
		park_frame(f, proc); /* the coordinator parks us; FUTEX_WAKE / timeout resumes us */
		return;
	}
	if (op == 1 || op == 10) { /* FUTEX_WAKE / FUTEX_WAKE_BITSET */
		uint32_t woken = 0;
		for (int s = 0; s < LXP_NSLOT && woken < val; s++) {
			lxp_proc_t *q = &g_lxp_proc[s];
			/* !futex_woken: a waiter already marked by an earlier WAKE (not yet resumed by
			 * the coordinator) must not be woken — or counted — twice. */
			if (q->alive && q->futex_wait && !q->futex_woken && q->futex_uaddr == uaddr) {
				q->futex_woken = 1;
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
static void flatten_vec(char *buf, const char **ptrs, const char *src_buf, const uint16_t *off_vec,
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

/* Inspect and, where necessary, consume one slot's highest-priority primary
 * event. The caller holds the engine critical section, so a program SVC cannot
 * change a flag between its test and clear. Keep this helper constant-time with
 * respect to LXP_NSLOT: the coordinator deliberately locks around one slot at a
 * time so a larger process table cannot lengthen one interrupt-masked window. */
static int claim_slot_event(int s)
{
	lxp_proc_t *p = &g_lxp_proc[s];

	if (!p->alive)
		return LXP_EV_NONE;
	if (p->exited)
		return LXP_EV_EXIT;
	if (p->exec_pending)
		return LXP_EV_EXEC;
	if (p->fork_pending) {
		p->fork_pending = 0;
		return LXP_EV_FORK;
	}
	if (deferred_state_load(s) == DEFER_READY)
		return LXP_EV_DEFER;
	if (p->sleep_pending) {
		p->sleep_pending = 0;
		return LXP_EV_SLEEP;
	}
	if (p->futex_wait && g_lxp_used[s])
		return LXP_EV_FUTEXWAIT;
	if (p->wait_pending && g_lxp_used[s])
		return LXP_EV_WAITPARK;
	if (p->pipe_wait && g_lxp_used[s])
		return LXP_EV_PIPE;
	if (p->dev_wait && g_lxp_used[s])
		return LXP_EV_DEVWAIT;
	if (p->sock_wait && g_lxp_used[s])
		return LXP_EV_SOCKWAIT;
#if LXP_ENABLE_NETFS
	if (p->netfs_wait && g_lxp_used[s])
		return LXP_EV_NETFSWAIT;
#endif
#if LXP_ENABLE_PTY
	if (p->pty_wait && g_lxp_used[s])
		return LXP_EV_PTYWAIT;
#endif
	if (p->sigsuspend_pending && g_lxp_used[s])
		return LXP_EV_SIGSUSPEND;
	if (p->console_wait && g_lxp_used[s])
		return LXP_EV_CONSOLEWAIT;
	return LXP_EV_NONE;
}

/* Lowest-numbered pending signal for @p p that is not currently blocked (SIGKILL/SIGSTOP are
 * never blocked), or 0 if none is deliverable. Does NOT clear it — the caller clears the bit
 * (pending_sigs &= ~lxp_sig_bit(sig)) once it commits to delivering. A blocked pending signal
 * is left set so it is delivered later, once the proc unblocks it. */
static int pending_deliverable(const lxp_proc_t *p)
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
	case LXP_NR_setpgid:
	case LXP_NR_getpgrp:
	case LXP_NR_setsid:
	case LXP_NR_sync:
	case LXP_NR_fsync:
	case LXP_NR_fdatasync:
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
void lxp_dispatch(struct lxp_frame *f, lxp_proc_t *proc)
{
	long nr = (long)(int32_t)f->r[7];
	if (nr == LXP_NR_kill || nr == LXP_NR_tkill || nr == LXP_NR_tgkill) {
		int sig = (nr == LXP_NR_tgkill) ? (int)f->r[2] : (int)f->r[1];
		int target = (int)f->r[0];
		/* Process-group target for a kill(pid<=0): pid==0 = the caller's group, pid<-1 = group |pid|. */
		int want_pgid = (target == 0) ? proc->group->pgid : (target < -1 ? -target : 0);
		if (sig < 0 || sig >= LXP_NSIG) { /* sig indexes sig_handler[]/pending_sig — reject OOB */
			f->r[0] = -LXP_EINVAL;
			return;
		}
		/* halt/poweroff/reboot signal a shutdown to init (pid 1) — SIGUSR1/SIGUSR2/
		 * SIGTERM respectively. init is parked and can't receive it, so honor a
		 * shutdown signal to pid 1 directly as a system halt. */
		if (nr == LXP_NR_kill && target == 1 && (sig == 10 || sig == 12 || sig == 15)) {
			g_lxp_halt = 1;
			f->r[0] = 0; /* kill() succeeds; the run loop stops next iteration */
			return;
		}
		/* Self-signal (tkill/tgkill, or kill to own pid) is delivered inline. */
		if (nr != LXP_NR_kill || target == proc->pid) {
			deliver_signal(f, proc, sig, 0);
			return;
		}
		/* Cross-process kill (Phase D3): latch the signal on the target proc(s); it is
		 * delivered at the target's next syscall boundary (running) or by the coordinator
		 * (parked in sleep/wait/pipe). Real Linux targeting: pid>0 = that process; pid==0 =
		 * the caller's process group; pid<-1 = process group |pid|; pid==-1 = broadcast to
		 * all (but init). Skips the sender + init; an explicit self-signal took the inline
		 * path above. This is the fix for `kill %job` no longer nuking unrelated procs. */
		f->r[0] = -LXP_ESRCH;
		for (int t = 0; t < LXP_NSLOT; t++) {
			lxp_proc_t *tp = &g_lxp_proc[t];
			if (!tp->alive || tp == proc || tp->pid <= 1)
				continue;
			if (target > 0) {
				if (tp->pid != target)
					continue; /* a specific pid */
			} else if (target != -1) {
				if (tp->group->pgid != want_pgid)
					continue; /* a process group (the caller's, or |pid|) */
			}			  /* target == -1: broadcast to every live proc */
			tp->pending_sigs |= lxp_sig_bit(sig);
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
	 * to spawn a child. The parent is suspended (no thread) through the vfork window
	 * (NOMMU shares the image) until the child execs into its own region or exits. */
	if (nr == LXP_NR_vfork || nr == LXP_NR_fork || nr == LXP_NR_clone) {
		/* CLONE_VM shares the address space for life and therefore co-runs on
		 * the supplied child stack. CLONE_THREAD additionally joins the
		 * caller's thread group; legacy LinuxThreads-style CLONE_VM children
		 * remain distinct, waitable processes. */
		proc->clone_flags = nr == LXP_NR_clone ? (uint32_t)f->r[0] : 0;
		if (((proc->clone_flags & LXP_CLONE_SIGHAND) &&
		     !(proc->clone_flags & LXP_CLONE_VM)) ||
		    ((proc->clone_flags & LXP_CLONE_THREAD) &&
		     (proc->clone_flags & (LXP_CLONE_VM | LXP_CLONE_SIGHAND)) !=
			     (LXP_CLONE_VM | LXP_CLONE_SIGHAND))) {
			proc->clone_flags = 0;
			f->r[0] = -LXP_EINVAL;
			return;
		}
		if (proc->clone_flags & LXP_CLONE_VM) {
			proc->clone_child_stack = f->r[1];
		}
		proc->fork_pending = 1;
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
	/* nanosleep / blocking wait4: the syscall set the pending flag; capture the
	 * post-svc context (resume the SAME image after the svc) and park. The
	 * coordinator delays/wakes and resumes via spawn_resume(&g_ctx[slot], r0). */
	if (proc->sleep_pending || proc->wait_pending || proc->pipe_wait || proc->dev_wait ||
	    proc->sock_wait || proc->netfs_wait || proc->pty_wait || proc->sigsuspend_pending ||
	    proc->console_wait) {
		park_frame(f, proc);
		return;
	}
	if (proc->exited || proc->exec_pending) {
		park_frame(f, proc);
		return;
	}
	/* Cross-process signal (Phase D3): another proc's kill() latched a signal on us;
	 * deliver it at this syscall boundary (Linux at-the-boundary async delivery) unless the
	 * proc has blocked it (rt_sigprocmask) — a blocked signal stays latched and is delivered
	 * at a later boundary once unblocked. (The parked-thread and console-^C paths do not yet
	 * consult the mask; blocking those is uncommon.) */
	int psig = pending_deliverable(proc);
	if (psig) {
		proc->pending_sigs &= ~lxp_sig_bit(psig);
		deliver_signal(f, proc, psig, r);
		return;
	}
	/* A console ^C latched a signal during this syscall (e.g. a read): deliver
	 * it now, resuming the syscall with its result (-EINTR) — the Linux
	 * at-the-boundary async-delivery model. Deferred while the proc blocks it. */
	if (g_pending_sig && !lxp_sig_blocked(proc, g_pending_sig)) {
		int sig = g_pending_sig;
		g_pending_sig = 0;
		deliver_signal(f, proc, sig, r);
		return;
	}
	f->r[0] = (uint32_t)r;
}

/* ---- host task lifecycle --------------------------------------------------- */
static uint32_t slot_generation(int sidx)
{
	return __atomic_load_n(&g_slot_generation[sidx], __ATOMIC_RELAXED);
}

static void slot_transition_failed(int sidx, int transition, int rc)
{
	if (sidx < 0 || sidx >= LXP_NSLOT)
		return;
	lxp_proc_t *p = &g_lxp_proc[sidx];
	if (!p->alive)
		return;
	p->exit_status = 127;
	p->exit_reason = LXP_EXIT_REASON_HOST_TRANSITION;
	p->exit_signal = 0;
	p->exit_detail = ((uint32_t)(transition & 0xff) << 24) |
			 (uint32_t)(-rc & 0x00ffffff);
	p->exit_address = 0;
	p->exited = 1;
	primary_slot_mark(sidx);
}

static int coordinator_abort_slot(const lxp_os_ops_t *eng, int sidx)
{
	if (sidx < 0 || sidx >= LXP_NSLOT || !eng || !eng->abort_slot)
		return -LXP_EINVAL;
	uint8_t old = g_slot_lifecycle[sidx];
	g_slot_lifecycle[sidx] = SLOT_EXITING;
	int rc = eng->abort_slot(sidx, slot_generation(sidx));
	if (rc == LXP_OK) {
		g_slot_lifecycle[sidx] = SLOT_DEAD;
		g_lxp_used[sidx] = 0;
		return LXP_OK;
	}
	/* The callback contract says failure leaves the prior host state intact.
	 * Preserve its runnable view and retain all Linux resources until a later
	 * abort succeeds; releasing an mm under a live task would be unsafe. */
	g_slot_lifecycle[sidx] = SLOT_FAILED;
	g_lxp_used[sidx] = (old == SLOT_RUNNING);
	slot_transition_failed(sidx, SLOT_EXITING, rc);
	return rc;
}

static int coordinator_park_slot(const lxp_os_ops_t *eng, int sidx)
{
	if (sidx < 0 || sidx >= LXP_NSLOT || !eng || !eng->park_slot)
		return -LXP_EINVAL;
	if (g_slot_lifecycle[sidx] == SLOT_PARKED)
		return LXP_OK;
	if (g_slot_lifecycle[sidx] != SLOT_RUNNING) {
		slot_transition_failed(sidx, SLOT_PARKING, -LXP_EINVAL);
		return -LXP_EINVAL;
	}
	g_slot_lifecycle[sidx] = SLOT_PARKING;
	int rc = eng->park_slot(sidx, slot_generation(sidx));
	if (rc == LXP_OK) {
		g_slot_lifecycle[sidx] = SLOT_PARKED;
		g_lxp_used[sidx] = 0;
		return LXP_OK;
	}
	g_slot_lifecycle[sidx] = SLOT_RUNNING;
	g_lxp_used[sidx] = 1;
	/* The guest has already been redirected to lxp_park_loop. A failed suspend
	 * therefore cannot be rolled back into useful execution; synchronously
	 * terminate it and let the ordinary exit path release ownership. */
	(void)coordinator_abort_slot(eng, sidx);
	slot_transition_failed(sidx, SLOT_PARKING, rc);
	return rc;
}

static int coordinator_resume_slot(const lxp_os_ops_t *eng, int sidx, int ridx,
				   const struct lxp_resume_ctx *ctx, long r0val)
{
	if (sidx < 0 || sidx >= LXP_NSLOT || !eng || !eng->spawn_resume ||
	    !g_lxp_proc[sidx].alive || g_lxp_proc[sidx].exited)
		return -LXP_EINVAL;
	uint8_t old = g_slot_lifecycle[sidx];
	if (old != SLOT_PARKED && old != SLOT_FREE && old != SLOT_DEAD)
		return -LXP_EAGAIN;
	g_slot_lifecycle[sidx] = old == SLOT_PARKED ? SLOT_RESUMING : SLOT_STARTING;
	int rc = eng->spawn_resume(sidx, slot_generation(sidx), ridx, ctx, r0val);
	if (rc == LXP_OK) {
		g_slot_lifecycle[sidx] = SLOT_RUNNING;
		g_lxp_used[sidx] = 1;
		return LXP_OK;
	}
	g_slot_lifecycle[sidx] = old;
	g_lxp_used[sidx] = 0;
	/* A failed persistent resume leaves the old task parked; a failed initial
	 * resume leaves no task. abort_slot is idempotent in both cases. */
	(void)coordinator_abort_slot(eng, sidx);
	slot_transition_failed(sidx, SLOT_RESUMING, rc);
	return rc;
}

static int coordinator_launch_slot(const lxp_os_ops_t *eng, int sidx, int ridx,
				   const lxp_flat_t *prog, void *entry, void *sp,
				   void *stack_lo)
{
	if (sidx < 0 || sidx >= LXP_NSLOT || !eng || !eng->spawn_launch)
		return -LXP_EINVAL;
	if (g_slot_lifecycle[sidx] != SLOT_FREE &&
	    g_slot_lifecycle[sidx] != SLOT_DEAD)
		return -LXP_EAGAIN;
	g_slot_lifecycle[sidx] = SLOT_STARTING;
	int rc = eng->spawn_launch(sidx, slot_generation(sidx), ridx, prog, entry, sp,
				   stack_lo);
	if (rc == LXP_OK) {
		g_slot_lifecycle[sidx] = SLOT_RUNNING;
		g_lxp_used[sidx] = 1;
		return LXP_OK;
	}
	g_slot_lifecycle[sidx] = SLOT_DEAD;
	g_lxp_used[sidx] = 0;
	slot_transition_failed(sidx, SLOT_STARTING, rc);
	return rc;
}

/* ---- the run loop ---------------------------------------------------------- */
/* Load an FDPIC ELF into region ridx + set up slot sidx's proc, then spawn it. @p remote_exec:
 * the image is a RAM staging buffer (a program off the remote mount), so the exec's own text is
 * copied into the region and the region is mapped executable (RWX) — gated by the caller. */
static int launch(const lxp_os_ops_t *eng, int sidx, int ridx, const uint8_t *data,
		  size_t len, int pid, int ppid, int argc, const char *const argv[],
		  const char *const envp[], int remote_exec)
{
	uint8_t *region = eng->region(ridx);
	lxp_flat_t prog;
	/* Every personality program is an FDPIC ELF (0x7f'ELF', ELFOSABI_ARM_FDPIC); reject
	 * anything else. spawn_launch reads prog.is_fdpic / prog.got to put the GOT base in r9. */
	if (!(len >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'))
		return -1;
	/* The loader reads the FDPIC ELF from `data` — on the STM32F746 that points into the
	 * QUADSPI-mapped NOR (0x90000000).  Correctness of that read is a memory-attribute concern,
	 * not a timing one: the coordinator reads the NOR through a bounded, non-cacheable MPU region
	 * (os_ops->rootfs_window), so no D-cache burst or speculative prefetch can garble it and a
	 * context switch mid-load is harmless.  No preemption masking needed. */
	int lrc = lxp_loader_load_fdpic(&prog, data, len, region, LXP_PROG_REGION_SIZE, 0,
					remote_exec);
	if (lrc != LXP_OK)
		return -1;

	/* FDPIC dynamic exec (DT_NEEDED): load the interpreter ld.so just past the exec in the
	 * region, build its loadmap, and enter IT (not the program) — r7 = the exec loadmap,
	 * r8 = ld.so's loadmap, r9 = ld.so's GOT, AT_ENTRY = the program's own entry, AT_BASE =
	 * ld.so's base. ld.so then loads the .so deps, relocates, and jumps to the program. */
	uintptr_t pc = prog.entry;	 /* what the seam jumps to (ld.so for a dynamic exec) */
	uintptr_t at_entry = prog.entry; /* AT_ENTRY = the program's own entry, always */
	uintptr_t at_base = 0;		 /* AT_BASE = ld.so base (0 when static) */
	prog.interp_loadmap = 0;
	int dynamic = prog.is_fdpic && prog.is_dynamic;
	if (dynamic) {
		const uint8_t *ld_data = NULL;
		size_t ld_len = 0;
		if (lxp_rootfs_resolve(g_cfg->rootfs, g_cfg->rootfs_count,
					   "/lib/ld-uClibc.so.0", &ld_data, &ld_len) != 0 ||
		    !ld_data)
			return -1; /* no interpreter in the rootfs */
		uintptr_t ld_base = (uintptr_t)region + ((prog.region_used + 15u) & ~15u);
		lxp_flat_t ld;
		int ldrc = lxp_loader_load_fdpic(&ld, ld_data, ld_len, (void *)ld_base,
						 LXP_PROG_REGION_SIZE -
							 (size_t)(ld_base - (uintptr_t)region),
						 1, 0); /* ld.so text is XIP from the rootfs (no copy) */
		if (ldrc != LXP_OK)
			return -1;
		pc = ld.entry;
		/* AT_BASE = ld.so's ELF header, which ld.so reads at _dl_start (dl-startup.c). With the
		 * text shared IN-PLACE, that header is in the cpio (ld.text_base), NOT at ld_base — which
		 * now holds only ld.so's RW block. (Pre-sharing, text+data were contiguous at ld_base, so
		 * the old `at_base = ld_base` happened to coincide with the header.) */
		at_base = ld.text_base;
		prog.interp_loadmap = ld.loadmap; /* r8 */
		/* r9 = ld.so's _DYNAMIC, NOT its GOT: uClibc-ng's FDPIC DL_BOOT_COMPUTE_DYN sets
		 * the dynamic-table ptr = dl_boot_ldso_dyn_pointer = the entry r9. (The working
		 * GOT is derived by __self_reloc.) Passing the GOT/base here mis-parses ld.so's
		 * dynamic → its RELATIVE relocs target wrong → _dl_malloc derefs an unrelocated
		 * GOT entry. */
		prog.got = ld.dynamic;
		prog.region_used = (size_t)(ld_base - (uintptr_t)region) + ld.region_used;
	}

	uint8_t *rw = region + ((prog.region_used + 15u) & ~15u);
	uint8_t *rw_end = region + LXP_PROG_REGION_SIZE;
	/* A dynamic proc's arena lives in the engine's PSRAM dyn_pool (ld.so mmaps libc.so
	 * ~500K from it); a static FDPIC proc uses the in-region 96K arena. The stack always sits
	 * in-region above the loaded image(s). */
	uint8_t *arena_mem = rw;
	size_t arena_sz = LXP_PROG_ARENA_SIZE;
	uint8_t *stack_lo = rw + LXP_PROG_ARENA_SIZE;
	if (dynamic) {
		if (!eng->dyn_pool)
			return -1; /* this engine has no room to host a dynamic proc */
		arena_mem = eng->dyn_pool(ridx, &arena_sz);
		stack_lo = rw; /* the region tail is the stack; the arena is in PSRAM */
	}
	if (lxp_arena_init(&g_arenas[ridx], arena_mem, arena_sz) != LXP_OK ||
	    lxp_proc_init(&g_lxp_proc[sidx], &g_arenas[ridx], 0x8000) != LXP_OK)
		return -1;
	lxp_proc_bind_exec_capture(&g_lxp_proc[sidx], eng->exec_capture(sidx));
	/* A fresh image has no handler return chain from the previous slot owner.
	 * execve likewise discards the old image's in-flight signal contexts. */
	g_sig_save[sidx].depth = 0;
	g_lxp_proc[sidx].write_fn = g_cfg->write_fn;
	g_lxp_proc[sidx].read_fn = g_cfg->read_fn;
	g_lxp_proc[sidx].console_poll = g_cfg->console_poll;
	g_lxp_proc[sidx].io_ctx = g_cfg->io_ctx;
	g_lxp_proc[sidx].pid = pid;
	g_lxp_proc[sidx].group->tgid = pid;
	g_lxp_proc[sidx].group->ppid = ppid;
	g_lxp_proc[sidx].group->pgid = pid; /* a fresh proc leads its own group; the child constructor inherits pgid, and execve restores it below */
	/* Concurrent model: this slot is now a live process owning region ridx. */
	g_lxp_proc[sidx].alive = 1;
	g_lxp_proc[sidx].mm->region = ridx;
	/* access_ok bounds: this proc's own writable memory (image region + dynamic arena). The syscall
	 * layer rejects any user pointer outside these (+ the shared RO rootfs for reads). */
	g_lxp_proc[sidx].mm->region_lo = (uintptr_t)region;
	g_lxp_proc[sidx].mm->region_hi = (uintptr_t)region + LXP_PROG_REGION_SIZE;
	g_lxp_proc[sidx].mm->pool_lo = (uintptr_t)arena_mem;
	g_lxp_proc[sidx].mm->pool_hi = (uintptr_t)arena_mem + arena_sz;
	g_lxp_proc[sidx].is_fdpic = prog.is_fdpic;
	g_lxp_proc[sidx].mm->is_dynamic = dynamic; /* arena/libc RW data lives in the dyn_pool */
	g_lxp_proc[sidx].stack_lo = (uintptr_t)stack_lo; /* writable-data / stack boundary (snapshot) */
	g_lxp_proc[sidx].snap_region = -1;		     /* no vfork snapshot outstanding */
	g_lxp_proc[sidx].vfork_parent_slot = -1;
	/* comm = argv[0] basename (strip the login-shell leading '-') for ps/top. */
	{
		const char *a0 = (argc > 0 && argv && argv[0]) ? argv[0] : "?";
		if (a0[0] == '-')
			a0++;
		const char *base = a0;
		for (const char *s = a0; *s; s++)
			if (*s == '/')
				base = s + 1;
		size_t cl = strlen(base);
		if (cl >= sizeof(g_lxp_proc[sidx].comm))
			cl = sizeof(g_lxp_proc[sidx].comm) - 1;
		memcpy(g_lxp_proc[sidx].comm, base, cl);
		g_lxp_proc[sidx].comm[cl] = '\0';
	}
	lxp_proc_set_rootfs(&g_lxp_proc[sidx], g_cfg->rootfs, g_cfg->rootfs_count);
	void *sp = lxp_setup_stack(stack_lo, (size_t)(rw_end - stack_lo), argc, argv, envp,
				       prog.is_fdpic, prog.phdr, prog.phnum, at_entry, at_base);
	if (!sp)
		return -1;
	/* Publish the program's runtime segment bases for the GDB source-level-debug helper. */
	g_lxp_dbg[sidx].text_base = prog.text_base;
	g_lxp_dbg[sidx].data_base = prog.data_base;
	g_lxp_dbg[sidx].entry = at_entry;
	g_lxp_dbg[sidx].dynamic = prog.dynamic; /* _DYNAMIC → DT_DEBUG → ld.so's link-map chain */
	g_lxp_dbg[sidx].interp_base = at_base;   /* ld.so text base (0 if static) */
	/* P3: a fresh image in this slot inherits no device mmap. Clear the dev_map ranges
	 * (they gate user_ok) and tear down any framebuffer region a prior occupant of this
	 * slot installed (map_device with size 0), so an exec/relaunch never leaks it. */
	g_lxp_proc[sidx].mm->dev_map_lo[0] = g_lxp_proc[sidx].mm->dev_map_hi[0] = 0;
	g_lxp_proc[sidx].mm->dev_map_lo[1] = g_lxp_proc[sidx].mm->dev_map_hi[1] = 0;
	if (eng->map_device)
		eng->map_device(sidx, 0, 0, 0);
	return coordinator_launch_slot(eng, sidx, ridx, &prog, (void *)pc, sp,
				       stack_lo);
}

/* Select one of the two device ranges represented in lxp_proc_t without
 * changing it. The backend map is installed first; only a successful host
 * transition commits the matching access_ok range below. */
static int device_map_index(const lxp_proc_t *p, uintptr_t addr, size_t len)
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

/* The logical mappings live in an mm object, while the hardware MPU entries
 * live in each engine task. Rebuild one slot from its mm after fork, rollback,
 * task replacement, or resume. A clear request (size == 0) removes every
 * device entry owned by the slot. */
static int coordinator_restore_mm_maps(const lxp_os_ops_t *eng, int sidx,
				       const lxp_mm_t *mm)
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
		if (eng->map_device(sidx, mm->dev_map_lo[i],
				    mm->dev_map_hi[i] - mm->dev_map_lo[i],
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
static int coordinator_map_mm_range(const lxp_os_ops_t *eng, lxp_mm_t *mm,
				    uintptr_t addr, size_t len, unsigned attrs)
{
	if (!eng->map_device)
		return -LXP_ENODEV;
	for (int s = 0; s < LXP_NSLOT; s++) {
		if (!g_lxp_proc[s].alive || g_lxp_proc[s].mm != mm)
			continue;
		if (eng->map_device(s, addr, len, attrs) != 0) {
			for (int r = 0; r < LXP_NSLOT; r++)
				if (g_lxp_proc[r].alive && g_lxp_proc[r].mm == mm)
					(void)coordinator_restore_mm_maps(eng, r, mm);
			return -LXP_ENOMEM;
		}
	}
	return 0;
}
#endif

/* A child (cpid, status) exited: hand it to its parent (ppid). Wake a parent blocked
 * in wait4 (resume returning cpid + write *status), else queue the zombie for a later
 * wait4. Decrements the parent's live-children count either way. */
static lxp_proc_t *parent_task_for_child(int ppid, int cpid, int stopped)
{
	lxp_proc_t *fallback = NULL;
	for (int t = 0; t < LXP_NSLOT; t++) {
		lxp_proc_t *p = &g_lxp_proc[t];
		if (!p->alive || !p->group || p->group->tgid != ppid)
			continue;
		if (!fallback)
			fallback = p;
		if (p->wait_pending && (p->wait_pid <= 0 || p->wait_pid == cpid) &&
		    (!stopped || (p->wait_options & LXP_WUNTRACED)))
			return p;
	}
	return fallback;
}

static void reap_to_parent(const lxp_os_ops_t *eng, int ppid, int cpid, int status, int sigchld)
{
	lxp_proc_t *par = parent_task_for_child(ppid, cpid, 0);
	if (!par)
		return;
	int pslot = slot_of(par);
	if (par->group->live_children > 0)
		par->group->live_children--;
	if (par->wait_pending && (par->wait_pid <= 0 || par->wait_pid == cpid)) {
		if (par->wait_status_p) {
			/* Encode the wait status the way Linux does: a signal-killed child (our exit_status
			 * convention is 128 + signal) becomes WIFSIGNALED — low 7 bits = the signal — so the
			 * shell prints "Terminated"/"Killed", not "Done"; a normal exit stays WIFEXITED with
			 * the code in bits 8-15. (1..31 covers every signal we deliver.) */
						*(int *)(uintptr_t)par->wait_status_p = lxp_encode_wstatus(status);
		}
		par->wait_pending = 0;
		coordinator_park_slot(eng, pslot);
		coordinator_resume_slot(eng, pslot, par->mm->region, &g_ctx[pslot], cpid);
	} else {
		/* The parent is not blocking in wait4 (typically sitting in select()/poll() —
		 * busybox inetd's accept loop, dropbear's session relay). Queue the zombie for a
		 * later wait4 and raise SIGCHLD: the parent's handler runs, wait4()s the zombie, and
		 * closes the session / reaps the connection. Default action is IGNORE, so a parent
		 * without a handler is unaffected. Coalesce onto a free pending slot (as SIGALRM). */
		if (par->group->child_count < LXP_MAX_CHILD) {
			par->group->child_pid[par->group->child_count] = cpid;
			par->group->child_status[par->group->child_count] = status;
			par->group->child_kind[par->group->child_count] = LXP_CHILD_EXITED;
			par->group->child_count++;
		}
		/* A vfork parent was just resumed (vfork returned the child pid) and will wait4() the
		 * queued zombie immediately; raising SIGCHLD here would interrupt that wait4 (-EINTR)
		 * before it reaps, so the shell prints "waitpid: Interrupted" and loses the exit code.
		 * Only signal a parent that is NOT synchronously reaping (a daemon in select/poll). */
		if (sigchld)
			par->pending_sigs |= lxp_sig_bit(LXP_SIGCHLD);
	}
}

/* A child (cpid) just STOPPED for job control (stopsig). Notify its parent (ppid) the
 * way reap_to_parent does for an exit — resume a wait4 that accepts stops (WUNTRACED)
 * with a WIFSTOPPED status, else queue a stop notice + raise SIGCHLD — but WITHOUT
 * decrementing live_children: a stopped child is still alive, only its state changed. */
static void notify_parent_stopped(const lxp_os_ops_t *eng, int ppid, int cpid, int stopsig)
{
	lxp_proc_t *par = parent_task_for_child(ppid, cpid, 1);
	if (!par)
		return;
	int pslot = slot_of(par);
	if (par->wait_pending && (par->wait_options & LXP_WUNTRACED) &&
	    (par->wait_pid <= 0 || par->wait_pid == cpid)) {
		if (par->wait_status_p)
			*(int *)(uintptr_t)par->wait_status_p = lxp_encode_wstopped(stopsig);
		par->wait_pending = 0;
		coordinator_park_slot(eng, pslot);
		coordinator_resume_slot(eng, pslot, par->mm->region, &g_ctx[pslot], cpid);
	} else {
		if (par->group->child_count < LXP_MAX_CHILD) {
			par->group->child_pid[par->group->child_count] = cpid;
			par->group->child_status[par->group->child_count] = stopsig;
			par->group->child_kind[par->group->child_count] = LXP_CHILD_STOPPED;
			par->group->child_count++;
		}
		par->pending_sigs |= lxp_sig_bit(LXP_SIGCHLD);
	}
}

/* Report a stable snapshot before LXP_EV_EXIT clears/reuses the process slot. The
 * callback is deliberately outside exception context; an embedded host may log
 * it, increment retained counters, or leave it unset for zero runtime cost. */
static void notify_guest_exit(int slot, const lxp_proc_t *proc)
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
	g_cfg->on_guest_exit(&info);
}

/* A parent's live children and queued zombies share one bounded accounting
 * budget. This prevents a later child status from being silently dropped. */
static int fork_capacity_available(const lxp_proc_t *proc)
{
	if (!proc || !proc->group)
		return 0;
	return proc->group->child_count >= 0 &&
	       proc->group->child_count < LXP_MAX_CHILD &&
	       proc->group->live_children >= 0 &&
	       proc->group->live_children <
		       LXP_MAX_CHILD - proc->group->child_count;
}

static int thread_group_live_count(const lxp_thread_group_t *group)
{
	int live = 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (g_lxp_proc[s].alive && g_lxp_proc[s].group == group)
			live++;
	return live;
}

static void thread_group_request_exit(int source_slot, int status)
{
	if (source_slot < 0 || source_slot >= LXP_NSLOT)
		return;
	lxp_thread_group_t *group = g_lxp_proc[source_slot].group;
	if (!group)
		return;
	group->exiting = 1;
	group->exit_status = status & 0xff;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_proc[s];
		if (!p->alive || p->group != group)
			continue;
		p->exit_status = status & 0xff;
		p->exit_reason = LXP_EXIT_REASON_NORMAL;
		p->exit_signal = 0;
		p->exit_detail = 0;
		p->exit_address = 0;
		p->exit_group = 1;
		p->exited = 1;
		primary_slot_mark(s);
	}
}

/* execve replaces the entire process image. Once the coordinator reaches the
 * commit point, peer threads may no longer execute in the old shared address
 * space. Stop their host tasks immediately; their normal EV_EXIT teardown
 * releases per-task references on subsequent coordinator passes. */
static int thread_group_stop_exec_peers(const lxp_os_ops_t *eng, int source_slot,
					int failure_status)
{
	lxp_thread_group_t *group = g_lxp_proc[source_slot].group;
	int rc = LXP_OK;
	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_proc[s];
		if (s == source_slot || !p->alive || p->group != group)
			continue;
		if (coordinator_abort_slot(eng, s) != LXP_OK)
			rc = -LXP_EAGAIN;
		p->exit_status = failure_status & 0xff;
		p->exit_reason = LXP_EXIT_REASON_NORMAL;
		p->exit_signal = 0;
		p->exit_group = 0;
		p->exited = 1;
		primary_slot_mark(s);
	}
	return rc;
}

/* Deliver `sig` to a proc PARKED in rt_sigsuspend (the LinuxThreads restart). There is no live
 * frame — the interrupted context is the captured g_ctx[slot]. Save that as the slot's sigreturn
 * frame (to resume with `ret` = -EINTR), then resume the proc INTO its handler; the handler's
 * sa_restorer -> rt_sigreturn restores the saved frame and the syscall returns -EINTR. SIG_IGN
 * just resumes with `ret`; SIG_DFL terminates (the LXP_EV_EXIT pass reaps it). */
static void deliver_signal_parked(const lxp_os_ops_t *eng, int slot,
				  lxp_proc_t *proc, int sig, long ret)
{
	uintptr_t h = lxp_sig_handler_get(proc, sig);
	if (h == LXP_SIG_IGN || (h == LXP_SIG_DFL && sig_default_ignore(sig))) {
		coordinator_resume_slot(eng, slot, proc->mm->region, &g_ctx[slot], ret); /* IGN or default-ignore (SIGCHLD/SIGCONT/...) */
		return;
	}
	/* A job-control stop must never terminate the proc here. The coordinator's
	 * parked-stop scan normally consumes it first; if one slips through (a deferred
	 * completion carrying a pending stop), re-latch it and resume the syscall so the
	 * scan stops the proc on the next pass. */
	if (sig_stops_proc(proc, sig)) {
		proc->pending_sigs |= lxp_sig_bit(sig);
		coordinator_resume_slot(eng, slot, proc->mm->region, &g_ctx[slot], ret);
		return;
	}
	if (h == LXP_SIG_DFL) {
		proc->exited = 1;
		proc->exit_status = 128 + sig;
		proc->exit_reason = LXP_EXIT_REASON_SIGNAL;
		proc->exit_signal = (uint8_t)sig;
		primary_slot_mark(slot);
		return;
	}
	struct sig_save_s *sv = sig_save_push(proc, sig);
	if (!sv) {
		/* Bounded signal state is exhausted. Never overwrite an older return
		 * context: terminate only this already-parked guest. */
		proc->exited = 1;
		proc->exit_status = 128 + LXP_SIGSEGV;
		proc->exit_reason = LXP_EXIT_REASON_SIGNAL_DEPTH;
		proc->exit_signal = LXP_SIGSEGV;
		primary_slot_mark(slot);
		return;
	}
	sv->r0 = (uint32_t)ret;
	sv->r1 = g_ctx[slot].r1;
	sv->r2 = g_ctx[slot].r2;
	sv->r3 = g_ctx[slot].r3;
	sv->r9 = g_ctx[slot].r4_11[5]; /* FDPIC GOT of the parked code — clobbered below (r4_11[5]=r9) */
	sv->r12 = g_ctx[slot].r12;
	sv->lr = g_ctx[slot].lr;
	sv->pc = g_ctx[slot].pc; /* the rt_sigsuspend resume point */
	sv->xpsr = g_ctx[slot].xpsr | (1u << 24); /* preserve APSR flags + Thumb */
#if LXP_ENABLE_FPU_CONTEXT
	sv->fp = g_ctx[slot].fp;
#endif
	/* Reuse the slot ctx as the handler-entry frame; sp + r4-r11 stay = the thread's, except r9
	 * (the handler's own GOT for FDPIC — resolve_handler derefs the {entry,GOT} funcdescs; the
	 * restart handler lives in libpthread, a different module than the interrupted libc). */
	uintptr_t entry, restorer;
	uint32_t got;
	resolve_handler(proc, sig, &entry, &got, &restorer);
	if (proc->is_fdpic)
		g_ctx[slot].r4_11[5] = got;	    /* r9 = handler's GOT */
	g_ctx[slot].lr = restorer | 1u;		    /* return -> sa_restorer entry -> sigreturn */
	g_ctx[slot].pc = entry | 1u;		    /* enter the handler (Thumb) */
	coordinator_resume_slot(eng, slot, proc->mm->region, &g_ctx[slot], sig); /* r0 = signo */
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
	if (user_ok(proc, ut, sizeof(lxp_termios), 0)) {
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

/* Execute one READY mailbox in privileged task context. The lower-priority guest
 * is suspended before its host syscall runs; immediate completion resumes that
 * same task, while a blocking syscall leaves it parked for the established wait
 * event. Host RT tasks above the coordinator can preempt all work performed here. */
static void execute_deferred(const lxp_os_ops_t *eng, int slot)
{
	uint8_t expected = DEFER_READY;
	if (!__atomic_compare_exchange_n(&g_deferred[slot].state, &expected, DEFER_RUNNING, 0,
					 __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return;
	struct deferred_req *req = &g_deferred[slot];
	lxp_proc_t *proc = &g_lxp_proc[slot];
	uint32_t generation = __atomic_load_n(&g_slot_generation[slot], __ATOMIC_RELAXED);
	if (!proc->alive || req->generation != generation) {
		deferred_state_store(slot, DEFER_IDLE);
		return;
	}
	if (coordinator_park_slot(eng, slot) != LXP_OK) {
		deferred_state_store(slot, DEFER_IDLE);
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
	long nr = (long)(int32_t)g_ctx[slot].r4_11[3]; /* captured r7 */
	long a0 = (long)(int32_t)req->a0;
	long a1 = (long)(int32_t)g_ctx[slot].r1;
	long a2 = (long)(int32_t)g_ctx[slot].r2;
	long a3 = (long)(int32_t)g_ctx[slot].r3;
	long a4 = (long)(int32_t)g_ctx[slot].r4_11[0];
	long a5 = (long)(int32_t)g_ctx[slot].r4_11[1];
	deferred_track_tty(proc, nr, a0, a1, a2);
	long r = lxp_syscall(proc, nr, a0, a1, a2, a3, a4, a5);
	if (r == -LXP_ENOSYS && g_cfg && g_cfg->on_enosys && nr != 141 && nr != 281)
		g_cfg->on_enosys(nr);
	deferred_state_store(slot, DEFER_IDLE);

	/* Existing retry state owns completion from here and expects the parked host
	 * task to remain present; exec/exit are likewise consumed by higher-level events. The
	 * deferred event hint was consumed before entering this function, so publish
	 * the follow-on state before returning to the coordinator wait loop. */
	if (proc->sleep_pending || proc->wait_pending || proc->pipe_wait || proc->dev_wait ||
	    proc->sock_wait || proc->netfs_wait || proc->pty_wait || proc->sigsuspend_pending ||
	    proc->console_wait || proc->exited || proc->exec_pending) {
		primary_slot_mark(slot);
		return;
	}

	int psig = pending_deliverable(proc);
	if (psig) {
		proc->pending_sigs &= ~lxp_sig_bit(psig);
		deliver_signal_parked(eng, slot, proc, psig, r);
		return;
	}
	if (g_pending_sig && !lxp_sig_blocked(proc, g_pending_sig)) {
		int sig = g_pending_sig;
		g_pending_sig = 0;
		deliver_signal_parked(eng, slot, proc, sig, r);
		return;
	}
	coordinator_resume_slot(eng, slot, proc->mm->region, &g_ctx[slot], r);
}

/* ---- vfork data isolation (NOMMU) ------------------------------------------ */
/* A region may be reused as vfork snapshot scratch (which then becomes the child's exec image) or as
 * a fresh exec region ONLY if no live process occupies it. rowner[r] tracks the region's *owner*, but
 * that table is the sole liveness signal the pickers below consult, and under deep vfork nesting (a
 * pipeline over an SSH session: init+getty+inetd+dropbear+shell+members) accounting drift can leave a
 * live daemon's region reading rowner<0 — reusing it then memcpy's a foreign image straight over that
 * daemon's live libc data (the inetd flap: init's snapshot trampling inetd's __pthread thread block →
 * a garbage descriptor → p_errnop=0xffffffff → DACCVIOL). So gate every region pick on BOTH the owner
 * table, the shared-mm refcount, AND actual task liveness. In the consistent state
 * a referenced region always has rowner>=0, so the latter checks are redundant
 * and never refuse a genuinely-free region — they only refuse to trample a live
 * one (worst case a clean -ENOMEM fork refusal instead of a corruption). */
static int region_free(int r, const int *rowner)
{
	if (rowner[r] >= 0 || g_region_refs[r] != 0)
		return 0;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (g_lxp_proc[s].alive && g_lxp_proc[s].mm &&
		    g_lxp_proc[s].mm->region == r)
			return 0; /* a live proc runs here despite rowner<0 — do not trample it */
	return 1;
}

static uint32_t region_generation_next(int r)
{
	uint32_t next = ++g_region_generation[r];
	if (next == 0) /* reserve zero for never-assigned test/startup state */
		next = ++g_region_generation[r];
	return next;
}

static uint32_t region_reserve(int r, int slot)
{
	if (r < 0 || r >= LXP_NREG || g_region_refs[r] != 0)
		return 0;
	g_region_owner[r] = slot;
	g_region_refs[r] = 1;
	return region_generation_next(r);
}

static int region_get(int r)
{
	if (r < 0 || r >= LXP_NREG || g_region_owner[r] < 0 ||
	    g_region_refs[r] == 0 || g_region_refs[r] >= LXP_NSLOT)
		return -1;
	g_region_refs[r]++;
	return 0;
}

static void region_put(int r)
{
	if (r < 0 || r >= LXP_NREG || g_region_refs[r] == 0)
		return;
	if (--g_region_refs[r] == 0) {
		g_region_owner[r] = -1;
		(void)region_generation_next(r);
	}
}

static void proc_mm_put(lxp_proc_t *p)
{
	if (!p || !p->mm)
		return;
	region_put(p->mm->region);
	lxp_proc_mm_put(p);
}

static void region_release_if_owned(int r, int slot)
{
	if (r >= 0 && r < LXP_NREG && g_region_owner[r] == slot &&
	    g_region_refs[r] == 1)
		region_put(r);
}

/* Stop every host task before releasing resource objects: descriptor close
 * hooks and request cancellation touch state a live guest could otherwise
 * still mutate. This is the common path for normal completion, halt, timeout
 * and launch failure, so a later lxp_run() never inherits the prior run. */
static void coordinator_teardown_all(const lxp_os_ops_t *eng)
{
	for (int s = 0; s < LXP_NSLOT; s++)
		coordinator_abort_slot(eng, s);

	for (int s = 0; s < LXP_NSLOT; s++) {
		lxp_proc_t *p = &g_lxp_proc[s];
		deferred_slot_reassign(s);
		primary_slot_clear(s);
#if LXP_ENABLE_NETFS
		if (p->netfs_req >= 0)
			lxp_netfs_cancel(p);
#endif
		lxp_proc_resources_put(p);
		if (eng->map_device)
			eng->map_device(s, 0, 0, 0);
		if (p->mm) {
			p->mm->dev_map_lo[0] = p->mm->dev_map_hi[0] = 0;
			p->mm->dev_map_lo[1] = p->mm->dev_map_hi[1] = 0;
		}
		if (p->snap_region >= 0)
			region_release_if_owned(p->snap_region, s);
		proc_mm_put(p);
		lxp_proc_group_put(p);
		g_sig_save[s].depth = 0;
		g_lxp_used[s] = 0;
		memset(p, 0, sizeof(*p));
		p->snap_region = -1;
		p->vfork_parent_slot = -1;
		p->netfs_req = -1;
	}

	/* Contain inconsistent ownership metadata as well as the ordinary
	 * reference-balanced case above. No guest survives this boundary. */
	memset(g_region_refs, 0, sizeof(g_region_refs));
	for (int r = 0; r < LXP_NREG; r++)
		g_region_owner[r] = -1;
	memset(g_vfork_guard, 0, sizeof(g_vfork_guard));
	for (int s = 0; s < LXP_NSLOT; s++)
		g_vfork_guard[s].parent_slot = g_vfork_guard[s].parent_region =
			g_vfork_guard[s].snapshot_region = -1;
	memset(g_diag_native_present, 0, sizeof(g_diag_native_present));
	g_diag_native_known = eng->thread_list != NULL;
	lxp_fd_runtime_reset();
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
 * Returns the reserved scratch region index, or -1 if the parent cannot be isolated. */
static int vfork_snapshot(const lxp_os_ops_t *eng, lxp_proc_t *par, int child_slot,
			  uintptr_t sp)
{
	int parent_slot = slot_of(par);
	if (parent_slot < 0 || child_slot < 0 || child_slot >= LXP_NSLOT || !par->alive ||
	    !par->mm ||
	    par->mm->region < 0 || par->mm->region >= LXP_NREG)
		return -1;
	int rsnap = -1;
	for (int r = 0; r < LXP_NREG; r++)
		if (region_free(r, g_region_owner)) {
			rsnap = r;
			break;
		}
	if (rsnap < 0)
		return -1; /* the caller must fail the fork rather than share without isolation */
	uint8_t *pr = eng->region(par->mm->region);
	size_t dlen = par->stack_lo - (uintptr_t)pr; /* in-region writable data, below the stack */
	uint8_t *sr = eng->region(rsnap);
	if (sp < par->stack_lo || sp > par->mm->region_hi)
		return -1; /* corrupt/unavailable capture: do not resume an unisolated parent */
	snapshot_copy_span(sr, pr, dlen);
	size_t slen = par->mm->region_hi - sp;
	snapshot_copy_span(sr + (sp - (uintptr_t)pr), (const void *)sp, slen);
	if (par->mm->is_dynamic && eng->dyn_pool) {
		size_t ds = 0;
		uint8_t *pdp = eng->dyn_pool(par->mm->region, &ds);
		uint8_t *sdp = eng->dyn_pool(rsnap, NULL);
		snapshot_copy_span(sdp, pdp, ds);
	}
	g_snap_arena[child_slot] = g_arenas[par->mm->region]; /* allocator metadata (coordinator memory) */
	struct vfork_snapshot_guard *guard = &g_vfork_guard[child_slot];
	guard->parent_slot = parent_slot;
	guard->parent_slot_generation = g_slot_generation[parent_slot];
	guard->parent_region = par->mm->region;
	guard->parent_region_generation = g_region_generation[par->mm->region];
	guard->snapshot_region = rsnap;
	guard->snapshot_region_generation = region_reserve(rsnap, child_slot);
	return rsnap;
}

/* Undo a vfork child's writes to the shared region before the parent resumes: copy the snapshot back
 * over the parent's region + dyn_pool and restore its arena metadata. Every identity is checked
 * before the first write; failure leaves memory untouched so the caller can contain both processes. */
static int vfork_restore(const lxp_os_ops_t *eng, lxp_proc_t *par, int rsnap,
			 int child_slot, uintptr_t sp)
{
	if (child_slot < 0 || child_slot >= LXP_NSLOT)
		return -1;
	struct vfork_snapshot_guard *guard = &g_vfork_guard[child_slot];
	int parent_slot = slot_of(par);
	if (parent_slot < 0 || !par->alive || !par->mm ||
	    par->mm->region < 0 || par->mm->region >= LXP_NREG ||
	    parent_slot != guard->parent_slot ||
	    g_slot_generation[parent_slot] != guard->parent_slot_generation ||
	    par->mm->region != guard->parent_region ||
	    g_region_generation[par->mm->region] != guard->parent_region_generation ||
	    rsnap != guard->snapshot_region || rsnap < 0 || rsnap >= LXP_NREG ||
	    g_region_owner[rsnap] != child_slot ||
	    g_region_refs[rsnap] != 1 ||
	    g_region_generation[rsnap] != guard->snapshot_region_generation)
		return -1;
	uint8_t *pr = eng->region(par->mm->region);
	size_t dlen = par->stack_lo - (uintptr_t)pr;
	uint8_t *sr = eng->region(rsnap);
	restore_copy_span(pr, sr, dlen);
	if (sp >= par->stack_lo && sp <= par->mm->region_hi) {
		size_t slen = par->mm->region_hi - sp;
		restore_copy_span((void *)sp, sr + (sp - (uintptr_t)pr), slen);
	}
	if (par->mm->is_dynamic && eng->dyn_pool) {
		size_t ds = 0;
		uint8_t *pdp = eng->dyn_pool(par->mm->region, &ds);
		restore_copy_span(pdp, eng->dyn_pool(rsnap, NULL), ds);
	}
	g_arenas[par->mm->region] = g_snap_arena[child_slot];
	memset(guard, 0, sizeof(*guard));
	guard->parent_slot = guard->parent_region = guard->snapshot_region = -1;
	return 0;
}

static int vfork_parent_is_current(int child_slot)
{
	const struct vfork_snapshot_guard *guard = &g_vfork_guard[child_slot];
	int ps = guard->parent_slot;
	return ps >= 0 && ps < LXP_NSLOT && g_lxp_proc[ps].alive &&
	       g_lxp_proc[ps].mm &&
	       g_slot_generation[ps] == guard->parent_slot_generation &&
	       g_lxp_proc[ps].mm->region == guard->parent_region;
}

/* A stale snapshot is an internal ownership violation, not a recoverable guest
 * error. Never copy it. Terminate a still-current suspended parent (its shared
 * image may already be dirty), fail the child, and release only a reservation
 * that is still demonstrably ours. */
static void vfork_contain_stale(int child_slot, lxp_proc_t *child)
{
	struct vfork_snapshot_guard *guard = &g_vfork_guard[child_slot];
	if (vfork_parent_is_current(child_slot)) {
		lxp_proc_t *par = &g_lxp_proc[guard->parent_slot];
		par->exit_status = 127;
		par->exit_reason = LXP_EXIT_REASON_STATE_CORRUPTION;
		par->exit_signal = 0;
		par->exited = 1;
		primary_slot_mark(guard->parent_slot);
	}
	if (guard->snapshot_region >= 0 && guard->snapshot_region < LXP_NREG &&
	    g_region_owner[guard->snapshot_region] == child_slot &&
	    g_region_generation[guard->snapshot_region] == guard->snapshot_region_generation)
		region_release_if_owned(guard->snapshot_region, child_slot);
	memset(guard, 0, sizeof(*guard));
	guard->parent_slot = guard->parent_region = guard->snapshot_region = -1;
	child->vfork_parent_slot = -1;
	child->snap_region = -1;
	child->exec_pending = 0;
	child->exit_status = 127;
	child->exit_reason = LXP_EXIT_REASON_STATE_CORRUPTION;
	child->exit_signal = 0;
	child->exited = 1;
	primary_slot_mark(child_slot);
}

/*
 * Fork construction owns one region reference plus the not-yet-published child
 * objects and native map. A failed step comes through fork_child_build_abort(),
 * so adding an acquisition cannot grow another hand-written rollback list.
 */
struct fork_child_build {
	lxp_proc_t *parent;
	lxp_proc_t *child;
	int parent_slot;
	int child_slot;
	int parent_region;
	uint8_t region_acquired;
	uint8_t child_constructed;
	uint8_t maps_touched;
	uint8_t child_counted;
};

static void fork_child_guard_reset(int child_slot)
{
	memset(&g_vfork_guard[child_slot], 0, sizeof(g_vfork_guard[child_slot]));
	g_vfork_guard[child_slot].parent_slot =
		g_vfork_guard[child_slot].parent_region =
			g_vfork_guard[child_slot].snapshot_region = -1;
}

static int fork_child_build_prepare(struct fork_child_build *build,
				    const lxp_os_ops_t *eng, int parent_slot,
				    int child_slot, uint32_t clone_flags,
				    int child_pid)
{
	memset(build, 0, sizeof(*build));
	build->parent = &g_lxp_proc[parent_slot];
	build->child = &g_lxp_proc[child_slot];
	build->parent_slot = parent_slot;
	build->child_slot = child_slot;
	build->parent_region = build->parent->mm->region;

	deferred_slot_reassign(child_slot);
	fork_child_guard_reset(child_slot);
	if (region_get(build->parent_region) != 0)
		return -LXP_EAGAIN;
	build->region_acquired = 1;

	int rc;
	if (clone_flags & LXP_CLONE_THREAD)
		rc = lxp_proc_init_thread_child(build->child, build->parent,
						clone_flags, child_pid);
	else
		rc = lxp_proc_init_process_child(build->child, build->parent,
						 clone_flags, child_pid);
	if (rc != LXP_OK)
		return -LXP_EAGAIN;
	build->child_constructed = 1;

	/* Every slot owns its cold exec capture and active signal return chain even
	 * when its process-wide objects are shared. */
	lxp_proc_bind_exec_capture(build->child, eng->exec_capture(child_slot));
	g_sig_save[child_slot] = g_sig_save[parent_slot];

	/* Hardware mappings are installed while the record is still unpublished.
	 * A later failure clears them through the same transaction abort. */
	build->maps_touched = 1;
	if (coordinator_restore_mm_maps(eng, child_slot, build->child->mm) != 0)
		return -LXP_ENOMEM;
	build->child->alive = 1;
	return LXP_OK;
}

static void fork_child_build_count(struct fork_child_build *build)
{
	build->parent->group->live_children++;
	build->child_counted = 1;
}

static void fork_child_build_abort(struct fork_child_build *build,
				   const lxp_os_ops_t *eng)
{
	if (build->child_counted && build->parent->group->live_children > 0)
		build->parent->group->live_children--;
	if (build->child_constructed && build->child->snap_region >= 0)
		region_release_if_owned(build->child->snap_region,
					build->child_slot);
	if (build->maps_touched && eng->map_device)
		(void)eng->map_device(build->child_slot, 0, 0, 0);
	if (build->region_acquired)
		region_put(build->parent_region);
	if (build->child_constructed)
		lxp_proc_child_discard(build->child);
	memset(&g_sig_save[build->child_slot], 0,
	       sizeof(g_sig_save[build->child_slot]));
	g_lxp_used[build->child_slot] = 0;
	primary_slot_clear(build->child_slot);
	fork_child_guard_reset(build->child_slot);
}

static void fork_child_build_commit(struct fork_child_build *build)
{
	build->region_acquired = 0;
	build->child_constructed = 0;
	build->maps_touched = 0;
	build->child_counted = 0;
}

static void fork_parent_resume_error(const lxp_os_ops_t *eng, int parent_slot,
				     long error)
{
	lxp_proc_t *parent = &g_lxp_proc[parent_slot];
	coordinator_park_slot(eng, parent_slot);
	coordinator_resume_slot(eng, parent_slot, parent->mm->region,
				&g_ctx[parent_slot], error);
}

int lxp_run_common(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg,
		       const char *path, int argc, const char *const argv[])
{
	if (!eng || !eng->exec_capture || !cfg || !cfg->rootfs ||
	    !cfg->rootfs_image || cfg->rootfs_image_size == 0u ||
	    !path || argc < 1 || !argv)
		return LXP_RUN_ELAUNCH;
	for (int s = 0; s < LXP_NSLOT; s++)
		if (!eng->exec_capture(s))
			return LXP_RUN_ELAUNCH;
	g_cfg = cfg;
	g_eng = eng;
	g_lxp_rootfs_lo = cfg->rootfs_image;
	g_lxp_rootfs_hi = g_lxp_rootfs_lo + cfg->rootfs_image_size;
	for (int i = 0; i < LXP_NSLOT; i++) {
		g_lxp_used[i] = 0;
		g_slot_lifecycle[i] = SLOT_FREE;
		g_lxp_proc[i].alive = 0;
		deferred_slot_reassign(i);
	}
	memset(g_primary_pending, 0, sizeof(g_primary_pending));
	memset(g_region_refs, 0, sizeof(g_region_refs));
	memset(g_region_generation, 0, sizeof(g_region_generation));
	memset(g_vfork_guard, 0, sizeof(g_vfork_guard));
	for (int i = 0; i < LXP_NSLOT; i++)
		g_vfork_guard[i].parent_slot = g_vfork_guard[i].parent_region =
			g_vfork_guard[i].snapshot_region = -1;
	g_pending_sig = 0;
	g_tty_isig = 1;
	g_tty_icrnl = 1;
	g_console_fg_pgrp = 0;
	lxp_stats_reset();
	for (int i = 0; i < LXP_NSLOT; i++)
		g_sig_save[i].depth = 0;
#if LXP_ENABLE_DEV
	/* Register the Kconfig-enabled /dev class drivers (fb, input, ...) on this
	 * coordinator thread, where blocking HAL init (ove_fb_init, ove_i2c_create) is legal. */
	lxp_dev_autoreg_all();
#endif
#if LXP_ENABLE_NETFS
	/* Connect the remote-fs mount (9P Tversion/Tattach). Coordinator thread, where blocking
	 * init is legal; a down server is non-fatal — the mount reconnects lazily. */
	lxp_netfs_init();
#endif

	int bb = -1;
	for (int i = 0; i < cfg->rootfs_count; i++)
		if (strcmp(cfg->rootfs[i].path, path) == 0) {
			bb = i;
			break;
		}
	if (bb < 0 || !cfg->rootfs[bb].data)
		goto launch_failed;

	/* Concurrent process model: the run loop COORDINATES the live process SET
	 * (g_lxp_proc[*].alive). Each live proc owns a region + an RTOS thread for
	 * its lifetime; a vfork parent resumes the instant its child execs into its own
	 * region (or exits) so the two co-run. The region table holds one reference
	 * per live task sharing an address space, plus reserved vfork
	 * snapshot/exec-handoff regions. */
	for (int r = 0; r < LXP_NREG; r++)
		g_region_owner[r] = -1;

	g_lxp_active = 1;
	g_lxp_halt = 0;
	(void)region_reserve(0, 0);
	if (launch(eng, 0, 0, cfg->rootfs[bb].data, cfg->rootfs[bb].size, 1, 0, argc, argv, cfg->env,
		   0) != 0) {
		goto launch_failed;
	}
	g_lxp_proc[0].exec_file_idx = bb; /* the running image, for /proc/self/exe re-exec */
	lxp_diag_checkpoint();

	int rc = LXP_RUN_ETIMEOUT;
	int next_pid = 2;
	int idle = 0;
	unsigned event_cursor = 0;
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
		if (g_lxp_halt) { /* reboot(2)/poweroff: stop the whole system */
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
		int es = -1, et = LXP_EV_NONE;
		for (int i = 0; i < LXP_NSLOT; i++) {
			int s = (int)((event_cursor + (unsigned)i) % LXP_NSLOT);
			if (!primary_slot_pending(s))
				continue;
			eng->crit_enter();
			primary_slot_clear(s);
			et = claim_slot_event(s);
			eng->crit_exit();
			if (et != LXP_EV_NONE) {
				es = s;
				break;
			}
		}
		if (es >= 0)
			event_cursor = ((unsigned)es + 1u) % LXP_NSLOT;
#if LXP_ENABLE_LATENCY
		if (es >= 0 && et) { /* dispatch starts here; closed at the loop top */
			lxp_time_ns(&lat_t0);
			lat_cls = et;
		}
#endif

		if (et == LXP_EV_DEFER) {
			lxp_coord_map(g_lxp_proc[es].mm->region); /* coherent coordinator view of es's guest buffers */
			execute_deferred(eng, es);
			idle = 0;
			continue;
		}

		if (et ==
		    LXP_EV_FORK) { /* spawn a child sharing the parent's region; suspend the parent. */
			lxp_proc_t *par = &g_lxp_proc[es];
			uint32_t clone_flags = par->clone_flags;
			par->clone_flags = 0;
			/* The zombie queue is bounded. Include both running children and
			 * already-queued zombies so a parent that does not reap cannot make a
			 * later exit status disappear. EAGAIN is Linux's process-table pressure
			 * result and becomes retryable as soon as wait4 drains one entry. */
			if (!(clone_flags & LXP_CLONE_THREAD) &&
			    !fork_capacity_available(par)) {
				fork_parent_resume_error(eng, es, -LXP_EAGAIN);
				idle = 0;
				continue;
			}
			int c = -1;
			for (int s = 0; s < LXP_NSLOT; s++)
				if (!g_lxp_proc[s].alive) {
					c = s;
					break;
				}
			if (c < 0) { /* no free slot: Linux reports retryable process pressure. */
				fork_parent_resume_error(eng, es, -LXP_EAGAIN);
				idle = 0;
				continue;
			}
			int child_pid = next_pid;
			struct fork_child_build build;
			int build_rc = fork_child_build_prepare(
				&build, eng, es, c, clone_flags, child_pid);
			if (build_rc != LXP_OK) {
				fork_child_build_abort(&build, eng);
				fork_parent_resume_error(eng, es, build_rc);
				idle = 0;
				continue;
			}
			lxp_proc_t *ch = build.child;
			next_pid++;
			if (clone_flags & LXP_CLONE_VM) {
				/* A shared-mm clone runs on its own stack while the parent
				 * co-runs. CLONE_THREAD controls thread-group membership;
				 * CLONE_VM alone is a distinct waitable process. */
				int child_is_thread = (clone_flags & LXP_CLONE_THREAD) != 0;
				if (!child_is_thread)
					fork_child_build_count(&build);
				g_ctx[c] = g_ctx[es]; /* clone resumes from the parent's ctx... */
				g_ctx[c].sp =
					par->clone_child_stack; /* ...but on the child stack */
				fork_child_build_commit(&build);
				coordinator_park_slot(eng, es);
				coordinator_resume_slot(eng, es, par->mm->region, &g_ctx[es],
						  ch->pid); /* parent co-runs, gets the tid */
				coordinator_resume_slot(eng, c, ch->mm->region, &g_ctx[c],
						  0); /* child enters the thread fn (r0=0) */
				idle = 0;
				continue;
			}
			fork_child_build_count(&build); /* a new process is waitable */
			ch->vfork_parent_slot =
				es; /* resume the parent when this child execs/exits */
			/* NOMMU vfork isolation: snapshot the parent's writable data so the child's
			 * pre-exec writes to the SHARED region can't corrupt the suspended parent. */
			ch->snap_region = vfork_snapshot(eng, par, c, g_ctx[es].sp);
			if (ch->snap_region < 0) {
				/* No spare region to isolate the child's pre-exec writes from the
				 * suspended parent (deep vfork nesting — e.g. a pipeline over an SSH
				 * session: init+getty+inetd+dropbear+shell+members). Refuse the fork
				 * (-ENOMEM) rather than share the parent's region and let the child
				 * corrupt it; the caller sees a clean fork failure, not a fault. */
				fork_child_build_abort(&build, eng);
				fork_parent_resume_error(eng, es, -LXP_ENOMEM);
				idle = 0;
				continue;
			}
			fork_child_build_commit(&build);
			coordinator_park_slot(eng, es); /* suspend the parent task */
			coordinator_resume_slot(eng, c, ch->mm->region, &g_ctx[es],
					  0); /* child returns 0 from fork */
			idle = 0;
			continue;
		}

		if (et ==
		    LXP_EV_EXEC) { /* the child gets its own region → resume any vfork parent NOW. */
			lxp_proc_t *p = &g_lxp_proc[es];
			/* Freeze the old image before inspecting or transferring any of its
			 * resources. A failed host park is contained as process exit. */
			if (coordinator_park_slot(eng, es) != LXP_OK) {
				idle = 0;
				continue;
			}
			lxp_exec_capture_t *cap = p->exec_capture;
			if (!cap) { /* a port contract violation: contain it to this process */
				p->exit_status = 127;
				p->exited = 1;
				primary_slot_mark(es);
				continue;
			}
			int idx = p->exec_file_idx, eargc = cap->argc, eenvc = cap->envc;
			/* Copy argv AND envp out of the proc into static buffers before launch()
			 * re-inits the slot (which clears the bound capture). */
			static char args[LXP_EXEC_ARGBUF];
			static const char *ptrs[LXP_EXEC_MAXARGS + 1];
			static char envs[LXP_EXEC_ENVBUF];
			static const char *eptrs[LXP_EXEC_MAXENVS + 1];
			flatten_vec(args, ptrs, cap->argv_buf, cap->argv, eargc);
			flatten_vec(envs, eptrs, cap->env_buf, cap->env, eenvc);
			/* Reuse the reserved snapshot region as the exec image region — it's free once we
			 * restore the parent from it below, and reserving it at fork is why exec always has
			 * a region. No snapshot (region-pressure fallback) → find a free region as before. */
			int nr = p->snap_region;
			if (nr < 0)
				for (int r = 0; r < LXP_NREG; r++)
					if (region_free(r, g_region_owner)) {
						nr = r;
						break;
					}
			int pid = p->pid, ppid = p->group->ppid, vp = p->vfork_parent_slot;
			if (nr <
			    0) { /* region exhaustion: kill THIS proc, do NOT tear down init. */
				if (coordinator_abort_slot(eng, es) != LXP_OK) {
					idle = 0;
					continue;
				}
				deferred_slot_reassign(es);
				lxp_proc_resources_put(p);
				proc_mm_put(p);
				p->exit_status = 127;
				p->exit_reason = LXP_EXIT_REASON_EXEC_RESOURCE;
				p->exit_signal = 0;
				notify_guest_exit(es, p);
				p->alive = 0;
				g_lxp_used[es] = 0;
				if (vp >= 0)
					coordinator_resume_slot(eng, vp, g_lxp_proc[vp].mm->region, &g_ctx[vp],
							  pid);
				reap_to_parent(eng, ppid, pid, 127, /*sigchld=*/vp < 0);
				lxp_proc_group_put(p);
				idle = 0;
				continue;
			}
			if (vp >=
			    0) { /* the child leaves the parent's region → the parent co-runs. */
				/* Undo the child's pre-exec writes to the shared region+dyn_pool BEFORE the
				 * parent runs again (the args were already copied out into `args` above, so
				 * restoring over them is safe). */
				if (p->snap_region < 0 ||
				    vfork_restore(eng, &g_lxp_proc[vp], p->snap_region, es,
						  g_ctx[vp].sp) != 0) {
					vfork_contain_stale(es, p);
					idle = 0;
					continue;
				}
				p->vfork_parent_slot = -1;
				coordinator_resume_slot(eng, vp, g_lxp_proc[vp].mm->region, &g_ctx[vp], pid);
			}
			/* execve gets a private descriptor table, preserves its descriptor
			 * entries and fs context, and resets signal dispositions. */
			if (lxp_proc_files_unshare(p) != 0) {
				p->exec_pending = 0;
				coordinator_resume_slot(eng, es, p->mm->region, &g_ctx[es], -LXP_ENOMEM);
				idle = 0;
				continue;
			}
			/* Local exec already did this after validation. Remote exec reaches
			 * its commit point here, after the fetch completed. */
			for (int fd = 0; fd < LXP_MAX_FDS; fd++)
				if (p->files->fd[fd].ofd && p->files->fd[fd].cloexec)
					(void)lxp_fd_close(p, fd);
			lxp_files_t *saved_files = p->files;
			lxp_fs_context_t *saved_fs_context = p->fs_context;
			lxp_sighand_t *old_sighand = p->sighand;
			lxp_thread_group_t *saved_group = p->group;
			uint64_t saved_mask = p->sig_blocked; /* the signal mask survives execve (POSIX) */
			int exec_region_reserved =
				p->snap_region == nr && g_region_owner[nr] == es &&
				g_region_refs[nr] == 1;
			if (thread_group_stop_exec_peers(eng, es, 127) != LXP_OK) {
				slot_transition_failed(es, SLOT_EXITING, -LXP_EAGAIN);
				idle = 0;
				continue;
			}
			if (coordinator_abort_slot(eng, es) != LXP_OK) {
				idle = 0;
				continue;
			}
			deferred_slot_reassign(es);
			if (eng->map_device)
				(void)eng->map_device(es, 0, 0, 0);
			proc_mm_put(p);
			/* Transfer these objects across launch()'s proc reinitialization. */
			p->files = NULL;
			p->fs_context = NULL;
			p->sighand = NULL;
			p->group = NULL;
			if (!exec_region_reserved)
				(void)region_reserve(nr, es);
			const uint8_t *img_data = cfg->rootfs[idx].data;
			size_t img_size = cfg->rootfs[idx].size;
			int rexec = 0;
#if LXP_ENABLE_NETFS_EXEC
			/* A program off the remote mount: its bytes are in the netfs exec staging
			 * buffer (RAM), not the rootfs; launch copies its text into the region (RWX). */
			if (idx == LXP_NETFS_EXEC_SENTINEL) {
				img_data = lxp_netfs_exec_image(&img_size);
				rexec = 1;
			}
#endif
			if (!img_data ||
			    launch(eng, es, nr, img_data, img_size, pid, ppid, eargc, ptrs, eptrs,
				   rexec) != 0) {
				region_release_if_owned(nr, es);
				lxp_proc_resources_put(&g_lxp_proc[es]);
				lxp_proc_t old_resources = {
					.files = saved_files,
					.fs_context = saved_fs_context,
					.sighand = old_sighand,
				};
				lxp_proc_resources_put(&old_resources);
				lxp_proc_mm_put(&g_lxp_proc[es]);
				g_lxp_proc[es].exit_status = 127;
				g_lxp_proc[es].exit_reason = LXP_EXIT_REASON_EXEC_LOAD;
				g_lxp_proc[es].exit_signal = 0;
				notify_guest_exit(es, &g_lxp_proc[es]);
				lxp_proc_group_put(&g_lxp_proc[es]);
				lxp_proc_t old_group = {.group = saved_group};
				lxp_proc_group_put(&old_group);
				g_lxp_proc[es].alive = 0;
				g_lxp_used[es] = 0;
				reap_to_parent(eng, ppid, pid, 127, /*sigchld=*/vp < 0);
				idle = 0;
				continue;
			}
			/* Discard launch's fresh files/fs, retain its default sighand, then
			 * transfer the exec-surviving objects without changing their refs. */
			lxp_sighand_t *fresh_sighand = g_lxp_proc[es].sighand;
			lxp_thread_group_t *fresh_group = g_lxp_proc[es].group;
			g_lxp_proc[es].sighand = NULL;
			g_lxp_proc[es].group = NULL;
			lxp_proc_resources_put(&g_lxp_proc[es]);
			lxp_proc_t discarded_group = {.group = fresh_group};
			lxp_proc_group_put(&discarded_group);
			g_lxp_proc[es].files = saved_files;
			g_lxp_proc[es].fs_context = saved_fs_context;
			g_lxp_proc[es].sighand = fresh_sighand;
			g_lxp_proc[es].group = saved_group;
			lxp_proc_t discarded_sighand = {.sighand = old_sighand};
			lxp_proc_resources_put(&discarded_sighand);
			g_lxp_proc[es].sig_blocked = saved_mask;
			g_lxp_proc[es].exec_file_idx = idx; /* remember the running image so a
								   later execv("/proc/self/exe") re-runs it */
			idle = 0;
			continue;
		}

		if (et ==
		    LXP_EV_EXIT) { /* reap: abort thread, free region, wake parent/queue zombie. */
			lxp_proc_t *p = &g_lxp_proc[es];
			if (p->exit_group)
				thread_group_request_exit(es, p->exit_status);
			/* Host termination is the commit point. Keep every Linux reference
			 * intact and retry the exit event if the RTOS did not stop the task. */
			if (coordinator_abort_slot(eng, es) != LXP_OK) {
				primary_slot_mark(es);
				idle = 0;
				continue;
			}
			deferred_slot_reassign(es);
			lxp_thread_group_t *group = p->group;
			int cpid = p->pid, tgid = group->tgid, status = p->exit_status,
			    vp = p->vfork_parent_slot, ppid = group->ppid;
			lxp_proc_resources_put(p);
			if (eng->map_device)
				(void)eng->map_device(es, 0, 0, 0);
			g_sig_save[es].depth = 0;
			if (vp >= 0 && p->snap_region >= 0) {
				/* a vfork child died before exec (e.g. a failed exec) → undo its writes to
				 * the shared region so the parent is not corrupted, and free the scratch. */
				if (vfork_restore(eng, &g_lxp_proc[vp], p->snap_region, es,
						  g_ctx[vp].sp) != 0) {
					vfork_contain_stale(es, p);
					vp = -1;
					status = p->exit_status;
				} else {
					region_release_if_owned(p->snap_region, es);
				}
			}
			notify_guest_exit(es, p);
			proc_mm_put(p);
			p->alive = 0;
			g_lxp_used[es] = 0;
			int group_is_dead = thread_group_live_count(group) == 0;
			if (tgid == 1 && group_is_dead) { /* init's final task exited */
				lxp_proc_group_put(p);
				rc = status;
				break;
			}
			if (vp >=
			    0) /* fork-without-exec: the suspended parent resumes (vfork returns) */
				coordinator_resume_slot(eng, vp, g_lxp_proc[vp].mm->region, &g_ctx[vp], cpid);
			if (group_is_dead)
				reap_to_parent(eng, ppid, tgid, status, /*sigchld=*/vp < 0);
			lxp_proc_group_put(p);
			idle = 0;
			continue;
		}

		if (et ==
		    LXP_EV_SLEEP) { /* park the slot for the nanosleep duration (deadline below). */
			coordinator_park_slot(eng, es);
			g_lxp_proc[es].sleeping = 1;
			idle = 0;
			continue;
		}
		if (et == LXP_EV_FUTEXWAIT) { /* block the waiter until a peer's FUTEX_WAKE. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
		if (et ==
		    LXP_EV_WAITPARK) { /* block the waiter until a child exits. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
		if (et == LXP_EV_PIPE) { /* block the task; the retry below resumes it. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
		if (et == LXP_EV_DEVWAIT) { /* block the task; the device retry below resumes it. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
		if (et == LXP_EV_SOCKWAIT) { /* block the task; the socket retry below resumes it. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
#if LXP_ENABLE_NETFS
		if (et == LXP_EV_NETFSWAIT) { /* block the task; the netfs retry below resumes it. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
#endif
#if LXP_ENABLE_PTY
		if (et == LXP_EV_PTYWAIT) { /* block the task; the pty retry below resumes it. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
#endif
		if (et == LXP_EV_SIGSUSPEND) { /* block the task; pending_sig below wakes it. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}
		if (et == LXP_EV_CONSOLEWAIT) { /* block the task; the console retry below resumes it. */
			coordinator_park_slot(eng, es);
			idle = 0;
			continue;
		}

		/* No pending event: resume any sleeper whose deadline passed; assess liveness. */
		uint64_t now = 0;
		lxp_time_us(&now);
		int progress = 0, any_alive = 0, any_busy = 0, any_pipe_wait = 0, any_dev_wait = 0,
		    any_sock_wait = 0, any_netfs_wait = 0, any_pty_wait = 0, any_console_wait = 0,
		    any_futex_wait = 0;
		uint64_t next_sleep = UINT64_MAX; /* earliest future sleeper deadline (µs) */
		for (int s = 0; s < LXP_NSLOT; s++) {
			lxp_proc_t *p = &g_lxp_proc[s];
			if (!p->alive)
				continue;
			any_alive = 1;
			/* Before any parked-op retry below writes this slot's guest buffers from
			 * the coordinator, give the coordinator a coherent (cacheable) view of
			 * the slot's region (no-op on a coherent host). */
			if (!g_lxp_used[s])
				lxp_coord_map(p->mm->region);
			/* Job-control stopped: alive but not scheduled. Counts as "busy" for the idle
			 * watchdog — its waker is an external signal, not a deadlock. SIGCONT resumes it;
			 * a pending signal whose default action is to TERMINATE wakes and kills it; a
			 * caught or default-ignore signal stays latched until it is continued. */
			if (p->stopped) {
				any_busy = 1;
				if (p->pending_sigs & lxp_sig_bit(LXP_SIGCONT)) {
					/* Resume. Checked before the terminate case so a stopped proc sent
					 * cont+term is continued, then terminated by the still-pending signal
					 * (matching Linux). */
					p->pending_sigs &= ~lxp_sig_bit(LXP_SIGCONT);
					int boundary = (p->stop_kind == LXP_STOP_BOUNDARY);
					p->stopped = 0;
					p->stop_kind = LXP_STOP_NONE;
					/* PARKED: its X_wait flag is still set → the normal retry resumes
					 * it on a later pass, right where it blocked. BOUNDARY: resume the
					 * captured context now with the stashed syscall result. */
					if (boundary)
						coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], p->stop_r0);
					progress = 1;
				} else {
					/* A default-action-terminate signal kills a stopped proc: SIGKILL
					 * always, and also e.g. SIGTERM from `kill %job`. POSIX would keep it
					 * stopped until SIGCONT, but the shell does not send SIGCONT with a
					 * job-kill, so a stopped job would otherwise leak its slot. A caught /
					 * default-ignore / stop signal leaves it stopped. */
					int ps = pending_deliverable(p);
					if (ps == LXP_SIGKILL ||
					    (ps && lxp_sig_handler_get(p, ps) == LXP_SIG_DFL &&
					     !sig_default_ignore(ps) && !sig_is_stop(ps))) {
						p->pending_sigs &= ~lxp_sig_bit(ps);
						p->stopped = 0;
						p->stop_kind = LXP_STOP_NONE;
						p->exited = 1; /* EV_EXIT reaps it next pass */
						p->exit_status = 128 + ps;
						p->exit_reason = LXP_EXIT_REASON_SIGNAL;
						p->exit_signal = (uint8_t)ps;
						primary_slot_mark(s);
						progress = 1;
					}
				}
				continue;
			}
			if (g_lxp_used[s])
				any_busy = 1;
			if (p->pipe_wait)
				any_pipe_wait = 1;
			if (p->dev_wait)
				any_dev_wait = 1;
			if (p->sock_wait)
				any_sock_wait = 1;
			if (p->netfs_wait)
				any_netfs_wait = 1;
			if (p->pty_wait)
				any_pty_wait = 1;
			if (p->console_wait)
				any_console_wait = 1;
			/* ITIMER_REAL: raise SIGALRM once the deadline passes (setitimer/alarm).
			 * Only for a parked proc — a running one owns these fields and takes the
			 * signal at its next syscall boundary. Re-arm from the interval, and clamp
			 * the coordinator's idle sleep to the (possibly new) deadline. */
			if (p->alarm_deadline_us && !g_lxp_used[s]) {
				if (now >= p->alarm_deadline_us) {
					p->pending_sigs |= lxp_sig_bit(LXP_SIGALRM);
					p->alarm_deadline_us =
						p->alarm_interval_us ? now + p->alarm_interval_us : 0;
				}
				if (p->alarm_deadline_us && p->alarm_deadline_us < next_sleep)
					next_sleep = p->alarm_deadline_us;
			}
			/* Cross-process signal (D3) to a parked, blocked proc: the dispatch can't
			 * deliver (no live thread), so the coordinator does. pending_deliverable skips
			 * a signal the proc has blocked (it stays pending until the proc unblocks it),
			 * so the mask is honored at the parked sites too, not only at the running
			 * boundary. Each branch clears the taken bit; SIG_IGN is dropped; a default
			 * action terminates (a custom handler on a blocked proc is approximated as
			 * terminate). LXP_EV_EXIT reaps it next pass. */
			int psig = (!g_lxp_used[s]) ? pending_deliverable(p) : 0;
			/* Job control: a stop signal pending on a parked proc SUSPENDS it (instead
			 * of terminating via the branches below). Handled here for ALL wait kinds —
			 * including console_wait/dev_wait, which have no psig branch. Keep the wait
			 * flag so SIGCONT resumes it exactly where it blocked; notify the parent
			 * (a wait4(WUNTRACED) waiter gets WIFSTOPPED). */
			if (psig && sig_stops_proc(p, psig)) {
				p->pending_sigs &= ~lxp_sig_bit(psig);
				p->stopped = 1;
				p->stop_kind = LXP_STOP_PARKED;
				p->stop_sig = (uint8_t)psig;
				notify_parent_stopped(eng, p->group->ppid, p->pid, psig);
				progress = 1;
				continue;
			}
			if (psig && p->sigsuspend_pending) {
				/* rt_sigsuspend-parked thread woken by a delivered signal (the
				 * LinuxThreads restart): run the handler, then resume the syscall
				 * returning -EINTR. Unlike a sleep/wait/pipe block (terminated by a
				 * default-action signal), sigsuspend EXPECTS the signal and continues. */
				p->pending_sigs &= ~lxp_sig_bit(psig);
				p->sigsuspend_pending = 0;
				deliver_signal_parked(eng, s, p, psig, -LXP_EINTR);
				progress = 1;
			} else if (psig && (p->sleeping || p->wait_pending || p->pipe_wait)) {
				/* Deliver per disposition, like the sock/futex cases below — not the
				 * old blanket terminate. A CUSTOM handler runs and the op returns
				 * -EINTR: an interactive shell parked in wait4 that takes ^C runs its
				 * SIGINT handler and prompts again instead of being killed, which had
				 * dropped the whole dropbear SSH session (the pty broadcasts ^C to the
				 * shell too). SIG_DFL terminates; SIG_IGN and SIGCHLD-default are
				 * swallowed, leaving the proc parked (a parent must not die because a
				 * child exited). */
				p->pending_sigs &= ~lxp_sig_bit(psig);
				if (!sig_swallowed(p, psig)) {
					p->sleeping = p->wait_pending = p->pipe_wait = 0;
					deliver_signal_parked(eng, s, p, psig, -LXP_EINTR);
					progress = 1;
				}
			} else if (psig && p->sock_wait) {
				/* Signal to a proc parked in a socket op (connect/recv/accept/
				 * poll): run a handler then the op returns -EINTR — busybox ping's
				 * SIGALRM timer drives its next send this way, and a server's
				 * blocked accept takes SIGTERM/SIGCHLD. SIG_DFL terminates; SIG_IGN
				 * (and SIGCHLD's default-ignore) is swallowed, leaving the proc
				 * parked (the retry re-attempts). */
				p->pending_sigs &= ~lxp_sig_bit(psig);
				if (!sig_swallowed(p, psig)) {
					p->sock_wait = 0;
					deliver_signal_parked(eng, s, p, psig, -LXP_EINTR);
					progress = 1;
				}
			} else if (psig && p->futex_wait) {
				/* Signal to a thread parked in FUTEX_WAIT: the futex returns -EINTR
				 * (SIG_DFL terminates), so a blocked worker stays killable rather than
				 * wedging until an unrelated FUTEX_WAKE arrives. */
				p->pending_sigs &= ~lxp_sig_bit(psig);
				if (!sig_swallowed(p, psig)) {
					p->futex_wait = p->futex_woken = 0;
					p->futex_deadline_us = 0;
					deliver_signal_parked(eng, s, p, psig, -LXP_EINTR);
					progress = 1;
				}
#if LXP_ENABLE_NETFS
			} else if (psig && p->netfs_wait) {
				/* Signal to a proc parked in a 9P op (read/getdents/stat off the
				 * remote mount): run a handler then the op returns -EINTR — else a
				 * stalled/hostile server leaves the guest uninterruptible (unkillable).
				 * SIG_DFL terminates; SIG_IGN / SIGCHLD-default is swallowed, leaving it
				 * parked. Cancel the in-flight request so a late reply is not marshaled
				 * into the resumed/dead guest's buffer. */
				p->pending_sigs &= ~lxp_sig_bit(psig);
				if (!sig_swallowed(p, psig)) {
					p->netfs_wait = 0;
					lxp_netfs_cancel(p);
					deliver_signal_parked(eng, s, p, psig, -LXP_EINTR);
					progress = 1;
				}
#endif
#if LXP_ENABLE_PTY
			} else if (psig && p->pty_wait) {
				/* Signal to a proc parked in a pty read/write: ^C (SIGINT) from the line
				 * discipline lands here — the shell's handler runs and its slave read
				 * returns -EINTR (re-prompt); a foreground child takes it by default
				 * action. SIG_IGN (and SIGCHLD's default-ignore) leaves it parked. */
				p->pending_sigs &= ~lxp_sig_bit(psig);
				if (!sig_swallowed(p, psig)) {
					p->pty_wait = 0;
					deliver_signal_parked(eng, s, p, psig, -LXP_EINTR);
					progress = 1;
				}
#endif
			} else if (psig && p->console_wait) {
				/* Signal to a proc parked reading the console: deliver it so e.g. login's
				 * timeout SIGALRM (or a kill) actually fires instead of lingering until the
				 * next keystroke — console_wait had no delivery branch, so such a signal used
				 * to sit undelivered while the proc blocked on input. The read returns -EINTR;
				 * SIG_DFL terminates; SIG_IGN / default-ignore is swallowed (stays parked). */
				p->pending_sigs &= ~lxp_sig_bit(psig);
				if (!sig_swallowed(p, psig)) {
					p->console_wait = 0;
					deliver_signal_parked(eng, s, p, psig, -LXP_EINTR);
					progress = 1;
				}
			}
			if (p->sleeping) {
				any_busy = 1;
				if (now >= p->sleep_until_us) {
					p->sleeping = 0;
					coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], 0);
					progress = 1;
				} else if (p->sleep_until_us < next_sleep) {
					next_sleep = p->sleep_until_us; /* wake the coordinator at this deadline */
				}
			}
			/* Parked FUTEX_WAIT: a peer's FUTEX_WAKE set futex_woken (resume 0), or the
			 * optional timeout deadline passed (resume -ETIMEDOUT). */
			if (p->futex_wait && !g_lxp_used[s]) {
				any_busy = 1;
				any_futex_wait = 1;
				if (p->futex_woken) {
					p->futex_wait = p->futex_woken = 0;
					p->futex_deadline_us = 0;
					coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], 0);
					progress = 1;
				} else if (p->futex_deadline_us && now >= p->futex_deadline_us) {
					p->futex_wait = 0;
					p->futex_deadline_us = 0;
					coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], -LXP_ETIMEDOUT);
					progress = 1;
				} else if (p->futex_deadline_us && p->futex_deadline_us < next_sleep) {
					next_sleep = p->futex_deadline_us;
				}
			}
			/* Blocked pipe I/O: retry now that a peer may have drained/filled the
			 * ring (or closed its end → EOF/EPIPE); resume the proc when it completes. */
			if (p->pipe_wait && !g_lxp_used[s]) {
				long r = lxp_pipe_retry(p);
				if (r != -LXP_EAGAIN) {
					p->pipe_wait = 0;
					if (r == -LXP_EPIPE &&
					    lxp_sig_handler_get(p, LXP_SIGPIPE) != LXP_SIG_IGN) {
						/* broken pipe + default SIGPIPE → terminate the
						 * writer; the LXP_EV_EXIT pass reaps it (no live thread). */
						p->exited = 1;
						p->exit_status = 128 + LXP_SIGPIPE;
						p->exit_reason = LXP_EXIT_REASON_SIGNAL;
						p->exit_signal = LXP_SIGPIPE;
						primary_slot_mark(s);
					} else {
						coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], r);
					}
					progress = 1;
				}
			}
#if LXP_ENABLE_DEV
			/* Blocked device I/O: retry (the driver may now have data/space); resume
			 * the proc when the op completes. Mirrors the pipe retry above. */
			if (p->dev_wait == LXP_DEVW_MMAP && !g_lxp_used[s]) {
				/* Device mmap (P3): install the unprivileged MPU region over the
				 * device buffer on THIS (coordinator) thread — domain/TCB edits are
				 * not svc-exception-safe — record it for user_ok, and resume the proc
				 * with r0 = the mapped address (or -errno if the engine can't map). */
				int map = device_map_index(p, (uintptr_t)p->dev_buf, p->dev_len);
				long r = map;
				if (map >= 0) {
					int mr = coordinator_map_mm_range(
						eng, p->mm, (uintptr_t)p->dev_buf,
						p->dev_len, (unsigned)p->dev_cmd);
					r = mr == 0 ? (long)p->dev_buf : mr;
				}
				if (r >= 0) {
					p->mm->dev_map_lo[map] = (uintptr_t)p->dev_buf;
					p->mm->dev_map_hi[map] = (uintptr_t)p->dev_buf + p->dev_len;
					p->mm->dev_map_attrs[map] = (unsigned)p->dev_cmd;
				}
				p->dev_wait = 0;
				coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], r);
				progress = 1;
			} else if (p->dev_wait && !g_lxp_used[s]) {
				long r = lxp_dev_retry(p);
				if (r != -LXP_EAGAIN) {
					p->dev_wait = 0;
					coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], r);
					progress = 1;
				}
			}
#endif
#if LXP_ENABLE_NET
			/* Blocked socket I/O: retry (connect may have completed, or data/space
			 * arrived); resume the proc when the op completes. Mirrors the pipe/device
			 * retries above. */
			if (p->sock_wait && !g_lxp_used[s]) {
				long r = lxp_sock_retry(p);
				if (r != -LXP_EAGAIN) {
					p->sock_wait = 0;
					coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], r);
					progress = 1;
				}
			}
#endif
#if LXP_ENABLE_NETFS
			/* Blocked remote-fs I/O: pump the 9P transport + advance the parked op;
			 * resume the proc when its reply completes. Mirrors the socket retry. */
			if (p->netfs_wait && !g_lxp_used[s]) {
				long r = lxp_netfs_retry(p);
				if (r != -LXP_EAGAIN) {
					p->netfs_wait = 0;
					/* a completed exec-fetch sets exec_pending → LXP_EV_EXEC launches it
					 * from the staging buffer; don't resume the parked execve. */
					if (!p->exec_pending)
						coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], r);
					progress = 1;
				}
			}
#endif
#if LXP_ENABLE_PTY
			/* Blocked pty I/O: retry (the peer end may have drained/filled the ring);
			 * resume the proc when the op completes. Mirrors the pipe/socket retries. */
			if (p->pty_wait && !g_lxp_used[s]) {
				long r = lxp_pty_retry(p);
				if (r != -LXP_EAGAIN) {
					p->pty_wait = 0;
					coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], r);
					progress = 1;
				}
			}
#endif
			/* Blocked console read: the coordinator polls readiness (so read_fn does
			 * not busy-wait in the SVC handler and starve background tasks like the net
			 * RX poll). When a key is ready, read it here and resume the proc. */
			if (p->console_wait && !g_lxp_used[s]) {
				if (p->console_poll && p->console_poll(p->io_ctx)) {
					long r = p->read_fn ? p->read_fn(p->io_ctx, 0,
									 (void *)p->console_buf,
									 p->console_len)
							    : 0;
					uint8_t ch = (r == 1)
						? ((const volatile uint8_t *)(uintptr_t)
							   p->console_buf)[0]
						: 0;
					/* ICRNL is part of the tty input discipline, not the hardware
					 * callback.  In cooked mode this turns the serial terminal's CR
					 * into the LF required by stdio fgets() (notably login's second
					 * username prompt).  A guest that clears ICRNL still receives CR. */
					if (r == 1) {
						ch = lxp_console_input_xlate(ch);
						((volatile uint8_t *)(uintptr_t)p->console_buf)[0] = ch;
					}
					/* Cooked-mode line discipline (ISIG on): ^C/^Z become signals to
					 * the foreground group, not literal bytes. ^Z (VSUSP=26) leaves the
					 * reader parked so the parked-stop scan suspends it — its pending
					 * read is not consumed. ^C (VINTR=3) interrupts the read (-EINTR).
					 * At the raw prompt (ISIG off) both are literal bytes for hush's own
					 * line editor. (c_cc is fixed; the console termios tracks ISIG only.) */
					if (r == 1 && g_tty_isig && ch == 26) {
						console_signal_fg(LXP_SIGTSTP);
						progress = 1;
						continue; /* stay in console_wait; do not resume */
					}
					if (r == 1 && g_tty_isig && ch == 3) {
						console_signal_fg(LXP_SIGINT);
						r = -LXP_EINTR;
					}
					p->console_wait = 0;
					coordinator_resume_slot(eng, s, p->mm->region, &g_ctx[s], r);
					progress = 1;
				}
			}
		}
		/* Async console ^C/^Z for a foreground program that never reads stdin (a GUI like
		 * lvbench, or any compute loop): with no parked reader to catch VINTR/VSUSP, the
		 * coordinator scans the console itself. Only in cooked mode (ISIG on = a
		 * foreground child is running; the raw prompt keeps ^C for hush's line editor)
		 * and only when no reader is parked to serve it. Any other byte has no waiting
		 * reader here and is dropped (this path does not buffer type-ahead). The signal
		 * is latched on the foreground group; a running target takes it at its next
		 * syscall boundary (e.g. the GUI's per-frame usleep), then stops/dies. */
		if (g_tty_isig && !any_console_wait && g_cfg && g_cfg->console_poll &&
		    g_cfg->console_poll(g_cfg->io_ctx)) {
			uint8_t c = 0;
			long r = g_cfg->read_fn ? g_cfg->read_fn(g_cfg->io_ctx, 0, &c, 1) : 0;
			if (r == 1 && (c == 3 || c == 26)) { /* ^C / ^Z */
				console_signal_fg(c == 3 ? LXP_SIGINT : LXP_SIGTSTP);
				idle = 0;
			}
		}
		if (!any_alive) {
			rc = 0;
			break;
		}
		if (progress) {
			idle = 0;
			continue;
		}
		/* Idle watchdog: trip only when nothing is runnable (a true deadlock — all
		 * procs blocked with no waker); a running or sleeping proc resets it. */
		if (any_busy)
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
		 * Socket waits use lxp_sock_kick when the port advertises it; portable ports keep
		 * the 5ms fallback. */
		int socket_ready_events = 0;
#if LXP_ENABLE_NET
		socket_ready_events =
			g_lxp_net_ops &&
			(g_lxp_net_ops->capabilities & LXP_NET_CAP_SOCKET_READY_EVENT);
#endif
		int any_poll_wait = any_pipe_wait || any_dev_wait || any_netfs_wait ||
				    any_pty_wait || any_console_wait || any_futex_wait;
		unsigned to = coordinator_wait_timeout(any_poll_wait, any_sock_wait,
						       socket_ready_events);
		if (next_sleep != UINT64_MAX && next_sleep > now) {
			uint64_t d_ms = (next_sleep - now + 999u) / 1000u; /* round up, don't wake early */
			if (d_ms < 1u)
				d_ms = 1u;
			if (d_ms < (uint64_t)to)
				to = (unsigned)d_ms;
		}
		eng->event_wait(to);
	}
	g_lxp_active = 0;
	coordinator_teardown_all(eng);
	lxp_diag_checkpoint();
	return rc;

launch_failed:
	g_lxp_active = 0;
	coordinator_teardown_all(eng);
	lxp_diag_checkpoint();
	return LXP_RUN_ELAUNCH;
}

static int os_ops_valid(const lxp_os_ops_t *ops)
{
	if (!ops || ops->abi_version != LXP_OS_OPS_ABI_VERSION ||
	    ops->struct_size != sizeof(*ops) ||
	    !ops->region || !ops->spawn_launch || !ops->spawn_resume ||
	    !ops->abort_slot || !ops->park_prepare || !ops->park_slot ||
	    !ops->crit_enter || !ops->crit_exit || !ops->event_post ||
	    !ops->event_wait || !ops->time_us || !ops->time_ns ||
	    !ops->exec_capture || !ops->random_fill)
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
	    ops->struct_size != sizeof(*ops) ||
	    !ops->sock_open || !ops->sock_accept || !ops->sock_close ||
	    !ops->sock_connect || !ops->sock_bind || !ops->sock_listen ||
	    !ops->sock_send || !ops->sock_recv || !ops->sock_sendto ||
	    !ops->sock_recvfrom || !ops->sock_set_nonblock || !ops->sock_poll ||
	    !ops->sock_shutdown || !ops->sock_getsockname ||
	    !ops->sock_getpeername || !ops->sock_get_error ||
	    !ops->netif_get_addr || !ops->netif_get_hwaddr ||
	    !ops->netif_get_flags || !ops->netif_set_addr ||
	    !ops->netif_set_up)
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
	if (!ops->fb_init || !ops->fb_get_info || !ops->fb_get_buffer ||
	    !ops->fb_flush || !ops->fb_present)
		return 0;
#endif
#if LXP_ENABLE_DEV_DMA2D
	if (!ops->dma2d_submit)
		return 0;
#endif
#if LXP_ENABLE_TOUCH
	if (!ops->touch_init || !ops->touch_read)
		return 0;
#endif
	(void)ops;
	return 1;
}

static int run_config_valid(const lxp_run_config_t *cfg)
{
	if (!cfg || !cfg->rootfs || cfg->rootfs_count <= 0 ||
	    !cfg->rootfs_image || cfg->rootfs_image_size == 0u)
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
	return 1;
}

/* THE port entry (see lxp_run.h). Validate and publish this run's exact
 * providers, then bracket the coordinator with optional host setup/teardown. */
int lxp_run(const lxp_os_ops_t *os_ops, const lxp_net_ops_t *net_ops,
	    const lxp_display_ops_t *disp_ops, const lxp_config_t *config,
	    const lxp_run_config_t *run_config, const char *path, int argc,
	    const char *const argv[])
{
	lxp_lat_reset(); /* counters describe THIS run, not a previous one */
	lxp_diag_reset_health();
	g_diag_native_known = 0;
	memset(g_diag_native_present, 0, sizeof(g_diag_native_present));
	if (!os_ops_valid(os_ops) || !net_ops_valid(net_ops) ||
	    !display_ops_valid(disp_ops) || !run_config_valid(run_config) ||
	    !path || argc < 1 || !argv)
		return LXP_RUN_ELAUNCH;

	/* Assign even NULL providers so a later sequential run cannot inherit one. */
#if LXP_ENABLE_NET
	g_lxp_net_ops = net_ops;
#else
	(void)net_ops;
#endif
#if LXP_ENABLE_DEV
	g_lxp_disp_ops = disp_ops;
#else
	(void)disp_ops;
#endif
#if LXP_ENABLE_DEV_INPUT
	/* Seed the touch/report geometry from the run config (replaces a host calling
	 * lxp_disp_set_geometry directly). 0 fields keep the compiled-in default. */
	if (config && config->display_width > 0 && config->display_height > 0)
		lxp_disp_set_geometry(config->display_width, config->display_height);
#endif
	(void)config;

	if (os_ops->rootfs_window)
		os_ops->rootfs_window(run_config->rootfs_image,
				    run_config->rootfs_image_size);

	if (os_ops->prepare) {
		int prc = os_ops->prepare();
		if (prc < 0) {
#if LXP_ENABLE_NET
			g_lxp_net_ops = NULL;
#endif
#if LXP_ENABLE_DEV
			g_lxp_disp_ops = NULL;
#endif
			return LXP_RUN_ELAUNCH;
		}
	}
	int rc = lxp_run_common(os_ops, run_config, path, argc, argv);
	if (os_ops->teardown)
		os_ops->teardown();
	g_eng = NULL;
	g_cfg = NULL;
	g_lxp_rootfs_lo = NULL;
	g_lxp_rootfs_hi = NULL;
#if LXP_ENABLE_NET
	g_lxp_net_ops = NULL;
#endif
#if LXP_ENABLE_DEV
	g_lxp_disp_ops = NULL;
#endif
	return rc;
}
