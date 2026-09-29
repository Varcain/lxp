/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Process and system syscalls: exit, identity and credential stubs, niceness,
 * process groups and sessions, resource limits, sysinfo, uname, getrandom, reboot and
 * wait4.
 */
#include "sys/lxp_sys.h"
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"
#include <string.h>

/* reboot(2)/poweroff requests. Kept outside the coordinator so isolated syscall tests
 * do not need the run loop; accessors keep this policy out of the public RTOS seam. */
static uint8_t g_halt_requested;

void lxp_request_halt(void)
{
	g_halt_requested = 1;
}

void lxp_reset_halt_request(void)
{
	g_halt_requested = 0;
}

int lxp_halt_requested(void)
{
	return g_halt_requested != 0;
}

static long sys_exit(lxp_proc_t *p, int status, int group)
{
	(void)lxp_intent_exit(p, group);
	p->exit_status = status & 0xff;
	if (group && p->group) {
		p->group->exiting = 1;
		p->group->exit_status = p->exit_status;
	}
	p->exit_reason = LXP_EXIT_REASON_NORMAL;
	p->exit_signal = 0;
	p->exit_detail = 0;
	p->exit_address = 0;
	return 0;
}

/* Fill a guest buffer through the active host entropy provider. The port contract
 * is all-or-error: it returns LXP_OK only after writing every requested byte.
 * Missing entropy is ENOSYS for getrandom(2), but an already-open random device
 * reports EIO. A transient non-blocking provider maps to EAGAIN. */
long lxp_random_fill_guest(void *buf, size_t count, int unavailable_errno)
{
	if (count == 0u)
		return 0;
	/* The host can write through an uncached alias while the first/last cache
	 * line contains unrelated dirty guest bytes.  Publish those complete lines
	 * before the write so the post-write invalidate cannot discard adjacent
	 * guest data. */
	lxp_cache_clean(buf, count);
	int r = lxp_random_fill(buf, count);
	if (r == LXP_OK) {
		/* A Cortex-M host may write through a privileged uncached view while the
		 * guest maps the same RAM cacheable. Drop stale guest lines before resume. */
		lxp_cache_invalidate(buf, count);
		return (long)count;
	}
	if (r == LXP_ERR_WOULD_BLOCK)
		return -LXP_EAGAIN;
	if (r == LXP_ERR_NOT_SUPPORTED || r == LXP_ERR_NOT_REGISTERED)
		return -unavailable_errno;
	return -LXP_EIO;
}

/* getrandom: validate Linux flags and fill from the host entropy provider. */
static long sys_getrandom(lxp_proc_t *p, void *buf, size_t count, unsigned flags)
{
	const unsigned valid = LXP_GRND_NONBLOCK | LXP_GRND_RANDOM | LXP_GRND_INSECURE;
	if ((flags & ~valid) != 0u || (flags & (LXP_GRND_RANDOM | LXP_GRND_INSECURE)) ==
					      (LXP_GRND_RANDOM | LXP_GRND_INSECURE))
		return -LXP_EINVAL;
	if (count == 0u)
		return 0;
	if (!lxp_guest_access_ok(p, buf, count, 1))
		return -LXP_EFAULT;
	return lxp_random_fill_guest(buf, count, LXP_ENOSYS);
}

long lxp_sys_exit(lxp_proc_t *proc, const long a[6])
{
	return sys_exit(proc, (int)a[0], 0);
}

long lxp_sys_exit_group(lxp_proc_t *proc, const long a[6])
{
	return sys_exit(proc, (int)a[0], 1);
}

/* ---- libc-init / identity stubs: enough for a static uClibc program to start ---- */

long lxp_sys_getpid(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	return proc->group ? proc->group->tgid : proc->pid;
}

long lxp_sys_getppid(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	return proc->group ? proc->group->ppid : 0;
}

long lxp_sys_gettid(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	return proc->pid;
}

long lxp_sys_getuid_root(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	(void)proc;
	return 0; /* run as root */
}

/* (ruid*, euid*, suid*) — all root (0) on this tier */
long lxp_sys_getresid(lxp_proc_t *proc, const long a[6])
{
	/* Validate every output before writing any, so a bad pointer changes nothing. */
	for (int i = 0; i < 3; i++)
		if (a[i] && !lxp_guest_access_ok(proc, (void *)(uintptr_t)a[i], sizeof(uint32_t), 1))
			return -LXP_EFAULT;
	for (int i = 0; i < 3; i++)
		if (a[i] && lxp_guest_put_u32(proc, (uintptr_t)a[i], 0) != 0)
			return -LXP_EFAULT;
	return 0;
}

long lxp_sys_nice(lxp_proc_t *proc, const long a[6])
{
	int64_t requested = (int64_t)lxp_proc_nice_get(proc) + (int32_t)a[0];
	lxp_proc_nice_set(proc, requested < -20	 ? -20
				: requested > 19 ? 19
						 : (int)requested);
	/* Linux's raw nice(2) syscall returns zero on success. Returning the
	 * resulting negative nice value would cross the -errno ABI boundary and
	 * make libc report a successful priority raise as an error. */
	return 0;
}

/* set the file-creation mask, return the previous (per-proc, inherited) */
long lxp_sys_umask(lxp_proc_t *proc, const long a[6])
{
	int old = proc->fs_context->umask;
	proc->fs_context->umask = (unsigned short)(a[0] & 0777);
	return old;
}

/* (pid, pgid) — job control: put a process into a group */
long lxp_sys_setpgid(lxp_proc_t *proc, const long a[6])
{
	int tpid = (int)a[0], tpgid = (int)a[1];
	/* Only a self-target is tracked here (pid 0, or my own pid); pgid 0 means "use my
	 * pid" (become group leader). A child sets its OWN group via setpgid(0, …) after
	 * fork, so a cross-proc setpgid is accepted inert (no proc table at this layer). */
	if (tpid == 0 || tpid == proc->pid)
		proc->group->pgid = (tpgid == 0) ? proc->pid : tpgid;
	return 0;
}

/* shell job control: the caller's process group */
long lxp_sys_getpgrp(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	return proc->group->pgid;
}

/* getty/login start a new session: the caller leads its own group */
long lxp_sys_setsid(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	proc->group->pgid = proc->pid;
	return proc->pid;
}

/* Process-control and fs-mode setup, accepted and inert: prctl; sched_yield (a hint —
 * host preemption/admission owns fairness); fchmod/fchown32/chown32 (modes and
 * ownership are not tracked: login chmods the tty, dropbear chowns the pty over SSH);
 * and the uid/gid calls, whose policy is not implemented — login's credential drop
 * and dropbear's post-auth privilege drop must not abort (a failed drop is fatal to
 * an SSH server). CPU privilege remains engine-enforced (nPRIV/user). */
long lxp_sys_inert(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	(void)proc;
	return 0;
}

/* (pid, resource, new_limit, old_limit) — report a sane finite limit; a "new" limit
 * is accepted (inert). getty/login and dropbear query RLIMIT_NOFILE etc. */
long lxp_sys_prlimit64(lxp_proc_t *proc, const long a[6])
{
	uintptr_t uold = (uintptr_t)a[3];
	if (uold) {
		/* Report the TRUTH for RLIMIT_NOFILE: the fd table is LXP_MAX_FDS, so
		 * advertising more just hands a guest a lie that turns into a surprise
		 * EMFILE at the (LXP_MAX_FDS)th open. Other resources keep a finite,
		 * never-RLIM_INFINITY default (a close-all-fds loop would else spin to 2^64). */
		uint64_t v = ((int)a[1] == 7 /* RLIMIT_NOFILE */) ? LXP_MAX_FDS : 1024;
		const uint64_t lim[2] = {v, v}; /* rlim_cur, rlim_max */
		if (lxp_copy_to_guest(proc, uold, lim, sizeof(lim)) != 0)
			return -LXP_EFAULT;
	}
	return 0;
}

/* uptime + ram totals (uptime/free read this) */
long lxp_sys_sysinfo(lxp_proc_t *proc, const long a[6])
{
	struct lxp_sysinfo {
		int32_t uptime;
		uint32_t loads[3];
		uint32_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
		uint16_t procs, pad;
		uint32_t totalhigh, freehigh, mem_unit;
		char _f[8];
	} info;
	LXP_STATIC_ASSERT(sizeof(struct lxp_sysinfo) == 64, "sysinfo ABI size drifted");
	struct lxp_sysinfo *si = &info;
	memset(si, 0, sizeof(*si));
	uint64_t ns = 0;
	lxp_time_ns(&ns);
	si->uptime = (int32_t)(ns / 1000000000ull);
	struct lxp_resource_stats resources;
	lxp_get_resource_stats(&resources);
	/* ARM's sysinfo fields are 32-bit. Pick the smallest power-of-two
	 * byte unit that represents the guest capacity. freeram is the
	 * effective capacity remaining after both slot and region limits. */
	uint64_t largest = resources.total_bytes > resources.available_bytes
				   ? resources.total_bytes
				   : resources.available_bytes;
	uint32_t unit = 1;
	while (largest / unit > UINT32_MAX && unit <= UINT32_MAX / 2u)
		unit *= 2u;
	uint64_t total_units = resources.total_bytes / unit;
	uint64_t free_units = resources.available_bytes / unit;
	si->totalram = (uint32_t)(total_units > UINT32_MAX ? UINT32_MAX : total_units);
	si->freeram = (uint32_t)(free_units > UINT32_MAX ? UINT32_MAX : free_units);
	si->mem_unit = unit;
	/* The coordinator contributes its aggregate without exposing the
	 * writable process table to syscall subsystems. Direct host tests
	 * have no coordinator, so retain one for the caller. */
	unsigned live = resources.processes;
	si->procs = (uint16_t)(live > UINT16_MAX ? UINT16_MAX : (live ? live : 1u));
	return lxp_copy_to_guest(proc, (uintptr_t)a[0], si, sizeof(*si)) != 0 ? -LXP_EFAULT : 0;
}

long lxp_sys_uname(lxp_proc_t *proc, const long a[6])
{
	/* struct utsname: 6 fixed 65-byte fields (sysname, nodename, release,
	 * version, machine, domainname). The shell reads these at startup. */
	const char *const f[6] = {"Linux",  "overtos", "6.1.0", lxp_system_version(),
				  "armv7l", "(none)"};
	char u[6 * 65];
	memset(u, 0, sizeof(u));
	for (int i = 0; i < 6; i++) {
		size_t l = 0;
		while (l < 64 && f[i][l])
			l++;
		memcpy(u + i * 65, f[i], l);
	}
	return lxp_copy_to_guest(proc, (uintptr_t)a[0], u, sizeof(u)) != 0 ? -LXP_EFAULT : 0;
}

/* (buf, count, flags) */
long lxp_sys_getrandom(lxp_proc_t *proc, const long a[6])
{
	return sys_getrandom(proc, (void *)(uintptr_t)a[0], (size_t)a[1], (unsigned)a[2]);
}

/* reboot(magic1, magic2, cmd, arg) — cmd is a2 */
long lxp_sys_reboot(lxp_proc_t *proc, const long a[6])
{
	unsigned cmd = (unsigned)a[2];
	/* Only an actual halt/poweroff/restart stops the system; init calls
	 * reboot(CAD_OFF=0) at startup to disable Ctrl-Alt-Del — a no-op here. */
	if (cmd == 0x01234567u /* RESTART */ || cmd == 0xcdef0123u /* HALT */ ||
	    cmd == 0x4321fedcu /* POWER_OFF */ || cmd == 0xa1b2c3d4u /* RESTART2 */) {
		lxp_request_halt();
		(void)lxp_intent_exit(proc, 0);
		proc->exit_status = 0;
		proc->exit_reason = LXP_EXIT_REASON_NORMAL;
	}
	return 0;
}

long lxp_sys_wait4(lxp_proc_t *proc, const long a[6])
{
	/* Validate the status output before a child state-change is consumed. */
	if (a[1] && !lxp_guest_access_ok(proc, (void *)(uintptr_t)a[1], sizeof(int), 1))
		return -LXP_EFAULT;
	int options = (int)a[2];
	int wpid = (int)a[0];
	uintptr_t status = (uintptr_t)a[1];
	/* Report the first queued child state-change this call is allowed to see (FIFO):
	 * an exited zombie always; a STOPPED notification only with WUNTRACED (job control).
	 * A pid filter (wpid > 0) must match. A STOPPED entry leaves live_children intact —
	 * the child is alive, only the notice is consumed. Else, if children are still live,
	 * block in a CHILD wait until the coordinator observes a change. None → -ECHILD. */
	lxp_thread_group_t *group = proc->group;
	if (!group)
		return -LXP_ECHILD;
	for (int i = 0; i < group->child_count; i++) {
		if (wpid > 0 && group->child_pid[i] != wpid)
			continue;
		if (group->child_kind[i] == LXP_CHILD_STOPPED && !(options & LXP_WUNTRACED))
			continue;
		int pid = group->child_pid[i];
		int code = group->child_status[i];
		int kind = group->child_kind[i];
		for (int j = i + 1; j < group->child_count; j++) {
			group->child_pid[j - 1] = group->child_pid[j];
			group->child_status[j - 1] = group->child_status[j];
			group->child_kind[j - 1] = group->child_kind[j];
		}
		group->child_count--;
		if (status)
			(void)lxp_guest_put_u32(proc, status,
						(uint32_t)((kind == LXP_CHILD_STOPPED)
								   ? lxp_encode_wstopped(code)
								   : lxp_encode_wstatus(code)));
		return pid;
	}
	if (group->live_children == 0)
		return -LXP_ECHILD;
	if (options & LXP_WNOHANG) /* children live but none ready */
		return 0;
	lxp_wait_t wait = {
		.kind = LXP_WAIT_CHILD,
		.data.child.pid = wpid,
		.data.child.options = options,
		.data.child.status = (uintptr_t)a[1],
	};
	return lxp_wait_park(proc, &wait); /* dispatch parks; the coordinator's resume supplies the real r0 */
}

long lxp_sys_set_tid_address(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	(void)proc;
	return 1; /* our single thread's tid */
}

long lxp_sys_set_robust_list(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	(void)proc;
	return 0;
}
