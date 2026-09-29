/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#include "lxp/lxp_config.h"
#include "lxp_loader.h" /* lxp_loader_abi_incompatible — refuse a wrong-ABI execve up front */

#include "lxp/lxp_stats.h"
#include "lxp_syscall.h"
#include "lxp/lxp_types.h"

#include "lxp_internal.h" /* lxp_guest_access_ok / lxp_guest_strnlen / file_mode / lxp_encode_wstatus */
#include "lxp_text.h"	  /* bounded text construction for synthetic names */
#include "fs/lxp_vfs.h"	  /* per-fd-kind file-operation vtable (dispatch by kind) */
#include "sys/lxp_sys.h"	  /* the syscall handlers the table dispatches to */

#include "fs/lxp_dirent.h"      /* getdents record output */
#include "fs/lxp_eventfd.h"     /* eventfd2(2) counters (FD_EVENTFD) */
#include "fs/lxp_fd_private.h" /* descriptor-table reference transaction */
#if LXP_ENABLE_FS
#include "fs/lxp_hostfs.h" /* writable host mount (FD_HOSTFS, /data) */
#endif
#include "fs/lxp_path.h"     /* path resolution (resolve_path / fs_lookup / fs_follow) */
#include "fs/lxp_pipe.h"     /* pipe ring ops (FD_PIPE) */
#include "fs/lxp_poll.h"     /* poll/ppoll/pselect6 */
#include "fs/lxp_stat.h"     /* ARM struct stat64 record */
#include "fs/lxp_tmpfs.h"    /* writable VFS overlay nodes (FD_TMPFS) */
#include "proc/lxp_procfs.h" /* synthetic /proc content generation (FD_PROC) */
#include "proc/lxp_script.h" /* bounded #! parsing shared with initial launch */
#if LXP_ENABLE_DEV
#include "dev/lxp_dev.h" /* /dev character-device routing (FD_DEV) */
#endif
#if LXP_ENABLE_NET
#include "net/lxp_net.h" /* socket routing (FD_SOCKET) */
#endif
#if LXP_ENABLE_NETFS
#include "netfs/lxp_netfs.h" /* remote-fs routing (FD_NET, /mnt/pi) */
#endif
#if LXP_ENABLE_PTY
#include "pty/lxp_pty.h" /* pseudo-terminal routing (FD_PTY) */
#endif

#include <limits.h>
#include <string.h>

/* ABI pins for the tty/poll uapi structs (lxp_proc.h). Fixed-width fields → these
 * hold on the 32-bit target and the 64-bit host build; a drift fails the build. */
LXP_STATIC_ASSERT(sizeof(struct lxp_termios) == 36, "termios ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_termios, c_cc) == 17, "termios c_cc offset drifted");
LXP_STATIC_ASSERT(sizeof(struct lxp_winsize) == 8, "winsize ABI size drifted");
LXP_STATIC_ASSERT(sizeof(struct lxp_pollfd) == 8, "pollfd ABI size drifted");

/*
 * Linux syscall personality — engine-agnostic dispatch.
 *
 * Translates the Linux syscall ABI into host-agnostic module primitives. The trap frame is
 * decoded by the per-engine SVC seam, which calls lxp_syscall() with the
 * register arguments; this file holds the dispatcher and most syscall handlers.
 * Pointer arguments are program addresses — in the flat (NOMMU) model the
 * program shares our address space, so they are used directly once
 * lxp_guest_access_ok() has checked them against the process's memory.
 */

/* fd kinds (lxp_ofd_t.kind) live in lxp_proc.h and are shared with subsystem TUs. */

/* The pipe subsystem (ring buffer + read/write/poll ops) lives in src/fs/lxp_pipe.c;
 * this dispatcher calls it via fs/lxp_pipe.h. */

#if LXP_ENABLE_NET
/* Resolve @p fd to its socket open-pool index, or -1 if @p fd is not a socket. Collapses
 * descriptor lookup + kind check that the socket syscalls all repeat. */
static int sock_slot(lxp_proc_t *p, int fd)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	return (s && s->kind == LXP_FD_SOCKET) ? s->file_idx : -1;
}

/* sendmsg(2): gather the message's iovec segments out over the socket. Ancillary data
 * (msg_control) is not interpreted — SCM_RIGHTS fd-passing is unsupported — so only the
 * ordinary payload is sent. Mirrors sys_writev: each segment goes through lxp_sock_send,
 * accumulating; a short segment ends the gather (a short sendmsg is legal). msg_name, when
 * present, is the datagram destination. If a later segment would block after earlier ones
 * were sent, the accumulated count is returned rather than parking mid-gather (the single-
 * buffer park cannot resume a partially-gathered message); a first-segment block parks as
 * usual and the coordinator retry completes it. */
static long sys_sendmsg(lxp_proc_t *p, int oi, const lxp_msghdr *umsg, int flags)
{
	lxp_msghdr m;
	if (lxp_copy_from_guest(p, &m, (uintptr_t)umsg, sizeof(m)) != 0)
		return -LXP_EFAULT;
	if (m.msg_iovlen > LXP_SYSCALL_MAX_IOV) /* bound before iovlen*sizeof(iovec) overflows */
		return -LXP_EINVAL;
	const lxp_iovec *iov = m.msg_iov;
	if (m.msg_iovlen && !lxp_guest_access_ok(p, iov, m.msg_iovlen * sizeof(*iov), 0))
		return -LXP_EFAULT; /* the iov array; each iov_base is checked in lxp_sock_send */
	const void *dest = (m.msg_name && m.msg_namelen) ? m.msg_name : NULL;

	/* A datagram is one message: gather every segment into a single packet, or a per-segment
	 * send would fragment it into several datagrams. Stream sockets keep the per-segment loop
	 * below (byte-stream, so segment boundaries don't matter). */
	if (m.msg_iovlen > 1 && lxp_sock_is_dgram(oi))
		return lxp_sock_sendmsg(p, oi, iov, (int)m.msg_iovlen, flags, dest, m.msg_namelen);

	long total = 0;
	size_t budget = LXP_SYSCALL_QUANTUM_BYTES;
	for (size_t i = 0; i < m.msg_iovlen; i++) {
		lxp_iovec entry;
		if (lxp_copy_from_guest(p, &entry, (uintptr_t)&iov[i], sizeof(entry)) != 0)
			return -LXP_EFAULT;
		if (entry.iov_len == 0)
			continue;
		size_t len = entry.iov_len < budget ? entry.iov_len : budget;
		long r = lxp_sock_send(p, oi, entry.iov_base, len, flags, dest, m.msg_namelen);
		if (r < 0)
			return total ? total : r;
		if ((size_t)r > len)
			return total ? total
				     : -LXP_EIO; /* host backend violated the write contract */
		if (p->wait.kind == LXP_WAIT_SOCKET) { /* this segment parked */
			if (total >
			    0) { /* earlier segments already sent: short send, do not park */
				(void)lxp_wait_cancel(p);
				return total;
			}
			return 0; /* first segment: let the coordinator retry complete it */
		}
		total += r;
		budget -= (size_t)r;
		if ((size_t)r < len || len < entry.iov_len || budget == 0)
			break; /* short send */
	}
	return total;
}

/* recvmsg(2): scatter received bytes into the message's iovec. A single underlying recv
 * fills the first non-empty segment — a short read is always legal, and it keeps the
 * blocking recv's single-buffer park valid on the resume. No ancillary data is produced
 * (msg_controllen/msg_flags are cleared); msg_name, when present, is filled with the
 * source address (and msg_namelen updated) as recvfrom does. */
static long sys_recvmsg(lxp_proc_t *p, int oi, lxp_msghdr *umsg, int flags)
{
	lxp_msghdr m;
	if (lxp_copy_from_guest(p, &m, (uintptr_t)umsg, sizeof(m)) != 0)
		return -LXP_EFAULT;
	if (m.msg_iovlen > LXP_SYSCALL_MAX_IOV)
		return -LXP_EINVAL;
	const lxp_iovec *iov = m.msg_iov;
	if (m.msg_iovlen && !lxp_guest_access_ok(p, iov, m.msg_iovlen * sizeof(*iov), 0))
		return -LXP_EFAULT;
	m.msg_controllen = 0; /* no ancillary data is ever produced */
	m.msg_flags = 0;
	if (lxp_copy_to_guest(p, (uintptr_t)umsg, &m, sizeof(m)) != 0)
		return -LXP_EFAULT;

	/* Receive into the first non-empty segment only. A blocking recv parks with a single
	 * guest buffer, so a multi-segment scatter cannot be resumed after a park — and the
	 * transport does not report a datagram's true length, so MSG_TRUNC cannot be set. This is
	 * a legal short read for a stream socket; for a datagram it means the tail of a message
	 * larger than the first segment is lost. Callers that need the whole datagram should pass
	 * a single sufficiently large segment. */
	void *src = (m.msg_name && m.msg_namelen) ? m.msg_name : NULL;
	void *srclen = src ? &umsg->msg_namelen : NULL;
	for (size_t i = 0; i < m.msg_iovlen; i++) {
		lxp_iovec entry;
		if (lxp_copy_from_guest(p, &entry, (uintptr_t)&iov[i], sizeof(entry)) != 0)
			return -LXP_EFAULT;
		if (entry.iov_len == 0)
			continue;
		size_t len = entry.iov_len;
		if (len > LXP_SYSCALL_QUANTUM_BYTES)
			len = LXP_SYSCALL_QUANTUM_BYTES;
		return lxp_sock_recv(p, oi, entry.iov_base, len, flags, src, srclen);
	}
	return 0; /* no buffer space in the iov: nothing received */
}
#endif

/*
 * execve: resolve the program in the rootfs and capture its argument vector,
 * then flag the request. The per-engine seam (privileged) does the actual image
 * replacement — reload the bFLT, rebuild the MPU domain + stack, and relaunch
 * the thread — because that is engine-specific. We never truly return: on
 * success the old image is gone; on failure we report a negated errno.
 */
/* Snapshot an untrusted guest argv/envp into coordinator-owned storage. The guest is parked,
 * but another CLONE_VM thread can still mutate its memory, so each pointer is loaded once and no
 * raw vector is revisited after this copy. */
static long exec_copy_vec(lxp_proc_t *p, char *const uvec[], uint16_t *vec, char *buf, size_t bufsz,
			  int max, int *count, size_t *used)
{
	*count = 0;
	if (used)
		*used = 0;
	/* Leave no plausible offset behind from the image this slot ran before. */
	for (int j = 0; j < max; j++)
		vec[j] = LXP_EXEC_OFF_NONE;
	if (!uvec)
		return 0;
	size_t off = 0;
	for (int j = 0; j <= max; j++) {
		const char *us;
		if (lxp_copy_from_guest(p, &us, (uintptr_t)&uvec[j], sizeof(us)) != 0)
			return -LXP_EFAULT;
		if (!us)
			return 0;
		if (j == max || off == bufsz)
			return -LXP_E2BIG;
		size_t room = bufsz - off;
		/* Copy each byte once and decide termination from the copied value. A
		 * co-running CLONE_VM thread may mutate the source: a separate strnlen +
		 * memcpy could observe a NUL during the scan and then copy a non-terminated
		 * string, making the later trusted-buffer strlen walk out of bounds. */
		size_t len;
		long rc = lxp_copy_string_from_guest(p, buf + off, room, (uintptr_t)us, &len);
		if (rc != 0)
			return rc;
		vec[j] = (uint16_t)off;
		off += len + 1;
		*count = j + 1;
		if (used)
			*used = off;
	}
	return -LXP_E2BIG;
}

/* Rewrite an already-snapshotted script argv in place. Keeping the snapshot in privileged
 * slot storage avoids a second argument buffer on the coordinator task's embedded stack. */
static long exec_rewrite_script_argv(lxp_exec_capture_t *cap, int old_argc, size_t old_bytes,
				     const char *interp, const char *iarg, int have_iarg,
				     const char *script, int *new_argc)
{
	const int prefix_count = have_iarg ? 3 : 2;
	const int tail_count = old_argc > 1 ? old_argc - 1 : 0;
	if (prefix_count + tail_count > LXP_EXEC_MAXARGS)
		return -LXP_E2BIG;

	size_t tail_off = old_bytes;
	if (tail_count)
		tail_off = cap->argv[1];
	if (tail_off > old_bytes)
		return -LXP_EFAULT; /* internal snapshot invariant */
	size_t tail_bytes = old_bytes - tail_off;

	const char *prefix[3] = {interp, script, NULL};
	if (have_iarg) {
		prefix[1] = iarg;
		prefix[2] = script;
	}
	size_t prefix_bytes = 0;
	for (int j = 0; j < prefix_count; j++) {
		size_t len = strlen(prefix[j]) + 1;
		if (prefix_bytes > sizeof(cap->argv_buf) ||
		    len > sizeof(cap->argv_buf) - prefix_bytes)
			return -LXP_E2BIG;
		prefix_bytes += len;
	}
	if (tail_bytes > sizeof(cap->argv_buf) - prefix_bytes)
		return -LXP_E2BIG;

	memmove(cap->argv_buf + prefix_bytes, cap->argv_buf + tail_off, tail_bytes);
	size_t off = 0;
	for (int j = 0; j < prefix_count; j++) {
		size_t len = strlen(prefix[j]) + 1;
		cap->argv[j] = (uint16_t)off;
		memcpy(cap->argv_buf + off, prefix[j], len);
		off += len;
	}
	for (int j = 0; j < tail_count; j++) {
		cap->argv[prefix_count + j] = (uint16_t)off;
		off += strlen(cap->argv_buf + off) + 1;
	}
	/* The rewrite shortens the vector when the script took no arguments; leave
	 * nothing from the pre-rewrite capture readable as a valid offset. */
	for (int j = prefix_count + tail_count; j < LXP_EXEC_MAXARGS; j++)
		cap->argv[j] = LXP_EXEC_OFF_NONE;
	*new_argc = prefix_count + tail_count;
	return 0;
}

static long sys_execve(lxp_proc_t *p, const char *path, char *const argv[], char *const envp[])
{
	if (!path)
		return -LXP_EFAULT;
	lxp_exec_capture_t *cap = p->exec_capture;
	if (!cap)
		return -LXP_ENOMEM;
	/* Snapshot both vectors before path resolution. This bounds work to the actual storage the
	 * relaunch can preserve instead of scanning and silently dropping hundreds of strings. */
	int raw_argc = 0, envc = 0;
	size_t raw_argbytes = 0;
	long vr = exec_copy_vec(p, argv, cap->argv, cap->argv_buf, sizeof(cap->argv_buf),
				LXP_EXEC_MAXARGS, &raw_argc, &raw_argbytes);
	if (vr < 0)
		return vr;
	vr = exec_copy_vec(p, envp, cap->env, cap->env_buf, sizeof(cap->env_buf), LXP_EXEC_MAXENVS,
			   &envc, NULL);
	if (vr < 0)
		return vr;
	cap->envc = envc;
	char execabs[LXP_PATH_MAX];
	long rr = resolve_path(p, path, execabs, sizeof(execabs));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_NETFS_EXEC
	/* Exec a program off the remote mount (/mnt/pi/prog): capture argv and
	 * park the ELF fetch. CLOEXEC is deliberately deferred until the fetched
	 * image reaches the coordinator's exec commit point. */
	if (lxp_netfs_lookup(execabs) >= 0) {
		cap->argc = raw_argc;
		return lxp_netfs_exec_fetch(p, execabs); /* parks, or a negative errno inline */
	}
#endif
	int idx;
	if (strcmp(execabs, "/proc/self/exe") == 0) {
		/* BusyBox re-execs its own image via execv("/proc/self/exe", argv) on NOMMU
		 * — httpd (and any vfork+re-exec server) does this per connection. Re-run the
		 * caller's current program image (kept in exec_file_idx across relaunches). */
		idx = p->exec_file_idx;
		if (idx < 0 || idx >= p->fs_count)
			return -LXP_ENOENT;
	} else {
		/* Follow symlinks, e.g. /bin/echo -> busybox (Buildroot installs applets as
		 * symlinks). The argv (argv[0] = "echo") is kept, so busybox runs that applet. */
		idx = fs_follow(p, fs_lookup(p, execabs));
		if (idx < 0)
			return -LXP_ENOENT;
	}
	if ((file_mode(&p->fs[idx]) & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EACCES;

	/* Interpreter scripts: a "#!interp [arg]" first line re-targets the exec to
	 * the interpreter, with argv = [interp, arg?, scriptpath, original argv[1:]].
	 * init runs /etc/init.d/rcS (a #!/bin/sh script) this way. */
	const lxp_file_t *f = &p->fs[idx];
	lxp_script_spec_t script;
	int script_rc = lxp_script_parse(f->data, f->size, &script);
	if (script_rc < 0)
		return script_rc;
	int interp_idx = -1;
	if (script_rc == LXP_SCRIPT_PRESENT) {
		char interpabs[LXP_PATH_MAX];
		/* _trusted, not resolve_path(): interp was copied out of the script's
		 * own bytes into this stack buffer, so it is not a guest pointer and
		 * resolve_path()'s lxp_guest_strnlen guard rejects it -EFAULT. That made
		 * every #! script unrunnable — BusyBox init's /etc/init.d/rcS included. */
		if (resolve_path_trusted(script.interpreter, interpabs, sizeof(interpabs)) < 0)
			return -LXP_ENOENT;
		interp_idx = fs_follow(p, fs_lookup(p, interpabs));
		if (interp_idx < 0)
			return -LXP_ENOENT;
	}

	int argc = raw_argc;
	if (interp_idx >= 0) {
		long ar = exec_rewrite_script_argv(cap, raw_argc, raw_argbytes, script.interpreter,
						   script.argument, script.has_argument, execabs,
						   &argc);
		if (ar < 0)
			return ar;
		idx = interp_idx;
	}
	/* Refuse a wrong-ABI (hard-float) image before committing, so the caller gets a clean ENOEXEC
	 * and its shell keeps running — the loader would otherwise reject it only at launch, which
	 * terminates the caller. idx is the image that actually runs (the interpreter for a #! script);
	 * a remote-mount exec took the early netfs path above and is caught by the loader instead. */
	if (lxp_loader_abi_incompatible(p->fs[idx].data, p->fs[idx].size))
		return -LXP_ENOEXEC;
	/* close-on-exec: the fd table survives execve (the run loop preserves it), so drop the
	 * FD_CLOEXEC fds here — the exec is committed past every error check. dropbear confirms
	 * the shell exec'd by its exec-status pipe (FD_CLOEXEC) closing this way. */
	if (lxp_proc_files_unshare(p) != 0)
		return -LXP_ENOMEM;
	lxp_fd_close_on_exec(p);
	cap->argc = argc;
	p->exec_file_idx = idx;
	if (lxp_intent_begin(p, &(lxp_intent_t){.kind = LXP_INTENT_EXEC}) != 0)
		return -LXP_EAGAIN;
	return 0;
}

/* ---- syscall handlers: (proc, the six argument registers) → result ---------- */

/* (path, argv, envp) */
static long sc_execve(lxp_proc_t *proc, const long a[6])
{
	return sys_execve(proc, (const char *)(uintptr_t)a[0], (char *const *)(uintptr_t)a[1],
			  (char *const *)(uintptr_t)a[2]);
}

static long sc_rt_sigaction(lxp_proc_t *proc, const long a[6])
{
	/* Record the per-signal disposition; the engine seam delivers it.
	 * struct sigaction: sa_handler@0, sa_flags@4, sa_restorer@8. */
	int sig = (int)a[0];
	if (sig < 1 || sig >= LXP_NSIG)
		return -LXP_EINVAL;
	const uint32_t *act = (const uint32_t *)(uintptr_t)a[1];
	uint32_t *oact = (uint32_t *)(uintptr_t)a[2];
	if (act && !lxp_guest_access_ok(proc, act, 3 * sizeof(uint32_t), 0))
		return -LXP_EFAULT;
	if (oact && !lxp_guest_access_ok(proc, oact, 3 * sizeof(uint32_t), 1))
		return -LXP_EFAULT;
	if (oact) {
		oact[0] = (uint32_t)lxp_sig_handler_get(proc, sig);
		oact[2] = (uint32_t)lxp_sig_restorer_get(proc);
	}
	if (act) {
		proc->sighand->handler[sig] = act[0];
		proc->sighand->restorer = act[2];
	}
	return 0;
}

/* (nfds, readfds, writefds, exceptfds, timeout, sigmask) */
static long sc_pselect6_time64(lxp_proc_t *proc, const long a[6])
{
	return lxp_sys_pselect6(proc, (int)a[0], (uintptr_t)a[1], (uintptr_t)a[2], (uintptr_t)a[3],
				(uintptr_t)a[4]);
}

static long sc_poll(lxp_proc_t *proc, const long a[6])
{
	return lxp_sys_poll(proc, LXP_NR_poll, a[0], a[1], a[2]);
}

static long sc_ppoll_time64(lxp_proc_t *proc, const long a[6])
{
	return lxp_sys_poll(proc, LXP_NR_ppoll_time64, a[0], a[1], a[2]);
}
/* (unewset, sigsetsize) */
static long sc_rt_sigsuspend(lxp_proc_t *proc, const long a[6])
{
	/* LinuxThreads suspend(): block until a signal (the restart) is delivered. If one is
	 * already pending (a restart that beat us here), fall through so the dispatch delivers
	 * it now; otherwise ask the run loop to park us — the coordinator runs the handler on
	 * the restart kill() and resumes us. sigsuspend always "returns" -EINTR.
	 *
	 * INSTALL the mask arg (POSIX: atomically set the signal mask for the wait): the whole
	 * point of the restart protocol is that the caller BLOCKS the restart signal normally and
	 * sigsuspend UNBLOCKS it only while waiting. If we ignore the mask, the restart stays
	 * blocked, the coordinator's pending_deliverable skips it, and the parked thread is never
	 * woken (deadlock — curl's LinuxThreads resolver: manager, main, and a sigwait thread all
	 * stuck). The prior mask is restored when the delivered handler returns (sig_restore). */
	const uint32_t *uset = (const uint32_t *)(uintptr_t)a[0];
	size_t sz = (size_t)a[1];
	if (sz != 8)
		return -LXP_EINVAL; /* Linux: sigsetsize must equal sizeof(kernel sigset_t) */
	if (!uset || !lxp_guest_access_ok(proc, uset, sz, 0))
		return -LXP_EFAULT; /* validate the whole 8-byte mask before reading either word */
	uint64_t m = (uint64_t)uset[0] | ((uint64_t)uset[1] << 32);
	m &= ~(lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGSTOP)); /* never blockable */
	proc->sigsuspend_saved_mask = proc->sig_blocked;
	proc->sig_blocked = m;
	proc->sigsuspend_active = 1;
	/* Park unless a signal that is deliverable UNDER THE NEW MASK is already pending — then
	 * fall through so the dispatch delivers it now. A signal pending but blocked by the new
	 * mask must NOT keep us running (it stays pending until the mask is restored). Mirrors
	 * the run loop's pending_deliverable, which is static there. */
	int deliverable = 0;
	for (int sig = 1; sig < LXP_NSIG; sig++)
		if ((proc->pending_sigs & lxp_sig_bit(sig)) &&
		    !lxp_sig_blocked(proc, sig)) {
			deliverable = 1;
			break;
		}
	if (!deliverable) {
		lxp_wait_t wait = {.kind = LXP_WAIT_SIGSUSPEND};
		if (lxp_wait_begin(proc, &wait) != 0)
			return -LXP_EAGAIN;
	}
	return -LXP_EINTR;
}

/* (set, info, timeout, sigsetsize) */
static long sc_rt_sigtimedwait_time64(lxp_proc_t *proc, const long a[6])
{
	/* Poll variant: return a pending signal that is in `set` (dequeuing it), else report
	 * a timeout. Blocking for the timeout is not modeled — this is enough for libc/shell
	 * startup, which drains pending signals with sigtimedwait and must see -EAGAIN (not
	 * -ENOSYS) to finish and continue to the interactive read. */
	const uint32_t *uset = (const uint32_t *)(uintptr_t)a[0];
	size_t sz = (size_t)a[3];
	if (sz > 8)
		return -LXP_EINVAL;
	uint64_t set = 0;
	if (uset) {
		if (!lxp_guest_access_ok(proc, uset, sz, 0))
			return -LXP_EFAULT;
		if (sz >= 4)
			set |= (uint64_t)uset[0];
		if (sz >= 8)
			set |= (uint64_t)uset[1] << 32;
	}
	uint64_t ready = proc->pending_sigs & set;
	if (ready) {
		int sig = __builtin_ctzll(ready) + 1; /* lowest pending signal in the set */
		proc->pending_sigs &= ~lxp_sig_bit(sig);
		(void)a[1]; /* siginfo output omitted; the return value carries the signo */
		return sig;
	}
	return -LXP_EAGAIN;
}

/* (how, set, oldset, sigsetsize) */
static long sc_rt_sigprocmask(lxp_proc_t *proc, const long a[6])
{
	int how = (int)a[0];
	const uint32_t *uset = (const uint32_t *)(uintptr_t)a[1];
	uint32_t *uold = (uint32_t *)(uintptr_t)a[2];
	size_t sz = (size_t)a[3]; /* bytes of the guest sigset_t (8 for the 64-bit mask) */
	if (sz > 8)
		return -LXP_EINVAL;
	if (uset && !lxp_guest_access_ok(proc, uset, sz, 0))
		return -LXP_EFAULT;
	if (uold && !lxp_guest_access_ok(proc, uold, sz, 1))
		return -LXP_EFAULT;
	/* Read the new set BEFORE writing oldset — the guest may alias them, the legal
	 * sigprocmask(SIG_SETMASK, &m, &m) swap — and validate `how` up front so an invalid
	 * value has no side effects. */
	uint64_t nv = 0;
	if (uset) {
		if (how != LXP_SIG_BLOCK && how != LXP_SIG_UNBLOCK &&
		    how != LXP_SIG_SETMASK)
			return -LXP_EINVAL;
		if (sz >= 4)
			nv |= (uint64_t)uset[0];
		if (sz >= 8)
			nv |= (uint64_t)uset[1] << 32;
	}
	uint64_t old = proc->sig_blocked;
	if (uold) { /* report the previous mask, low word then high, within sigsetsize */
		if (sz >= 4)
			uold[0] = (uint32_t)old;
		if (sz >= 8)
			uold[1] = (uint32_t)(old >> 32);
	}
	if (uset) {
		proc->sig_blocked = how == LXP_SIG_BLOCK     ? old | nv
				    : how == LXP_SIG_UNBLOCK ? old & ~nv
							     : nv; /* LXP_SIG_SETMASK */
		/* SIGKILL and SIGSTOP can never be blocked. */
		proc->sig_blocked &= ~(lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGSTOP));
	}
	return 0;
}

/* futex / futex_time64 are intercepted by the coordinator (src/lxp_run.c, lxp_futex):
 * a co-running thread's WAIT parks on the uaddr and a peer's WAKE resumes it. They
 * never reach the dispatcher. */

#if LXP_ENABLE_NET
/* (domain, type, protocol) */
static long sc_socket(lxp_proc_t *proc, const long a[6])
{
	long oi = lxp_sock_new((int)a[0], (int)a[1], (int)a[2]);
	if (oi < 0)
		return oi;
	/* SOCK_NONBLOCK / SOCK_CLOEXEC share O_NONBLOCK / O_CLOEXEC's values. */
	int fd = lxp_sys_fd_alloc(proc, LXP_FD_SOCKET, (int)oi, 0,
			  LXP_O_RDWR | ((int)a[1] & (LXP_O_NONBLOCK | LXP_O_CLOEXEC)));
	if (fd < 0) {
		lxp_sock_close((int)oi);
		return -LXP_EMFILE;
	}
	return fd;
}

/* (fd, addr, addrlen) */
static long sc_connect(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_connect(proc, oi, (const void *)(uintptr_t)a[1], (unsigned)a[2]);
}

/* send/sendto on socket fd a[0]; @p dest/@p destlen are sendto's address. */
static long sock_send_common(lxp_proc_t *proc, const long a[6], const void *dest,
			     unsigned destlen)
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_send(proc, oi, (const void *)(uintptr_t)a[1], (size_t)a[2], (int)a[3], dest,
			     destlen);
}

/* (fd, buf, len, flags) */
static long sc_send(lxp_proc_t *proc, const long a[6])
{
	return sock_send_common(proc, a, NULL, (unsigned)a[5]);
}

/* (fd, buf, len, flags, dest, destlen) */
static long sc_sendto(lxp_proc_t *proc, const long a[6])
{
	return sock_send_common(proc, a, (const void *)(uintptr_t)a[4], (unsigned)a[5]);
}
/* recv/recvfrom on socket fd a[0]; @p src/@p srclen are recvfrom's address out. */
static long sock_recv_common(lxp_proc_t *proc, const long a[6], void *src, void *srclen)
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_recv(proc, oi, (void *)(uintptr_t)a[1], (size_t)a[2], (int)a[3], src,
			     srclen);
}

/* (fd, buf, len, flags) */
static long sc_recv(lxp_proc_t *proc, const long a[6])
{
	return sock_recv_common(proc, a, NULL, NULL);
}

/* (fd, buf, len, flags, src, srclen) */
static long sc_recvfrom(lxp_proc_t *proc, const long a[6])
{
	return sock_recv_common(proc, a, (void *)(uintptr_t)a[4], (void *)(uintptr_t)a[5]);
}
/* (fd, how) */
static long sc_shutdown(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_shutdown(oi, (int)a[1]);
}

/* (fd, addr, addrlen) */
static long sc_getsockname(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_getsockname(proc, oi, (void *)(uintptr_t)a[1], (void *)(uintptr_t)a[2]);
}

/* (fd, addr, addrlen) */
static long sc_getpeername(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_getpeername(proc, oi, (void *)(uintptr_t)a[1], (void *)(uintptr_t)a[2]);
}

/* (fd, level, optname, optval, optlen) */
static long sc_setsockopt(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_setsockopt(proc, oi, (int)a[1], (int)a[2], (const void *)(uintptr_t)a[3],
				   (unsigned)a[4]);
}

/* (fd, level, optname, optval, optlen) */
static long sc_getsockopt(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_getsockopt(proc, oi, (int)a[1], (int)a[2], (void *)(uintptr_t)a[3],
				   (void *)(uintptr_t)a[4]);
}

/* (fd, addr, addrlen) */
static long sc_bind(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_bind(proc, oi, (const void *)(uintptr_t)a[1], (unsigned)a[2]);
}

/* (fd, backlog) */
static long sc_listen(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_listen(oi, (int)a[1]);
}

/* accept/accept4 on socket fd a[0] with accept4's @p flags. */
static long sock_accept_common(lxp_proc_t *proc, const long a[6], int flags)
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return lxp_sock_accept(proc, oi, (void *)(uintptr_t)a[1], (void *)(uintptr_t)a[2], flags);
}

/* (fd, addr, addrlen) */
static long sc_accept(lxp_proc_t *proc, const long a[6])
{
	return sock_accept_common(proc, a, 0);
}

/* (fd, addr, addrlen, flags) */
static long sc_accept4(lxp_proc_t *proc, const long a[6])
{
	return sock_accept_common(proc, a, (int)a[3]);
}
/* (fd, msghdr, flags) */
static long sc_sendmsg(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return sys_sendmsg(proc, oi, (const lxp_msghdr *)(uintptr_t)a[1], (int)a[2]);
}

/* (fd, msghdr, flags) */
static long sc_recvmsg(lxp_proc_t *proc, const long a[6])
{
	int oi = sock_slot(proc, (int)a[0]);
	if (oi < 0)
		return -LXP_ENOTSOCK;
	return sys_recvmsg(proc, oi, (lxp_msghdr *)(uintptr_t)a[1], (int)a[2]);
}

/* fd-passing (SCM_RIGHTS) unsupported */
static long sc_socketpair(lxp_proc_t *proc, const long a[6])
{
	(void)a;
	(void)proc;
	return -LXP_EOPNOTSUPP;
}

#endif /* LXP_ENABLE_NET */

/* ---- the syscall table ------------------------------------------------------
 * One row per syscall the dispatcher answers, indexed by number, with its flags
 * (LXP_SYS_*, lxp_syscall.h); a row without a handler is ENOSYS. The coordinator
 * answers futex and get/setpriority itself, before dispatch. */

struct lxp_sys_entry {
	long (*fn)(lxp_proc_t *proc, const long a[6]);
	uint8_t flags;
};

/* One past the highest syscall number (faccessat2); a row beyond it fails to compile. */
#define LXP_SYS_TABLE_SIZE (LXP_NR_faccessat2 + 1)

static const struct lxp_sys_entry g_lxp_sys_table[LXP_SYS_TABLE_SIZE] = {
	[LXP_NR_read] = {lxp_sys_read, LXP_SYS_CLAMP_A2},
	[LXP_NR_write] = {lxp_sys_write, LXP_SYS_CLAMP_A2},
	[LXP_NR_writev] = {lxp_sys_writev, 0},
	[LXP_NR_brk] = {lxp_sys_brk, 0},
	[LXP_NR_mmap2] = {lxp_sys_mmap2, 0},
	[LXP_NR_munmap] = {lxp_sys_munmap, 0},
	[LXP_NR_mprotect] = {lxp_sys_mprotect, LXP_SYS_FAST},
	[LXP_NR_pread64] = {lxp_sys_pread64, LXP_SYS_CLAMP_A2_FILE},
	[LXP_NR_pwrite64] = {lxp_sys_pwrite64, LXP_SYS_CLAMP_A2_FILE},
	[LXP_NR_open] = {lxp_sys_open, 0},
	[LXP_NR_execve] = {sc_execve, 0},
	[LXP_NR_openat] = {lxp_sys_openat, 0},
	[LXP_NR_close] = {lxp_sys_close, 0},
	[LXP_NR_pipe] = {lxp_sys_pipe, 0},
	[LXP_NR_pipe2] = {lxp_sys_pipe2, 0},
	[LXP_NR_dup] = {lxp_sys_dup, 0},
	[LXP_NR_dup2] = {lxp_sys_dup2, 0},
	[LXP_NR_dup3] = {lxp_sys_dup3, 0},
	[LXP_NR_lseek] = {lxp_sys_lseek, 0},
	[LXP_NR__llseek] = {lxp_sys_llseek, 0},
	[LXP_NR_ftruncate64] = {lxp_sys_ftruncate64, 0},
	[LXP_NR_fsync] = {lxp_sys_fsync, 0},
	[LXP_NR_fdatasync] = {lxp_sys_fsync, 0},
	[LXP_NR_sync] = {lxp_sys_sync, 0},
	[LXP_NR_syncfs] = {lxp_sys_syncfs, 0},
	[LXP_NR_fstat64] = {lxp_sys_fstat64, 0},
	[LXP_NR_stat64] = {lxp_sys_stat64, 0},
	[LXP_NR_lstat64] = {lxp_sys_lstat64, 0},
	[LXP_NR_fstatat64] = {lxp_sys_fstatat64, 0},
	[LXP_NR_readlink] = {lxp_sys_readlink, 0},
	[LXP_NR_readlinkat] = {lxp_sys_readlinkat, 0},
	[LXP_NR_access] = {lxp_sys_access, 0},
	[LXP_NR_faccessat] = {lxp_sys_faccessat, 0},
	[LXP_NR_faccessat2] = {lxp_sys_faccessat, 0},
	[LXP_NR_mkdir] = {lxp_sys_mkdir, 0},
	[LXP_NR_mkdirat] = {lxp_sys_mkdirat, 0},
	[LXP_NR_rmdir] = {lxp_sys_rmdir, 0},
	[LXP_NR_unlink] = {lxp_sys_unlink, 0},
	[LXP_NR_unlinkat] = {lxp_sys_unlinkat, 0},
	[LXP_NR_rename] = {lxp_sys_rename, 0},
	[LXP_NR_renameat] = {lxp_sys_renameat, 0},
	[LXP_NR_renameat2] = {lxp_sys_renameat2, 0},
	[LXP_NR_symlink] = {lxp_sys_symlink, 0},
	[LXP_NR_symlinkat] = {lxp_sys_symlinkat, 0},
	[LXP_NR_link] = {lxp_sys_link, 0},
	[LXP_NR_linkat] = {lxp_sys_linkat, 0},
	[LXP_NR_chmod] = {lxp_sys_chmod, 0},
	[LXP_NR_fchmodat] = {lxp_sys_fchmodat, 0},
	[LXP_NR_utimensat] = {lxp_sys_utimensat, 0},
	[LXP_NR_utimensat_time64] = {lxp_sys_utimensat, 0},
	[LXP_NR_mount] = {lxp_sys_mount, 0},
	[LXP_NR_umount2] = {lxp_sys_umount2, 0},
	[LXP_NR_statfs64] = {lxp_sys_statfs64, 0},
	[LXP_NR_fstatfs64] = {lxp_sys_fstatfs64, 0},
	[LXP_NR_getrandom] = {lxp_sys_getrandom, LXP_SYS_CLAMP_A1},
	[LXP_NR_eventfd2] = {lxp_sys_eventfd2, 0},
	[LXP_NR_sysinfo] = {lxp_sys_sysinfo, 0},
	[LXP_NR_fcntl] = {lxp_sys_fcntl, 0},
	[LXP_NR_fcntl64] = {lxp_sys_fcntl, 0},
	[LXP_NR_getdents] = {lxp_sys_getdents, LXP_SYS_CLAMP_A2},
	[LXP_NR_getdents64] = {lxp_sys_getdents64, LXP_SYS_CLAMP_A2},
	[LXP_NR_statx] = {lxp_sys_statx, 0},
	[LXP_NR_exit] = {lxp_sys_exit, LXP_SYS_FAST},
	[LXP_NR_exit_group] = {lxp_sys_exit_group, LXP_SYS_FAST},
	[LXP_NR_getpid] = {lxp_sys_getpid, LXP_SYS_FAST},
	[LXP_NR_nice] = {lxp_sys_nice, LXP_SYS_FAST},
	[LXP_NR_getppid] = {lxp_sys_getppid, LXP_SYS_FAST},
	[LXP_NR_getcwd] = {lxp_sys_getcwd, 0},
	[LXP_NR_chdir] = {lxp_sys_chdir, 0},
	[LXP_NR_umask] = {lxp_sys_umask, LXP_SYS_FAST},
	[LXP_NR_setpgid] = {lxp_sys_setpgid, LXP_SYS_FAST},
	[LXP_NR_prctl] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_sched_yield] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_fchmod] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_fchown32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_chown32] = {lxp_sys_inert, 0},
	[LXP_NR_setgroups32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_setuid32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_setgid32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_setreuid32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_setregid32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_setresuid32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_setresgid32] = {lxp_sys_inert, LXP_SYS_FAST},
	[LXP_NR_getresuid32] = {lxp_sys_getresid, 0},
	[LXP_NR_getresgid32] = {lxp_sys_getresid, 0},
	[LXP_NR_prlimit64] = {lxp_sys_prlimit64, 0},
	[LXP_NR_times] = {lxp_sys_times, 0},
	[LXP_NR_setitimer] = {lxp_sys_setitimer, 0},
	[LXP_NR_getpgrp] = {lxp_sys_getpgrp, LXP_SYS_FAST},
	[LXP_NR_setsid] = {lxp_sys_setsid, LXP_SYS_FAST},
	[LXP_NR_reboot] = {lxp_sys_reboot, LXP_SYS_FAST},
	[LXP_NR_gettid] = {lxp_sys_gettid, LXP_SYS_FAST},
	[LXP_NR_clock_gettime] = {lxp_sys_clock_gettime, 0},
	[LXP_NR_clock_gettime64] = {lxp_sys_clock_gettime64, 0},
	[LXP_NR_gettimeofday] = {lxp_sys_gettimeofday, 0},
	[LXP_NR_nanosleep] = {lxp_sys_nanosleep, 0},
	[LXP_NR_clock_nanosleep] = {lxp_sys_clock_nanosleep, 0},
	[LXP_NR_clock_nanosleep_time64] = {lxp_sys_clock_nanosleep_time64, 0},
	[LXP_NR_uname] = {lxp_sys_uname, 0},
	[LXP_NR_rt_sigaction] = {sc_rt_sigaction, 0},
	[LXP_NR_pselect6_time64] = {sc_pselect6_time64, 0},
	[LXP_NR_poll] = {sc_poll, 0},
	[LXP_NR_ppoll_time64] = {sc_ppoll_time64, 0},
	[LXP_NR_wait4] = {lxp_sys_wait4, 0},
	[LXP_NR_getuid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_geteuid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_getgid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_getegid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_ioctl] = {lxp_sys_ioctl, 0},
	[LXP_NR_rt_sigsuspend] = {sc_rt_sigsuspend, 0},
	[LXP_NR_rt_sigtimedwait_time64] = {sc_rt_sigtimedwait_time64, 0},
	[LXP_NR_rt_sigprocmask] = {sc_rt_sigprocmask, 0},
	[LXP_NR_set_tid_address] = {lxp_sys_set_tid_address, LXP_SYS_FAST},
	[LXP_NR_set_robust_list] = {lxp_sys_set_robust_list, LXP_SYS_FAST},
#if LXP_ENABLE_NET
	[LXP_NR_socket] = {sc_socket, 0},
	[LXP_NR_connect] = {sc_connect, 0},
	[LXP_NR_send] = {sc_send, LXP_SYS_CLAMP_A2},
	[LXP_NR_sendto] = {sc_sendto, LXP_SYS_CLAMP_A2},
	[LXP_NR_recv] = {sc_recv, LXP_SYS_CLAMP_A2},
	[LXP_NR_recvfrom] = {sc_recvfrom, LXP_SYS_CLAMP_A2},
	[LXP_NR_shutdown] = {sc_shutdown, 0},
	[LXP_NR_getsockname] = {sc_getsockname, 0},
	[LXP_NR_getpeername] = {sc_getpeername, 0},
	[LXP_NR_setsockopt] = {sc_setsockopt, 0},
	[LXP_NR_getsockopt] = {sc_getsockopt, 0},
	[LXP_NR_bind] = {sc_bind, 0},
	[LXP_NR_listen] = {sc_listen, 0},
	[LXP_NR_accept] = {sc_accept, 0},
	[LXP_NR_accept4] = {sc_accept4, 0},
	[LXP_NR_sendmsg] = {sc_sendmsg, 0},
	[LXP_NR_recvmsg] = {sc_recvmsg, 0},
	[LXP_NR_socketpair] = {sc_socketpair, 0},
#else
	[LXP_NR_socket] = {NULL, LXP_SYS_QUIET_ENOSYS}, /* libc probes for networking */
#endif
};

unsigned lxp_syscall_flags(long nr)
{
	return nr >= 0 && nr < LXP_SYS_TABLE_SIZE ? g_lxp_sys_table[nr].flags : 0u;
}

long lxp_syscall(lxp_proc_t *proc, long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
#if LXP_ENABLE_FS
	lxp_hostfs_syscall_enter(proc, nr, a0, a1, a2, a3, a4, a5);
#endif
	if (!proc)
		return -LXP_EINVAL;
	if (nr < 0 || nr >= LXP_SYS_TABLE_SIZE || !g_lxp_sys_table[nr].fn)
		return -LXP_ENOSYS;
	const struct lxp_sys_entry *e = &g_lxp_sys_table[nr];
	long a[6] = {a0, a1, a2, a3, a4, a5};
	/* Cast via uint32_t: this is the 32-bit ARM syscall ABI even in host tests. */
	if ((e->flags & LXP_SYS_CLAMP_A1) && (uint32_t)a[1] > LXP_SYSCALL_QUANTUM_BYTES)
		a[1] = LXP_SYSCALL_QUANTUM_BYTES;
	if ((e->flags & LXP_SYS_CLAMP_A2) && (uint32_t)a[2] > LXP_SYSCALL_QUANTUM_BYTES)
		a[2] = LXP_SYSCALL_QUANTUM_BYTES;
	if ((e->flags & LXP_SYS_CLAMP_A2_FILE) && (uint32_t)a[2] > LXP_SYSCALL_FILE_QUANTUM_BYTES)
		a[2] = LXP_SYSCALL_FILE_QUANTUM_BYTES;
	return e->fn(proc, a);
}

