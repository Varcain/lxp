/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * execve: resolve and validate the program (#! scripts included), capture its
 * argument and environment vectors, and hand the coordinator an exec intent.
 */
#include "sys/lxp_sys.h"
#include "fs/lxp_fd_private.h"
#include "fs/lxp_path.h"
#include "fs/lxp_tmpfs.h"
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"
#include "lxp_loader.h"
#include "proc/lxp_script.h"
#if LXP_ENABLE_NETFS
#include "netfs/lxp_netfs.h"
#endif

#include <string.h>

/*
 * execve: resolve the program in the rootfs and capture its argument vector,
 * then flag the request. The coordinator and the per-engine seam do the actual image
 * replacement — load the FDPIC image, rebuild the memory domain + stack, and relaunch
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

/* (path, argv, envp) */
long lxp_sys_execve(lxp_proc_t *proc, const long a[6])
{
	return sys_execve(proc, (const char *)(uintptr_t)a[0], (char *const *)(uintptr_t)a[1],
			  (char *const *)(uintptr_t)a[2]);
}
