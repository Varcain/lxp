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


/* ---- syscall handlers: (proc, the six argument registers) → result ---------- */

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
/* futex / futex_time64 are intercepted by the coordinator (src/lxp_run.c, lxp_futex):
 * a co-running thread's WAIT parks on the uaddr and a peer's WAKE resumes it. They
 * never reach the dispatcher. */


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
	[LXP_NR_execve] = {lxp_sys_execve, 0},
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
	[LXP_NR_rt_sigaction] = {lxp_sys_rt_sigaction, 0},
	[LXP_NR_pselect6_time64] = {sc_pselect6_time64, 0},
	[LXP_NR_poll] = {sc_poll, 0},
	[LXP_NR_ppoll_time64] = {sc_ppoll_time64, 0},
	[LXP_NR_wait4] = {lxp_sys_wait4, 0},
	[LXP_NR_getuid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_geteuid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_getgid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_getegid32] = {lxp_sys_getuid_root, LXP_SYS_FAST},
	[LXP_NR_ioctl] = {lxp_sys_ioctl, 0},
	[LXP_NR_rt_sigsuspend] = {lxp_sys_rt_sigsuspend, 0},
	[LXP_NR_rt_sigtimedwait_time64] = {lxp_sys_rt_sigtimedwait_time64, 0},
	[LXP_NR_rt_sigprocmask] = {lxp_sys_rt_sigprocmask, 0},
	[LXP_NR_set_tid_address] = {lxp_sys_set_tid_address, LXP_SYS_FAST},
	[LXP_NR_set_robust_list] = {lxp_sys_set_robust_list, LXP_SYS_FAST},
#if LXP_ENABLE_NET
	[LXP_NR_socket] = {lxp_sys_socket, 0},
	[LXP_NR_connect] = {lxp_sys_connect, 0},
	[LXP_NR_send] = {lxp_sys_send, LXP_SYS_CLAMP_A2},
	[LXP_NR_sendto] = {lxp_sys_sendto, LXP_SYS_CLAMP_A2},
	[LXP_NR_recv] = {lxp_sys_recv, LXP_SYS_CLAMP_A2},
	[LXP_NR_recvfrom] = {lxp_sys_recvfrom, LXP_SYS_CLAMP_A2},
	[LXP_NR_shutdown] = {lxp_sys_shutdown, 0},
	[LXP_NR_getsockname] = {lxp_sys_getsockname, 0},
	[LXP_NR_getpeername] = {lxp_sys_getpeername, 0},
	[LXP_NR_setsockopt] = {lxp_sys_setsockopt, 0},
	[LXP_NR_getsockopt] = {lxp_sys_getsockopt, 0},
	[LXP_NR_bind] = {lxp_sys_bind, 0},
	[LXP_NR_listen] = {lxp_sys_listen, 0},
	[LXP_NR_accept] = {lxp_sys_accept, 0},
	[LXP_NR_accept4] = {lxp_sys_accept4, 0},
	[LXP_NR_sendmsg] = {lxp_sys_sendmsg, 0},
	[LXP_NR_recvmsg] = {lxp_sys_recvmsg, 0},
	[LXP_NR_socketpair] = {lxp_sys_socketpair, 0},
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

