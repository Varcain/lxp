/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * The syscall handlers the table in src/lxp_syscall.c dispatches to, grouped by the
 * unit under src/sys/ (or subsystem) that implements them. Every handler takes the
 * calling process and its six argument registers and returns the Linux result.
 */
#ifndef LXP_SYS_H
#define LXP_SYS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_config.h"
#include "proc/lxp_proc.h"

/* ---- descriptors (src/sys/lxp_sys_fd.c) ---- */
int lxp_sys_fd_alloc(lxp_proc_t *p, uint8_t kind, int idx, size_t off, int flags);
long lxp_sys_fd_pread(lxp_proc_t *p, int fd, void *buf, size_t len, uint64_t off);
long lxp_sys_read(lxp_proc_t *proc, const long a[6]);
long lxp_sys_write(lxp_proc_t *proc, const long a[6]);
long lxp_sys_writev(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pread64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pwrite64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_close(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pipe(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pipe2(lxp_proc_t *proc, const long a[6]);
long lxp_sys_dup(lxp_proc_t *proc, const long a[6]);
long lxp_sys_dup2(lxp_proc_t *proc, const long a[6]);
long lxp_sys_dup3(lxp_proc_t *proc, const long a[6]);
long lxp_sys_lseek(lxp_proc_t *proc, const long a[6]);
long lxp_sys_llseek(lxp_proc_t *proc, const long a[6]);
long lxp_sys_ftruncate64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fsync(lxp_proc_t *proc, const long a[6]);
long lxp_sys_sync(lxp_proc_t *proc, const long a[6]);
long lxp_sys_syncfs(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fcntl(lxp_proc_t *proc, const long a[6]);
long lxp_sys_ioctl(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getdents(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getdents64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_eventfd2(lxp_proc_t *proc, const long a[6]);

/* ---- path names, stat and mounts (src/sys/lxp_sys_path.c) ---- */
long lxp_sys_open(lxp_proc_t *proc, const long a[6]);
long lxp_sys_openat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fstat64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_stat64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_lstat64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fstatat64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_statx(lxp_proc_t *proc, const long a[6]);
long lxp_sys_readlink(lxp_proc_t *proc, const long a[6]);
long lxp_sys_readlinkat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_access(lxp_proc_t *proc, const long a[6]);
long lxp_sys_faccessat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_mkdir(lxp_proc_t *proc, const long a[6]);
long lxp_sys_mkdirat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_rmdir(lxp_proc_t *proc, const long a[6]);
long lxp_sys_unlink(lxp_proc_t *proc, const long a[6]);
long lxp_sys_unlinkat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_rename(lxp_proc_t *proc, const long a[6]);
long lxp_sys_renameat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_renameat2(lxp_proc_t *proc, const long a[6]);
long lxp_sys_symlink(lxp_proc_t *proc, const long a[6]);
long lxp_sys_symlinkat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_link(lxp_proc_t *proc, const long a[6]);
long lxp_sys_linkat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_chmod(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fchmodat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_utimensat(lxp_proc_t *proc, const long a[6]);
long lxp_sys_mount(lxp_proc_t *proc, const long a[6]);
long lxp_sys_umount2(lxp_proc_t *proc, const long a[6]);
long lxp_sys_statfs64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_fstatfs64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getcwd(lxp_proc_t *proc, const long a[6]);
long lxp_sys_chdir(lxp_proc_t *proc, const long a[6]);

/* ---- memory (src/sys/lxp_sys_mm.c) ---- */
long lxp_sys_brk(lxp_proc_t *proc, const long a[6]);
long lxp_sys_mmap2(lxp_proc_t *proc, const long a[6]);
long lxp_sys_munmap(lxp_proc_t *proc, const long a[6]);
long lxp_sys_mprotect(lxp_proc_t *proc, const long a[6]);

/* ---- process and system (src/sys/lxp_sys_proc.c) ---- */
long lxp_sys_exit(lxp_proc_t *proc, const long a[6]);
long lxp_sys_exit_group(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getpid(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getppid(lxp_proc_t *proc, const long a[6]);
long lxp_sys_gettid(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getuid_root(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getresid(lxp_proc_t *proc, const long a[6]);
long lxp_sys_nice(lxp_proc_t *proc, const long a[6]);
long lxp_sys_umask(lxp_proc_t *proc, const long a[6]);
long lxp_sys_setpgid(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getpgrp(lxp_proc_t *proc, const long a[6]);
long lxp_sys_setsid(lxp_proc_t *proc, const long a[6]);
long lxp_sys_inert(lxp_proc_t *proc, const long a[6]);
long lxp_sys_prlimit64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_sysinfo(lxp_proc_t *proc, const long a[6]);
long lxp_sys_uname(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getrandom(lxp_proc_t *proc, const long a[6]);
long lxp_sys_reboot(lxp_proc_t *proc, const long a[6]);
long lxp_sys_wait4(lxp_proc_t *proc, const long a[6]);
long lxp_sys_set_tid_address(lxp_proc_t *proc, const long a[6]);
long lxp_sys_set_robust_list(lxp_proc_t *proc, const long a[6]);

/* ---- time (src/sys/lxp_sys_time.c) ---- */
long lxp_sys_clock_gettime(lxp_proc_t *proc, const long a[6]);
long lxp_sys_clock_gettime64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_gettimeofday(lxp_proc_t *proc, const long a[6]);
long lxp_sys_clock_settime(lxp_proc_t *proc, const long a[6]);
long lxp_sys_clock_settime64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_settimeofday(lxp_proc_t *proc, const long a[6]);
long lxp_sys_nanosleep(lxp_proc_t *proc, const long a[6]);
long lxp_sys_clock_nanosleep(lxp_proc_t *proc, const long a[6]);
long lxp_sys_clock_nanosleep_time64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_setitimer(lxp_proc_t *proc, const long a[6]);
long lxp_sys_times(lxp_proc_t *proc, const long a[6]);

/* ---- signals (src/sys/lxp_sys_signal.c) ---- */
long lxp_sys_rt_sigaction(lxp_proc_t *proc, const long a[6]);
long lxp_sys_rt_sigprocmask(lxp_proc_t *proc, const long a[6]);
long lxp_sys_rt_sigsuspend(lxp_proc_t *proc, const long a[6]);
long lxp_sys_rt_sigtimedwait_time64(lxp_proc_t *proc, const long a[6]);

/* ---- exec (src/sys/lxp_sys_exec.c) ---- */
long lxp_sys_execve(lxp_proc_t *proc, const long a[6]);

/* ---- sockets (src/net/lxp_net_sys.c) ---- */
long lxp_sys_socket(lxp_proc_t *proc, const long a[6]);
long lxp_sys_connect(lxp_proc_t *proc, const long a[6]);
long lxp_sys_send(lxp_proc_t *proc, const long a[6]);
long lxp_sys_sendto(lxp_proc_t *proc, const long a[6]);
long lxp_sys_recv(lxp_proc_t *proc, const long a[6]);
long lxp_sys_recvfrom(lxp_proc_t *proc, const long a[6]);
long lxp_sys_shutdown(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getsockname(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getpeername(lxp_proc_t *proc, const long a[6]);
long lxp_sys_setsockopt(lxp_proc_t *proc, const long a[6]);
long lxp_sys_getsockopt(lxp_proc_t *proc, const long a[6]);
long lxp_sys_bind(lxp_proc_t *proc, const long a[6]);
long lxp_sys_listen(lxp_proc_t *proc, const long a[6]);
long lxp_sys_accept(lxp_proc_t *proc, const long a[6]);
long lxp_sys_accept4(lxp_proc_t *proc, const long a[6]);
long lxp_sys_sendmsg(lxp_proc_t *proc, const long a[6]);
long lxp_sys_recvmsg(lxp_proc_t *proc, const long a[6]);
long lxp_sys_socketpair(lxp_proc_t *proc, const long a[6]);

/* ---- poll and select (src/fs/lxp_poll.c) ---- */
long lxp_sys_poll(lxp_proc_t *proc, const long a[6]);
long lxp_sys_ppoll_time64(lxp_proc_t *proc, const long a[6]);
long lxp_sys_pselect6_time64(lxp_proc_t *proc, const long a[6]);

#endif /* LXP_SYS_H */
