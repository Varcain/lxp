/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_LINUX_UAPI_H
#define LXP_LINUX_UAPI_H

/**
 * @file lxp_linux_uapi.h
 * @brief Linux ARM EABI constants shared across the personality boundary.
 *
 * Keep syscall numbers independent of the mutable process representation.
 * Dispatchers, RTOS seams, tests, and conformance tooling can consume this
 * contract without acquiring ownership of @c lxp_proc_t internals.
 */

/* Linux ARM EABI syscall numbers implemented or classified by lxp. */
#define LXP_NR_exit 1
#define LXP_NR_fork 2
#define LXP_NR_read 3
#define LXP_NR_dup 41
#define LXP_NR_pipe 42
#define LXP_NR_pipe2 359
#define LXP_NR_fcntl 55
#define LXP_NR_dup2 63
#define LXP_NR_kill 37
#define LXP_NR_sigreturn 119
#define LXP_NR_sched_yield 158
#define LXP_NR_eventfd2 356
#define LXP_NR_dup3 358
#define LXP_NR_rt_sigreturn 173
#define LXP_NR_gettid 224
#define LXP_NR_tkill 238
#define LXP_NR_tgkill 268
#define LXP_NR_write 4
#define LXP_NR_open 5
#define LXP_NR_close 6
#define LXP_NR_chdir 12
#define LXP_NR_execve 11
#define LXP_NR_nice 34
#define LXP_NR_lseek 19
#define LXP_NR__llseek 140
#define LXP_NR_ftruncate64 194
#define LXP_NR_getpid 20
#define LXP_NR_setpgid 57
#define LXP_NR_getppid 64
#define LXP_NR_wait4 114
#define LXP_NR_uname 122
#define LXP_NR_poll 168
#define LXP_NR_pselect6_time64 413
#define LXP_NR_ppoll_time64 414
#define LXP_NR_brk 45
#define LXP_NR_ioctl 54
#define LXP_NR_munmap 91
#define LXP_NR_writev 146
#define LXP_NR_prctl 172
#define LXP_NR_rt_sigaction 174
#define LXP_NR_rt_sigprocmask 175
#define LXP_NR_rt_sigsuspend 179
#define LXP_NR_getcwd 183
#define LXP_NR_vfork 190
#define LXP_NR_mmap2 192
#define LXP_NR_mprotect 125 /* ld.so RELRO hardening — no-op on NOMMU */
#define LXP_NR_pread64 180  /* ld.so loads .so segments via positioned reads (NOMMU) */
#define LXP_NR_pwrite64 181 /* LVGL fbdev writes framebuffer scanlines via positioned writes */
#define LXP_NR_fstat64 197
#define LXP_NR_getuid32 199
#define LXP_NR_getgid32 200
#define LXP_NR_geteuid32 201
#define LXP_NR_getegid32 202
#define LXP_NR_getdents 141
#define LXP_NR_getdents64 217
#define LXP_NR_fcntl64 221
#define LXP_NR_exit_group 248
#define LXP_NR_set_tid_address 256
#define LXP_NR_openat 322
#define LXP_NR_set_robust_list 338
#define LXP_NR_futex 240
#define LXP_NR_futex_time64 422
#define LXP_NR_rt_sigtimedwait_time64 421
#define LXP_NR_statx 397

/* Path-based metadata: stat/lstat/readlink/access families. */
#define LXP_NR_access 33
#define LXP_NR_readlink 85
#define LXP_NR_stat64 195
#define LXP_NR_lstat64 196
#define LXP_NR_fstatat64 327
#define LXP_NR_readlinkat 332
#define LXP_NR_faccessat 334
#define LXP_NR_faccessat2 439

/* Time: clock_gettime / gettimeofday / nanosleep (+ time64 variants). */
#define LXP_NR_gettimeofday 78
#define LXP_NR_nanosleep 162
#define LXP_NR_clock_gettime 263
#define LXP_NR_clock_nanosleep 265
#define LXP_NR_clock_gettime64 403
#define LXP_NR_clock_nanosleep_time64 407

/* Writable filesystem mutation. */
#define LXP_NR_link 9
#define LXP_NR_unlink 10
#define LXP_NR_chmod 15
#define LXP_NR_rename 38
#define LXP_NR_mkdir 39
#define LXP_NR_rmdir 40
#define LXP_NR_symlink 83
#define LXP_NR_mkdirat 323
#define LXP_NR_unlinkat 328
#define LXP_NR_renameat 329
#define LXP_NR_linkat 330
#define LXP_NR_symlinkat 331
#define LXP_NR_fchmodat 333
#define LXP_NR_utimensat 348
#define LXP_NR_renameat2 382
#define LXP_NR_utimensat_time64 412

/* Mount/statfs/sysinfo and process/runtime support. */
#define LXP_NR_sysinfo 116
#define LXP_NR_mount 21
#define LXP_NR_umount2 52
#define LXP_NR_statfs64 266
#define LXP_NR_fstatfs64 267
#define LXP_NR_getrandom 384
#define LXP_NR_sync 36
#define LXP_NR_times 43
#define LXP_NR_fsync 118
#define LXP_NR_fdatasync 148
#define LXP_NR_syncfs 373
#define LXP_NR_prlimit64 369
#define LXP_NR_umask 60
#define LXP_NR_getpgrp 65
#define LXP_NR_setsid 66
#define LXP_NR_reboot 88
#define LXP_NR_getpriority 96
#define LXP_NR_setpriority 97
#define LXP_NR_fchmod 94
#define LXP_NR_setitimer 104
#define LXP_NR_clone 120
#define LXP_NR_setgroups32 206
#define LXP_NR_fchown32 207
#define LXP_NR_chown32 212
#define LXP_NR_setuid32 213
#define LXP_NR_setgid32 214
/* These identity calls are accepted as inert privilege drops on this tier. */
#define LXP_NR_setreuid32 203
#define LXP_NR_setregid32 204
#define LXP_NR_setresuid32 208
#define LXP_NR_getresuid32 209
#define LXP_NR_setresgid32 210
#define LXP_NR_getresgid32 211

/* Socket family (ARM EABI direct numbers; EABI does not use socketcall). */
#define LXP_NR_socket 281
#define LXP_NR_bind 282
#define LXP_NR_connect 283
#define LXP_NR_listen 284
#define LXP_NR_accept 285
#define LXP_NR_getsockname 286
#define LXP_NR_getpeername 287
#define LXP_NR_socketpair 288
#define LXP_NR_send 289
#define LXP_NR_sendto 290
#define LXP_NR_recv 291
#define LXP_NR_recvfrom 292
#define LXP_NR_shutdown 293
#define LXP_NR_setsockopt 294
#define LXP_NR_getsockopt 295
#define LXP_NR_sendmsg 296
#define LXP_NR_recvmsg 297
#define LXP_NR_accept4 366

#endif /* LXP_LINUX_UAPI_H */
