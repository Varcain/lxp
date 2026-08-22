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
 * @brief Immutable Linux ARM EABI constants and wire layouts.
 *
 * Keep target ABI definitions independent of the mutable process
 * representation. Dispatchers, providers, tests, and conformance tooling can
 * consume this contract without acquiring ownership of @c lxp_proc_t internals.
 */

#include <stddef.h>
#include <stdint.h>

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

/* clone(2) resource-sharing flags used by the bounded NOMMU task model. */
#define LXP_CLONE_VM 0x00000100u
#define LXP_CLONE_FS 0x00000200u
#define LXP_CLONE_FILES 0x00000400u
#define LXP_CLONE_SIGHAND 0x00000800u
#define LXP_CLONE_THREAD 0x00010000u

/* *at(2), mmap(2), and descriptor flags. */
#define LXP_AT_FDCWD (-100)
#define LXP_AT_SYMLINK_NOFOLLOW 0x100
#define LXP_AT_REMOVEDIR 0x200
#define LXP_AT_EMPTY_PATH 0x1000
#define LXP_MAP_ANONYMOUS 0x20
#define LXP_O_ACCMODE 0x3
#define LXP_O_RDONLY 0x0
#define LXP_O_WRONLY 0x1
#define LXP_O_RDWR 0x2
#define LXP_O_CREAT 0x40
#define LXP_O_EXCL 0x80
#define LXP_O_TRUNC 0x200
#define LXP_O_APPEND 0x400
#define LXP_O_NONBLOCK 0x800
#define LXP_O_DIRECTORY 0x4000
#define LXP_O_CLOEXEC 0x80000
#define LXP_FD_CLOEXEC 1
#define LXP_SEEK_SET 0
#define LXP_SEEK_CUR 1
#define LXP_SEEK_END 2

/* struct stat file types and getdents64 d_type values. */
#define LXP_S_IFMT 0xf000u
#define LXP_S_IFREG 0x8000u
#define LXP_S_IFDIR 0x4000u
#define LXP_S_IFBLK 0x6000u
#define LXP_S_IFCHR 0x2000u
#define LXP_S_IFLNK 0xa000u
#define LXP_S_IFSOCK 0xc000u
#define LXP_DT_CHR 2
#define LXP_DT_DIR 4
#define LXP_DT_BLK 6
#define LXP_DT_REG 8

/* termios and Unix98 pty ioctls used by the personality. */
#define LXP_TCGETS 0x5401
#define LXP_TCSETS 0x5402
#define LXP_TCSETSW 0x5403
#define LXP_TCSETSF 0x5404
#define LXP_TIOCGWINSZ 0x5413
#define LXP_TIOCSWINSZ 0x5414
#define LXP_TIOCGPTN 0x80045430u
#define LXP_TIOCSPTLCK 0x40045431u
#define LXP_TIOCGPTPEER 0x5441
#define LXP_TIOCSCTTY 0x540e
#define LXP_TIOCGPGRP 0x540f
#define LXP_TIOCSPGRP 0x5410
#define LXP_TIOCNOTTY 0x5422
#define LXP_ISIG 0x0001u
#define LXP_ICANON 0x0002u
#define LXP_ECHO 0x0008u
#define LXP_ICRNL 0x0100u
#define LXP_OPOST 0x0001u
#define LXP_ONLCR 0x0004u
#define LXP_CS8 0x0030u
#define LXP_CREAD 0x0080u
#define LXP_VINTR 0
#define LXP_VERASE 2
#define LXP_VEOF 4
#define LXP_VMIN 6
#define LXP_VSUSP 10
#define LXP_NCCS 19

/* Linux signal numbers and mask operations. */
#define LXP_NSIG 65
#define LXP_SIG_DFL 0
#define LXP_SIG_IGN 1
#define LXP_SIGINT 2
#define LXP_SIGQUIT 3
#define LXP_SIGABRT 6
#define LXP_SIGKILL 9
#define LXP_SIGSEGV 11
#define LXP_SIGPIPE 13
#define LXP_SIGALRM 14
#define LXP_SIGTERM 15
#define LXP_SIGCHLD 17
#define LXP_SIGCONT 18
#define LXP_SIGSTOP 19
#define LXP_SIGTSTP 20
#define LXP_SIGTTIN 21
#define LXP_SIGTTOU 22
#define LXP_SIGURG 23
#define LXP_SIGWINCH 28
#define LXP_SIG_BLOCK 0
#define LXP_SIG_UNBLOCK 1
#define LXP_SIG_SETMASK 2
#define LXP_ITIMER_REAL 0

/* fcntl(2), wait4(2), statx(2), eventfd2(2), and getrandom(2). */
#define LXP_F_DUPFD 0
#define LXP_F_GETFD 1
#define LXP_F_SETFD 2
#define LXP_F_GETFL 3
#define LXP_F_SETFL 4
#define LXP_F_DUPFD_CLOEXEC 1030
#define LXP_WNOHANG 1
#define LXP_WUNTRACED 2
#define LXP_WCONTINUED 8
#define LXP_STATX_BASIC_STATS 0x000007ffu
#define LXP_EFD_SEMAPHORE 0x00000001
#define LXP_EFD_NONBLOCK 0x00000800
#define LXP_EFD_CLOEXEC 0x00080000
#define LXP_GRND_NONBLOCK 0x0001u
#define LXP_GRND_RANDOM 0x0002u
#define LXP_GRND_INSECURE 0x0004u

/* Linux errno values returned negated by the syscall boundary. */
#define LXP_EPERM 1
#define LXP_ENOENT 2
#define LXP_ESRCH 3
#define LXP_EINTR 4
#define LXP_EIO 5
#define LXP_E2BIG 7
#define LXP_ENOEXEC 8
#define LXP_EBADF 9
#define LXP_ECHILD 10
#define LXP_EAGAIN 11
#define LXP_ENOMEM 12
#define LXP_EACCES 13
#define LXP_EFAULT 14
#define LXP_EBUSY 16
#define LXP_EEXIST 17
#define LXP_EXDEV 18
#define LXP_ENODEV 19
#define LXP_ENOTDIR 20
#define LXP_EISDIR 21
#define LXP_EINVAL 22
#define LXP_EMFILE 24
#define LXP_ENOTTY 25
#define LXP_EFBIG 27
#define LXP_ENOSPC 28
#define LXP_ESPIPE 29
#define LXP_EROFS 30
#define LXP_EPIPE 32
#define LXP_ERANGE 34
#define LXP_ENAMETOOLONG 36
#define LXP_ENOSYS 38
#define LXP_ENOTEMPTY 39
#define LXP_EOVERFLOW 75
#define LXP_ENOTSOCK 88
#define LXP_EMSGSIZE 90
#define LXP_EPROTONOSUPPORT 93
#define LXP_EOPNOTSUPP 95
#define LXP_EAFNOSUPPORT 97
#define LXP_EADDRINUSE 98
#define LXP_EADDRNOTAVAIL 99
#define LXP_ENETUNREACH 101
#define LXP_ECONNRESET 104
#define LXP_EISCONN 106
#define LXP_ENOTCONN 107
#define LXP_ETIMEDOUT 110
#define LXP_ECONNREFUSED 111
#define LXP_EHOSTUNREACH 113
#define LXP_EALREADY 114
#define LXP_EINPROGRESS 115
#define LXP_ESTALE 116

/** Scatter/gather element matching the target's struct iovec layout. */
typedef struct lxp_iovec {
	void *iov_base;
	size_t iov_len;
} lxp_iovec;

/** Target struct msghdr; ancillary data is not interpreted by LXP. */
typedef struct lxp_msghdr {
	void *msg_name;
	unsigned int msg_namelen;
	lxp_iovec *msg_iov;
	size_t msg_iovlen;
	void *msg_control;
	size_t msg_controllen;
	int msg_flags;
} lxp_msghdr;

/** Kernel struct termios for ARM (NCCS=19). */
typedef struct lxp_termios {
	uint32_t c_iflag;
	uint32_t c_oflag;
	uint32_t c_cflag;
	uint32_t c_lflag;
	uint8_t c_line;
	uint8_t c_cc[LXP_NCCS];
} lxp_termios;

typedef struct lxp_winsize {
	uint16_t ws_row;
	uint16_t ws_col;
	uint16_t ws_xpixel;
	uint16_t ws_ypixel;
} lxp_winsize;

typedef struct lxp_pollfd {
	int fd;
	short events;
	short revents;
} lxp_pollfd;

#define LXP_POLLIN 0x0001
#define LXP_POLLOUT 0x0004

#endif /* LXP_LINUX_UAPI_H */
