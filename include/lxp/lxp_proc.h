/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#ifndef LXP_PROC_H
#define LXP_PROC_H

/**
 * @file lxp_proc.h
 * @defgroup lxp_linux Linux personality
 * @ingroup lxp_mem
 * @brief Bounded Linux task, resource, and deferred-work state.
 *
 * The process core owns task identity, refcounted Linux resources, typed
 * coordinator intent/wait state, descriptor descriptions, and the bounded
 * NOMMU address space. RTOS seams do not include this mutable representation;
 * they consume generation-qualified identities and immutable memory-policy
 * snapshots through narrower contracts.
 *
 * @note Requires @c LXP_ENABLE_LINUX.
 * @{
 */

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_arena.h"
#include "lxp/lxp_exec.h"
#include "lxp/lxp_identity.h"
#include "lxp/lxp_linux_uapi.h"
#include "lxp/lxp_program.h"
#include "lxp/lxp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* clone(2) resource-sharing flags used by the bounded NOMMU task model. */
#define LXP_CLONE_VM 0x00000100u
#define LXP_CLONE_FS 0x00000200u
#define LXP_CLONE_FILES 0x00000400u
#define LXP_CLONE_SIGHAND 0x00000800u
#define LXP_CLONE_THREAD 0x00010000u
#define LXP_AT_REMOVEDIR 0x200

/* mmap flags (ARM). Only anonymous mappings are backed (from the arena). */
#define LXP_MAP_ANONYMOUS 0x20

/* open(2) flags: low two bits select the access mode (read-only filesystem). */
#define LXP_O_ACCMODE 0x3
#define LXP_O_RDONLY 0x0
#define LXP_O_WRONLY 0x1
#define LXP_O_RDWR 0x2
#define LXP_O_CREAT 0x40
#define LXP_O_EXCL 0x80
#define LXP_O_TRUNC 0x200
#define LXP_O_APPEND 0x400
#define LXP_O_NONBLOCK 0x800  /* a device open that returns -EAGAIN instead of blocking */
#define LXP_O_DIRECTORY 0x4000
#define LXP_O_CLOEXEC 0x80000 /* close-on-exec (also pipe2/dup3/accept4 flag) */
#define LXP_FD_CLOEXEC 1      /* fcntl(F_SETFD/F_GETFD) close-on-exec bit */
/* openat dirfd sentinel for the current working directory. */
#define LXP_AT_FDCWD (-100)
/* lseek(2) whence. */
#define LXP_SEEK_SET 0
#define LXP_SEEK_CUR 1
#define LXP_SEEK_END 2
/* struct stat st_mode file-type bits. */
#define LXP_S_IFMT 0xf000u
#define LXP_S_IFREG 0x8000u
#define LXP_S_IFDIR 0x4000u
#define LXP_S_IFBLK 0x6000u
#define LXP_S_IFCHR 0x2000u
#define LXP_S_IFLNK 0xa000u
#define LXP_S_IFSOCK 0xc000u
/* getdents64 d_type values. */
#define LXP_DT_CHR 2
#define LXP_DT_DIR 4
#define LXP_DT_BLK 6
#define LXP_DT_REG 8
/* termios ioctls so a console looks like a tty (isatty → interactive shell). */
#define LXP_TCGETS 0x5401
#define LXP_TCSETS 0x5402
#define LXP_TCSETSW 0x5403
#define LXP_TCSETSF 0x5404
#define LXP_TIOCGWINSZ 0x5413
#define LXP_TIOCSWINSZ 0x5414
/* Unix98 pty-master ioctls (dropbear/openpty on /dev/ptmx): get the pts number and
 * lock/unlock the slave (grantpt/unlockpt). _IOR/_IOW('T',0x30/0x31) encodings. */
#define LXP_TIOCGPTN 0x80045430u
#define LXP_TIOCSPTLCK 0x40045431u
#define LXP_TIOCGPTPEER 0x5441
/* tty/session ioctls getty + login issue (accepted; we are a single console). */
#define LXP_TIOCSCTTY 0x540e
#define LXP_TIOCGPGRP 0x540f
#define LXP_TIOCSPGRP 0x5410
#define LXP_TIOCNOTTY 0x5422
/* c_lflag/c_iflag/c_oflag/c_cflag bits used for the canonical-tty default. */
#define LXP_ISIG 0x0001u
#define LXP_ICANON 0x0002u
#define LXP_ECHO 0x0008u
#define LXP_ICRNL 0x0100u
#define LXP_OPOST 0x0001u
#define LXP_ONLCR 0x0004u
#define LXP_CS8 0x0030u
#define LXP_CREAD 0x0080u
/* Signals: a per-process disposition table + the handful the shell cares about.
 * SIG_DFL/SIG_IGN are the special handler sentinels. Must cover the POSIX RT signals
 * (SIGRTMIN..): LinuxThreads uses __SIGRTMIN (>=32) for its thread restart/cancel/debug
 * signals, so a 32-wide table would reject the restart kill() and hang every pthread. */
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
#define LXP_SIGCHLD 17	/* child stop/exit; default action = IGNORE (never terminates) */
#define LXP_SIGCONT 18	/* continue a stopped process; default action never terminates */
#define LXP_SIGSTOP 19	/* stop (job control); can never be caught or blocked */
#define LXP_SIGTSTP 20	/* stop from the tty (^Z); default action = stop */
#define LXP_SIGTTIN 21	/* background read from the tty; default action = stop */
#define LXP_SIGTTOU 22	/* background write to the tty; default action = stop */
#define LXP_SIGURG 23	/* urgent socket data; default action = IGNORE */
#define LXP_SIGWINCH 28 /* terminal resized; default action = IGNORE */

/* rt_sigprocmask(2) `how` values. */
#define LXP_SIG_BLOCK 0
#define LXP_SIG_UNBLOCK 1
#define LXP_SIG_SETMASK 2
#define LXP_ITIMER_REAL 0 /* setitimer(): real-time countdown -> SIGALRM */
/* fcntl commands: F_DUPFD duplicates an fd (the shell dups stdin for its
 * interactive fd); the rest are benign get/set probes. */
#define LXP_F_DUPFD 0
#define LXP_F_GETFD 1
#define LXP_F_SETFD 2
#define LXP_F_GETFL 3
#define LXP_F_SETFL 4
#define LXP_F_DUPFD_CLOEXEC 1030
/* c_cc indices (Linux generic, NCCS=19). */
#define LXP_VINTR 0
#define LXP_VERASE 2
#define LXP_VEOF 4
#define LXP_VMIN 6
#define LXP_VSUSP 10 /* ^Z suspend key */
#define LXP_NCCS 19

/* wait4/waitpid options. */
#define LXP_WNOHANG 1
#define LXP_WUNTRACED 2 /* also report children that stopped (job control) */
#define LXP_WCONTINUED 8

/* Ready-child queue entry kind (child_kind[]): an exited zombie vs a stop notification. */
#define LXP_CHILD_EXITED 0
#define LXP_CHILD_STOPPED 1

/* How a process entered the `stopped` state, for the SIGCONT resume path. */
#define LXP_STOP_NONE 0
#define LXP_STOP_PARKED \
	1 /* stopped while already host-parked; the existing wait/lifecycle owner retains it */
#define LXP_STOP_READY 2 /* saved slot context has a completed result and may resume on SIGCONT */
/* statx: AT_EMPTY_PATH means "stat the dirfd itself" (fstat); the basic-stats
 * result mask reported back in stx_mask. */
#define LXP_AT_EMPTY_PATH 0x1000
#define LXP_AT_SYMLINK_NOFOLLOW 0x100
#define LXP_STATX_BASIC_STATS 0x000007ffu

/* Linux errno values returned (negated) on syscall failure. */
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
#define LXP_EXDEV 18
#define LXP_ENODEV 19
#define LXP_ENOTDIR 20
#define LXP_EISDIR 21
#define LXP_EMFILE 24
#define LXP_ENOTTY 25
#define LXP_EFBIG 27
#define LXP_ESPIPE 29
#define LXP_EROFS 30
#define LXP_EPIPE 32
#define LXP_EEXIST 17
#define LXP_EINVAL 22
#define LXP_ENOSPC 28
#define LXP_ERANGE 34
#define LXP_ENAMETOOLONG 36
#define LXP_ENOTEMPTY 39
#define LXP_ENOSYS 38
#define LXP_EOVERFLOW 75
#define LXP_ETIMEDOUT 110 /* a futex wait whose timeout expired */
/* socket errnos (asm-generic values; ARM shares them). */
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
#define LXP_ECONNREFUSED 111
#define LXP_EHOSTUNREACH 113
#define LXP_EALREADY 114
#define LXP_EINPROGRESS 115
#define LXP_ESTALE 116 /* a remote-fs fid invalidated by a server reconnect */

/** Scatter/gather element, matching the target's @c struct iovec layout. */
typedef struct lxp_iovec {
	void *iov_base; /**< Start of the buffer (in the program's address space). */
	size_t iov_len; /**< Length of the buffer in bytes. */
} lxp_iovec;

/** Message header for sendmsg(2)/recvmsg(2), matching the target's @c struct msghdr.
 * Ancillary data (@c msg_control) is not interpreted — SCM_RIGHTS fd-passing is
 * unsupported — so only the iovec payload is carried. */
typedef struct lxp_msghdr {
	void *msg_name;		  /**< Optional address (datagram dest / source), or NULL. */
	unsigned int msg_namelen; /**< Length of @c msg_name (in, and out on recvmsg). */
	lxp_iovec *msg_iov;	  /**< Scatter/gather buffer array. */
	size_t msg_iovlen;	  /**< Entries in @c msg_iov. */
	void *msg_control;	  /**< Ancillary data (ignored). */
	size_t msg_controllen;	  /**< Length of @c msg_control (out: 0). */
	int msg_flags;		  /**< Flags (out: 0 on recvmsg). */
} lxp_msghdr;

/** Kernel @c struct termios (ARM, NCCS=19), filled by the TCGETS ioctl. */
typedef struct lxp_termios {
	uint32_t c_iflag;
	uint32_t c_oflag;
	uint32_t c_cflag;
	uint32_t c_lflag;
	uint8_t c_line;
	uint8_t c_cc[LXP_NCCS];
} lxp_termios;

/** @c struct winsize returned by TIOCGWINSZ. */
typedef struct lxp_winsize {
	uint16_t ws_row;
	uint16_t ws_col;
	uint16_t ws_xpixel;
	uint16_t ws_ypixel;
} lxp_winsize;

/** @c struct pollfd for poll(2). */
typedef struct lxp_pollfd {
	int fd;
	short events;
	short revents;
} lxp_pollfd;
#define LXP_POLLIN 0x0001
#define LXP_POLLOUT 0x0004

/** Refcounted open-file description shared by dup() and inherited descriptors. */
typedef struct lxp_ofd {
	uint16_t refs;	  /**< Number of descriptor-table entries referring to this object. */
	uint8_t kind;	  /**< 0 = free, 1 = console, 2 = rootfs file, 3 = pipe, 4 = tmpfs,
			*   5 = /proc, 6 = device (values 4-6 are private to the syscall +
			*   device layers; only FD_DEV is exported below). */
	uint8_t rw;	  /**< pipe end: 0 = read, 1 = write (kind == pipe). */
	uint8_t nonblock; /**< O_NONBLOCK: a pipe read/write returns -EAGAIN instead of parking
			   *   (dropbear's SIGCHLD self-pipe is drained with a non-blocking read
			   *   loop; without this the final empty read parks forever). */
	uint8_t accmode; /**< O_RDONLY/O_WRONLY/O_RDWR for regular provider-backed files. */
	int file_idx;  /**< rootfs index (file) / pipe index (pipe) / open-pool index (device). */
	size_t offset; /**< Read cursor (kind == file). */
} lxp_ofd_t;

/** One descriptor-table entry: descriptor-local flags plus an open-file description. */
typedef struct lxp_fd {
	uint16_t ofd;	 /**< Open-file-description pool index plus one; zero means free. */
	uint8_t cloexec; /**< FD_CLOEXEC / O_CLOEXEC (descriptor-local). */
	uint8_t _pad;
} lxp_fd_t;

/* fd kinds (lxp_fd_t.kind). Shared across the syscall dispatcher + the subsystem TUs
 * (pipe/tmpfs/proc/dev/socket/pty/netfs) that own the backing objects. */
#define LXP_FD_FREE 0	 /**< unused slot */
#define LXP_FD_CONSOLE 1 /**< stdio console (host write_fn/read_fn) */
#define LXP_FD_FILE 2  /**< read-only rootfs file; @c file_idx = rootfs index, @c offset = cursor */
#define LXP_FD_PIPE 3  /**< pipe end; @c file_idx = pipe-pool index, @c rw = 1 write end */
#define LXP_FD_TMPFS 4 /**< writable tmpfs node; @c file_idx = wnode index */
#define LXP_FD_PROC 5  /**< synthetic /proc file; @c file_idx = proc-fd backing index */
/** Device fd kind (shared by the syscall + device layers). @c file_idx = open-pool index. */
#define LXP_FD_DEV 6
/** Socket fd kind (shared by the syscall + socket layers). @c file_idx = open-pool index. */
#define LXP_FD_SOCKET 7
/** eventfd fd kind (thread wakeup counter). @c file_idx = eventfd-pool index. */
#define LXP_FD_EVENTFD 8
/** pty fd kind (pseudo-terminal). @c file_idx = pty-pool index; @c rw = 1 master, 0 slave. */
#define LXP_FD_PTY 9
/** remote-fs fd kind (9P mount, e.g. /mnt/pi). @c file_idx = netfs open-pool index. */
#define LXP_FD_NET 10
/** host-backed writable filesystem fd. @c file_idx = hostfs open-pool index. */
#define LXP_FD_HOSTFS 11
/* eventfd2(2) flags. */
#define LXP_EFD_SEMAPHORE 0x00000001
#define LXP_EFD_NONBLOCK 0x00000800
#define LXP_EFD_CLOEXEC 0x00080000

/** Maximum simultaneously-open file descriptors per process. A fork-per-connection
 * server (httpd) holds std streams + the listener + the accepted client, per proc. */
#define LXP_MAX_FDS 32
/** Maximum path length (absolute, normalized) the personality resolves. */
#define LXP_PATH_MAX 256

/** Refcounted Linux descriptor table. CLONE_FILES shares this object; ordinary
 * fork receives a private table whose entries refer to the same open-file
 * descriptions. */
typedef struct lxp_files {
	uint16_t refs;
	lxp_fd_t fd[LXP_MAX_FDS];
} lxp_files_t;

/** Refcounted filesystem context shared by CLONE_FS. */
typedef struct lxp_fs_context {
	uint16_t refs;
	unsigned short umask;
	char cwd[LXP_PATH_MAX];
} lxp_fs_context_t;

/** Refcounted signal dispositions shared by CLONE_SIGHAND. Signal masks and
 * pending signals remain task-local in @ref lxp_proc. */
typedef struct lxp_sighand {
	uint16_t refs;
	uintptr_t handler[LXP_NSIG];
	uintptr_t restorer;
} lxp_sighand_t;

/** Refcounted NOMMU address-space state. CLONE_VM shares this object; a
 * vfork-style child receives a logical copy while its task temporarily
 * references the same program region. */
typedef struct lxp_mm {
	uint16_t refs;
	uint16_t _pad;
	/** Logical device-capability and copied-text policy versions. Zero is
	 * reserved for an uninitialized/freed address space. */
	uint32_t device_generation;
	uint32_t exec_generation;
	lxp_arena_t *arena;
	uintptr_t brk_base;
	uintptr_t brk_cur;
	uintptr_t brk_max;
	lxp_region_ref_t region;
	uintptr_t region_lo, region_hi;
	uintptr_t pool_lo, pool_hi;
	int is_dynamic;
	uint8_t copied_text_executable;
	uint8_t _policy_pad[3];
	uintptr_t copied_text_base;
	size_t copied_text_size;
	uintptr_t dev_map_lo[2], dev_map_hi[2];
	unsigned dev_map_attrs[2];
} lxp_mm_t;

/** Max exited children queued for wait4 (a pipeline forks several). */
#define LXP_MAX_CHILD 8

/** Process-wide identity, job-control and child-reaping state. Tasks created
 * with CLONE_THREAD share this object; a new process gets a fresh object whose
 * parent and process-group identity are derived from its creator. */
typedef struct lxp_thread_group {
	uint16_t refs;
	uint16_t _pad;
	int tgid;
	int ppid;
	int pgid;
	int exiting;
	int exit_status;
	int child_pid[LXP_MAX_CHILD];
	int child_status[LXP_MAX_CHILD];
	uint8_t child_kind[LXP_MAX_CHILD];
	int child_count;
	int live_children;
} lxp_thread_group_t;
/** One coordinator action requested by a guest task. The discriminant makes
 * fork/exec/exit/deferred-syscall publication structurally exclusive. */
typedef enum lxp_intent_kind {
	LXP_INTENT_NONE = 0,
	LXP_INTENT_DEFERRED_SYSCALL,
	LXP_INTENT_FORK,
	LXP_INTENT_EXEC,
	LXP_INTENT_EXIT,
	LXP_INTENT_COUNT,
} lxp_intent_kind_t;

typedef struct lxp_intent {
	lxp_intent_kind_t kind;
	union {
		struct {
			uint32_t flags;
			uintptr_t child_stack;
		} fork;
		struct {
			uint8_t group;
		} exit;
	} data;
} lxp_intent_t;

/** Why a guest task is blocked. Exactly one tagged payload is live. */
typedef enum lxp_wait_kind {
	LXP_WAIT_NONE = 0,
	LXP_WAIT_TIMER,
	LXP_WAIT_CHILD,
	LXP_WAIT_FUTEX,
	LXP_WAIT_PIPE,
	LXP_WAIT_CONSOLE,
	LXP_WAIT_DEVICE,
	LXP_WAIT_SOCKET,
	LXP_WAIT_NETFS,
	LXP_WAIT_HOSTFS,
	LXP_WAIT_PTY,
	LXP_WAIT_SIGSUSPEND,
	LXP_WAIT_COUNT,
} lxp_wait_kind_t;

typedef struct lxp_wait {
	lxp_wait_kind_t kind;
	uint8_t op;    /**< Subsystem-specific LXP_*W_* operation. */
	uint8_t flags; /**< Wait-kind-specific flags (socket select currently uses bit 0). */
	uint16_t _pad;
	uint64_t enqueued_us; /**< Coordinator-service aging timestamp. */
	union {
		struct {
			uint64_t deadline_us;
		} timer;
		struct {
			int pid;
			int options;
			uintptr_t status;
		} child;
		struct {
			uintptr_t uaddr;
			uint64_t deadline_us;
			uint8_t woken;
		} futex;
		struct {
			int object;
			int request;
			uintptr_t buffer;
			size_t length;
			uint64_t offset;
			unsigned long command;
			uint64_t deadline_us;
		} io;
		struct {
			int object;
			int nfds;
			uintptr_t buffer;
			size_t length;
			uint64_t deadline_us;
			uintptr_t readfds;
			uintptr_t writefds;
			uintptr_t exceptfds;
		} socket;
		struct {
			intptr_t nr;
			intptr_t args[6];
			uint64_t owner;
		} hostfs;
	} data;
} lxp_wait_t;

/**
 * @brief A Linux task context — the per-slot state syscalls act on.
 *
 * NOMMU model: a bounded program break + anonymous mmap carved from an
 * @c lxp_arena_t, a small fd table over standard streams (caller callbacks) and a
 * read-only in-memory rootfs, and typed coordinator state. Process-wide state
 * is held by the refcounted mm, files, fs-context, sighand and thread-group
 * objects.
 */
typedef struct lxp_proc {
	struct lxp_guest_view *guest_view; /**< Active privileged dispatch view; never inherited. */
	lxp_mm_t *mm;			   /**< Refcounted address space, arena and mappings. */
	lxp_write_fn write_fn;		   /**< fd 1/2 sink; NULL → @c -LXP_EBADF. */
	lxp_read_fn read_fn;		   /**< fd 0 source; NULL → EOF. */
	int (*console_poll)(void *ctx); /**< Optional non-blocking "key available?" for poll(2). */
	void *io_ctx;			/**< Opaque, passed to @c write_fn / @c read_fn. */
	const lxp_file_t *fs;		/**< Read-only rootfs table (NULL → no files). */
	int fs_count;			/**< Number of entries in @c fs. */
	lxp_files_t *files;		/**< Refcounted descriptor table; 0/1/2 are std streams. */
	int pid;			/**< Linux task id (TID; 1 for the initial task). */
	int nice;			/**< Linux per-task nice value, clamped to [-20, 19]. */
	lxp_thread_group_t *group;    /**< Refcounted process identity, children and job control. */
	char comm[16];		      /**< Program name (argv[0] basename) for ps/top. */
	lxp_fs_context_t *fs_context; /**< Refcounted cwd + umask context. */
	int exit_status;	      /**< Low 8 bits of the exit code. */
	uint8_t exit_reason; /**< @c LXP_EXIT_REASON_* host-side termination attribution. */
	uint8_t exit_signal; /**< Signal number for SIGNAL / SIGNAL_DEPTH / MEMORY_FAULT. */
	uint16_t _exit_pad;
	uint32_t exit_detail;	/**< Port-defined fault status (0 for core-originated exits). */
	uintptr_t exit_address; /**< Port-defined fault address, when one is valid. */
	/* Job control: a stopped process stays alive with its host task parked until
	 * it takes SIGCONT. stop_kind records whether another park owner is still
	 * active or the saved context has a result ready to resume. */
	int stopped;	   /**< Non-zero while job-control-stopped (SIGSTOP/SIGTSTP). */
	uint8_t stop_kind; /**< LXP_STOP_PARKED / LXP_STOP_READY. */
	uint8_t stop_sig;  /**< The stop signal, for the WIFSTOPPED status word. */
	long stop_r0;	   /**< LXP_STOP_READY: result restored when SIGCONT resumes. */
	/* Signal disposition: per-signal handler address (or SIG_DFL/SIG_IGN). The
	 * sa_restorer the engine returns to after a handler is ONE value per proc, not one
	 * per signal — uClibc-ng installs the same __restore_rt trampoline for every signal
	 * — which saves ~3K of .bss across the slot table. */
	lxp_sighand_t *sighand; /**< Refcounted signal dispositions. */
	/* Blocked-signal mask (rt_sigprocmask): signals 1..64 map to bits 0..63. A pending
	 * signal whose bit is set is deferred at delivery until unblocked; a handler blocks
	 * its own signal for its duration (restored at rt_sigreturn). SIGKILL/SIGSTOP never. */
	uint64_t sig_blocked;
	/* rt_sigsuspend atomically installs a wait mask. The saved mask is restored
	 * after the caught signal handler returns. */
	uint64_t sigsuspend_saved_mask;
	int sigsuspend_active; /**< Wait mask installed; next caught signal frame consumes saved_mask. */
	/* The coordinator consumes at most one typed action and one typed blocking
	 * reason, preventing contradictory pending states. */
	lxp_intent_t intent;
	lxp_wait_t wait;
	/* execve request: the target image identity and capture outlive the intent
	 * while the coordinator relaunches the slot. */
	int exec_file_idx;		  /**< Rootfs index of the program to run. */
	lxp_exec_capture_t *exec_capture; /**< Port-owned capture, or NULL if exec is unavailable. */
	/* Concurrent process model: the run loop coordinates a live process set;
	 * incarnation, resume, and host lifecycle live in its private slot-runtime
	 * record. */
	int alive;		     /**< This slot holds a live process. */
	lxp_slot_ref_t vfork_parent; /**< Parent suspended awaiting this child's exec/exit. */
	/* vfork data isolation (NOMMU has no copy-on-write): a vfork child SHARES the parent's region,
	 * so its pre-exec writes (e.g. a libc signal-disposition reset) would corrupt the suspended
	 * parent. The coordinator snapshots the parent's writable data into a spare region at EV_FORK
	 * and restores it before the parent resumes (EV_EXEC/EV_EXIT). See vfork_snapshot/vfork_restore. */
	lxp_region_ref_t snapshot; /**< Scratch region holding the parent's data snapshot. */
	uintptr_t stack_lo; /**< Boundary between this proc's in-region writable data and its stack. */
	int is_fdpic; /**< Program is FDPIC: signal handlers/restorers are funcdescs {entry,GOT}. */
	/* kill(pid,sig) from another proc, or a coordinator-raised SIGCHLD/SIGALRM,
	 * latches here as a bitmask (bit sig-1); delivered lowest-first at
	 * this proc's next syscall boundary (if running) or by the coordinator (if parked). A set
	 * rather than a single slot so a signal blocked by sig_blocked can stay pending without a
	 * later signal overwriting it. 0 = none. */
	uint64_t pending_sigs;
	uint64_t alarm_deadline_us; /**< setitimer(ITIMER_REAL)/alarm() fire time; 0 = disarmed. */
	uint64_t alarm_interval_us; /**< Repeating interval (0 = one-shot); re-arms on fire. */
} lxp_proc_t;

/** Publish one action/wait. A second live record fails with @c -LXP_EAGAIN. */
int lxp_intent_begin(lxp_proc_t *proc, const lxp_intent_t *intent);
int lxp_intent_complete(lxp_proc_t *proc, lxp_intent_kind_t expected);
int lxp_intent_exit(lxp_proc_t *proc, int group);
int lxp_wait_begin(lxp_proc_t *proc, const lxp_wait_t *wait);
int lxp_wait_complete(lxp_proc_t *proc, lxp_wait_kind_t expected);
int lxp_wait_interrupt(lxp_proc_t *proc, lxp_wait_kind_t expected);
int lxp_wait_timeout(lxp_proc_t *proc, lxp_wait_kind_t expected);
int lxp_wait_cancel(lxp_proc_t *proc);

/** Bit for signal @p sig (1..64) in a @c sig_blocked mask; 0 for out-of-range. */
static inline uint64_t lxp_sig_bit(int sig)
{
	return (sig >= 1 && sig <= 64) ? ((uint64_t)1 << (sig - 1)) : 0;
}

/** Whether signal @p sig is currently blocked for @p proc. SIGKILL and SIGSTOP can
 * never be blocked (POSIX), so they always report deliverable. */
static inline int lxp_sig_blocked(const lxp_proc_t *proc, int sig)
{
	if (sig == LXP_SIGKILL || sig == LXP_SIGSTOP)
		return 0;
	return (proc->sig_blocked & lxp_sig_bit(sig)) != 0;
}

/** Read a disposition defensively; an uninitialized/contained task has all
 * default dispositions. */
static inline uintptr_t lxp_sig_handler_get(const lxp_proc_t *proc, int sig)
{
	return (proc && proc->sighand && sig >= 0 && sig < LXP_NSIG) ? proc->sighand->handler[sig]
								     : LXP_SIG_DFL;
}

static inline uintptr_t lxp_sig_restorer_get(const lxp_proc_t *proc)
{
	return (proc && proc->sighand) ? proc->sighand->restorer : 0;
}

/** Descriptor introspection for descriptor-aware backing-object layers. */
lxp_ofd_t *lxp_fd_description(lxp_proc_t *proc, int fd);
uint8_t lxp_fd_kind(const lxp_proc_t *proc, int fd);
int lxp_fd_backing(const lxp_proc_t *proc, int fd);
/** Take references for a descriptor table being copied, or fail without changes. */
int lxp_fd_fork_inherit(lxp_proc_t *child);
/** Acquire fork/clone resource ownership for an otherwise unowned child. */
int lxp_proc_resources_fork(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags);
/** Acquire a shared or copied address-space object for an unowned child. */
int lxp_proc_mm_fork(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags);
/** Drop only the address-space object reference (the coordinator owns region refs). */
void lxp_proc_mm_put(lxp_proc_t *proc);
/** Acquire a shared thread group for CLONE_THREAD, or a fresh child process group. */
int lxp_proc_group_fork(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags,
			int child_pid);
/** Drop one task's thread-group reference. */
void lxp_proc_group_put(lxp_proc_t *proc);
/** Drop one task's files/fs/sighand ownership, closing descriptors at the last table user. */
void lxp_proc_resources_put(lxp_proc_t *proc);
/**
 * Construct an unpublished process child without copying coordinator/runtime
 * state. The destination must not own resources. Fork inheritance is explicit:
 * callbacks, image identity, signal mask and immutable rootfs bindings are
 * copied; mm/files/fs/sighand follow @p clone_flags; a fresh process group is
 * derived from @p parent.
 */
int lxp_proc_init_process_child(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags,
				int child_pid);
/**
 * Construct an unpublished CLONE_THREAD child. CLONE_VM and CLONE_SIGHAND are
 * mandatory; task-local waits, pending work, timers, signals and exit state
 * start empty.
 */
int lxp_proc_init_thread_child(lxp_proc_t *child, const lxp_proc_t *parent, uint32_t clone_flags,
			       int child_tid);
/**
 * Release every object acquired by a child constructor and restore an empty,
 * unpublished record. Region reservations remain coordinator-owned.
 */
void lxp_proc_child_discard(lxp_proc_t *child);
/** Make a shared descriptor table private while retaining its open descriptions. */
int lxp_proc_files_unshare(lxp_proc_t *proc);
/** Close one descriptor through the generic last-reference path. */
int lxp_fd_close(lxp_proc_t *proc, int fd);
/** Close every descriptor through the generic last-reference path. */
void lxp_fd_close_all(lxp_proc_t *proc);
/** Reset the descriptor owner's open-file-description pool after all tasks stop. */
void lxp_fd_runtime_reset(void);
/** Reset process-owned resource pools after all tasks are stopped. */
void lxp_proc_runtime_reset(void);

/** @brief Install a kernel object (@p kind, @p idx) into @p p's fd table, returning the
 * lowest free fd or @c -LXP_EMFILE. Lets the socket bridge mint an accept(2) fd. */
int lxp_fd_install(lxp_proc_t *p, uint8_t kind, int idx);

/** @brief Retry a parked pipe read/write (run-loop coordinator). Returns the byte
 * count, 0 (EOF), or -EPIPE on completion; @c -LXP_EAGAIN while still blocked. */
long lxp_pipe_retry(lxp_proc_t *p);

/**
 * @brief Attach a read-only in-memory rootfs the program can @c open / @c read.
 * @note Requires @c LXP_ENABLE_LINUX.
 */
void lxp_proc_set_rootfs(lxp_proc_t *proc, const lxp_file_t *files, int count);

/* ---- OS-service hooks routed through the engine ops ------------------------
 * The personality core calls these module-internal wrappers instead of the
 * host's clock / cache primitives; the per-engine seam fills the underlying
 * ops (see lxp_os_ops_t in lxp_port.h). This keeps host primitives outside the
 * process core. */
int lxp_time_us(uint64_t *out);
int lxp_time_ns(uint64_t *out);
/** Fill @p len bytes from the active host entropy provider. Returns an lxp_err_t. */
int lxp_random_fill(void *buf, size_t len);
void lxp_cache_clean(const void *base, size_t len);
void lxp_cache_invalidate(const void *base, size_t len);
struct lxp_thread_info;
int lxp_thread_list(struct lxp_thread_info *out, size_t max_count, size_t *actual_count);

/**
 * @brief Resolve an absolute path through a rootfs (following symlinks) to a file's bytes.
 *
 * Used by the run loop to locate the FDPIC interpreter (ld.so) at launch, before a proc
 * exists. Follows up to 8 symlink hops (each normalized against the link's directory).
 * @return 0 with @p data / @p len set, or a negative errno (@c -ENOENT if unresolved).
 */
long lxp_rootfs_resolve(const lxp_file_t *fs, int count, const char *abspath, const uint8_t **data,
			size_t *len);

/**
 * @brief Initialise a process context with an arena-backed program break.
 *
 * Reserves @p brk_bytes from @p arena for the program break. The caller wires
 * @c write_fn / @c read_fn / @c io_ctx afterwards.
 *
 * @return LXP_OK; LXP_ERR_INVALID_PARAM on bad arguments;
 *         LXP_ERR_NO_MEMORY if the arena cannot satisfy @p brk_bytes.
 * @note Requires @c LXP_ENABLE_LINUX.
 */
int lxp_proc_init(lxp_proc_t *proc, lxp_arena_t *arena, size_t brk_bytes);

/** Lock-free niceness accessors shared with the coordinator and RTOS seams. */
int lxp_proc_nice_get(const lxp_proc_t *proc);
void lxp_proc_nice_set(lxp_proc_t *proc, int nice);

/** Bounded embedded guest-share weight: nice -20..19 maps to 40..1. */
uint32_t lxp_nice_weight(int nice);

/** Bind and clear the transient exec capture owned by @p proc's process slot. */
void lxp_proc_bind_exec_capture(lxp_proc_t *proc, lxp_exec_capture_t *capture);

/* getrandom(2) flags from Linux UAPI <linux/random.h>. */
#define LXP_GRND_NONBLOCK 0x0001u
#define LXP_GRND_RANDOM 0x0002u
#define LXP_GRND_INSECURE 0x0004u

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* LXP_PROC_H */
