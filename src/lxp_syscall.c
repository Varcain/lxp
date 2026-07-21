/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 */

#include "lxp/lxp_config.h"
#include "lxp/lxp_loader.h" /* lxp_loader_abi_incompatible — refuse a wrong-ABI execve up front */

#if LXP_ENABLE_LINUX

#include "lxp/lxp_stats.h"
#include "lxp/lxp_syscall.h"
#include "lxp/lxp_types.h"

#include "lxp_internal.h"    /* user_ok / user_strnlen / file_mode / lxp_encode_wstatus */
#include "lxp_vfs.h"         /* per-fd-kind file-operation vtable (dispatch by kind) */

#include "fs/lxp_path.h"     /* path resolution (resolve_path / fs_lookup / fs_follow) */
#include "fs/lxp_pipe.h"     /* pipe ring ops (FD_PIPE) */
#include "fs/lxp_tmpfs.h"    /* writable VFS overlay nodes (FD_TMPFS) */
#include "proc/lxp_procfs.h" /* synthetic /proc content generation (FD_PROC) */
#if LXP_ENABLE_DEV
#include "lxp/lxp_dev.h" /* /dev character-device routing (FD_DEV) */
#endif
#if LXP_ENABLE_NET
#include "lxp/lxp_net.h" /* socket routing (FD_SOCKET) */
#endif
#if LXP_ENABLE_NETFS
#include "lxp/lxp_netfs.h" /* remote-fs routing (FD_NET, /mnt/pi) */
#endif
#if LXP_ENABLE_PTY
#include "lxp/lxp_pty.h" /* pseudo-terminal routing (FD_PTY) */
#endif

#include <string.h>

/* Set by reboot(2)/poweroff to stop the run loop; the common run loop observes
 * it (declared extern there). Defined here so the host syscall tests, which do
 * not link the run loop, still resolve the symbol. */
volatile int g_lxp_halt;

/* ABI pins for the tty/poll uapi structs (lxp_syscall.h). Fixed-width fields → these
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
 * register arguments; this file owns the syscall table and the process state
 * those syscalls mutate. Pointer arguments are program addresses — in the flat
 * (NOMMU) model the program shares our address space, so they are used
 * directly after a NULL check (a future MMU tier would translate them).
 */

/* fd-slot kinds (lxp_fd.kind) are now in lxp_syscall.h (shared with the subsystem TUs). */

/* Host entropy adapter (defined with sys_getrandom); random-device reads use it
 * before that point. */
static long random_fill(void *buf, size_t count, int unavailable_errno);

/* fd-kind → file-operation vtable resolver (defined with the fops below); used by
 * proc_init to seed the std streams before the fops block appears in the file. */
static const struct lxp_file_ops *ops_for_kind(uint8_t kind);

#if LXP_ENABLE_NET
/* pselect6(2): select() over the poll machinery (busybox inetd + dropbear are
 * select-based). Defined with the poll retry below; the dispatch calls it earlier. */
#define LXP_SEL_MAXFDS 32 /* max nfds handled (fd_set = one 32-bit word here) */
static long sys_pselect6(lxp_proc_t *p, int nfds, uintptr_t urfds, uintptr_t uwfds,
			 uintptr_t uefds, uintptr_t utimeout);
#endif

/* The pipe subsystem (ring buffer + read/write/poll ops) lives in src/fs/lxp_pipe.c;
 * this dispatcher calls it via fs/lxp_pipe.h. */

/* lxp_proc_table / lxp_proc_nslot enumerate the live procs (used by the pipe layer's
 * open-ends count). Weak fallbacks so the host syscall test — which links these layers
 * but not the run loop — resolves them; the run loop supplies the strong versions. */
__attribute__((weak)) lxp_proc_t *lxp_proc_table(void)
{
	return NULL;
}
__attribute__((weak)) int lxp_proc_nslot(void)
{
	return 0;
}

/* The shared read-only rootfs span [lo,hi): a program's .rodata (its FDPIC text is shared in-place
 * from the embedded cpio) lives here, so a READ-source user pointer may legitimately point into it.
 * Weak fallback (empty range) so the host test links; the run loop supplies the strong version. */
__attribute__((weak)) void lxp_rootfs_bounds(uintptr_t *lo, uintptr_t *hi)
{
	*lo = 0;
	*hi = 0;
}

/* ---- user-pointer validation (access_ok) ----------------------------------
 * The syscall handlers run PRIVILEGED, so an unchecked user pointer would let a program make the
 * KERNEL read/write kernel, device, or unmapped memory on its behalf — a confused deputy the
 * per-program MPU cannot stop. Every syscall that dereferences a user pointer must first prove the
 * whole [ptr, ptr+len) lies inside the calling program's own writable memory (its image region or
 * dynamic arena), or — for a read SOURCE only — the shared read-only rootfs. */

/* Upper bound of the valid range that CONTAINS `a`, or 0 if `a` is in none. */
static uintptr_t user_range_hi(const lxp_proc_t *p, uintptr_t a, int write)
{
	if (a >= p->region_lo && a < p->region_hi)
		return p->region_hi;
	if (p->pool_hi > p->pool_lo && a >= p->pool_lo && a < p->pool_hi)
		return p->pool_hi;
#if LXP_ENABLE_DEV
	/* A mapped device buffer (framebuffer, P3) is RW-valid for the program. */
	for (int i = 0; i < 2; i++)
		if (p->dev_map_hi[i] > p->dev_map_lo[i] && a >= p->dev_map_lo[i] &&
		    a < p->dev_map_hi[i])
			return p->dev_map_hi[i];
#endif
	if (!write) {
		uintptr_t rlo, rhi;
		lxp_rootfs_bounds(&rlo, &rhi);
		if (rhi > rlo && a >= rlo && a < rhi)
			return rhi;
	}
	return 0;
}

/* True iff [ptr, ptr+len) is wholly readable (write==0) or writable (write==1) by program `p`.
 * Non-static so the host unit tests exercise the boundary/overflow logic directly. */
int user_ok(const lxp_proc_t *p, const void *ptr, size_t len, int write)
{
	uintptr_t a = (uintptr_t)ptr, end = a + len;
	if (len == 0)
		return 1; /* zero length: nothing is dereferenced */
	if (end < a)
		return 0; /* ptr+len wrapped the address space */
	uintptr_t hi = user_range_hi(p, a, write);
	return hi != 0 && end <= hi;
}

/* strlen of a user string, or -EFAULT if it is not NUL-terminated wholly within a valid readable
 * range (so a later strlen/copy can't walk off the region into kernel memory). Bounded by `max`.
 * Non-static so the host unit tests exercise the terminated/unterminated/at-edge cases directly. */
long user_strnlen(const lxp_proc_t *p, const char *s, size_t max)
{
	uintptr_t a = (uintptr_t)s;
	uintptr_t hi = user_range_hi(p, a, 0);
	if (!hi)
		return -LXP_EFAULT;
	size_t avail = (size_t)(hi - a);
	size_t lim = avail < max ? avail : max;
	for (size_t i = 0; i < lim; i++)
		if (s[i] == '\0')
			return (long)i;
	return -LXP_EFAULT; /* no NUL within the range / max */
}



/* Synthetic /proc fd backing (content generated on open; see proc_* below). */
#define LXP_NPROCF 12
#define LXP_PROCBUF 1024
#define LXP_PROCPATH 64 /* /proc paths are short ("/proc/<pid>/status"); not LXP_PATH_MAX */
static struct {
	char path[LXP_PROCPATH];
	char buf[LXP_PROCBUF];
	size_t len;
	int is_dir;
	int used;
} g_procf[LXP_NPROCF];

/*
 * ARM kernel struct stat64. Spelled with fixed-width types (the kernel's
 * `unsigned long` is 32-bit on ARM but 64-bit on the x86-64 host) so the binary
 * layout is identical on target and in host tests.
 */
struct lxp_kstat64 {
	uint64_t st_dev;
	uint8_t __pad0[4];
	uint32_t __st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint64_t st_rdev;
	uint8_t __pad3[4];
	int64_t st_size;
	uint32_t st_blksize;
	uint64_t st_blocks;
	uint32_t st_atime;
	uint32_t st_atime_nsec;
	uint32_t st_mtime;
	uint32_t st_mtime_nsec;
	uint32_t st_ctime;
	uint32_t st_ctime_nsec;
	uint64_t st_ino;
};
/* ABI pins: the ARM-EABI struct stat64 layout uClibc-ng expects. A field-order or
 * type drift (which would silently corrupt every stat/fstat) fails the build. The
 * struct uses fixed-width fields, so these hold on the 32-bit target and the 64-bit
 * host test build alike. */
LXP_STATIC_ASSERT(sizeof(struct lxp_kstat64) == 104, "stat64 ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_mode) == 16, "stat64 st_mode offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_rdev) == 32, "stat64 st_rdev offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_size) == 48, "stat64 st_size offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_blocks) == 64, "stat64 st_blocks offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_kstat64, st_ino) == 96, "stat64 st_ino offset drifted");

/* getdents64 record: fixed 19-byte head (d_ino..d_type) then a NUL-terminated name. */
struct lxp_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	uint16_t d_reclen;
	uint8_t d_type;
	char d_name[];
};
LXP_STATIC_ASSERT(offsetof(struct lxp_dirent64, d_name) == 19, "dirent64 head size drifted");

/* Effective st_mode for a rootfs node (0 in the table means a regular file). */
uint32_t file_mode(const lxp_file_t *f)
{
	return f->mode ? f->mode : (LXP_S_IFREG | 0644u);
}

/* If @p path names an entry exactly one component below directory @p dir, return
 * that child's name; otherwise NULL. */
static const char *child_name(const char *dir, const char *path)
{
	if (dir[0] == '/' && dir[1] == 0) { /* root */
		if (path[0] != '/' || path[1] == 0)
			return NULL;
		return strchr(path + 1, '/') ? NULL : path + 1;
	}
	size_t dl = strlen(dir);
	if (strncmp(path, dir, dl) != 0 || path[dl] != '/')
		return NULL;
	const char *name = path + dl + 1;
	return (*name && !strchr(name, '/')) ? name : NULL;
}

int lxp_proc_init(lxp_proc_t *proc, lxp_arena_t *arena, size_t brk_bytes)
{
	if (!proc || !arena)
		return LXP_ERR_INVALID_PARAM;

	memset(proc, 0, sizeof(*proc));
	proc->arena = arena;
	proc->pid = 1;	    /* the initial program is pid 1 (ppid 0); fork assigns the rest */
	proc->cwd[0] = '/'; /* start at the root directory */
	proc->cwd[1] = '\0';
	/* fd 0/1/2 are the standard streams, routed to the caller's callbacks.
	 * For console fds, file_idx marks the direction: 0 = readable (stdin),
	 * 1 = writable (stdout/stderr); this survives F_DUPFD so a dup of stdin
	 * stays readable (the shell dups stdin for its interactive fd). */
	proc->fds[0].kind = LXP_FD_CONSOLE;
	proc->fds[0].file_idx = 0;
	proc->fds[0].ops = ops_for_kind(LXP_FD_CONSOLE);
	proc->fds[1].kind = LXP_FD_CONSOLE;
	proc->fds[1].file_idx = 1;
	proc->fds[1].ops = ops_for_kind(LXP_FD_CONSOLE);
	proc->fds[2].kind = LXP_FD_CONSOLE;
	proc->fds[2].file_idx = 1;
	proc->fds[2].ops = ops_for_kind(LXP_FD_CONSOLE);
	if (brk_bytes) {
		void *brk = lxp_arena_alloc(arena, brk_bytes);
		if (!brk)
			return LXP_ERR_NO_MEMORY;
		proc->brk_base = (uintptr_t)brk;
		proc->brk_cur = proc->brk_base;
		proc->brk_max = proc->brk_base + brk_bytes;
	}
	return LXP_OK;
}

void lxp_proc_set_rootfs(lxp_proc_t *proc, const lxp_file_t *files, int count)
{
	if (!proc)
		return;
	proc->fs = files;
	proc->fs_count = (files && count > 0) ? count : 0;
}

/* Parse 8 ASCII-hex chars (a newc CPIO header field). */
static uint32_t cpio_hex(const char *s)
{
	uint32_t v = 0;
	for (int i = 0; i < 8; i++) {
		char c = s[i];
		uint32_t d = (c >= '0' && c <= '9')   ? (uint32_t)(c - '0')
			     : (c >= 'a' && c <= 'f') ? (uint32_t)(c - 'a' + 10)
			     : (c >= 'A' && c <= 'F') ? (uint32_t)(c - 'A' + 10)
						      : 0u;
		v = (v << 4) | d;
	}
	return v;
}

int lxp_cpio_to_rootfs(const uint8_t *cpio, size_t len, lxp_file_t *out, int max,
			   char *namebuf, size_t nblen)
{
	if (!cpio || !out || !namebuf)
		return -1;
	size_t pos = 0, nb = 0;
	int n = 0;
	while (pos + 110 <= len) {
		const char *h = (const char *)(cpio + pos);
		if (memcmp(h, "070701", 6) != 0) /* newc magic */
			return -1;
		uint32_t mode = cpio_hex(h + 14);  /* c_mode */
		uint32_t fsize = cpio_hex(h + 54); /* c_filesize */
		uint32_t nsize = cpio_hex(h + 94); /* c_namesize (incl NUL) */
		if (pos + 110 + nsize > len)
			return -1;
		const char *name = h + 110;
		if (nsize == 0 || name[nsize - 1] != '\0') /* the name field must be NUL-terminated */
			return -1;
		if (strcmp(name, "TRAILER!!!") == 0)
			break;
		size_t data_off = (pos + 110 + nsize + 3u) & ~(size_t)3u;
		if (fsize && data_off + fsize > len)
			return -1;
		if (n >= max)
			return -1;
		/* Write "/" + relative-name (strip a leading "./") into namebuf. */
		const char *nm = name;
		if (nm[0] == '.' && nm[1] == '/')
			nm += 2;
		else if (nm[0] == '.' && nm[1] == 0)
			nm += 1; /* "." -> "" -> "/" */
		size_t l = strlen(nm);
		if (nb + 2 + l > nblen)
			return -1;
		char *path = namebuf + nb;
		path[0] = '/';
		memcpy(path + 1, nm, l + 1);
		nb += 2 + l;
		out[n].path = path;
		/* Keep content for regular files AND symlinks (the link target string),
		 * so exec can resolve /bin/<applet> -> busybox. Dirs have no content. */
		out[n].data = fsize ? (cpio + data_off) : NULL;
		out[n].size = fsize;
		out[n].mode = mode;
		n++;
		pos = (data_off + fsize + 3u) & ~(size_t)3u;
	}
	return n;
}

/* Bound on argv/envp entries the startup stack will lay out. */
#define LXP_MAX_VEC 32

void *lxp_setup_stack(void *stack, size_t stack_size, int argc, const char *const argv[],
			  const char *const envp[], int fdpic, uintptr_t phdr, int phnum,
			  uintptr_t entry, uintptr_t at_base)
{
	if (!stack || !argv || argc < 0 || argc > LXP_MAX_VEC)
		return NULL;

	int envc = 0;
	while (envp && envp[envc])
		envc++;
	if (envc > LXP_MAX_VEC)
		return NULL;

	uintptr_t argp[LXP_MAX_VEC];
	uintptr_t envpp[LXP_MAX_VEC];
	uint8_t *sp = (uint8_t *)stack + stack_size;
	uint8_t *floor = (uint8_t *)stack;

	/* Copy env then arg strings to the top of the stack, recording addresses. */
	for (int i = envc - 1; i >= 0; i--) {
		size_t n = strlen(envp[i]) + 1;
		if (sp - n < floor)
			return NULL;
		sp -= n;
		memcpy(sp, envp[i], n);
		envpp[i] = (uintptr_t)sp;
	}
	for (int i = argc - 1; i >= 0; i--) {
		size_t n = strlen(argv[i]) + 1;
		if (sp - n < floor)
			return NULL;
		sp -= n;
		memcpy(sp, argv[i], n);
		argp[i] = (uintptr_t)sp;
	}

	/* 16 bytes for AT_RANDOM (stack-canary seed). Do not launch a process when
	 * the host has no trustworthy entropy: a fixed or time-derived fallback
	 * would silently give every guest a predictable canary. */
	if (sp - 16 < floor)
		return NULL;
	sp -= 16;
	uint8_t *rnd = sp;
	if (lxp_random_fill(rnd, 16u) != LXP_OK)
		return NULL;

	/* FDPIC programs use the STANDARD ELF inline stack (the crt reads argc at sp,
	 * argv[] inline at sp+4, then computes envp = &argv[argc+1]): argc, argv[0..],
	 * NULL, envp[0..], NULL, auxv. (bFLT instead wants a 3-word
	 * argc/argv-ptr/envp-ptr header — see below.) */
	if (fdpic) {
		size_t nwords = 1 + (size_t)argc + 1 + (size_t)envc + 1 + 16;
		uintptr_t *hdr =
			(uintptr_t *)((uintptr_t)(sp - nwords * sizeof(uintptr_t)) & ~(uintptr_t)7);
		if ((uint8_t *)hdr < floor)
			return NULL;
		size_t k = 0;
		hdr[k++] = (uintptr_t)argc;
		for (int i = 0; i < argc; i++)
			hdr[k++] = argp[i];
		hdr[k++] = 0; /* argv[] terminator */
		for (int i = 0; i < envc; i++)
			hdr[k++] = envpp[i];
		hdr[k++] = 0; /* envp[] terminator */
		/* auxv — the FDPIC crt locates PT_TLS / the segments via AT_PHDR/AT_PHNUM. */
		hdr[k++] = LXP_AT_PHDR;
		hdr[k++] = phdr;
		hdr[k++] = LXP_AT_PHENT;
		hdr[k++] = 32; /* sizeof(Elf32_Phdr) */
		hdr[k++] = LXP_AT_PHNUM;
		hdr[k++] = (uintptr_t)phnum;
		hdr[k++] = LXP_AT_BASE;
		hdr[k++] = at_base; /* ld.so's load base for a dynamic exec; 0 when static */
		hdr[k++] = LXP_AT_ENTRY;
		hdr[k++] = entry; /* the program's own entry (AT_ENTRY), even when ld.so runs first */
		hdr[k++] = LXP_AT_PAGESZ;
		hdr[k++] = 4096;
		hdr[k++] = LXP_AT_RANDOM;
		hdr[k++] = (uintptr_t)rnd;
		hdr[k++] = LXP_AT_NULL;
		hdr[k++] = 0;
		return hdr; /* SP -> argc, argv[] inline */
	}

	/*
	 * uClinux/bFLT (flat_argvp_envp_on_stack, used on ARM) layout — NOT the
	 * ELF inline layout: the kernel passes the argv/envp array *pointers* on
	 * the stack, so an elf2flt crt0 reads sp[0]=argc, sp[1]=argv, sp[2]=envp.
	 * Below the strings lay the 3-word header, the argv[] and envp[] arrays it
	 * points at, then a terminated auxv — __uClibc_main scans for one right
	 * after the envp array, and unterminated garbage there crashes it.
	 */
	size_t nwords = 3 + (size_t)argc + 1 + (size_t)envc + 1 + 6;
	uintptr_t *hdr =
		(uintptr_t *)((uintptr_t)(sp - nwords * sizeof(uintptr_t)) & ~(uintptr_t)7);
	if ((uint8_t *)hdr < floor)
		return NULL;

	uintptr_t *argv_arr = hdr + 3;
	uintptr_t *envp_arr = argv_arr + (size_t)argc + 1;
	uintptr_t *auxv = envp_arr + (size_t)envc + 1;
	hdr[0] = (uintptr_t)argc;
	hdr[1] = (uintptr_t)argv_arr;
	hdr[2] = (uintptr_t)envp_arr;
	for (int i = 0; i < argc; i++)
		argv_arr[i] = argp[i];
	argv_arr[argc] = 0;
	for (int i = 0; i < envc; i++)
		envp_arr[i] = envpp[i];
	envp_arr[envc] = 0;
	auxv[0] = LXP_AT_PAGESZ;
	auxv[1] = 4096;
	auxv[2] = LXP_AT_RANDOM;
	auxv[3] = (uintptr_t)rnd;
	auxv[4] = LXP_AT_NULL;
	auxv[5] = 0;

	return hdr; /* initial SP, pointing at argc */
}

/* Validate an fd index and return its slot, or NULL. */
static lxp_fd_t *fd_slot(lxp_proc_t *p, int fd)
{
	if (fd < 0 || fd >= LXP_MAX_FDS || p->fds[fd].kind == LXP_FD_FREE)
		return NULL;
	return &p->fds[fd];
}

#if LXP_ENABLE_NET
/* Resolve @p fd to its socket open-pool index, or -1 if @p fd is not a socket. Collapses
 * the fd_slot + kind check that the socket syscalls all repeat. */
static int sock_slot(lxp_proc_t *p, int fd)
{
	lxp_fd_t *s = fd_slot(p, fd);
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
	if (!user_ok(p, umsg, sizeof(*umsg), 0))
		return -LXP_EFAULT;
	lxp_msghdr m = *umsg;
	if (m.msg_iovlen > LXP_SYSCALL_MAX_IOV) /* bound before iovlen*sizeof(iovec) overflows */
		return -LXP_EINVAL;
	const lxp_iovec *iov = m.msg_iov;
	if (m.msg_iovlen && !user_ok(p, iov, m.msg_iovlen * sizeof(*iov), 0))
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
		if (iov[i].iov_len == 0)
			continue;
		size_t len = iov[i].iov_len < budget ? iov[i].iov_len : budget;
		long r = lxp_sock_send(p, oi, iov[i].iov_base, len, flags, dest,
				       m.msg_namelen);
		if (r < 0)
			return total ? total : r;
		if ((size_t)r > len)
			return total ? total : -LXP_EIO; /* host backend violated the write contract */
		if (p->sock_wait) {	 /* this segment parked */
			if (total > 0) { /* earlier segments already sent: short send, do not park */
				p->sock_wait = 0;
				return total;
			}
			return 0; /* first segment: let the coordinator retry complete it */
		}
		total += r;
		budget -= (size_t)r;
		if ((size_t)r < len || len < iov[i].iov_len || budget == 0)
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
	if (!user_ok(p, umsg, sizeof(*umsg), 1)) /* msg_controllen / msg_flags are written back */
		return -LXP_EFAULT;
	lxp_msghdr m = *umsg;
	if (m.msg_iovlen > LXP_SYSCALL_MAX_IOV)
		return -LXP_EINVAL;
	const lxp_iovec *iov = m.msg_iov;
	if (m.msg_iovlen && !user_ok(p, iov, m.msg_iovlen * sizeof(*iov), 0))
		return -LXP_EFAULT;
	umsg->msg_controllen = 0; /* no ancillary data is ever produced */
	umsg->msg_flags = 0;

	/* Receive into the first non-empty segment only. A blocking recv parks with a single
	 * guest buffer, so a multi-segment scatter cannot be resumed after a park — and the
	 * transport does not report a datagram's true length, so MSG_TRUNC cannot be set. This is
	 * a legal short read for a stream socket; for a datagram it means the tail of a message
	 * larger than the first segment is lost. Callers that need the whole datagram should pass
	 * a single sufficiently large segment. */
	void *src = (m.msg_name && m.msg_namelen) ? m.msg_name : NULL;
	void *srclen = src ? &umsg->msg_namelen : NULL;
	for (size_t i = 0; i < m.msg_iovlen; i++) {
		if (iov[i].iov_len == 0)
			continue;
		size_t len = iov[i].iov_len;
		if (len > LXP_SYSCALL_QUANTUM_BYTES)
			len = LXP_SYSCALL_QUANTUM_BYTES;
		return lxp_sock_recv(p, oi, iov[i].iov_base, len, flags, src, srclen);
	}
	return 0; /* no buffer space in the iov: nothing received */
}
#endif

/* eventfd counter read/write (defined below fd_alloc); sys_read/sys_write route to them. */
static long efd_read(lxp_proc_t *p, int ei, void *buf, size_t len);
static long efd_write(lxp_proc_t *p, int ei, const void *buf, size_t len);
static void efd_close(int ei); /* release an eventfd pool slot (defined with efd_new). */
static int efd_readable(int ei); /* eventfd counter nonzero? (poll readiness; defined with efd_new). */

/* Fill an ARM kstat64 (defined below with sys_fstat64); the fstat fops use it. */
struct lxp_kstat64;
static void fill_kstat64(struct lxp_kstat64 *st, uint32_t ino, uint32_t mode, uint64_t size);

/* ─────────────────────────────────────────────────────────────────────────
 * VFS file-operation vtable (src/lxp_vfs.h). The fd syscalls dispatch on the
 * open fd's kind through a per-kind ops table instead of an inline switch — the
 * Linux struct file_operations / gVisor FileDescriptionImpl pattern. Each fd
 * carries its kind's ops (set at creation via ops_for_kind); a NULL method means
 * the kind does not support that operation. A blocking backend parks the proc
 * (sets the coordinator park state) and returns 0, exactly as before.
 * ───────────────────────────────────────────────────────────────────────── */

/* ---- read fops ---- */
static long fop_read_console(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	if (s->file_idx == 1) /* output consoles (stdout/stderr) are not readable */
		return -LXP_EBADF;
	if (s->file_idx == 3) /* /dev/null */
		return 0;     /* EOF */
	if (s->file_idx == 5) { /* /dev/zero: an all-zero fill */
		memset(buf, 0, len);
		return (long)len;
	}
	if (s->file_idx == 4) /* /dev/urandom + /dev/random: host entropy */
		return random_fill(buf, len, LXP_EIO);
	if (!p->read_fn)
		return 0; /* EOF */
	/* Park until a key is ready (probed via console_poll) so the syscall bottom
	 * half returns to its coordinator loop instead of pinning it in read_fn. This
	 * lets other slots and background work progress. Without a poll hook, retain
	 * the legacy blocking-read fallback for host integrations that need it. */
	if (p->console_poll && p->console_poll(p->io_ctx) == 0) {
		p->console_wait = 1;
		p->console_buf = (uintptr_t)buf;
		p->console_len = len;
		return 0; /* parked; the coordinator resumes it when a key arrives */
	}
	return p->read_fn(p->io_ctx, (int)(s - p->fds), buf, len);
}

/* A pipe read end drains the shared ring; blocks while empty + a writer is open,
 * EOF (0) once all writers have closed. */
static long fop_read_pipe(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	if (s->rw != 0)
		return -LXP_EBADF;
	long r = pipe_try_read(s->file_idx, buf, len);
	if (r == -LXP_EAGAIN) { /* empty but a writer is open */
		if (s->nonblock)
			return -LXP_EAGAIN; /* O_NONBLOCK: don't park (self-pipe drain) */
		p->pipe_wait = 1; /* blocking: park + retry */
		p->pipe_idx = s->file_idx;
		p->pipe_buf = (uintptr_t)buf;
		p->pipe_len = len;
		return 0;
	}
	return r; /* bytes read, or 0 (EOF) */
}

/* A writable-node file read returns bytes from its buffer at the fd offset. */
static long fop_read_tmpfs(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	(void)p;
	lxp_wnode_t *t = wnode_at(s->file_idx);
	if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EISDIR;
	if (s->offset >= t->size)
		return 0; /* EOF */
	size_t n = t->size - s->offset;
	if (n > len)
		n = len;
	memcpy(buf, t->data + s->offset, n);
	s->offset += n;
	return (long)n;
}

/* A /proc file read returns bytes from the content generated at open. */
static long fop_read_proc(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	(void)p;
	if (g_procf[s->file_idx].is_dir)
		return -LXP_EISDIR;
	size_t plen = g_procf[s->file_idx].len;
	if ((size_t)s->offset >= plen)
		return 0; /* EOF */
	size_t n = plen - s->offset;
	if (n > len)
		n = len;
	memcpy(buf, g_procf[s->file_idx].buf + s->offset, n);
	s->offset += n;
	return (long)n;
}

/* Read from a read-only rootfs file at the current offset. */
static long fop_read_rootfs(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	const lxp_file_t *f = &p->fs[s->file_idx];
	if ((file_mode(f) & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EISDIR;
	if (s->offset >= f->size)
		return 0; /* EOF */
	size_t n = f->size - s->offset;
	if (n > len)
		n = len;
	memcpy(buf, f->data + s->offset, n);
	s->offset += n;
	return (long)n;
}

static long fop_read_eventfd(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	return efd_read(p, s->file_idx, buf, len);
}

#if LXP_ENABLE_DEV
static long fop_read_dev(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	return lxp_dev_read(p, s->file_idx, buf, len);
}
#endif
#if LXP_ENABLE_NET
static long fop_read_socket(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	return lxp_sock_recv(p, s->file_idx, buf, len, 0, NULL, NULL);
}
#endif
#if LXP_ENABLE_NETFS
static long fop_read_netfs(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	return lxp_netfs_read(p, s->file_idx, buf, len);
}
#endif
#if LXP_ENABLE_PTY
/* A pty end drains its ring (master reads program output, slave reads program input);
 * blocks while empty + the peer end is open, EOF (0) once the peer closes. */
static long fop_read_pty(lxp_proc_t *p, lxp_fd_t *s, void *buf, size_t len)
{
	long r = lxp_pty_read(p, s->file_idx, s->rw, buf, len);
	if (r == -LXP_EAGAIN && !lxp_pty_nonblock(s->file_idx, s->rw)) {
		p->pty_wait = s->rw ? LXP_PTYW_MREAD : LXP_PTYW_SREAD;
		p->pty_idx = s->file_idx;
		p->pty_buf = (uintptr_t)buf;
		p->pty_len = len;
		return 0; /* parked; coordinator retries via lxp_pty_retry */
	}
	return r; /* bytes read, 0 (EOF), or -EAGAIN (O_NONBLOCK) */
}
#endif

/* ---- write fops ---- */
static long fop_write_console(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	if (s->file_idx == 3 || s->file_idx == 4 || s->file_idx == 5)
		return (long)len; /* /dev/null + /dev/urandom + /dev/zero: discard writes */
	if (s->file_idx == 0 || !p->write_fn) /* stdin is not writable; no sink → EBADF */
		return -LXP_EBADF;
	return p->write_fn(p->io_ctx, (int)(s - p->fds), buf, len);
}

/* A pipe write end appends to the shared ring; blocks when full (reader open). */
static long fop_write_pipe(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	if (s->rw != 1)
		return -LXP_EBADF;
	long r = pipe_try_write(s->file_idx, buf, len);
	if (r == -LXP_EAGAIN) { /* full but a reader is open */
		if (s->nonblock)
			return -LXP_EAGAIN; /* O_NONBLOCK: don't park */
		p->pipe_wait = 2; /* blocking: park + retry */
		p->pipe_idx = s->file_idx;
		p->pipe_buf = (uintptr_t)buf;
		p->pipe_len = len;
		return 0; /* dispatch parks; coordinator completes via lxp_pipe_retry */
	}
	if (r == -LXP_EPIPE && /* no readers: SIGPIPE — default terminates the writer */
	    p->sig_handler[LXP_SIGPIPE] != LXP_SIG_IGN) {
		p->exited = 1;
		p->exit_status = 128 + LXP_SIGPIPE;
		p->exit_reason = LXP_EXIT_REASON_SIGNAL;
		p->exit_signal = LXP_SIGPIPE;
	}
	return r; /* bytes written, or -EPIPE (no readers; writer exits unless it ignores it) */
}

/* A writable-node file write copies into its (growable) buffer at the offset. */
static long fop_write_tmpfs(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	(void)p;
	lxp_wnode_t *t = wnode_at(s->file_idx);
	if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EBADF;
	if (wfs_reserve(s->file_idx, s->offset + len) != 0)
		return -LXP_EFBIG; /* writable-fs pool exhausted */
	if (s->offset > t->size) /* zero the hole of a sparse write (else it leaks stale pool bytes) */
		memset(t->data + t->size, 0, s->offset - t->size);
	memcpy(t->data + s->offset, buf, len);
	s->offset += len;
	if (s->offset > t->size)
		t->size = s->offset;
	return (long)len;
}

static long fop_write_eventfd(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	return efd_write(p, s->file_idx, buf, len);
}

#if LXP_ENABLE_DEV
static long fop_write_dev(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	return lxp_dev_write(p, s->file_idx, buf, len);
}
#endif
#if LXP_ENABLE_NET
static long fop_write_socket(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	return lxp_sock_send(p, s->file_idx, buf, len, 0, NULL, 0);
}
#endif
#if LXP_ENABLE_NETFS
static long fop_write_netfs(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	(void)p;
	(void)s;
	(void)buf;
	(void)len;
	return -LXP_EROFS; /* read-only remote mount */
}
#endif
#if LXP_ENABLE_PTY
/* A pty write feeds the peer's ring through the line discipline (master write runs
 * input processing toward the slave; slave write runs output/ONLCR toward the master).
 * Blocks (backpressure) when the destination ring is full and the peer is open. */
static long fop_write_pty(lxp_proc_t *p, lxp_fd_t *s, const void *buf, size_t len)
{
	long r = lxp_pty_write(p, s->file_idx, s->rw, buf, len);
	if (r == -LXP_EAGAIN && !lxp_pty_nonblock(s->file_idx, s->rw)) {
		p->pty_wait = s->rw ? LXP_PTYW_MWRITE : LXP_PTYW_SWRITE;
		p->pty_idx = s->file_idx;
		p->pty_buf = (uintptr_t)buf;
		p->pty_len = len;
		return 0; /* parked; coordinator completes via lxp_pty_retry */
	}
	return r; /* bytes consumed, or -EAGAIN (O_NONBLOCK) */
}
#endif

/* ---- lseek fops ---- */
/* Shared SEEK_SET/CUR/END arithmetic against a file of logical size @p end. */
static long lseek_within(lxp_fd_t *s, long end, long off, int whence)
{
	long base;
	switch (whence) {
	case LXP_SEEK_SET:
		base = 0;
		break;
	case LXP_SEEK_CUR:
		base = (long)s->offset;
		break;
	case LXP_SEEK_END:
		base = end;
		break;
	default:
		return -LXP_EINVAL;
	}
	long pos = base + off;
	if (pos < 0)
		return -LXP_EINVAL;
	s->offset = (size_t)pos;
	return pos;
}

static long fop_lseek_rootfs(lxp_proc_t *p, lxp_fd_t *s, long off, int whence)
{
	return lseek_within(s, (long)p->fs[s->file_idx].size, off, whence);
}

static long fop_lseek_tmpfs(lxp_proc_t *p, lxp_fd_t *s, long off, int whence)
{
	(void)p;
	return lseek_within(s, (long)wnode_at(s->file_idx)->size, off, whence);
}

#if LXP_ENABLE_DEV
static long fop_lseek_dev(lxp_proc_t *p, lxp_fd_t *s, long off, int whence)
{
	(void)p;
	return lxp_dev_lseek(s->file_idx, off, whence);
}
#endif
#if LXP_ENABLE_NETFS
static long fop_lseek_netfs(lxp_proc_t *p, lxp_fd_t *s, long off, int whence)
{
	(void)p;
	return lxp_netfs_lseek(s->file_idx, off, whence);
}
#endif

/* ---- fstat fops (each kind reports its own mode/size + a unique inode base) ---- */
static long fop_fstat_rootfs(lxp_proc_t *p, lxp_fd_t *s, void *statbuf)
{
	fill_kstat64(statbuf, 1u + (uint32_t)s->file_idx, file_mode(&p->fs[s->file_idx]),
		     p->fs[s->file_idx].size);
	return 0;
}

static long fop_fstat_tmpfs(lxp_proc_t *p, lxp_fd_t *s, void *statbuf)
{
	(void)p;
	fill_kstat64(statbuf, 0x100000u + (uint32_t)s->file_idx, wnode_at(s->file_idx)->mode,
		     wnode_at(s->file_idx)->size);
	return 0;
}

static long fop_fstat_proc(lxp_proc_t *p, lxp_fd_t *s, void *statbuf)
{
	(void)p;
	fill_kstat64(statbuf, 0x200000u + (uint32_t)s->file_idx,
		     g_procf[s->file_idx].is_dir ? (LXP_S_IFDIR | 0555u) : (LXP_S_IFREG | 0444u),
		     g_procf[s->file_idx].len);
	return 0;
}

#if LXP_ENABLE_DEV
static long fop_fstat_dev(lxp_proc_t *p, lxp_fd_t *s, void *statbuf)
{
	(void)p;
	uint32_t mode;
	uint64_t rdev, size;
	lxp_dev_fstat(s->file_idx, &mode, &rdev, &size);
	fill_kstat64(statbuf, 0x300000u + (uint32_t)s->file_idx, mode, size);
	((struct lxp_kstat64 *)statbuf)->st_rdev = rdev;
	return 0;
}
#endif
#if LXP_ENABLE_NET
static long fop_fstat_socket(lxp_proc_t *p, lxp_fd_t *s, void *statbuf)
{
	(void)p;
	uint32_t mode;
	uint64_t size;
	lxp_sock_fstat(s->file_idx, &mode, &size);
	fill_kstat64(statbuf, 0x400000u + (uint32_t)s->file_idx, mode, size);
	return 0;
}
#endif
#if LXP_ENABLE_NETFS
static long fop_fstat_netfs(lxp_proc_t *p, lxp_fd_t *s, void *statbuf)
{
	uint32_t mode;
	uint64_t size, mtime, ino;
	if (lxp_netfs_fstat(s->file_idx, &mode, &size, &mtime, &ino) != 0)
		return -LXP_EBADF;
	return lxp_netfs_fill_stat(p, (uintptr_t)statbuf, 0, mode, size, mtime, ino);
}
#endif
#if LXP_ENABLE_PTY
static long fop_fstat_pty(lxp_proc_t *p, lxp_fd_t *s, void *statbuf)
{
	(void)p;
	uint32_t mode;
	uint64_t size;
	lxp_pty_fstat(&mode, &size); /* S_IFCHR so isatty() → interactive shell */
	fill_kstat64(statbuf, 0x500000u + (uint32_t)s->file_idx, mode, size);
	return 0;
}
#endif

/* ---- close fops (release the backing object; kinds with no backing omit it) ---- */
static void fop_close_proc(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	g_procf[s->file_idx].used = 0; /* release the generated-content slot */
}

static void fop_close_eventfd(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	efd_close(s->file_idx); /* threads share the fd table → one close frees it */
}

#if LXP_ENABLE_DEV
static void fop_close_dev(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	lxp_dev_close(s->file_idx); /* refs--, ops->release at the last close */
}
#endif
#if LXP_ENABLE_NET
static void fop_close_socket(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	lxp_sock_close(s->file_idx); /* refs--, socket close at the last close */
}
#endif
#if LXP_ENABLE_NETFS
static void fop_close_netfs(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	lxp_netfs_close(s->file_idx); /* refs--, enqueue a Tclunk at the last close */
}
#endif

/* ---- ioctl fops (dev/socket/pty delegate to their layers; console is the tty) ---- */
static long fop_ioctl_console(lxp_proc_t *p, lxp_fd_t *s, unsigned long cmd, unsigned long arg)
{
	/* Make the console fds look like a tty so the shell goes interactive
	 * (isatty → prompt + line editing). */
	(void)s;
	void *ua = (void *)(uintptr_t)arg;
	switch (cmd) {
	case LXP_TCGETS: {
		if (!user_ok(p, ua, sizeof(lxp_termios), 1))
			return -LXP_EFAULT;
		lxp_termios t = {0};
		t.c_iflag = LXP_ICRNL;
		t.c_oflag = LXP_OPOST | LXP_ONLCR;
		t.c_cflag = LXP_CS8 | LXP_CREAD;
		t.c_lflag = LXP_ICANON | LXP_ECHO | LXP_ISIG;
		t.c_cc[LXP_VINTR] = 3;     /* ^C */
		t.c_cc[LXP_VERASE] = 0x7f; /* DEL */
		t.c_cc[LXP_VEOF] = 4;      /* ^D */
		t.c_cc[LXP_VMIN] = 1;
		memcpy(ua, &t, sizeof(t));
		return 0;
	}
	case LXP_TCSETS:
	case LXP_TCSETSW:
	case LXP_TCSETSF:
		if (!user_ok(p, ua, sizeof(lxp_termios), 0))
			return -LXP_EFAULT;
		return 0; /* accept mode changes; the console echo is the engine's job */
	case LXP_TIOCGWINSZ: {
		if (!user_ok(p, ua, sizeof(lxp_winsize), 1))
			return -LXP_EFAULT;
		const lxp_winsize w = {.ws_row = 24, .ws_col = 80, .ws_xpixel = 0, .ws_ypixel = 0};
		memcpy(ua, &w, sizeof(w));
		return 0;
	}
	case LXP_TIOCSCTTY: /* getty/login: become/drop/set the tty session */
	case LXP_TIOCNOTTY:
		return 0;
	case LXP_TIOCSPGRP: {
		/* tcsetpgrp(): the shell (HUSH_JOB) records which process group is in the
		 * foreground of the console. A console ^C then raises SIGINT on exactly that
		 * group (see console_signal_fg). Runs in coordinator context (ioctl defers),
		 * so writing the shared fg-pgrp state here is safe. */
		if (!user_ok(p, ua, sizeof(int), 0))
			return -LXP_EFAULT;
		int pgrp;
		memcpy(&pgrp, ua, sizeof(pgrp));
		lxp_console_set_fg_pgrp(pgrp);
		return 0;
	}
	case LXP_TIOCGPGRP: {
		if (!user_ok(p, ua, sizeof(int), 1))
			return -LXP_EFAULT;
		/* Report the tracked foreground group once set; before the shell's first
		 * tcsetpgrp, fall back to the caller's pid so tcgetpgrp() returns non-zero
		 * and the shell enables job control at startup. */
		int pgrp = lxp_console_fg_pgrp();
		if (pgrp <= 0)
			pgrp = p->pid;
		memcpy(ua, &pgrp, sizeof(pgrp));
		return 0;
	}
	default:
		return -LXP_ENOTTY;
	}
}

#if LXP_ENABLE_DEV
static long fop_ioctl_dev(lxp_proc_t *p, lxp_fd_t *s, unsigned long cmd, unsigned long arg)
{
	return lxp_dev_ioctl(p, s->file_idx, cmd, arg);
}
#endif
#if LXP_ENABLE_NET
static long fop_ioctl_socket(lxp_proc_t *p, lxp_fd_t *s, unsigned long cmd, unsigned long arg)
{
	(void)s;
	return lxp_sock_ioctl(p, cmd, arg); /* SIOC* interface config (ifconfig/route) */
}
#endif
#if LXP_ENABLE_PTY
static long fop_ioctl_pty(lxp_proc_t *p, lxp_fd_t *s, unsigned long cmd, unsigned long arg)
{
	return lxp_pty_ioctl(p, s->file_idx, s->rw, cmd, arg);
}
#endif

/* ---- poll fops (readiness bits; a kind with no poll fop is always ready) ---- */
static unsigned fop_poll_console(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)s;
	int key = (p->console_poll && p->console_poll(p->io_ctx) > 0);
	return (unsigned)((p->console_poll ? (key ? LXP_POLLIN : 0) : LXP_POLLIN) | LXP_POLLOUT);
}

static unsigned fop_poll_eventfd(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	return (unsigned)LXP_POLLOUT | (efd_readable(s->file_idx) ? (unsigned)LXP_POLLIN : 0u);
}

static unsigned fop_poll_pipe(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	return (unsigned)pipe_poll(s->file_idx, s->rw); /* real readiness (empty self-pipe!) */
}

#if LXP_ENABLE_DEV
static unsigned fop_poll_dev(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	return (unsigned)lxp_dev_poll(s->file_idx);
}
#endif
#if LXP_ENABLE_NET
static unsigned fop_poll_socket(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	return (unsigned)lxp_sock_poll(s->file_idx);
}
#endif
#if LXP_ENABLE_PTY
static unsigned fop_poll_pty(lxp_proc_t *p, lxp_fd_t *s)
{
	(void)p;
	return (unsigned)lxp_pty_poll(s->file_idx, s->rw);
}
#endif

/* ---- per-kind ops tables + kind→ops resolver ----
 * A NULL read/write means the kind rejects that direction: the syscall entry
 * returns -EBADF (the errno the former fallthrough returned for rootfs/proc and
 * a wrong-direction console). netfs is the exception — its write returns -EROFS,
 * so it supplies an explicit write fop rather than a NULL. */
static const lxp_file_ops_t console_fops = {.read = fop_read_console, .write = fop_write_console,
					    .ioctl = fop_ioctl_console, .poll = fop_poll_console};
static const lxp_file_ops_t rootfs_fops = {.read = fop_read_rootfs, /* read-only → write EBADF */
					   .lseek = fop_lseek_rootfs,
					   .fstat = fop_fstat_rootfs};
static const lxp_file_ops_t tmpfs_fops = {.read = fop_read_tmpfs, .write = fop_write_tmpfs,
					  .lseek = fop_lseek_tmpfs, .fstat = fop_fstat_tmpfs};
static const lxp_file_ops_t pipe_fops = {.read = fop_read_pipe, .write = fop_write_pipe,
					 .poll = fop_poll_pipe};
static const lxp_file_ops_t proc_fops = {.read = fop_read_proc, /* read-only → write EBADF */
					 .fstat = fop_fstat_proc, .close = fop_close_proc};
static const lxp_file_ops_t eventfd_fops = {.read = fop_read_eventfd, .write = fop_write_eventfd,
					    .close = fop_close_eventfd, .poll = fop_poll_eventfd};
#if LXP_ENABLE_DEV
static const lxp_file_ops_t dev_fops = {.read = fop_read_dev, .write = fop_write_dev,
					.lseek = fop_lseek_dev, .fstat = fop_fstat_dev,
					.close = fop_close_dev, .ioctl = fop_ioctl_dev,
					.poll = fop_poll_dev};
#endif
#if LXP_ENABLE_NET
static const lxp_file_ops_t socket_fops = {.read = fop_read_socket, .write = fop_write_socket,
					   .fstat = fop_fstat_socket, .close = fop_close_socket,
					   .ioctl = fop_ioctl_socket, .poll = fop_poll_socket};
#endif
#if LXP_ENABLE_NETFS
static const lxp_file_ops_t netfs_fops = {.read = fop_read_netfs, .write = fop_write_netfs,
					  .lseek = fop_lseek_netfs, .fstat = fop_fstat_netfs,
					  .close = fop_close_netfs};
#endif
#if LXP_ENABLE_PTY
static const lxp_file_ops_t pty_fops = {.read = fop_read_pty, .write = fop_write_pty,
					.fstat = fop_fstat_pty, .ioctl = fop_ioctl_pty,
					.poll = fop_poll_pty};
#endif

/* Resolve an fd kind to its ops table (stamped on the fd at creation). This is the
 * ONE place the fd syscalls' former per-verb kind ladders collapse into. */
static const struct lxp_file_ops *ops_for_kind(uint8_t kind)
{
	switch (kind) {
	case LXP_FD_CONSOLE:
		return &console_fops;
	case LXP_FD_FILE:
		return &rootfs_fops;
	case LXP_FD_TMPFS:
		return &tmpfs_fops;
	case LXP_FD_PIPE:
		return &pipe_fops;
	case LXP_FD_PROC:
		return &proc_fops;
	case LXP_FD_EVENTFD:
		return &eventfd_fops;
#if LXP_ENABLE_DEV
	case LXP_FD_DEV:
		return &dev_fops;
#endif
#if LXP_ENABLE_NET
	case LXP_FD_SOCKET:
		return &socket_fops;
#endif
#if LXP_ENABLE_NETFS
	case LXP_FD_NET:
		return &netfs_fops;
#endif
#if LXP_ENABLE_PTY
	case LXP_FD_PTY:
		return &pty_fops;
#endif
	default:
		return NULL;
	}
}

static long sys_write(lxp_proc_t *p, int fd, const void *buf, size_t len)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!user_ok(p, buf, len, 0)) /* the kernel READS buf → reject a bad source pointer */
		return -LXP_EFAULT;
	/* A guest may write this buffer through a cacheable MPU view while the privileged host reads
	 * the same SDRAM through an uncached background view.  Publish dirty guest lines before any
	 * console/filesystem/device backend dereferences the payload.  Socket sends use the same hook
	 * internally; the duplicate clean is harmless and keeps this boundary correct for every fd. */
	if (len)
		lxp_cache_clean(buf, len);
	if (s->ops && s->ops->write)
		return s->ops->write(p, s, buf, len);
	return -LXP_EBADF; /* read-only kind (rootfs/proc) or wrong-direction console */
}

static long sys_writev(lxp_proc_t *p, int fd, const lxp_iovec *iov, int iovcnt)
{
	/* Any fd sys_write accepts: console, socket (uClibc stdio flushes a socket via
	 * writev — this is how wget sends its HTTP request), device, file. sys_write
	 * validates the fd (EBADF) and routes by kind. */
	if (iovcnt < 0 || iovcnt > LXP_SYSCALL_MAX_IOV)
		return -LXP_EINVAL;
	if (iovcnt && !user_ok(p, iov, (size_t)iovcnt * sizeof(*iov), 0))
		return -LXP_EFAULT; /* the iov array itself; each iov_base is checked in sys_write */
	/* Publish the descriptors before the host reads their bases and lengths.  sys_write() below
	 * publishes each referenced payload independently. */
	if (iovcnt)
		lxp_cache_clean(iov, (size_t)iovcnt * sizeof(*iov));
	lxp_fd_t *slot = fd_slot(p, fd);
	if (!slot)
		return -LXP_EBADF;
	/* The retry records describe one buffer, not an iovec cursor. Stop after one
	 * segment for fd kinds that may park; the legal short write lets libc retry
	 * the tail without losing an earlier byte count or orphaning backend state. */
	int single_segment = slot->kind == LXP_FD_PIPE || slot->kind == LXP_FD_DEV ||
			     slot->kind == LXP_FD_SOCKET || slot->kind == LXP_FD_PTY ||
			     slot->kind == LXP_FD_NET;

	long total = 0;
	size_t budget = LXP_SYSCALL_QUANTUM_BYTES;
	for (int i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len == 0)
			continue;
		size_t len = iov[i].iov_len < budget ? iov[i].iov_len : budget;
		long r = sys_write(p, fd, iov[i].iov_base, len);
		if (r < 0)
			return total ? total : r;
		if ((size_t)r > len)
			return total ? total : -LXP_EIO; /* host backend violated the write contract */
		total += r;
		budget -= (size_t)r;
		if (single_segment || (size_t)r < len || len < iov[i].iov_len || budget == 0)
			break; /* short write */
	}
	return total;
}

static long sys_read(lxp_proc_t *p, int fd, void *buf, size_t len)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!user_ok(p, buf, len, 1)) /* the kernel WRITES buf → reject a bad destination pointer */
		return -LXP_EFAULT;
	if (s->ops && s->ops->read)
		return s->ops->read(p, s, buf, len);
	return -LXP_EBADF;
}

/*
 * pread64(fd, buf, count, offset): a positioned read that does NOT move the fd offset.
 * ld.so uses it to pull each PT_LOAD of a .so out of the rootfs into the anonymous memory
 * it mapped (the NOMMU path: MAP_FIXED-file mmap fails, so it mmaps anon + preads). Only
 * regular (seekable) files are supported — console/pipe return ESPIPE.
 */
static long sys_pread(lxp_proc_t *p, int fd, void *buf, size_t len, uint32_t off)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!user_ok(p, buf, len, 1))
		return -LXP_EFAULT;

#if LXP_ENABLE_DEV
	if (s->kind == LXP_FD_DEV)
		return lxp_dev_pread(p, s->file_idx, buf, len, off);
#endif
	const uint8_t *data;
	size_t size;
	if (s->kind == LXP_FD_TMPFS) {
		lxp_wnode_t *t = wnode_at(s->file_idx);
		if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
			return -LXP_EISDIR;
		data = (const uint8_t *)t->data;
		size = t->size;
	} else if (s->kind == LXP_FD_PROC) {
		if (g_procf[s->file_idx].is_dir)
			return -LXP_EISDIR;
		data = (const uint8_t *)g_procf[s->file_idx].buf;
		size = g_procf[s->file_idx].len;
	} else if (s->kind == LXP_FD_CONSOLE || s->kind == LXP_FD_PIPE) {
		return -LXP_ESPIPE; /* not seekable */
	} else {
		const lxp_file_t *f = &p->fs[s->file_idx];
		if ((file_mode(f) & LXP_S_IFMT) == LXP_S_IFDIR)
			return -LXP_EISDIR;
		data = (const uint8_t *)f->data;
		size = f->size;
	}
	if ((size_t)off >= size)
		return 0; /* EOF */
	size_t n = size - off;
	if (n > len)
		n = len;
	memcpy(buf, data + off, n);
	return (long)n;
}

/*
 * pwrite64(fd, buf, count, offset): a positioned write that does NOT move the fd offset.
 * LVGL's fbdev driver (LV_LINUX_FBDEV_MMAP=0) writes each framebuffer scanline this way.
 * Device fds route to the driver; the writable overlay writes at the offset; the read-only
 * rootfs and console/pipe are not positioned-writable (ESPIPE).
 */
static long sys_pwrite(lxp_proc_t *p, int fd, const void *buf, size_t len, uint32_t off)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!user_ok(p, buf, len, 0))
		return -LXP_EFAULT;
#if LXP_ENABLE_DEV
	if (s->kind == LXP_FD_DEV)
		return lxp_dev_pwrite(p, s->file_idx, buf, len, off);
#endif
	if (s->kind == LXP_FD_TMPFS) {
		lxp_wnode_t *t = wnode_at(s->file_idx);
		if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
			return -LXP_EBADF;
		if ((size_t)off + len < len) /* off+len wrapped a 32-bit size_t → tiny reserve, OOB write */
			return -LXP_EINVAL;
		if (wfs_reserve(s->file_idx, (size_t)off + len) != 0)
			return -LXP_EFBIG;
		if ((size_t)off > t->size) /* zero the sparse hole (else it leaks stale pool bytes) */
			memset(t->data + t->size, 0, (size_t)off - t->size);
		memcpy(t->data + off, buf, len);
		if ((size_t)off + len > t->size)
			t->size = (size_t)off + len;
		return (long)len;
	}
	return -LXP_ESPIPE; /* console / pipe / read-only rootfs */
}

/*
 * mprotect: a no-op on NOMMU (there is no per-page protection). ld.so calls it to apply
 * PT_GNU_RELRO hardening; it must succeed rather than fault the loader.
 */
static long sys_mprotect(uintptr_t addr, size_t len, int prot)
{
	(void)addr;
	(void)len;
	(void)prot;
	return 0;
}

static long sys_brk(lxp_proc_t *p, uintptr_t addr)
{
	/* Linux brk: move the break to addr if valid, then return the (possibly
	 * unchanged) break. uClibc's sbrk detects failure by ret != requested. */
	if (addr >= p->brk_base && addr <= p->brk_max)
		p->brk_cur = addr;
	return (long)p->brk_cur;
}

static long sys_exit(lxp_proc_t *p, int status)
{
	p->exited = 1;
	p->exit_status = status & 0xff;
	p->exit_reason = LXP_EXIT_REASON_NORMAL;
	p->exit_signal = 0;
	p->exit_detail = 0;
	p->exit_address = 0;
	return 0;
}

/*
 * Anonymous mmap, backed by the process arena (uClibc's malloc uses it for
 * larger allocations). File mappings need a VFS and are not supported yet.
 */
static long sys_mmap2(lxp_proc_t *p, uintptr_t addr, size_t len, int prot, int flags, int fd,
		      uint32_t pgoff)
{
	(void)addr;
	if (len == 0)
		return -LXP_EINVAL;

	/* Text-sharing: a read-only file map of a rootfs file whose whole extent lies within the file
	 * is returned IN-PLACE (zero-copy). FDPIC text is pure PIC — its relocations land in the
	 * per-process GOT/data, never the shared text — so every dynamic process shares ONE libc.so
	 * text copy (the embedded cpio bytes) instead of its own ~358K arena copy. Privileged engines
	 * (FreeRTOS/NuttX) reach the cpio directly; Zephyr embeds the cpio in an executable .text
	 * subsection (.text.ove_rootfs), covered by the kernel's user-RX .text MPU region, so the
	 * unprivileged program reads + executes the in-place text there too — no separate partition. */
	if (!(flags & LXP_MAP_ANONYMOUS) && fd >= 0 && !(prot & 0x2 /* PROT_WRITE */)) {
		lxp_fd_t *s = fd_slot(p, fd);
		if (s && s->kind == LXP_FD_FILE) {
			const lxp_file_t *f = &p->fs[s->file_idx];
			size_t foff = (size_t)pgoff * 4096u; /* guard the *4096 and +len wraps (32-bit) */
			if (foff / 4096u == (size_t)pgoff && foff <= f->size && f->size - foff >= len)
				return (long)(uintptr_t)(f->data + foff);
		}
	}

#if LXP_ENABLE_DEV
	/* Device mmap (P3): a real /dev fd with a driver .mmap op (e.g. /dev/fb0) is mapped to
	 * the device's own buffer — lxp_dev_mmap parks on DEVW_MMAP and the coordinator
	 * installs the unprivileged MPU region + resumes with the mapped address. Devices
	 * without an .mmap op return -ENODEV and fall through to the anonymous-arena copy. */
	if (fd >= 0 && !(flags & LXP_MAP_ANONYMOUS)) {
		lxp_fd_t *s = fd_slot(p, fd);
		if (s && s->kind == LXP_FD_DEV) {
			long r = lxp_dev_mmap(p, s->file_idx, len, pgoff);
			if (r != -LXP_ENODEV)
				return r;
		}
	}
#endif

	void *m = lxp_arena_alloc_tracked(p->arena, len);
	if (!m)
		return -LXP_ENOMEM;
	memset(m, 0, len); /* anon reads as zero; also zero-fills a file map's bss tail */
	if (!(flags & LXP_MAP_ANONYMOUS) && fd >= 0) {
		/* File-backed mapping: ld.so loads a .so's read-only segment (the symtab/hash/
		 * text) this way on NOMMU — read the file's bytes at the page offset into the
		 * freshly-allocated block. (Anonymous maps ignore the fd.) */
		long r = sys_pread(p, fd, m, len, pgoff * 4096u);
		if (r < 0) {
			(void)lxp_arena_free_tracked(p->arena, m, len);
			return r;
		}
	}
	return (long)(uintptr_t)m;
}

/*
 * Arena-backed mappings are reclaimed only when both address and original
 * length match a privileged live-extent record.  Guest-writable arena headers
 * are not mapping authority: interior, stale, partial, brk and double unmaps
 * fail without changing allocator state.  Rootfs zero-copy and device mappings
 * live outside the arena and remain successful no-ops on this NOMMU target.
 */
static long sys_munmap(lxp_proc_t *p, uintptr_t addr, size_t len)
{
	if (!p || !p->arena || len == 0)
		return -LXP_EINVAL;
	if (!lxp_arena_owns(p->arena, (void *)addr))
		return 0;
	return lxp_arena_free_tracked(p->arena, (void *)addr, len) ? 0 : -LXP_EINVAL;
}

/* open a rootfs file read-only; the fs is immutable, so writes are refused. */
/* Claim the lowest free fd for (kind, idx, off); -EMFILE if the table is full. */
static int fd_alloc(lxp_proc_t *p, uint8_t kind, int idx, size_t off)
{
	for (int fd = 0; fd < LXP_MAX_FDS; fd++) {
		if (p->fds[fd].kind == LXP_FD_FREE) {
			p->fds[fd].kind = kind;
			p->fds[fd].rw = 0;
			p->fds[fd].cloexec = 0;
			p->fds[fd].nonblock = 0; /* else stale from the slot's prior occupant */
			p->fds[fd].file_idx = idx;
			p->fds[fd].offset = off;
			p->fds[fd].ops = ops_for_kind(kind);
			return fd;
		}
	}
	return -LXP_EMFILE;
}

/* Public wrapper so the socket bridge can mint an accept(2) fd (the fd table is
 * owned by this TU; the bridge owns the socket pool). */
int lxp_fd_install(lxp_proc_t *p, uint8_t kind, int idx)
{
	return fd_alloc(p, kind, idx, 0);
}

/* eventfd(2): a 64-bit counter fd used to wake a poller from another thread — curl's
 * threaded resolver (AsynchDNS) writes it when a name resolves. Threads share the fd
 * table (CLONE_VM), so both ends address the same counter by its pool index. */
#define LXP_NEVENTFD 8
static struct {
	uint64_t ctr;
	uint16_t flags;
	uint8_t used;
} g_efd[LXP_NEVENTFD];

static long efd_new(unsigned initval, int flags)
{
	for (int i = 0; i < LXP_NEVENTFD; i++)
		if (!g_efd[i].used) {
			g_efd[i].used = 1;
			g_efd[i].ctr = initval;
			g_efd[i].flags = (uint16_t)flags;
			return i;
		}
	return -LXP_EMFILE;
}

/* Release an eventfd pool slot at close(2). Any close frees it — threads share the
 * fd table, so one close is enough (matches the pre-vtable close semantics). */
static void efd_close(int ei)
{
	if (ei >= 0 && ei < LXP_NEVENTFD)
		g_efd[ei].used = 0;
}

static int efd_readable(int ei)
{
	return (ei >= 0 && ei < LXP_NEVENTFD && g_efd[ei].ctr) ? 1 : 0;
}

/* eventfd read/write: 8-byte counter. read returns (and clears, or decrements in
 * SEMAPHORE mode) the counter, EAGAIN when zero (the caller polls first); write adds. */
static long efd_read(lxp_proc_t *p, int ei, void *buf, size_t len)
{
	if (ei < 0 || ei >= LXP_NEVENTFD || !g_efd[ei].used)
		return -LXP_EBADF;
	if (len < 8)
		return -LXP_EINVAL;
	if (g_efd[ei].ctr == 0)
		return -LXP_EAGAIN; /* counter empty; the poller re-checks on the tick */
	if (!user_ok(p, buf, 8, 1))
		return -LXP_EFAULT;
	uint64_t v = (g_efd[ei].flags & LXP_EFD_SEMAPHORE) ? 1u : g_efd[ei].ctr;
	g_efd[ei].ctr -= v;
	memcpy(buf, &v, 8);
	return 8;
}

static long efd_write(lxp_proc_t *p, int ei, const void *buf, size_t len)
{
	if (ei < 0 || ei >= LXP_NEVENTFD || !g_efd[ei].used)
		return -LXP_EBADF;
	if (len < 8)
		return -LXP_EINVAL;
	if (!user_ok(p, buf, 8, 0))
		return -LXP_EFAULT;
	uint64_t v;
	memcpy(&v, buf, 8);
	if (v == UINT64_MAX) /* -1 is reserved */
		return -LXP_EINVAL;
	if (UINT64_MAX - g_efd[ei].ctr - 1 < v) /* would overflow past max-1 */
		g_efd[ei].ctr = UINT64_MAX - 1;
	else
		g_efd[ei].ctr += v;
	return 8;
}


/* Open a /proc node: a generated-content file fd, or a directory fd for
 * getdents. Returns an fd, or a negative errno (caller already resolved `abs`). */
static long proc_open(lxp_proc_t *p, const char *abs)
{
	uint32_t m = proc_mode(abs, p);
	if (m == 0 || (m & LXP_S_IFMT) == LXP_S_IFLNK)
		return -LXP_ENOENT; /* /proc/self resolves via readlink, not open */
	if (strlen(abs) >= LXP_PROCPATH) /* the cached path buffer is /proc-sized, not PATH_MAX */
		return -LXP_ENOENT;
	int dir = (m & LXP_S_IFMT) == LXP_S_IFDIR;
	for (int i = 0; i < LXP_NPROCF; i++) {
		if (g_procf[i].used)
			continue;
		long n = dir ? 0 : proc_gen(abs, p, g_procf[i].buf, LXP_PROCBUF);
		if (n < 0)
			return -LXP_ENOENT;
		strcpy(g_procf[i].path, abs);
		g_procf[i].len = (size_t)n;
		g_procf[i].is_dir = dir;
		g_procf[i].used = 1;
		int fd = fd_alloc(p, LXP_FD_PROC, i, 0);
		if (fd < 0)
			g_procf[i].used = 0; /* no fd installed → release the content slot */
		return fd;
	}
	return -LXP_EMFILE;
}

static long sys_openat(lxp_proc_t *p, int dirfd, const char *path, int flags)
{
	(void)dirfd; /* dirfd is AT_FDCWD; relative paths resolve against p->cwd */
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	path = abspath;
	if (proc_is(path)) /* synthetic /proc shadows everything */
		return proc_open(p, path);
	/* The synthetic console/null/random nodes all open as an FD_CONSOLE; file_idx selects
	 * the behaviour (2 = r/w console, 3 = /dev/null → EOF/discard, 4 = host entropy,
	 * 5 = /dev/zero → zero-fill/discard). A small name→idx table instead of a strcmp chain
	 * (smaller .text). getty opens /dev/console + dups it to fds 0/1/2; dropbear/mbedTLS open
	 * /dev/urandom for entropy. */
	static const struct {
		const char *path;
		uint8_t idx;
	} console_dev[] = {
		{"/dev/console", 2}, {"/dev/tty", 2},	  {"/dev/tty0", 2}, {"/dev/ttyS0", 2},
		{"/dev/null", 3},    {"/dev/urandom", 4}, {"/dev/random", 4}, {"/dev/zero", 5},
	};
	for (size_t k = 0; k < sizeof(console_dev) / sizeof(console_dev[0]); k++)
		if (strcmp(path, console_dev[k].path) == 0)
			return fd_alloc(p, LXP_FD_CONSOLE, console_dev[k].idx, 0);
#if LXP_ENABLE_PTY
	/* Unix98 pty: each open of /dev/ptmx mints a fresh pair (the master, rw=1); the
	 * slave is /dev/pts/N (rw=0), N = the pool index from TIOCGPTN/ptsname. */
	if (strcmp(path, "/dev/ptmx") == 0) {
		long idx = lxp_pty_open_master(flags);
		if (idx < 0)
			return idx;
		int fd = fd_alloc(p, LXP_FD_PTY, (int)idx, 0);
		if (fd >= 0)
			p->fds[fd].rw = 1; /* master end */
		return fd;
	}
	if (strncmp(path, "/dev/pts/", 9) == 0) {
		int num = 0;
		const char *d = path + 9;
		if (*d < '0' || *d > '9')
			return -LXP_ENOENT;
		for (; *d >= '0' && *d <= '9'; d++)
			num = num * 10 + (*d - '0');
		if (*d != '\0')
			return -LXP_ENOENT;
		long idx = lxp_pty_open_slave(num, flags);
		if (idx < 0)
			return idx;
		return fd_alloc(p, LXP_FD_PTY, (int)idx, 0); /* slave end (rw=0) */
	}
#endif
#if LXP_ENABLE_DEV
	/* Registered character devices (/dev/fb0, /dev/input/event0, ...). A hit opens
	 * an FD_DEV whose file_idx is the device open-pool index; a miss falls through. */
	{
		int di = lxp_dev_lookup(path);
		if (di >= 0) {
			long oi = lxp_dev_open_new(p, di, flags);
			if (oi < 0)
				return oi;
			int fd = fd_alloc(p, LXP_FD_DEV, (int)oi, 0);
			if (fd < 0)
				lxp_dev_close((int)oi);
			return fd;
		}
	}
#endif
#if LXP_ENABLE_NETFS
	/* Remote 9P mount (/mnt/pi): read-only browse. Shadows the RO rootfs; the open
	 * parks (walk+getattr+lopen round-trips) and the coordinator installs the fd. */
	if (lxp_netfs_lookup(path) >= 0)
		return lxp_netfs_open(p, path, flags);
#endif
	int wr = (flags & LXP_O_ACCMODE) != LXP_O_RDONLY;
	int wi = wfs_find(path);

	/* A writable open (or O_CREAT) goes to the writable VFS overlay. */
	if (wr || (flags & LXP_O_CREAT)) {
		if (wi < 0) {
			if (!(flags & LXP_O_CREAT)) {
				if (fs_lookup(p, path) >= 0)
					return -LXP_EROFS; /* RO rootfs file */
				return -LXP_ENOENT;
			}
			wi = wfs_create(path, LXP_S_IFREG | 0644u);
			if (wi < 0)
				return -LXP_EMFILE;
		} else {
			if ((wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR)
				return -LXP_EISDIR;
			if (flags & LXP_O_TRUNC)
				wnode_at(wi)->size = 0;
		}
		return fd_alloc(p, LXP_FD_TMPFS, wi,
				(flags & LXP_O_APPEND) ? wnode_at(wi)->size : 0);
	}

	/* Read: a writable node shadows the rootfs; else the read-only rootfs. */
	if (wi >= 0)
		return fd_alloc(p, LXP_FD_TMPFS, wi, 0);
	/* Follow symlinks so a read open of e.g. /lib/libc.so.0 -> libuClibc.so returns the
	 * target ELF (ld.so opens its .so deps by their symlinked SONAMEs). */
	int idx = fs_follow(p, fs_lookup(p, path));
	if (idx >= 0)
		return fd_alloc(p, LXP_FD_FILE, idx, 0);
	return -LXP_ENOENT;
}

static long sys_close(lxp_proc_t *p, int fd)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (s->ops && s->ops->close)
		s->ops->close(p, s); /* release the backing object (refcount-- / pool slot) */
	s->kind = LXP_FD_FREE;
	return 0;
}

/* pipe(2)/pipe2(2): allocate a pipe object + a read-end / write-end fd pair. @p flags
 * carries O_CLOEXEC for pipe2 (dropbear's exec-status pipe is a CLOEXEC pipe2). */
static long sys_pipe(lxp_proc_t *p, int *fds, int flags)
{
	if (!user_ok(p, fds, 2 * sizeof(int), 1)) /* the kernel writes fds[0],fds[1] */
		return -LXP_EFAULT;
	uint8_t cx = (flags & LXP_O_CLOEXEC) ? 1 : 0;
	uint8_t nb = (flags & LXP_O_NONBLOCK) ? 1 : 0; /* pipe2(O_NONBLOCK): both ends non-blocking */
	/* Claim a free pipe slot (one with no live holders — auto-reclaimed when both ends
	 * close or the holders exit; there is no explicit pipe free path). */
	int pi = lxp_pipe_alloc();
	if (pi < 0)
		return -LXP_EMFILE;
	int rfd = -1, wfd = -1;
	for (int fd = 0; fd < LXP_MAX_FDS && wfd < 0; fd++) {
		if (p->fds[fd].kind != LXP_FD_FREE)
			continue;
		if (rfd < 0)
			rfd = fd;
		else
			wfd = fd;
	}
	if (wfd < 0)
		return -LXP_EMFILE;
	p->fds[rfd] = (lxp_fd_t){.kind = LXP_FD_PIPE, .rw = 0, .cloexec = cx, .nonblock = nb,
				 .file_idx = pi, .ops = ops_for_kind(LXP_FD_PIPE)};
	p->fds[wfd] = (lxp_fd_t){.kind = LXP_FD_PIPE, .rw = 1, .cloexec = cx, .nonblock = nb,
				 .file_idx = pi, .ops = ops_for_kind(LXP_FD_PIPE)};
	fds[0] = rfd;
	fds[1] = wfd;
	return 0;
}

/* dup/dup2/F_DUPFD: the new fd aliases oldfd's backing object, so take a reference on the
 * refcounted-backend kinds. Consolidates the get all three call sites open-coded (F_DUPFD
 * had previously omitted netfs — now consistent). */
static void fd_dup_backing(const lxp_fd_t *s)
{
	(void)s;
#if LXP_ENABLE_DEV
	if (s->kind == LXP_FD_DEV)
		lxp_dev_get(s->file_idx);
#endif
#if LXP_ENABLE_NET
	if (s->kind == LXP_FD_SOCKET)
		lxp_sock_get(s->file_idx);
#endif
#if LXP_ENABLE_NETFS
	if (s->kind == LXP_FD_NET)
		lxp_netfs_get(s->file_idx);
#endif
}

/* dup2 replaces its target fd: release the replaced fd's backing (dev/socket/netfs) first. */
static void fd_release_backing(const lxp_fd_t *s)
{
	(void)s;
#if LXP_ENABLE_DEV
	if (s->kind == LXP_FD_DEV)
		lxp_dev_close(s->file_idx);
#endif
#if LXP_ENABLE_NET
	if (s->kind == LXP_FD_SOCKET)
		lxp_sock_close(s->file_idx);
#endif
#if LXP_ENABLE_NETFS
	if (s->kind == LXP_FD_NET)
		lxp_netfs_close(s->file_idx);
#endif
}

/* dup2/dup3: make newfd alias oldfd's target (the pipe wiring the shell does). */
static long sys_dup2(lxp_proc_t *p, int oldfd, int newfd)
{
	lxp_fd_t *s = fd_slot(p, oldfd);
	if (!s)
		return -LXP_EBADF;
	if (newfd < 0 || newfd >= LXP_MAX_FDS)
		return -LXP_EBADF;
	if (oldfd != newfd) {
		fd_release_backing(&p->fds[newfd]); /* dup2 closes the target first */
		p->fds[newfd] = *s;
		p->fds[newfd].cloexec = 0; /* dup2/dup3 clear FD_CLOEXEC; dup3(O_CLOEXEC) re-sets it */
		fd_dup_backing(s);	   /* the new fd shares oldfd's backing */
	}
	return newfd;
}

/* dup(2): alias oldfd onto the lowest free fd. */
static long sys_dup(lxp_proc_t *p, int oldfd)
{
	lxp_fd_t *s = fd_slot(p, oldfd);
	if (!s)
		return -LXP_EBADF;
	for (int fd = 0; fd < LXP_MAX_FDS; fd++) {
		if (p->fds[fd].kind == LXP_FD_FREE) {
			p->fds[fd] = *s;
			p->fds[fd].cloexec = 0; /* dup(2) clears FD_CLOEXEC on the new fd */
			fd_dup_backing(s);	/* the dup shares oldfd's backing */
			return fd;
		}
	}
	return -LXP_EMFILE;
}

static long sys_lseek(lxp_proc_t *p, int fd, long off, int whence)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (s->ops && s->ops->lseek)
		return s->ops->lseek(p, s, off, whence);
	return -LXP_ESPIPE; /* console/pipe/proc/eventfd/pty/socket not seekable */
}

/* _llseek(fd, offset_high, offset_low, loff_t *result, whence): the 64-bit-offset
 * seek uClibc uses in large-file mode. Pagers/editors (less/more/vi) seek to size
 * the file (the %-position). Our files are well under 4 GB so offset_high is 0. */
static long sys_llseek(lxp_proc_t *p, int fd, unsigned long off_hi, unsigned long off_lo,
		       uint64_t *result, unsigned int whence)
{
	(void)off_hi;
	long pos = sys_lseek(p, fd, (long)off_lo, (int)whence);
	if (pos < 0)
		return pos;
	if (result && !user_ok(p, result, sizeof(*result), 1))
		return -LXP_EFAULT;
	if (result)
		*result = (uint64_t)pos;
	return 0;
}

/* ftruncate64(fd, length) on a writable-VFS file: set its logical size, growing
 * with zeros if needed. vi's :w writes the new content then truncates to the exact
 * length, so editing an existing file shorter drops the old trailing bytes. */
static long sys_ftruncate(lxp_proc_t *p, int fd, uint64_t length)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (s->kind != LXP_FD_TMPFS)
		return -LXP_EINVAL; /* the rootfs is read-only; console/pipe N/A */
	lxp_wnode_t *t = wnode_at(s->file_idx);
	if ((t->mode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EISDIR;
	size_t newlen = (size_t)length;
	if (newlen > t->size) {
		if (wfs_reserve(s->file_idx, newlen) != 0)
			return -LXP_EFBIG;
		memset(t->data + t->size, 0, newlen - t->size);
	}
	t->size = newlen;
	return 0;
}

/* Fill an ARM kstat64 from a node's inode + mode + size. */
static void fill_kstat64(struct lxp_kstat64 *st, uint32_t ino, uint32_t mode, uint64_t size)
{
	memset(st, 0, sizeof(*st));
	st->st_nlink = 1;
	/* A UNIQUE, non-zero inode per node: ld.so dedups loaded objects by (st_dev, st_ino),
	 * so a zero inode makes every .so look already-loaded — libc.so would be skipped and
	 * its symbols never resolve. */
	st->__st_ino = ino;
	st->st_ino = ino;
	st->st_mode = mode;
	st->st_size = (int64_t)size;
	/* A character device blksize makes uClibc block-buffer stdio. */
	st->st_blksize = ((mode & LXP_S_IFMT) == LXP_S_IFCHR) ? 1024u : 512u;
	st->st_blocks = (uint64_t)((size + 511u) / 512u);
}

static long sys_fstat64(lxp_proc_t *p, int fd, void *statbuf)
{
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!user_ok(p, statbuf, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT;
	if (s->ops && s->ops->fstat)
		return s->ops->fstat(p, s, statbuf);
	/* console/pipe/eventfd: a bare character device (S_IFCHR) so isatty()/stdio behaves. */
	fill_kstat64(statbuf, 0x300000u + (uint32_t)s->file_idx, LXP_S_IFCHR | 0620u, 0);
	return 0;
}

/* path-based stat: resolve, optionally follow a trailing symlink, fill kstat64. */
static long sys_stat_path(lxp_proc_t *p, const char *path, int follow, void *statbuf)
{
	if (!user_ok(p, statbuf, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (proc_is(abspath)) {
		uint32_t m = proc_mode(abspath, p);
		if (m == 0)
			return -LXP_ENOENT;
		fill_kstat64(statbuf, 0x200000u, m, 0);
		return 0;
	}
#if LXP_ENABLE_DEV
	{
		uint32_t dmode;
		uint64_t drdev;
		if (lxp_dev_stat_path(abspath, &dmode, &drdev) == 0) {
			fill_kstat64(statbuf, 0x300000u, dmode, 0);
			((struct lxp_kstat64 *)statbuf)->st_rdev = drdev;
			return 0;
		}
	}
#endif
#if LXP_ENABLE_NETFS
	if (lxp_netfs_lookup(abspath) >= 0)
		return lxp_netfs_stat(p, abspath, (uintptr_t)statbuf, 0); /* parks */
#endif
	int wi = wfs_find(abspath); /* writable overlay shadows the rootfs */
	if (wi >= 0) {
		fill_kstat64(statbuf, 0x100000u + (uint32_t)wi, wnode_at(wi)->mode, wnode_at(wi)->size);
		return 0;
	}
	int idx = fs_lookup(p, abspath);
	if (idx < 0)
		return -LXP_ENOENT;
	if (follow) {
		idx = fs_follow(p, idx);
		if (idx < 0)
			return -LXP_ENOENT;
	}
	fill_kstat64(statbuf, 1u + (uint32_t)idx, file_mode(&p->fs[idx]), p->fs[idx].size);
	return 0;
}

/* readlink: write the symlink target (not NUL-terminated) + return its length. */
static long sys_readlink(lxp_proc_t *p, const char *path, char *buf, size_t bufsiz)
{
	if (!user_ok(p, buf, bufsiz, 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (strcmp(abspath, "/proc/self") == 0) { /* -> the running process's pid */
		char tmp[12];
		size_t n = p_dec(tmp, 0, sizeof(tmp), (uint64_t)p->pid);
		if (n > bufsiz)
			n = bufsiz;
		memcpy(buf, tmp, n);
		return (long)n;
	}
	if (strcmp(abspath, "/proc/self/exe") == 0) { /* -> the running program's path */
		/* Same running image execve re-runs for "/proc/self/exe" (exec_file_idx). Programs
		 * readlink() this to learn where they were launched from; without it they got ENOENT. */
		int ei = p->exec_file_idx;
		if (ei < 0 || ei >= p->fs_count)
			return -LXP_ENOENT;
		const char *exe = p->fs[ei].path;
		size_t n = strlen(exe);
		if (n > bufsiz)
			n = bufsiz;
		memcpy(buf, exe, n);
		return (long)n;
	}
	int wi = wfs_find(abspath); /* a writable symlink (ln -s) shadows the rootfs */
	if (wi >= 0) {
		lxp_wnode_t *w = wnode_at(wi);
		if ((w->mode & LXP_S_IFMT) != LXP_S_IFLNK || !w->data)
			return -LXP_EINVAL;
		size_t n = w->size > bufsiz ? bufsiz : w->size;
		memcpy(buf, w->data, n);
		return (long)n;
	}
	int idx = fs_lookup(p, abspath);
	if (idx < 0)
		return -LXP_ENOENT;
	const lxp_file_t *lnk = &p->fs[idx];
	if ((file_mode(lnk) & LXP_S_IFMT) != LXP_S_IFLNK || !lnk->data)
		return -LXP_EINVAL;
	size_t n = lnk->size > bufsiz ? bufsiz : lnk->size;
	memcpy(buf, lnk->data, n);
	return (long)n;
}

/* access/faccessat: existence check (all existing nodes are accessible). */
static long sys_access(lxp_proc_t *p, const char *path)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (abspath[0] == '/' && abspath[1] == '\0')
		return 0; /* root */
	if (proc_is(abspath))
		return proc_mode(abspath, p) ? 0 : -LXP_ENOENT;
	if (wfs_find(abspath) >= 0 || fs_lookup(p, abspath) >= 0)
		return 0;
	return -LXP_ENOENT;
}

static long sys_mkdir(lxp_proc_t *p, const char *path, uint32_t mode)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (wfs_find(abspath) >= 0 || fs_lookup(p, abspath) >= 0)
		return -LXP_EEXIST;
	if (wfs_create(abspath, LXP_S_IFDIR | (mode & 0777u)) < 0)
		return -LXP_ENOSPC;
	return 0;
}

/* unlink (is_rmdir=0) / rmdir (is_rmdir=1) on a writable node. */
static long sys_unlink(lxp_proc_t *p, const char *path, int is_rmdir)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	int wi = wfs_find(abspath);
	if (wi < 0)
		return (fs_lookup(p, abspath) >= 0) ? -LXP_EROFS : -LXP_ENOENT;
	int isdir = (wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR;
	if (is_rmdir && !isdir)
		return -LXP_ENOTDIR;
	if (!is_rmdir && isdir)
		return -LXP_EISDIR;
	if (isdir) {
		for (int j = 0; j < LXP_NWNODE; j++)
			if (wnode_at(j)->used && child_name(abspath, wnode_at(j)->path))
				return -LXP_ENOTEMPTY;
	}
	wfs_free(wi); /* reclaim the node + its pool bytes */
	return 0;
}

static long sys_rename(lxp_proc_t *p, const char *oldp, const char *newp)
{
	if (!oldp || !newp)
		return -LXP_EFAULT;
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	long r1 = resolve_path(p, oldp, oldabs, sizeof(oldabs));
	if (r1 < 0)
		return r1;
	long r2 = resolve_path(p, newp, newabs, sizeof(newabs));
	if (r2 < 0)
		return r2;
	int wi = wfs_find(oldabs);
	if (wi < 0)
		return (fs_lookup(p, oldabs) >= 0) ? -LXP_EROFS : -LXP_ENOENT;
	if (strlen(newabs) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	int di = wfs_find(newabs); /* replace an existing destination node */
	if (di >= 0 && di != wi)
		wfs_free(di); /* reclaim the replaced destination's bytes */
	strcpy(wnode_at(wi)->path, newabs);
	return 0;
}

static long sys_symlink(lxp_proc_t *p, const char *target, const char *linkp)
{
	if (!target || !linkp)
		return -LXP_EFAULT;
	if (user_strnlen(p, target, LXP_PATH_MAX) < 0)
		return -LXP_EFAULT; /* target is stored verbatim (strlen'd) — bound it in guest memory */
	char linkabs[LXP_PATH_MAX];
	long rr = resolve_path(p, linkp, linkabs, sizeof(linkabs));
	if (rr < 0)
		return rr;
	if (wfs_find(linkabs) >= 0 || fs_lookup(p, linkabs) >= 0)
		return -LXP_EEXIST;
	int wi = wfs_create(linkabs, LXP_S_IFLNK | 0777u);
	if (wi < 0)
		return -LXP_ENOSPC;
	size_t tl = strlen(target);
	if (wfs_reserve(wi, tl) < 0) {
		wfs_free(wi); /* roll back the just-created node (its data is still NULL) */
		return -LXP_ENOSPC;
	}
	memcpy(wnode_at(wi)->data, target, tl);
	wnode_at(wi)->size = tl;
	return 0;
}

/*
 * link(oldpath, newpath): make newpath name oldpath's file.
 *
 * The writable overlay has no shared-inode / link-count model (st_nlink is always
 * reported as 1), so a true hard link is not representable. We satisfy the call by
 * creating newpath as an independent writable copy of oldpath's current bytes — enough
 * for the only realistic uses on this read-only-rootfs target: `ln a b`, and the
 * write-temp / link / unlink-temp atomic-replace idiom (dropbear host-key generation,
 * mkstemp-based writers, editors). oldpath may live in the RO rootfs or the overlay;
 * directories are rejected with EPERM, matching Linux. The final path component is not
 * dereferenced — link() does not follow a symlink at oldpath.
 */
static long sys_link(lxp_proc_t *p, const char *oldp, const char *newp)
{
	if (!oldp || !newp)
		return -LXP_EFAULT;
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	long r1 = resolve_path(p, oldp, oldabs, sizeof(oldabs));
	if (r1 < 0)
		return r1;
	long r2 = resolve_path(p, newp, newabs, sizeof(newabs));
	if (r2 < 0)
		return r2;
	if (strlen(newabs) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	if (wfs_find(newabs) >= 0 || fs_lookup(p, newabs) >= 0)
		return -LXP_EEXIST;

	/* Source bytes: writable overlay first, then the RO rootfs. */
	const uint8_t *src;
	size_t srclen;
	uint32_t srcmode;
	int wi = wfs_find(oldabs);
	if (wi >= 0) {
		src = wnode_at(wi)->data;
		srclen = wnode_at(wi)->size;
		srcmode = wnode_at(wi)->mode;
	} else {
		int idx = fs_lookup(p, oldabs);
		if (idx < 0)
			return -LXP_ENOENT;
		src = p->fs[idx].data;
		srclen = p->fs[idx].size;
		srcmode = file_mode(&p->fs[idx]);
	}
	if ((srcmode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EPERM; /* hard links to directories are not permitted */

	int ni = wfs_create(newabs, LXP_S_IFREG | (srcmode & 0777u));
	if (ni < 0)
		return -LXP_ENOSPC;
	if (srclen > 0) {
		if (wfs_reserve(ni, srclen) < 0) {
			wfs_free(ni); /* roll back the just-created node (its data is still NULL) */
			return -LXP_ENOSPC;
		}
		memcpy(wnode_at(ni)->data, src, srclen); /* the arena never moves the source block */
		wnode_at(ni)->size = srclen;
	}
	return 0;
}

static long sys_chmod(lxp_proc_t *p, const char *path, uint32_t mode)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	int wi = wfs_find(abspath);
	if (wi >= 0) {
		wnode_at(wi)->mode = (wnode_at(wi)->mode & LXP_S_IFMT) | (mode & 0777u);
		return 0;
	}
	return (fs_lookup(p, abspath) >= 0) ? 0 : -LXP_ENOENT; /* rootfs: accept, inert */
}

/* utimensat: times are not tracked, but the existence check must be honest —
 * `touch` probes with utimensat first and only creates the file on -ENOENT. */
static long sys_utimensat(lxp_proc_t *p, const char *path)
{
	if (!path) /* futimens(fd): operate on the open fd — accept */
		return 0;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if ((abspath[0] == '/' && abspath[1] == '\0') || wfs_find(abspath) >= 0 ||
	    fs_lookup(p, abspath) >= 0)
		return 0;
	return -LXP_ENOENT;
}

/* Fill a guest buffer through the active host entropy provider. The port contract
 * is all-or-error: it returns LXP_OK only after writing every requested byte.
 * Missing entropy is ENOSYS for getrandom(2), but an already-open random device
 * reports EIO. A transient non-blocking provider maps to EAGAIN. */
static long random_fill(void *buf, size_t count, int unavailable_errno)
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
	if ((flags & ~valid) != 0u ||
	    (flags & (LXP_GRND_RANDOM | LXP_GRND_INSECURE)) ==
		    (LXP_GRND_RANDOM | LXP_GRND_INSECURE))
		return -LXP_EINVAL;
	if (count == 0u)
		return 0;
	if (!user_ok(p, buf, count, 1))
		return -LXP_EFAULT;
	return random_fill(buf, count, LXP_ENOSYS);
}

/* statfs64: synthetic filesystem stats (no real block device backs the rootfs). */
struct lxp_statfs64 {
	uint32_t f_type, f_bsize;
	uint64_t f_blocks, f_bfree, f_bavail, f_files, f_ffree;
	uint32_t f_fsid[2], f_namelen, f_frsize, f_flags, f_spare[4];
};
LXP_STATIC_ASSERT(sizeof(struct lxp_statfs64) == 88, "statfs64 ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statfs64, f_blocks) == 8, "statfs64 f_blocks offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statfs64, f_namelen) == 56, "statfs64 f_namelen offset drifted");
static long sys_statfs(lxp_proc_t *p, void *buf)
{
	if (!user_ok(p, buf, sizeof(struct lxp_statfs64), 1))
		return -LXP_EFAULT;
	struct lxp_statfs64 *st = buf;
	memset(st, 0, sizeof(*st));
	st->f_type = 0x01021994u; /* TMPFS_MAGIC */
	st->f_bsize = 4096;
	st->f_frsize = 4096;
	st->f_blocks = 256;
	st->f_bfree = 192;
	st->f_bavail = 192;
	st->f_files = 64;
	st->f_ffree = 48;
	st->f_namelen = 255;
	return 0;
}

/* Directory-entry format for the in-progress getdents: 1 = linux_dirent64 (getdents64),
 * 0 = the 32-bit linux_dirent (getdents). Set by the two entry points; the walk is single
 * threaded (the coordinator runs one syscall at a time), so a file-static is safe here. */
static int s_dirent_is64 = 1;

/* Append one dirent record in the s_dirent_is64 format (the 32-bit linux_dirent puts d_type
 * as a trailing byte at d_reclen-1). Skips entries already emitted (pos < s->offset);
 * returns 0 if the record does not fit, else 1 (and advances). */
static int dirent_emit(uint8_t *out, size_t count, size_t *filled, long *pos, lxp_fd_t *s,
		       uint64_t ino, const char *name, uint32_t mode)
{
	int is64 = s_dirent_is64;
	if (*pos < (long)s->offset) {
		(*pos)++;
		return 1; /* already returned by an earlier getdents call */
	}
	size_t namelen = strlen(name);
	uint8_t dtype = ((mode & LXP_S_IFMT) == LXP_S_IFDIR)   ? LXP_DT_DIR
			: ((mode & LXP_S_IFMT) == LXP_S_IFCHR) ? LXP_DT_CHR
								       : LXP_DT_REG;
	if (is64) {
		size_t reclen = (offsetof(struct lxp_dirent64, d_name) + namelen + 1 + 7u) &
				~(size_t)7u;
		if (*filled + reclen > count)
			return 0;
		struct lxp_dirent64 *de = (struct lxp_dirent64 *)(out + *filled);
		de->d_ino = ino;
		de->d_off = *pos + 1;
		de->d_reclen = (uint16_t)reclen;
		de->d_type = dtype;
		memcpy(de->d_name, name, namelen + 1);
		*filled += reclen;
	} else {
		/* 32-bit linux_dirent: [d_ino:4][d_off:4][d_reclen:2][name+NUL][pad][d_type:1]. */
		size_t reclen = (8u + 2u + namelen + 1u + 1u + 7u) & ~(size_t)7u;
		if (*filled + reclen > count)
			return 0;
		uint8_t *r = out + *filled;
		uint32_t di = (uint32_t)ino, doff = (uint32_t)(*pos + 1);
		uint16_t rl = (uint16_t)reclen;
		memcpy(r, &di, 4);
		memcpy(r + 4, &doff, 4);
		memcpy(r + 8, &rl, 2);
		memcpy(r + 10, name, namelen + 1);
		for (size_t k = 10 + namelen + 1; k < reclen - 1; k++)
			r[k] = 0;
		r[reclen - 1] = dtype;
		*filled += reclen;
	}
	(*pos)++;
	s->offset++;
	return 1;
}

/* getdents/getdents64: emit the directory's immediate children (read-only rootfs entries
 * + writable-overlay nodes) as linux_dirent (is64=0) or linux_dirent64 (is64=1) records.
 * uClibc's readdir on this FDPIC target uses the 32-bit getdents(2) for some callers (e.g.
 * dropbear's pty session setup), so both are supported. */
static long sys_getdents64(lxp_proc_t *p, int fd, void *buf, size_t count, int is64)
{
	s_dirent_is64 = is64;
	lxp_fd_t *s = fd_slot(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!user_ok(p, buf, count, 1))
		return -LXP_EFAULT;
	const char *dirpath;
	if (s->kind == LXP_FD_FILE) {
		if ((file_mode(&p->fs[s->file_idx]) & LXP_S_IFMT) != LXP_S_IFDIR)
			return -LXP_ENOTDIR;
		dirpath = p->fs[s->file_idx].path;
	} else if (s->kind == LXP_FD_TMPFS) {
		if ((wnode_at(s->file_idx)->mode & LXP_S_IFMT) != LXP_S_IFDIR)
			return -LXP_ENOTDIR;
		dirpath = wnode_at(s->file_idx)->path;
	} else if (s->kind == LXP_FD_PROC) {
		if (!g_procf[s->file_idx].is_dir)
			return -LXP_ENOTDIR;
		dirpath = g_procf[s->file_idx].path;
#if LXP_ENABLE_NETFS
	} else if (s->kind == LXP_FD_NET) {
		/* Remote dir: a Treaddir round-trip → the netfs layer emits the records. Parks. */
		return lxp_netfs_getdents(p, s->file_idx, (uintptr_t)buf, count, is64);
#endif
	} else {
		return -LXP_ENOTDIR;
	}

	uint8_t *out = (uint8_t *)buf;
	size_t filled = 0;
	long pos = 0; /* running child index across both sources; s->offset = emitted */
	int full = 0;
	/* rootfs children (a writable node of the same path shadows the rootfs one) */
	for (int i = 0; i < p->fs_count && !full; i++) {
		const char *name = child_name(dirpath, p->fs[i].path);
		if (!name || wfs_find(p->fs[i].path) >= 0)
			continue;
		if (!dirent_emit(out, count, &filled, &pos, s, (uint64_t)(i + 1), name,
				 file_mode(&p->fs[i])))
			full = 1;
	}
	/* writable-overlay children */
	for (int i = 0; i < LXP_NWNODE && !full; i++) {
		if (!wnode_at(i)->used)
			continue;
		const char *name = child_name(dirpath, wnode_at(i)->path);
		if (!name)
			continue;
		if (!dirent_emit(out, count, &filled, &pos, s, (uint64_t)(100000 + i), name,
				 wnode_at(i)->mode))
			full = 1;
	}
#if LXP_ENABLE_DEV
	/* registered character devices whose node sits directly under this dir (/dev/fb0). */
	for (int i = 0; i < lxp_dev_count() && !full; i++) {
		uint32_t dmode = LXP_S_IFCHR | 0666u;
		const char *dp = lxp_dev_path(i, &dmode);
		const char *name = dp ? child_name(dirpath, dp) : NULL;
		if (!name)
			continue;
		if (!dirent_emit(out, count, &filled, &pos, s, (uint64_t)(0x300000 + i), name, dmode))
			full = 1;
	}
#endif
	/* synthetic /proc children */
	if (!full && proc_is(dirpath)) {
		const char *file;
		int dpid = proc_pid(dirpath, p, &file);
		if (strcmp(dirpath, "/proc") == 0) {
			uint64_t ino = 200000;
			for (int i = 0; g_proc_files[i] && !full; i++)
				if (!dirent_emit(out, count, &filled, &pos, s, ino++,
						 g_proc_files[i], LXP_S_IFREG))
					full = 1;
			if (!full && !dirent_emit(out, count, &filled, &pos, s, ino++, "self",
						  LXP_S_IFLNK))
				full = 1;
			/* every live process + kernel thread from the ps/top snapshot */
			int np = lxp_pent_count(), seen1 = 0, seenself = 0;
			for (int i = 0; i < np && !full; i++) {
				const struct lxp_pentry *e = lxp_pent_at(i);
				if (!e)
					break;
				char pidstr[12];
				size_t k = p_dec(pidstr, 0, sizeof(pidstr) - 1, (uint64_t)e->pid);
				pidstr[k] = '\0';
				seen1 |= (e->pid == 1);
				seenself |= (e->pid == p->pid);
				if (!dirent_emit(out, count, &filled, &pos, s, ino++, pidstr,
						 LXP_S_IFDIR))
					full = 1;
			}
			/* fallbacks before the first snapshot refresh populates the table */
			if (!full && !seen1 &&
			    !dirent_emit(out, count, &filled, &pos, s, ino++, "1", LXP_S_IFDIR))
				full = 1;
			if (!full && !seenself && p->pid != 1) {
				char pidstr[12];
				size_t k = p_dec(pidstr, 0, sizeof(pidstr) - 1, (uint64_t)p->pid);
				pidstr[k] = '\0';
				if (!dirent_emit(out, count, &filled, &pos, s, ino++, pidstr,
						 LXP_S_IFDIR))
					full = 1;
			}
		} else if (dpid > 0 && !file && proc_pid_known(p, dpid)) {
			static const char *const pf[] = {"stat", "cmdline", "status", "comm", NULL};
			uint64_t ino = 300000;
			for (int i = 0; pf[i] && !full; i++)
				if (!dirent_emit(out, count, &filled, &pos, s, ino++, pf[i],
						 LXP_S_IFREG))
					full = 1;
		}
	}
	if (full && filled == 0)
		return -LXP_EINVAL; /* buffer too small for even one entry */
	return (long)filled;
}

/* Modern struct statx (256 bytes); fixed-width so host tests match the target. */
struct lxp_statx {
	uint32_t stx_mask;
	uint32_t stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink;
	uint32_t stx_uid;
	uint32_t stx_gid;
	uint16_t stx_mode;
	uint16_t __spare0;
	uint64_t stx_ino;
	uint64_t stx_size;
	uint64_t stx_blocks;
	uint64_t stx_attributes_mask;
	uint8_t __times[64];	 /* atime/btime/ctime/mtime (4 x 16B) — offsets 64..128 */
	uint32_t stx_rdev_major; /* offset 128 */
	uint32_t stx_rdev_minor; /* offset 132 */
	uint32_t stx_dev_major;
	uint32_t stx_dev_minor;
	uint8_t __rest[256 - 144];
};
LXP_STATIC_ASSERT(sizeof(struct lxp_statx) == 256, "statx ABI size drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statx, stx_mode) == 28, "statx stx_mode offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statx, stx_ino) == 32, "statx stx_ino offset drifted");
LXP_STATIC_ASSERT(offsetof(struct lxp_statx, stx_rdev_major) == 128, "statx stx_rdev offset drifted");

/*
 * statx: the stat() uClibc-ng actually issues. With AT_EMPTY_PATH (or an empty
 * path) it stats the open dirfd (fstat); otherwise it resolves a rootfs path.
 */
static long sys_statx(lxp_proc_t *p, int dirfd, const char *path, int flags, void *buf)
{
	if (!user_ok(p, buf, sizeof(struct lxp_statx), 1))
		return -LXP_EFAULT;

	uint32_t mode;
	uint64_t size;
	uint64_t rdev = 0;	  /* device id for a character node, else 0 */
	uint32_t ino = 0x300000u; /* unique, non-zero inode: ld.so dedups by (st_dev, st_ino) */
	/* Validate the path pointer before the path[0] empty-check deref below — resolve_path
	 * validates it too, but only after this reads path[0] (a bad pointer would fault here). */
	if (path && user_strnlen(p, path, LXP_PATH_MAX) < 0)
		return -LXP_EFAULT;
	if (path && path[0] && !(flags & LXP_AT_EMPTY_PATH)) {
		char abspath[LXP_PATH_MAX];
		long rr = resolve_path(p, path, abspath, sizeof(abspath));
		if (rr < 0)
			return rr;
		int wi;
		if (proc_is(abspath)) {
			mode = proc_mode(abspath, p);
			if (mode == 0)
				return -LXP_ENOENT;
			size = 0;
			ino = 0x200000u;
#if LXP_ENABLE_DEV
		} else if (lxp_dev_lookup(abspath) >= 0) { /* /dev character node */
			uint32_t dmode;
			uint64_t drdev;
			lxp_dev_stat_path(abspath, &dmode, &drdev);
			mode = dmode;
			size = 0;
			rdev = drdev;
			ino = 0x300000u;
#endif
#if LXP_ENABLE_NETFS
		} else if (lxp_netfs_lookup(abspath) >= 0) {
			return lxp_netfs_stat(p, abspath, (uintptr_t)buf, 1); /* parks */
#endif
		} else if ((wi = wfs_find(abspath)) >= 0) { /* writable overlay shadows rootfs */
			mode = wnode_at(wi)->mode;
			size = wnode_at(wi)->size;
			ino = 0x100000u + (uint32_t)wi;
		} else {
			int idx = fs_lookup(p, abspath);
			if (idx < 0)
				return -LXP_ENOENT;
			if (!(flags & LXP_AT_SYMLINK_NOFOLLOW)) { /* lstat passes NOFOLLOW */
				idx = fs_follow(p, idx);
				if (idx < 0)
					return -LXP_ENOENT;
			}
			mode = file_mode(&p->fs[idx]);
			size = p->fs[idx].size;
			ino = 1u + (uint32_t)idx;
		}
	} else {
		lxp_fd_t *s = fd_slot(p, dirfd);
		if (!s)
			return -LXP_EBADF;
		if (s->kind == LXP_FD_FILE) {
			mode = file_mode(&p->fs[s->file_idx]);
			size = p->fs[s->file_idx].size;
			ino = 1u + (uint32_t)s->file_idx;
		} else if (s->kind == LXP_FD_TMPFS) {
			mode = wnode_at(s->file_idx)->mode;
			size = wnode_at(s->file_idx)->size;
			ino = 0x100000u + (uint32_t)s->file_idx;
#if LXP_ENABLE_DEV
		} else if (s->kind == LXP_FD_DEV) {
			uint32_t dmode;
			uint64_t drdev, dsize;
			lxp_dev_fstat(s->file_idx, &dmode, &drdev, &dsize);
			mode = dmode;
			size = dsize;
			rdev = drdev;
			ino = 0x300000u + (uint32_t)s->file_idx;
#endif
#if LXP_ENABLE_NETFS
		} else if (s->kind == LXP_FD_NET) {
			uint32_t nmode;
			uint64_t nsize, nmtime, nino;
			if (lxp_netfs_fstat(s->file_idx, &nmode, &nsize, &nmtime, &nino) != 0)
				return -LXP_EBADF;
			return lxp_netfs_fill_stat(p, (uintptr_t)buf, 1, nmode, nsize, nmtime, nino);
#endif
		} else {
			mode = LXP_S_IFCHR | 0620u;
			size = 0;
			ino = 0x300000u + (uint32_t)s->file_idx;
		}
	}

	struct lxp_statx *st = buf;
	memset(st, 0, sizeof(*st));
	st->stx_mask = LXP_STATX_BASIC_STATS;
	st->stx_blksize = 512;
	st->stx_nlink = 1;
	st->stx_mode = (uint16_t)mode;
	st->stx_size = size;
	st->stx_blocks = (size + 511u) / 512u;
	st->stx_ino = ino; /* ld.so dedups loaded .so objects by (st_dev, st_ino) */
	st->stx_rdev_major = (uint32_t)(rdev >> 8);
	st->stx_rdev_minor = (uint32_t)(rdev & 0xffu);
	return 0;
}

#if LXP_ENABLE_NETFS
/* Marshal remote 9P attributes into a guest stat/statx buffer. Called by the netfs
 * retry (which owns the transport) for a path stat, and inline for an fstat on an
 * FD_NET fd. @p statkind: 0 = kstat64 (stat/lstat/fstat/fstatat), 1 = statx. The
 * netfs inode namespace is 0x600000+, with a distinct synthetic st_dev so ld.so's
 * (st_dev, st_ino) dedup never collides with the local rootfs. */
long lxp_netfs_fill_stat(lxp_proc_t *p, uintptr_t ustat, int statkind, uint32_t mode,
			     uint64_t size, uint64_t mtime, uint64_t ino)
{
	uint32_t nino = 0x600000u + (uint32_t)ino;
	if (statkind == 1) {
		if (!user_ok(p, (void *)ustat, sizeof(struct lxp_statx), 1))
			return -LXP_EFAULT;
		struct lxp_statx *st = (struct lxp_statx *)ustat;
		memset(st, 0, sizeof(*st));
		st->stx_mask = LXP_STATX_BASIC_STATS;
		st->stx_blksize = 512;
		st->stx_nlink = 1;
		st->stx_mode = (uint16_t)mode;
		st->stx_size = size;
		st->stx_blocks = (size + 511u) / 512u;
		st->stx_ino = nino;
		st->stx_dev_minor = 0xfeu;
		memcpy(st->__times + 48, &mtime, sizeof(uint64_t)); /* mtime tv_sec (4th 16B slot) */
		return 0;
	}
	if (!user_ok(p, (void *)ustat, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT;
	struct lxp_kstat64 *st = (struct lxp_kstat64 *)ustat;
	fill_kstat64(st, nino, mode, size);
	st->st_dev = 0xfeu;
	st->st_mtime = (uint32_t)mtime;
	return 0;
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
static long exec_copy_vec(lxp_proc_t *p, char *const uvec[], uint16_t *vec, char *buf,
			  size_t bufsz, int max, int *count, size_t *used)
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
		if (!user_ok(p, &uvec[j], sizeof(uvec[j]), 0))
			return -LXP_EFAULT;
		const char *us = ((char *const volatile *)uvec)[j]; /* load guest pointer once */
		if (!us)
			return 0;
		if (j == max || off == bufsz)
			return -LXP_E2BIG;
		uintptr_t a = (uintptr_t)us;
		uintptr_t hi = user_range_hi(p, a, 0);
		if (!hi)
			return -LXP_EFAULT;
		size_t room = bufsz - off;
		size_t readable = (size_t)(hi - a);
		size_t limit = readable < room ? readable : room;
		/* Copy each byte once and decide termination from the copied value. A
		 * co-running CLONE_VM thread may mutate the source: a separate strnlen +
		 * memcpy could observe a NUL during the scan and then copy a non-terminated
		 * string, making the later trusted-buffer strlen walk out of bounds. */
		size_t len = 0;
		for (; len < limit; len++) {
			unsigned char c = ((const volatile unsigned char *)us)[len];
			buf[off + len] = (char)c;
			if (c == 0)
				break;
		}
		if (len == limit)
			return readable < room ? -LXP_EFAULT : -LXP_E2BIG;
		vec[j] = (uint16_t)off;
		off += len + 1;
		*count = j + 1;
		if (used)
			*used = off;
	}
	return -LXP_E2BIG;
}

/* Rewrite an already-snapshotted script argv in place. Keeping the snapshot in the process
 * object avoids a second 256-byte argument buffer on the coordinator task's embedded stack. */
static long exec_rewrite_script_argv(lxp_proc_t *p, int old_argc, size_t old_bytes,
				     const char *interp, const char *iarg, int have_iarg,
				     const char *script, int *new_argc)
{
	const int prefix_count = have_iarg ? 3 : 2;
	const int tail_count = old_argc > 1 ? old_argc - 1 : 0;
	if (prefix_count + tail_count > LXP_EXEC_MAXARGS)
		return -LXP_E2BIG;

	size_t tail_off = old_bytes;
	if (tail_count)
		tail_off = p->exec_argv[1];
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
		if (prefix_bytes > sizeof(p->exec_argv_buf) ||
		    len > sizeof(p->exec_argv_buf) - prefix_bytes)
			return -LXP_E2BIG;
		prefix_bytes += len;
	}
	if (tail_bytes > sizeof(p->exec_argv_buf) - prefix_bytes)
		return -LXP_E2BIG;

	memmove(p->exec_argv_buf + prefix_bytes, p->exec_argv_buf + tail_off, tail_bytes);
	size_t off = 0;
	for (int j = 0; j < prefix_count; j++) {
		size_t len = strlen(prefix[j]) + 1;
		p->exec_argv[j] = (uint16_t)off;
		memcpy(p->exec_argv_buf + off, prefix[j], len);
		off += len;
	}
	for (int j = 0; j < tail_count; j++) {
		p->exec_argv[prefix_count + j] = (uint16_t)off;
		off += strlen(p->exec_argv_buf + off) + 1;
	}
	/* The rewrite shortens the vector when the script took no arguments; leave
	 * nothing from the pre-rewrite capture readable as a valid offset. */
	for (int j = prefix_count + tail_count; j < LXP_EXEC_MAXARGS; j++)
		p->exec_argv[j] = LXP_EXEC_OFF_NONE;
	*new_argc = prefix_count + tail_count;
	return 0;
}

static long sys_execve(lxp_proc_t *p, const char *path, char *const argv[], char *const envp[])
{
	if (!path)
		return -LXP_EFAULT;
	/* Snapshot both vectors before path resolution. This bounds work to the actual storage the
	 * relaunch can preserve instead of scanning and silently dropping hundreds of strings. */
	int raw_argc = 0, envc = 0;
	size_t raw_argbytes = 0;
	long vr = exec_copy_vec(p, argv, p->exec_argv, p->exec_argv_buf,
				sizeof(p->exec_argv_buf), LXP_EXEC_MAXARGS, &raw_argc,
				&raw_argbytes);
	if (vr < 0)
		return vr;
	vr = exec_copy_vec(p, envp, p->exec_env, p->exec_env_buf, sizeof(p->exec_env_buf),
			   LXP_EXEC_MAXENVS, &envc, NULL);
	if (vr < 0)
		return vr;
	p->exec_envc = envc;
	char execabs[LXP_PATH_MAX];
	long rr = resolve_path(p, path, execabs, sizeof(execabs));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_NETFS_EXEC
	/* exec a program off the remote mount (/mnt/pi/prog): capture argv, drop close-on-exec
	 * fds, then park the ELF fetch. The netfs retry sets exec_pending + a SENTINEL exec_file_idx
	 * on completion, and the run loop's EV_EXEC launches it from the RAM staging buffer. */
	if (lxp_netfs_lookup(execabs) >= 0) {
		for (int cfd = 0; cfd < LXP_MAX_FDS; cfd++)
			if (p->fds[cfd].kind != LXP_FD_FREE && p->fds[cfd].cloexec)
				sys_close(p, cfd);
		p->exec_argc = raw_argc;
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
	char interp[64], iarg[64];
	int have_iarg = 0, interp_idx = -1;
	if (f->data && f->size >= 2 && f->data[0] == '#' && f->data[1] == '!') {
		const char *s = (const char *)f->data + 2, *end = (const char *)f->data + f->size;
		while (s < end && (*s == ' ' || *s == '\t'))
			s++;
		int k = 0;
		while (s < end && *s != ' ' && *s != '\t' && *s != '\n' &&
		       k < (int)sizeof(interp) - 1)
			interp[k++] = *s++;
		interp[k] = '\0';
		while (s < end && (*s == ' ' || *s == '\t'))
			s++;
		int m = 0;
		while (s < end && *s != '\n' && *s != ' ' && *s != '\t' &&
		       m < (int)sizeof(iarg) - 1)
			iarg[m++] = *s++;
		iarg[m] = '\0';
		have_iarg = (m > 0);
		if (k == 0)
			return -LXP_ENOEXEC;
		char interpabs[LXP_PATH_MAX];
		/* _trusted, not resolve_path(): interp was copied out of the script's
		 * own bytes into this stack buffer, so it is not a guest pointer and
		 * resolve_path()'s user_strnlen guard rejects it -EFAULT. That made
		 * every #! script unrunnable — BusyBox init's /etc/init.d/rcS included. */
		if (resolve_path_trusted(interp, interpabs, sizeof(interpabs)) < 0)
			return -LXP_ENOENT;
		interp_idx = fs_follow(p, fs_lookup(p, interpabs));
		if (interp_idx < 0)
			return -LXP_ENOENT;
	}

	int argc = raw_argc;
	if (interp_idx >= 0) {
		long ar = exec_rewrite_script_argv(p, raw_argc, raw_argbytes, interp, iarg,
						   have_iarg, execabs, &argc);
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
	for (int cfd = 0; cfd < LXP_MAX_FDS; cfd++)
		if (p->fds[cfd].kind != LXP_FD_FREE && p->fds[cfd].cloexec)
			sys_close(p, cfd);
	p->exec_argc = argc;
	p->exec_file_idx = idx;
	p->exec_pending = 1;
	return 0;
}

/* There is no RTC: wall-clock time is a fixed base epoch (~2026-06-23) + uptime. */
#define LXP_BOOT_EPOCH 1782172800ull

static void now_sec_nsec(int clockid, uint64_t *sec, uint32_t *nsec)
{
	uint64_t ns = 0;
	lxp_time_ns(&ns);
	uint64_t up = ns / 1000000000ull;
	*nsec = (uint32_t)(ns % 1000000000ull);
	/* CLOCK_MONOTONIC(1)/_RAW(4)/BOOTTIME(7) → uptime; REALTIME(0) → wall clock. */
	*sec = (clockid == 0) ? (LXP_BOOT_EPOCH + up) : up;
}

/* ── Large syscall handlers, extracted from the lxp_syscall() switch so the
 *    dispatcher stays a lean router; each is individually unit-testable. The
 *    args keep the raw (nr, a0..a5) names the dispatcher passes, so the bodies
 *    are byte-for-byte the former switch-arm bodies. ── */
static long sys_fcntl(lxp_proc_t *proc, long a0, long a1, long a2)
{
		lxp_fd_t *s = fd_slot(proc, (int)a0);
		if (!s)
			return -LXP_EBADF;
		if ((int)a1 == LXP_F_DUPFD || (int)a1 == LXP_F_DUPFD_CLOEXEC) {
			/* Duplicate to the lowest free fd >= arg. The shell asks for a high
			 * fd (>=255) for its interactive fd; our table is small, so a too-high
			 * arg falls back to any free fd (the shell tolerates a low one and
			 * relocates it if needed). */
			int from = (int)a2;
			if (from < 0 || from >= LXP_MAX_FDS)
				from = 0;
			for (int nfd = from; nfd < LXP_MAX_FDS; nfd++) {
				if (proc->fds[nfd].kind == LXP_FD_FREE) {
					proc->fds[nfd] = *s;
					proc->fds[nfd].cloexec =
						((int)a1 == LXP_F_DUPFD_CLOEXEC) ? 1 : 0;
					fd_dup_backing(s); /* share the backing (now incl. netfs) */
					return nfd;
				}
			}
			return -LXP_EMFILE;
		}
#if LXP_ENABLE_DEV
		/* A device fd honours F_SETFL/F_GETFL so O_NONBLOCK takes effect (LVGL's
		 * evdev opens blocking, then fcntl(F_SETFL, O_NONBLOCK)). */
		if (s->kind == LXP_FD_DEV) {
			if ((int)a1 == LXP_F_SETFL) {
				lxp_dev_setfl(s->file_idx, (int)a2);
				return 0;
			}
			if ((int)a1 == LXP_F_GETFL)
				return lxp_dev_getfl(s->file_idx);
		}
#endif
#if LXP_ENABLE_NET
		/* A socket fd honours F_SETFL/F_GETFL so O_NONBLOCK gates parking. */
		if (s->kind == LXP_FD_SOCKET) {
			if ((int)a1 == LXP_F_SETFL) {
				lxp_sock_setfl(s->file_idx, (int)a2);
				return 0;
			}
			if ((int)a1 == LXP_F_GETFL)
				return lxp_sock_getfl(s->file_idx);
		}
#endif
#if LXP_ENABLE_PTY
		/* A pty fd honours F_SETFL/F_GETFL so O_NONBLOCK gates parking (dropbear sets
		 * the master non-blocking and drives it with select). */
		if (s->kind == LXP_FD_PTY) {
			if ((int)a1 == LXP_F_SETFL) {
				lxp_pty_setfl(s->file_idx, s->rw, (int)a2);
				return 0;
			}
			if ((int)a1 == LXP_F_GETFL)
				return lxp_pty_getfl(s->file_idx, s->rw);
		}
#endif
		/* A pipe fd honours F_SETFL/F_GETFL so O_NONBLOCK gates parking (dropbear sets its
		 * SIGCHLD self-pipe non-blocking and drains it with a read-until-EAGAIN loop). */
		if (s->kind == LXP_FD_PIPE) {
			if ((int)a1 == LXP_F_SETFL) {
				s->nonblock = ((int)a2 & LXP_O_NONBLOCK) ? 1 : 0;
				return 0;
			}
			if ((int)a1 == LXP_F_GETFL)
				return (s->rw ? LXP_O_WRONLY : LXP_O_RDONLY) |
				       (s->nonblock ? LXP_O_NONBLOCK : 0);
		}
		/* F_SETFD/F_GETFD track close-on-exec (dropbear sets FD_CLOEXEC on its exec-status
		 * pipe and detects a successful shell exec by that fd closing on execve). */
		if ((int)a1 == LXP_F_SETFD) {
			s->cloexec = ((int)a2 & LXP_FD_CLOEXEC) ? 1 : 0;
			return 0;
		}
		if ((int)a1 == LXP_F_GETFD)
			return s->cloexec ? LXP_FD_CLOEXEC : 0;
		/* F_GETFL must report a truthful access mode. uClibc's fdopen() validates
		 * the FILE* mode against it, so answering O_RDONLY (0) for a writable fd
		 * fails fdopen(fd, "w") with EINVAL — which is how dropbearkey's .pub
		 * write died while the key itself generated fine. The open flags are not
		 * stored per fd, so report what the kind can actually do; that is enough
		 * for fdopen, which only checks the access mode. */
		if ((int)a1 == LXP_F_GETFL) {
			int acc;
			switch (s->kind) {
			case LXP_FD_TMPFS:   /* the writable overlay */
			case LXP_FD_CONSOLE: /* stdin/stdout/stderr */
				acc = LXP_O_RDWR;
				break;
			default: /* read-only rootfs file, and anything not handled above */
				acc = LXP_O_RDONLY;
				break;
			}
			return acc | (s->nonblock ? LXP_O_NONBLOCK : 0);
		}
		/* F_SETFL on a stdio/other fd: benign. */
		return 0;
}

static long sys_poll(lxp_proc_t *proc, long nr, long a0, long a1, long a2)
{
		lxp_pollfd *pfds = (lxp_pollfd *)(uintptr_t)a0;
		unsigned nfds = (unsigned)a1;
		if (nfds > LXP_MAX_FDS) /* bound before nfds*sizeof(pollfd) wraps a 32-bit size_t */
			return -LXP_EINVAL;
		if (nfds && !user_ok(proc, pfds, (size_t)nfds * sizeof(lxp_pollfd), 1))
			return -LXP_EFAULT;
		/* Timeout: poll(2) passes ms in a2 (<0 = block); ppoll passes a struct
		 * timespec* (NULL = block). A SHORT finite timeout means the caller is
		 * probing for input that might *immediately* follow — e.g. vi/hush's
		 * read_key polling ~50 ms after ESC to tell a lone ESC from an escape
		 * sequence. We keep no read-ahead, so honestly report "no data yet" for
		 * such probes: a lone ESC then stays ESC (Esc then :q works in vi). vi
		 * also uses poll(timeout 0) as "is input pending? if not, repaint the
		 * screen" — reporting ready there made it never repaint while inserting
		 * (edits stayed invisible). A blocking/long poll reports ready and the
		 * caller blocks in read() for the real byte (the console read blocks
		 * until a key arrives). */
		long tmo_ms;
		if (nr == LXP_NR_poll) {
			tmo_ms = (long)(int32_t)a2;
		} else {
			const int64_t *ts = (const int64_t *)(uintptr_t)a2; /* {sec, nsec} */
			if (ts && !user_ok(proc, ts, 2 * sizeof(int64_t), 0))
				return -LXP_EFAULT;
			tmo_ms = ts ? (long)(ts[0] * 1000 + ts[1] / 1000000) : -1;
		}
		/* With a console_poll callback (UART console) we report the console fd's REAL
		 * readiness, enabling interactive top's `q` quit; without one a short finite
		 * timeout is a read_key probe (vi/hush ESC + "input pending?") reported
		 * not-ready (no read-ahead), and a longer/blocking poll reports ready so the
		 * caller blocks in read() for the byte. */
		int probe = (tmo_ms >= 0 && tmo_ms <= 100);
		int key = (proc->console_poll && proc->console_poll(proc->io_ctx) > 0);
		int ready = 0;
#if LXP_ENABLE_NET
		int has_socket = 0, has_eventfd = 0, has_pty = 0;
#endif
		for (unsigned i = 0; i < nfds; i++) {
			pfds[i].revents = 0;
			lxp_fd_t *s = fd_slot(proc, pfds[i].fd);
			if (!s)
				continue;
			int avail;
			if (s->kind == LXP_FD_CONSOLE)
				avail = (tmo_ms < 0) ? 1 : (proc->console_poll ? key : !probe);
#if LXP_ENABLE_DEV
			else if (s->kind == LXP_FD_DEV) {
				/* Report the driver's real readiness bits (fb POLLOUT, evdev
				 * POLLIN when the event ring is non-empty). */
				unsigned pb = lxp_dev_poll(s->file_idx);
				pfds[i].revents = (short)(pfds[i].events & pb &
							  (LXP_POLLIN | LXP_POLLOUT));
				if (pfds[i].revents)
					ready++;
				continue;
			}
#endif
#if LXP_ENABLE_NET
			else if (s->kind == LXP_FD_SOCKET) {
				unsigned pb = lxp_sock_poll(s->file_idx);
				pfds[i].revents = (short)(pfds[i].events & pb &
							  (LXP_POLLIN | LXP_POLLOUT));
				if (pfds[i].revents)
					ready++;
				has_socket = 1;
				continue;
			} else if (s->kind == LXP_FD_EVENTFD) {
				/* Readable once the counter is non-zero (the resolver thread
				 * wrote it); always writable. Park like a socket poll so the
				 * coordinator re-checks on its tick. */
				unsigned pb = LXP_POLLOUT |
					      ((s->file_idx >= 0 && s->file_idx < LXP_NEVENTFD &&
						g_efd[s->file_idx].ctr)
						       ? LXP_POLLIN
						       : 0u);
				pfds[i].revents = (short)(pfds[i].events & pb &
							  (LXP_POLLIN | LXP_POLLOUT));
				if (pfds[i].revents)
					ready++;
				has_eventfd = 1;
				continue;
			}
#if LXP_ENABLE_PTY
			else if (s->kind == LXP_FD_PTY) {
				unsigned pb = lxp_pty_poll(s->file_idx, s->rw);
				pfds[i].revents = (short)(pfds[i].events & pb &
							  (LXP_POLLIN | LXP_POLLOUT));
				if (pfds[i].revents)
					ready++;
				has_pty = 1; /* park via SOCKW_POLL; the re-scan re-checks the pty */
				continue;
			}
#endif
#endif
			else if (s->kind == LXP_FD_PIPE) {
				/* Real pipe readiness — NOT "always ready", or a select on an empty
				 * self-pipe wrongly reports readable (dropbear then blocks forever). */
				unsigned pb = pipe_poll(s->file_idx, s->rw);
				pfds[i].revents = (short)(pfds[i].events & pb &
							  (LXP_POLLIN | LXP_POLLOUT));
				if (pfds[i].revents)
					ready++;
				continue;
			} else
				avail = 1; /* regular files: always readable/writable */
			if (avail) {
				pfds[i].revents = pfds[i].events &
						  (LXP_POLLIN | LXP_POLLOUT);
				if (pfds[i].revents)
					ready++;
			}
		}
		if (ready > 0 || tmo_ms == 0)
			return ready;
#if LXP_ENABLE_NET
		/* A blocking poll whose set includes a socket parks on SOCKW_POLL: the
		 * coordinator re-scans readiness on its <=5 ms socket-retry tick (via
		 * lxp_poll_retry) and resumes us when an fd becomes ready or the timeout
		 * elapses. Without this a socket poll would sleep the whole timeout and return
		 * 0, breaking the uClibc DNS resolver (poll(POLLIN) then recv(MSG_DONTWAIT)). */
		if (has_socket || has_eventfd || has_pty) {
			proc->sel_active = 0; /* this is a real poll(2), not a pselect6 */
			proc->sock_buf = (uintptr_t)pfds;
			proc->sock_len = nfds;
			if (tmo_ms > 0) {
				uint64_t now_us = 0;
				lxp_time_us(&now_us);
				proc->sock_deadline_us = now_us + (uint64_t)tmo_ms * 1000ull;
			} else {
				proc->sock_deadline_us = UINT64_MAX; /* poll(-1): block forever */
			}
			proc->sock_oi = -1; /* the retry re-scans the whole set, not one open */
			proc->sock_wait = LXP_SOCKW_POLL;
			return 0; /* parked; coordinator resumes with the ready count / 0 */
		}
#endif
		/* Nothing ready + a real timeout: with the UART console, park for the timeout
		 * (paces interactive top's refresh, returns 0); a buffered keystroke is caught
		 * at the next poll. Without console_poll a long timeout already reported ready
		 * above, so we only reach here on a no-callback probe → return 0. */
		if (proc->console_poll && tmo_ms > 0) {
			/* TICK (cross-idle), not DWT: tickless idle freezes the DWT while the proc is
			 * parked here, and the coordinator checks this against ove_time_get_us (see the
			 * nanosleep handler). Both must use the same clock or top's refresh + q drift. */
			uint64_t now_us = 0;
			lxp_time_us(&now_us);
			proc->sleep_until_us = now_us + (uint64_t)tmo_ms * 1000ull;
			proc->sleep_pending = 1;
		}
		return 0;
}

static long sys_ioctl(lxp_proc_t *proc, long a0, long a1, long a2)
{
	lxp_fd_t *s = fd_slot(proc, (int)a0);
	if (!s)
		return -LXP_ENOTTY;
	if (s->ops && s->ops->ioctl)
		return s->ops->ioctl(proc, s, (unsigned long)a1, (unsigned long)a2);
	return -LXP_ENOTTY; /* not a tty / char device / socket */
}

long lxp_syscall(lxp_proc_t *proc, long nr, long a0, long a1, long a2, long a3, long a4,
		     long a5)
{
	if (!proc)
		return -LXP_EINVAL;

	/* A guest controls these byte counts. Normalise them before any pointer-range
	 * validation or host callback: each interface permits a short result, and the
	 * finite quantum keeps one deferred request preemptible and bounded. Cast via
	 * uint32_t because this is the 32-bit ARM syscall ABI even in host tests. */
	switch (nr) {
	case LXP_NR_read:
	case LXP_NR_write:
	case LXP_NR_getdents:
	case LXP_NR_getdents64:
	case LXP_NR_send:
	case LXP_NR_sendto:
	case LXP_NR_recv:
	case LXP_NR_recvfrom:
		if ((uint32_t)a2 > LXP_SYSCALL_QUANTUM_BYTES)
			a2 = LXP_SYSCALL_QUANTUM_BYTES;
		break;
	case LXP_NR_pread64:
	case LXP_NR_pwrite64:
		if ((uint32_t)a2 > LXP_SYSCALL_FILE_QUANTUM_BYTES)
			a2 = LXP_SYSCALL_FILE_QUANTUM_BYTES;
		break;
	case LXP_NR_getrandom:
		if ((uint32_t)a1 > LXP_SYSCALL_QUANTUM_BYTES)
			a1 = LXP_SYSCALL_QUANTUM_BYTES;
		break;
	default:
		break;
	}

	switch (nr) {
	case LXP_NR_read:
		return sys_read(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2);
	case LXP_NR_write:
		return sys_write(proc, (int)a0, (const void *)(uintptr_t)a1, (size_t)a2);
	case LXP_NR_writev:
		return sys_writev(proc, (int)a0, (const lxp_iovec *)(uintptr_t)a1, (int)a2);
	case LXP_NR_brk:
		return sys_brk(proc, (uintptr_t)a0);
	case LXP_NR_mmap2:
		return sys_mmap2(proc, (uintptr_t)a0, (size_t)a1, (int)a2, (int)a3, (int)a4,
				 (uint32_t)a5);
	case LXP_NR_munmap:
		return sys_munmap(proc, (uintptr_t)a0, (size_t)a1);
	case LXP_NR_mprotect: /* NOMMU: RELRO/protection is a no-op */
		return sys_mprotect((uintptr_t)a0, (size_t)a1, (int)a2);
	case LXP_NR_pread64: /* (fd, buf, count, [pad a3], off_lo a4, off_hi a5) */
		return sys_pread(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2, (uint32_t)a4);
	case LXP_NR_pwrite64: /* (fd, buf, count, [pad a3], off_lo a4, off_hi a5) */
		return sys_pwrite(proc, (int)a0, (const void *)(uintptr_t)a1, (size_t)a2,
				  (uint32_t)a4);
	case LXP_NR_open: { /* legacy open(path, flags, mode): dirfd = cwd */
		long f = sys_openat(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a0, (int)a1);
		if (f >= 0 && ((int)a1 & LXP_O_CLOEXEC))
			proc->fds[f].cloexec = 1;
		return f;
	}
	case LXP_NR_execve: /* (path, argv, envp) */
		return sys_execve(proc, (const char *)(uintptr_t)a0, (char *const *)(uintptr_t)a1,
				  (char *const *)(uintptr_t)a2);
	case LXP_NR_openat: {
		long f = sys_openat(proc, (int)a0, (const char *)(uintptr_t)a1, (int)a2);
		if (f >= 0 && ((int)a2 & LXP_O_CLOEXEC))
			proc->fds[f].cloexec = 1;
		return f;
	}
	case LXP_NR_close:
		return sys_close(proc, (int)a0);
	case LXP_NR_pipe:
		return sys_pipe(proc, (int *)(uintptr_t)a0, 0);
	case LXP_NR_pipe2: /* (fds, flags) — flags carries O_CLOEXEC and/or O_NONBLOCK */
		return sys_pipe(proc, (int *)(uintptr_t)a0, (int)a1);
	case LXP_NR_dup:
		return sys_dup(proc, (int)a0);
	case LXP_NR_dup2:
		return sys_dup2(proc, (int)a0, (int)a1);
	case LXP_NR_dup3: { /* (old, new, flags) — flags carries O_CLOEXEC on the new fd */
		if ((int)a0 == (int)a1) /* dup3 (unlike dup2) rejects oldfd == newfd */
			return -LXP_EINVAL;
		long nf = sys_dup2(proc, (int)a0, (int)a1);
		if (nf >= 0 && ((int)a2 & LXP_O_CLOEXEC))
			proc->fds[nf].cloexec = 1;
		return nf;
	}
	case LXP_NR_lseek:
		return sys_lseek(proc, (int)a0, a1, (int)a2);
	case LXP_NR__llseek:
		return sys_llseek(proc, (int)a0, (unsigned long)a1, (unsigned long)a2,
				  (uint64_t *)(uintptr_t)a3, (unsigned int)a4);
	case LXP_NR_ftruncate64:
		/* 64-bit length is register-pair aligned on ARM: fd=a0, len=(a2,a3). */
		return sys_ftruncate(proc, (int)a0,
				     (uint64_t)(uint32_t)a2 | ((uint64_t)(uint32_t)a3 << 32));
	case LXP_NR_fstat64:
		return sys_fstat64(proc, (int)a0, (void *)(uintptr_t)a1);
	case LXP_NR_stat64: /* (path, statbuf) — follows symlinks */
		return sys_stat_path(proc, (const char *)(uintptr_t)a0, 1, (void *)(uintptr_t)a1);
	case LXP_NR_lstat64: /* (path, statbuf) — does NOT follow */
		return sys_stat_path(proc, (const char *)(uintptr_t)a0, 0, (void *)(uintptr_t)a1);
	case LXP_NR_fstatat64: /* (dirfd, path, statbuf, flags) */
		return sys_stat_path(proc, (const char *)(uintptr_t)a1,
				     !((int)a3 & LXP_AT_SYMLINK_NOFOLLOW),
				     (void *)(uintptr_t)a2);
	case LXP_NR_readlink: /* (path, buf, bufsiz) */
		return sys_readlink(proc, (const char *)(uintptr_t)a0, (char *)(uintptr_t)a1,
				    (size_t)a2);
	case LXP_NR_readlinkat: /* (dirfd, path, buf, bufsiz) */
		return sys_readlink(proc, (const char *)(uintptr_t)a1, (char *)(uintptr_t)a2,
				    (size_t)a3);
	case LXP_NR_access: /* (path, mode) — mode ignored */
		return sys_access(proc, (const char *)(uintptr_t)a0);
	case LXP_NR_faccessat:  /* (dirfd, path, mode) */
	case LXP_NR_faccessat2: /* (dirfd, path, mode, flags) */
		return sys_access(proc, (const char *)(uintptr_t)a1);
	case LXP_NR_mkdir: /* (path, mode) */
		return sys_mkdir(proc, (const char *)(uintptr_t)a0, (uint32_t)a1);
	case LXP_NR_mkdirat: /* (dirfd, path, mode) */
		return sys_mkdir(proc, (const char *)(uintptr_t)a1, (uint32_t)a2);
	case LXP_NR_rmdir: /* (path) */
		return sys_unlink(proc, (const char *)(uintptr_t)a0, 1);
	case LXP_NR_unlink: /* (path) */
		return sys_unlink(proc, (const char *)(uintptr_t)a0, 0);
	case LXP_NR_unlinkat: /* (dirfd, path, flags) */
		return sys_unlink(proc, (const char *)(uintptr_t)a1,
				  ((int)a2 & LXP_AT_REMOVEDIR) ? 1 : 0);
	case LXP_NR_rename: /* (oldpath, newpath) */
		return sys_rename(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a1);
	case LXP_NR_renameat:  /* (olddirfd, old, newdirfd, new) */
	case LXP_NR_renameat2: /* (olddirfd, old, newdirfd, new, flags) */
		return sys_rename(proc, (const char *)(uintptr_t)a1, (const char *)(uintptr_t)a3);
	case LXP_NR_symlink: /* (target, linkpath) */
		return sys_symlink(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a1);
	case LXP_NR_symlinkat: /* (target, newdirfd, linkpath) */
		return sys_symlink(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a2);
	case LXP_NR_link: /* (oldpath, newpath) */
		return sys_link(proc, (const char *)(uintptr_t)a0, (const char *)(uintptr_t)a1);
	case LXP_NR_linkat: /* (olddirfd, oldpath, newdirfd, newpath, flags) */
		return sys_link(proc, (const char *)(uintptr_t)a1, (const char *)(uintptr_t)a3);
	case LXP_NR_chmod: /* (path, mode) */
		return sys_chmod(proc, (const char *)(uintptr_t)a0, (uint32_t)a1);
	case LXP_NR_fchmodat: /* (dirfd, path, mode) */
		return sys_chmod(proc, (const char *)(uintptr_t)a1, (uint32_t)a2);
	case LXP_NR_utimensat:	  /* (dirfd, path, times, flags) — times not tracked */
	case LXP_NR_utimensat_time64: /* time64 variant uClibc-ng issues for touch */
		return sys_utimensat(proc, (const char *)(uintptr_t)a1);
	case LXP_NR_mount:	 /* synthetic /proc + overlay are always present */
	case LXP_NR_umount2: /* (rcS does `mount -t proc proc /proc`) */
		return 0;
	case LXP_NR_statfs64:  /* (path, sz, buf) */
	case LXP_NR_fstatfs64: /* (fd, sz, buf) */
		return sys_statfs(proc, (void *)(uintptr_t)a2);
	case LXP_NR_getrandom: /* (buf, count, flags) */
		return sys_getrandom(proc, (void *)(uintptr_t)a0, (size_t)a1, (unsigned)a2);
	case LXP_NR_eventfd2: { /* (initval, flags) — curl's threaded-resolver wakeup */
		long ei = efd_new((unsigned)a0, (int)a1);
		if (ei < 0)
			return ei;
		int fd = fd_alloc(proc, LXP_FD_EVENTFD, (int)ei, 0);
		if (fd < 0) {
			g_efd[ei].used = 0;
			return -LXP_EMFILE;
		}
		return fd;
	}
	case LXP_NR_sysinfo: { /* uptime + ram totals (uptime/free read this) */
		struct lxp_sysinfo {
			int32_t uptime;
			uint32_t loads[3];
			uint32_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
			uint16_t procs, pad;
			uint32_t totalhigh, freehigh, mem_unit;
			char _f[8];
		} *si = (void *)(uintptr_t)a0;
		LXP_STATIC_ASSERT(sizeof(struct lxp_sysinfo) == 64, "sysinfo ABI size drifted");
		if (!user_ok(proc, si, sizeof(*si), 1))
			return -LXP_EFAULT;
		memset(si, 0, sizeof(*si));
		uint64_t ns = 0;
		lxp_time_ns(&ns);
		si->uptime = (int32_t)(ns / 1000000000ull);
		si->totalram = 4u * 1024u * 1024u;
		si->freeram = 2u * 1024u * 1024u;
		si->procs = 2;
		si->mem_unit = 1;
		return 0;
	}
	case LXP_NR_fcntl: /* old 32-bit fcntl: same dispatch as fcntl64 here */
	case LXP_NR_fcntl64:
		return sys_fcntl(proc, a0, a1, a2);
	case LXP_NR_getdents: /* 32-bit linux_dirent (uClibc readdir on this target) */
		return sys_getdents64(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2, 0);
	case LXP_NR_getdents64:
		return sys_getdents64(proc, (int)a0, (void *)(uintptr_t)a1, (size_t)a2, 1);
	case LXP_NR_statx: /* (dirfd, path, flags, mask, buf); mask ignored */
		return sys_statx(proc, (int)a0, (const char *)(uintptr_t)a1, (int)a2,
				 (void *)(uintptr_t)a4);
	case LXP_NR_exit:
	case LXP_NR_exit_group:
		return sys_exit(proc, (int)a0);
	/* libc-init / identity stubs: enough for a static uClibc program to start. */
	case LXP_NR_getpid:
		return proc->pid;
	case LXP_NR_getppid:
		return proc->ppid;
	case LXP_NR_getcwd: {
		/* getcwd(buf, size): write the cwd; the raw syscall returns the length
		 * including the NUL terminator. */
		char *buf = (char *)(uintptr_t)a0;
		if (!buf)
			return -LXP_EFAULT;
		size_t len = strlen(proc->cwd) + 1;
		if ((size_t)a1 < len)
			return -LXP_ERANGE;
		if (!user_ok(proc, buf, len, 1))
			return -LXP_EFAULT;
		memcpy(buf, proc->cwd, len);
		return (long)len;
	}
	case LXP_NR_chdir: {
		const char *path = (const char *)(uintptr_t)a0;
		if (!path)
			return -LXP_EFAULT;
		char abspath[LXP_PATH_MAX];
		long r = resolve_path(proc, path, abspath, sizeof(abspath));
		if (r < 0)
			return r;
		/* "/" is always valid; else require an existing directory in either the
		 * writable overlay or the read-only rootfs. */
		if (!(abspath[0] == '/' && abspath[1] == '\0')) {
			int wi = wfs_find(abspath);
			if (wi >= 0) {
				if ((wnode_at(wi)->mode & LXP_S_IFMT) != LXP_S_IFDIR)
					return -LXP_ENOTDIR;
			} else {
				int idx = fs_lookup(proc, abspath);
				if (idx < 0)
					return -LXP_ENOENT;
				if ((file_mode(&proc->fs[idx]) & LXP_S_IFMT) != LXP_S_IFDIR)
					return -LXP_ENOTDIR;
			}
		}
		strcpy(proc->cwd, abspath);
		return 0;
	}
	case LXP_NR_umask: { /* set the file-creation mask, return the previous (per-proc, inherited) */
		int old = proc->umask;
		proc->umask = (unsigned short)(a0 & 0777);
		return old;
	}
	case LXP_NR_setpgid: { /* (pid, pgid) — job control: put a process into a group */
		int tpid = (int)a0, tpgid = (int)a1;
		/* Only a self-target is tracked here (pid 0, or my own pid); pgid 0 means "use my
		 * pid" (become group leader). A child sets its OWN group via setpgid(0, …) after
		 * fork, so a cross-proc setpgid is accepted inert (no proc table at this layer). */
		if (tpid == 0 || tpid == proc->pid)
			proc->pgid = (tpgid == 0) ? proc->pid : tpgid;
		return 0;
	}
	case LXP_NR_prctl:
	case LXP_NR_sched_yield: /* cooperative hint; FreeRTOS time-slices peers anyway */
	case LXP_NR_sync:	  /* no backing store to flush */
	case LXP_NR_fsync:	  /* dropbearkey fsyncs the host key; the writable overlay is RAM */
	case LXP_NR_fdatasync:
	case LXP_NR_fchmod: /* modes/ownership not tracked (login chmods the tty) */
	case LXP_NR_fchown32:
	case LXP_NR_chown32: /* dropbear chowns the pty over SSH; ownership not enforced (inert) */
	case LXP_NR_setgroups32: /* uid/gid not enforced (login's privilege drop is */
	case LXP_NR_setuid32:    /* inert — programs run privileged in this tier) */
	case LXP_NR_setgid32:
	case LXP_NR_setreuid32: /* dropbear's post-auth privilege drop: accept (inert) so it */
	case LXP_NR_setregid32: /* does not abort — a failed drop is fatal to an SSH server */
	case LXP_NR_setresuid32:
	case LXP_NR_setresgid32:
		return 0; /* process-control / fs-mode setup accepted (inert) */
	case LXP_NR_getresuid32: /* (ruid*, euid*, suid*) — all root (0) on this tier */
	case LXP_NR_getresgid32: {
		uint32_t *r = (uint32_t *)(uintptr_t)a0, *e = (uint32_t *)(uintptr_t)a1,
			 *s = (uint32_t *)(uintptr_t)a2;
		if ((r && !user_ok(proc, r, sizeof(*r), 1)) ||
		    (e && !user_ok(proc, e, sizeof(*e), 1)) ||
		    (s && !user_ok(proc, s, sizeof(*s), 1)))
			return -LXP_EFAULT;
		if (r)
			*r = 0;
		if (e)
			*e = 0;
		if (s)
			*s = 0;
		return 0;
	}
	case LXP_NR_prlimit64: { /* (pid, resource, new_limit, old_limit) — report a sane
				     * finite limit; a "new" limit is accepted (inert). getty/login
				     * and dropbear query RLIMIT_NOFILE etc. */
		void *uold = (void *)(uintptr_t)a3;
		if (uold) {
			if (!user_ok(proc, uold, 2 * sizeof(uint64_t), 1))
				return -LXP_EFAULT;
			/* Report the TRUTH for RLIMIT_NOFILE: the fd table is LXP_MAX_FDS, so
			 * advertising more just hands a guest a lie that turns into a surprise
			 * EMFILE at the (LXP_MAX_FDS)th open. Other resources keep a finite,
			 * never-RLIM_INFINITY default (a close-all-fds loop would else spin to 2^64). */
			uint64_t v = ((int)a1 == 7 /* RLIMIT_NOFILE */) ? LXP_MAX_FDS : 1024;
			uint64_t *lim = (uint64_t *)uold; /* rlim_cur, rlim_max */
			lim[0] = lim[1] = v;
		}
		return 0;
	}
	case LXP_NR_times: { /* (struct tms*) — CPU-time accounting; dropbear mixes it into
				 * its RNG pool. Report uptime ticks (100 Hz) + zero the per-proc
				 * breakdown (not tracked here). Must be >=0 (glibc treats -1 as error). */
		void *ubuf = (void *)(uintptr_t)a0;
		uint64_t us = 0;
		lxp_time_us(&us);
		long ticks = (long)(us / 10000u); /* CLK_TCK = 100 */
		if (ubuf) {
			if (!user_ok(proc, ubuf, 4 * sizeof(long), 1))
				return -LXP_EFAULT;
			long *tms = (long *)ubuf; /* tms_utime, tms_stime, tms_cutime, tms_cstime */
			tms[0] = ticks;
			tms[1] = tms[2] = tms[3] = 0;
		}
		return ticks;
	}
	case LXP_NR_setitimer: { /* (which, new, old) — ITIMER_REAL -> SIGALRM (alarm()) */
		int which = (int)a0;
		const void *unew = (const void *)(uintptr_t)a1;
		void *uold = (void *)(uintptr_t)a2;
		if (which != LXP_ITIMER_REAL)
			return 0; /* only the real-time timer (login timeout, ping interval) */
		/* struct itimerval { timeval it_interval; timeval it_value; }; ARM32 long=4,
		 * so it is 4 x u32: [interval_sec, interval_usec, value_sec, value_usec]. */
		uint64_t now = 0;
		lxp_time_us(&now);
		if (uold) {
			if (!user_ok(proc, uold, 16, 1))
				return -LXP_EFAULT;
			uint32_t ov[4] = {0, 0, 0, 0};
			uint64_t rem = (proc->alarm_deadline_us && proc->alarm_deadline_us > now)
					       ? proc->alarm_deadline_us - now
					       : 0;
			ov[0] = (uint32_t)(proc->alarm_interval_us / 1000000u);
			ov[1] = (uint32_t)(proc->alarm_interval_us % 1000000u);
			ov[2] = (uint32_t)(rem / 1000000u);
			ov[3] = (uint32_t)(rem % 1000000u);
			memcpy(uold, ov, 16);
		}
		if (!unew)
			return 0;
		if (!user_ok(proc, unew, 16, 0))
			return -LXP_EFAULT;
		uint32_t nv[4];
		memcpy(nv, unew, 16);
		proc->alarm_interval_us = (uint64_t)nv[0] * 1000000u + nv[1];
		uint64_t val_us = (uint64_t)nv[2] * 1000000u + nv[3];
		proc->alarm_deadline_us = val_us ? now + val_us : 0; /* it_value 0 disarms */
		return 0;
	}
	case LXP_NR_getpgrp: /* shell job control: the caller's process group */
		return proc->pgid;
	case LXP_NR_setsid: /* getty/login start a new session: the caller leads its own group */
		proc->pgid = proc->pid;
		return proc->pid;
	case LXP_NR_reboot: {  /* reboot(magic1, magic2, cmd, arg) — cmd is a2 */
		unsigned cmd = (unsigned)a2;
		/* Only an actual halt/poweroff/restart stops the system; init calls
		 * reboot(CAD_OFF=0) at startup to disable Ctrl-Alt-Del — a no-op here. */
		if (cmd == 0x01234567u /* RESTART */ || cmd == 0xcdef0123u /* HALT */ ||
		    cmd == 0x4321fedcu /* POWER_OFF */ || cmd == 0xa1b2c3d4u /* RESTART2 */) {
			g_lxp_halt = 1;
			proc->exited = 1;
			proc->exit_status = 0;
			proc->exit_reason = LXP_EXIT_REASON_NORMAL;
		}
		return 0;
	}
	case LXP_NR_gettid:
		return proc->pid;	 /* single-threaded: tid == pid */
	case LXP_NR_clock_gettime: { /* (clockid, struct timespec*) — 32-bit time_t */
		int32_t *ts = (int32_t *)(uintptr_t)a1;
		if (!user_ok(proc, ts, 2 * sizeof(int32_t), 1))
			return -LXP_EFAULT;
		uint64_t sec;
		uint32_t nsec;
		now_sec_nsec((int)a0, &sec, &nsec);
		ts[0] = (int32_t)sec;
		ts[1] = (int32_t)nsec;
		return 0;
	}
	case LXP_NR_clock_gettime64: { /* (clockid, struct __kernel_timespec*) — 64-bit */
		int64_t *ts = (int64_t *)(uintptr_t)a1;
		if (!user_ok(proc, ts, 2 * sizeof(int64_t), 1))
			return -LXP_EFAULT;
		uint64_t sec;
		uint32_t nsec;
		now_sec_nsec((int)a0, &sec, &nsec);
		ts[0] = (int64_t)sec;
		ts[1] = (int64_t)nsec;
		return 0;
	}
	case LXP_NR_gettimeofday: { /* (struct timeval*, tz) */
		int32_t *tv = (int32_t *)(uintptr_t)a0;
		if (!user_ok(proc, tv, 2 * sizeof(int32_t), 1))
			return -LXP_EFAULT;
		uint64_t sec;
		uint32_t nsec;
		now_sec_nsec(0, &sec, &nsec);
		tv[0] = (int32_t)sec;
		tv[1] = (int32_t)(nsec / 1000u);
		return 0;
	}
	case LXP_NR_nanosleep:	 /* (req, rem) */
	case LXP_NR_clock_nanosleep: /* (clockid, flags, req, rem) */
	case LXP_NR_clock_nanosleep_time64: {
		/* Record a wake deadline and ask the run loop to park + delay this proc
		 * (the trap context cannot block). The run loop aborts the slot for the
		 * duration so the RTOS idle/kernel/other threads run and real time + CPU
		 * stats advance — which is what top needs between its two samples. */
		uintptr_t reqp = (nr == LXP_NR_nanosleep) ? (uintptr_t)a0 : (uintptr_t)a2;
		if (!user_ok(proc, (const void *)reqp,
			     (nr == LXP_NR_clock_nanosleep_time64) ? 16u : 8u, 0))
			return -LXP_EFAULT;
		uint64_t sec, nsec;
		if (nr == LXP_NR_clock_nanosleep_time64) {
			const int64_t *t = (const int64_t *)reqp; /* time64 {sec, nsec} */
			sec = (uint64_t)t[0];
			nsec = (uint64_t)t[1];
		} else {
			const int32_t *t = (const int32_t *)reqp; /* time32 {sec, nsec} */
			sec = (uint64_t)(uint32_t)t[0];
			nsec = (uint64_t)(uint32_t)t[1];
		}
		uint64_t dur_us = sec * 1000000ull + nsec / 1000ull;
		if (dur_us > 100000000ull)
			dur_us = 100000000ull; /* clamp to 100 s */
		/* Use the FreeRTOS TICK (ove_time_get_us), NOT the DWT (ove_time_get_ns): with
		 * configUSE_TICKLESS_IDLE the idle task WFI-sleeps between events, gating the CPU clock
		 * so the DWT cycle counter FREEZES across the sleep, while the tick is re-accounted by
		 * vTaskStepTick() on wake. The run-loop coordinator compares this deadline against
		 * ove_time_get_us, so both must use the same cross-idle clock or every sleep / poll
		 * timeout drifts (on real silicon interactive top ran ~1.66x slow + un-quittable). */
		uint64_t now_us = 0;
		lxp_time_us(&now_us);
		proc->sleep_until_us = now_us + dur_us;
		proc->sleep_pending = 1;
		return 0;
	}
	case LXP_NR_uname: {
		/* struct utsname: 6 fixed 65-byte fields (sysname, nodename, release,
		 * version, machine, domainname). The shell reads these at startup. */
		char *u = (char *)(uintptr_t)a0;
		if (!user_ok(proc, u, 6 * 65, 1))
			return -LXP_EFAULT;
		static const char *const f[6] = {"Linux",   "overtos", "6.1.0",
						 "oveRTOS", "armv7l",  "(none)"};
		memset(u, 0, 6 * 65);
		for (int i = 0; i < 6; i++) {
			size_t l = strlen(f[i]);
			memcpy(u + i * 65, f[i], l + 1);
		}
		return 0;
	}
	case LXP_NR_rt_sigaction: {
		/* Record the per-signal disposition; the engine seam delivers it.
		 * struct sigaction: sa_handler@0, sa_flags@4, sa_restorer@8. */
		int sig = (int)a0;
		if (sig < 1 || sig >= LXP_NSIG)
			return -LXP_EINVAL;
		const uint32_t *act = (const uint32_t *)(uintptr_t)a1;
		uint32_t *oact = (uint32_t *)(uintptr_t)a2;
		if (act && !user_ok(proc, act, 3 * sizeof(uint32_t), 0))
			return -LXP_EFAULT;
		if (oact && !user_ok(proc, oact, 3 * sizeof(uint32_t), 1))
			return -LXP_EFAULT;
		if (oact) {
			oact[0] = (uint32_t)proc->sig_handler[sig];
			oact[2] = (uint32_t)proc->sig_restorer;
		}
		if (act) {
			proc->sig_handler[sig] = act[0];
			proc->sig_restorer = act[2];
		}
		return 0;
	}
#if LXP_ENABLE_NET
	case LXP_NR_pselect6_time64: /* (nfds, readfds, writefds, exceptfds, timeout, sigmask) */
		return sys_pselect6(proc, (int)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3,
				    (uintptr_t)a4);
#endif
	case LXP_NR_poll:
	case LXP_NR_ppoll_time64:
		return sys_poll(proc, nr, a0, a1, a2);
	case LXP_NR_wait4: {
		if (a1 && !user_ok(proc, (void *)(uintptr_t)a1, sizeof(int), 1))
			return -LXP_EFAULT; /* the kernel WRITES *status */
		/* Reap an already-exited child immediately (FIFO; status = exit_code << 8).
		 * Else, if children are still live, BLOCK: set wait_pending so the dispatch
		 * parks us and the run-loop coordinator resumes us (returning the reaped pid
		 * + writing *status) when one exits. No children at all → -ECHILD. */
		if (proc->child_count > 0) {
			int pid = proc->child_pid[0];
			int code = proc->child_status[0];
			for (int i = 1; i < proc->child_count; i++) {
				proc->child_pid[i - 1] = proc->child_pid[i];
				proc->child_status[i - 1] = proc->child_status[i];
			}
			proc->child_count--;
			int *status = (int *)(uintptr_t)a1;
			if (status)
				*status = lxp_encode_wstatus(code);
			return pid;
		}
		if (proc->live_children == 0)
			return -LXP_ECHILD;
		if ((int)a2 & 1) /* WNOHANG: children live but none ready */
			return 0;
		proc->wait_pending = 1;
		proc->wait_pid = (int)a0;
		proc->wait_status_p = (uintptr_t)a1;
		return 0; /* dispatch parks; the coordinator's resume supplies the real r0 */
	}
	case LXP_NR_getuid32:
	case LXP_NR_geteuid32:
	case LXP_NR_getgid32:
	case LXP_NR_getegid32:
		return 0; /* run as root */
	case LXP_NR_ioctl:
		return sys_ioctl(proc, a0, a1, a2);
	case LXP_NR_rt_sigsuspend: { /* (unewset, sigsetsize) */
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
		const uint32_t *uset = (const uint32_t *)(uintptr_t)a0;
		size_t sz = (size_t)a1;
		if (sz != 8)
			return -LXP_EINVAL; /* Linux: sigsetsize must equal sizeof(kernel sigset_t) */
		if (!uset || !user_ok(proc, uset, sz, 0))
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
			if ((proc->pending_sigs & lxp_sig_bit(sig)) && !lxp_sig_blocked(proc, sig)) {
				deliverable = 1;
				break;
			}
		if (!deliverable)
			proc->sigsuspend_pending = 1;
		return -LXP_EINTR;
	}
	case LXP_NR_rt_sigtimedwait_time64: { /* (set, info, timeout, sigsetsize) */
		/* Poll variant: return a pending signal that is in `set` (dequeuing it), else report
		 * a timeout. Blocking for the timeout is not modeled — this is enough for libc/shell
		 * startup, which drains pending signals with sigtimedwait and must see -EAGAIN (not
		 * -ENOSYS) to finish and continue to the interactive read. */
		const uint32_t *uset = (const uint32_t *)(uintptr_t)a0;
		size_t sz = (size_t)a3;
		if (sz > 8)
			return -LXP_EINVAL;
		uint64_t set = 0;
		if (uset) {
			if (!user_ok(proc, uset, sz, 0))
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
			(void)a1; /* siginfo output omitted; the return value carries the signo */
			return sig;
		}
		return -LXP_EAGAIN;
	}
	case LXP_NR_rt_sigprocmask: { /* (how, set, oldset, sigsetsize) */
		int how = (int)a0;
		const uint32_t *uset = (const uint32_t *)(uintptr_t)a1;
		uint32_t *uold = (uint32_t *)(uintptr_t)a2;
		size_t sz = (size_t)a3; /* bytes of the guest sigset_t (8 for the 64-bit mask) */
		if (sz > 8)
			return -LXP_EINVAL;
		if (uset && !user_ok(proc, uset, sz, 0))
			return -LXP_EFAULT;
		if (uold && !user_ok(proc, uold, sz, 1))
			return -LXP_EFAULT;
		/* Read the new set BEFORE writing oldset — the guest may alias them, the legal
		 * sigprocmask(SIG_SETMASK, &m, &m) swap — and validate `how` up front so an invalid
		 * value has no side effects. */
		uint64_t nv = 0;
		if (uset) {
			if (how != LXP_SIG_BLOCK && how != LXP_SIG_UNBLOCK && how != LXP_SIG_SETMASK)
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
			proc->sig_blocked = how == LXP_SIG_BLOCK	? old | nv
					    : how == LXP_SIG_UNBLOCK ? old & ~nv
								     : nv; /* LXP_SIG_SETMASK */
			/* SIGKILL and SIGSTOP can never be blocked. */
			proc->sig_blocked &= ~(lxp_sig_bit(LXP_SIGKILL) | lxp_sig_bit(LXP_SIGSTOP));
		}
		return 0;
	}
	case LXP_NR_set_tid_address:
		return 1; /* our single thread's tid */
	case LXP_NR_set_robust_list:
		return 0;
	/* futex / futex_time64 are intercepted by the coordinator (src/lxp_run.c, lxp_futex):
	 * a co-running thread's WAIT parks on the uaddr and a peer's WAKE resumes it. They
	 * never reach this switch. */
#if LXP_ENABLE_NET
	case LXP_NR_socket: { /* (domain, type, protocol) */
		long oi = lxp_sock_new((int)a0, (int)a1, (int)a2);
		if (oi < 0)
			return oi;
		int fd = fd_alloc(proc, LXP_FD_SOCKET, (int)oi, 0);
		if (fd < 0) {
			lxp_sock_close((int)oi);
			return -LXP_EMFILE;
		}
		return fd;
	}
	case LXP_NR_connect: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_connect(proc, oi, (const void *)(uintptr_t)a1,
					    (unsigned)a2);
	}
	case LXP_NR_send:	  /* (fd, buf, len, flags) */
	case LXP_NR_sendto: { /* (fd, buf, len, flags, dest, destlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		const void *dest = (nr == LXP_NR_sendto) ? (const void *)(uintptr_t)a4 : NULL;
		return lxp_sock_send(proc, oi, (const void *)(uintptr_t)a1, (size_t)a2,
					 (int)a3, dest, (unsigned)a5);
	}
	case LXP_NR_recv:	    /* (fd, buf, len, flags) */
	case LXP_NR_recvfrom: { /* (fd, buf, len, flags, src, srclen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		void *src = (nr == LXP_NR_recvfrom) ? (void *)(uintptr_t)a4 : NULL;
		void *srclen = (nr == LXP_NR_recvfrom) ? (void *)(uintptr_t)a5 : NULL;
		return lxp_sock_recv(proc, oi, (void *)(uintptr_t)a1, (size_t)a2, (int)a3,
					 src, srclen);
	}
	case LXP_NR_shutdown: { /* (fd, how) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_shutdown(oi, (int)a1);
	}
	case LXP_NR_getsockname: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_getsockname(proc, oi, (void *)(uintptr_t)a1,
						(void *)(uintptr_t)a2);
	}
	case LXP_NR_getpeername: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_getpeername(proc, oi, (void *)(uintptr_t)a1,
						(void *)(uintptr_t)a2);
	}
	case LXP_NR_setsockopt: { /* (fd, level, optname, optval, optlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_setsockopt(proc, oi, (int)a1, (int)a2,
					       (const void *)(uintptr_t)a3, (unsigned)a4);
	}
	case LXP_NR_getsockopt: { /* (fd, level, optname, optval, optlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_getsockopt(proc, oi, (int)a1, (int)a2,
					       (void *)(uintptr_t)a3, (void *)(uintptr_t)a4);
	}
	case LXP_NR_bind: { /* (fd, addr, addrlen) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_bind(proc, oi, (const void *)(uintptr_t)a1, (unsigned)a2);
	}
	case LXP_NR_listen: { /* (fd, backlog) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return lxp_sock_listen(oi, (int)a1);
	}
	case LXP_NR_accept:	   /* (fd, addr, addrlen) */
	case LXP_NR_accept4: { /* (fd, addr, addrlen, flags) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		int flags = (nr == LXP_NR_accept4) ? (int)a3 : 0;
		return lxp_sock_accept(proc, oi, (void *)(uintptr_t)a1,
					   (void *)(uintptr_t)a2, flags);
	}
	case LXP_NR_sendmsg: { /* (fd, msghdr, flags) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return sys_sendmsg(proc, oi, (const lxp_msghdr *)(uintptr_t)a1, (int)a2);
	}
	case LXP_NR_recvmsg: { /* (fd, msghdr, flags) */
		int oi = sock_slot(proc, (int)a0);
		if (oi < 0)
			return -LXP_ENOTSOCK;
		return sys_recvmsg(proc, oi, (lxp_msghdr *)(uintptr_t)a1, (int)a2);
	}
	case LXP_NR_socketpair: /* fd-passing (SCM_RIGHTS) unsupported */
		return -LXP_EOPNOTSUPP;
#endif
	default:
		return -LXP_ENOSYS;
	}
}

#if LXP_ENABLE_NET
/* Re-evaluate a parked poll(2)'s fd set for readiness (socket + device + console).
 * Mirrors the initial sys_poll scan but in blocking mode — a console fd reports its
 * real key readiness rather than the vi/top ESC-probe heuristic. */
static int lxp_poll_scan(lxp_proc_t *proc, lxp_pollfd *pfds, unsigned nfds)
{
	int ready = 0;
	for (unsigned i = 0; i < nfds; i++) {
		pfds[i].revents = 0;
		lxp_fd_t *s = fd_slot(proc, pfds[i].fd);
		if (!s)
			continue;
		/* Dispatch readiness through the fd's ops; a kind with no poll fop
		 * (regular file / tmpfs / proc / netfs) is always ready. */
		unsigned pb = (s->ops && s->ops->poll) ? s->ops->poll(proc, s)
						       : (unsigned)(LXP_POLLIN | LXP_POLLOUT);
		pfds[i].revents = (short)(pfds[i].events & pb & (LXP_POLLIN | LXP_POLLOUT));
		if (pfds[i].revents)
			ready++;
	}
	return ready;
}

/* ── pselect6(2): select() bridged onto the poll machinery ─────────────────────
 * An fd_set here is one 32-bit word (nfds capped at LXP_SEL_MAXFDS). We derive a
 * pollfd set from the caller's readfds/writefds, scan it with lxp_poll_scan, and
 * write the ready fds back into the fd_sets. A blocking select parks on SOCKW_POLL and
 * the retry re-derives the set from the (still-unmodified) fd_sets each pass. */
static int sel_isset(const uint32_t *set, int fd)
{
	return set && ((set[fd >> 5] >> (fd & 31)) & 1u);
}

/* Build a pollfd array from the fd_sets; returns the count. */
static int sel_build(lxp_proc_t *p, lxp_pollfd *pf)
{
	const uint32_t *r = (const uint32_t *)p->sel_rfds;
	const uint32_t *w = (const uint32_t *)p->sel_wfds;
	int n = 0;
	for (int fd = 0; fd < p->sel_nfds && n < LXP_SEL_MAXFDS; fd++) {
		unsigned ev = 0;
		if (sel_isset(r, fd))
			ev |= LXP_POLLIN;
		if (sel_isset(w, fd))
			ev |= LXP_POLLOUT;
		if (ev) {
			pf[n].fd = fd;
			pf[n].events = (short)ev;
			pf[n].revents = 0;
			n++;
		}
	}
	return n;
}

/* Write the scanned pollfd revents back into the caller's fd_sets; returns select()'s
 * count (a fd ready for both read and write counts twice). Zeroes the sets first. */
static long sel_writeback(lxp_proc_t *p, const lxp_pollfd *pf, int npf)
{
	uint32_t *r = (uint32_t *)p->sel_rfds, *w = (uint32_t *)p->sel_wfds,
		 *e = (uint32_t *)p->sel_efds;
	if (r)
		r[0] = 0;
	if (w)
		w[0] = 0;
	if (e)
		e[0] = 0;
	long ready = 0;
	for (int i = 0; i < npf; i++) {
		int fd = pf[i].fd;
		if ((pf[i].revents & LXP_POLLIN) && r) {
			r[fd >> 5] |= (1u << (fd & 31));
			ready++;
		}
		if ((pf[i].revents & LXP_POLLOUT) && w) {
			w[fd >> 5] |= (1u << (fd & 31));
			ready++;
		}
	}
	return ready; /* exceptfds left cleared (no out-of-band data on this tier) */
}

static long sys_pselect6(lxp_proc_t *p, int nfds, uintptr_t urfds, uintptr_t uwfds,
			 uintptr_t uefds, uintptr_t utimeout)
{
	if (nfds < 0)
		return -LXP_EINVAL;
	if (nfds > LXP_SEL_MAXFDS)
		nfds = LXP_SEL_MAXFDS; /* one fd_set word; higher fds are not selectable here */
	size_t setb = sizeof(uint32_t);
	if ((urfds && !user_ok(p, (void *)urfds, setb, 1)) ||
	    (uwfds && !user_ok(p, (void *)uwfds, setb, 1)) ||
	    (uefds && !user_ok(p, (void *)uefds, setb, 1)))
		return -LXP_EFAULT;
	long tmo_ms = -1; /* NULL timeout = block forever */
	if (utimeout) {
		if (!user_ok(p, (void *)utimeout, 2 * sizeof(int64_t), 0))
			return -LXP_EFAULT;
		const int64_t *ts = (const int64_t *)utimeout; /* time64: tv_sec, tv_nsec */
		int64_t ms = ts[0] * 1000 + ts[1] / 1000000;
		tmo_ms = ms < 0 ? 0 : (long)ms;
	}
	p->sel_nfds = nfds;
	p->sel_rfds = urfds;
	p->sel_wfds = uwfds;
	p->sel_efds = uefds;
	lxp_pollfd pf[LXP_SEL_MAXFDS];
	int npf = sel_build(p, pf);
	int ready = lxp_poll_scan(p, pf, (unsigned)npf);
	if (ready > 0 || tmo_ms == 0) {
		p->sel_active = 0;
		return sel_writeback(p, pf, npf);
	}
	/* Park on the poll machinery; lxp_poll_retry re-derives + completes it. */
	p->sel_active = 1;
	if (tmo_ms > 0) {
		uint64_t now = 0;
		lxp_time_us(&now);
		p->sock_deadline_us = now + (uint64_t)tmo_ms * 1000ull;
	} else {
		p->sock_deadline_us = UINT64_MAX;
	}
	p->sock_oi = -1;
	p->sock_wait = LXP_SOCKW_POLL;
	return 0;
}

long lxp_poll_retry(lxp_proc_t *proc)
{
	if (proc->sel_active) { /* a parked pselect6: re-derive from the fd_sets each pass */
		lxp_pollfd pf[LXP_SEL_MAXFDS];
		int npf = sel_build(proc, pf);
		int ready = lxp_poll_scan(proc, pf, (unsigned)npf);
		int timedout = 0;
		if (proc->sock_deadline_us != UINT64_MAX) {
			uint64_t now_us = 0;
			lxp_time_us(&now_us);
			timedout = (now_us >= proc->sock_deadline_us);
		}
		if (ready > 0 || timedout) {
			proc->sel_active = 0;
			return sel_writeback(proc, pf, npf); /* 0 on timeout (sets zeroed) */
		}
		return -LXP_EAGAIN;
	}
	lxp_pollfd *pfds = (lxp_pollfd *)(uintptr_t)proc->sock_buf;
	int ready = lxp_poll_scan(proc, pfds, (unsigned)proc->sock_len);
	if (ready > 0)
		return ready;
	if (proc->sock_deadline_us != UINT64_MAX) {
		uint64_t now_us = 0;
		lxp_time_us(&now_us);
		if (now_us >= proc->sock_deadline_us)
			return 0; /* timed out */
	}
	return -LXP_EAGAIN; /* still waiting */
}
#endif /* LXP_ENABLE_NET */

#endif /* LXP_ENABLE_LINUX */
