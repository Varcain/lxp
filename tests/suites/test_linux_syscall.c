/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Linux personality syscall-dispatch tests: drive lxp_syscall() directly
 * (no hardware SVC) against an arena-backed process context, checking the
 * core syscall set against the Linux behaviour guests expect.
 */

#include "../framework/lxp_test.h"
#include "lxp_arena.h"
#include "lxp/lxp_bootstrap.h"
#include "lxp_guest.h"
#include "lxp_syscall.h"
#include "fs/lxp_tty.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern size_t g_lxp_test_cache_clean_calls;
extern const void *g_lxp_test_cache_clean_base;
extern size_t g_lxp_test_cache_clean_len;

/* The exec capture stores uint16_t offsets into its own backing buffer rather
 * than pointers, so resolve one to compare its text. */
#define EXEC_ARG(p, j) ((p).exec_capture->argv_buf + (p).exec_capture->argv[j])
#define EXEC_ENV(p, j) ((p).exec_capture->env_buf + (p).exec_capture->env[j])

/* Captures fd 1/2 output so writes can be asserted by value. */
static char g_cap[256];
static size_t g_cap_len;

static long cap_write(void *ctx, int fd, const void *buf, size_t len)
{
	(void)ctx;
	(void)fd;
	if (g_cap_len + len > sizeof(g_cap))
		len = sizeof(g_cap) - g_cap_len;
	memcpy(g_cap + g_cap_len, buf, len);
	g_cap_len += len;
	return (long)len;
}

static uint8_t g_pool[8192] __attribute__((aligned(16)));

static void setup_proc(lxp_proc_t *p, lxp_arena_t *arena)
{
	assert_int_equal(lxp_arena_init(arena, g_pool, sizeof(g_pool)), LXP_OK);
	assert_int_equal(lxp_test_proc_init(p, arena, 4096), LXP_OK);
	/* The host test uses ordinary host buffers, not a bounded program region, so give this proc an
	 * all-permitting access_ok range (NULL is still rejected via region_lo=1). On-target the run loop
	 * restricts region_lo/hi to the real image region. */
	p->mm->region_lo = 1;
	p->mm->region_hi = UINTPTR_MAX;
	p->mm->pool_lo = p->mm->pool_hi = 0;
	p->write_fn = cap_write;
	g_cap_len = 0;
	g_lxp_test_cache_clean_calls = 0;
	g_lxp_test_cache_clean_base = NULL;
	g_lxp_test_cache_clean_len = 0;
}

static void test_lnx_write(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	long r = lxp_syscall(&p, LXP_NR_write, 1, (long)(uintptr_t)"hello", 5, 0, 0, 0);
	assert_int_equal(r, 5);
	assert_int_equal((int)g_cap_len, 5);
	assert_memory_equal(g_cap, "hello", 5);
	assert_int_equal(g_lxp_test_cache_clean_calls, 1);
	assert_ptr_equal(g_lxp_test_cache_clean_base, "hello");
	assert_int_equal(g_lxp_test_cache_clean_len, 5);

	/* A bad fd is rejected. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, 7, (long)(uintptr_t)"x", 1, 0, 0, 0),
			 -LXP_EBADF);
}

static void test_lnx_niceness(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	assert_int_equal(lxp_proc_nice_get(&p), 0);
	assert_int_equal(lxp_nice_weight(0), 20);
	assert_int_equal(lxp_nice_weight(-20), 40);
	assert_int_equal(lxp_nice_weight(19), 1);
	/* nice(2) moves the value by its increment, clamped to [-20, 19]; get/setpriority
	 * are answered by the coordinator (test_coord_lifecycle.c). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_nice, -7, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_proc_nice_get(&p), -7);
	assert_int_equal(lxp_syscall(&p, LXP_NR_nice, 50, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_proc_nice_get(&p), 19);
	assert_int_equal(lxp_syscall(&p, LXP_NR_nice, INT32_MIN, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_proc_nice_get(&p), -20);
}

/* The syscalls that may run in the trap's top half: exactly this set. */
static void test_lnx_fast_syscalls(void **state)
{
	(void)state;
	static const long fast[] = {
		LXP_NR_exit,	    LXP_NR_exit_group,	    LXP_NR_getpid,	 LXP_NR_getppid,
		LXP_NR_getuid32,    LXP_NR_getgid32,	    LXP_NR_geteuid32,	 LXP_NR_getegid32,
		LXP_NR_gettid,	    LXP_NR_umask,	    LXP_NR_prctl,	 LXP_NR_sched_yield,
		LXP_NR_nice,	    LXP_NR_setpgid,	    LXP_NR_getpgrp,	 LXP_NR_setsid,
		LXP_NR_fchmod,	    LXP_NR_fchown32,	    LXP_NR_setgroups32,	 LXP_NR_setuid32,
		LXP_NR_setgid32,    LXP_NR_setreuid32,	    LXP_NR_setregid32,	 LXP_NR_setresuid32,
		LXP_NR_setresgid32, LXP_NR_set_tid_address, LXP_NR_set_robust_list, LXP_NR_mprotect,
		LXP_NR_reboot,
	};
	for (long nr = -1; nr < 512; nr++) {
		int expected = 0;
		for (size_t i = 0; i < sizeof(fast) / sizeof(fast[0]); i++)
			expected |= fast[i] == nr;
		assert_int_equal((lxp_syscall_flags(nr) & LXP_SYS_FAST) != 0, expected);
	}
}

static void test_lnx_writev(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	lxp_iovec iov[2] = {
		{(void *)"foo", 3},
		{(void *)"bar!", 4},
	};
	long r = lxp_syscall(&p, LXP_NR_writev, 2, (long)(uintptr_t)iov, 2, 0, 0, 0);
	assert_int_equal(r, 7);
	assert_int_equal((int)g_cap_len, 7);
	assert_memory_equal(g_cap, "foobar!", 7);
	/* One clean publishes the iovec descriptors; sys_write() publishes both payloads. */
	assert_int_equal(g_lxp_test_cache_clean_calls, 3);
	assert_ptr_equal(g_lxp_test_cache_clean_base, "bar!");
	assert_int_equal(g_lxp_test_cache_clean_len, 4);
}

static void test_lnx_brk(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	/* brk(0) reports the current break without moving it. */
	long base = lxp_syscall(&p, LXP_NR_brk, 0, 0, 0, 0, 0, 0);
	assert_int_equal((uintptr_t)base, p.mm->brk_base);

	/* A valid grow moves the break and returns the new value. */
	long grown = lxp_syscall(&p, LXP_NR_brk, base + 100, 0, 0, 0, 0, 0);
	assert_int_equal(grown, base + 100);
	assert_int_equal(p.mm->brk_cur, (uintptr_t)base + 100);

	/* A request beyond the arena reservation leaves the break unchanged. */
	long over = lxp_syscall(&p, LXP_NR_brk, (long)(p.mm->brk_max + 4096), 0, 0, 0, 0, 0);
	assert_int_equal(over, base + 100);
}

static void test_lnx_mmap(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	/* Anonymous mmap returns usable, zeroed memory from the arena. */
	long m = lxp_syscall(&p, LXP_NR_mmap2, 0, 256, 0x3 /*PROT_RW*/, LXP_MAP_ANONYMOUS, -1, 0);
	assert_true(m > 0);
	uint8_t *mem = (uint8_t *)(uintptr_t)m;
	for (int i = 0; i < 256; i++)
		assert_int_equal(mem[i], 0);
	mem[0] = 0xab; /* and it is writable */
	assert_int_equal(mem[0], 0xab);

	/* Only the exact live mmap extent can be reclaimed. Interior pointers,
	 * mismatched lengths and the untracked brk reservation fail closed. */
	size_t mapped_used = lxp_arena_used(&arena);
	assert_int_equal(lxp_syscall(&p, LXP_NR_munmap, m + 16, 240, 0, 0, 0, 0), -LXP_EINVAL);
	assert_int_equal(lxp_syscall(&p, LXP_NR_munmap, m, 255, 0, 0, 0, 0), -LXP_EINVAL);
	assert_int_equal(lxp_syscall(&p, LXP_NR_munmap, (long)p.mm->brk_base, 4096, 0, 0, 0, 0),
			 -LXP_EINVAL);
	assert_int_equal(lxp_arena_used(&arena), mapped_used);
	assert_int_equal(lxp_syscall(&p, LXP_NR_munmap, m, 256, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_munmap, m, 256, 0, 0, 0, 0), -LXP_EINVAL);
	assert_int_equal(lxp_syscall(&p, LXP_NR_munmap, m, 0, 0, 0, 0, 0), -LXP_EINVAL);

	/* A file-backed mapping reads the fd's bytes into the block (ld.so loads .so segments
	 * this way on NOMMU); an unopened fd is rejected without leaking its provisional block. */
	size_t before_failed_map = lxp_arena_used(&arena);
	assert_int_equal(lxp_syscall(&p, LXP_NR_mmap2, 0, 256, 0x3, 0, 3, 0), -LXP_EBADF);
	assert_int_equal(lxp_arena_used(&arena), before_failed_map);

	/* Exhausting the arena yields -ENOMEM rather than a crash. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_mmap2, 0, 1 << 20, 0x3, LXP_MAP_ANONYMOUS, -1, 0),
			 -LXP_ENOMEM);
}

static void test_lnx_init_stubs(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	assert_int_equal(lxp_syscall(&p, LXP_NR_getpid, 0, 0, 0, 0, 0, 0), 1);	/* pid */
	assert_int_equal(lxp_syscall(&p, LXP_NR_getppid, 0, 0, 0, 0, 0, 0), 0); /* ppid */
	/* wait4: -ECHILD with no child; reaps queued zombies oldest-first (FIFO),
	 * so a pipeline's two children both get reaped. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_wait4, -1, 0, 0, 0, 0, 0), -LXP_ECHILD);
	p.group->child_pid[0] = 2;
	p.group->child_status[0] = 7;
	p.group->child_pid[1] = 3;
	p.group->child_status[1] = 0;
	p.group->child_count = 2;
	int wstatus = -1;
	assert_int_equal(lxp_syscall(&p, LXP_NR_wait4, -1, (long)(uintptr_t)&wstatus, 0, 0, 0, 0),
			 2);
	assert_int_equal(wstatus, 7 << 8); /* first child: WEXITSTATUS == 7 */
	assert_int_equal(lxp_syscall(&p, LXP_NR_wait4, -1, 0, 0, 0, 0, 0), 3); /* second */
	assert_int_equal(lxp_syscall(&p, LXP_NR_wait4, -1, 0, 0, 0, 0, 0), -LXP_ECHILD);
	assert_int_equal(lxp_syscall(&p, LXP_NR_getuid32, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_getegid32, 0, 0, 0, 0, 0, 0), 0);
	/* Console fds are ttys: TCGETS fills a canonical termios (so isatty → the
	 * shell goes interactive); a non-open fd is not a tty. */
	lxp_termios tio;
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_ioctl, 0, LXP_TCGETS, (long)(uintptr_t)&tio, 0, 0, 0), 0);
	assert_true((tio.c_lflag & LXP_ICANON) != 0);
	assert_true((tio.c_lflag & LXP_ECHO) != 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 7, LXP_TCGETS, (long)(uintptr_t)&tio, 0, 0,
				     0),
			 -LXP_ENOTTY);
	lxp_winsize ws;
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_ioctl, 1, LXP_TIOCGWINSZ, (long)(uintptr_t)&ws, 0, 0, 0), 0);
	assert_int_equal(ws.ws_col, 80);
	/* fcntl F_DUPFD duplicates stdin to the lowest free fd >= arg; a too-high
	 * arg has no slot (the shell then retries low for its interactive fd). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_fcntl64, 0, LXP_F_DUPFD, 3, 0, 0, 0), 3);
	/* A too-high arg (the shell asks for >=255) falls back to the lowest free fd. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_fcntl64, 0, LXP_F_DUPFD, 255, 0, 0, 0), 4);
	/* A blocking poll (timeout < 0) reports the console ready; the caller then
	 * blocks in read() for the real byte. */
	lxp_pollfd pfd = {.fd = 0, .events = LXP_POLLIN, .revents = 0};
	assert_int_equal(lxp_syscall(&p, LXP_NR_poll, (long)(uintptr_t)&pfd, 1, -1, 0, 0, 0), 1);
	assert_int_equal(pfd.revents, LXP_POLLIN);
	/* A short finite poll is a "is input pending right now?" probe (vi's repaint
	 * gate / read_key's ESC-sequence timeout). With no read-ahead we honestly
	 * report not-ready so a lone ESC stays ESC and vi repaints while inserting. */
	pfd.revents = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_poll, (long)(uintptr_t)&pfd, 1, 50, 0, 0, 0), 0);
	assert_int_equal(pfd.revents, 0);
	/* Thread-bookkeeping stubs succeed so libc startup proceeds. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_set_tid_address, 0, 0, 0, 0, 0, 0), 1);
	assert_int_equal(lxp_syscall(&p, LXP_NR_set_robust_list, 0, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, 0, 0, 0, 0, 0, 0), 0);
	/* A thread reports its task id through gettid and its group id through getpid. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_gettid, 0, 0, 0, 0, 0, 0), 1);
	p.pid = 7;
	p.group->tgid = 3;
	assert_int_equal(lxp_syscall(&p, LXP_NR_gettid, 0, 0, 0, 0, 0, 0), 7);
	assert_int_equal(lxp_syscall(&p, LXP_NR_getpid, 0, 0, 0, 0, 0, 0), 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_prctl, 0, 0, 0, 0, 0, 0), 0);
	/* rt_sigaction records the per-signal disposition (sa_handler@0, sa_restorer@8)
	 * for the engine seam to deliver; the old disposition is reported via oact. */
	uint32_t act[4] = {0x1234, 0, 0x5678, 0}, oact[4] = {0xff, 0, 0xff, 0};
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigaction, LXP_SIGINT, (long)(uintptr_t)act,
				     (long)(uintptr_t)oact, 0, 0, 0),
			 0);
	assert_int_equal((uint32_t)p.sighand->handler[LXP_SIGINT], 0x1234);
	assert_int_equal((uint32_t)p.sighand->restorer, 0x5678);
	assert_int_equal(oact[0], LXP_SIG_DFL); /* was unset (default) */
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigaction, 99, (long)(uintptr_t)act, 0, 0, 0, 0),
			 -LXP_EINVAL);
	/* getcwd writes "/" and returns its length incl. NUL; -ERANGE if too small. */
	char cwd[8] = {0};
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_getcwd, (long)(uintptr_t)cwd, sizeof(cwd), 0, 0, 0, 0), 2);
	assert_string_equal(cwd, "/");
	assert_int_equal(lxp_syscall(&p, LXP_NR_getcwd, (long)(uintptr_t)cwd, 1, 0, 0, 0, 0),
			 -LXP_ERANGE);
}

/* The console is a tty: TCGETS returns what TCSETS set (so a program restoring saved
 * settings restores its own), TIOCSWINSZ sticks, and a new tty starts from the cooked
 * defaults with ^C and ^Z. */
static void test_lnx_console_termios_roundtrip(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_tty_init(lxp_console_tty());

	lxp_termios tio;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 0, LXP_TCGETS, (long)(uintptr_t)&tio, 0, 0,
				     0),
			 0);
	assert_int_equal(tio.c_cc[LXP_VINTR], 3);
	assert_int_equal(tio.c_cc[LXP_VSUSP], 26);
	tio.c_lflag &= ~(LXP_ICANON | LXP_ECHO | LXP_ISIG);
	tio.c_cc[LXP_VMIN] = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 0, LXP_TCSETSW, (long)(uintptr_t)&tio, 0,
				     0, 0),
			 0);
	lxp_termios got;
	memset(&got, 0xa5, sizeof(got));
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 1, LXP_TCGETS, (long)(uintptr_t)&got, 0, 0,
				     0),
			 0);
	assert_memory_equal(&got, &tio, sizeof(tio));

	lxp_winsize ws = {.ws_row = 50, .ws_col = 132};
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 1, LXP_TIOCSWINSZ, (long)(uintptr_t)&ws, 0,
				     0, 0),
			 0);
	lxp_winsize wgot = {0};
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 0, LXP_TIOCGWINSZ, (long)(uintptr_t)&wgot,
				     0, 0, 0),
			 0);
	assert_int_equal(wgot.ws_row, 50);
	assert_int_equal(wgot.ws_col, 132);

	/* Before a tcsetpgrp the caller is reported as the foreground group. */
	uint32_t pgrp = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 0, LXP_TIOCGPGRP, (long)(uintptr_t)&pgrp, 0,
				     0, 0),
			 0);
	assert_int_equal(pgrp, (uint32_t)p.pid);
	pgrp = 9;
	assert_int_equal(lxp_syscall(&p, LXP_NR_ioctl, 0, LXP_TIOCSPGRP, (long)(uintptr_t)&pgrp, 0,
				     0, 0),
			 0);
	assert_int_equal(lxp_console_tty()->fg_pgrp, 9);
	lxp_tty_init(lxp_console_tty());
}

static void test_lnx_setup_stack(void **state)
{
	(void)state;
	static uint8_t stk[512] __attribute__((aligned(8)));
	const char *const argv[] = {"/bin/app", "arg1", NULL};
	const char *const envp[] = {"PATH=/bin", "HOME=/", NULL};

	/* uClinux/bFLT layout: sp[0]=argc, sp[1]=argv ptr, sp[2]=envp ptr. */
	uintptr_t *sp = lxp_setup_stack(stk, sizeof(stk), 2, argv, envp, 0, 0, 0, 0, 0);
	assert_non_null(sp);
	assert_int_equal((uintptr_t)sp & 7u, 0); /* SP is 8-aligned */

	assert_int_equal((int)sp[0], 2); /* argc */
	char *const *av = (char *const *)sp[1];
	assert_string_equal(av[0], "/bin/app");
	assert_string_equal(av[1], "arg1");
	assert_null((void *)av[2]); /* argv terminator */
	char *const *ev = (char *const *)sp[2];
	assert_string_equal(ev[0], "PATH=/bin");
	assert_string_equal(ev[1], "HOME=/");
	assert_null((void *)ev[2]); /* envp terminator */

	/* auxv follows the envp array's NULL (envc=2 -> at ev[3]). */
	const uintptr_t *aux = (const uintptr_t *)&ev[3];
	assert_int_equal(aux[0], LXP_AT_PAGESZ);
	assert_int_equal(aux[1], 4096);
	assert_int_equal(aux[2], LXP_AT_RANDOM);
	assert_non_null((void *)aux[3]); /* AT_RANDOM points into the stack */
	for (int i = 0; i < 16; i++)
		assert_int_equal(((const uint8_t *)aux[3])[i], (uint8_t)(0xa5u ^ (uint8_t)i));
	assert_int_equal(aux[4], LXP_AT_NULL);

	/* FDPIC inline layout: sp -> argc, argv[] inline, NULL, envp[] inline, NULL, auxv.
	 * The crt reads envp as &argv[argc+1], so the env must be laid out here too. */
	uintptr_t *fsp = lxp_setup_stack(stk, sizeof(stk), 2, argv, envp, 1, 0, 0, 0, 0);
	assert_non_null(fsp);
	assert_int_equal((int)fsp[0], 2); /* argc */
	assert_string_equal((char *)fsp[1], "/bin/app");
	assert_string_equal((char *)fsp[2], "arg1");
	assert_null((void *)fsp[3]); /* argv terminator */
	assert_string_equal((char *)fsp[4], "PATH=/bin");
	assert_string_equal((char *)fsp[5], "HOME=/");
	assert_null((void *)fsp[6]);	       /* envp terminator */
	assert_int_equal(fsp[7], LXP_AT_PHDR); /* auxv begins right after the envp NULL */

	/* A NULL environment is accepted (empty envp). */
	uintptr_t *sp2 = lxp_setup_stack(stk, sizeof(stk), 1, argv, NULL, 0, 0, 0, 0, 0);
	assert_non_null(sp2);
	assert_int_equal((int)sp2[0], 1);
	char *const *av2 = (char *const *)sp2[1];
	assert_string_equal(av2[0], "/bin/app");
	assert_null((void *)av2[1]); /* argv terminator */
	char *const *ev2 = (char *const *)sp2[2];
	assert_null((void *)ev2[0]); /* empty envp */

	/* Process creation fails closed rather than installing a predictable canary. */
	g_lxp_test_random_result = LXP_ERR_NOT_SUPPORTED;
	assert_null(lxp_setup_stack(stk, sizeof(stk), 1, argv, NULL, 0, 0, 0, 0, 0));
	g_lxp_test_random_result = LXP_OK;
}

/* Mirrors the kernel struct stat64 prefix through st_size (offset 48). */
struct test_kstat64 {
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
	uint8_t __tail[64];
};

static const uint8_t k_motd[] = "Welcome to oveRTOS\n"; /* 19 bytes + NUL */
static const uint8_t k_elf[] = {0x7f, 'E', 'L', 'F'};
static const uint8_t k_script[] = "#!/bin/sh -e\necho script\n";
static const lxp_file_t k_rootfs[] = {
	{"/", NULL, 0, LXP_S_IFDIR},
	{"/etc", NULL, 0, LXP_S_IFDIR},
	{"/etc/motd", k_motd, sizeof(k_motd) - 1, 0},
	{"/bin", NULL, 0, LXP_S_IFDIR},
	{"/bin/sh", k_elf, sizeof(k_elf), 0},
	{"/bin/script", k_script, sizeof(k_script) - 1, 0},
};
#define K_ROOTFS_N ((int)(sizeof(k_rootfs) / sizeof(k_rootfs[0])))

/* A rootfs shaped like the real Buildroot one, which k_rootfs above is not:
 * there /bin/sh is a RELATIVE symlink to busybox rather than a regular file, and
 * the script lives two directories down. Buildroot installs every applet that
 * way, so an interpreter reached through a symlink is the normal case on target,
 * not an exotic one — and nothing covered it. */
static const uint8_t k_bb_elf[] = {0x7f, 'E', 'L', 'F'};
static const uint8_t k_rcs[] = "#!/bin/sh\necho rcS\n";
static const lxp_file_t k_lnkfs[] = {
	{"/", NULL, 0, LXP_S_IFDIR},
	{"/bin", NULL, 0, LXP_S_IFDIR},
	{"/bin/busybox", k_bb_elf, sizeof(k_bb_elf), 0},
	{"/bin/sh", (const uint8_t *)"busybox", 7, LXP_S_IFLNK},
	{"/etc", NULL, 0, LXP_S_IFDIR},
	{"/etc/init.d", NULL, 0, LXP_S_IFDIR},
	{"/etc/init.d/rcS", k_rcs, sizeof(k_rcs) - 1, 0},
};
#define K_LNKFS_N ((int)(sizeof(k_lnkfs) / sizeof(k_lnkfs[0])))

/* fcntl(F_GETFL) must report a truthful access mode: uClibc's fdopen() checks the
 * FILE* mode against it, so a writable fd answering O_RDONLY fails
 * fdopen(fd, "w") with EINVAL. That is what broke dropbearkey's .pub write on
 * target while the key itself generated fine. */
static void test_lnx_fcntl_getfl_access_mode(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);

	/* A writable tmpfs fd must not claim to be read-only. */
	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/tmp/k.pub",
			      LXP_O_RDWR | LXP_O_CREAT, 0644, 0, 0);
	assert_true(fd >= 0);
	long fl = lxp_syscall(&p, LXP_NR_fcntl64, fd, LXP_F_GETFL, 0, 0, 0, 0);
	assert_true(fl >= 0);
	assert_int_not_equal(fl & LXP_O_ACCMODE, LXP_O_RDONLY);

	/* A read-only rootfs fd may. */
	long rfd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/etc/motd",
			       LXP_O_RDONLY, 0, 0, 0);
	assert_true(rfd >= 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_fcntl64, rfd, LXP_F_GETFL, 0, 0, 0, 0) &
				 LXP_O_ACCMODE,
			 LXP_O_RDONLY);
}

/* Two guests can be parked with an exec request pending at the same time — a
 * pipeline forks several — so the capture is per-proc rather than one global
 * staging buffer. Nothing pinned that: with a shared buffer both procs would
 * still pass every single-proc test and only corrupt each other under
 * concurrency, where it reads as a random wrong-program launch. */
static void test_lnx_exec_capture_is_per_proc(void **state)
{
	(void)state;
	lxp_arena_t arena_a, arena_b;
	lxp_proc_t a, b;
	setup_proc(&a, &arena_a);
	setup_proc(&b, &arena_b);
	lxp_proc_set_rootfs(&a, k_rootfs, K_ROOTFS_N);
	lxp_proc_set_rootfs(&b, k_rootfs, K_ROOTFS_N);

	char *const argv_a[] = {"aaa", "a1", NULL};
	char *const envp_a[] = {"A=1", NULL};
	char *const argv_b[] = {"bbb", "b1", "b2", NULL};
	char *const envp_b[] = {"B=2", NULL};

	/* Interleave: b's capture must not disturb a's already-pending one. */
	assert_int_equal(lxp_syscall(&a, LXP_NR_execve, (long)(uintptr_t)"/bin/sh",
				     (long)(uintptr_t)argv_a, (long)(uintptr_t)envp_a, 0, 0, 0),
			 0);
	assert_int_equal(lxp_syscall(&b, LXP_NR_execve, (long)(uintptr_t)"/bin/sh",
				     (long)(uintptr_t)argv_b, (long)(uintptr_t)envp_b, 0, 0, 0),
			 0);

	assert_int_equal(a.intent.kind, LXP_INTENT_EXEC);
	assert_int_equal(b.intent.kind, LXP_INTENT_EXEC);
	assert_int_equal(a.exec_capture->argc, 2);
	assert_int_equal(b.exec_capture->argc, 3);
	assert_string_equal(EXEC_ARG(a, 0), "aaa");
	assert_string_equal(EXEC_ARG(a, 1), "a1");
	assert_string_equal(EXEC_ARG(b, 0), "bbb");
	assert_string_equal(EXEC_ARG(b, 2), "b2");
	assert_int_equal(a.exec_capture->envc, 1);
	assert_int_equal(b.exec_capture->envc, 1);
	assert_string_equal(EXEC_ENV(a, 0), "A=1");
	assert_string_equal(EXEC_ENV(b, 0), "B=2");

	/* The buffers are distinct storage, not two views of one staging area. */
	assert_ptr_not_equal(a.exec_capture->argv_buf, b.exec_capture->argv_buf);
	assert_ptr_not_equal(a.exec_capture->env_buf, b.exec_capture->env_buf);
}

/* Exec a #! script whose interpreter is a symlink — BusyBox init running
 * /etc/init.d/rcS, which fails on target with ENOENT. */
static void test_lnx_exec_script_symlink_interp(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_lnkfs, K_LNKFS_N);

	/* setup_proc leaves an all-permitting access_ok range, and that is exactly
	 * what hid this bug: on target the #! interpreter path is a kernel stack
	 * buffer OUTSIDE the guest's region, so lxp_resolve_path()'s user-pointer guard
	 * rejected it and every interpreter script died with ENOENT. A test with no
	 * region bound can never see that. So give this proc a real one — argv and
	 * the strings it points at laid out in one blob, the way a guest's are —
	 * and nothing the kernel owns may be passed off as guest memory. */
	static struct {
		char *vec[2];
		char path[32];
	} gmem;
	memcpy(gmem.path, "/etc/init.d/rcS", sizeof("/etc/init.d/rcS"));
	gmem.vec[0] = gmem.path;
	gmem.vec[1] = NULL;
	p.mm->region_lo = (uintptr_t)&gmem;
	p.mm->region_hi = p.mm->region_lo + sizeof(gmem);

	long rc = lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)gmem.path,
			      (long)(uintptr_t)gmem.vec, 0, 0, 0, 0);
	assert_int_equal(rc, 0);
	/* Re-targeted at the interpreter's target, not the script. */
	assert_int_equal(p.intent.kind, LXP_INTENT_EXEC);
	assert_string_equal(k_lnkfs[p.exec_file_idx].path, "/bin/busybox");
	assert_int_equal(p.exec_capture->argc, 2);
	assert_string_equal(EXEC_ARG(p, 0), "/bin/sh");
	assert_string_equal(EXEC_ARG(p, 1), "/etc/init.d/rcS");
}

static void test_lnx_file(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);

	const long motd_len = (long)(sizeof(k_motd) - 1);

	/* open a rootfs file -> a fresh (>= 3) fd. */
	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/etc/motd",
			      LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);

	/* sequential read + short read + EOF. */
	char buf[32];
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 7, 0, 0, 0), 7);
	assert_memory_equal(buf, "Welcome", 7);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, sizeof(buf), 0, 0,
				     0),
			 motd_len - 7);
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, sizeof(buf), 0, 0, 0), 0);

	/* lseek SET / END. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_SET, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 7, 0, 0, 0), 7);
	assert_int_equal(lxp_syscall(&p, LXP_NR_lseek, fd, 0, LXP_SEEK_END, 0, 0, 0), motd_len);

	/* fstat64: a regular file with the right size. */
	struct test_kstat64 st;
	assert_int_equal(lxp_syscall(&p, LXP_NR_fstat64, fd, (long)(uintptr_t)&st, 0, 0, 0, 0), 0);
	assert_int_equal(st.st_mode & 0xf000u, LXP_S_IFREG);
	assert_int_equal((long)st.st_size, motd_len);

	/* close -> the fd is no longer valid. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 1, 0, 0, 0),
			 -LXP_EBADF);

	/* errors: missing path, write attempt on the read-only fs. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/nope",
				     LXP_O_RDONLY, 0, 0, 0),
			 -LXP_ENOENT);
	assert_int_equal(lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/etc/motd",
				     1 /* O_WRONLY */, 0, 0, 0),
			 -LXP_EROFS);

	/* fstat64 on a standard stream reports a character device. */
	struct test_kstat64 st2;
	assert_int_equal(lxp_syscall(&p, LXP_NR_fstat64, 1, (long)(uintptr_t)&st2, 0, 0, 0, 0), 0);
	assert_int_equal(st2.st_mode & 0xf000u, LXP_S_IFCHR);
}

static void test_dup_and_fork_share_file_offset(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);

	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/etc/motd",
			      LXP_O_RDONLY, 0, 0, 0);
	long alias = lxp_syscall(&p, LXP_NR_dup, fd, 0, 0, 0, 0, 0);
	assert_true(fd >= 3 && alias >= 3);
	char buf[8];
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, 7, 0, 0, 0), 7);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, alias, (long)(uintptr_t)buf, 3, 0, 0, 0), 3);
	assert_memory_equal(buf, " to", 3);

	lxp_proc_t child = p;
	assert_int_equal(lxp_fd_fork_inherit(&child), 0);
	assert_int_equal(lxp_syscall(&child, LXP_NR_read, fd, (long)(uintptr_t)buf, 3, 0, 0, 0), 3);
	assert_memory_equal(buf, " ov", 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, alias, (long)(uintptr_t)buf, 4, 0, 0, 0), 4);
	assert_memory_equal(buf, "eRTO", 4);
	lxp_fd_close_all(&child);
	lxp_fd_close_all(&p);
}

static void test_clone_resource_sharing_flags(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t parent;
	const int sig = 10;
	setup_proc(&parent, &arena);
	strcpy(parent.fs_context->cwd, "/parent");
	parent.sighand->handler[sig] = 0x1234;

	lxp_proc_t shared = parent;
	assert_int_equal(lxp_proc_resources_fork(&shared, &parent,
						 LXP_CLONE_FILES | LXP_CLONE_FS |
							 LXP_CLONE_SIGHAND),
			 0);
	assert_ptr_equal(shared.files, parent.files);
	assert_ptr_equal(shared.fs_context, parent.fs_context);
	assert_ptr_equal(shared.sighand, parent.sighand);
	strcpy(shared.fs_context->cwd, "/shared");
	shared.sighand->handler[sig] = 0x5678;
	assert_string_equal(parent.fs_context->cwd, "/shared");
	assert_int_equal(parent.sighand->handler[sig], 0x5678);
	assert_int_equal(lxp_fd_close(&shared, 0), 0);
	assert_int_equal(lxp_fd_kind(&parent, 0), LXP_FD_FREE);
	lxp_proc_resources_put(&shared);
	assert_int_equal(parent.files->refs, 1);

	lxp_proc_t copied = parent;
	assert_int_equal(lxp_proc_resources_fork(&copied, &parent, 0), 0);
	assert_ptr_not_equal(copied.files, parent.files);
	assert_ptr_not_equal(copied.fs_context, parent.fs_context);
	assert_ptr_not_equal(copied.sighand, parent.sighand);
	strcpy(copied.fs_context->cwd, "/private");
	copied.sighand->handler[sig] = 0x9abc;
	assert_string_equal(parent.fs_context->cwd, "/shared");
	assert_int_equal(parent.sighand->handler[sig], 0x5678);
	assert_int_equal(lxp_fd_close(&copied, 1), 0);
	assert_int_equal(lxp_fd_kind(&parent, 1), LXP_FD_CONSOLE);

	lxp_proc_t shared_mm = parent;
	assert_int_equal(lxp_proc_mm_fork(&shared_mm, &parent, LXP_CLONE_VM), 0);
	assert_ptr_equal(shared_mm.mm, parent.mm);
	shared_mm.mm->brk_cur += 16;
	assert_int_equal(parent.mm->brk_cur, shared_mm.mm->brk_cur);
	lxp_proc_mm_put(&shared_mm);

	lxp_proc_t copied_mm = parent;
	assert_int_equal(lxp_proc_mm_fork(&copied_mm, &parent, 0), 0);
	assert_ptr_not_equal(copied_mm.mm, parent.mm);
	uintptr_t parent_brk = parent.mm->brk_cur;
	copied_mm.mm->brk_cur += 16;
	assert_int_equal(parent.mm->brk_cur, parent_brk);
	lxp_proc_mm_put(&copied_mm);

	parent.group->tgid = 10;
	parent.group->ppid = 2;
	parent.group->pgid = 7;
	parent.group->live_children = 1;
	lxp_proc_t thread_group = parent;
	assert_int_equal(lxp_proc_group_fork(&thread_group, &parent, LXP_CLONE_THREAD, 11), 0);
	assert_ptr_equal(thread_group.group, parent.group);
	thread_group.group->pgid = 8;
	assert_int_equal(parent.group->pgid, 8);
	lxp_proc_group_put(&thread_group);

	lxp_proc_t child_group = parent;
	assert_int_equal(lxp_proc_group_fork(&child_group, &parent, 0, 20), 0);
	assert_ptr_not_equal(child_group.group, parent.group);
	assert_int_equal(child_group.group->tgid, 20);
	assert_int_equal(child_group.group->ppid, 10);
	assert_int_equal(child_group.group->pgid, 8);
	assert_int_equal(child_group.group->live_children, 0);
	assert_int_equal(child_group.group->child_count, 0);
	lxp_proc_group_put(&child_group);

	lxp_proc_resources_put(&copied);
	lxp_proc_resources_put(&parent);
	lxp_proc_mm_put(&parent);
	lxp_proc_group_put(&parent);
}

static void test_eventfd_alias_survives_peer_close(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	long fd = lxp_syscall(&p, LXP_NR_eventfd2, 0, 0, 0, 0, 0, 0);
	long alias = lxp_syscall(&p, LXP_NR_dup, fd, 0, 0, 0, 0, 0);
	assert_true(fd >= 3 && alias >= 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, alias, 0, 0, 0, 0, 0), 0);
	uint64_t one = 1, value = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, fd, (long)(uintptr_t)&one, sizeof(one), 0, 0,
				     0),
			 sizeof(one));
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)&value, sizeof(value), 0,
				     0, 0),
			 sizeof(value));
	assert_int_equal(value, 1);
}

static void test_maximum_descriptor_aliases_keep_last_reference_live(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);
	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/etc/motd",
			      LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	while (lxp_syscall(&p, LXP_NR_dup, fd, 0, 0, 0, 0, 0) >= 0)
		;

	lxp_proc_t children[LXP_NSLOT - 1];
	for (int i = 0; i < LXP_NSLOT - 1; i++) {
		children[i] = p;
		assert_int_equal(lxp_fd_fork_inherit(&children[i]), 0);
	}
	lxp_fd_close_all(&p);
	for (int i = 0; i < LXP_NSLOT - 2; i++)
		lxp_fd_close_all(&children[i]);

	char byte = 0;
	assert_int_equal(lxp_syscall(&children[LXP_NSLOT - 2], LXP_NR_read, fd,
				     (long)(uintptr_t)&byte, 1, 0, 0, 0),
			 1);
	assert_int_equal(byte, 'W');
	lxp_fd_close_all(&children[LXP_NSLOT - 2]);
}

/* Writable tmpfs overlay: O_CREAT makes a file, O_APPEND extends it, reads see it. */
static void test_lnx_tmpfs(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);

	/* O_CREAT|O_WRONLY|O_TRUNC creates a fresh writable file; write "hello". */
	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/tmp/t.txt",
			      LXP_O_WRONLY | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, fd, (long)(uintptr_t)"hello", 5, 0, 0, 0),
			 5);
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0), 0);

	/* Re-open O_APPEND: the offset starts at end-of-file, so "!" extends it. */
	fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/tmp/t.txt",
			 LXP_O_WRONLY | LXP_O_APPEND, 0, 0, 0);
	assert_true(fd >= 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, fd, (long)(uintptr_t)"!", 1, 0, 0, 0), 1);
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0), 0);

	/* Read it back: "hello!" (a tmpfs file shadows the read-only rootfs). */
	fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/tmp/t.txt",
			 LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	char buf[16];
	assert_int_equal(
		lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)buf, sizeof(buf), 0, 0, 0), 6);
	assert_memory_equal(buf, "hello!", 6);

	/* fstat64: a regular file sized 6. */
	struct test_kstat64 st;
	assert_int_equal(lxp_syscall(&p, LXP_NR_fstat64, fd, (long)(uintptr_t)&st, 0, 0, 0, 0), 0);
	assert_int_equal(st.st_mode & 0xf000u, LXP_S_IFREG);
	assert_int_equal((long)st.st_size, 6);
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0), 0);

	/* Reading a non-existent path without O_CREAT does NOT create it. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
				     (long)(uintptr_t)"/tmp/missing", LXP_O_RDONLY, 0, 0, 0),
			 -LXP_ENOENT);
}

/* unlink removes the name but an existing open-file description keeps the
 * inode and bytes alive. SQLite opens and immediately unlinks temp databases. */
static void test_lnx_tmpfs_unlink_open(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	const char *path = "/tmp/unlinked.db";
	long oldfd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
				 (long)(uintptr_t)path,
				 LXP_O_RDWR | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(oldfd >= 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, oldfd,
				     (long)(uintptr_t)"old", 3, 0, 0, 0), 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_unlink, (long)(uintptr_t)path,
				     0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
				     (long)(uintptr_t)path, LXP_O_RDONLY, 0, 0, 0),
			 -LXP_ENOENT);

	assert_int_equal(lxp_syscall(&p, LXP_NR_lseek, oldfd, 0, LXP_SEEK_SET, 0, 0, 0), 0);
	char old[3];
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, oldfd,
				     (long)(uintptr_t)old, sizeof(old), 0, 0, 0), 3);
	assert_memory_equal(old, "old", 3);

	/* Reusing the pathname creates a distinct live node. Closing the old,
	 * unlinked fd must not reclaim the replacement. */
	long newfd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD,
				 (long)(uintptr_t)path,
				 LXP_O_RDWR | LXP_O_CREAT | LXP_O_TRUNC, 0644, 0, 0);
	assert_true(newfd >= 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_write, newfd,
				     (long)(uintptr_t)"new", 3, 0, 0, 0), 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, oldfd, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_lseek, newfd, 0, LXP_SEEK_SET, 0, 0, 0), 0);
	char fresh[3];
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, newfd,
				     (long)(uintptr_t)fresh, sizeof(fresh), 0, 0, 0), 3);
	assert_memory_equal(fresh, "new", 3);
	assert_int_equal(lxp_syscall(&p, LXP_NR_close, newfd, 0, 0, 0, 0, 0), 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_unlink, (long)(uintptr_t)path,
				     0, 0, 0, 0, 0), 0);
}

/* Search a getdents64 buffer for an entry by name; returns its d_type or -1. */
static int dirents_find(const uint8_t *buf, long len, const char *name)
{
	long off = 0;
	while (off + 19 <= len) {
		uint16_t reclen;
		memcpy(&reclen, buf + off + 16, sizeof(reclen));
		if (reclen == 0)
			break;
		uint8_t type = buf[off + 18];
		if (strcmp((const char *)(buf + off + 19), name) == 0)
			return type;
		off += reclen;
	}
	return -1;
}

static void test_lnx_getdents(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);

	uint8_t dbuf[256];

	/* "/etc" lists one regular file: motd. */
	long fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/etc",
			      LXP_O_RDONLY, 0, 0, 0);
	assert_true(fd >= 3);
	long n = lxp_syscall(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, sizeof(dbuf), 0, 0,
			     0);
	assert_true(n > 0);
	assert_int_equal(dirents_find(dbuf, n, "motd"), LXP_DT_REG);
	/* A second call drains the directory (returns 0). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, sizeof(dbuf),
				     0, 0, 0),
			 0);
	/* read() on a directory is -EISDIR. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)dbuf, 4, 0, 0, 0),
			 -LXP_EISDIR);
	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* "/" lists the subdirectories etc and bin. */
	fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/", LXP_O_RDONLY, 0, 0,
			 0);
	n = lxp_syscall(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, sizeof(dbuf), 0, 0, 0);
	assert_int_equal(dirents_find(dbuf, n, "etc"), LXP_DT_DIR);
	assert_int_equal(dirents_find(dbuf, n, "bin"), LXP_DT_DIR);
	lxp_syscall(&p, LXP_NR_close, fd, 0, 0, 0, 0, 0);

	/* getdents64 on a regular file is -ENOTDIR. */
	fd = lxp_syscall(&p, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)"/etc/motd",
			 LXP_O_RDONLY, 0, 0, 0);
	assert_int_equal(lxp_syscall(&p, LXP_NR_getdents64, fd, (long)(uintptr_t)dbuf, sizeof(dbuf),
				     0, 0, 0),
			 -LXP_ENOTDIR);
}

static void test_lnx_execve(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);

	/* execve captures the request for the engine: which program + argv. */
	char *const argv[] = {"prog", "x", NULL};
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/sh",
				     (long)(uintptr_t)argv, 0, 0, 0, 0),
			 0);
	assert_int_equal(p.intent.kind, LXP_INTENT_EXEC);
	assert_string_equal(k_rootfs[p.exec_file_idx].path, "/bin/sh");
	assert_int_equal(p.exec_capture->argc, 2);
	assert_string_equal(EXEC_ARG(p, 0), "prog");
	assert_string_equal(EXEC_ARG(p, 1), "x");
	assert_int_equal(lxp_intent_complete(&p, LXP_INTENT_EXEC), 0);

	/* A script rewrites the bounded snapshot in place without revisiting guest argv. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/script",
				     (long)(uintptr_t)argv, 0, 0, 0, 0),
			 0);
	assert_int_equal(p.exec_capture->argc, 4);
	assert_string_equal(EXEC_ARG(p, 0), "/bin/sh");
	assert_string_equal(EXEC_ARG(p, 1), "-e");
	assert_string_equal(EXEC_ARG(p, 2), "/bin/script");
	assert_string_equal(EXEC_ARG(p, 3), "x");
	assert_int_equal(lxp_intent_complete(&p, LXP_INTENT_EXEC), 0);

	/* execve also captures the environment (a2 = envp) for the relaunch to re-emit. */
	char *const envp[] = {"PATH=/bin:/sbin", "TERM=vt100", NULL};
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/sh",
				     (long)(uintptr_t)argv, (long)(uintptr_t)envp, 0, 0, 0),
			 0);
	assert_int_equal(p.exec_capture->envc, 2);
	assert_string_equal(EXEC_ENV(p, 0), "PATH=/bin:/sbin");
	assert_string_equal(EXEC_ENV(p, 1), "TERM=vt100");
	assert_int_equal(lxp_intent_complete(&p, LXP_INTENT_EXEC), 0);

	/* A NULL envp captures an empty environment (the new image starts with none). */
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/bin/sh",
				     (long)(uintptr_t)argv, 0, 0, 0, 0),
			 0);
	assert_int_equal(p.exec_capture->envc, 0);
	assert_int_equal(lxp_intent_complete(&p, LXP_INTENT_EXEC), 0);

	/* A missing path is -ENOENT; exec'ing a directory is -EACCES. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/nope",
				     (long)(uintptr_t)argv, 0, 0, 0, 0),
			 -LXP_ENOENT);
	assert_int_equal(lxp_syscall(&p, LXP_NR_execve, (long)(uintptr_t)"/etc",
				     (long)(uintptr_t)argv, 0, 0, 0, 0),
			 -LXP_EACCES);
}

static void test_lnx_exit_and_unknown(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	assert_int_equal(p.intent.kind, LXP_INTENT_NONE);
	lxp_syscall(&p, LXP_NR_exit_group, 42, 0, 0, 0, 0, 0);
	assert_int_equal(p.intent.kind, LXP_INTENT_EXIT);
	assert_int_equal(p.exit_status, 42);

	/* Unimplemented syscalls report -ENOSYS rather than crashing. */
	assert_int_equal(lxp_syscall(&p, 999, 0, 0, 0, 0, 0, 0), -LXP_ENOSYS);
}

/* Emit one newc CPIO entry into buf at off; returns the new offset. */
static size_t cpio_emit(uint8_t *buf, size_t off, const char *name, uint32_t mode, const char *data,
			uint32_t fsize)
{
	uint32_t nsize = (uint32_t)strlen(name) + 1;
	uint32_t f[13] = {1, mode, 0, 0, 1, 0, fsize, 0, 0, 0, 0, nsize, 0};
	char tmp[9];
	memcpy(buf + off, "070701", 6);
	off += 6;
	for (int i = 0; i < 13; i++) {
		snprintf(tmp, sizeof(tmp), "%08x", f[i]);
		memcpy(buf + off, tmp, 8);
		off += 8;
	}
	memcpy(buf + off, name, nsize);
	off += nsize;
	while (off & 3u)
		buf[off++] = 0;
	if (fsize) {
		memcpy(buf + off, data, fsize);
		off += fsize;
		while (off & 3u)
			buf[off++] = 0;
	}
	return off;
}

static void test_lnx_cpio(void **state)
{
	(void)state;
	/* Hand-build a tiny newc CPIO: "/", "/etc", "/etc/motd". */
	static uint8_t cpio[512];
	size_t off = 0;
	off = cpio_emit(cpio, off, ".", LXP_S_IFDIR | 0755, NULL, 0);
	off = cpio_emit(cpio, off, "etc", LXP_S_IFDIR | 0755, NULL, 0);
	off = cpio_emit(cpio, off, "etc/motd", LXP_S_IFREG | 0644, "hi\n", 3);
	off = cpio_emit(cpio, off, "TRAILER!!!", 0, NULL, 0);

	static lxp_file_t tbl[8];
	static char nbuf[256];
	int n = lxp_cpio_to_rootfs(cpio, off, tbl, 8, nbuf, sizeof(nbuf));
	assert_int_equal(n, 3); /* TRAILER stops the parse */
	assert_string_equal(tbl[0].path, "/");
	assert_true((tbl[0].mode & LXP_S_IFMT) == LXP_S_IFDIR);
	assert_string_equal(tbl[2].path, "/etc/motd");
	assert_int_equal((int)tbl[2].size, 3);
	assert_memory_equal(tbl[2].data, "hi\n", 3);
	assert_true((tbl[2].mode & LXP_S_IFMT) == LXP_S_IFREG);

	/* The parsed table drives the VFS: open + read the file. */
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, tbl, n);
	long fd = lxp_syscall(&p, LXP_NR_open, (long)(uintptr_t)"/etc/motd", 0, 0, 0, 0, 0);
	assert_true(fd >= 0);
	char b[8] = {0};
	assert_int_equal(lxp_syscall(&p, LXP_NR_read, fd, (long)(uintptr_t)b, 8, 0, 0, 0), 3);
	assert_memory_equal(b, "hi\n", 3);
}

/* access_ok: good / out-of-range / boundary / overflow, against a bounded region. */
static void test_lnx_user_ok(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	/* Bound the proc to a concrete host buffer so access_ok has a real [lo,hi) to police. */
	static char rgn[4096] __attribute__((aligned(16)));
	uintptr_t lo = (uintptr_t)rgn, hi = lo + sizeof(rgn);
	p.mm->region_lo = lo;
	p.mm->region_hi = hi;
	p.mm->pool_lo = p.mm->pool_hi = 0;

	/* good: wholly inside, both read and write */
	assert_true(lxp_guest_access_ok(&p, rgn, sizeof(rgn), 0));
	assert_true(lxp_guest_access_ok(&p, rgn, sizeof(rgn), 1));
	assert_true(lxp_guest_access_ok(&p, rgn + 100, 1, 1));
	/* zero length dereferences nothing → always ok, even for a wild pointer */
	assert_true(lxp_guest_access_ok(&p, (void *)0x20000000u, 0, 1));
	/* NULL and out-of-region are rejected */
	assert_false(lxp_guest_access_ok(&p, NULL, 1, 0));
	assert_false(lxp_guest_access_ok(&p, (void *)(lo - 1), 1, 0));
	assert_false(lxp_guest_access_ok(&p, (void *)hi, 1, 1));
	assert_false(lxp_guest_access_ok(&p, (void *)(hi + 4096), 8, 1));
	assert_false(lxp_guest_access_ok(&p, (void *)0x20000000u, 64, 1)); /* a "kernel" pointer */
	/* boundary: the last byte is in range; a run ending one past hi is not */
	assert_true(lxp_guest_access_ok(&p, (void *)(hi - 1), 1, 1));
	assert_false(lxp_guest_access_ok(&p, (void *)(hi - 1), 2, 1));
	assert_true(lxp_guest_access_ok(&p, (void *)lo, hi - lo, 0));	 /* exactly fills the region */
	assert_false(lxp_guest_access_ok(&p, (void *)lo, (hi - lo) + 1, 0)); /* one byte past the end */
	/* overflow: ptr+len must not wrap the address space into a "valid" range */
	assert_false(lxp_guest_access_ok(&p, (void *)(UINTPTR_MAX - 8), 64, 0));
	assert_false(lxp_guest_access_ok(&p, (void *)(hi - 4), SIZE_MAX, 1));

	/* a separate dynamic-pool range is honoured too */
	static char pool[512] __attribute__((aligned(16)));
	p.mm->pool_lo = (uintptr_t)pool;
	p.mm->pool_hi = (uintptr_t)pool + sizeof(pool);
	assert_true(lxp_guest_access_ok(&p, pool, sizeof(pool), 1));
	assert_false(lxp_guest_access_ok(&p, pool, sizeof(pool) + 1, 1));
}

/* lxp_guest_strnlen: terminated / unterminated-runs-off-the-end / at-edge / max-bounded. */
static void test_lnx_user_strnlen(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	static char rgn[256] __attribute__((aligned(16)));
	uintptr_t lo = (uintptr_t)rgn, hi = lo + sizeof(rgn);
	p.mm->region_lo = lo;
	p.mm->region_hi = hi;
	p.mm->pool_lo = p.mm->pool_hi = 0;

	/* terminated inside the region → its length */
	memset(rgn, 'x', sizeof(rgn));
	memcpy(rgn + 10, "hello", 6); /* copies the trailing NUL too */
	assert_int_equal(lxp_guest_strnlen(&p, rgn + 10, 256), 5);

	/* a start pointer outside every range → EFAULT */
	assert_int_equal(lxp_guest_strnlen(&p, (const char *)0x20000000u, 256), -LXP_EFAULT);

	/* unterminated: no NUL before the region end → EFAULT (must not walk past hi) */
	memset(rgn, 'A', sizeof(rgn));
	assert_int_equal(lxp_guest_strnlen(&p, rgn, 256), -LXP_EFAULT);
	assert_int_equal(lxp_guest_strnlen(&p, rgn + 250, 256), -LXP_EFAULT);

	/* at-edge: the NUL is the very last byte of the region → still OK */
	memset(rgn, 'B', sizeof(rgn));
	rgn[255] = '\0';
	assert_int_equal(lxp_guest_strnlen(&p, rgn + 250, 256), 5); /* B B B B B \0 */

	/* bounded by max: no NUL within `max` (though one exists later) → EFAULT */
	memset(rgn, 'C', sizeof(rgn));
	rgn[100] = '\0';
	assert_int_equal(lxp_guest_strnlen(&p, rgn, 10), -LXP_EFAULT);
}

static void test_guest_view_rejects_stale_dispatch(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	uint8_t region[32] = {0};
	p.mm->region_lo = (uintptr_t)region;
	p.mm->region_hi = (uintptr_t)region + sizeof(region);
	p.mm->region = (lxp_region_ref_t){.index = 2, .generation = 11};
	uint32_t slot_generation = 7;
	lxp_slot_ref_t slot = {.index = 1, .generation = slot_generation};
	lxp_guest_view_t view;

	lxp_slot_ref_t stale_slot = {.index = slot.index, .generation = slot.generation - 1};
	assert_int_equal(lxp_guest_view_begin(&p, stale_slot, &slot_generation,
					      LXP_GUEST_READ_WRITE, &view),
			 -LXP_ESRCH);
	assert_null(p.guest_view);

	assert_int_equal(lxp_guest_view_begin(&p, slot, &slot_generation,
					      LXP_GUEST_READ_WRITE, &view),
			 LXP_OK);
	assert_true(lxp_guest_view_is_current(&view));
	assert_int_equal(lxp_guest_put_u32(&p, (uintptr_t)region, 0x12345678u), 0);
	uint32_t value = 0;
	assert_int_equal(lxp_guest_get_u32(&p, (uintptr_t)region, &value), 0);
	assert_int_equal(value, 0x12345678u);
	assert_int_equal(lxp_guest_view_begin(&p, slot, &slot_generation,
					      LXP_GUEST_READ_WRITE, &view),
			 -LXP_EINVAL);

	slot_generation++;
	assert_false(lxp_guest_view_is_current(&view));
	assert_int_equal(lxp_guest_get_u32(&p, (uintptr_t)region, &value), -LXP_EFAULT);
	slot_generation = slot.generation;
	p.mm->region.generation++;
	assert_false(lxp_guest_view_is_current(&view));
	assert_int_equal(lxp_guest_put_u32(&p, (uintptr_t)region, 0), -LXP_EFAULT);

	lxp_guest_view_end(&view);
	lxp_guest_view_end(&view); /* idempotent revocation */
	assert_null(p.guest_view);

	assert_int_equal(lxp_guest_view_begin(&p, slot, &slot_generation, LXP_GUEST_WRITE, &view),
			 LXP_OK);
	assert_int_equal(lxp_guest_strnlen(&p, (const char *)region, sizeof(region)),
			 -LXP_EFAULT);
	lxp_guest_view_end(&view);
}

/* rt_sigprocmask maintains a real per-proc blocked mask: block/unblock/setmask, the old
 * mask reported through oldset, and SIGKILL/SIGSTOP that can never be blocked. */
static void test_lnx_sigprocmask(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	/* Block SIGTERM (15) + SIGINT (2); the previous mask was empty. */
	uint32_t set[2] = {(1u << (15 - 1)) | (1u << (2 - 1)), 0};
	uint32_t old[2] = {0xdead, 0xbeef};
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, LXP_SIG_BLOCK, (long)(uintptr_t)set,
				     (long)(uintptr_t)old, 8, 0, 0),
			 0);
	assert_int_equal(old[0], 0);
	assert_int_equal(old[1], 0);
	assert_true(lxp_sig_blocked(&p, LXP_SIGTERM));
	assert_true(lxp_sig_blocked(&p, LXP_SIGINT));
	assert_false(lxp_sig_blocked(&p, LXP_SIGCHLD));

	/* A NULL set just reports the current mask through oldset. */
	memset(old, 0, sizeof(old));
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, LXP_SIG_SETMASK, 0,
				     (long)(uintptr_t)old, 8, 0, 0),
			 0);
	assert_int_equal(old[0], (1u << (15 - 1)) | (1u << (2 - 1)));

	/* Unblock SIGINT only. */
	uint32_t clr[2] = {(1u << (2 - 1)), 0};
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, LXP_SIG_UNBLOCK,
				     (long)(uintptr_t)clr, 0, 8, 0, 0),
			 0);
	assert_true(lxp_sig_blocked(&p, LXP_SIGTERM));
	assert_false(lxp_sig_blocked(&p, LXP_SIGINT));

	/* SIG_SETMASK to "block everything" still cannot block SIGKILL/SIGSTOP. */
	uint32_t all[2] = {0xffffffffu, 0xffffffffu};
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, LXP_SIG_SETMASK,
				     (long)(uintptr_t)all, 0, 8, 0, 0),
			 0);
	assert_false(lxp_sig_blocked(&p, LXP_SIGKILL));
	assert_false(lxp_sig_blocked(&p, LXP_SIGSTOP));
	assert_true(lxp_sig_blocked(&p, LXP_SIGTERM));

	/* set and oldset may alias — the legal sigprocmask(SIG_SETMASK, &m, &m) swap. The new
	 * mask must be read before the old is written into the shared buffer. */
	uint32_t m[2] = {(1u << (15 - 1)), 0}; /* start blocked on SIGTERM */
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, LXP_SIG_SETMASK, (long)(uintptr_t)m,
				     0, 8, 0, 0),
			 0);
	m[0] = (1u << (2 - 1)); /* swap to SIGINT, with oldset aliasing set */
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, LXP_SIG_SETMASK, (long)(uintptr_t)m,
				     (long)(uintptr_t)m, 8, 0, 0),
			 0);
	assert_true(lxp_sig_blocked(&p, LXP_SIGINT)); /* the new mask took effect (not clobbered) */
	assert_false(lxp_sig_blocked(&p, LXP_SIGTERM)); /* replaced, not merged */
	assert_int_equal(m[0], (1u << (15 - 1)));	/* oldset reports the prior {SIGTERM} */

	/* Bad `how` and an oversized sigsetsize are both -EINVAL. */
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, 99, (long)(uintptr_t)all, 0, 8, 0,
				     0),
			 -LXP_EINVAL);
	assert_int_equal(lxp_syscall(&p, LXP_NR_rt_sigprocmask, LXP_SIG_SETMASK, 0, 0, 16, 0, 0),
			 -LXP_EINVAL);
}

/* prlimit64 must report the TRUTH for RLIMIT_NOFILE (the fd table is LXP_MAX_FDS), not the old
 * blanket 1024 that turned into a surprise EMFILE at the 32nd open. */
static void test_lnx_prlimit_nofile(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);

	uint64_t lim[2] = {0, 0};
	/* getrlimit(RLIMIT_NOFILE) == prlimit64(pid=0, resource=7, new=NULL, old=&lim) */
	assert_int_equal(lxp_syscall(&p, LXP_NR_prlimit64, 0, 7, 0, (long)(uintptr_t)lim, 0, 0), 0);
	assert_int_equal((int)lim[0], LXP_MAX_FDS); /* rlim_cur */
	assert_int_equal((int)lim[1], LXP_MAX_FDS); /* rlim_max */

	/* A non-NOFILE resource keeps the finite (never RLIM_INFINITY) default. */
	lim[0] = lim[1] = 0;
	assert_int_equal(lxp_syscall(&p, LXP_NR_prlimit64, 0, 3 /*RLIMIT_STACK*/, 0,
				     (long)(uintptr_t)lim, 0, 0),
			 0);
	assert_int_equal((int)lim[0], 1024);
}

/* readlink("/proc/self/exe") returns the running program's path (exec_file_idx), not ENOENT. */
static void test_lnx_readlink_self_exe(void **state)
{
	(void)state;
	lxp_arena_t arena;
	lxp_proc_t p;
	setup_proc(&p, &arena);
	lxp_proc_set_rootfs(&p, k_rootfs, K_ROOTFS_N);
	p.exec_file_idx = 4; /* k_rootfs[4] = "/bin/sh" */

	char buf[64];
	long n = lxp_syscall(&p, LXP_NR_readlink, (long)(uintptr_t)"/proc/self/exe",
			     (long)(uintptr_t)buf, sizeof(buf), 0, 0, 0);
	assert_true(n > 0);
	assert_int_equal((int)n, (int)strlen("/bin/sh"));
	buf[n] = '\0';
	assert_string_equal(buf, "/bin/sh");
}

/* wait4 reports a job-control STOPPED child only when WUNTRACED is set, and leaves the
 * child alive (only the notice is consumed) — how the shell learns a job was Ctrl+Z'd. */
static void test_lnx_wait4_wuntraced_stopped(void **state)
{
	(void)state;
	lxp_proc_t p;
	lxp_arena_t arena;
	setup_proc(&p, &arena);
	/* One live child with a queued STOPPED notification (status = the stop signal). */
	p.group->live_children = 1;
	p.group->child_pid[0] = 7;
	p.group->child_status[0] = LXP_SIGTSTP;
	p.group->child_kind[0] = LXP_CHILD_STOPPED;
	p.group->child_count = 1;

	/* Without WUNTRACED the stop is not reported; the child is still live, so wait4 blocks
	 * (returns 0 with a CHILD wait) and the notice stays queued. */
	int status = -1;
	long r = lxp_syscall(&p, LXP_NR_wait4, -1, (long)(uintptr_t)&status, 0, 0, 0, 0);
	assert_int_equal(r, 0);
	assert_int_equal(p.wait.kind, LXP_WAIT_CHILD);
	assert_int_equal(p.group->child_count, 1);

	/* With WUNTRACED it is reported as WIFSTOPPED(SIGTSTP); the child stays alive. */
	(void)lxp_wait_cancel(&p);
	status = -1;
	r = lxp_syscall(&p, LXP_NR_wait4, -1, (long)(uintptr_t)&status, LXP_WUNTRACED, 0, 0, 0);
	assert_int_equal(r, 7);
	assert_int_equal(status, ((LXP_SIGTSTP & 0xff) << 8) | 0x7f); /* WIFSTOPPED */
	assert_int_equal(p.group->child_count, 0);		      /* notice consumed */
	assert_int_equal(p.group->live_children, 1);		      /* child is still alive */
}

int test_linux_syscall_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_lnx_wait4_wuntraced_stopped),
		cmocka_unit_test(test_lnx_prlimit_nofile),
		cmocka_unit_test(test_lnx_readlink_self_exe),
		cmocka_unit_test(test_lnx_sigprocmask),
		cmocka_unit_test(test_lnx_write),
		cmocka_unit_test(test_lnx_niceness),
		cmocka_unit_test(test_lnx_fast_syscalls),
		cmocka_unit_test(test_lnx_writev),
		cmocka_unit_test(test_lnx_brk),
		cmocka_unit_test(test_lnx_mmap),
		cmocka_unit_test(test_lnx_init_stubs),
		cmocka_unit_test(test_lnx_console_termios_roundtrip),
		cmocka_unit_test(test_lnx_setup_stack),
		cmocka_unit_test(test_lnx_file),
		cmocka_unit_test(test_dup_and_fork_share_file_offset),
		cmocka_unit_test(test_clone_resource_sharing_flags),
		cmocka_unit_test(test_eventfd_alias_survives_peer_close),
		cmocka_unit_test(test_maximum_descriptor_aliases_keep_last_reference_live),
		cmocka_unit_test(test_lnx_exec_script_symlink_interp),
		cmocka_unit_test(test_lnx_exec_capture_is_per_proc),
		cmocka_unit_test(test_lnx_fcntl_getfl_access_mode),
		cmocka_unit_test(test_lnx_tmpfs),
		cmocka_unit_test(test_lnx_tmpfs_unlink_open),
		cmocka_unit_test(test_lnx_getdents),
		cmocka_unit_test(test_lnx_execve),
		cmocka_unit_test(test_lnx_exit_and_unknown),
		cmocka_unit_test(test_lnx_cpio),
		cmocka_unit_test(test_lnx_user_ok),
		cmocka_unit_test(test_lnx_user_strnlen),
		cmocka_unit_test(test_guest_view_rejects_stale_dispatch),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
