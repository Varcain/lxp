/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Fuzz target: the syscall dispatcher, lxp_syscall(proc, nr, a0..a5). The system under
 * test is the user-pointer gate (user_ok / user_strnlen, src/lxp_syscall.c): every guest
 * pointer a syscall dereferences must be bounded to the proc's region. So the guest
 * region is a real ASan-instrumented buffer, region_lo/hi are set to exactly it (as the
 * run loop does on-target), and each argument is fuzzed as EITHER a small immediate
 * (fd / whence / flags / size) OR a pointer INTO the guest buffer — a syscall that
 * derefs past a user_ok it skipped (or miscomputes an offset) reads/writes past g_guest
 * and aborts.
 *
 * CAVEATS (documented in fuzz/README.md): this exercises a 32-bit-target ABI as 64-bit
 * host code, so pointer-width-sensitive paths differ from production. The nr set is an
 * allow-list of non-terminating, non-blocking, per-proc-deterministic syscalls
 * (no exit/exec/clone/fork/kill/signal/futex/poll/nanosleep, and no pipe/eventfd whose
 * global pools would carry state across inputs); a fresh proc is built per input.
 */
#include "fuzz_common.h"

#include "lxp/lxp_arena.h"
#include "lxp/lxp_syscall.h"

#include <stdint.h>
#include <string.h>

#define GUEST_SZ 65536u

static uint8_t g_guest[GUEST_SZ] __attribute__((aligned(16)));
static uint8_t g_pool[128 * 1024] __attribute__((aligned(16)));

/* Non-terminating, non-blocking, per-proc-deterministic syscalls whose user-pointer
 * handling is worth stressing. */
static const long k_nr[] = {
	LXP_NR_read,	  LXP_NR_write,	    LXP_NR_writev,    LXP_NR_lseek,    LXP_NR__llseek,
	LXP_NR_close,	  LXP_NR_fstat64,   LXP_NR_stat64,    LXP_NR_lstat64,
	LXP_NR_fstatat64, LXP_NR_statx,	    LXP_NR_getdents64, LXP_NR_ioctl,   LXP_NR_fcntl64,
	LXP_NR_dup,	  LXP_NR_dup2,	    LXP_NR_dup3,      LXP_NR_access,   LXP_NR_faccessat,
	LXP_NR_readlink,  LXP_NR_readlinkat, LXP_NR_getcwd,   LXP_NR_pread64,  LXP_NR_pwrite64,
	LXP_NR_brk,	  LXP_NR_mmap2,	    LXP_NR_munmap,    LXP_NR_mprotect, LXP_NR_uname,
	LXP_NR_sysinfo,	  LXP_NR_times,	    LXP_NR_gettimeofday, LXP_NR_clock_gettime,
};

/* Each argument is either a small signed immediate (fds/whence/flags/small sizes) or a
 * pointer into the front half of the guest region (leaving room for the syscall's length,
 * which user_ok bounds against region_hi). */
static long mkarg(fuzz_cursor_t *c)
{
	uint8_t sel = fuzz_u8(c);
	uint32_t raw = fuzz_u32(c);
	if (sel & 1)
		return (long)(uintptr_t)(g_guest + (raw % (GUEST_SZ / 2)));
	return (long)(int32_t)(int16_t)raw;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_cursor_t c = {data, size};
	uint8_t nsel = fuzz_u8(&c);
	long a[6];
	for (int i = 0; i < 6; i++)
		a[i] = mkarg(&c);

	/* seed the guest region with the remaining bytes so pointer args reference fuzzer data
	 * (iovecs, paths, ioctl/stat structs, …) rather than zeros */
	memset(g_guest, 0, GUEST_SZ);
	size_t gn = c.n < GUEST_SZ ? c.n : GUEST_SZ;
	if (gn)
		memcpy(g_guest, c.p, gn);

	lxp_arena_t arena;
	lxp_proc_t p;
	if (lxp_arena_init(&arena, g_pool, sizeof(g_pool)) != LXP_OK)
		return 0;
	if (lxp_proc_init(&p, &arena, 4096) != LXP_OK)
		return 0;
	/* guest region = g_guest exactly, so user_ok bounds every deref to it, as on-target */
	p.region_lo = (uintptr_t)g_guest;
	p.region_hi = (uintptr_t)g_guest + GUEST_SZ;
	p.pool_lo = p.pool_hi = 0;

	long nr = k_nr[nsel % (sizeof(k_nr) / sizeof(k_nr[0]))];
	(void)lxp_syscall(&p, nr, a[0], a[1], a[2], a[3], a[4], a[5]);
	return 0;
}
