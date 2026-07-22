/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Cross-TU private internals of the syscall core: user-pointer validation + a couple
 * of rootfs helpers the extracted subsystem TUs (fs/proc/...) share with the
 * dispatcher. Defined in src/lxp_syscall.c; NOT part of the public include/ API.
 */
#ifndef LXP_INTERNAL_H
#define LXP_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_syscall.h" /* lxp_proc_t, lxp_file_t */

/* True iff [ptr, ptr+len) is wholly readable (write==0) or writable (write==1) by
 * program `p` — the access_ok guard every user-pointer deref must pass first. */
int user_ok(const lxp_proc_t *p, const void *ptr, size_t len, int write);

/* strlen of a user string, or -EFAULT if not NUL-terminated within a valid readable
 * range (bounded by `max`). */
long user_strnlen(const lxp_proc_t *p, const char *s, size_t max);

/* The stat mode (S_IF* | perms) of a rootfs file entry. */
uint32_t file_mode(const lxp_file_t *f);

/* The console tty's foreground process group (job control). Set from tcsetpgrp
 * (TIOCSPGRP) on a console fd; read by TIOCGPGRP and the coordinator's console ^C
 * delivery. Coordinator-owned (defined in lxp_run.c), like the tty ISIG state. */
void lxp_console_set_fg_pgrp(int pgrp);
int lxp_console_fg_pgrp(void);

/* Apply the console tty's currently tracked input-character translations.  Both
 * immediate reads in lxp_syscall.c and coordinator-resumed reads must pass bytes
 * through the same discipline. */
uint8_t lxp_console_input_xlate(uint8_t ch);

/* Snapshot the host allocator through lxp_os_ops.mem_stats.  On failure `out`
 * is zeroed, so procfs/sysinfo never fall back to fabricated memory totals. */
int lxp_mem_stats(struct lxp_mem_stats *out);

/* Capacity of the personality's fixed process slots and program regions. The
 * byte view is what sysinfo/free consume; the count view is exported explicitly
 * through procfs because Linux memory tools cannot label values as slots. */
struct lxp_resource_stats {
	size_t program_region_bytes;
	size_t dynamic_pool_bytes;
	uint64_t total_bytes;
	uint64_t free_bytes;
	uint64_t available_bytes;
	unsigned slots_total;
	unsigned slots_free;
	unsigned regions_total;
	unsigned regions_free;
};
void lxp_get_resource_stats(struct lxp_resource_stats *out);

/* Host-supplied utsname.version identity, or the honest module fallback "lxp". */
const char *lxp_system_version(void);

/* Encode a child's exit code (our convention: 128 + signal for a signal-killed child) as
 * a Linux wait(2) status word: WIFSIGNALED with the signal in the low 7 bits for 129..159,
 * else WIFEXITED with the code in bits 8-15. Shared by sys_wait4 + the coordinator's
 * reap_to_parent (1..31 covers every signal the personality delivers). */
static inline int lxp_encode_wstatus(int code)
{
	return (code > 128 && code <= 128 + 31) ? (code - 128) : ((code & 0xff) << 8);
}

/* Encode a WIFSTOPPED wait status for a job-control stop: the stop signal in bits 8-15
 * with 0x7f in the low byte (Linux WIFSTOPPED(s) == (s & 0xff) == 0x7f). */
static inline int lxp_encode_wstopped(int stopsig)
{
	return ((stopsig & 0xff) << 8) | 0x7f;
}

#endif /* LXP_INTERNAL_H */
