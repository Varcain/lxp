/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Cross-TU private internals of the syscall core: user-pointer validation and
 * rootfs helpers shared by subsystem TUs and the dispatcher. Defined in
 * src/lxp_syscall.c; not part of the public include/ API.
 */
#ifndef LXP_INTERNAL_H
#define LXP_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "lxp_guest.h"
#include "lxp/lxp_program.h"

struct lxp_mem_stats;

/* The stat mode (S_IF* | perms) of a rootfs file entry. */
uint32_t file_mode(const lxp_file_t *f);

/* Fill guest memory from the host entropy provider (getrandom, /dev/urandom):
 * @p count, or a negated errno (-@p unavailable_errno without a provider). */
long lxp_random_fill_guest(void *buf, size_t count, int unavailable_errno);

/* The console tty's foreground process group (job control). Set from tcsetpgrp
 * (TIOCSPGRP) on a console fd; read by TIOCGPGRP and the coordinator's console ^C
 * delivery. Coordinator-owned (defined in lxp_run.c), like the tty ISIG state. */
void lxp_console_set_fg_pgrp(int pgrp);
int lxp_console_fg_pgrp(void);
/* Whether the console tty has ISIG set (tracked from TCSETS): ^C/^Z raise
 * SIGINT/SIGTSTP instead of being delivered as bytes. */
int lxp_tty_isig(void);
/* Latch @p sig on every live member of @p pgid and wake the coordinator.
 * The process table remains owned by the run core; tty subsystems use this
 * narrow operation instead of enumerating tasks. Returns recipients signalled. */
int lxp_signal_process_group(int pgid, int sig);

/* Apply the console tty's currently tracked input-character translations.
 * lxp_console_read() applies it to every console byte it returns. */
uint8_t lxp_console_input_xlate(uint8_t ch);

/* Console input discipline. The coordinator's ^C/^Z check reads input while no
 * guest is reading the console; ordinary bytes it reads are kept as typeahead and
 * delivered, in order, before any further transport input. */
struct lxp_run_config;
/* Whether a console read would return data now (typeahead or transport input). */
int lxp_console_input_ready(const lxp_proc_t *proc);
/* Read console input for @p proc: typeahead first, then the transport's read_fn,
 * with the tracked input translation applied to a single-byte result. */
long lxp_console_read(lxp_proc_t *proc, int fd, void *buf, size_t len);
/* With ISIG on, read one pending byte: ^C/^Z signal the foreground group, anything
 * else is queued as typeahead. Does not read while the queue is full. Returns
 * nonzero when a signal was raised. */
int lxp_console_poll_interrupts(const struct lxp_run_config *cfg);
/* Discard queued typeahead (run start). */
void lxp_console_typeahead_reset(void);

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
	unsigned processes;
	unsigned regions_total;
	unsigned regions_free;
};
void lxp_get_resource_stats(struct lxp_resource_stats *out);

/* Host-supplied utsname.version identity, or the honest module fallback "lxp". */
const char *lxp_system_version(void);

/* Format the active run's optional host real-time snapshot. */
long lxp_rt_scope_read(char *buf, size_t cap);

/* reboot(2)/poweroff requests are private core state, not part of the RTOS seam. */
void lxp_request_halt(void);
void lxp_reset_halt_request(void);
int lxp_halt_requested(void);

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
