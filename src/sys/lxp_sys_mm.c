/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Memory syscalls on the NOMMU process: the program break, anonymous and file
 * mappings in the process arena, and the protection no-op.
 */
#include "sys/lxp_sys.h"
#include "fs/lxp_vfs.h"
#include "lxp_arena.h"
#include "lxp_linux_uapi.h"
#include <string.h>

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
	if (!p || !p->mm)
		return 0;
	if (addr >= p->mm->brk_base && addr <= p->mm->brk_max)
		p->mm->brk_cur = addr;
	return (long)p->mm->brk_cur;
}

/*
 * mmap: a kind with an mmap file operation maps its object directly (the rootfs
 * read-only in place, a device its own buffer). Everything else — anonymous maps
 * (uClibc's malloc), and file maps a kind cannot share (ld.so's writable .so
 * segments) — is a private copy in the process arena, filled from the file.
 */
static long sys_mmap2(lxp_proc_t *p, uintptr_t addr, size_t len, int prot, int flags, int fd,
		      uint32_t pgoff)
{
	(void)addr;
	if (!p || !p->mm || !p->mm->arena || len == 0)
		return -LXP_EINVAL;

	int file = !(flags & LXP_MAP_ANONYMOUS) && fd >= 0;
	if (file) {
		lxp_ofd_t *s = lxp_fd_description(p, fd);
		if (!s)
			return -LXP_EBADF;
		/* A file map reads the file; a shared writable one would also write it. */
		if (!lxp_vfs_readable(s) ||
		    ((flags & LXP_MAP_SHARED) && (prot & LXP_PROT_WRITE) && !lxp_vfs_writable(s)))
			return -LXP_EACCES;
		const lxp_file_ops_t *ops = lxp_vfs_ops(s);
		if (ops && ops->mmap) {
			long r = ops->mmap(p, s, len, prot, pgoff);
			if (r != -LXP_ENODEV)
				return r;
		}
	}

	void *m = lxp_arena_alloc_tracked(p->mm->arena, len);
	if (!m)
		return -LXP_ENOMEM;
	memset(m, 0, len); /* anon reads as zero; also zero-fills a file map's bss tail */
	if (file) {
		/* On NOMMU ld.so loads a .so's read-only segment (the symtab/hash/text) this
		 * way: read the file's bytes at the page offset into the new block. */
		long r = lxp_sys_fd_pread(p, fd, m, len, pgoff * 4096u);
		if (r < 0) {
			(void)lxp_arena_free_tracked(p->mm->arena, m, len);
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
	if (!p || !p->mm || !p->mm->arena || len == 0)
		return -LXP_EINVAL;
	if (!lxp_arena_owns(p->mm->arena, (void *)addr))
		return 0;
	return lxp_arena_free_tracked(p->mm->arena, (void *)addr, len) ? 0 : -LXP_EINVAL;
}

long lxp_sys_brk(lxp_proc_t *proc, const long a[6])
{
	return sys_brk(proc, (uintptr_t)a[0]);
}

long lxp_sys_mmap2(lxp_proc_t *proc, const long a[6])
{
	return sys_mmap2(proc, (uintptr_t)a[0], (size_t)a[1], (int)a[2], (int)a[3], (int)a[4],
			 (uint32_t)a[5]);
}

long lxp_sys_munmap(lxp_proc_t *proc, const long a[6])
{
	return sys_munmap(proc, (uintptr_t)a[0], (size_t)a[1]);
}

/* NOMMU: RELRO/protection is a no-op */
long lxp_sys_mprotect(lxp_proc_t *proc, const long a[6])
{
	(void)proc;
	return sys_mprotect((uintptr_t)a[0], (size_t)a[1], (int)a[2]);
}
