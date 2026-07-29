/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private image-construction transaction shared by initial launch and exec.
 */

#include <string.h>

#include "lxp/lxp_bootstrap.h"
#include "lxp/lxp_loader.h"
#include "run/lxp_coordinator.h"
#include "run/lxp_image.h"

/*
 * An image is built off-slot. The transaction owns the region lease and every
 * freshly allocated process object until publish transfers them to the slot.
 * This keeps a partially loaded image invisible and gives both initial launch
 * and exec one idempotent cleanup path.
 */
void image_txn_init(struct image_txn *tx, int slot, lxp_region_ref_t region, lxp_slot_ref_t owner)
{
	memset(tx, 0, sizeof(*tx));
	tx->slot = slot;
	tx->region = region;
	tx->owner = owner;
	tx->proc.snapshot = lxp_region_ref_none();
	tx->proc.vfork_parent = lxp_slot_ref_none();
}

/* Load an FDPIC ELF and construct its process objects without publishing the
 * slot or starting a native task. @p remote_exec means executable text is
 * copied from a RAM staging buffer into the region. */
int image_txn_prepare(struct image_txn *tx, const lxp_os_ops_t *eng, const lxp_run_config_t *cfg,
		      const uint8_t *data, size_t len, int pid, int ppid, int argc,
		      const char *const argv[], const char *const envp[], int remote_exec)
{
	int slot = tx->slot;
	int region_index = tx->region.index;
	if (!cfg || slot < 0 || slot >= LXP_NSLOT || region_index < 0 || region_index >= LXP_NREG ||
	    tx->region.generation == 0 || !lxp_region_lease_matches(tx->region, tx->owner, 1))
		return -LXP_EINVAL;
	uint8_t *region = eng->region(region_index);
	/* Every personality program is an FDPIC ELF. */
	if (!(len >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'))
		return -LXP_ENOEXEC;
	/* The coordinator reads the image through the engine's bounded rootfs
	 * window; preemption does not change the mapping's memory attributes. */
	int lrc = lxp_loader_load_fdpic(&tx->prog, data, len, region, LXP_PROG_REGION_SIZE, 0,
					remote_exec);
	if (lrc != LXP_OK)
		return -LXP_ENOEXEC;

	/* Dynamic FDPIC enters the interpreter with both loadmaps published in the
	 * architecture-defined startup registers. */
	uintptr_t pc = tx->prog.entry;
	uintptr_t at_entry = tx->prog.entry;
	uintptr_t at_base = 0;
	tx->prog.interp_loadmap = 0;
	int dynamic = tx->prog.is_fdpic && tx->prog.is_dynamic;
	if (dynamic) {
		const uint8_t *ld_data = NULL;
		size_t ld_len = 0;
		if (lxp_rootfs_resolve(cfg->rootfs, cfg->rootfs_count, "/lib/ld-uClibc.so.0",
				       &ld_data, &ld_len) != 0 ||
		    !ld_data)
			return -LXP_ENOEXEC;
		uintptr_t ld_base = (uintptr_t)region + ((tx->prog.region_used + 15u) & ~15u);
		lxp_flat_t ld;
		int ldrc = lxp_loader_load_fdpic(
			&ld, ld_data, ld_len, (void *)ld_base,
			LXP_PROG_REGION_SIZE - (size_t)(ld_base - (uintptr_t)region), 1, 0);
		if (ldrc != LXP_OK)
			return -LXP_ENOEXEC;
		pc = ld.entry;
		/* Text is XIP from rootfs, so AT_BASE names its ELF header rather than
		 * the region holding only the interpreter's writable block. */
		at_base = ld.text_base;
		tx->prog.interp_loadmap = ld.loadmap;
		/* uClibc FDPIC startup expects the interpreter's dynamic table in r9. */
		tx->prog.got = ld.dynamic;
		tx->prog.region_used = (size_t)(ld_base - (uintptr_t)region) + ld.region_used;
	}

	uint8_t *rw = region + ((tx->prog.region_used + 15u) & ~15u);
	uint8_t *rw_end = region + LXP_PROG_REGION_SIZE;
	uint8_t *arena_mem = rw;
	size_t arena_size = LXP_PROG_ARENA_SIZE;
	uint8_t *stack_lo = rw + LXP_PROG_ARENA_SIZE;
	if (dynamic) {
		if (!eng->dyn_pool)
			return -LXP_ENOMEM;
		arena_mem = eng->dyn_pool(region_index, &arena_size);
		stack_lo = rw;
	}
	lxp_arena_t *arena = lxp_region_arena(region_index);
	if (!arena || lxp_arena_init(arena, arena_mem, arena_size) != LXP_OK ||
	    lxp_proc_init(&tx->proc, arena, 0x8000) != LXP_OK)
		return -LXP_ENOMEM;
	tx->proc.write_fn = cfg->write_fn;
	tx->proc.read_fn = cfg->read_fn;
	tx->proc.console_poll = cfg->console_poll;
	tx->proc.io_ctx = cfg->io_ctx;
	tx->proc.pid = pid;
	tx->proc.group->tgid = pid;
	tx->proc.group->ppid = ppid;
	tx->proc.group->pgid = pid;
	tx->proc.alive = 1;
	tx->proc.mm->region = tx->region;
	tx->proc.mm->region_lo = (uintptr_t)region;
	tx->proc.mm->region_hi = (uintptr_t)region + LXP_PROG_REGION_SIZE;
	tx->proc.mm->pool_lo = (uintptr_t)arena_mem;
	tx->proc.mm->pool_hi = (uintptr_t)arena_mem + arena_size;
	tx->proc.is_fdpic = tx->prog.is_fdpic;
	tx->proc.mm->is_dynamic = dynamic;
	tx->proc.mm->copied_text_executable = (uint8_t)(tx->prog.region_exec != 0);
	tx->proc.stack_lo = (uintptr_t)stack_lo;
	tx->proc.snapshot = lxp_region_ref_none();
	tx->proc.vfork_parent = lxp_slot_ref_none();

	/* comm is argv[0]'s basename, without a login-shell leading dash. */
	const char *arg0 = (argc > 0 && argv && argv[0]) ? argv[0] : "?";
	if (arg0[0] == '-')
		arg0++;
	const char *base = arg0;
	for (const char *scan = arg0; *scan; scan++)
		if (*scan == '/')
			base = scan + 1;
	size_t comm_len = strlen(base);
	if (comm_len >= sizeof(tx->proc.comm))
		comm_len = sizeof(tx->proc.comm) - 1;
	memcpy(tx->proc.comm, base, comm_len);
	tx->proc.comm[comm_len] = '\0';

	lxp_proc_set_rootfs(&tx->proc, cfg->rootfs, cfg->rootfs_count);
	void *sp = lxp_setup_stack(stack_lo, (size_t)(rw_end - stack_lo), argc, argv, envp,
				   tx->prog.is_fdpic, tx->prog.phdr, tx->prog.phnum, at_entry,
				   at_base);
	if (!sp)
		return -LXP_ENOMEM;
	tx->debug.text_base = tx->prog.text_base;
	tx->debug.data_base = tx->prog.data_base;
	tx->debug.entry = at_entry;
	tx->debug.dynamic = tx->prog.dynamic;
	tx->debug.interp_base = at_base;
	tx->launch.r[0] = 0; /* static fini = NULL (uClinux entry convention) */
	tx->launch.r[7] = (uint32_t)tx->prog.loadmap;
	tx->launch.r[8] = (uint32_t)tx->prog.interp_loadmap;
	tx->launch.r[9] = (uint32_t)tx->prog.got;
	tx->launch.r[13] = (uint32_t)(uintptr_t)sp;
	tx->launch.r[15] = (uint32_t)pc;
	tx->launch.xpsr = 1u << 24; /* Cortex-M Thumb state */
	if (tx->prog.region_exec) {
		tx->launch.copied_text_base = tx->prog.text_base;
		tx->launch.copied_text_size = tx->prog.text_size;
	}
	tx->prepared = 1;
	return LXP_OK;
}

int image_txn_publish(struct image_txn *tx, const lxp_os_ops_t *eng)
{
	if (!tx->prepared || tx->published)
		return -LXP_EINVAL;
	const uintptr_t text_base = tx->launch.copied_text_base;
	const size_t text_size = tx->launch.copied_text_size;
	const int copied_text = text_size != 0;
	if (!tx->proc.mm ||
	    tx->proc.mm->copied_text_executable != (uint8_t)copied_text ||
	    (!copied_text && text_base != 0) ||
	    !lxp_region_lease_matches(tx->region, tx->owner, 1))
		return -LXP_EINVAL;
	if (copied_text && !tx->executable_published) {
		uint8_t *region = eng->region(tx->region.index);
		uintptr_t region_lo = (uintptr_t)region;
		uintptr_t region_hi = region_lo + LXP_PROG_REGION_SIZE;
		if (!region || region_hi < region_lo || text_base < region_lo ||
		    text_base >= region_hi || text_size > region_hi - text_base)
			return -LXP_EINVAL;
		int rc = eng->publish_executable(tx->region, text_base, text_size);
		if (rc != LXP_OK)
			return rc;
	}
	tx->executable_published = 1;
	int rc = lxp_slot_publish_image(tx->slot, &tx->proc, eng->exec_capture(tx->slot),
					&tx->debug);
	if (rc != LXP_OK)
		return rc;
	if (eng->map_device)
		(void)eng->map_device(tx->slot, 0, 0, 0);
	tx->published = 1;
	return lifecycle_failpoint(LXP_FAIL_EXEC_PUBLISHED) ? -LXP_EIO : LXP_OK;
}

int image_txn_start(struct image_txn *tx, const lxp_os_ops_t *eng)
{
	if (!tx->published)
		return -LXP_EINVAL;
	int rc = coordinator_launch_slot(eng, tx->slot, tx->region.index, &tx->launch);
	if (rc != LXP_OK)
		return rc;
	tx->native_started = 1;
	if (lifecycle_failpoint(LXP_FAIL_EXEC_NATIVE_STARTED))
		return -LXP_EIO;
	if (lxp_region_commit_address_space(tx->region, tx->owner) != LXP_OK)
		return -LXP_EIO;
	tx->region_committed = 1;
	return lifecycle_failpoint(LXP_FAIL_EXEC_REGION_COMMITTED) ? -LXP_EIO : LXP_OK;
}

int image_txn_abort(struct image_txn *tx, const lxp_os_ops_t *eng)
{
	lxp_proc_t *proc = &tx->proc;
	if (tx->published) {
		proc = lxp_slot_proc(tx->slot);
		if (proc->alive && coordinator_abort_slot(eng, tx->slot) != LXP_OK)
			return -LXP_EAGAIN;
	}

	lxp_proc_resources_put(proc);
	if (proc->mm) {
		if (lxp_region_ref_equal(proc->mm->region, tx->region))
			proc_mm_put(proc);
		else
			lxp_proc_mm_put(proc);
	}
	lxp_proc_group_put(proc);
	proc->alive = 0;
	if (tx->published) {
		lxp_slot_proc_reset(tx->slot);
		slot_runnable_store(tx->slot, 0);
		primary_slot_clear(tx->slot);
		lxp_slot_signal_reset(tx->slot);
	}
	if (lxp_region_lease_matches(tx->region, tx->owner, 1))
		(void)region_release_if_owned(tx->region, tx->owner);
	tx->prepared = 0;
	tx->executable_published = 0;
	tx->published = 0;
	tx->native_started = 0;
	tx->region_committed = 0;
	return LXP_OK;
}

int lxp_image_launch(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg, int slot,
		     lxp_region_ref_t region, lxp_slot_ref_t owner, const uint8_t *data, size_t len,
		     int pid, int ppid, int argc, const char *const argv[],
		     const char *const envp[], int remote_exec)
{
	struct image_txn tx;
	image_txn_init(&tx, slot, region, owner);
	int rc = image_txn_prepare(&tx, eng, cfg, data, len, pid, ppid, argc, argv, envp,
				   remote_exec);
	if (rc == LXP_OK)
		rc = image_txn_publish(&tx, eng);
	if (rc == LXP_OK)
		rc = image_txn_start(&tx, eng);
	if (rc != LXP_OK)
		(void)image_txn_abort(&tx, eng);
	return rc;
}
