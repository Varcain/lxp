/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private exec transaction. Included only by the exec owner and its white-box
 * tests; other coordinator policies see only lxp_handle_exec().
 */
#ifndef LXP_EXEC_PRIVATE_H
#define LXP_EXEC_PRIVATE_H

#include "run/lxp_coordinator.h"
#include "run/lxp_image.h"

enum exec_txn_phase {
	EXEC_TXN_EMPTY,
	EXEC_TXN_RESERVED,
	EXEC_TXN_VALIDATED,
	EXEC_TXN_COMMITTED,
	EXEC_TXN_IMAGE_READY,
	EXEC_TXN_PUBLISHED,
	EXEC_TXN_FINISHED,
	EXEC_TXN_ABORTED,
};

struct exec_txn {
	lxp_proc_t *old;
	struct image_txn image;
	lxp_slot_ref_t old_ref;
	lxp_slot_ref_t new_ref;
	lxp_slot_ref_t parent_ref;
	lxp_region_ref_t region;
	lxp_files_t *saved_files;
	lxp_fs_context_t *saved_fs;
	lxp_sighand_t *old_sighand;
	lxp_thread_group_t *saved_group;
	enum exec_txn_phase phase;
	int slot;
	int pid;
	int ppid;
	int image_index;
	uint64_t saved_mask;
	char comm[sizeof(((lxp_proc_t *)0)->comm)];
	uint8_t region_acquired;
	uint8_t uses_snapshot;
	uint8_t parent_restored;
	uint8_t parent_resumed;
	uint8_t old_detached;
	uint8_t slot_reassigned;
	uint8_t image_initialized;
	uint8_t terminal;
};

#if defined(LXP_TEST_INTERNALS)
#define LXP_EXEC_TXN_LINKAGE
#else
#define LXP_EXEC_TXN_LINKAGE static
#endif

LXP_EXEC_TXN_LINKAGE void exec_txn_init(struct exec_txn *tx, int slot);
LXP_EXEC_TXN_LINKAGE int exec_txn_reserve(struct exec_txn *tx);
LXP_EXEC_TXN_LINKAGE int exec_txn_validate_image(struct exec_txn *tx, const uint8_t *image,
						 size_t image_size, int remote_exec);
LXP_EXEC_TXN_LINKAGE int exec_txn_commit(struct exec_txn *tx, const lxp_os_ops_t *eng);
LXP_EXEC_TXN_LINKAGE void exec_txn_abort(struct exec_txn *tx, const lxp_os_ops_t *eng, long error,
					 int reason);

#endif /* LXP_EXEC_PRIVATE_H */
