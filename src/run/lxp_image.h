/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private image-construction transaction. Only the initial-launch and exec
 * owners may prepare or publish an image.
 */
#ifndef LXP_IMAGE_H
#define LXP_IMAGE_H

#include "lxp_loader.h"
#include "lxp/lxp_run.h"
#include "run/lxp_runtime_store.h"

struct image_txn {
	lxp_proc_t proc;
	lxp_flat_t prog;
	struct lxp_dbg_s debug;
	lxp_slot_ref_t owner;
	lxp_region_ref_t region;
	lxp_guest_launch_t launch;
	int slot;
	uint8_t prepared;
	uint8_t executable_published;
	uint8_t published;
	uint8_t native_started;
	uint8_t region_committed;
};

void image_txn_init(struct image_txn *tx, int slot, lxp_region_ref_t region, lxp_slot_ref_t owner);
int image_txn_prepare(struct image_txn *tx, const lxp_os_ops_t *eng, const lxp_run_config_t *cfg,
		      const uint8_t *data, size_t len, int pid, int ppid, int argc,
		      const char *const argv[], const char *const envp[], int remote_exec);
int image_txn_publish(struct image_txn *tx, const lxp_os_ops_t *eng);
int image_txn_start(struct image_txn *tx, const lxp_os_ops_t *eng);
int image_txn_abort(struct image_txn *tx, const lxp_os_ops_t *eng);

int lxp_image_launch(const lxp_os_ops_t *eng, const lxp_run_config_t *cfg, int slot,
		     lxp_region_ref_t region, lxp_slot_ref_t owner, const uint8_t *data, size_t len,
		     int pid, int ppid, int argc, const char *const argv[],
		     const char *const envp[], int remote_exec);

#endif /* LXP_IMAGE_H */
