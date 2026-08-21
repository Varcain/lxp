/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Raw block-media provider contract for the Linux personality.
 */

#ifndef LXP_BLOCK_OPS_H
#define LXP_BLOCK_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "lxp/lxp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LXP_BLOCK_OPS_ABI_VERSION 3u

#define LXP_BLOCK_F_REMOVABLE 0x01u
#define LXP_BLOCK_F_READ_ONLY 0x02u
#define LXP_BLOCK_F_MEDIA_PRESENT 0x04u

#define LXP_BLOCK_OPEN_WRITE 0x01u

typedef struct lxp_block_info {
	uint64_t block_count;
	uint32_t logical_block_size;
	uint32_t erase_block_size; /**< Erase granularity in bytes. */
	uint32_t flags;
	uint32_t generation;
} lxp_block_info_t;

/** Notify LXP that one asynchronous block operation may be complete. */
typedef void (*lxp_block_ready_fn)(const void *context);

/**
 * Run-scoped host block provider. Data operations may complete asynchronously:
 * return LXP_ERR_WOULD_BLOCK, invoke the run-scoped readiness callback, then
 * return the saved completion when the same generation-qualified owner retries.
 */
typedef struct lxp_block_ops {
	uint32_t abi_version;
	uint32_t struct_size;

	/** An asynchronous provider retains @p ready and @p context only between a
	 * successful run_begin() and matching run_end(), and stops all callbacks
	 * before run_end() returns. A synchronous provider may ignore them.
	 * run_begin() leaves prior state unchanged on failure. */
	int (*run_begin)(lxp_block_ready_fn ready, const void *context);
	void (*run_end)(void);
	void (*request_owner)(uint64_t owner);
	void (*request_cancel)(uint64_t owner);

	int (*get_info)(lxp_block_info_t *out);
	/** Acquire/release the provider's aggregate raw-media lease. LXP calls
	 * open(0) only for the first Linux reader and close(0) after the last one;
	 * a writable open is exclusive and has one matching close. The provider
	 * remains responsible for arbitration with native filesystem/raw callers. */
	int (*open)(unsigned flags);
	void (*close)(unsigned flags);
	int (*read)(uint64_t offset, void *buf, size_t count, size_t *bytes_read);
	int (*write)(uint64_t offset, const void *buf, size_t count, size_t *bytes_written);
	int (*sync)(void);
} lxp_block_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* LXP_BLOCK_OPS_H */
