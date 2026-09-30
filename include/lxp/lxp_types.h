/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Self-contained foundation types owned by the personality. No host framework
 * headers are required.
 */

#ifndef LXP_TYPES_H
#define LXP_TYPES_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__GNUC__) && !defined(__clang__)
#error "lxp requires a GCC-compatible compiler (gcc or clang)."
#endif

/* ---- public-API annotation macros ------------------------------------------ */
#if defined(__BINDGEN__) || defined(__ZIG_CIMPORT__) || defined(__EMSCRIPTEN__) || \
	defined(__LXP_LINT__)
#define LXP_NONNULL(...)
#define LXP_NODISCARD
#else
#define LXP_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#define LXP_NODISCARD __attribute__((warn_unused_result))
#endif

/**
 * @brief lxp result / error codes.
 *
 * Zero (@c LXP_OK) on success, negative on error. These pinned values form the
 * provider ABI; host adapters must return or translate to these exact codes. A
 * retired code's number is never reused: -7, -14 to -17 and -20 are retired.
 */
typedef enum lxp_err {
	LXP_OK = 0,
	LXP_ERR_NOT_REGISTERED = -1,
	LXP_ERR_INVALID_PARAM = -2,
	LXP_ERR_NO_MEMORY = -3,
	LXP_ERR_TIMEOUT = -4,
	LXP_ERR_NOT_SUPPORTED = -5,
	LXP_ERR_QUEUE_FULL = -6,
	LXP_ERR_NET_REFUSED = -8,
	LXP_ERR_NET_UNREACHABLE = -9,
	LXP_ERR_NET_ADDR_IN_USE = -10,
	LXP_ERR_NET_RESET = -11,
	LXP_ERR_NET_DNS_FAIL = -12,
	LXP_ERR_NET_CLOSED = -13,
	LXP_ERR_WOULD_BLOCK = -18,
	LXP_ERR_EOF = -19,
	LXP_ERR_NOT_FOUND = -21,
	LXP_ERR_NET_ADDR_NOT_AVAILABLE = -22,
	LXP_ERR_ALREADY_EXISTS = -23,
	LXP_ERR_NO_SPACE = -24,
	LXP_ERR_NOT_DIR = -25,
	LXP_ERR_IS_DIR = -26,
	LXP_ERR_NOT_EMPTY = -27,
	LXP_ERR_READ_ONLY = -28,
	LXP_ERR_IO = -29,
	LXP_ERR_BUSY = -30,
	LXP_ERR_NAME_TOO_LONG = -31,
	LXP_ERR_BAD_HANDLE = -32,
	LXP_ERR_PERMISSION = -33,
	LXP_ERR_CROSS_DEVICE = -34,
} lxp_err_t;

/** @brief Timeout value that means "block indefinitely". */
#define LXP_WAIT_FOREVER UINT64_MAX

/* ---- ABI pins (a re-numbering fails to compile) ---------------------------- */
#if defined(__cplusplus)
#define LXP_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define LXP_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif
LXP_STATIC_ASSERT(LXP_ERR_INVALID_PARAM == -2, "LXP_ERR_INVALID_PARAM drifted");
LXP_STATIC_ASSERT(LXP_ERR_NO_MEMORY == -3, "LXP_ERR_NO_MEMORY drifted");
LXP_STATIC_ASSERT(LXP_ERR_TIMEOUT == -4, "LXP_ERR_TIMEOUT drifted");
LXP_STATIC_ASSERT(LXP_ERR_NOT_SUPPORTED == -5, "LXP_ERR_NOT_SUPPORTED drifted");
LXP_STATIC_ASSERT(LXP_ERR_NET_REFUSED == -8, "LXP_ERR_NET_REFUSED drifted");
LXP_STATIC_ASSERT(LXP_ERR_NET_UNREACHABLE == -9, "LXP_ERR_NET_UNREACHABLE drifted");
LXP_STATIC_ASSERT(LXP_ERR_NET_ADDR_IN_USE == -10, "LXP_ERR_NET_ADDR_IN_USE drifted");
LXP_STATIC_ASSERT(LXP_ERR_NET_RESET == -11, "LXP_ERR_NET_RESET drifted");
LXP_STATIC_ASSERT(LXP_ERR_NET_DNS_FAIL == -12, "LXP_ERR_NET_DNS_FAIL drifted");
LXP_STATIC_ASSERT(LXP_ERR_NET_CLOSED == -13, "LXP_ERR_NET_CLOSED drifted");
LXP_STATIC_ASSERT(LXP_ERR_NOT_FOUND == -21, "LXP_ERR_NOT_FOUND drifted");
LXP_STATIC_ASSERT(LXP_ERR_NET_ADDR_NOT_AVAILABLE == -22,
		  "LXP_ERR_NET_ADDR_NOT_AVAILABLE drifted");
LXP_STATIC_ASSERT(LXP_ERR_ALREADY_EXISTS == -23, "LXP_ERR_ALREADY_EXISTS drifted");
LXP_STATIC_ASSERT(LXP_ERR_CROSS_DEVICE == -34, "LXP_ERR_CROSS_DEVICE drifted");
LXP_STATIC_ASSERT(LXP_WAIT_FOREVER == UINT64_MAX, "LXP_WAIT_FOREVER drifted");

/* ---- thread introspection (for the ps/top /proc snapshot) ------------------ */
/** @brief Execution state of a host kernel thread. */
typedef enum lxp_thread_state {
	LXP_THREAD_STATE_RUNNING = 0,
	LXP_THREAD_STATE_READY,
	LXP_THREAD_STATE_BLOCKED,
	LXP_THREAD_STATE_SUSPENDED,
	LXP_THREAD_STATE_TERMINATED,
	LXP_THREAD_STATE_UNKNOWN,
} lxp_thread_state_t;

/** @brief Cumulative time per thread state (microseconds). */
struct lxp_thread_state_times {
	uint64_t running_us;
	uint64_t ready_us;
	uint64_t blocked_us;
	uint64_t suspended_us;
};

/** No Linux slot owns this host thread. */
#define LXP_THREAD_SLOT_NONE (-1)

/** Optional host-thread fields supplied by the RTOS seam. */
#define LXP_THREAD_INFO_VALID_STACK_USED     (1u << 0)
#define LXP_THREAD_INFO_VALID_STACK_SIZE     (1u << 1)
#define LXP_THREAD_INFO_VALID_CPU_PERCENT    (1u << 2)
#define LXP_THREAD_INFO_VALID_RUNNING_TIME   (1u << 3)
#define LXP_THREAD_INFO_VALID_READY_TIME     (1u << 4)
#define LXP_THREAD_INFO_VALID_BLOCKED_TIME   (1u << 5)
#define LXP_THREAD_INFO_VALID_SUSPENDED_TIME (1u << 6)
#define LXP_THREAD_INFO_VALID_STATE_TIMES                                           \
	(LXP_THREAD_INFO_VALID_RUNNING_TIME | LXP_THREAD_INFO_VALID_READY_TIME |      \
	 LXP_THREAD_INFO_VALID_BLOCKED_TIME | LXP_THREAD_INFO_VALID_SUSPENDED_TIME)

/**
 * @brief Snapshot of one host kernel thread.
 *
 * @c identity is an opaque host-thread cookie used only for equality by a
 * seam. @c lxp_slot is assigned explicitly by an LXP-aware seam; the core
 * never derives ownership from a display name.
 */
struct lxp_thread_info {
	const char *name;
	uintptr_t identity;
	int32_t lxp_slot;
	lxp_thread_state_t state;
	int priority;
	size_t stack_used;
	size_t stack_size;
	uint32_t cpu_percent_x100;
	uint32_t valid_fields;
	struct lxp_thread_state_times state_times;
};

/**
 * @brief Host system-heap snapshot.
 *
 * This describes the allocator exposed by the host OS, not fabricated physical
 * RAM. Every field is copied explicitly across the provider boundary.
 */
struct lxp_mem_stats {
	size_t total;     /**< Total host system-heap capacity in bytes. */
	size_t free;      /**< Bytes currently available for allocation. */
	size_t used;      /**< Bytes currently allocated. */
	size_t peak_used; /**< Peak allocated bytes, or 0 when unavailable. */
};

#endif /* LXP_TYPES_H */
