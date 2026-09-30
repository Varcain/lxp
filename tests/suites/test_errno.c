/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Provider results as the guest sees them (src/lxp_errno.c): every lxp_err_t code has
 * exactly the errno below, and sockets read a timeout as would-block. The inverse gives
 * every such errno back to a host as a code that means it.
 */
#include "../framework/lxp_test.h"
#include "lxp_errno.h"
#include "lxp_linux_uapi.h"

static const struct {
	int err;
	long result;
} g_expected[] = {
	{LXP_OK, 0},
	{LXP_ERR_NOT_REGISTERED, -LXP_ENODEV},
	{LXP_ERR_INVALID_PARAM, -LXP_EINVAL},
	{LXP_ERR_NO_MEMORY, -LXP_ENOMEM},
	{LXP_ERR_TIMEOUT, -LXP_ETIMEDOUT},
	{LXP_ERR_NOT_SUPPORTED, -LXP_EOPNOTSUPP},
	{LXP_ERR_QUEUE_FULL, -LXP_EAGAIN},
	{LXP_ERR_NET_REFUSED, -LXP_ECONNREFUSED},
	{LXP_ERR_NET_UNREACHABLE, -LXP_ENETUNREACH},
	{LXP_ERR_NET_ADDR_IN_USE, -LXP_EADDRINUSE},
	{LXP_ERR_NET_RESET, -LXP_ECONNRESET},
	{LXP_ERR_NET_DNS_FAIL, -LXP_EIO},
	{LXP_ERR_NET_CLOSED, -LXP_EPIPE},
	{LXP_ERR_WOULD_BLOCK, -LXP_EAGAIN},
	{LXP_ERR_EOF, 0},
	{LXP_ERR_NOT_FOUND, -LXP_ENOENT},
	{LXP_ERR_NET_ADDR_NOT_AVAILABLE, -LXP_EADDRNOTAVAIL},
	{LXP_ERR_ALREADY_EXISTS, -LXP_EEXIST},
	{LXP_ERR_NO_SPACE, -LXP_ENOSPC},
	{LXP_ERR_NOT_DIR, -LXP_ENOTDIR},
	{LXP_ERR_IS_DIR, -LXP_EISDIR},
	{LXP_ERR_NOT_EMPTY, -LXP_ENOTEMPTY},
	{LXP_ERR_READ_ONLY, -LXP_EROFS},
	{LXP_ERR_IO, -LXP_EIO},
	{LXP_ERR_BUSY, -LXP_EBUSY},
	{LXP_ERR_NAME_TOO_LONG, -LXP_ENAMETOOLONG},
	{LXP_ERR_BAD_HANDLE, -LXP_EBADF},
	{LXP_ERR_PERMISSION, -LXP_EACCES},
	{LXP_ERR_CROSS_DEVICE, -LXP_EXDEV},
};

/* Numbers of retired codes (lxp_types.h), which read as any unknown code does. */
static const int g_retired[] = {-7, -14, -15, -16, -17, -20};

/* The table above names every code once, and the translator agrees with it. */
static void test_every_code_has_its_errno(void **state)
{
	(void)state;
	const size_t n = sizeof(g_expected) / sizeof(g_expected[0]);
	const size_t retired = sizeof(g_retired) / sizeof(g_retired[0]);
	assert_int_equal(n + retired, (size_t)(LXP_OK - LXP_ERR_CROSS_DEVICE + 1));
	for (size_t r = 0; r < retired; r++)
		assert_int_equal(lxp_errno_from_err(g_retired[r]), -LXP_EIO);
	for (int err = LXP_ERR_CROSS_DEVICE; err <= LXP_OK; err++) {
		size_t i = 0;
		while (i < n && g_expected[i].err != err)
			i++;
		size_t r = 0;
		while (r < retired && g_retired[r] != err)
			r++;
		assert_true(i < n || r < retired); /* a code the table does not cover */
		if (i < n)
			assert_int_equal(lxp_errno_from_err(err), g_expected[i].result);
	}
	assert_int_equal(lxp_errno_from_err(-1000), -LXP_EIO);
}

/* A socket provider reports "cannot complete yet" as a timeout; everything else reads as
 * it does for any provider. */
static void test_net_reads_timeout_as_would_block(void **state)
{
	(void)state;
	assert_int_equal(lxp_net_errno_from_err(LXP_ERR_TIMEOUT), -LXP_EAGAIN);
	for (int err = LXP_ERR_CROSS_DEVICE; err <= LXP_OK; err++)
		if (err != LXP_ERR_TIMEOUT)
			assert_int_equal(lxp_net_errno_from_err(err), lxp_errno_from_err(err));
}

/* Every errno a provider result can become maps back to a code with that same errno;
 * the errnos with no code of their own take the nearest one. */
static void test_errno_maps_back_to_its_code(void **state)
{
	(void)state;
	for (int err = LXP_ERR_CROSS_DEVICE; err <= LXP_OK; err++) {
		long e = lxp_errno_from_err(err);
		assert_int_equal(lxp_errno_from_err(lxp_err_from_errno(e)), e);
	}
	assert_int_equal(lxp_err_from_errno(0), LXP_OK);
	assert_int_equal(lxp_err_from_errno(-LXP_ENOENT), LXP_ERR_NOT_FOUND);
	assert_int_equal(lxp_err_from_errno(-LXP_E2BIG), LXP_ERR_INVALID_PARAM);
	assert_int_equal(lxp_err_from_errno(-LXP_ENOEXEC), LXP_ERR_NOT_SUPPORTED);
	assert_int_equal(lxp_err_from_errno(-LXP_ENOSYS), LXP_ERR_NOT_SUPPORTED);
	assert_int_equal(lxp_err_from_errno(-LXP_EPERM), LXP_ERR_PERMISSION);
	assert_int_equal(lxp_err_from_errno(-LXP_ECHILD), LXP_ERR_IO);
}

int test_errno_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_every_code_has_its_errno),
		cmocka_unit_test(test_net_reads_timeout_as_would_block),
		cmocka_unit_test(test_errno_maps_back_to_its_code),
	};
	return cmocka_run_group_tests_name("errno", tests, NULL, NULL);
}
