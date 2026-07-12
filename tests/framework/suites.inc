/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * X-macro suite registry: the single source of truth for which suites exist.
 * The includer defines LXP_SUITE(name, label) before including this; new suites
 * are picked up by the dispatcher automatically.
 */
#ifndef LXP_SUITE
#define LXP_SUITE(name, label)
#endif

LXP_SUITE(arena,         "Arena allocator")
LXP_SUITE(linux_syscall, "Linux personality: syscall dispatch")
LXP_SUITE(linux_dev,     "Linux personality: /dev device layer")
LXP_SUITE(linux_net,     "Linux personality: socket layer")
LXP_SUITE(linux_netfs,   "Linux personality: remote filesystem (9P)")
LXP_SUITE(linux_pty,     "Linux personality: pseudo-terminal layer")

#undef LXP_SUITE
