#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Keep privileged guest access behind lxp_guest.c. This is intentionally a
# source gate rather than a compiler heuristic: it catches the pointer-shaped
# raw copies most likely to be introduced in syscall/subsystem reviews.
set -eu
cd "$(dirname "$0")/.."

legacy=$(grep -rEn '\b(user_ok|user_strnlen)\b' src include 2>/dev/null || true)
raw=$(grep -rEn \
	'memcpy\([^;]*(uaddr|uaddrlen|ubuf|uval|ulen|umsg|uvec|uset|uold|unew|ustat|statbuf)' \
	src --exclude=lxp_guest.c 2>/dev/null || true)
cast=$(grep -rEn \
	'\*[[:space:]]*\([^)]*\*[[:space:]]*\)[[:space:]]*(uaddr|uaddrlen|ubuf|uval|ulen|umsg|uvec|uset|uold|unew|ustat|arg|ua)\b' \
	src --exclude=lxp_guest.c 2>/dev/null || true)

if [ -n "$legacy" ] || [ -n "$raw" ] || [ -n "$cast" ]; then
	echo "FAIL: raw privileged guest-memory access escaped the common boundary:"
	[ -n "$legacy" ] && echo "$legacy"
	[ -n "$raw" ] && echo "$raw"
	[ -n "$cast" ] && echo "$cast"
	exit 1
fi

echo "OK: guest pointer validation/copies use the common lxp_guest boundary."
