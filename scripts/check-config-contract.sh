#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Prove that feature children cannot be configured without their owner.
set -eu

cd "$(dirname "$0")/.."
cc_bin=${1:-${CC:-cc}}
cmake_bin=${2:-${CMAKE_COMMAND:-cmake}}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail=0

expect_header_reject()
{
	name=$1
	shift
	if "$cc_bin" -std=c11 -Iinclude "$@" -c tests/config_contract_probe.c \
		-o "$tmp/$name.o" >"$tmp/$name.out" 2>&1; then
		echo "FAIL: header accepted invalid feature set: $name"
		fail=1
	fi
}

expect_cmake_reject()
{
	name=$1
	shift
	if "$cmake_bin" -S . -B "$tmp/cmake-$name" "$@" \
		>"$tmp/cmake-$name.out" 2>&1; then
		echo "FAIL: CMake accepted invalid feature set: $name"
		fail=1
	fi
}

expect_header_reject netfs-without-net \
	-DLXP_ENABLE_NETFS=1 -DLXP_ENABLE_NET=0
expect_header_reject netfs-exec-without-netfs \
	-DLXP_ENABLE_NETFS_EXEC=1 -DLXP_ENABLE_NETFS=0
expect_header_reject fb-without-dev \
	-DLXP_ENABLE_DEV_FB=1 -DLXP_ENABLE_DEV=0
expect_header_reject dma2d-without-dev \
	-DLXP_ENABLE_DEV_DMA2D=1 -DLXP_ENABLE_DEV=0
expect_header_reject input-without-dev \
	-DLXP_ENABLE_DEV_INPUT=1 -DLXP_ENABLE_DEV=0
expect_header_reject testpad-without-input \
	-DLXP_ENABLE_DEV_INPUT_TESTPAD=1 -DLXP_ENABLE_DEV_INPUT=0
expect_header_reject touch-without-input \
	-DLXP_ENABLE_TOUCH=1 -DLXP_ENABLE_DEV_INPUT=0
expect_header_reject latency-not-boolean \
	-DLXP_ENABLE_LATENCY=2

expect_cmake_reject netfs-without-net -DLXP_ENABLE_NETFS=ON
expect_cmake_reject netfs-exec-without-netfs -DLXP_ENABLE_NETFS_EXEC=ON
expect_cmake_reject fb-without-dev -DLXP_ENABLE_DEV_FB=ON
expect_cmake_reject dma2d-without-dev -DLXP_ENABLE_DEV_DMA2D=ON
expect_cmake_reject input-without-dev -DLXP_ENABLE_DEV_INPUT=ON
expect_cmake_reject testpad-without-input -DLXP_ENABLE_DEV_INPUT_TESTPAD=ON
expect_cmake_reject touch-without-input -DLXP_ENABLE_TOUCH=ON

if ! "$cc_bin" -std=c11 -Iinclude \
	-DLXP_ENABLE_NET=1 \
	-DLXP_ENABLE_NETFS=1 \
	-DLXP_ENABLE_NETFS_EXEC=1 \
	-DLXP_ENABLE_DEV=1 \
	-DLXP_ENABLE_DEV_FB=1 \
	-DLXP_ENABLE_DEV_DMA2D=1 \
	-DLXP_ENABLE_DEV_INPUT=1 \
	-DLXP_ENABLE_DEV_INPUT_TESTPAD=1 \
	-DLXP_ENABLE_TOUCH=1 \
	-c tests/config_contract_probe.c -o "$tmp/valid.o"; then
	echo "FAIL: header rejected a complete feature hierarchy"
	fail=1
fi

if [ "$fail" -eq 0 ]; then
	echo "OK: invalid feature hierarchies fail at configure and compile time."
fi
exit "$fail"
