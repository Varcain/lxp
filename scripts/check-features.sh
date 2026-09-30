#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# cmake/lxp_features.cmake is the one list of LXP feature gates. Prove that lxp_config.h
# defaults exactly those gates and rejects exactly the owner pairs the table names, and
# that CI's gate-rot matrix builds every gate on (its "all" leg, each one at once).
set -eu

cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

sed -n 's/^  "\([A-Z0-9_]*\)|\([A-Z0-9_-]*\)|.*/\1 \2/p' cmake/lxp_features.cmake >"$tmp/table"
cut -d' ' -f1 "$tmp/table" | sort >"$tmp/table.names"
awk '$2 != "-"' "$tmp/table" | sort >"$tmp/table.owners"

sed -n 's/^#ifndef LXP_ENABLE_\([A-Z0-9_]*\)$/\1/p' include/lxp/lxp_config.h | sort >"$tmp/config.names"
sed -n 's/^#if LXP_ENABLE_\([A-Z0-9_]*\) && !LXP_ENABLE_\([A-Z0-9_]*\)$/\1 \2/p' \
	include/lxp/lxp_config.h | sort >"$tmp/config.owners"

if ! diff -u "$tmp/table.names" "$tmp/config.names"; then
	echo "FAIL: the feature table and lxp_config.h's defaults name different gates"
	fail=1
fi
if ! diff -u "$tmp/table.owners" "$tmp/config.owners"; then
	echo "FAIL: the feature table and lxp_config.h's #error rules name different owners"
	fail=1
fi

all_leg=$(grep -E '^[[:space:]]*- \{ name: all,' .github/workflows/ci.yml || true)
[ -n "$all_leg" ] || { echo "FAIL: CI has no \"all\" gate leg"; fail=1; }
while read -r name; do
	case "$all_leg" in
	*"-DLXP_ENABLE_$name=1"*) ;;
	*)
		echo "FAIL: CI's \"all\" gate leg does not enable LXP_ENABLE_$name"
		fail=1
		;;
	esac
done <"$tmp/table.names"

[ "$fail" -eq 0 ] || exit 1
echo "OK: $(wc -l <"$tmp/table.names") feature gates agree across the table, lxp_config.h and CI."
