#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Every symbol LXP exports carries its namespace (lxp_, g_lxp_ or LXP_), so a host
# linking the library cannot collide with it. Lists the global definitions in the
# given objects or archives that lack it and fails if there are any.
#
# Usage: check-symbols.sh <object-or-archive>...   ($NM picks nm; default nm)
#        check-symbols.sh --self-test              ($CC picks the compiler; default cc)
set -eu

if [ "${1:-}" = --self-test ]; then
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	cc_bin=${CC:-cc}
	printf 'static int helper(void) { return 1; }\nint lxp_ok(void) { return helper(); }\nint g_lxp_ok;\n' \
		>"$tmp/good.c"
	printf 'int stray(void) { return 0; }\n' >"$tmp/bad.c"
	"$cc_bin" -c "$tmp/good.c" -o "$tmp/good.o"
	"$cc_bin" -c "$tmp/bad.c" -o "$tmp/bad.o"
	if ! sh "$0" "$tmp/good.o" >/dev/null; then
		echo "FAIL: self-test rejected prefixed and static symbols"
		exit 1
	fi
	if sh "$0" "$tmp/bad.o" >/dev/null; then
		echo "FAIL: self-test accepted an unprefixed symbol"
		exit 1
	fi
	echo "OK: check-symbols self-test"
	exit 0
fi

[ $# -gt 0 ] || { echo "usage: $0 <object-or-archive>... | --self-test" >&2; exit 2; }
bad=$("${NM:-nm}" -g --defined-only "$@" | awk 'NF == 3 { print $3 }' | sort -u |
	grep -vE '^(lxp_|g_lxp_|LXP_)' || true)
if [ -n "$bad" ]; then
	echo "FAIL: exported symbols without the lxp_ namespace:"
	echo "$bad" | sed 's/^/  /'
	exit 1
fi
echo "OK: every exported symbol carries the lxp_ namespace."
