#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# CI guard: fail if lxp regains coupling to a consumer or, in its portable core, to a
# native RTOS. The core (src/, include/) names neither; the optional ports/ may use their
# own RTOS's headers but no consumer's, and no string literal anywhere names a consumer.
# The definitive proof is that the core source inventory builds without an oveRTOS or
# native-RTOS include path; this checks the source-level contract.
#
#   check-decoupled.sh [root]      check a tree (default: this repository)
#   check-decoupled.sh --self-test prove each rule rejects a planted violation
set -eu

code() {
	find "$@" -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' -o -name '*.s' \) 2>/dev/null
}

check_tree() {
	root=$1
	core=$(code "$root/src" "$root/include")
	ports=$(code "$root/ports")
	out=""
	scan() { # <label> <regex> <files...>
		label=$1
		regex=$2
		shift 2
		[ "$#" -gt 0 ] || return 0
		# Comment lines may name a consumer; only code counts.
		hits=$(grep -EnH "$regex" "$@" 2>/dev/null |
			grep -Ev '^[^:]*:[0-9]+:[[:space:]]*(/\*|\*|//)' || true)
		[ -z "$hits" ] || out="$out$label:\n$hits\n"
	}
	# shellcheck disable=SC2086
	{
		# Any #include of an oveRTOS header or board_desc.h, anywhere.
		scan "consumer include" '#[[:space:]]*include[[:space:]]*"(ove/|ove_config|board_desc)' \
			$core $ports
		# Real CONFIG_OVE_ preprocessor conditionals (comment mentions are fine).
		scan "consumer config" \
			'(defined[[:space:]]*\([[:space:]]*CONFIG_OVE_|#[[:space:]]*if(n?def)?[[:space:]]+CONFIG_OVE_)' \
			$core $ports
		# oveRTOS symbols (ove_*) used by code; a port gets its host services through
		# its configuration struct, never by name.
		scan "consumer symbol" '(^|[^A-Za-z0-9_])ove_[a-z][a-z0-9_]*[[:space:]]*\(' $core $ports
		# A string literal naming a consumer leaks it into what a guest or host sees.
		scan "consumer name in a string" '"[^"]*([Oo][Vv][Ee][Rr][Tt][Oo][Ss]|ovefb)[^"]*"' \
			$core $ports
		# Native RTOS dependencies belong in ports/<rtos>, never in the portable core.
		scan "native RTOS include in the core" \
			'#[[:space:]]*include[[:space:]]*[<"](FreeRTOS\.h|task\.h|semphr\.h|nuttx/|zephyr/)' $core
		scan "native RTOS config in the core" \
			'#[[:space:]]*if(n?def)?.*(CONFIG_(OVE_RTOS_|FREERTOS|NUTTX|ZEPHYR)|__ZEPHYR__|__NuttX__)' \
			$core
	}
	if [ -n "$out" ]; then
		printf "FAIL: lxp regained a consumer or native-RTOS dependency:\n%b" "$out"
		return 1
	fi
	return 0
}

self_test() {
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	plant() { # <name> <relative path> <line>
		rm -rf "$tmp/t" && mkdir -p "$tmp/t/src" "$tmp/t/include" "$tmp/t/ports/x"
		mkdir -p "$(dirname "$tmp/t/$2")"
		printf '%s\n' "$3" >"$tmp/t/$2"
		if check_tree "$tmp/t" >/dev/null; then
			echo "FAIL: self-test: $1 was not caught"
			exit 1
		fi
	}
	plant consumer-include-core src/a.c '#include "ove/thread.h"'
	plant consumer-include-port ports/x/p.c '#include "ove_config.h"'
	plant consumer-config-port ports/x/p.c '#if defined(CONFIG_OVE_BOARD)'
	plant consumer-symbol-port ports/x/p.c 'int x = ove_hal_now();'
	plant consumer-name-core src/a.c 'static const char n[] = "overtos";'
	plant consumer-name-port ports/x/p.c 'const char *id = "ovefb";'
	plant rtos-include-core src/a.c '#include "FreeRTOS.h"'
	plant rtos-config-core include/a.h '#ifdef __ZEPHYR__'
	rm -rf "$tmp/t" && mkdir -p "$tmp/t/src" "$tmp/t/ports/x"
	printf '%s\n' '#include "FreeRTOS.h"' '/* oveRTOS supplies ove_now() */' >"$tmp/t/ports/x/p.c"
	check_tree "$tmp/t" >/dev/null || { echo "FAIL: self-test: a clean port was rejected"; exit 1; }
	echo "OK: every decoupling rule rejects its planted violation."
}

if [ "${1:-}" = "--self-test" ]; then
	self_test
	exit 0
fi
root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
check_tree "$root"
echo "OK: lxp is decoupled — host dependencies are confined to ports/, and no consumer is named."
