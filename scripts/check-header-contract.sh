#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Every installed header must compile by itself as C11 and C++17. The umbrella
# probe additionally proves that lxp.h exposes the embedding entry point. Guest ABI
# headers (include/uapi) are built by guest toolchains, so they must also compile as
# C99 and include nothing but the C library.
set -eu

cd "$(dirname "$0")/.."
cc_bin=${1:-${CC:-cc}}

for header in $(find include/lxp -type f -name '*.h' | sort); do
	name=${header#include/}
	"$cc_bin" -std=c11 -Iinclude -fsyntax-only -x c -include "$name" /dev/null
	"$cc_bin" -std=c++17 -Iinclude -fsyntax-only -x c++ -include "$name" /dev/null
done

for header in $(find include/uapi -type f -name '*.h' | sort); do
	name=${header#include/uapi/}
	"$cc_bin" -std=c99 -pedantic -Werror -Iinclude/uapi -fsyntax-only -x c -include "$name" /dev/null
	"$cc_bin" -std=c11 -Iinclude/uapi -fsyntax-only -x c -include "$name" /dev/null
	"$cc_bin" -std=c++17 -Iinclude/uapi -fsyntax-only -x c++ -include "$name" /dev/null
	if grep -n '#include "' "$header"; then
		echo "FAIL: $header includes a non-system header; guest ABI headers stand alone" >&2
		exit 1
	fi
done

"$cc_bin" -std=c11 -Iinclude -fsyntax-only tests/header_contract_probe.c
"$cc_bin" -std=c++17 -Iinclude -fsyntax-only -x c++ tests/header_contract_probe.c

echo "OK: every public header is self-contained in C11 and C++17, guest ABI headers in C99."
