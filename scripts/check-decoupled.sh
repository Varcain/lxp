#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# CI guard: fail if the lxp core regains consumer or native-RTOS coupling. The
# optional implementations under ports/ are the only place host headers belong.
# This checks the source-level contract; the definitive proof is that the core
# source inventory builds without an oveRTOS or native-RTOS include path.
set -eu
cd "$(dirname "$0")/.."

# Any #include of an oveRTOS header, or a board_desc.h, is a coupling regression.
# (Plain "ove_*" mentions in comments/docs are fine — this matches include lines
#  and the CONFIG_OVE_ / board_desc.h build coupling only.)
bad=$(grep -rEn '#[[:space:]]*include[[:space:]]*"(ove/|ove_config|board_desc)' src include 2>/dev/null || true)
# Real CONFIG_OVE_ preprocessor conditionals (not comment mentions of them).
cfg=$(grep -rEn '(defined[[:space:]]*\([[:space:]]*CONFIG_OVE_|#[[:space:]]*if(n?def)?[[:space:]]+CONFIG_OVE_)' src include 2>/dev/null || true)
# Native RTOS dependencies belong in ports/<rtos>, never in the portable core.
rtos_inc=$(grep -rEn '#[[:space:]]*include[[:space:]]*[<"](FreeRTOS\.h|task\.h|semphr\.h|nuttx/|zephyr/)' src include 2>/dev/null || true)
rtos_cfg=$(grep -rEn '#[[:space:]]*if(n?def)?.*(CONFIG_(OVE_RTOS_|FREERTOS|NUTTX|ZEPHYR)|__ZEPHYR__|__NuttX__)' src include 2>/dev/null || true)

if [ -n "$bad" ] || [ -n "$cfg" ] || [ -n "$rtos_inc" ] || [ -n "$rtos_cfg" ]; then
	echo "FAIL: lxp core regained a consumer or native-RTOS dependency:"
	[ -n "$bad" ] && echo "$bad"
	[ -n "$cfg" ] && echo "$cfg"
	[ -n "$rtos_inc" ] && echo "$rtos_inc"
	[ -n "$rtos_cfg" ] && echo "$rtos_cfg"
	exit 1
fi
echo "OK: lxp core is decoupled — host dependencies are confined to ports/."
