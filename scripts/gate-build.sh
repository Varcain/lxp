#!/bin/sh
# Cross-compile every lxp src/ TU for Cortex-M under a given LXP_ENABLE_* gate
# config, warnings-as-errors — the gate-rot guard. An unguarded reference to a
# disabled subsystem (a call not wrapped in its #if LXP_ENABLE_X) fails the build;
# a clean build across the matrix proves each -DLXP_ENABLE_X=0 genuinely removes
# the code (value-based gates, post-D3). Compile-only: the module links only with
# an engine seam + port, which the QEMU end-to-end job already exercises.
#
# Usage: gate-build.sh [extra -D flags ...]
#   e.g. gate-build.sh -DLXP_ENABLE_NET=1 -DLXP_ENABLE_NETFS=1
# The target compiler defaults to arm-none-eabi-gcc; override with $ARMCC.
set -eu

CC="${ARMCC:-arm-none-eabi-gcc}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Mirror the QEMU port's target flags (ports/qemu-mps2/build.sh) so the matrix
# compiles the sources exactly as production does, plus -Wextra -Werror -Wundef.
FLAGS="-mcpu=cortex-m7 -mthumb -mfloat-abi=softfp -mfpu=fpv5-d16 -ffreestanding -Os \
-Wall -Wextra -Werror -Wundef -ffunction-sections -fdata-sections"
INC="-I$ROOT/include -I$ROOT/src"

OBJ="$(mktemp -d)"
trap 'rm -rf "$OBJ"' EXIT

n=0
for f in $(find "$ROOT/src" -name '*.c' | sort); do
	"$CC" $FLAGS $INC "$@" -c "$f" -o "$OBJ/$(basename "$f").o"
	n=$((n + 1))
done
echo "OK: $n TU(s) compiled clean [gates: ${*:-defaults (all off)}]"
