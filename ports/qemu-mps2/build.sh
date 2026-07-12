#!/bin/bash
# Cross-build the standalone FreeRTOS lxp QEMU harness firmware.
# Run fetch-deps.sh once first (vendors FreeRTOS). Run from ports/qemu-mps2/.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
ARMCC="${ARMCC:-$HOME/projects/private/hIRoic/oveRTOS/output/toolchains/arm-gnu-toolchain-15.2.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-gcc}"
LXP_ROOT="$HERE/../.."
FRT="$HERE/vendor/FreeRTOS-Kernel"
# Use the ARM_CM3 (ARMv7-M, FPU-less) port on the CM7: soft-float everywhere avoids
# the FPU lazy-stacking hazard in the svc-exception context — the CM7 runs it fine.
PORT="$FRT/portable/GCC/ARM_CM3"
if [ ! -f "$PORT/port.c" ]; then echo "FreeRTOS missing — run: bash fetch-deps.sh"; exit 1; fi
INC="-I$LXP_ROOT/include -I$LXP_ROOT/src -I$HERE -I$HERE/board -I$FRT/include -I$PORT"
FLAGS="-mcpu=cortex-m7 -mthumb -mfloat-abi=soft -ffreestanding -Os -g -Wall -ffunction-sections -fdata-sections"

rm -rf build && mkdir -p build
err=0
for f in $(find "$LXP_ROOT/src" -name '*.c'); do
    $ARMCC $FLAGS $INC -c "$f" -o "build/$(basename "$f").o" || err=1
done
for f in "$FRT/tasks.c" "$FRT/queue.c" "$FRT/list.c" "$PORT/port.c"; do
    $ARMCC $FLAGS $INC -c "$f" -o "build/$(basename "$f").o" || err=1
done
for f in engine.c boot.c; do
    $ARMCC $FLAGS $INC -c "$f" -o "build/$(basename "$f").o" || err=1
done
if [ "$err" -ne 0 ]; then echo "COMPILE FAILED"; exit 1; fi

$ARMCC $FLAGS -nostartfiles --specs=nano.specs --specs=nosys.specs \
    -T "$HERE/board/mps2_an500.ld" -Wl,--gc-sections -Wl,-Map=build/firmware.map \
    build/*.o -o firmware.elf -lc -lgcc
echo "LINK rc=$?"
ls -la firmware.elf 2>/dev/null
