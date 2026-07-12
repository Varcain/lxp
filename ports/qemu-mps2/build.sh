#!/bin/bash
# Cross-build the standalone FreeRTOS lxp QEMU harness firmware.
# Run fetch-deps.sh once first (vendors FreeRTOS). Run from ports/qemu-mps2/.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
ARMCC="${ARMCC:-$HOME/projects/private/hIRoic/oveRTOS/output/toolchains/arm-gnu-toolchain-15.2.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-gcc}"
LXP_ROOT="$HERE/../.."
FRT="$HERE/vendor/FreeRTOS-Kernel"
# ARM_CM4_MPU (ARMv7-M + PMSAv7 MPU) on the CM7: guests run unprivileged behind per-task
# MPU regions. CM4_MPU (not CM3_MPU) because it exposes 11 configurable regions — a
# dynamic M3 guest needs 4 (program + dyn_pool + two cpio windows); CM3_MPU allows only 3.
PORT="$FRT/portable/GCC/ARM_CM4_MPU"
MPU_WRAP="$FRT/portable/Common/mpu_wrappers.c" # V1 unprivileged API trampolines
if [ ! -f "$PORT/port.c" ]; then echo "FreeRTOS missing — run: bash fetch-deps.sh"; exit 1; fi
INC="-I$LXP_ROOT/include -I$LXP_ROOT/src -I$HERE -I$HERE/board -I$FRT/include -I$PORT"
# softfp (not soft): the CM4_MPU port's context switch has VFP save/restore asm
# (vstmia s16-s31) that the assembler only accepts with an FPU selected. softfp keeps
# the soft calling convention (link-compatible; guests are separate cpio ELFs) while
# allowing the VFP asm. No firmware C code uses float, so FPCA stays 0 → the port's
# conditional FPU-context save never actually runs (no lazy-stacking hazard).
FLAGS="-mcpu=cortex-m7 -mthumb -mfloat-abi=softfp -mfpu=fpv5-d16 -ffreestanding -Os -g -Wall -ffunction-sections -fdata-sections"
# Which milestone this firmware runs (M1=/hello, M2=/init, M3=busybox from PSRAM).
MILESTONE="${MILESTONE:-1}"
FLAGS="$FLAGS -DLXP_MILESTONE=$MILESTONE"
# Warnings-as-errors for our code. The lxp module gets full strictness incl. -Wundef,
# matching scripts/gate-build.sh (src/ includes no host headers, so it stays -Wundef-clean).
# The port TUs (engine.c/boot.c) include vendored FreeRTOS headers that are not -Wundef-clean,
# so they get -Wextra -Werror without -Wundef. Vendored FreeRTOS keeps the base -Wall.
LXPFLAGS="$FLAGS -Wextra -Werror -Wundef"
PORTFLAGS="$FLAGS -Wextra -Werror"

rm -rf build && mkdir -p build
err=0
for f in $(find "$LXP_ROOT/src" -name '*.c'); do
    $ARMCC $LXPFLAGS $INC -c "$f" -o "build/$(basename "$f").o" || err=1
done
for f in "$FRT/tasks.c" "$FRT/queue.c" "$FRT/list.c" "$PORT/port.c" "$MPU_WRAP"; do
    $ARMCC $FLAGS $INC -c "$f" -o "build/$(basename "$f").o" || err=1
done
for f in engine.c boot.c; do
    $ARMCC $PORTFLAGS $INC -c "$f" -o "build/$(basename "$f").o" || err=1
done
if [ "$err" -ne 0 ]; then echo "COMPILE FAILED"; exit 1; fi

$ARMCC $FLAGS -nostartfiles --specs=nano.specs --specs=nosys.specs \
    -T "$HERE/board/mps2_an500.ld" -Wl,--gc-sections -Wl,-Map=build/firmware.map \
    build/*.o -o firmware.elf -lc -lgcc
echo "LINK rc=$?"
ls -la firmware.elf 2>/dev/null
