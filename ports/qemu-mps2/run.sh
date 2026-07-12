#!/bin/bash
# Build the M1 firmware from the pinned guest fixture and assert the guest marker
# under QEMU. Run from ports/qemu-mps2/ (after `bash fetch-deps.sh` once).
#
# By default this uses the committed guest/rootfs.cpio fixture, so CI needs only
# arm-none-eabi-gcc + qemu-system-arm (NOT the Buildroot FDPIC toolchain). Set
# REGEN_GUEST=1 to rebuild the fixture from guest/hello.c (needs the FDPIC gcc).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
FDCC="${FDCC:-$HOME/projects/private/hIRoic/buildroot/output/host/bin/arm-buildroot-uclinuxfdpiceabi-gcc}"
QEMU="${QEMU:-/usr/bin/qemu-system-arm}"

# 1. (optional) regenerate the pinned guest fixture from source.
if [ "${REGEN_GUEST:-0}" = 1 ]; then
    [ -x "$FDCC" ] || { echo "REGEN_GUEST=1 but FDPIC gcc not found: $FDCC"; exit 1; }
    ( cd guest
      "$FDCC" -mfdpic -static -nostdlib -Os -ffreestanding -e _start -o hello.elf hello.c
      rm -rf root && mkdir root && cp hello.elf root/hello
      cd root && echo hello | cpio -o -H newc 2>/dev/null > ../rootfs.cpio )
    echo "regenerated pinned fixture guest/rootfs.cpio"
fi
[ -f guest/rootfs.cpio ] || { echo "missing pinned fixture guest/rootfs.cpio (run REGEN_GUEST=1)"; exit 1; }

# 2. embed the cpio as a flash blob. Align the blob to >=4 so the XIP'd FDPIC ELF
#    (Thumb text + word literal pools) lands on an even, word-aligned address — an
#    unaligned blob lands _start on an odd byte -> misaligned Thumb -> INVSTATE/NOCP.
{ echo "/* generated from guest/rootfs.cpio — do not edit */"
  xxd -i guest/rootfs.cpio | sed 's/unsigned char guest_rootfs_cpio\[\]/const unsigned char rootfs_cpio[] __attribute__((aligned(16)))/; s/unsigned int guest_rootfs_cpio_len/const unsigned int rootfs_cpio_len/'
} > rootfs_cpio.h

# 3. firmware
bash build.sh > build.log 2>&1 || { echo "BUILD FAILED"; grep -iE 'error|undefined|will not fit' build.log | head; exit 1; }

# 4. run + assert (redirect to a file — QEMU semihosting output isn't captured by $() )
echo "=== M1 QEMU run ==="
mkdir -p build
LOG="$HERE/build/m1.log"
timeout "${TIMEOUT:-10}" "$QEMU" -M mps2-an500 -m 16 -nographic -no-reboot \
    -semihosting-config enable=on -kernel firmware.elf > "$LOG" 2>&1 || true
cat "$LOG"
echo "=== verdict ==="
grep -q "lxp-m1-ok" "$LOG" && echo "PASS: lxp-m1-ok" || { echo "FAIL"; exit 1; }
