#!/bin/bash
# Build the firmware for a milestone and assert the guest marker under QEMU.
# Run from ports/qemu-mps2/ (after `bash fetch-deps.sh`).
#
#   M=1 bash run.sh   (default)  -> /hello                 -> "lxp-m1-ok"
#   M=2 bash run.sh              -> /init execs /child     -> "lxp-m2-ok"
#   M=3 bash run.sh              -> /bin/busybox echo ...  -> "lxp-m3-ok"
#
# M1/M2 embed a small cpio in flash (pinned guest/rootfs.cpio; CI needs only
# arm-none-eabi-gcc + qemu). M3 XIPs a big dynamic-FDPIC busybox cpio from PSRAM
# @0x60000000 via `-device loader`; M3_CPIO points at it (default: the Buildroot
# image). Set REGEN_GUEST=1 to rebuild the M1/M2 fixture from guest/*.c (FDPIC gcc).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
FDCC="${FDCC:-$HOME/projects/private/hIRoic/buildroot/output/host/bin/arm-buildroot-uclinuxfdpiceabi-gcc}"
QEMU="${QEMU:-/usr/bin/qemu-system-arm}"

M="${M:-1}"
case "$M" in
    1) MARK="lxp-m1-ok" ;;
    2) MARK="lxp-m2-ok" ;;
    3) MARK="lxp-m3-ok" ;;
    4) MARK="lxp-m4-ok" ;;
    *) echo "unknown milestone M=$M (use 1, 2, 3 or 4)"; exit 2 ;;
esac

mkdir -p build
LOG="$HERE/build/m$M.log"

if [ "$M" -lt 3 ] || [ "$M" = 4 ]; then
    # ---- M1/M2/M4: small cpio embedded in flash .rodata ---------------------
    GUESTS="hello init child syscheck spin"
    if [ "${REGEN_GUEST:-0}" = 1 ]; then
        [ -x "$FDCC" ] || { echo "REGEN_GUEST=1 but FDPIC gcc not found: $FDCC"; exit 1; }
        ( cd guest
          rm -rf root && mkdir root
          for g in $GUESTS; do
              "$FDCC" -mfdpic -static -nostdlib -Os -ffreestanding -e _start -I. -o "$g.elf" "$g.c"
              cp "$g.elf" "root/$g"
          done
          cd root && printf '%s\n' $GUESTS | cpio -o -H newc 2>/dev/null > ../rootfs.cpio )
        echo "regenerated pinned fixture guest/rootfs.cpio ($GUESTS)"
    fi
    [ -f guest/rootfs.cpio ] || { echo "missing pinned fixture guest/rootfs.cpio (run REGEN_GUEST=1)"; exit 1; }

    # Embed the cpio as a flash blob, aligned to >=4 so the XIP'd FDPIC ELF (Thumb text +
    # word literals) lands word-aligned — an unaligned blob -> misaligned Thumb -> fault.
    { echo "/* generated from guest/rootfs.cpio — do not edit */"
      xxd -i guest/rootfs.cpio | sed 's/unsigned char guest_rootfs_cpio\[\]/const unsigned char rootfs_cpio[] __attribute__((aligned(16)))/; s/unsigned int guest_rootfs_cpio_len/const unsigned int rootfs_cpio_len/'
    } > rootfs_cpio.h

    MILESTONE="$M" bash build.sh > build.log 2>&1 || { echo "BUILD FAILED"; grep -iE 'error|undefined|will not fit' build.log | head; exit 1; }

    echo "=== M$M QEMU run ==="
    timeout "${TIMEOUT:-10}" "$QEMU" -M mps2-an500 -m 16 -nographic -no-reboot \
        -semihosting-config enable=on -kernel firmware.elf > "$LOG" 2>&1 || true
else
    # ---- M3: dynamic-FDPIC busybox cpio XIP'd from PSRAM @0x60000000 ---------
    # Default: the committed minimal fixture (rebuild with guest/mkrootfs_m3.sh). Point
    # M3_CPIO at a full Buildroot output/images/rootfs.cpio to run the complete rootfs.
    M3_CPIO="${M3_CPIO:-$HERE/guest/rootfs_m3.cpio}"
    [ -f "$M3_CPIO" ] || { echo "missing M3 rootfs cpio: $M3_CPIO (build it: bash guest/mkrootfs_m3.sh)"; exit 1; }
    echo "M3 rootfs: $M3_CPIO ($(stat -c %s "$M3_CPIO") bytes)"

    MILESTONE=3 bash build.sh > build.log 2>&1 || { echo "BUILD FAILED"; grep -iE 'error|undefined|will not fit' build.log | head; exit 1; }

    echo "=== M3 QEMU run (/bin/busybox echo) ==="
    timeout "${TIMEOUT:-30}" "$QEMU" -M mps2-an500 -m 16 -nographic -no-reboot \
        -semihosting-config enable=on -kernel firmware.elf \
        -device "loader,file=$M3_CPIO,addr=0x60000000,force-raw=on" > "$LOG" 2>&1 || true
fi

cat "$LOG"
echo "=== verdict ==="
grep -q "$MARK" "$LOG" && echo "PASS: $MARK" || { echo "FAIL"; exit 1; }
