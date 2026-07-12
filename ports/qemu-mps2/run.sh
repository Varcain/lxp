#!/bin/bash
# Build the firmware for a milestone from the pinned guest fixture and assert the
# guest marker under QEMU. Run from ports/qemu-mps2/ (after `bash fetch-deps.sh`).
#
#   M=1 bash run.sh   (default)  -> /hello           -> "lxp-m1-ok"
#   M=2 bash run.sh              -> /init execs /child -> "lxp-m2-ok"
#
# By default this uses the committed guest/rootfs.cpio fixture (holds every
# milestone's programs), so CI needs only arm-none-eabi-gcc + qemu-system-arm (NOT
# the Buildroot FDPIC toolchain). Set REGEN_GUEST=1 to rebuild the fixture from the
# guest/*.c sources (needs the FDPIC gcc).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
FDCC="${FDCC:-$HOME/projects/private/hIRoic/buildroot/output/host/bin/arm-buildroot-uclinuxfdpiceabi-gcc}"
QEMU="${QEMU:-/usr/bin/qemu-system-arm}"

M="${M:-1}"
case "$M" in
    1) ENTRY="/hello"; MARK="lxp-m1-ok" ;;
    2) ENTRY="/init";  MARK="lxp-m2-ok" ;;
    *) echo "unknown milestone M=$M (use 1 or 2)"; exit 2 ;;
esac

# The programs baked into the pinned fixture (source lives in guest/*.c).
GUESTS="hello init child"

# 1. (optional) regenerate the pinned guest fixture from source.
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

# 2. embed the cpio as a flash blob. Align the blob to >=4 so the XIP'd FDPIC ELF
#    (Thumb text + word literal pools) lands on an even, word-aligned address — an
#    unaligned blob lands _start on an odd byte -> misaligned Thumb -> INVSTATE/NOCP.
{ echo "/* generated from guest/rootfs.cpio — do not edit */"
  xxd -i guest/rootfs.cpio | sed 's/unsigned char guest_rootfs_cpio\[\]/const unsigned char rootfs_cpio[] __attribute__((aligned(16)))/; s/unsigned int guest_rootfs_cpio_len/const unsigned int rootfs_cpio_len/'
} > rootfs_cpio.h

# 3. firmware (bake in the milestone's entry program)
GUEST_ENTRY="$ENTRY" bash build.sh > build.log 2>&1 || { echo "BUILD FAILED"; grep -iE 'error|undefined|will not fit' build.log | head; exit 1; }

# 4. run + assert (redirect to a file — QEMU semihosting output isn't captured by $() )
echo "=== M$M QEMU run ($ENTRY) ==="
mkdir -p build
LOG="$HERE/build/m$M.log"
timeout "${TIMEOUT:-10}" "$QEMU" -M mps2-an500 -m 16 -nographic -no-reboot \
    -semihosting-config enable=on -kernel firmware.elf > "$LOG" 2>&1 || true
cat "$LOG"
echo "=== verdict ==="
grep -q "$MARK" "$LOG" && echo "PASS: $MARK" || { echo "FAIL"; exit 1; }
