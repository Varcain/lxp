#!/bin/bash
# Assemble the minimal dynamic-FDPIC busybox rootfs cpio (the committed M3 fixture,
# guest/rootfs_m3.cpio) from a Buildroot FDPIC target tree. Only what busybox needs:
# the binary, its interpreter (/lib/ld-uClibc.so.0) and libc (libc.so.0), plus the
# symlink chains — busybox's only NEEDED is libc.so.0 (no libgcc). ~620 KiB.
#
#   BR_TARGET=/path/to/buildroot/output/target bash mkrootfs_m3.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
BR_TARGET="${BR_TARGET:-$HOME/projects/private/hIRoic/buildroot/output/target}"
[ -x "$BR_TARGET/bin/busybox" ] || { echo "busybox not found under BR_TARGET=$BR_TARGET"; exit 1; }

W="$HERE/m3root"
rm -rf "$W"; mkdir -p "$W/bin" "$W/lib"
cp -a "$BR_TARGET/bin/busybox"             "$W/bin/"
cp -a "$BR_TARGET/lib/ld-uClibc-1.0.58.so" "$W/lib/"   # the real FDPIC loader
cp -a "$BR_TARGET/lib/ld-uClibc.so.0"      "$W/lib/"   # -> ld-uClibc.so.1  (busybox PT_INTERP)
cp -a "$BR_TARGET/lib/ld-uClibc.so.1"      "$W/lib/"   # -> ld-uClibc-1.0.58.so
cp -a "$BR_TARGET/lib/libuClibc-1.0.58.so" "$W/lib/"   # the real libc
cp -a "$BR_TARGET/lib/libc.so.0"           "$W/lib/"   # -> libuClibc-1.0.58.so  (busybox NEEDED)

# --reproducible zeroes mtime/inode so the committed fixture is byte-stable across regens.
( cd "$W" && find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc --reproducible 2>/dev/null > "$HERE/rootfs_m3.cpio" )
rm -rf "$W"
echo "wrote $HERE/rootfs_m3.cpio ($(stat -c %s "$HERE/rootfs_m3.cpio") bytes)"
