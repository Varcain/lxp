# Guest rootfs fixtures: contents and sources

Two cpio archives in this directory are committed so CI can run the QEMU milestones without a
Buildroot toolchain.

## `rootfs.cpio`: this repository's test guests

`child`, `futex`, `hello`, `init`, `schedtest`, `spin` and `syscheck`, built from the
`guest/*.c` files next to this document with `-nostdlib`. They contain no third-party code.
`REGEN_GUEST=1 bash run.sh` rebuilds the archive (requires `FDCC`, see the port README).

## `rootfs_m3.cpio`: BusyBox and uClibc-ng binaries

| Path | Component | License | sha256 |
|---|---|---|---|
| `bin/busybox` | BusyBox 1.38.0 | GPL-2.0-only | `c16424a56cabab078e4de541bb79c98896217e9daae12ffc803929e41889ea9e` |
| `lib/ld-uClibc-1.0.58.so` | uClibc-ng 1.0.58 dynamic loader | LGPL-2.1-or-later | `8d210eb27aacbc795cb89c3b9319c80354190ea09bfa0f632154109cafb80c72` |
| `lib/libuClibc-1.0.58.so` | uClibc-ng 1.0.58 C library | LGPL-2.1-or-later | `74dabc3f35fdb8ccf59f3f7d5ae1d890620712199e79080db5e14d13f8af3a52` |
| `lib/ld-uClibc.so.0`, `lib/ld-uClibc.so.1`, `lib/libc.so.0` | symlinks to the files above | | |

### Corresponding source

| Component | Upstream source | sha256 of the tarball |
|---|---|---|
| BusyBox 1.38.0 | <https://www.busybox.net/downloads/busybox-1.38.0.tar.bz2> | `34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2` |
| uClibc-ng 1.0.58 | <https://downloads.uclibc-ng.org/releases/1.0.58/uClibc-ng-1.0.58.tar.xz> | `9e8100a442f7079b9728ca286e3035f67df0578606166ea2d1ef865a4a12ddb9` |

The binaries were built on 2026-07-09 by Buildroot:

- Tree: commit `8b9b62de5d8b8d832ddd7fff61883e72068c4226` on the `lxp` branch of
  <https://github.com/Varcain/buildroot>. That branch adds local `board/overtos` and
  `configs/overtos*` commits on top of upstream Buildroot master
  `6f39a9ba291db640ec5171fb9a14b1ff7c69d186`.
- None of the local commits change `package/busybox` or `package/uclibc`. The only patches
  applied are Buildroot's own `package/busybox/0001`–`0011`; uClibc-ng is unpatched.
- Build configuration, vendored here from that commit:
  - `buildroot/overtos_fdpic_defconfig` (`configs/overtos_fdpic_defconfig`)
  - `buildroot/busybox.config` (`board/overtos/busybox.config`, selected by
    `BR2_PACKAGE_BUSYBOX_CONFIG`)
- uClibc-ng was configured by Buildroot from its default `package/uclibc/uClibc-ng.config`
  plus the options selected by the defconfig.
- The defconfig's rootfs overlay, post-build script and `overtos-lvbench` package do not
  change these binaries, with one exception: `post-build.sh` runs
  `strip --strip-unneeded` on `busybox` and `libuClibc-*.so`.

### Rebuilding

```sh
make overtos_fdpic_defconfig && make                          # in the Buildroot tree above
BR_TARGET=/path/to/buildroot/output/target bash guest/mkrootfs_m3.sh
```

`mkrootfs_m3.sh` copies exactly the files listed above into a reproducible archive
(`cpio --reproducible`, sorted names).
