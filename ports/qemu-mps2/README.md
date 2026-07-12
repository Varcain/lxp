# lxp QEMU harness — Arm MPS2-AN500 (Cortex-M7) on FreeRTOS

A standalone, end-to-end test harness that runs the lxp Linux personality under
`qemu-system-arm -M mps2-an500`, with a vendored FreeRTOS kernel supplying the
task/context-switch primitives. It is a de-oveRTOS'd distillation of oveRTOS's
`backends/freertos/freertos_lnx.c`: each guest process is a FreeRTOS task whose
Linux syscalls trap to `SVC_Handler` → `lxp_dispatch()`.

The harness lives entirely under `ports/` and pulls in **no** `src/`/`include/`
dependency on any OS, so `scripts/check-decoupled.sh` still passes.

## Layout

| file | role |
|------|------|
| `fetch-deps.sh` | clones FreeRTOS-Kernel into `vendor/` (gitignored — never committed) |
| `engine.c` | fills `lxp_os_ops_t` on top of FreeRTOS (SVC trap, fault containment, spawn/resume, region placement) |
| `boot.c` | reset/vectors, semihosting console + exit, tick clock, coordinator task that calls `lxp_run()` |
| `board/FreeRTOSConfig.h`, `board/mps2_an500.ld` | board config + link map |
| `build.sh` | cross-compiles the module + FreeRTOS + engine/boot into `firmware.elf` (bakes in `GUEST_ENTRY`) |
| `run.sh` | selects a milestone (`M=1`/`M=2`), (re)generates the embedded cpio, builds, runs QEMU, asserts the marker |
| `guest/lxpsys.h` | shared FDPIC syscall shims (inline `svc`, no libc, no GOT dependency) |
| `guest/hello.c` | the M1 guest (static FDPIC: `write` + `exit_group`) |
| `guest/init.c` | the M2 parent (`pipe` + `vfork` + `execve(/child)` + `wait4`, verifies the round trip) |
| `guest/child.c` | the M2 exec'd child (writes a byte to the inherited pipe end, exits with a code) |
| `guest/rootfs.cpio` | **M1/M2 pinned fixture** — the built hand-written guests (embedded in flash) |
| `guest/mkrootfs_m3.sh` | rebuilds the minimal busybox rootfs from a Buildroot FDPIC target tree |
| `guest/rootfs_m3.cpio` | **M3 pinned fixture** — minimal dynamic-FDPIC busybox (busybox + ld.so + libc, ~620 KiB) |

## Prerequisites

- `qemu-system-arm` (mps2-an500 machine)
- `arm-none-eabi-gcc` (bare-metal, for the firmware)
- **only for `REGEN_GUEST=1`:** a uClinux FDPIC toolchain
  (`arm-buildroot-uclinuxfdpiceabi-gcc`) to rebuild `guest/rootfs.cpio` from source

Override tool paths via env: `ARMCC`, `QEMU`, `FDCC`.

## Usage

```sh
bash fetch-deps.sh          # once — vendors FreeRTOS-Kernel
M=1 bash run.sh             # M1: /hello             -> asserts "lxp-m1-ok"  (default M=1)
M=2 bash run.sh             # M2: /init execs /child -> asserts "lxp-m2-ok"
M=3 bash run.sh             # M3: /bin/busybox echo  -> asserts "lxp-m3-ok"  (busybox from PSRAM)
REGEN_GUEST=1 bash run.sh   # rebuild guest/rootfs.cpio from guest/*.c first (needs FDPIC gcc)
```

`run.sh` exits 0 and prints `PASS: lxp-m<N>-ok` on success. M1/M2 embed a small cpio in
flash; M3 XIPs `guest/rootfs_m3.cpio` from PSRAM `@0x60000000` (QEMU `-device loader`).
Point `M3_CPIO=...` at a full Buildroot `output/images/rootfs.cpio` to run the complete
rootfs (~11 MiB) instead of the minimal fixture.

## Milestones

- **M1** — static-FDPIC `hello` (`write`+`exit`) end-to-end. **Done.**
- **M2** — `pipe` + `vfork` + `execve` + `wait4` across slots (multi-slot spawn_launch +
  spawn_resume, pipe IPC, reaped exit status). **Done.**
- **M3a** — dynamic-FDPIC busybox: `ld-uClibc.so.0` + `libuClibc` loaded/relocated, libc
  mmap'd into the PSRAM `dyn_pool`, cpio XIP'd from PSRAM. Runs **privileged**. **Done.**
- **M3b** — unprivileged guests + per-slot MPU (W^X) via the ARM_CM4_MPU port. All three
  milestones run unprivileged; a stray access faults MemManage (contained as SIGSEGV).
  **Done.**

## Gotchas (learned the hard way)

- **Thumb entry bit.** Cortex-M is Thumb-only. The guest entry PC handed to
  `prog_tramp`'s `bx` must have bit 0 set, else the core switches to ARM state →
  `INVSTATE` UsageFault. `engine.c` forces it (`c.pc | 1u`).
- **cpio alignment.** The embedded cpio blob is XIP'd in place, so the FDPIC ELF's
  Thumb text and its word literal pools must be word-aligned. An unaligned blob
  lands `_start` on an odd byte → misaligned Thumb → `INVSTATE`/`NOCP`. `run.sh`
  aligns the generated `rootfs_cpio[]` to 16.
- **MPU region count.** `configTOTAL_MPU_REGIONS` must equal the hardware MPU region
  count (QEMU's an500 CM7 reports 16) or the ARM_CM4_MPU port SILENTLY skips all MPU
  setup and then HardFaults at scheduler start.
- **CM4_MPU + softfp, not CM3_MPU.** A dynamic M3 guest needs 4 per-task MPU regions
  (program + dyn_pool + two cpio windows); CM3_MPU exposes only 3, so the port is
  ARM_CM4_MPU. Its context switch has VFP save/restore asm, so the firmware is built
  `-mfloat-abi=softfp` (link-compatible with the soft-float guests; no firmware C uses
  float, so FPCA stays 0 and the FPU save never runs).
- **Syscall resume preserves r1-r3.** The Linux syscall ABI preserves r1-r14 (only r0
  is the return). A parking syscall that resumes must restore r1-r3, or a guest that
  reuses an arg register after the call reads garbage (this manifested as `wait4`
  intermittently taking WNOHANG). The module captures them (`lxp_resume_ctx`); the
  restore in `prog_tramp` stages `ctx.pc` 8 bytes below sp so it can't clobber the
  descriptor's own `ctx.r3` (`stash_desc` leaves that gap).
