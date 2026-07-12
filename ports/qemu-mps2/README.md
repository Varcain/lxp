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
| `guest/rootfs.cpio` | **pinned fixture** — every milestone's built guests, committed so CI needs no FDPIC toolchain |

## Prerequisites

- `qemu-system-arm` (mps2-an500 machine)
- `arm-none-eabi-gcc` (bare-metal, for the firmware)
- **only for `REGEN_GUEST=1`:** a uClinux FDPIC toolchain
  (`arm-buildroot-uclinuxfdpiceabi-gcc`) to rebuild `guest/rootfs.cpio` from source

Override tool paths via env: `ARMCC`, `QEMU`, `FDCC`.

## Usage

```sh
bash fetch-deps.sh          # once — vendors FreeRTOS-Kernel
M=1 bash run.sh             # M1: /hello       -> asserts "lxp-m1-ok"  (default M=1)
M=2 bash run.sh             # M2: /init execs /child -> asserts "lxp-m2-ok"
REGEN_GUEST=1 bash run.sh   # rebuild guest/rootfs.cpio from guest/*.c first (needs FDPIC gcc)
```

`run.sh` exits 0 and prints `PASS: lxp-m<N>-ok` on success.

## Milestones

- **M1** — static-FDPIC `hello` (`write`+`exit`) end-to-end. **Done.**
- **M2** — `pipe` + `vfork` + `execve` + `wait4` across slots (multi-slot spawn_launch +
  spawn_resume, pipe IPC, reaped exit status). **Done.**
- **M3** — dynamic-FDPIC busybox, unprivileged + full MPU, PSRAM XIP rootfs. (todo)

## Gotchas (learned the hard way)

- **Thumb entry bit.** Cortex-M is Thumb-only. The guest entry PC handed to
  `prog_tramp`'s `bx` must have bit 0 set, else the core switches to ARM state →
  `INVSTATE` UsageFault. `engine.c` forces it (`c.pc | 1u`).
- **cpio alignment.** The embedded cpio blob is XIP'd in place, so the FDPIC ELF's
  Thumb text and its word literal pools must be word-aligned. An unaligned blob
  lands `_start` on an odd byte → misaligned Thumb → `INVSTATE`/`NOCP`. `run.sh`
  aligns the generated `rootfs_cpio[]` to 16.
- **FPU-less FreeRTOS port.** The build uses the `ARM_CM3` (FPU-less, soft-float)
  FreeRTOS port on the CM7 to avoid FPU lazy-stacking hazards in the SVC exception
  context; soft-float everywhere. The CM7 runs the ARMv7-M subset fine.
