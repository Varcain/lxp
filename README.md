# lxp — a Linux personality for MMU-less microcontrollers

`lxp` runs real, unmodified Linux userspace — busybox, dropbear, curl, LVGL apps — on an
ARM Cortex-M with **no MMU**, as a portable library on top of any RTOS or bare metal. It
presents a Linux/uClinux ABI (a ~130-call syscall core, an FDPIC ELF loader, `/proc`, `/dev`,
pipes, ptys, signals, `fork`/`exec`/`wait`, and an optional socket bridge + 9P filesystem)
with **zero dependency on any host OS** — the host fills in a few function-pointer structs
and calls `lxp_run()`. No `lxp` source includes a host header.

## Linux without a memory unit

A normal Linux leans on the MMU for nearly everything a process expects: private virtual
address spaces, binaries linked to fixed addresses, copy-on-write `fork`, demand-paged
`mmap`, a hardware user/kernel boundary. A Cortex-M has none of it — one flat physical
address space, no virtual memory, no page faults. `lxp` provides the personality anyway, by
replacing each MMU trick with something that works when every process shares one address
space:

- **FDPIC binaries + a per-process GOT as the MMU substitute.** With no MMU to map a program
  to its linked address, guests are FDPIC (function-descriptor PIC) ELFs — fully relocatable,
  each segment placed anywhere and reached through a per-process GOT, which supplies the
  position bias page tables otherwise would. So one read-only copy of each program and shared
  library (busybox, `libc.so`, `ld.so`) lives in flash and is executed in place by every
  process; only writable data, the GOT, and the heap are per-process in RAM.
- **The loader does the kernel's job.** There's no `binfmt_elf_fdpic` in a kernel underneath,
  so lxp's loader is it — it places the segments, self-applies the `R_ARM_RELATIVE` fixups,
  and builds the FUNCDESC `{func, GOT}` descriptors into each process's GOT, then hands
  dynamic executables to a stock `ld.so` for the rest.
- **`fork`/`vfork`/`clone` without copy-on-write.** You can't cheaply duplicate an address
  space that everyone shares, so the process model is cooperative: `fork`/`vfork` suspend the
  parent while the child runs in its memory — snapshotting the parent's writable data and
  restoring it around the window, so a child that scribbles shared state before `exec` can't
  corrupt it — while `clone(CLONE_VM)` co-runs as a thread. Enough for shells, pipelines, and
  daemons.
- **Deterministic spawning, no fragmentation.** Process slots and their program regions are
  carved upfront into fixed, statically-sized pools (`LXP_NSLOT` slots over `LXP_NREG`
  regions) — no heap, no buddy allocator. A spawn claims a free slot and region in bounded
  time; it never fragments and never fails partway for want of a contiguous block. Process
  count and RAM footprint are fixed at compile time.
- **`mmap` + `brk` over a bounded arena.** There is no page cache or demand paging: writable
  mappings are copied eagerly into a fixed region, while read-only rootfs text can execute
  in place. A full arena returns `ENOMEM` synchronously (no overcommit, no OOM killer). The
  stack is a fixed slice of that region: W^X stops a stray *execute*, but a stack that grows
  into the heap corrupts rather than page-faults. Arena block links are never guest-controlled,
  and `munmap` reclaims memory only for an exact live extent recorded in privileged metadata.
- **Software-checked user pointers.** With no hardware user/kernel split, every syscall
  validates guest pointers against the program's region bounds; on target the Cortex-M MPU
  adds per-task W^X isolation, so guests still run unprivileged.
- **Even signals swap the GOT.** A handler is itself a `{entry, GOT}` descriptor that may live
  in a different module (say libpthread) than the interrupted code, so delivery dereferences
  it and swaps r9 to the handler's GOT, restoring it at `sigreturn` — and the signal frame is
  built on the guest's own stack, since there's no kernel stack to borrow.

Guest-facing structs use fixed-width types, so the 32-bit-target ABI is byte-identical on a
64-bit host — the whole syscall layer is unit-tested natively, no emulator required.

## Using it

A host implements the port interface in `include/lxp/lxp_port.h` — OS ops (program-memory
placement, task spawn, run-loop event wait/post, monotonic time) plus optional net and
display ops — and calls:

```c
int rc = lxp_run(&os_ops, &net_ops, &display_ops, &cfg, &run_cfg, "/sbin/init", argc, argv);
```

Feature gates and sizing knobs live in `include/lxp/lxp_config.h`, set on the command line or
via a drop-in `lxp_config_user.h`.

## Building and testing

- **Standalone** (bundled POSIX port): `cmake -S . -B build -DLXP_PORT_POSIX=ON && cmake --build build`
- **Host unit tests** (cmocka, fetched at configure time): `cmake -S . -B build -DLXP_BUILD_TESTS=ON && ctest --test-dir build -R lxp_unit` — the OS-agnostic sources drive `lxp_syscall()` and the arena directly on x86-64, no emulator.
- **QEMU end-to-end** (Cortex-M7): `ports/qemu-mps2/` runs static and dynamic (busybox) FDPIC guests on `qemu-system-arm -M mps2-an500` under FreeRTOS, unprivileged behind the MPU — see its README.

## License

GPL-3.0-or-later.
