# Architecture

lxp runs unmodified Linux programs (ARM FDPIC ELF, uClibc, BusyBox) on an MMU-less Cortex-M
under a host RTOS. It is a library: the host gives it an RTOS port and a set of providers and
calls `lxp_run()`, and lxp owns everything between a guest's `svc #0` and the host services
that answer it.

## Layers

| Layer | Where | What it is |
|---|---|---|
| Embedding API | `include/lxp/lxp_run.h`, `lxp_host.h`, `lxp_observe.h`, `lxp_debug.h` | What a host calls: run a program, build a reusable host from a CPIO image, observe a finished run, find guest programs from a debugger. |
| Provider and port contracts | `include/lxp/lxp_port.h`, `lxp_seam.h`, `lxp_*_ops.h`, `include/lxp/ports/*.h` | What a host implements: the RTOS port (`lxp_os_ops_t`) and the optional net, display, fs and block providers. |
| Guest ABI | `include/uapi/lxp/` | LXP's extensions to the Linux ABI, for guest programs to include. |
| Core | `src/` (the `LXP_CORE_SOURCES` group) | The syscall layer, the VFS and its filesystems, processes, signal policy, the loader. It needs only the provider contracts. |
| Coordinator | `src/run/`, `src/lxp_run.c`, `src/lxp_signal.c`, `src/lxp_host.c` | The run loop that drives processes through the port: traps, fork/exec/exit, waits, signals, diagnostics. |
| Port support | `src/lxp_async_gate.c`, `lxp_latency.c`, `lxp_rt_metrics.c` | Self-contained helpers that ports and hosts link beside the core. |
| Ports | `ports/freertos`, `ports/nuttx`, `ports/zephyr`, `ports/posix`, `ports/qemu-mps2` | Optional `lxp_os_ops_t` implementations. Only here may native RTOS headers appear. `ports/common` holds the services the Cortex-M ports share; a consumer builds it beside its port. |

`cmake/lxp_sources.cmake` lists every translation unit in exactly one of these groups (plus
the optional groups that follow the feature gates) and fails configuration when a new `src/*.c`
is not classified.

## Source map

| Directory | Contents |
|---|---|
| `src/` | Syscall dispatch (`lxp_syscall.c`), provider wrappers, the loader, the arena allocator, bootstrap (CPIO to rootfs table), error translation, host facade, run loop. |
| `src/sys/` | Syscall handlers by area: fd, path, memory, process, time, signal, exec. |
| `src/fs/` | The VFS: fd table, per-kind file operations, mount table, path resolution, rootfs, tmpfs overlay, hostfs, pipes, console, tty, poll, stat. |
| `src/proc/` | The process model (`lxp_proc_t` and its shared parts), `/proc`, `#!` scripts, exec staging. |
| `src/run/` | The coordinator's units: trap top half, fork, exec, exit, image launch, regions, futex, blocked-wait scan, signal routing, diagnostics, validation, the runtime record. |
| `src/signal/` | Signal policy: which signal is deliverable, and termination. |
| `src/net/`, `src/netfs/`, `src/pty/`, `src/dev/` | Optional subsystems: sockets, the 9P client, pseudo-terminals, `/dev` devices. |

## A syscall's path

1. A guest executes `svc #0`. The port's SVC handler captures the frame and calls the trap top
   half (`src/run/lxp_trap.c`).
2. The trap answers **fast** syscalls inline (table flag `LXP_SYS_FAST`, e.g. `getpid`) and
   handles the calls that act across slots (`kill`, `fork`, `futex`, `sigreturn`).
3. Every other syscall parks the guest with its resume context captured and posts an event to
   the **coordinator**, which runs on its own privileged host task.
4. The coordinator dispatches through the dense table in `src/lxp_syscall.c`
   (`[LXP_NR_x] = {lxp_sys_x, flags}`) and resumes the guest with the result.
5. A call that must wait (a pipe read, a socket connect, a netfs reply) parks the process with
   `lxp_wait_park()`. The coordinator's blocked-wait scan retries it when its wait class may
   have become ready, and resumes the guest once it completes.

Because only the coordinator executes deferred syscalls, the core needs no locking: provider
calls are serialized on that one task.

## State

The coordinator keeps its state in one record, `struct lxp_runtime g_lxp_rt`
(`src/run/lxp_runtime_store.h`): the run configuration, slots, program regions, arenas,
vfork snapshots, diagnostics and the exec scratch. Three objects stay separately named
because something outside the record finds them by name:

- the trap gate, which port SVC assembly loads;
- `g_lxp_sig_save`, the signal-save stacks, placed through `LXP_SIGNAL_STATE_SECTION` so a
  linker script can put them in tightly coupled memory;
- `g_lxp_dbg`, the debugger records (`include/lxp/lxp_debug.h`).

Every live process occupies a slot and runs in one of `LXP_NREG` fixed program regions. There
is no MMU, so `fork` is vfork-style: the child borrows the parent's region, whose writable data
is snapshotted and restored when the child execs or exits.

## Providers

`lxp_run()` takes an `lxp_providers_t`:

- `os`, the RTOS port (required): program memory, task spawn and abort, the run-loop event,
  time, cache maintenance, optional thread introspection.
- `net`, `display` (`fb`, `dma2d`, `touch`), `fs` and `block`: each optional, and used only
  when its feature gate is on.

The run configuration (`lxp_run_config_t`) adds the rootfs, the network interface, the netfs
mount and the launch policy (`lxp_launch_config_t`): the console, environment, exit and
ENOSYS hooks, and the names a guest sees for the system.

## Errors

Each layer uses one error domain:

- the public, port and provider boundary: `lxp_err_t` (`include/lxp/lxp_types.h`);
- inside the coordinator and the process layer: 0 or a negated errno;
- towards the guest: errno only.

`src/lxp_errno.c` holds the one table from `lxp_err_t` to errno and its inverse.

## Configuration

Every tunable and feature gate is defined in `include/lxp/lxp_config.h`, overridable with a
`-D` and range-checked there. `cmake/lxp_features.cmake` is the one list of feature gates and
their owners; the standalone build, the tests and the fuzzers derive their definitions from it,
and `scripts/check-features.sh` ties it to `lxp_config.h` and CI.

## Checks

| Script | Guards |
|---|---|
| `scripts/check-decoupled.sh` | No consumer is named anywhere; native RTOS headers only in `ports/`. |
| `scripts/syscalls/check-syscalls.sh` | Every syscall number has one disposition, and the table matches it. |
| `scripts/check-guest-memory.sh` | Guest pointers are reached only through the copy helpers. |
| `scripts/check-header-contract.sh` | Public headers stand alone in C11/C++17, guest ABI headers in C99. |
| `scripts/check-config-contract.sh` | Invalid gate combinations and out-of-range tunables are rejected. |
| `scripts/check-symbols.sh` | Every exported symbol carries the `lxp_` prefix. |
| `scripts/check-features.sh` | The feature table, `lxp_config.h` and the CI legs agree. |
| `scripts/gate-build.sh` | Every unit cross-compiles for Cortex-M under each gate combination. |

[extending.md](extending.md) adds a syscall, a descriptor kind, a device or a mount backend;
[porting.md](porting.md) adds a port for another RTOS.
