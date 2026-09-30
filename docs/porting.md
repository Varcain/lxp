# Porting lxp to an RTOS

A port lets lxp run guests on one RTOS: it turns lxp's process model into that RTOS's tasks,
exceptions and memory protection. This guide walks through writing one. Read
[architecture.md](architecture.md) for how the core, the coordinator and the ports fit together,
and [port-ownership.md](port-ownership.md) for what belongs in a port and what belongs to the
embedding system.

The three production ports, `ports/freertos`, `ports/nuttx` and `ports/zephyr`, are the
references. `ports/qemu-mps2` builds the FreeRTOS port into a standalone firmware and is the
smallest complete embedding to read alongside this guide.

## What a port provides

A port is one translation unit under `ports/<rtos>/`, plus a public header
`include/lxp/ports/<rtos>.h` that declares its configuration. It defines:

- `const lxp_os_ops_t g_lxp_host_engine`, the engine table (`include/lxp/lxp_port.h`), which the
  embedding passes as `lxp_providers_t.os`;
- the RTOS's exception entry for a guest `svc #0` and for guest faults;
- a configuration type (`lxp_<rtos>_port_config_t`) and the declaration of the one instance the
  embedding supplies (`g_lxp_<rtos>_port_config`). Board facts reach the port only through it.

Only a port may include native RTOS headers. `scripts/check-decoupled.sh` fails if a port names a
consumer, and a consumer's build should check the reverse.

## The engine table

`lxp_os_ops_t` groups its operations by role. `lxp_os_ops_valid()` (`src/run/lxp_validate.c`)
rejects a table that lacks a required operation, and `lxp_run()` then returns
`LXP_ERR_INVALID_PARAM`.

| Table | Operations | Notes |
|---|---|---|
| `core` | `prepare`, `teardown`, `crit_enter`, `crit_exit`, `event_post`, `event_wait` | `prepare`/`teardown` are optional; the critical section and the run-loop event are required. |
| `task` | `spawn_launch`, `spawn_resume`, `abort_slot`, `park_entry`, `park_prepare`, `park_slot`, `guest_stack_usage` | All but `guest_stack_usage` are required. Each takes an `lxp_slot_ref_t` and must reject a stale generation. |
| `memory` | `region`, `dyn_pool`, `exec_capture`, `exec_stage`, `map_device`, `publish_executable`, `coord_map`, `rootfs_window`, `cache_clean`, `cache_invalidate`, `cpu_memory_contract`, `validate_memory_contract` | `region`, `exec_capture`, `publish_executable` and the memory contract are required; `exec_stage` is required with `LXP_ENABLE_NETFS_EXEC`. |
| `services` | `time_us`, `time_ns`, `thread_list`, `mem_stats`, `system_version`, `random_fill` | The clock and entropy are required. |

Each operation's comment in `lxp_port.h` is its contract: the context it runs in, what a failure
must leave behind, and what `NULL` means for an optional one.

## Guest tasks

Every guest process runs in a slot, as one native task that the port owns.

1. **Launch.** `task.spawn_launch(slot, ridx, launch)` creates the task for a new image in
   program region `ridx` and starts it at `launch`'s registers. Record the slot reference's
   generation before any API that can schedule the task: a guest may trap before the call
   returns.
2. **Run unprivileged.** The task runs the guest unprivileged, behind MPU regions that grant only
   its own program region and dynamic pool (plus shared read-only text and granted devices).
3. **Park.** A syscall the trap cannot answer inline parks the guest. The core calls
   `task.park_prepare(slot, ctx)` from the SVC exception; it may return a token that the core
   passes to `task.park_entry` in `r0`, the engine's guest-executable wait target. Later the
   coordinator calls `task.park_slot(slot)` to block the native task.
4. **Resume.** `task.spawn_resume(slot, ridx, LXP_SPAWN_RESUME_PARKED, ctx, r0)` restores the
   captured context (`struct lxp_resume_ctx`, including the syscall result in `r0` and the
   condition flags) and makes the same task runnable. A fork child arrives with
   `LXP_SPAWN_RESUME_START` and gets a new task.
5. **Abort.** `task.abort_slot(slot)` deletes the task. It must be idempotent: the core also uses
   it to clean up after a failed launch or resume.

Parking must reuse the task. Deleting and recreating it on every blocking syscall is not a
supported lifecycle.

## The trap

The port's SVC entry turns the native exception frame into a `struct lxp_frame` (`lxp_seam.h`):
`r0`-`r15`, `xpsr`, and on a hard-float build the VFP state. It then calls
`lxp_dispatch_slot(slot, &frame)` and writes the frame back.

- Find the slot from the running native task. Check `lxp_trap_active()` first, and treat an SVC
  from a task that is not a guest as the RTOS's own.
- `r13` in the frame is the guest's stack pointer before the exception: the frame address plus
  the stacked bytes (32, plus 72 for an extended FP frame, plus 4 when the hardware aligned the
  stack).
- Write back `r4`-`r11` as well as the stacked registers. `rt_sigreturn` restores a guest's
  callee-saved registers, including `r9`, the FDPIC GOT pointer.
- Before dispatching, confirm the guest's MPU profile is the one its policy describes (see
  below). If it is not, report a memory fault with `LXP_CORTEX_M_MPU_PROFILE_FAULT` and return
  to the park entry instead of running the syscall.

## Memory protection

`lxp_slot_memory_policy(slot, &policy)` describes, in portable terms, what the running guest may
touch: its address space, its copied executable text, and its device grants. A port compiles
that policy into native MPU descriptors when it installs a guest.

- Cache the compiled profile under `lxp_memory_policy_make_key()`, and recompile only when
  `lxp_memory_policy_matches_key()` or `lxp_memory_policy_key_equal()` says the policy changed.
- After programming the MPU, read it back and check each region with
  `lxp_cortex_m_mpu_snapshot_region_holds()`, so a descriptor the RTOS rewrote or a stale
  higher-numbered region fails closed.
- `memory.cpu_memory_contract` declares the cache model. `validate_memory_contract` checks it
  against the live hardware after `prepare`, before any guest image is loaded.
- `memory.publish_executable` makes loader-written text visible to instruction fetch. Implement
  it even on a coherent machine, as a validated no-op.

## Fault containment

A guest's MemManage, BusFault or UsageFault must not take the system down.

1. Enable the configurable fault handlers (`SHCSR`) in `prepare`.
2. In the handler, if the fault came from a guest, read the fault status
   (`lxp_cortex_m_fault_status_read()`, `lxp_cortex_m_fault_address()`), report it with
   `lxp_slot_report_memory_fault()`, clear the status, and return to the park entry. The
   coordinator reaps the guest with status 139 (SIGSEGV).
3. A fault from privileged code is a host bug: pass it to the RTOS's fatal path.

The handler must not execute a VFP instruction before it has dealt with a pending lazy FP
store: an invalid guest stack would make the store fault again.

## Cortex-M ports

Ports for ARMv7-M share code under `include/lxp/arch/` and `ports/common/`:

| Where | What |
|---|---|
| `include/lxp/arch/cortex_m_scb.h` | SCB registers, fault status and address, barriers. |
| `include/lxp/arch/cortex_m_mpu.h` | MPU registers, RASR encoding (`lxp_cortex_m_mpu_rasr()`), snapshots and region checks. |
| `include/lxp/arch/cortex_m_cache.h` | Cache geometry and maintenance, executable publication. |
| `include/lxp/ports/cortex_m.h` | `lxp_cortex_m_port_common_t`, the configuration every Cortex-M port embeds as `.common`. |
| `ports/common/lxp_cortex_m_port.c` | The engine operations that only read `.common`, and the checks of it. A port binds them directly and defines `g_lxp_cortex_m_port_common`. |
| `ports/common/lxp_cortex_m_context.h` | Lazy-FP capture and write-back, and `LXP_CORTEX_M_RESUME_FROM_R3`, the trampoline tail that restores a `struct lxp_resume_ctx`. |

A new Cortex-M port embeds `.common` first in its configuration, calls
`lxp_cortex_m_port_config_valid()`, `lxp_cortex_m_port_cache_prepare()` and
`lxp_cortex_m_port_host_prepare()` from its `prepare`, and keeps only what its RTOS makes
different.

## Building

Compile the port unit and, for a Cortex-M port, `ports/common/lxp_cortex_m_port.c`, together
with lxp's source groups from `cmake/lxp_sources.cmake` (`LXP_CORE_SOURCES`,
`LXP_COORDINATOR_SOURCES`, `LXP_PORT_SUPPORT_SOURCES` and the enabled optional groups). Set the
same `LXP_ENABLE_*` and sizing definitions for every unit, including the port. The port needs
`include/` on its include path, never `src/`.

## Verifying a port

The host tests cover the core, not the ports. Check a new port with:

1. a standalone fixture in the style of `ports/qemu-mps2`: a guest that writes and exits, then a
   parent that pipes, vforks, execs and waits (`run.sh M=1`, `M=2`);
2. BusyBox from a real rootfs: the shell, pipelines, 100 fork/execs, `^C`;
3. the containment cases: a guest that faults (`segv`, exit 139) while its shell survives, and a
   kernel-pointer syscall (`kstress`);
4. on a hard-float build, `fpcheck` and `sigctx`, which check every VFP register across
   blocking syscalls and signals;
5. the same list on the target hardware. QEMU does not model caches, and its MPU checks are
   more lenient than silicon.
