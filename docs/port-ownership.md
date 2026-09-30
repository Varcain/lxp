# Port ownership

LXP is a portable Linux personality with an OS-independent core and optional
host ports. This document is the ownership contract for integrations. Its
purpose is to prevent a consumer application from becoming the permanent home
of generally useful LXP mechanisms, while keeping board and product policy out
of LXP.

## Repository boundary

LXP owns:

- Linux ABI, process, scheduler, loader, VFS, device, network, and coordinator
  semantics;
- the public provider contracts in `include/lxp/`;
- reusable RTOS ports under `ports/<rtos>/`, including guest task lifecycle,
  SVC/trap entry, MPU profile installation, cache publication needed by guest
  executable memory, and RTOS-specific SVC accounting;
- architecture helpers used by those ports, under `include/lxp/arch/` rather
  than a consumer application;
- reusable host composition under `include/lxp/lxp_host.h`: early rootfs-window
  publication, zero-heap CPIO ingestion, immutable provider/rootfs/network
  topology capture, and construction of complete per-run contracts;
- the versioned, quiescent host observation in `include/lxp/lxp_observe.h`,
  which copies run health, world-validation results, object-size accounting,
  optional latency rows, and normalized native guest-stack usage without
  exposing process-global registries or an RTOS-specific accessor;
- generation-qualified asynchronous provider correlation under
  `include/lxp/lxp_async_gate.h`, including cancellation/completion races;
- Linux block-device reader/writer aggregation: providers acquire one native
  lease for the first reader through the last reader, or one exclusive writer;
- guest socket lifecycle, nonblocking publication, parked retry state, and the
  coordinator wakeup selected by a run-scoped provider readiness callback;
- run-scoped binding and clearing of the host-selected interface used by eth0
  ioctls and `/proc/net`, plus copying and clearing the optional 9P mount on
  every run so sequential hosts cannot inherit topology;
- console wait semantics and the run-scoped readiness subscription that turns
  a host RX notification into a coordinator wakeup without exposing a global
  LXP kick symbol;
- patches required to make a supported RTOS port implement LXP's task,
  privilege, or MPU contract; and
- standalone port tests and integration fixtures.

A consuming host owns:

- implementations of LXP's provider tables using the host's stable HAL;
- board addresses, linker regions, devicetree, clocks, pins, DMA buffers, QSPI
  and rootfs placement;
- native filesystem, block, display, touch, entropy, console, and network
  adapters where the implementation is expressed in the host HAL rather than
  an RTOS kernel primitive;
- translating the host build configuration into `LXP_ENABLE_*` and sizing
  definitions; and
- product policy: the init path, rootfs choice, enabled providers, priorities,
  interface addressing, netfs endpoint, watchdog behavior, diagnostic
  presentation/thresholds, and demo workloads.

An application owns only application behavior. Benchmark signal generation,
fault demonstrations, workload selection, and reporting may remain in an app.
Rootfs discovery, provider composition, task/MPU mechanics, syscall trapping,
and generic process lifecycle do not become application-owned merely because
one app was their first consumer.

The consumer still chooses the rootfs image, fixed table/name storage capacity,
enabled providers, native interface configuration, optional netfs endpoint,
init path, and launch callbacks. The host facade sequences native interface
bring-up and translates those choices into an immutable LXP host; it does not
turn product policy into LXP defaults.

Native-media arbitration does not move into LXP. It must also cover RTOS-native
filesystem and raw-block callers, so the host storage layer owns physical-card
generation leases, DMA-safe staging, worker priority, and budget admission.

Native socket storage and stack notification policy likewise remain host-owned.
The host owns native interface allocation, bring-up, address readiness, rollback,
and teardown. LXP receives only an opaque interface handle in its immutable host
contract and binds it for one run; no application or provider mutates a process-
global LXP interface selector. The optional netfs topology follows the same
contract: the host supplies product-selected strings/addressing, LXP copies them,
and teardown clears the active mount before the provider is withdrawn.
The network provider may subscribe to an RTOS or driver readiness source only
while it owns native sockets. If it advertises readiness events, it translates
that source into the callback supplied to `run_begin()`; it does not call a
global LXP wake function. LXP owns what the callback means: post the current
coordinator event and retry generation-qualified parked socket operations.
Every opened or accepted provider socket must successfully enter nonblocking
mode before LXP publishes it, because a blocking call would stall the privileged
coordinator rather than only the calling guest.

Observability follows the same boundary. LXP owns the meaning, capacity, and
lifetime of coordinator diagnostics and latency counters. A caller takes one
`lxp_host_observation_t` only while the host is quiescent; an active run returns
`LXP_ERR_BUSY` rather than a cross-registry partial view. A port may publish an
aggregate guest-task stack high-water mark through the optional
`lxp_os_ops_t::task.guest_stack_usage` callback. LXP normalizes that result into the
host observation, so consumers do not include an RTOS port header. The host or
application still decides when to sample, how to render the copy, whether to
enforce a threshold, and how a watchdog reacts to the separate live heartbeat.

Console input follows the same callback-lifetime rule. The host owns the UART,
RX FIFO, newline transport policy, and any non-consuming lookahead required by
its HAL. If it can publish RX readiness, the per-launch subscription retains
LXP's callback and immutable context only until the matching unsubscribe
returns. LXP owns what readiness means: wake the current coordinator and retry
the generation-qualified console wait. Hosts without an event source leave the
subscription unset and retain the bounded polling fallback.

Display and input follow the same split. LXP owns Linux framebuffer and evdev
semantics, dirty-rectangle coalescing, presentation cadence, touch-event state,
DMA2D descriptor validation, and the run-scoped device-open/tick lifecycle. The
host owns the physical framebuffer, cache publication required by scanout,
panel update, DMA2D registers/completion/coherency, and touch-controller bus
instance. Hardware initialization is reached through the provider contract,
not a demo application: an unavailable DMA2D initializer means `/dev/dma2d` is
not registered, and every successfully initialized touch provider is released
before its run-scoped provider table is withdrawn.

## Dependency direction

The core (`src/` and `include/lxp/`) may use only LXP interfaces and the C
implementation. It must not include oveRTOS, FreeRTOS, NuttX, or Zephyr headers
or select behavior using their configuration macros. `scripts/check-decoupled.sh`
enforces this source-level rule.

Code under `ports/` may depend on the RTOS and architecture named by that port.
It may depend on LXP public and port-private interfaces, but not on an oveRTOS
application, board description, or oveRTOS HAL. Board resources reach a port
through explicit configuration or callbacks supplied by the consumer.

The host adapter depends inward on LXP's public provider contracts and outward
on the host HAL. LXP never calls oveRTOS APIs directly. This keeps a port usable
by another product built on the same RTOS and makes the POSIX and QEMU ports
meaningful independent integration tests.

## Production-port migration ledger

The oveRTOS STM32 production integration predates this contract. The FreeRTOS
task/trap/MPU seam and its required kernel patch now live in
`ports/freertos/`; `ports/qemu-mps2` builds the same implementation as its
standalone integration fixture. NuttX task/trap/scheduler-note/MPU mechanics
live in `ports/nuttx/` behind an immutable host configuration. Zephyr K_USER
thread, software-fault, memory-domain, park/resume, guest-rotation and fault
containment mechanics likewise live in `ports/zephyr/`; its consumer supplies
only storage placement, priorities, memory policy and host-service callbacks.
There are no remaining consumer-owned production RTOS seams. What the Cortex-M
ports share (the common configuration prefix and the operations that only read
it) lives once in `ports/common/`.

Move one engine at a time. A move is complete only when:

1. the mechanism is built from `ports/<rtos>/` in a standalone LXP-owned test
   or fixture;
2. its public inputs contain no oveRTOS board or application type;
3. oveRTOS supplies only board facts, provider implementations, and policy;
4. host tests, all three production builds, and the selected hardware test are
   unchanged or their intentional delta is documented; and
5. the old consumer copy and its migration exception are removed in the same
   integration commit.

Temporary forwarding wrappers are allowed only when they have one owner and a
recorded removal iteration. Parallel implementations of the same seam are not.

## Review test

For any disputed function, ask whether another product using the same RTOS
would need substantially the same mechanism to run LXP. If yes, it belongs in
the LXP port. If it names oveRTOS facilities, STM32 board resources, or a demo
workload, it belongs in the host or application. Mixed functions must be split
at that boundary rather than assigned wholesale to either repository.
