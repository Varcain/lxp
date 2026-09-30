# FreeRTOS MPU port

This directory contains LXP's production FreeRTOS port for ARMv7-M/PMSAv7
targets. It owns the mechanisms another FreeRTOS product would otherwise have
to reproduce:

- restricted, unprivileged guest-task creation and persistent park/resume;
- `SVC_Handler` capture and forwarding of kernel-owned SVC numbers;
- guest MemManage, BusFault and UsageFault containment;
- generation-keyed MPU profile compilation, TCB readback and live validation;
- coordinator MPU overlays and bounded copied-executable publication;
- guest-only weighted scheduling, event wakeup and bootstrap-stack auditing.

The embedding system supplies exactly one `g_lxp_freertos_port_config` declared
by `include/lxp/ports/freertos.h`. That object provides storage placement,
rootfs memory attributes, the CPU-memory contract, and board/HAL callbacks such
as time, entropy, cache maintenance, thread reporting and fatal diagnostics.
The part every Cortex-M port shares is its `.common` member
(`lxp_cortex_m_port_common_t`, `include/lxp/ports/cortex_m.h`), served by
`ports/common/lxp_cortex_m_port.c`, which a build selecting this port compiles
beside `lxp_freertos_port.c`.
It also supplies a synchronized single-subscriber bridge to the embedding
system's FreeRTOS tick hook. The port publishes its guest-only weighted-slicing
callback during per-run prepare and withdraws it during teardown; the generic
host tick hook therefore has no permanent LXP dependency or inactive-run call.
The port does not include or select on consumer configuration.

The accompanying kernel patch removes FreeRTOS's broad unprivileged peripheral
mapping, returns that MPU descriptor to restricted tasks, and restores the
additional descriptor in both context-switch paths. Any build selecting this
port must apply `patches/0001-arm-cm4-mpu-drop-global-user-peripheral-map.patch`
to FreeRTOS-Kernel V11.1.0 before compilation.

FreeRTOS advances an equal-priority ready-list cursor whenever it selects that
priority, even with `configUSE_TIME_SLICING=0`. The port therefore keeps only
one core-runnable Linux guest native-runnable at a time. SysTick accounts that
guest's nice-weighted quantum and wakes a statically allocated privileged
selector task, which suspends it and resumes the next guest in thread context.
The selector runs one native level above the guest class and no higher than the
coordinator; `prepare()` rejects an embedding whose coordinator cannot provide
that separation. Higher-priority host work stays immediately preemptive, and
unrelated FreeRTOS tasks never participate in the Linux guest rotation.

The selector, its 192-word stack, and its binary wake semaphore are owned by
this port. They are created for a run after host preparation, while the tick
callback is still unpublished, and destroyed after callback withdrawal during
teardown. Park, resume, abort, and slot-generation reuse all update the native
gate synchronously, so a delayed tick notification cannot rotate a replacement
task or resume a lifecycle-parked guest.

`ports/qemu-mps2` is the standalone integration fixture. Its `engine.c` now
contains only a host configuration object; it builds this same production port
and exercises the real SVC, task, park/resume and MPU paths under QEMU.
