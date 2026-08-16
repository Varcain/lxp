# FreeRTOS MPU port

This directory contains LXP's production FreeRTOS port for ARMv7-M/PMSAv7
targets. It owns the mechanisms another FreeRTOS product would otherwise have
to reproduce:

- restricted, unprivileged guest-task creation and persistent park/resume;
- `SVC_Handler` capture and forwarding of kernel-owned SVC numbers;
- guest MemManage, BusFault and UsageFault containment;
- generation-keyed MPU profile compilation, TCB readback and live validation;
- coordinator MPU overlays and bounded copied-executable publication;
- guest-only weighted time slicing, event wakeup and bootstrap-stack auditing.

The embedding system supplies exactly one `g_lxp_freertos_port_config` declared
by `include/lxp/ports/freertos.h`. That object provides storage placement,
rootfs memory attributes, the CPU-memory contract, and board/HAL callbacks such
as time, entropy, cache maintenance, thread reporting and fatal diagnostics.
The port does not include or select on consumer configuration.

The accompanying kernel patch removes FreeRTOS's broad unprivileged peripheral
mapping, returns that MPU descriptor to restricted tasks, and restores the
additional descriptor in both context-switch paths. Any build selecting this
port must apply `patches/0001-arm-cm4-mpu-drop-global-user-peripheral-map.patch`
to FreeRTOS-Kernel V11.1.0 before compilation.

`ports/qemu-mps2` is the standalone integration fixture. Its `engine.c` now
contains only a host configuration object; it builds this same production port
and exercises the real SVC, task, park/resume and MPU paths under QEMU.
