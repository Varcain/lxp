# Zephyr Cortex-M port

This directory contains LXP's production Zephyr port for Cortex-M targets. It
owns the native mechanisms another Zephyr product would otherwise have to
reproduce:

- persistent unprivileged `K_USER` guest threads and exact-frame park/resume;
- per-address-space `k_mem_domain` construction with copied-text W^X policy;
- guest `svc #0` capture through Zephyr's software-fault path;
- contained unprivileged faults with bounded post-mortem diagnostics;
- live PMSAv7 MPU-profile validation and copied-executable publication;
- guest-only weighted rotation while Zephyr kernel time slicing stays off; and
- coordinator wakeup and critical-section telemetry.

The embedding system supplies one immutable `g_lxp_zephyr_port_config`
declared by `include/lxp/ports/zephyr.h`. It provides external-memory placement,
an optional non-static rootfs window, native priorities, the CPU-memory
contract, and host callbacks for time, entropy, process attribution, memory
statistics and validation. The port has no oveRTOS board or application
dependency.

Zephyr does not expose a dedicated application-SVC registration point. The
port therefore intentionally interposes `z_do_kernel_oops` with
`-Wl,--wrap=z_do_kernel_oops`, recognizes only an unprivileged guest's
`svc #0`, and forwards every other oops to the real Zephyr handler. This single
link option is part of the port integration contract; it is not host policy.
