# NuttX Cortex-M port

This directory owns the reusable NuttX mechanism required to run LXP guests:
native task creation, SVCall and fault interposition, stopped-task parking and
resume, scheduler-note runtime hooks, and PMSAv7 MPU profile installation.

The embedding product supplies one immutable `lxp_nuttx_port_config_t`. It
contains physical storage placement, static MPU regions and memory attributes,
trusted TCB bounds, native priority, time/thread/memory providers, version
text, optional accounting callbacks, and the live memory-contract validator.
No oveRTOS board or application symbols are referenced by the port.

The port deliberately has four NuttX-internal dependencies because the public
NuttX API cannot express the required operations: `arm_svcall`,
`arm_hardfault`, `nxsched_suspend`/`nxsched_add_readytorun` with
`g_stoppedtasks`, and the scheduler note-driver interface. They are isolated in
this file and guarded by the production build and hardware tests. A NuttX
upgrade that changes these interfaces must be qualified here rather than
worked around in the consuming application.
