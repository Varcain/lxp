# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Canonical LXP translation-unit inventory.
#
# Standalone builds, embedding firmware, host tests, and fuzzers import these
# feature groups instead of independently rediscovering or copying the source
# list. Consumers may deliberately omit a group, but a new source file must be
# classified here before any LXP CMake build will configure.

include_guard(GLOBAL)

get_filename_component(LXP_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

set(LXP_RUNTIME_SOURCES
    "${LXP_SOURCE_ROOT}/src/lxp_syscall.c"
    "${LXP_SOURCE_ROOT}/src/lxp_bootstrap.c"
    "${LXP_SOURCE_ROOT}/src/lxp_guest.c"
    "${LXP_SOURCE_ROOT}/src/lxp_provider.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_console.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_devfs.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_dir.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_dirent.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_eventfd.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_fd.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_hostfs.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_mount.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_overlay.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_path.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_pipe.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_poll.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_rootfs.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_stat.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_tmpfs.c"
    "${LXP_SOURCE_ROOT}/src/fs/lxp_vfs.c"
    "${LXP_SOURCE_ROOT}/src/proc/lxp_exec_stage.c"
    "${LXP_SOURCE_ROOT}/src/proc/lxp_process.c"
    "${LXP_SOURCE_ROOT}/src/proc/lxp_procfs.c"
    "${LXP_SOURCE_ROOT}/src/proc/lxp_script.c"
    "${LXP_SOURCE_ROOT}/src/sys/lxp_sys_exec.c"
    "${LXP_SOURCE_ROOT}/src/sys/lxp_sys_fd.c"
    "${LXP_SOURCE_ROOT}/src/sys/lxp_sys_mm.c"
    "${LXP_SOURCE_ROOT}/src/sys/lxp_sys_path.c"
    "${LXP_SOURCE_ROOT}/src/sys/lxp_sys_proc.c"
    "${LXP_SOURCE_ROOT}/src/sys/lxp_sys_signal.c"
    "${LXP_SOURCE_ROOT}/src/sys/lxp_sys_time.c"
)

set(LXP_COORDINATOR_SOURCES
    "${LXP_SOURCE_ROOT}/src/lxp_async_gate.c"
    "${LXP_SOURCE_ROOT}/src/lxp_host.c"
    "${LXP_SOURCE_ROOT}/src/lxp_run.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_blocked.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_child.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_diag.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_exec.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_exit.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_fork.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_guest_event.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_image.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_initial.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_lifecycle.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_primary.c"
    "${LXP_SOURCE_ROOT}/src/run/lxp_validate.c"
)

set(LXP_POST_COORDINATOR_SOURCES
    "${LXP_SOURCE_ROOT}/src/lxp_signal.c"
    "${LXP_SOURCE_ROOT}/src/lxp_stats.c"
)
set(LXP_UTILITY_SOURCES
    "${LXP_SOURCE_ROOT}/src/lxp_latency.c"
    "${LXP_SOURCE_ROOT}/src/lxp_rt_metrics.c"
    "${LXP_SOURCE_ROOT}/src/lxp_arena.c"
    "${LXP_SOURCE_ROOT}/src/lxp_loader.c"
)
set(LXP_BASE_SOURCES
    ${LXP_RUNTIME_SOURCES}
    ${LXP_POST_COORDINATOR_SOURCES}
    ${LXP_UTILITY_SOURCES}
)

set(LXP_DEV_SOURCES
    "${LXP_SOURCE_ROOT}/src/dev/lxp_dev.c"
)
set(LXP_BLOCK_SOURCES
    "${LXP_SOURCE_ROOT}/src/dev/lxp_dev_block.c"
)
set(LXP_DEV_FB_SOURCES
    "${LXP_SOURCE_ROOT}/src/dev/lxp_dev_fb.c"
)
set(LXP_DEV_DMA2D_SOURCES
    "${LXP_SOURCE_ROOT}/src/dev/lxp_dev_dma2d.c"
)
set(LXP_DEV_INPUT_SOURCES
    "${LXP_SOURCE_ROOT}/src/dev/lxp_dev_input.c"
)
set(LXP_NET_SOURCES
    "${LXP_SOURCE_ROOT}/src/net/lxp_net.c"
    "${LXP_SOURCE_ROOT}/src/net/lxp_net_sys.c"
)
set(LXP_NETFS_SOURCES
    "${LXP_SOURCE_ROOT}/src/netfs/lxp_netfs.c"
)
set(LXP_PTY_SOURCES
    "${LXP_SOURCE_ROOT}/src/pty/lxp_pty.c"
)

set(LXP_OPTIONAL_SOURCES
    ${LXP_DEV_SOURCES}
    ${LXP_BLOCK_SOURCES}
    ${LXP_DEV_FB_SOURCES}
    ${LXP_DEV_DMA2D_SOURCES}
    ${LXP_DEV_INPUT_SOURCES}
    ${LXP_NET_SOURCES}
    ${LXP_NETFS_SOURCES}
    ${LXP_PTY_SOURCES}
)
set(LXP_NON_COORDINATOR_SOURCES
    ${LXP_BASE_SOURCES}
    ${LXP_OPTIONAL_SOURCES}
)
set(LXP_ALL_SOURCES
    ${LXP_RUNTIME_SOURCES}
    ${LXP_COORDINATOR_SOURCES}
    ${LXP_POST_COORDINATOR_SOURCES}
    ${LXP_UTILITY_SOURCES}
    ${LXP_OPTIONAL_SOURCES}
)

# Fail closed when a translation unit is added without an ownership decision.
# CONFIGURE_DEPENDS makes supported generators re-run this check after src/
# changes instead of silently retaining an incomplete prior configuration.
file(GLOB_RECURSE _LXP_DISCOVERED_SOURCES CONFIGURE_DEPENDS
     "${LXP_SOURCE_ROOT}/src/*.c")
set(_LXP_DECLARED_SOURCES ${LXP_ALL_SOURCES})
list(SORT _LXP_DISCOVERED_SOURCES)
list(SORT _LXP_DECLARED_SOURCES)
if(NOT _LXP_DISCOVERED_SOURCES STREQUAL _LXP_DECLARED_SOURCES)
    message(FATAL_ERROR
        "LXP source inventory is stale. Classify every src/*.c translation unit "
        "in ${CMAKE_CURRENT_LIST_FILE}.")
endif()
unset(_LXP_DISCOVERED_SOURCES)
unset(_LXP_DECLARED_SOURCES)
