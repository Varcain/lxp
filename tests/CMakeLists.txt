# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Host unit-test build (cmocka). Enabled from the top-level CMakeLists with
# -DLXP_BUILD_TESTS=ON. The suites drive lxp_syscall() directly on the host, so the
# module's OS-agnostic TUs are compiled in WITHOUT the coordinator (src/lxp_run.c);
# tests/stub_lnx_run.c supplies the run-loop hooks (clock + no-op cache/flush).

# ---- cmocka via FetchContent (git clone at configure time; no system dep) --------
include(FetchContent)
FetchContent_Declare(
  cmocka
  GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
  GIT_TAG        cmocka-1.1.7
  GIT_SHALLOW    TRUE
)
set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)
set(UNIT_TESTING ON CACHE BOOL "" FORCE) # builds cmocka-static; also registers cmocka's own
FetchContent_MakeAvailable(cmocka) #   self-tests in CTest — filter ours with `ctest -R lxp_unit`.

set(LXP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# Module TUs the suites exercise. NOT src/lxp_run.c (the coordinator) — its OS-service
# hooks come from tests/stub_lnx_run.c instead.
set(LXP_TEST_MODULE_SRC
  "${LXP_ROOT}/src/lxp_arena.c"
  "${LXP_ROOT}/src/lxp_loader.c"
  "${LXP_ROOT}/src/lxp_syscall.c"
  "${LXP_ROOT}/src/fs/lxp_pipe.c"
  "${LXP_ROOT}/src/lxp_stats.c"
  "${LXP_ROOT}/src/dev/lxp_dev.c"
  "${LXP_ROOT}/src/net/lxp_net.c"
  "${LXP_ROOT}/src/netfs/lxp_netfs.c"
  "${LXP_ROOT}/src/pty/lxp_pty.c"
)

add_executable(lxp_test_stub
  ${LXP_TEST_MODULE_SRC}
  "${LXP_ROOT}/ports/posix/lxp_port_posix.c"  # g_lxp_net_ops over BSD sockets + netif
  "${CMAKE_CURRENT_SOURCE_DIR}/stub_lnx_run.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/stub_main.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_arena.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_syscall.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_dev.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_net.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_netfs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_pty.c"
)

target_include_directories(lxp_test_stub PRIVATE
  "${LXP_ROOT}/include"
  "${LXP_ROOT}/src"
  "${cmocka_SOURCE_DIR}/include"
)

# Feature gates for the TUs under test (value-based, matching the module's #if LXP_ENABLE_X).
target_compile_definitions(lxp_test_stub PRIVATE
  LXP_ENABLE_DEV=1
  LXP_ENABLE_PTY=1
  LXP_ENABLE_NET=1
  LXP_ENABLE_NETFS=1
  LXP_ENABLE_NETFS_EXEC=1
  LXP_ENABLE_DEV_FB=0
  LXP_ENABLE_DEV_INPUT=0
)

target_link_libraries(lxp_test_stub PRIVATE cmocka-static pthread rt m)

# The module TUs + port + suites must build warning-clean (the cmocka dependency,
# fetched separately, is not held to this).
target_compile_options(lxp_test_stub PRIVATE -Wall -Wextra -Werror)

add_test(NAME lxp_unit COMMAND lxp_test_stub)
