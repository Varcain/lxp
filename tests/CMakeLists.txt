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
include("${LXP_ROOT}/cmake/lxp_sources.cmake")

# Module TUs the suites exercise. NOT src/lxp_run.c (the coordinator) — its OS-service
# hooks come from tests/stub_lnx_run.c instead.
# Use the canonical non-coordinator group so host coverage cannot drift from the
# firmware inventory. The coordinator hooks used by lxp_signal.c come from the
# test fixtures; coordinator policy has its own target below.
set(LXP_TEST_MODULE_SRC ${LXP_NON_COORDINATOR_SOURCES})

add_executable(lxp_test_stub
  ${LXP_TEST_MODULE_SRC}
  "${LXP_ROOT}/ports/posix/lxp_port_posix.c"  # g_lxp_net_ops over BSD sockets + netif
  "${CMAKE_CURRENT_SOURCE_DIR}/stub_lnx_run.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/stub_main.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_arena.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_cortex_m.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_loader.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_loader_fdpic.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_rt_metrics.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_fs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_overflow.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_signal.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_syscall.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_syscall_conformance.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_dev.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_net.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_netfs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_hostfs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_linux_pty.c"
)

target_include_directories(lxp_test_stub PRIVATE
  "${LXP_ROOT}/include"
  "${LXP_ROOT}/src"
  "${LXP_ROOT}/fuzz"  # the syscall-conformance suite reuses fuzz_common.h's low-4GiB helper
  "${cmocka_SOURCE_DIR}/include"
)

# Feature gates for the TUs under test (value-based, matching the module's #if LXP_ENABLE_X).
target_compile_definitions(lxp_test_stub PRIVATE
  LXP_RESOURCE_POOL_COUNT=64
  LXP_ENABLE_DEV=1
  LXP_ENABLE_BLOCK=1
  LXP_ENABLE_PTY=1
  LXP_ENABLE_NET=1
  LXP_ENABLE_NETFS=1
  LXP_ENABLE_NETFS_EXEC=1
  LXP_ENABLE_FS=1
  LXP_ENABLE_DEV_FB=1
  LXP_ENABLE_DEV_DMA2D=1
  LXP_ENABLE_DEV_INPUT=1
  LXP_ENABLE_FPU_CONTEXT=1
  LXP_ENABLE_RT_METRICS=1
)

target_link_libraries(lxp_test_stub PRIVATE cmocka-static pthread rt m)

# The module TUs + port + suites must build warning-clean (the cmocka dependency,
# fetched separately, is not held to this).
target_compile_options(lxp_test_stub PRIVATE -Wall -Wextra -Werror)

# Opt-in ASan+UBSan (-DLXP_SANITIZE=ON): the CI "sanitizers" job builds with these so the
# 32-bit-overflow / OOB bugs the Stage-2 fixes target are caught at runtime on the host.
option(LXP_SANITIZE "Build the host tests with AddressSanitizer + UBSan" OFF)
if(LXP_SANITIZE)
  target_compile_options(lxp_test_stub PRIVATE
    -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  target_link_options(lxp_test_stub PRIVATE -fsanitize=address,undefined)
endif()

add_test(NAME lxp_unit COMMAND lxp_test_stub)
add_test(NAME lxp_guest_memory_boundary
  COMMAND sh "${LXP_ROOT}/scripts/check-guest-memory.sh")
add_test(NAME lxp_unit_config_contract
  COMMAND sh "${LXP_ROOT}/scripts/check-config-contract.sh"
          "${CMAKE_C_COMPILER}" "${CMAKE_COMMAND}")
add_test(NAME lxp_unit_header_contract
  COMMAND sh "${LXP_ROOT}/scripts/check-header-contract.sh"
          "${CMAKE_C_COMPILER}")

# ---- asynchronous provider completion gate ----------------------------------
add_executable(lxp_async_gate_test
  "${LXP_ROOT}/src/lxp_async_gate.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_async_gate.c"
)
target_include_directories(lxp_async_gate_test PRIVATE
  "${LXP_ROOT}/include"
  "${cmocka_SOURCE_DIR}/include"
)
target_compile_options(lxp_async_gate_test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(lxp_async_gate_test PRIVATE cmocka-static)
add_test(NAME lxp_unit_async_gate COMMAND lxp_async_gate_test)

# ---- immutable host/bootstrap facade ------------------------------------------
# A focused lxp_run substitute captures composition without starting a guest;
# lxp_coord_test below continues to exercise the real coordinator entry.
add_executable(lxp_host_test
  "${LXP_ROOT}/src/lxp_bootstrap.c"
  "${LXP_ROOT}/src/lxp_host.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_host.c"
)
target_include_directories(lxp_host_test PRIVATE
  "${LXP_ROOT}/include"
  "${cmocka_SOURCE_DIR}/include"
)
target_compile_options(lxp_host_test PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(lxp_host_test PRIVATE
  LXP_ENABLE_NET=1
  LXP_ENABLE_NETFS=1
  LXP_ENABLE_LATENCY=1)
target_link_libraries(lxp_host_test PRIVATE cmocka-static)
add_test(NAME lxp_unit_host COMMAND lxp_host_test)

# ---- coordinator (src/lxp_run.c) unit tests -------------------------------------
# The coordinator is deliberately absent from lxp_test_stub above: its 32-bit-target
# pointer casts warn on a 64-bit host, and the OS-service symbols it defines would clash
# with tests/stub_lnx_run.c. So it has only ever run end-to-end on QEMU. This dedicated
# binary tests its process-bookkeeping state machine on the host. The real
# coordinator is linked as a production translation unit; a test-only fixture
# bridge exposes the white-box state required by the protocol suite.
add_executable(lxp_coord_test
  ${LXP_TEST_MODULE_SRC}
  ${LXP_COORDINATOR_SOURCES}
  "${LXP_ROOT}/ports/posix/lxp_port_posix.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/suites/test_run_coord.c"
)
target_include_directories(lxp_coord_test PRIVATE
  "${LXP_ROOT}/include"
  "${LXP_ROOT}/src"
  "${LXP_ROOT}/fuzz"
  "${cmocka_SOURCE_DIR}/include"
)
# Full coordinator-facing feature set: the protocol suite crosses deferred
# lifecycle work with socket/netfs waits and verifies that the same state
# machine remains valid when optional subsystems are compiled in.
target_compile_options(lxp_coord_test PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(lxp_coord_test PRIVATE
  LXP_RESOURCE_POOL_COUNT=64
  LXP_ENABLE_DEV=1
  LXP_ENABLE_NET=1
  LXP_ENABLE_NETFS=1
  LXP_ENABLE_NETFS_EXEC=1
  LXP_ENABLE_FS=1
  LXP_ENABLE_PTY=1
  LXP_ENABLE_FPU_CONTEXT=1
  LXP_TEST_FAILPOINTS=1
  LXP_TEST_INTERNALS=1
)
target_link_libraries(lxp_coord_test PRIVATE cmocka-static pthread rt m)
if(LXP_SANITIZE)
  target_compile_options(lxp_coord_test PRIVATE
    -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  target_link_options(lxp_coord_test PRIVATE -fsanitize=address,undefined)
endif()

add_test(NAME lxp_unit_coord COMMAND lxp_coord_test)
