# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Coverage-guided fuzz harnesses for lxp's untrusted-input parsers. Enabled from
# the top-level CMakeLists with -DLXP_BUILD_FUZZ=ON. Each harness is its own
# executable exporting LLVMFuzzerTestOneInput(); the driver is selected by
# LXP_FUZZ_ENGINE:
#
#   libfuzzer (default) : clang + libFuzzer; local coverage-guided fuzzing.
#                         `build/fuzz/fuzz_fdpic -max_total_time=60 fuzz/corpus/fdpic`
#   replay              : gcc or clang; a standalone main replays a corpus once
#                         under ASan/UBSan (-DLXP_SANITIZE=ON). This is the CI form
#                         (keeps CI gcc-only) and the AFL++ `-- ./fuzz_x @@` form.
#   afl                 : same driver as replay, but expect an AFL++ compiler
#                         (configure with -DCMAKE_C_COMPILER=afl-clang-lto).
#
# The harnesses build the SAME module TUs as the host suite (src/*.c minus the
# coordinator src/lxp_run.c), so they add no new module TU and stay off oveRTOS's
# source lists — a fuzz change is a pin-bump at most.

set(LXP_FUZZ_ENGINE "libfuzzer" CACHE STRING "Fuzz driver: libfuzzer | replay | afl")
set_property(CACHE LXP_FUZZ_ENGINE PROPERTY STRINGS libfuzzer replay afl)

set(LXP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# Same collection rule as tests/CMakeLists.txt: every module TU by glob, minus the
# 32-bit-only coordinator (its hooks come from tests/stub_lnx_run.c + fuzz_stubs.c).
file(GLOB_RECURSE FUZZ_MODULE_SRC CONFIGURE_DEPENDS "${LXP_ROOT}/src/*.c")
list(REMOVE_ITEM FUZZ_MODULE_SRC "${LXP_ROOT}/src/lxp_run.c")

# ---- engine -> compile / link flag sets --------------------------------------
# Two UBSan sub-checks are dropped as target-benign C-standard pedantry (they do not
# manifest on the ARMv7-M target, and would otherwise bury the real findings):
#   * alignment            — ARMv7-M handles unaligned word/halfword LDR/STR in hardware,
#                            and a guest may legitimately pass an unaligned pointer, so a
#                            misaligned typed store to a user pointer (e.g. gettimeofday
#                            writing a struct timeval) is not a target bug.
#   * nonnull-attribute    — memcpy(p, q, 0) with a 0-length user buffer is a no-op on every
#                            real platform; only the C standard's nonnull attribute objects.
# ASan + the rest of UBSan still catch the real OOB / overflow / null-deref / user_ok-bypass.
set(FUZZ_SAN_COMMON -fno-sanitize-recover=all -fno-omit-frame-pointer
    -fno-sanitize=alignment -fno-sanitize=nonnull-attribute)
if(LXP_FUZZ_ENGINE STREQUAL "libfuzzer")
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
      "LXP_FUZZ_ENGINE=libfuzzer needs clang (got '${CMAKE_C_COMPILER_ID}'). "
      "Configure with -DCMAKE_C_COMPILER=clang, or use -DLXP_FUZZ_ENGINE=replay for gcc.")
  endif()
  # fuzzer-no-link instruments every TU for coverage; the final link adds libFuzzer's main.
  set(FUZZ_COMPILE_FLAGS -fsanitize=fuzzer-no-link,address,undefined ${FUZZ_SAN_COMMON})
  set(FUZZ_LINK_FLAGS    -fsanitize=fuzzer,address,undefined)
  set(FUZZ_NEEDS_MAIN OFF)
else() # replay | afl
  if(LXP_SANITIZE)
    set(FUZZ_COMPILE_FLAGS -fsanitize=address,undefined ${FUZZ_SAN_COMMON})
    set(FUZZ_LINK_FLAGS    -fsanitize=address,undefined)
  else()
    set(FUZZ_COMPILE_FLAGS "")
    set(FUZZ_LINK_FLAGS    "")
  endif()
  set(FUZZ_NEEDS_MAIN ON)
endif()
message(STATUS "lxp fuzz: engine=${LXP_FUZZ_ENGINE} compiler=${CMAKE_C_COMPILER_ID} sanitize=${LXP_SANITIZE}")

# ---- shared module objects (compiled once; PUBLIC flags flow to each harness) --
add_library(lxp_fuzz_obj OBJECT
  ${FUZZ_MODULE_SRC}
  "${LXP_ROOT}/ports/posix/lxp_port_posix.c"   # g_lxp_net_ops over BSD sockets
  "${LXP_ROOT}/tests/stub_lnx_run.c"           # clock + no-op cache/flush + mock display
  "${CMAKE_CURRENT_SOURCE_DIR}/fuzz_stubs.c")  # g_sig_save / slot_of / park_frame
target_include_directories(lxp_fuzz_obj PUBLIC "${LXP_ROOT}/include" "${LXP_ROOT}/src")
target_compile_definitions(lxp_fuzz_obj PUBLIC
  LXP_ENABLE_DEV=1 LXP_ENABLE_PTY=1 LXP_ENABLE_NET=1 LXP_ENABLE_NETFS=1
  LXP_ENABLE_NETFS_EXEC=1 LXP_ENABLE_DEV_FB=1 LXP_ENABLE_DEV_INPUT=1
  LXP_FUZZ=1)
target_compile_options(lxp_fuzz_obj PUBLIC ${FUZZ_COMPILE_FLAGS})
target_compile_options(lxp_fuzz_obj PRIVATE -Wall -Wextra) # module is warning-clean; harnesses are not held to -Werror

# ---- one executable per harness ----------------------------------------------
function(lxp_add_fuzz_harness name src)
  add_executable(${name} "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
  if(FUZZ_NEEDS_MAIN)
    target_sources(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/replay_main.c")
  endif()
  target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_compile_options(${name} PRIVATE -Wall -Wextra)
  target_link_libraries(${name} PRIVATE lxp_fuzz_obj pthread rt m)
  target_link_options(${name} PRIVATE ${FUZZ_LINK_FLAGS})

  # Under the replay driver, register a CTest that replays this harness's seed
  # corpus once (deterministic; the CI regression). No-op if the corpus is empty.
  if(FUZZ_NEEDS_MAIN)
    string(REGEX REPLACE "^fuzz_" "" _corpus "${name}")
    file(GLOB _seeds "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${_corpus}/*")
    add_test(NAME ${name}_corpus COMMAND ${name} ${_seeds})
  endif()
endfunction()

lxp_add_fuzz_harness(fuzz_fdpic harness_fdpic.c)
lxp_add_fuzz_harness(fuzz_etrel harness_etrel.c)
lxp_add_fuzz_harness(fuzz_cpio  harness_cpio.c)
lxp_add_fuzz_harness(fuzz_path  harness_path.c)
lxp_add_fuzz_harness(fuzz_9p    harness_9p.c)
lxp_add_fuzz_harness(fuzz_syscall harness_syscall.c)
