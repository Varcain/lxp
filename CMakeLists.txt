# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# lxp — the OS-agnostic Linux personality, as a standalone module.
#
# Two ways to consume it:
#   * Standalone:  cmake -S . -B build && cmake --build build builds liblxp.a
#                  (pick a port, e.g. -DLXP_PORT_POSIX=ON for the reference port);
#                  add_subdirectory() it and link lxp::lxp to embed that library.
#   * Source list: include(cmake/lxp_sources.cmake), compile the LXP_*_SOURCES
#                  groups you need, and set the LXP_ENABLE_* / sizing defines from
#                  your own config (this is how oveRTOS consumes lxp).

cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED PROJECT_NAME)
  project(lxp C)
endif()

# ---- feature options (exposed to a standalone build; the embedded build sets
#      the LXP_ENABLE_* compile-defs directly from its Kconfig instead) --------
option(LXP_ENABLE_NET "Guest sockets (net-ops port required)" OFF)
option(LXP_ENABLE_NETFS "9P remote filesystem (needs NET)" OFF)
option(LXP_ENABLE_NETFS_EXEC "Execute programs off the 9P mount" OFF)
option(LXP_ENABLE_PTY "Pseudo-terminal support" OFF)
option(LXP_ENABLE_FS "Writable host filesystem provider" OFF)
option(LXP_ENABLE_BLOCK "Raw block media (/dev/mmcblk*)" OFF)
option(LXP_ENABLE_DEV "Device layer (/dev)" OFF)
option(LXP_ENABLE_DEV_FB "Framebuffer /dev/fb0 (display-ops port required)" OFF)
option(LXP_ENABLE_DEV_DMA2D "DMA2D 2D-accelerator /dev/dma2d (display-ops dma2d_submit)" OFF)
option(LXP_ENABLE_DEV_INPUT "Input event device (/dev/input)" OFF)
option(LXP_ENABLE_DEV_INPUT_TESTPAD "Synthetic input provider (needs DEV_INPUT)" OFF)
option(LXP_ENABLE_TOUCH "Physical touch provider (needs DEV_INPUT)" OFF)
option(LXP_ENABLE_RT_METRICS "Low-overhead native-port timing metrics" OFF)
option(LXP_ENABLE_FPU_CONTEXT "Preserve VFP state for floating-point guests" OFF)
option(LXP_PORT_POSIX "Build the bundled POSIX reference port" OFF)
option(LXP_BUILD_TESTS "Build the host (cmocka) unit-test suite" OFF)
option(LXP_BUILD_FUZZ "Build the coverage-guided fuzz harnesses" OFF)

function(lxp_require child parent)
  if(${child} AND NOT ${parent})
    message(FATAL_ERROR "${child} requires ${parent}")
  endif()
endfunction()

lxp_require(LXP_ENABLE_NETFS LXP_ENABLE_NET)
lxp_require(LXP_ENABLE_NETFS_EXEC LXP_ENABLE_NETFS)
lxp_require(LXP_ENABLE_BLOCK LXP_ENABLE_DEV)
lxp_require(LXP_ENABLE_DEV_FB LXP_ENABLE_DEV)
lxp_require(LXP_ENABLE_DEV_DMA2D LXP_ENABLE_DEV)
lxp_require(LXP_ENABLE_DEV_INPUT LXP_ENABLE_DEV)
lxp_require(LXP_ENABLE_DEV_INPUT_TESTPAD LXP_ENABLE_DEV_INPUT)
lxp_require(LXP_ENABLE_TOUCH LXP_ENABLE_DEV_INPUT)

# ---- sources: one feature-grouped inventory shared by every consumer ---------
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/lxp_sources.cmake")

add_library(lxp STATIC ${LXP_ALL_SOURCES})
target_include_directories(lxp PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(lxp PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

# Value-based feature gates: the module tests `#if LXP_ENABLE_X`, so emit an
# explicit 0/1 for each (matches lxp_config.h's defaults and keeps the matrix
# build -Wundef-clean; -DLXP_ENABLE_X=0 genuinely disables).
foreach(feat NET NETFS NETFS_EXEC PTY FS BLOCK DEV DEV_FB DEV_DMA2D DEV_INPUT
             DEV_INPUT_TESTPAD TOUCH FPU_CONTEXT RT_METRICS)
  if(LXP_ENABLE_${feat})
    target_compile_definitions(lxp PUBLIC LXP_ENABLE_${feat}=1)
  else()
    target_compile_definitions(lxp PUBLIC LXP_ENABLE_${feat}=0)
  endif()
endforeach()

if(LXP_PORT_POSIX)
  target_sources(lxp PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lxp_port_posix.c")
endif()

add_library(lxp::lxp ALIAS lxp)

# ---- host test suite (opt-in; cmocka) -----------------------------------------
if(LXP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---- fuzz harnesses (opt-in; libFuzzer/AFL++/replay over the untrusted parsers) --
if(LXP_BUILD_FUZZ)
  enable_testing()
  add_subdirectory(fuzz)
endif()
