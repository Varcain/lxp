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
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/lxp_features.cmake")
lxp_declare_features()
option(LXP_PORT_POSIX "Build the bundled POSIX reference port" OFF)
option(LXP_BUILD_TESTS "Build the host (cmocka) unit-test suite" OFF)
option(LXP_BUILD_FUZZ "Build the coverage-guided fuzz harnesses" OFF)

# ---- sources: one feature-grouped inventory shared by every consumer ---------
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/lxp_sources.cmake")

add_library(lxp STATIC ${LXP_ALL_SOURCES})
target_include_directories(lxp PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Value-based feature gates: the module tests `#if LXP_ENABLE_X`, so every gate gets an
# explicit 0 or 1 (-DLXP_ENABLE_X=0 genuinely disables).
lxp_enabled_features(LXP_ENABLED_FEATURES)
lxp_feature_definitions(lxp PUBLIC ${LXP_ENABLED_FEATURES})

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
