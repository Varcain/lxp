# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The LXP feature gates, one row each: NAME|OWNER|description, OWNER "-" for none. An
# owner is listed before the gates that need it. Everything that lists the gates derives
# from this table: the options and owner checks (lxp_declare_features) and the compile
# definitions (lxp_feature_definitions). scripts/check-features.sh ties the table to
# lxp_config.h's defaults and #error rules and to the CI gate legs.
set(LXP_FEATURES
  "NET|-|Guest sockets (net-ops port required)"
  "NETFS|NET|9P remote filesystem"
  "NETFS_EXEC|NETFS|Execute programs off the 9P mount"
  "PTY|-|Pseudo-terminal support"
  "FS|-|Writable host filesystem provider"
  "DEV|-|Device layer (/dev)"
  "BLOCK|DEV|Raw block media (/dev/mmcblk*)"
  "DEV_FB|DEV|Framebuffer /dev/fb0 (display fb provider)"
  "DEV_DMA2D|DEV|2D accelerator /dev/dma2d (display dma2d provider)"
  "DEV_INPUT|DEV|Input event device (/dev/input)"
  "DEV_INPUT_TESTPAD|DEV_INPUT|Synthetic input provider"
  "TOUCH|DEV_INPUT|Physical touch provider"
  "RT_METRICS|-|Low-overhead native-port timing metrics"
  "FPU_CONTEXT|-|Preserve VFP state for floating-point guests"
  "LATENCY|-|Coordinator service and wake latency histograms")

# lxp_feature_names(<out>): every gate name, in table order.
function(lxp_feature_names out)
  set(names)
  foreach(row IN LISTS LXP_FEATURES)
    string(REPLACE "|" ";" fields "${row}")
    list(GET fields 0 name)
    list(APPEND names ${name})
  endforeach()
  set(${out} ${names} PARENT_SCOPE)
endfunction()

# lxp_declare_features(): an OFF-by-default option per gate, and a configure error for a
# gate enabled without its owner.
macro(lxp_declare_features)
  foreach(lxp_feature_row IN LISTS LXP_FEATURES)
    string(REPLACE "|" ";" lxp_feature_fields "${lxp_feature_row}")
    list(GET lxp_feature_fields 0 lxp_feature_name)
    list(GET lxp_feature_fields 1 lxp_feature_owner)
    list(GET lxp_feature_fields 2 lxp_feature_desc)
    option(LXP_ENABLE_${lxp_feature_name} "${lxp_feature_desc}" OFF)
    if(NOT lxp_feature_owner STREQUAL "-" AND LXP_ENABLE_${lxp_feature_name} AND
       NOT LXP_ENABLE_${lxp_feature_owner})
      message(FATAL_ERROR
        "LXP_ENABLE_${lxp_feature_name} requires LXP_ENABLE_${lxp_feature_owner}")
    endif()
  endforeach()
endmacro()

# lxp_enabled_features(<out>): the gates whose option is ON.
function(lxp_enabled_features out)
  lxp_feature_names(all)
  set(on)
  foreach(name IN LISTS all)
    if(LXP_ENABLE_${name})
      list(APPEND on ${name})
    endif()
  endforeach()
  set(${out} ${on} PARENT_SCOPE)
endfunction()

# lxp_feature_definitions(<target> <PUBLIC|PRIVATE|INTERFACE> [NAME...]): define every
# gate on <target>, 1 for each NAME given and 0 for the rest, so no unit falls back to a
# default and #if LXP_ENABLE_X stays -Wundef-clean.
function(lxp_feature_definitions target scope)
  lxp_feature_names(all)
  foreach(name IN LISTS ARGN)
    if(NOT name IN_LIST all)
      message(FATAL_ERROR "unknown LXP feature ${name}")
    endif()
  endforeach()
  foreach(name IN LISTS all)
    if(name IN_LIST ARGN)
      target_compile_definitions(${target} ${scope} LXP_ENABLE_${name}=1)
    else()
      target_compile_definitions(${target} ${scope} LXP_ENABLE_${name}=0)
    endif()
  endforeach()
endfunction()
