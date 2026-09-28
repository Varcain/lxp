/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Private interface of the input device class.
 */

#ifndef LXP_DEV_INPUT_H
#define LXP_DEV_INPUT_H

/* Set the display geometry used to clamp / report touch coordinates.
 * Non-positive dimensions reset to the 480x272 default independently.
 * lxp_run() seeds it from lxp_run_config_t for every run. */
void lxp_display_set_geometry(int width, int height);

#endif /* LXP_DEV_INPUT_H */
