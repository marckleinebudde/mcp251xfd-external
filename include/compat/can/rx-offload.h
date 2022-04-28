/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2022 Pengutronix,
 *               Marc Kleine-Budde <kernel@pengutronix.de>
 */
#ifndef _COMPAT_RX_OFFLOAD_H
#define _COMPAT_RX_OFFLOAD_H

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
#include "../../linux/can/rx-offload.h"
#else
#include <linux/can/rx-offload.h>
#endif

#endif
