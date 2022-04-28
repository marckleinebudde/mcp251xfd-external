/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2022 Pengutronix,
 *               Marc Kleine-Budde <kernel@pengutronix.de>
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)

#include <linux/can/dev.h>

struct sk_buff *
__can_get_echo_skb(struct net_device *dev, unsigned int idx, u8 *len_ptr)
{
	struct can_priv *priv = netdev_priv(dev);

	if (idx >= priv->echo_skb_max) {
		netdev_err(dev, "%s: BUG! Trying to access can_priv::echo_skb out of bounds (%u/max %u)\n",
			   __func__, idx, priv->echo_skb_max);
		return NULL;
	}

	if (priv->echo_skb[idx]) {
		/* Using "struct canfd_frame::len" for the frame
		 * length is supported on both CAN and CANFD frames.
		 */
		struct sk_buff *skb = priv->echo_skb[idx];
		struct canfd_frame *cf = (struct canfd_frame *)skb->data;

		/* get the real payload length for netdev statistics */
		if (cf->can_id & CAN_RTR_FLAG)
			*len_ptr = 0;
		else
			*len_ptr = cf->len;

		priv->echo_skb[idx] = NULL;

		return skb;
	}

	return NULL;
}

#include "../dev/rx-offload.c"

#endif
