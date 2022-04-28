/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2022 Pengutronix,
 *               Marc Kleine-Budde <kernel@pengutronix.de>
 */

#ifndef _CAN_COMPAT_H
#define _CAN_COMPAT_H

#include <linux/clk.h>
#include <linux/interrupt.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/version.h>

#include <compat/can/rx-offload.h>

#ifndef static_assert
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#endif

#ifndef __BUILD_BUG_ON_NOT_POWER_OF_2
#ifdef __CHECKER__
#define __BUILD_BUG_ON_NOT_POWER_OF_2(n) (0)
#else /* __CHECKER__ */

#define __BUILD_BUG_ON_NOT_POWER_OF_2(n) \
	BUILD_BUG_ON(((n) & ((n) - 1)) != 0)
#endif
#endif

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

#ifndef CAN_CTRLMODE_CC_LEN8_DLC
#define CAN_CTRLMODE_CC_LEN8_DLC 0x100
#endif

#ifndef CAN_MAX_RAW_DLC
#define CAN_MAX_RAW_DLC 15
#endif

#ifndef can_cc_dlc2len
#define can_cc_dlc2len(dlc) (min_t(u8, (dlc), CAN_MAX_DLEN))
#endif

#ifndef regmap_read_poll_timeout
#define regmap_read_poll_timeout(map, addr, val, cond, sleep_us, timeout_us) \
({ \
	ktime_t timeout = ktime_add_us(ktime_get(), timeout_us); \
	int ret; \
	might_sleep_if(sleep_us); \
	for (;;) { \
		ret = regmap_read((map), (addr), &(val)); \
		if (ret) \
			break; \
		if (cond) \
			break; \
		if (timeout_us && ktime_compare(ktime_get(), timeout) > 0) { \
			ret = regmap_read((map), (addr), &(val)); \
			break; \
		} \
		if (sleep_us) \
			usleep_range((sleep_us >> 2) + 1, sleep_us); \
	} \
	ret ?: ((cond) ? 0 : -ETIMEDOUT); \
})
#endif

/* don't export rx-offload symbols kernel-wide */
#undef EXPORT_SYMBOL_GPL
#define EXPORT_SYMBOL_GPL(_symbol)



#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define controller master
#define spi_controller spi_master
#define SPI_CONTROLLER_HALF_DUPLEX SPI_MASTER_HALF_DUPLEX
#endif /* < v4.13.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
extern void __compiletime_error("bad bitfield mask")
__bad_mask(void);

static __always_inline u64 field_multiplier(u64 field)
{
	if ((field | (field - 1)) & ((field | (field - 1)) + 1))
		__bad_mask();
	return field & -field;
}

static __always_inline u64 field_mask(u64 field)
{
	return field / field_multiplier(field);
}
#endif /* < v4.15.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#include <linux/of_device.h>
static inline const void *device_get_match_data(struct device *dev)
{
	return of_device_get_match_data(dev);
}
#endif /* < v4.16.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
static inline int
regmap_raw_write_compat(struct regmap *map, unsigned int reg,
			const void *val, size_t val_len)
{
	size_t off = 0;

	while (val_len) {
		size_t len;
		int err;

		/* Older regmap_raw_write() implementations are
		 * limited to map->max_raw_write. But struct regmap is
		 * defined in an internal header. So hard code 32,
		 * wich is smaller than the max_raw_write of both used
		 * maps.
		 */
		len = min_t(size_t, val_len, 32);
		err = regmap_raw_write(map, reg + off, val + off, len);
		if (err)
			return err;

		off += len;
		val_len -= len;
	}

	return 0;
}

#define regmap_raw_write(_map, _reg, _val, _val_len) \
	regmap_raw_write_compat(_map, _reg, _val, _val_len)
#endif /* < v4.16.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
static inline struct clk *devm_clk_get_optional(struct device *dev, const char *id)
{
	struct clk *clk = devm_clk_get(dev, id);

	if (clk == ERR_PTR(-ENOENT))
		return NULL;

	return clk;
}
#endif /* < v5.1.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) && \
	!(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 153) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)) && \
	!(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 83) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0))
static inline bool skb_queue_empty_lockless(const struct sk_buff_head *list)
{
	return READ_ONCE(list->next) == (const struct sk_buff *) list;
}
#endif /* < v5.4.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define __vmalloc(_size, _gfp_mask) \
	__vmalloc((_size), (_gfp_mask), PAGE_KERNEL)
#endif /* < v5.8.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
static int __maybe_unused
dev_err_probe(const struct device *dev, int err, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	if (err != -EPROBE_DEFER)
		dev_err(dev, "error %pe: %pV", ERR_PTR(err), &vaf);
	else
		dev_dbg(dev, "error %pe: %pV", ERR_PTR(err), &vaf);

	va_end(args);

	return err;
}
#endif /* < v5.9.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && \
	!(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 86) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0))
static inline int pm_runtime_resume_and_get(struct device *dev)
{
	int ret;

	ret = __pm_runtime_resume(dev, RPM_GET_PUT);
	if (ret < 0) {
		pm_runtime_put_noidle(dev);
		return ret;
	}

	return 0;
}
#endif /* < v5.10.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
static inline u8 can_fd_dlc2len(u8 dlc)
{
	return can_len2dlc(dlc);
}

static inline u8 can_fd_len2dlc(u8 len)
{
	return can_len2dlc(len);
}

#define len can_dlc
#define len8_dlc __res1

/* helper to get the data length code (DLC) for Classical CAN raw DLC access */
static inline u8 can_get_cc_dlc(const struct can_frame *cf, const u32 ctrlmode)
{
	/* return len8_dlc as dlc value only if all conditions apply */
	if ((ctrlmode & CAN_CTRLMODE_CC_LEN8_DLC) &&
	    (cf->len == CAN_MAX_DLEN) &&
	    (cf->len8_dlc > CAN_MAX_DLEN && cf->len8_dlc <= CAN_MAX_RAW_DLC))
		return cf->len8_dlc;

	/* return the payload length as dlc value */
	return cf->len;
}

/* helper to set len and len8_dlc value for Classical CAN raw DLC access */
static inline void can_frame_set_cc_len(struct can_frame *cf, const u8 dlc,
					const u32 ctrlmode)
{
	/* the caller already ensured that dlc is a value from 0 .. 15 */
	if (ctrlmode & CAN_CTRLMODE_CC_LEN8_DLC && dlc > CAN_MAX_DLEN)
		cf->len8_dlc = dlc;

	/* limit the payload length 'len' to CAN_MAX_DLEN */
	cf->len = can_cc_dlc2len(dlc);
}

#undef len
#undef len8_dlc

#endif /* < v5.11.0 */



#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)

#define timecounter_cyc2time(_tc, _cycle_tstamp) \
	timecounter_cyc2time((struct timecounter *)(_tc), (_cycle_tstamp))

/* do not use BQL */
#define netdev_reset_queue(_dev) \
	({ (void)(_dev); })

#define netdev_completed_queue(_dev, _pkts, _bytes) \
	({ \
		(void)(_dev); \
		(void)(_pkts); \
		(void)(_bytes); \
	})

#define netdev_sent_queue(_dev, _bytes) \
	({ \
		(void)(_dev); \
		(void)(_bytes); \
	})

static inline int
can_put_echo_skb_compat(struct sk_buff *skb, struct net_device *dev,
			unsigned int idx, unsigned int frame_len)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	can_put_echo_skb(skb, dev, idx);
	return 0;
#else
	return can_put_echo_skb(skb, dev, idx);
#endif /* < v5.10.0 */
}

#define can_put_echo_skb(_skb, _dev, _idx, _len) \
	can_put_echo_skb_compat(_skb, _dev, _idx, _len) \

#define __can_get_echo_skb(_dev, _idx, _len_ptr, _frame_len_ptr) \
	__can_get_echo_skb((_dev), (_idx), (_len_ptr))

static inline u8 canfd_sanitize_len(u8 len)
{
	return can_fd_dlc2len(can_fd_len2dlc(len));
}

static inline unsigned int can_skb_get_frame_len(const struct sk_buff *skb)
{
	return 0;
}

#endif /* < v5.13.0 */


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)

static inline int
can_rx_offload_queue_timestamp(struct can_rx_offload *offload,
			       struct sk_buff *skb, u32 timestamp)
{
	return can_rx_offload_queue_sorted(offload, skb, timestamp);
}

#endif /* < v5.18.0 && >= v5.12.0 */

#endif
