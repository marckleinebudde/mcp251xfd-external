# SPDX-License-Identifier: GPL-2.0-only

ifneq ($(KERNELRELEASE),)

export CONFIG_CAN_MCP251XFD = m

obj-m += drivers/net/can/spi/mcp251xfd/

else

KDIR ?= /lib/modules/$(shell uname -r)/build

modules:

modules modules_install clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $(@)

endif
