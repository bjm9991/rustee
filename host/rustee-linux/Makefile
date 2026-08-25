# SPDX-License-Identifier: GPL-2.0-only
# Out-of-tree. Not in the TEE TCB.
obj-m += rustee_virt.o
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
