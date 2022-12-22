# SPDX-License-Identifier: GPL-2.0
KDIR ?= ../../

obj-m += da_test.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
