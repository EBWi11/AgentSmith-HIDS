obj-m += smith.o
smith-objs := smith_hook.o share_mem.o anti_rootkit.o

KERNEL_VER := $(shell uname -r)
KERNEL_DIR := /lib/modules/$(KERNEL_VER)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

insmod:
	sudo insmod smith_hook.ko

rmmod:
	sudo rmmod smith_hook