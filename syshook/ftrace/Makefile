obj-m   := syshook.o
syshook-objs := syscall_hook.o
KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm -rf Module.symvers syscall_stub_hook.o syshook.ko syshook.mod.o modules.order syscall_hook.o syshook.mod.c syshook.o