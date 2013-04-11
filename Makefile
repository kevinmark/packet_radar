#
# make a kernel module in kernel 2.6
#

PWD = $(shell pwd)
KERNEL_DIR := /lib/modules/$(shell uname -r)/build

# make target to module
obj-m:=001.o

CLEAN_FILES += .tmp_versions \
	.*.cmd *.mod.c *.o *.ko .*.o.d -r .tmp *.order *.symvers *.swp

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(RM) $(CLEAN_FILES)
