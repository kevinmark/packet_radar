#Makefile for hello.c file
#
#VERSION = 2
#PATCHLEVEL = 6
#SUBLEVEL = 32
#EXTRAVERSION = -5-686
#NAME = debian lenny

#KERNEL_DIR:=/home/omk/download_large/linux-2.6.39.4
KERNEL_DIR:=/home/omk/download_large/linux-2.6.32.5
obj-m:=001.o

CLEAN_FILES += .tmp_versions \
	.*.cmd *.mod.c *.o *.ko .*.o.d -r .tmp *.order *.symvers *.swp

default:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

clean:
	$(RM) $(CLEAN_FILES)
