obj-y += argv0.o audit.o autobind.o capability.o chroot.o condition.o domain.o environ.o file.o maymount.o mount.o network.o pivot_root.o proc_if.o realpath.o signal.o umount.o util.o

ifeq ($(PATCHLEVEL),4)
O_TARGET := ccsecurity.o
export-objs += autobind.o capability.o file.o network.o
include $(TOPDIR)/Rules.make
endif
