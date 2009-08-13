obj-y += address_group.o audit.o autobind.o capability.o chroot.o condition.o domain.o environ.o file.o gc.o load_policy.o maymount.o memory.o mount.o network.o number_group.o path_group.o pivot_root.o policy_io.o proc_if.o realpath.o signal.o umount.o util.o

ifeq ($(PATCHLEVEL),4)
O_TARGET := ccsecurity.o
export-objs += autobind.o capability.o file.o network.o
include $(TOPDIR)/Rules.make
endif
