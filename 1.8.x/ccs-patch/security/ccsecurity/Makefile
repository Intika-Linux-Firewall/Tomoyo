ccsecurity-objs := audit.o autobind.o capability.o condition.o domain.o environ.o file.o gc.o group.o memory.o mount.o network.o policy_io.o proc_if.o realpath.o signal.o util.o

ifeq ($(PATCHLEVEL),4)

ifdef CONFIG_CCSECURITY
O_TARGET := ccsecurity.o
ifdef CONFIG_CCSECURITY_LKM
all_targets: load_policy.o
obj-m := ccsecurity.o
obj-y := $(ccsecurity-objs)
else
all_targets: ccsecurity.o
obj-y := load_policy.o $(ccsecurity-objs)
endif
export-objs := load_policy.o
endif
include $(TOPDIR)/Rules.make

tomoyo2c: tomoyo2c.c
	@echo Compiling built-in policy generator for TOMOYO 1.8.x.
	@$(HOSTCC) $(HOSTCFLAGS) -o ./tomoyo2c tomoyo2c.c

policy/profile.conf:
	@echo Creating an empty policy/profile.conf
	@touch $@

policy/exception_policy.conf:
	@echo Creating a default policy/exception_policy.conf
	@echo /sbin/modprobe >> $@
	@echo /sbin/hotplug >> $@

policy/domain_policy.conf:
	@echo Creating an empty policy/domain_policy.conf
	@touch $@

policy/manager.conf:
	@echo Creating an empty policy/manager.conf
	@touch $@

policy/stat.conf:
	@echo Creating an empty policy/stat.conf
	@touch $@

builtin-policy.h: policy/profile.conf policy/exception_policy.conf policy/domain_policy.conf policy/manager.conf policy/stat.conf tomoyo2c
	@echo Generating built-in policy for TOMOYO 1.8.x.
	@./tomoyo2c profile < policy/profile.conf > $@
	@./tomoyo2c exception_policy < policy/exception_policy.conf >> $@
	@./tomoyo2c domain_policy < policy/domain_policy.conf >> $@
	@./tomoyo2c manager < policy/manager.conf >> $@
	@./tomoyo2c stat < policy/stat.conf >> $@

policy_io.o: builtin-policy.h

else

obj-y += load_policy.o
ifdef CONFIG_CCSECURITY_LKM
obj-m += ccsecurity.o
else
obj-y += ccsecurity.o
endif

$(obj)/tomoyo2c: $(obj)/tomoyo2c.c
	@echo Compiling built-in policy generator for TOMOYO 1.8.x.
	@$(HOSTCC) $(HOSTCFLAGS) -o $(obj)/tomoyo2c $(obj)/tomoyo2c.c

$(obj)/policy/profile.conf:
	@echo Creating an empty policy/profile.conf
	@touch $@

$(obj)/policy/exception_policy.conf:
	@echo Creating a default policy/exception_policy.conf
	@echo /sbin/modprobe >> $@
	@echo /sbin/hotplug >> $@

$(obj)/policy/domain_policy.conf:
	@echo Creating an empty policy/domain_policy.conf
	@touch $@

$(obj)/policy/manager.conf:
	@echo Creating an empty policy/manager.conf
	@touch $@

$(obj)/policy/stat.conf:
	@echo Creating an empty policy/stat.conf
	@touch $@

$(obj)/builtin-policy.h: $(obj)/policy/profile.conf $(obj)/policy/exception_policy.conf $(obj)/policy/domain_policy.conf $(obj)/policy/manager.conf $(obj)/policy/stat.conf $(obj)/tomoyo2c
	@echo Generating built-in policy for TOMOYO 1.8.x.
	@$(obj)/tomoyo2c profile < $(obj)/policy/profile.conf > $@
	@$(obj)/tomoyo2c exception_policy < $(obj)/policy/exception_policy.conf >> $@
	@$(obj)/tomoyo2c domain_policy < $(obj)/policy/domain_policy.conf >> $@
	@$(obj)/tomoyo2c manager < $(obj)/policy/manager.conf >> $@
	@$(obj)/tomoyo2c stat < $(obj)/policy/stat.conf >> $@

$(obj)/policy_io.o: $(obj)/builtin-policy.h

endif
