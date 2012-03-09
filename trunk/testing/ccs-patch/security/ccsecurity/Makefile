ccsecurity-objs := permission.o gc.o memory.o policy_io.o realpath.o

ifeq ($(VERSION)$(PATCHLEVEL),24)

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

policy/policy.conf:
	@mkdir -p policy/
	@echo Creating an empty policy/policy.conf
	@touch $@

builtin-policy.h: policy/policy.conf
	@echo Generating built-in policy for TOMOYO 1.8.x.
	@echo "static char ccs_builtin_policy[] __initdata =" > $@.tmp
	@sed -e 's/\\/\\134/g' -e 's/"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < policy/policy.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@mv $@.tmp $@

policy_io.o: builtin-policy.h

else

obj-y += load_policy.o
ifdef CONFIG_CCSECURITY_LKM
obj-m += ccsecurity.o
else
obj-y += ccsecurity.o
endif

$(obj)/policy/policy.conf:
	@mkdir -p $(obj)/policy/
	@echo Creating an empty policy/policy.conf
	@touch $@

$(obj)/builtin-policy.h: $(obj)/policy/policy.conf
	@echo Generating built-in policy for TOMOYO 1.8.x.
	@echo "static char ccs_builtin_policy[] __initdata =" > $@.tmp
	@sed -e 's/\\/\\134/g' -e 's/"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < $(obj)/policy/policy.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@mv $@.tmp $@

$(obj)/policy_io.o: $(obj)/builtin-policy.h

endif
