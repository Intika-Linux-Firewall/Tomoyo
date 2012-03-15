ccsecurity-objs := permission.o gc.o memory.o policy_io.o realpath.o

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
