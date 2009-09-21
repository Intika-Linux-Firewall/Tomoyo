ALL_FILES = tomoyo_filesystem_test tomoyo_capability_test tomoyo_file_test tomoyo_rewrite_test tomoyo_argv0_test tomoyo_env_test tomoyo_network_test newns tomoyo_accept_test tomoyo_bprm_test tomoyo_cond_test tomoyo_policy_io_test tomoyo_new_file_test tomoyo_new_capability_test tomoyo_new_network_test tomoyo_execute_handler_test tomoyo_new_test tomoyo_policy_memory_test

all: $(ALL_FILES)
	chmod 755 testall.sh

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

#
# Tools for kernel testing.
#

tomoyo_capability_test: tomoyo_capability_test.c include.h
	$(CC) $(CFLAGS) -o tomoyo_capability_test tomoyo_capability_test.c -lutil
	chmod 700 tomoyo_capability_test

tomoyo_new_capability_test: tomoyo_new_capability_test.c include.h
	$(CC) $(CFLAGS) -o tomoyo_new_capability_test tomoyo_new_capability_test.c -lutil
	chmod 700 tomoyo_new_capability_test

tomoyo_new_test: tomoyo_new_test.c include.h
	$(CC) $(CFLAGS) -o tomoyo_new_test tomoyo_new_test.c -lutil
	chmod 700 tomoyo_new_test

.c:	include.h
	$(CC) $(CFLAGS) -o $@ $<
	chmod 700 $@

#
# Delete all tools in this package.
#

clean:
	rm -f $(ALL_FILES)
