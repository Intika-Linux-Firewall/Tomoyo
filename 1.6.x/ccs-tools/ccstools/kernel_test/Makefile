ALL_FILES = ccs_policy_io_test newns sakura_bind_test sakura_filesystem_test \
	tomoyo_accept_test tomoyo_argv0_test tomoyo_bprm_test \
	tomoyo_capability_test tomoyo_cond_test tomoyo_env_test \
	tomoyo_execute_handler_test tomoyo_file_test tomoyo_network_test \
	tomoyo_new_capability_test tomoyo_new_file_test \
	tomoyo_new_network_test tomoyo_rewrite_test tomoyo_signal_test

all: $(ALL_FILES)
	chmod 755 testall.sh

$(ALL_FILES): include.h

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

#
# Tools for kernel testing.
#

tomoyo_capability_test: tomoyo_capability_test.c
	$(CC) $(CFLAGS) -o tomoyo_capability_test tomoyo_capability_test.c -lutil

tomoyo_new_capability_test: tomoyo_new_capability_test.c
	$(CC) $(CFLAGS) -o tomoyo_new_capability_test tomoyo_new_capability_test.c -lutil

.c:
	$(CC) $(CFLAGS) -o $@ $<

#
# Delete all tools in this package.
#

clean:
	rm -f $(ALL_FILES)
