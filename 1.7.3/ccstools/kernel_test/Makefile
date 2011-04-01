ALL_FILES = ccs_accept_test ccs_argv0_test ccs_bind_test ccs_bprm_test \
	ccs_capability_test ccs_cond_test ccs_env_test \
	ccs_execute_handler_test ccs_file_test ccs_filesystem_test \
	ccs_network_test ccs_new_capability_test ccs_new_file_test \
	ccs_new_network_test ccs_new_test ccs_policy_io_test \
	ccs_policy_memory_test ccs_rewrite_test ccs_signal_test newns

all: $(ALL_FILES)
	chmod 755 testall.sh

$(ALL_FILES): include.h

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

#
# Tools for kernel testing.
#

ccs_capability_test: ccs_capability_test.c
	$(CC) $(CFLAGS) -o ccs_capability_test ccs_capability_test.c -lutil

ccs_new_capability_test: ccs_new_capability_test.c
	$(CC) $(CFLAGS) -o ccs_new_capability_test ccs_new_capability_test.c -lutil

ccs_new_test: ccs_new_test.c
	$(CC) $(CFLAGS) -o ccs_new_test ccs_new_test.c -lutil

.c:
	$(CC) $(CFLAGS) -o $@ $<

#
# Delete all tools in this package.
#

clean:
	rm -f $(ALL_FILES)
