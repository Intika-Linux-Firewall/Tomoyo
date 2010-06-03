ALL_FILES = ccs_filesystem_test ccs_file_test ccs_rewrite_test newns ccs_accept_test ccs_policy_io_test ccs_new_file_test ccs_new_test ccs_policy_memory_test

all: $(ALL_FILES)
	chmod 755 testall.sh

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

#
# Tools for kernel testing.
#

ccs_new_test: ccs_new_test.c include.h
	$(CC) $(CFLAGS) -o ccs_new_test ccs_new_test.c -lutil
	chmod 700 ccs_new_test

.c:	include.h
	$(CC) $(CFLAGS) -o $@ $<
	chmod 700 $@

#
# Delete all tools in this package.
#

clean:
	rm -f $(ALL_FILES)
