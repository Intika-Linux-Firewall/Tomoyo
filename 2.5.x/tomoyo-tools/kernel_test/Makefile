include ../Include.make

ALL_FILES = tomoyo_accept_test tomoyo_argv0_test tomoyo_bprm_test \
	tomoyo_cond_test tomoyo_env_test tomoyo_filesystem_test \
	tomoyo_file_test tomoyo_network_test tomoyo_new_file_test \
	tomoyo_new_network_test tomoyo_new_test tomoyo_policy_io_test \
	tomoyo_policy_memory_test tomoyo_rewrite_test tomoyo_transition_test \
	newns

all: $(ALL_FILES)
	chmod 755 testall.sh

$(ALL_FILES): include.h



#
# Tools for kernel testing.
#

.c:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

#
# Delete all test programs.
#

clean:
	rm -f $(ALL_FILES)
