/*
 * ccs_policy_io_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2   2011/06/20
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "include.h"

static FILE *policy_fp = NULL;
static const char *policy_file = "";

static void try_io(const char *policy, const char should_success)
{
	FILE *fp = fopen(policy_file, "r");
	char buffer[8192];
	int policy_found = 0;
	memset(buffer, 0, sizeof(buffer));
	printf("%s: ", policy);
	fprintf(policy_fp, "%s\n", policy);
	if (!fp) {
		printf("BUG: policy read failed\n");
		return;
	}
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strcmp(policy_file, proc_policy_exception_policy) &&
		    !strncmp(buffer, "<kernel> ", 9))
			memmove(buffer, buffer + 9, strlen(buffer + 9) + 1);
		if (!strcmp(buffer, policy)) {
			policy_found = 1;
			break;
		}
	}
	fclose(fp);
	if (should_success) {
		if (policy_found)
			printf("OK\n");
		else
			printf("BUG: policy write failed\n");
	} else {
		if (!policy_found)
			printf("OK : write rejected.\n");
		else
			printf("BUG: policy write not rejected.\n");
	}
	fprintf(policy_fp, "delete %s\n", policy);
}

static void stage_policy_io_test(void)
{
	int i;
	policy_file = proc_policy_domain_policy;
	policy_fp = domain_fp;
	for (i = 0; i < 3; i++) {
		try_io("file chroot /", 1);
		try_io("file chroot ", 0);
		try_io("file chroot /mnt0/", 1);
		try_io("file chroot /var1/chroot2/", 1);
		try_io("file chroot /mnt0/", 1);
		try_io("file chroot /mnt0/", 1);
		try_io("file chroot /mnt0/", 1);
		try_io("file chroot /mnt\\?\\*/", 1);
		try_io("file chroot /mnt\\?\\*/", 1);
		try_io("file unmount /", 1);
		try_io("file unmount /sys1/", 1);
		try_io("file unmount /initrd2/", 1);
		try_io("file unmount /initrd/dev3/", 1);
		try_io("file unmount /initrd/\\*\\+/", 1);
		try_io("file unmount /initrd/\\@\\*/", 1);
		try_io("file unmount /initrd2/", 1);
		try_io("file pivot_root / /proc3/", 1);
		try_io("file pivot_root /sys5/ /proc3/", 1);
		try_io("file pivot_root /sys/", 0);
		try_io("file pivot_root *", 0);
		try_io("file pivot_root /sys5/ /proc3/", 1);
		try_io("file mount / / --bind 0xD", 1);
		try_io("file mount / / --move 0xF", 1);
		try_io("file mount / --remount", 0);
		try_io("file mount /", 0);
		try_io("file mount none /tmp/ tmpfs 0x1", 1);
		try_io("file mount none /tmp/ tmpfs", 0);
		try_io("file mount none /tmp/ nonexistent 0x0", 1);
		try_io("file mount none /proc/ proc 0x0", 1);
		try_io("file mount none /selinux/ selinuxfs 0x0", 1);
		try_io("file mount /proc/bus/usb proc:/bus/usb/ usbfs 0x0", 1);
		try_io("file mount none /dev/pts/ devpts 0x0", 1);
		try_io("file mount any / --remount 0xC00", 1);
		try_io("file mount /dev/sda1 /boot/ ext3 0xC00", 1);
		try_io("file mount none /dev/shm/ tmpfs 0x0", 1);
		try_io("file mount none proc:/sys/fs/binfmt_misc/ binfmt_misc "
		       "0x0", 1);
		try_io("file mount none proc:/sys/fs/binfmt_misc/ binfmt_misc "
		       "0x0 0x1", 0);
		try_io("file mount none proc:/sys/fs/binfmt_misc/ tmpfs "
		       "binfmt_misc 0x0", 0);
		try_io("file mount /proc/bus/usb proc:/bus/usb/ usbfs 0x0", 1);
	}
	policy_file = proc_policy_exception_policy;
	policy_fp = exception_fp;
	for (i = 0; i < 3; i++) {
		try_io("acl_group 0 file read /tmp/abc", 1);
		try_io("acl_group 0 file read /tmp/abc\\*", 1);
		try_io("acl_group 0 file read abc", 1);
		try_io("acl_group 0 file read /tmp/abc/", 1);
		try_io("acl_group 0 file read", 0);
		try_io("acl_group 0 file read *", 1);
		try_io("acl_group 0 misc env FOO", 1);
		try_io("acl_group 0 misc env FOO=", 0);
		try_io("acl_group 0 misc env FOO=BAR", 0);
		try_io("acl_group 0 misc env FOO BAR", 0);
		try_io("acl_group 0 misc env FOO\\040BAR", 1);
		try_io("acl_group 0 misc env FOO;BAR;BUZ", 1);
		try_io("path_group TEST /", 1);
		try_io("path_group TEST /boo", 1);
		try_io("path_group TEST /bar", 1);
		try_io("path_group TEST /\\*", 1);
		try_io("path_group TEST / /", 0);
		try_io("path_group TEST /boo", 1);
		try_io("path_group TEST /bar", 1);
		try_io("path_group TEST boo", 1);
		try_io("path_group TEST boo/", 1);
		try_io("path_group TEST /bar", 1);
		try_io("path_group TEST3 /\\*", 1);
		try_io("path_group TEST3 / /", 0);
		try_io("path_group TEST3 /boo", 1);
		try_io("path_group TEST3 /bar", 1);
		try_io("path_group TEST3 boo", 1);
		try_io("path_group TEST3 boo/", 1);
		try_io("address_group TEST 0.0.0.0", 1);
		try_io("address_group TEST 0.0.0.0-1.2.3.4", 1);
		try_io("address_group TEST 0:0:0:0:0:0:0:ff", 1);
		try_io("address_group TEST "
		       "0:0:0:0:0:0:0:0-ff:ff:ff:ff:ff:ff:ff:ff", 1);
		try_io("address_group TEST "
		       "fff0:fff1:fff2:fff3:fff4:fff5:fff6:fff7-"
		       "fff8:fff9:fffa:fffb:fffc:fffd:fffe:ffff", 1);
		try_io("address_group TEST2 0:0:0:0:0:0:0:ff", 1);
		try_io("address_group TEST2 "
		       "0:0:0:0:0:0:0:0-ff:ff:ff:ff:ff:ff:ff:ff", 1);
		try_io("address_group TEST2 "
		       "fff0:fff1:fff2:fff3:fff4:fff5:fff6:fff7-"
		       "fff8:fff9:fffa:fffb:fffc:fffd:fffe:ffff", 1);
		try_io("aggregator /boo/\\* /BOO", 1);
		try_io("aggregator /boo/\\* /BOO\\*", 0);
		try_io("aggregator /boo/\\*/ /BOO", 1);
		try_io("aggregator /boo/\\* /BOO/", 1);
		try_io("keep_domain any from <kernel>", 1);
		try_io("keep_domain any from <kernel> /sbin/init", 1);
		try_io("keep_domain any from <kernel> foo", 0);
		try_io("keep_domain any from <kernel> \\*", 0);
		try_io("keep_domain any from /ssh", 1);
		try_io("keep_domain any from /ssh /foo", 0);
		try_io("keep_domain /foo from <kernel>", 1);
		try_io("keep_domain /foo from <kernel> /sbin/init", 1);
		try_io("keep_domain from <kernel> /sbin/init", 0);
		try_io("keep_domain \\* from <kernel> /sbin/init", 0);
		try_io("no_keep_domain any from <kernel>", 1);
		try_io("no_keep_domain any from <kernel> /sbin/init", 1);
		try_io("no_keep_domain any from <kernel> foo", 0);
		try_io("no_keep_domain any from <kernel> \\*", 0);
		try_io("no_keep_domain any from /ssh", 1);
		try_io("no_keep_domain any from /ssh /foo", 0);
		try_io("no_keep_domain /foo from <kernel>", 1);
		try_io("no_keep_domain /foo from <kernel> /sbin/init", 1);
		try_io("no_keep_domain from <kernel> /sbin/init", 0);
		try_io("no_keep_domain \\* from <kernel> /sbin/init", 0);
		try_io("initialize_domain /foo from any", 1);
		try_io("initialize_domain /\\* from any", 1);
		try_io("initialize_domain /foo /bar from any", 0);
		try_io("initialize_domain /foo from /bar", 1);
		try_io("initialize_domain /foo from <kernel> /bar", 1);
		try_io("initialize_domain /\\* from <kernel>", 1);
		try_io("initialize_domain /foo from <kernel> \\*", 0);
		try_io("no_initialize_domain /foo from any", 1);
		try_io("no_initialize_domain /\\* from any", 1);
		try_io("no_initialize_domain /foo /bar from any", 0);
		try_io("no_initialize_domain /foo from /bar", 1);
		try_io("no_initialize_domain /foo from <kernel> /bar", 1);
		try_io("no_initialize_domain /\\* from <kernel>", 1);
		try_io("no_initialize_domain /foo from <kernel> \\*", 0);
		try_io("deny_autobind 0-65535", 1);
		try_io("deny_autobind 0-65536", 0);
		try_io("deny_autobind 65-100", 1);
		try_io("deny_autobind 100-65", 0);
		try_io("deny_autobind 500", 1);
		try_io("deny_autobind 65535", 1);
		try_io("deny_autobind 65536", 0);
		try_io("deny_autobind *", 0);
		try_io("deny_autobind 500", 1);
		try_io("deny_autobind 0-65535", 1);
		try_io("deny_autobind 500", 1);
		try_io("deny_autobind 0-65535", 1);
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	stage_policy_io_test();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
		set_profile(0, "");
	}
	return 0;
}
