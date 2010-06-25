/*
 * security/ccsecurity/policy_io.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/06/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

static struct ccs_profile ccs_default_profile = {
	.learning = &ccs_default_profile.preference,
	.permissive = &ccs_default_profile.preference,
	.enforcing = &ccs_default_profile.preference,
	.audit = &ccs_default_profile.preference,
#ifdef CONFIG_CCSECURITY_AUDIT
	.preference.audit_max_grant_log = CONFIG_CCSECURITY_MAX_GRANT_LOG,
	.preference.audit_max_reject_log = CONFIG_CCSECURITY_MAX_REJECT_LOG,
#endif
	.preference.audit_task_info = true,
	.preference.audit_path_info = true,
	.preference.enforcing_penalty = 0,
	.preference.enforcing_verbose = true,
	.preference.learning_max_entry = CONFIG_CCSECURITY_MAX_ACCEPT_ENTRY,
	.preference.learning_verbose = false,
	.preference.learning_exec_realpath = true,
	.preference.learning_exec_argv0 = true,
	.preference.learning_symlink_target = true,
	.preference.permissive_verbose = true
};

/* Profile version. Currently only 20090903 is defined. */
static unsigned int ccs_profile_version;

/* Profile table. Memory is allocated as needed. */
static struct ccs_profile *ccs_profile_ptr[CCS_MAX_PROFILES];

/* String table for functionality that takes 4 modes. */
const char *ccs_mode[CCS_CONFIG_MAX_MODE] = {
	[CCS_CONFIG_DISABLED] = "disabled",
	[CCS_CONFIG_LEARNING] = "learning",
	[CCS_CONFIG_PERMISSIVE] = "permissive",
	[CCS_CONFIG_ENFORCING] = "enforcing"
};

/* String table for /proc/ccs/profile */
static const char *ccs_mac_keywords[CCS_MAX_MAC_INDEX +
				    CCS_MAX_CAPABILITY_INDEX +
				    CCS_MAX_MAC_CATEGORY_INDEX] = {
	[CCS_MAC_FILE_EXECUTE]
	= "file::execute",
	[CCS_MAC_FILE_OPEN]
	= "file::open",
	[CCS_MAC_FILE_CREATE]
	= "file::create",
	[CCS_MAC_FILE_UNLINK]
	= "file::unlink",
	[CCS_MAC_FILE_MKDIR]
	= "file::mkdir",
	[CCS_MAC_FILE_RMDIR]
	= "file::rmdir",
	[CCS_MAC_FILE_MKFIFO]
	= "file::mkfifo",
	[CCS_MAC_FILE_MKSOCK]
	= "file::mksock",
	[CCS_MAC_FILE_TRUNCATE]
	= "file::truncate",
	[CCS_MAC_FILE_SYMLINK]
	= "file::symlink",
	[CCS_MAC_FILE_REWRITE]
	= "file::rewrite",
	[CCS_MAC_FILE_MKBLOCK]
	= "file::mkblock",
	[CCS_MAC_FILE_MKCHAR]
	= "file::mkchar",
	[CCS_MAC_FILE_LINK]
	= "file::link",
	[CCS_MAC_FILE_RENAME]
	= "file::rename",
	[CCS_MAC_FILE_CHMOD]
	= "file::chmod",
	[CCS_MAC_FILE_CHOWN]
	= "file::chown",
	[CCS_MAC_FILE_CHGRP]
	= "file::chgrp",
	[CCS_MAC_FILE_IOCTL]
	= "file::ioctl",
	[CCS_MAC_FILE_CHROOT]
	= "file::chroot",
	[CCS_MAC_FILE_MOUNT]
	= "file::mount",
	[CCS_MAC_FILE_UMOUNT]
	= "file::umount",
	[CCS_MAC_FILE_PIVOT_ROOT]
	= "file::pivot_root",
	[CCS_MAC_FILE_TRANSIT]
	= "file::transit",
	[CCS_MAC_ENVIRON]
	= "misc::env",
	[CCS_MAC_NETWORK_UDP_BIND]
	= "network::inet_udp_bind",
	[CCS_MAC_NETWORK_UDP_CONNECT]
	= "network::inet_udp_connect",
	[CCS_MAC_NETWORK_TCP_BIND]
	= "network::inet_tcp_bind",
	[CCS_MAC_NETWORK_TCP_LISTEN]
	= "network::inet_tcp_listen",
	[CCS_MAC_NETWORK_TCP_CONNECT]
	= "network::inet_tcp_connect",
	[CCS_MAC_NETWORK_TCP_ACCEPT]
	= "network::inet_tcp_accept",
	[CCS_MAC_NETWORK_RAW_BIND]
	= "network::inet_raw_bind",
	[CCS_MAC_NETWORK_RAW_CONNECT]
	= "network::inet_raw_connect",
	[CCS_MAC_SIGNAL]
	= "ipc::signal",
	[CCS_MAX_MAC_INDEX + CCS_INET_STREAM_SOCKET_CREATE]
	= "capability::inet_tcp_create",
	[CCS_MAX_MAC_INDEX + CCS_INET_STREAM_SOCKET_LISTEN]
	= "capability::inet_tcp_listen",
	[CCS_MAX_MAC_INDEX + CCS_INET_STREAM_SOCKET_CONNECT]
	= "capability::inet_tcp_connect",
	[CCS_MAX_MAC_INDEX + CCS_USE_INET_DGRAM_SOCKET]
	= "capability::use_inet_udp",
	[CCS_MAX_MAC_INDEX + CCS_USE_INET_RAW_SOCKET]
	= "capability::use_inet_ip",
	[CCS_MAX_MAC_INDEX + CCS_USE_ROUTE_SOCKET]
	= "capability::use_route",
	[CCS_MAX_MAC_INDEX + CCS_USE_PACKET_SOCKET]
	= "capability::use_packet",
	[CCS_MAX_MAC_INDEX + CCS_SYS_MOUNT]
	= "capability::SYS_MOUNT",
	[CCS_MAX_MAC_INDEX + CCS_SYS_UMOUNT]
	= "capability::SYS_UMOUNT",
	[CCS_MAX_MAC_INDEX + CCS_SYS_REBOOT]
	= "capability::SYS_REBOOT",
	[CCS_MAX_MAC_INDEX + CCS_SYS_CHROOT]
	= "capability::SYS_CHROOT",
	[CCS_MAX_MAC_INDEX + CCS_SYS_KILL]
	= "capability::SYS_KILL",
	[CCS_MAX_MAC_INDEX + CCS_SYS_VHANGUP]
	= "capability::SYS_VHANGUP",
	[CCS_MAX_MAC_INDEX + CCS_SYS_SETTIME]
	= "capability::SYS_TIME",
	[CCS_MAX_MAC_INDEX + CCS_SYS_NICE]
	= "capability::SYS_NICE",
	[CCS_MAX_MAC_INDEX + CCS_SYS_SETHOSTNAME]
	= "capability::SYS_SETHOSTNAME",
	[CCS_MAX_MAC_INDEX + CCS_USE_KERNEL_MODULE]
	= "capability::use_kernel_module",
	[CCS_MAX_MAC_INDEX + CCS_CREATE_FIFO]
	= "capability::create_fifo",
	[CCS_MAX_MAC_INDEX + CCS_CREATE_BLOCK_DEV]
	= "capability::create_block_dev",
	[CCS_MAX_MAC_INDEX + CCS_CREATE_CHAR_DEV]
	= "capability::create_char_dev",
	[CCS_MAX_MAC_INDEX + CCS_CREATE_UNIX_SOCKET]
	= "capability::create_unix_socket",
	[CCS_MAX_MAC_INDEX + CCS_SYS_LINK]
	= "capability::SYS_LINK",
	[CCS_MAX_MAC_INDEX + CCS_SYS_SYMLINK]
	= "capability::SYS_SYMLINK",
	[CCS_MAX_MAC_INDEX + CCS_SYS_RENAME]
	= "capability::SYS_RENAME",
	[CCS_MAX_MAC_INDEX + CCS_SYS_UNLINK]
	= "capability::SYS_UNLINK",
	[CCS_MAX_MAC_INDEX + CCS_SYS_CHMOD]
	= "capability::SYS_CHMOD",
	[CCS_MAX_MAC_INDEX + CCS_SYS_CHOWN]
	= "capability::SYS_CHOWN",
	[CCS_MAX_MAC_INDEX + CCS_SYS_IOCTL]
	= "capability::SYS_IOCTL",
	[CCS_MAX_MAC_INDEX + CCS_SYS_KEXEC_LOAD]
	= "capability::SYS_KEXEC_LOAD",
	[CCS_MAX_MAC_INDEX + CCS_SYS_PIVOT_ROOT]
	= "capability::SYS_PIVOT_ROOT",
	[CCS_MAX_MAC_INDEX + CCS_SYS_PTRACE]
	= "capability::SYS_PTRACE",
	[CCS_MAX_MAC_INDEX + CCS_CONCEAL_MOUNT]
	= "capability::conceal_mount",
	[CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
	 + CCS_MAC_CATEGORY_FILE] = "file",
	[CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
	 + CCS_MAC_CATEGORY_NETWORK] = "network",
	[CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
	 + CCS_MAC_CATEGORY_MISC] = "misc",
	[CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
	 + CCS_MAC_CATEGORY_IPC] = "ipc",
	[CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
	 + CCS_MAC_CATEGORY_CAPABILITY] = "capability",
};

/* Permit policy management by non-root user? */
static bool ccs_manage_by_non_root;

/**
 * ccs_cap2keyword - Convert capability operation to capability name.
 *
 * @operation: The capability index.
 *
 * Returns the name of the specified capability's name.
 */
const char *ccs_cap2keyword(const u8 operation)
{
	return operation < CCS_MAX_CAPABILITY_INDEX
		? ccs_mac_keywords[CCS_MAX_MAC_INDEX + operation] + 12 : NULL;
}

/**
 * ccs_yesno - Return "yes" or "no".
 *
 * @value: Bool value.
 */
static const char *ccs_yesno(const unsigned int value)
{
	return value ? "yes" : "no";
}

static void ccs_addprintf(char *buffer, int len, const char *fmt, ...)
{
	va_list args;
	const int pos = strlen(buffer);
	va_start(args, fmt);
	vsnprintf(buffer + pos, len - pos - 1, fmt, args);
	va_end(args);
}

/**
 * ccs_flush - Flush queued string to userspace's buffer.
 *
 * @head:   Pointer to "struct ccs_io_buffer".
 *
 * Returns true if all data was flushed, false otherwise.
 */
static bool ccs_flush(struct ccs_io_buffer *head)
{
	while (head->r.w_pos) {
		const char *w = head->r.w[0];
		int len = strlen(w);
		if (len) {
			if (len > head->read_user_buf_avail)
				len = head->read_user_buf_avail;
			if (!len)
				return false;
			if (copy_to_user(head->read_user_buf, w, len))
				return false;
			head->read_user_buf_avail -= len;
			head->read_user_buf += len;
			w += len;
		}
		if (*w) {
			head->r.w[0] = w;
			return false;
		}
		/* Add '\0' for audit logs and query. */
		if (head->poll) {
			if (!head->read_user_buf_avail ||
			    copy_to_user(head->read_user_buf, "", 1))
				return false;
			head->read_user_buf_avail--;
			head->read_user_buf++;
		}
		head->r.w_pos--;
		for (len = 0; len < head->r.w_pos; len++)
			head->r.w[len] = head->r.w[len + 1];
	}
	head->r.avail = 0;
	return true;
}

/**
 * ccs_set_string - Queue string to "struct ccs_io_buffer" structure.
 *
 * @head:   Pointer to "struct ccs_io_buffer".
 * @string: String to print.
 *
 * Note that @string has to be kept valid until @head is kfree()d.
 * This means that char[] allocated on stack memory cannot be passed to
 * this function. Use ccs_io_printf() for char[] allocated on stack memory.
 */
static void ccs_set_string(struct ccs_io_buffer *head, const char *string)
{
	if (head->r.w_pos < CCS_MAX_IO_READ_QUEUE) {
		head->r.w[head->r.w_pos++] = string;
		ccs_flush(head);
	} else
		WARN_ON(1);
}

/**
 * ccs_io_printf - printf() to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @fmt:  The printf()'s format string, followed by parameters.
 */
void ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
{
	va_list args;
	int len;
	int pos = head->r.avail;
	int size = head->readbuf_size - pos;
	if (size <= 0)
		return;
	va_start(args, fmt);
	len = vsnprintf(head->read_buf + pos, size, fmt, args) + 1;
	va_end(args);
	if (pos + len >= head->readbuf_size) {
		WARN_ON(1);
		return;
	}
	head->r.avail += len;
	ccs_set_string(head, head->read_buf + pos);
}

static void ccs_set_space(struct ccs_io_buffer *head)
{
	ccs_set_string(head, " ");
}

static bool ccs_set_lf(struct ccs_io_buffer *head)
{
	ccs_set_string(head, "\n");
	return !head->r.w_pos;
}

/**
 * ccs_assign_profile - Create a new profile.
 *
 * @profile: Profile number to create.
 *
 * Returns pointer to "struct ccs_profile" on success, NULL otherwise.
 */
static struct ccs_profile *ccs_assign_profile(const unsigned int profile)
{
	struct ccs_profile *ptr;
	struct ccs_profile *entry;
	if (profile >= CCS_MAX_PROFILES)
		return NULL;
	ptr = ccs_profile_ptr[profile];
	if (ptr)
		return ptr;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	ptr = ccs_profile_ptr[profile];
	if (!ptr && ccs_memory_ok(entry, sizeof(*entry))) {
		ptr = entry;
		ptr->audit = &ccs_default_profile.preference;
		ptr->learning = &ccs_default_profile.preference;
		ptr->permissive = &ccs_default_profile.preference;
		ptr->enforcing = &ccs_default_profile.preference;
		ptr->default_config = CCS_CONFIG_DISABLED |
			CCS_CONFIG_WANT_GRANT_LOG | CCS_CONFIG_WANT_REJECT_LOG;
		memset(ptr->config, CCS_CONFIG_USE_DEFAULT,
		       sizeof(ptr->config));
		mb(); /* Avoid out-of-order execution. */
		ccs_profile_ptr[profile] = ptr;
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	kfree(entry);
	return ptr;
}

/**
 * ccs_check_profile - Check all profiles currently assigned to domains are defined.
 */
static void ccs_check_profile(void)
{
	struct ccs_domain_info *domain;
	const int idx = ccs_read_lock();
	ccs_policy_loaded = true;
	list_for_each_entry_rcu(domain, &ccs_domain_list, list) {
		const u8 profile = domain->profile;
		if (ccs_profile_ptr[profile])
			continue;
		panic("Profile %u (used by '%s') not defined.\n",
		      profile, domain->domainname->name);
	}
	ccs_read_unlock(idx);
	if (ccs_profile_version != 20090903)
		panic("Profile version %u is not supported.\n",
		      ccs_profile_version);
	printk(KERN_INFO "CCSecurity: 1.7.2+   2010/06/04\n");
	printk(KERN_INFO "Mandatory Access Control activated.\n");
}

/**
 * ccs_profile - Find a profile.
 *
 * @profile: Profile number to find.
 *
 * Returns pointer to "struct ccs_profile".
 */
struct ccs_profile *ccs_profile(const u8 profile)
{
	struct ccs_profile *ptr = ccs_profile_ptr[profile];
	if (!ccs_policy_loaded)
		return &ccs_default_profile;
	BUG_ON(!ptr);
	return ptr;
}

static s8 ccs_find_yesno(const char *string, const char *find)
{
	const char *cp = strstr(string, find);
	if (cp) {
		cp += strlen(find);
		if (!strncmp(cp, "=yes", 4))
			return 1;
		else if (!strncmp(cp, "=no", 3))
			return 0;
	}
	return -1;
}

static void ccs_set_bool(bool *b, const char *string, const char *find)
{
	switch (ccs_find_yesno(string, find)) {
	case 1:
		*b = true;
		break;
	case 0:
		*b = false;
		break;
	}
}

static void ccs_set_uint(unsigned int *i, const char *string, const char *find)
{
	const char *cp = strstr(string, find);
	if (cp)
		sscanf(cp + strlen(find), "=%u", i);
}

static void ccs_set_pref(const char *name, const char *value,
			 const bool use_default, struct ccs_profile *profile)
{
	struct ccs_preference **pref;
	bool *verbose;
	if (!strcmp(name, "audit")) {
		if (use_default) {
			pref = &profile->audit;
			goto set_default;
		}
		profile->audit = &profile->preference;
#ifdef CONFIG_CCSECURITY_AUDIT
		ccs_set_uint(&profile->preference.audit_max_grant_log, value,
			     "max_grant_log");
		ccs_set_uint(&profile->preference.audit_max_reject_log, value,
			     "max_reject_log");
#endif
		ccs_set_bool(&profile->preference.audit_task_info, value,
			     "task_info");
		ccs_set_bool(&profile->preference.audit_path_info, value,
			     "path_info");
		return;
	}
	if (!strcmp(name, "enforcing")) {
		if (use_default) {
			pref = &profile->enforcing;
			goto set_default;
		}
		profile->enforcing = &profile->preference;
		ccs_set_uint(&profile->preference.enforcing_penalty, value,
			     "penalty");
		verbose = &profile->preference.enforcing_verbose;
		goto set_verbose;
	}
	if (!strcmp(name, "permissive")) {
		if (use_default) {
			pref = &profile->permissive;
			goto set_default;
		}
		profile->permissive = &profile->preference;
		verbose = &profile->preference.permissive_verbose;
		goto set_verbose;
	}
	if (!strcmp(name, "learning")) {
		if (use_default) {
			pref = &profile->learning;
			goto set_default;
		}
		profile->learning = &profile->preference;
		ccs_set_uint(&profile->preference.learning_max_entry, value,
			     "max_entry");
		ccs_set_bool(&profile->preference.learning_exec_realpath,
			     value, "exec.realpath");
		ccs_set_bool(&profile->preference.learning_exec_argv0, value,
			     "exec.argv0");
		ccs_set_bool(&profile->preference.learning_symlink_target,
			     value, "symlink.target");
		verbose = &profile->preference.learning_verbose;
		goto set_verbose;
	}
	return;
 set_default:
	*pref = &ccs_default_profile.preference;
	return;
 set_verbose:
	ccs_set_bool(verbose, value, "verbose");
}

static int ccs_set_mode(char *name, const char *value, const bool use_default,
			struct ccs_profile *profile)
{
	u8 i;
	u8 config;
	if (!strcmp(name, "CONFIG")) {
		i = CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
			+ CCS_MAX_MAC_CATEGORY_INDEX;
		config = profile->default_config;
	} else if (ccs_str_starts(&name, "CONFIG::")) {
		config = 0;
		for (i = 0; i < CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
			     + CCS_MAX_MAC_CATEGORY_INDEX; i++) {
			if (strcmp(name, ccs_mac_keywords[i]))
				continue;
			config = profile->config[i];
			break;
		}
		if (i == CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
		    + CCS_MAX_MAC_CATEGORY_INDEX)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (use_default) {
		config = CCS_CONFIG_USE_DEFAULT;
	} else {
		u8 mode;
		for (mode = 0; mode < CCS_CONFIG_MAX_MODE; mode++)
			if (strstr(value, ccs_mode[mode]))
				/*
				 * Update lower 3 bits in order to distinguish
				 * 'config' from 'CCS_CONFIG_USE_DEAFULT'.
				 */
				config = (config & ~7) | mode;
#ifdef CONFIG_CCSECURITY_AUDIT
		if (config != CCS_CONFIG_USE_DEFAULT) {
			switch (ccs_find_yesno(value, "grant_log")) {
			case 1:
				config |= CCS_CONFIG_WANT_GRANT_LOG;
				break;
			case 0:
				config &= ~CCS_CONFIG_WANT_GRANT_LOG;
				break;
			}
			switch (ccs_find_yesno(value, "reject_log")) {
			case 1:
				config |= CCS_CONFIG_WANT_REJECT_LOG;
				break;
			case 0:
				config &= ~CCS_CONFIG_WANT_REJECT_LOG;
				break;
			}
		}
#endif
	}
	if (i < CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
	    + CCS_MAX_MAC_CATEGORY_INDEX)
		profile->config[i] = config;
	else if (config != CCS_CONFIG_USE_DEFAULT)
		profile->default_config = config;
	return 0;
}

/**
 * ccs_write_profile - Write profile table.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_profile(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	unsigned int i;
	bool use_default = false;
	char *cp;
	struct ccs_profile *profile;
	if (sscanf(data, "PROFILE_VERSION=%u", &ccs_profile_version) == 1)
		return 0;
	i = simple_strtoul(data, &cp, 10);
	if (data == cp) {
		profile = &ccs_default_profile;
	} else {
		if (*cp != '-')
			return -EINVAL;
		data = cp + 1;
		profile = ccs_assign_profile(i);
		if (!profile)
			return -EINVAL;
	}
	cp = strchr(data, '=');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	if (profile != &ccs_default_profile)
		use_default = strstr(cp, "use_default") != NULL;
	if (ccs_str_starts(&data, "PREFERENCE::")) {
		ccs_set_pref(data, cp, use_default, profile);
		return 0;
	}
	if (profile == &ccs_default_profile)
		return -EINVAL;
	if (!strcmp(data, "COMMENT")) {
		const struct ccs_path_info *old_comment = profile->comment;
		profile->comment = ccs_get_name(cp);
		ccs_put_name(old_comment);
		return 0;
	}
	return ccs_set_mode(data, cp, use_default, profile);
}

static void ccs_print_preference(struct ccs_io_buffer *head, const int idx)
{
	struct ccs_preference *pref = &ccs_default_profile.preference;
	const struct ccs_profile *profile = idx >= 0 ?
		ccs_profile_ptr[idx] : NULL;
	char buffer[16] = "";
	if (profile) {
		buffer[sizeof(buffer) - 1] = '\0';
		snprintf(buffer, sizeof(buffer) - 1, "%u-", idx);
	}
	if (profile) {
		pref = profile->audit;
		if (pref == &ccs_default_profile.preference)
			goto skip0;
	}
	ccs_io_printf(head, "%sPREFERENCE::%s={ "
#ifdef CONFIG_CCSECURITY_AUDIT
		      "max_grant_log=%u max_reject_log=%u "
#endif
		      "task_info=%s path_info=%s }\n", buffer,
		      "audit",
#ifdef CONFIG_CCSECURITY_AUDIT
		      pref->audit_max_grant_log,
		      pref->audit_max_reject_log,
#endif
		      ccs_yesno(pref->audit_task_info),
		      ccs_yesno(pref->audit_path_info));
 skip0:
	if (profile) {
		pref = profile->learning;
		if (pref == &ccs_default_profile.preference)
			goto skip1;
	}
	ccs_io_printf(head, "%sPREFERENCE::%s={ "
		      "verbose=%s max_entry=%u exec.realpath=%s "
		      "exec.argv0=%s symlink.target=%s }\n",
		      buffer, "learning",
		      ccs_yesno(pref->learning_verbose),
		      pref->learning_max_entry,
		      ccs_yesno(pref->learning_exec_realpath),
		      ccs_yesno(pref->learning_exec_argv0),
		      ccs_yesno(pref->learning_symlink_target));
 skip1:
	if (profile) {
		pref = profile->permissive;
		if (pref == &ccs_default_profile.preference)
			goto skip2;
	}
	ccs_io_printf(head, "%sPREFERENCE::%s={ verbose=%s }\n",
		      buffer, "permissive",
		      ccs_yesno(pref->permissive_verbose));
 skip2:
	if (profile) {
		pref = profile->enforcing;
		if (pref == &ccs_default_profile.preference)
			return;
	}
	ccs_io_printf(head, "%sPREFERENCE::%s={ verbose=%s "
		      "penalty=%u }\n", buffer, "enforcing",
		      ccs_yesno(pref->enforcing_verbose),
		      pref->enforcing_penalty);
}

static void ccs_print_config(struct ccs_io_buffer *head, const u8 config)
{
	ccs_io_printf(head, "={ mode=%s", ccs_mode[config & 3]);
#ifdef CONFIG_CCSECURITY_AUDIT
	ccs_io_printf(head, " grant_log=%s reject_log=%s",
		      ccs_yesno(config & CCS_CONFIG_WANT_GRANT_LOG),
		      ccs_yesno(config & CCS_CONFIG_WANT_REJECT_LOG));
#endif
	ccs_set_string(head, " }\n");
}

/**
 * ccs_read_profile - Read profile table.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 */
static void ccs_read_profile(struct ccs_io_buffer *head)
{
	u8 index;
	const struct ccs_profile *profile;
 next:
	index = head->r.index;
	profile = ccs_profile_ptr[index];
	switch (head->r.step) {
	case 0:
		ccs_io_printf(head, "PROFILE_VERSION=%s\n", "20090903");
		ccs_print_preference(head, -1);
		head->r.step++;
		break;
	case 1:
		for ( ; head->r.index < CCS_MAX_PROFILES;
		      head->r.index++)
			if (ccs_profile_ptr[head->r.index])
				break;
		if (head->r.index == CCS_MAX_PROFILES)
			return;
		head->r.step++;
		break;
	case 2:
		{
			const struct ccs_path_info *comment = profile->comment;
			ccs_io_printf(head, "%u-COMMENT=", index);
			ccs_set_string(head, comment ? comment->name : "");
			ccs_set_lf(head);
			head->r.step++;
		}
		break;
	case 3:
		{
			ccs_io_printf(head, "%u-%s", index, "CONFIG");
			ccs_print_config(head, profile->default_config);
			head->r.bit = 0;
			head->r.step++;
		}
		break;
	case 4:
		for ( ; head->r.bit < CCS_MAX_MAC_INDEX
			      + CCS_MAX_CAPABILITY_INDEX
			      + CCS_MAX_MAC_CATEGORY_INDEX; head->r.bit++) {
			const u8 i = head->r.bit;
			const u8 config = profile->config[i];
			if (config == CCS_CONFIG_USE_DEFAULT)
				continue;
			ccs_io_printf(head, "%u-%s%s", index, "CONFIG::",
				      ccs_mac_keywords[i]);
			ccs_print_config(head, config);
			head->r.bit++;
			break;
		}
		if (head->r.bit == CCS_MAX_MAC_INDEX
		    + CCS_MAX_CAPABILITY_INDEX
		    + CCS_MAX_MAC_CATEGORY_INDEX) {
			ccs_print_preference(head, index);
			head->r.index++;
			head->r.step = 1;
		}
		break;
	}
	if (ccs_flush(head))
		goto next;
}

static bool ccs_same_manager(const struct ccs_acl_head *a,
			     const struct ccs_acl_head *b)
{
	return container_of(a, struct ccs_manager, head)->manager
		== container_of(b, struct ccs_manager, head)->manager;
}

/**
 * ccs_update_manager_entry - Add a manager entry.
 *
 * @manager:   The path to manager or the domainnamme.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_manager_entry(const char *manager, const bool is_delete)
{
	struct ccs_manager e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (ccs_domain_def(manager)) {
		if (!ccs_correct_domain(manager))
			return -EINVAL;
		e.is_domain = true;
	} else {
		if (!ccs_correct_path(manager))
			return -EINVAL;
	}
	e.manager = ccs_get_name(manager);
	if (!e.manager)
		return error;
	error = ccs_update_policy(&e.head, sizeof(e), is_delete,
				  &ccs_policy_list[CCS_ID_MANAGER],
				  ccs_same_manager);
	ccs_put_name(e.manager);
	return error;
}

/**
 * ccs_write_manager - Write manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_manager(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	bool is_delete = ccs_str_starts(&data, CCS_KEYWORD_DELETE);
	if (!strcmp(data, "manage_by_non_root")) {
		ccs_manage_by_non_root = !is_delete;
		return 0;
	}
	return ccs_update_manager_entry(data, is_delete);
}

/**
 * ccs_read_manager - Read manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_manager(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	list_for_each_cookie(head->r.acl, &ccs_policy_list[CCS_ID_MANAGER]) {
		struct ccs_manager *ptr =
			list_entry(head->r.acl, typeof(*ptr), head.list);
		if (ptr->head.is_deleted)
			continue;
		if (!ccs_flush(head))
			return;
		ccs_set_string(head, ptr->manager->name);
		ccs_set_lf(head);
	}
	head->r.eof = true;
}

/**
 * ccs_manager - Check whether the current process is a policy manager.
 *
 * Returns true if the current process is permitted to modify policy
 * via /proc/ccs/ interface.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_manager(void)
{
	struct ccs_manager *ptr;
	const char *exe;
	struct task_struct *task = current;
	const struct ccs_path_info *domainname
		= ccs_current_domain()->domainname;
	bool found = false;
	if (!ccs_policy_loaded)
		return true;
	if (task->ccs_flags & CCS_TASK_IS_MANAGER)
		return true;
	if (!ccs_manage_by_non_root && (current_uid() || current_euid()))
		return false;
	exe = ccs_get_exe();
	list_for_each_entry_rcu(ptr, &ccs_policy_list[CCS_ID_MANAGER],
				head.list) {
		if (ptr->head.is_deleted)
			continue;
		if (ptr->is_domain) {
			if (ccs_pathcmp(domainname, ptr->manager))
				continue;
		} else {
			if (!exe || strcmp(exe, ptr->manager->name))
				continue;
		}
		/* Set manager flag. */
		task->ccs_flags |= CCS_TASK_IS_MANAGER;
		found = true;
		break;
	}
	if (!found) { /* Reduce error messages. */
		static pid_t ccs_last_pid;
		const pid_t pid = current->pid;
		if (ccs_last_pid != pid) {
			printk(KERN_WARNING "%s ( %s ) is not permitted to "
			       "update policies.\n", domainname->name, exe);
			ccs_last_pid = pid;
		}
	}
	kfree(exe);
	return found;
}

/**
 * ccs_find_condition_part - Find condition part from the statement.
 *
 * @data: String to parse.
 *
 * Returns pointer to the condition part if it was found in the statement,
 * NULL otherwise.
 */
static char *ccs_find_condition_part(char *data)
{
	char *cp = strstr(data, " if ");
	if (!cp)
		cp = strstr(data, " ; set ");
	if (cp)
		*cp++ = '\0';
	return cp;
}

/**
 * ccs_select_one - Parse select command.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_select_one(struct ccs_io_buffer *head, const char *data)
{
	unsigned int pid;
	struct ccs_domain_info *domain = NULL;
	bool global_pid = false;
	if (!strcmp(data, "allow_execute")) {
		head->r.print_execute_only = true;
		return true;
	}
	if (sscanf(data, "pid=%u", &pid) == 1 ||
	    (global_pid = true, sscanf(data, "global-pid=%u", &pid) == 1)) {
		struct task_struct *p;
		ccs_tasklist_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
		if (global_pid)
			p = ccsecurity_exports.find_task_by_pid_ns(pid,
							       &init_pid_ns);
		else
			p = ccsecurity_exports.find_task_by_vpid(pid);
#else
		p = find_task_by_pid(pid);
#endif
		if (p)
			domain = ccs_task_domain(p);
		ccs_tasklist_unlock();
	} else if (!strncmp(data, "domain=", 7)) {
		if (ccs_domain_def(data + 7))
			domain = ccs_find_domain(data + 7);
	} else
		return false;
	head->w.domain = domain;
	/* Accessing read_buf is safe because head->io_sem is held. */
	if (!head->read_buf)
		return true; /* Do nothing if open(O_WRONLY). */
	memset(&head->r, 0, sizeof(head->r));
	head->r.print_this_domain_only = true;
	head->r.eof = !domain;
	head->r.domain = &domain->list;
	ccs_io_printf(head, "# select %s\n", data);
	if (domain && domain->is_deleted)
		ccs_set_string(head, "# This is a deleted domain.\n");
	return true;
}

static int ccs_write_domain2(char *data, struct ccs_domain_info *domain,
			     const bool is_delete)
{
	static const struct {
		const char *keyword;
		int (*write) (char *, struct ccs_domain_info *,
			      struct ccs_condition *, const bool);
	} ccs_callback[5] = {
		{ CCS_KEYWORD_ALLOW_NETWORK, ccs_write_network },
		{ CCS_KEYWORD_ALLOW_ENV, ccs_write_env },
		{ CCS_KEYWORD_ALLOW_CAPABILITY, ccs_write_capability },
		{ CCS_KEYWORD_ALLOW_SIGNAL, ccs_write_signal },
		{ CCS_KEYWORD_ALLOW_MOUNT, ccs_write_mount }
	};
	int (*write) (char *, struct ccs_domain_info *, struct ccs_condition *,
		      const bool) = ccs_write_file;
	int error;
	u8 i;
	struct ccs_condition *cond = NULL;
	char *cp = ccs_find_condition_part(data);
	if (cp) {
		cond = ccs_get_condition(cp);
		if (!cond)
			return -EINVAL;
	}
	for (i = 0; i < 5; i++) {
		if (!ccs_str_starts(&data, ccs_callback[i].keyword))
			continue;
		write = ccs_callback[i].write;
		break;
	}
	error = write(data, domain, cond, is_delete);
	if (cond)
		ccs_put_condition(cond);
	return error;
}

static const char *ccs_dif[CCS_MAX_DOMAIN_INFO_FLAGS] = {
	[CCS_DIF_QUOTA_WARNED] = CCS_KEYWORD_QUOTA_EXCEEDED "\n",
	[CCS_DIF_IGNORE_GLOBAL] = CCS_KEYWORD_IGNORE_GLOBAL "\n",
	[CCS_DIF_IGNORE_GLOBAL_ALLOW_READ]
	= CCS_KEYWORD_IGNORE_GLOBAL_ALLOW_READ "\n",
	[CCS_DIF_IGNORE_GLOBAL_ALLOW_ENV]
	= CCS_KEYWORD_IGNORE_GLOBAL_ALLOW_ENV "\n",
	[CCS_DIF_TRANSITION_FAILED] = CCS_KEYWORD_TRANSITION_FAILED "\n"
};
	
/**
 * ccs_write_domain - Write domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_domain(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct ccs_domain_info *domain = head->w.domain;
	bool is_delete = false;
	bool is_select = false;
	unsigned int profile;
	if (ccs_str_starts(&data, CCS_KEYWORD_DELETE))
		is_delete = true;
	else if (ccs_str_starts(&data, CCS_KEYWORD_SELECT))
		is_select = true;
	if (is_select && ccs_select_one(head, data))
		return 0;
	/* Don't allow updating policies by non manager programs. */
	if (!ccs_manager())
		return -EPERM;
	if (ccs_domain_def(data)) {
		domain = NULL;
		if (is_delete)
			ccs_delete_domain(data);
		else if (is_select)
			domain = ccs_find_domain(data);
		else
			domain = ccs_assign_domain(data, 0);
		head->w.domain = domain;
		return 0;
	}
	if (!domain)
		return -EINVAL;

	if (sscanf(data, CCS_KEYWORD_USE_PROFILE "%u", &profile) == 1
	    && profile < CCS_MAX_PROFILES) {
		if (!ccs_policy_loaded || ccs_profile_ptr[(u8) profile])
			domain->profile = (u8) profile;
		return 0;
	}
	for (profile = 0; profile < CCS_MAX_DOMAIN_INFO_FLAGS; profile++) {
		const char *cp = ccs_dif[profile];
		if (strncmp(data, cp, strlen(cp) - 1))
			continue;
		domain->flags[profile] = !is_delete;
		return 0;
	}
	return ccs_write_domain2(data, domain, is_delete);
}

/**
 * ccs_print_name_union - Print a ccs_name_union.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_name_union".
 */
static void ccs_print_name_union(struct ccs_io_buffer *head,
				 const struct ccs_name_union *ptr)
{
	const bool cond = head->r.print_cond_part;
	if (!cond)
		ccs_set_space(head);
	if (ptr->is_group) {
		ccs_set_string(head, "@");
		ccs_set_string(head, ptr->group->group_name->name);
	} else {
		if (cond)
			ccs_set_string(head, "\"");
		ccs_set_string(head, ptr->filename->name);
		if (cond)
			ccs_set_string(head, "\"");
	}
}

/**
 * ccs_print_number_union - Print a ccs_number_union.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_number_union".
 */
static void ccs_print_number_union(struct ccs_io_buffer *head,
				   const struct ccs_number_union *ptr)
{
	if (!head->r.print_cond_part)
		ccs_set_space(head);
	if (ptr->is_group) {
		ccs_set_string(head, "@");
		ccs_set_string(head, ptr->group->group_name->name);
	} else {
		int i;
		unsigned long min = ptr->values[0];
		const unsigned long max = ptr->values[1];
		u8 min_type = ptr->value_type[0];
		const u8 max_type = ptr->value_type[1];
		char buffer[128];
		buffer[0] = '\0';
		for (i = 0; i < 2; i++) {
			switch (min_type) {
			case CCS_VALUE_TYPE_HEXADECIMAL:
				ccs_addprintf(buffer, sizeof(buffer), "0x%lX",
					      min);
				break;
			case CCS_VALUE_TYPE_OCTAL:
				ccs_addprintf(buffer, sizeof(buffer), "0%lo",
					      min);
				break;
			default:
				ccs_addprintf(buffer, sizeof(buffer), "%lu",
					      min);
				break;
			}
			if (min == max && min_type == max_type)
				break;
			ccs_addprintf(buffer, sizeof(buffer), "-");
			min_type = max_type;
			min = max;
		}
		ccs_io_printf(head, "%s", buffer);
	}
}

/**
 * ccs_print_condition - Print condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @cond: Pointer to "struct ccs_condition".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_condition(struct ccs_io_buffer *head,
				const struct ccs_condition *cond)
{
	switch (head->r.cond_step) {
	case 0:
		{ 
			if (cond->condc)
				ccs_set_string(head, " if");
			head->r.cond_index = 0;
			head->r.cond_step++;
		}
		/* fall through */
	case 1:
		{
			const u16 condc = cond->condc;
			const struct ccs_condition_element *condp =
				(typeof(condp)) (cond + 1);
			const struct ccs_number_union *numbers_p =
				(typeof(numbers_p)) (condp + condc);
			const struct ccs_name_union *names_p =
				(typeof(names_p))
				(numbers_p + cond->numbers_count);
			const struct ccs_argv *argv =
				(typeof(argv)) (names_p + cond->names_count);
			const struct ccs_envp *envp =
				(typeof(envp)) (argv + cond->argc);
			u16 skip;
			for (skip = 0; skip < head->r.cond_index; skip++) {
				const u8 left = condp->left;
				const u8 right = condp->right;
				condp++;
				switch (left) {
				case CCS_ARGV_ENTRY:
					argv++;
					continue;
				case CCS_ENVP_ENTRY:
					envp++;
					continue;
				case CCS_NUMBER_UNION:
					numbers_p++;
					break;
				}
				switch (right) {
				case CCS_NAME_UNION:
					names_p++;
					break;
				case CCS_NUMBER_UNION:
					numbers_p++;
					break;
				}
			}
			while (head->r.cond_index < condc) {
				const u8 match = condp->equals;
				const u8 left = condp->left;
				const u8 right = condp->right;
				if (!ccs_flush(head))
					return false;
				condp++;
				head->r.cond_index++;
				ccs_set_space(head);
				switch (left) {
				case CCS_ARGV_ENTRY:
					ccs_io_printf(head,
						      "exec.argv[%u]%s\"%s\"",
						      argv->index,
						      argv->is_not ?
						      "!=" : "=",
						      argv->value->name);
					argv++;
					continue;
				case CCS_ENVP_ENTRY:
					ccs_io_printf(head,
						      "exec.envp[\"%s\"]%s",
						      envp->name->name,
						      envp->is_not ?
						      "!=" : "=");
					if (envp->value) {
						ccs_set_string(head, "\"");
						ccs_set_string(head, envp->
							       value->name);
						ccs_set_string(head, "\"");
					} else {
						ccs_set_string(head, "NULL");
					}
					envp++;
					continue;
				case CCS_NUMBER_UNION:
					ccs_print_number_union(head,
							       numbers_p++);
					break;
				default:
					ccs_set_string(head,
					       ccs_condition_keyword[left]);
					break;
				}
				ccs_set_string(head, match ? "=" : "!=");
				switch (right) {
				case CCS_NAME_UNION:
					ccs_print_name_union(head, names_p++);
					break;
				case CCS_NUMBER_UNION:
					ccs_print_number_union(head,
							       numbers_p++);
					break;
				default:
					ccs_set_string(head,
					       ccs_condition_keyword[right]);
					break;
				}
			}
		}
		head->r.cond_step++;
		/* fall through */
	case 2:
		if (!ccs_flush(head))
			break;
		head->r.cond_step++;
		/* fall through */
	case 3:
		{
			u8 j;
			const u8 i = cond->post_state[3];
			if (i)
				ccs_set_string(head, " ; set");
			for (j = 0; j < 3; j++)
				if ((i & (1 << j)))
					ccs_io_printf(head, 
						      " task.state[%u]=%u", j,
						      cond->post_state[j]);
			if (i & (1 << 4))
				ccs_io_printf(head, " audit=%s",
					      ccs_yesno(cond->post_state[4]));
		}
		ccs_set_lf(head);
		return true;
	}
	return false;
}

/**
 * ccs_fns - Find next set bit.
 *
 * @perm: 8 bits value.
 * @bit:  First bit to find.
 *
 * Returns next set bit on success, 8 otherwise.
 */
static u8 ccs_fns(const u8 perm, u8 bit)
{
	for ( ; bit < 8; bit++)
		if (perm & (1 << bit))
			break;
	return bit;
}

/**
 * ccs_print_entry - Print an ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @acl:  Pointer to an ACL entry.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_entry(struct ccs_io_buffer *head,
			    const struct ccs_acl_info *acl)
{
	const u8 acl_type = acl->type;
	u8 bit;
	if (head->r.print_cond_part)
		goto print_cond_part;
	if (acl->is_deleted)
		return true;
 next:
	bit = head->r.bit;
	if (!ccs_flush(head))
		return false;
	else if (acl_type == CCS_TYPE_PATH_ACL) {
		struct ccs_path_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		const u16 perm = ptr->perm;
		for ( ; bit < CCS_MAX_PATH_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (head->r.print_execute_only &&
			    bit != CCS_TYPE_EXECUTE && bit != CCS_TYPE_TRANSIT)
				continue;
			/* Print "read/write" instead of "read" and "write". */
			if ((bit == CCS_TYPE_READ || bit == CCS_TYPE_WRITE)
			    && (perm & (1 << CCS_TYPE_READ_WRITE)))
				continue;
			break;
		}
		if (bit >= CCS_MAX_PATH_OPERATION)
			goto done;
		ccs_io_printf(head, "allow_%s", ccs_path_keyword[bit]);
		ccs_print_name_union(head, &ptr->name);
	} else if (acl_type == CCS_TYPE_EXECUTE_HANDLER ||
		   acl_type == CCS_TYPE_DENIED_EXECUTE_HANDLER) {
		struct ccs_execute_handler *ptr
			= container_of(acl, typeof(*ptr), head);
		ccs_io_printf(head, "%s ",
			      acl_type == CCS_TYPE_EXECUTE_HANDLER ?
			      CCS_KEYWORD_EXECUTE_HANDLER :
			      CCS_KEYWORD_DENIED_EXECUTE_HANDLER);
		ccs_set_string(head, ptr->handler->name);
	} else if (head->r.print_execute_only) {
		return true;
	} else if (acl_type == CCS_TYPE_MKDEV_ACL) {
		struct ccs_mkdev_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		bit = ccs_fns(ptr->perm, bit);
		if (bit >= CCS_MAX_MKDEV_OPERATION)
			goto done;
		ccs_io_printf(head, "allow_%s", ccs_mkdev_keyword[bit]);
		ccs_print_name_union(head, &ptr->name);
		ccs_print_number_union(head, &ptr->mode);
		ccs_print_number_union(head, &ptr->major);
		ccs_print_number_union(head, &ptr->minor);
	} else if (acl_type == CCS_TYPE_PATH2_ACL) {
		struct ccs_path2_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		bit = ccs_fns(ptr->perm, bit);
		if (bit >= CCS_MAX_PATH2_OPERATION)
			goto done;
		ccs_io_printf(head, "allow_%s", ccs_path2_keyword[bit]);
		ccs_print_name_union(head, &ptr->name1);
		ccs_print_name_union(head, &ptr->name2);
	} else if (acl_type == CCS_TYPE_PATH_NUMBER_ACL) {
		struct ccs_path_number_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		bit = ccs_fns(ptr->perm, bit);
		if (bit >= CCS_MAX_PATH_NUMBER_OPERATION)
			goto done;
		ccs_io_printf(head, "allow_%s",
			      ccs_path_number_keyword[bit]);
		ccs_print_name_union(head, &ptr->name);
		ccs_print_number_union(head, &ptr->number);
	} else if (acl_type == CCS_TYPE_ENV_ACL) {
		struct ccs_env_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_string(head, CCS_KEYWORD_ALLOW_ENV);
		ccs_set_string(head, ptr->env->name);
	} else if (acl_type == CCS_TYPE_CAPABILITY_ACL) {
		struct ccs_capability_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_string(head, CCS_KEYWORD_ALLOW_CAPABILITY);
		ccs_set_string(head, ccs_cap2keyword(ptr->operation));
	} else if (acl_type == CCS_TYPE_IP_NETWORK_ACL) {
		struct ccs_ip_network_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		bit = ccs_fns(ptr->perm, bit);
		if (bit >= CCS_MAX_NETWORK_OPERATION)
			goto done;
		ccs_io_printf(head, CCS_KEYWORD_ALLOW_NETWORK "%s ",
			      ccs_net_keyword[bit]);
		switch (ptr->address_type) {
			char buf[128];
		case CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP:
			ccs_set_string(head, "@");
			ccs_set_string(head,
				       ptr->address.group->group_name->name);
			break;
		case CCS_IP_ADDRESS_TYPE_IPv4:
			ccs_print_ipv4(buf, sizeof(buf), ptr->address.ipv4.min,
				       ptr->address.ipv4.max);
			ccs_io_printf(head, "%s", buf);
			break;
		case CCS_IP_ADDRESS_TYPE_IPv6:
			ccs_print_ipv6(buf, sizeof(buf), ptr->address.ipv6.min,
				       ptr->address.ipv6.max);
			ccs_io_printf(head, "%s", buf);
			break;
		}
		ccs_print_number_union(head, &ptr->port);
	} else if (acl_type == CCS_TYPE_SIGNAL_ACL) {
		struct ccs_signal_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_io_printf(head, CCS_KEYWORD_ALLOW_SIGNAL "%u ", ptr->sig);
		ccs_set_string(head, ptr->domainname->name);
	} else if (acl_type == CCS_TYPE_MOUNT_ACL) {
		struct ccs_mount_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_io_printf(head, "allow_mount");
		ccs_print_name_union(head, &ptr->dev_name);
		ccs_print_name_union(head, &ptr->dir_name);
		ccs_print_name_union(head, &ptr->fs_type);
		ccs_print_number_union(head, &ptr->flags);
	}
	head->r.bit = bit + 1;
	if (acl->cond) {
		head->r.print_cond_part = true;
		head->r.cond_step = 0;
		if (!ccs_flush(head))
			return false;
 print_cond_part:
		if (!ccs_print_condition(head, acl->cond))
			return false;
		head->r.print_cond_part = false;
	} else {
		ccs_set_lf(head);
	}
	switch (acl_type) {
	case CCS_TYPE_PATH_ACL:
	case CCS_TYPE_MKDEV_ACL:
	case CCS_TYPE_PATH2_ACL:
	case CCS_TYPE_PATH_NUMBER_ACL:
	case CCS_TYPE_IP_NETWORK_ACL:
		goto next;
	}
 done:
	head->r.bit = 0;
	return true;
}

/**
 * ccs_read_domain2 - Read domain policy.
 *
 * @head:   Pointer to "struct ccs_io_buffer".
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Caller holds ccs_read_lock().
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_read_domain2(struct ccs_io_buffer *head,
			     struct ccs_domain_info *domain)
{
	list_for_each_cookie(head->r.acl, &domain->acl_info_list) {
		struct ccs_acl_info *ptr =
			list_entry(head->r.acl, typeof(*ptr), list);
		if (!ccs_print_entry(head, ptr))
			return false;
	}
	head->r.acl = NULL;
	return true;
}

/**
 * ccs_read_domain - Read domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_domain(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	list_for_each_cookie(head->r.domain, &ccs_domain_list) {
		struct ccs_domain_info *domain =
			list_entry(head->r.domain, typeof(*domain), list);
		switch (head->r.step) {
			u8 i;
		case 0:
			if (domain->is_deleted &&
			    !head->r.print_this_domain_only)
				continue;
			/* Print domainname and flags. */
			ccs_set_string(head, domain->domainname->name);
			ccs_set_lf(head);
			ccs_io_printf(head, CCS_KEYWORD_USE_PROFILE "%u\n",
				      domain->profile);
			for (i = 0; i < CCS_MAX_DOMAIN_INFO_FLAGS; i++)
				if (domain->flags[i])
					ccs_set_string(head, ccs_dif[i]);
			head->r.step++;
			ccs_set_lf(head);
			/* fall through */
		case 1:
			if (!ccs_read_domain2(head, domain))
				return;
			head->r.step++;
			if (!ccs_set_lf(head))
				return;
			/* fall through */
		case 2:
			head->r.step = 0;
			if (head->r.print_this_domain_only)
				goto done;
		}
	}
 done:
	head->r.eof = true;
}

/**
 * ccs_write_domain_profile - Assign profile for specified domain.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 *
 * This is equivalent to doing
 *
 *     ( echo "select " $domainname; echo "use_profile " $profile ) |
 *     /usr/sbin/ccs-loadpolicy -d
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_domain_profile(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	char *cp = strchr(data, ' ');
	struct ccs_domain_info *domain;
	unsigned int profile;
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	profile = simple_strtoul(data, NULL, 10);
	if (profile >= CCS_MAX_PROFILES)
		return -EINVAL;
	domain = ccs_find_domain(cp + 1);
	if (domain && (!ccs_policy_loaded || ccs_profile_ptr[(u8) profile]))
		domain->profile = (u8) profile;
	return 0;
}

/**
 * ccs_read_domain_profile - Read only domainname and profile.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * This is equivalent to doing
 *
 *     grep -A 1 '^<kernel>' /proc/ccs/domain_policy |
 *     awk ' { if ( domainname == "" ) { if ( $1 == "<kernel>" )
 *     domainname = $0; } else if ( $1 == "use_profile" ) {
 *     print $2 " " domainname; domainname = ""; } } ; '
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_domain_profile(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	list_for_each_cookie(head->r.domain, &ccs_domain_list) {
		struct ccs_domain_info *domain =
			list_entry(head->r.domain, typeof(*domain), list);
		if (domain->is_deleted)
			continue;
		if (!ccs_flush(head))
			return;
		ccs_io_printf(head, "%u ", domain->profile);
		ccs_set_string(head, domain->domainname->name);
		ccs_set_lf(head);
	}
	head->r.eof = true;
}

/**
 * ccs_write_pid: Specify PID to obtain domainname.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_write_pid(struct ccs_io_buffer *head)
{
	head->r.eof = false;
	return 0;
}

/**
 * ccs_read_pid - Read information of a process.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns the domainname which the specified PID is in or
 * process information of the specified PID on success,
 * empty string otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_pid(struct ccs_io_buffer *head)
{
	char *buf = head->write_buf;
	bool task_info = false;
	bool global_pid = false;
	unsigned int pid;
	struct task_struct *p;
	struct ccs_domain_info *domain = NULL;
	u32 ccs_flags = 0;
	/* Accessing write_buf is safe because head->io_sem is held. */
	if (!buf) {
		head->r.eof = true;
		return; /* Do nothing if open(O_RDONLY). */
	}
	if (head->r.w_pos || head->r.eof)
		return;
	head->r.eof = true;
	if (ccs_str_starts(&buf, "info "))
		task_info = true;
	if (ccs_str_starts(&buf, "global-pid "))
		global_pid = true;
	pid = (unsigned int) simple_strtoul(buf, NULL, 10);
	ccs_tasklist_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (global_pid)
		p = ccsecurity_exports.find_task_by_pid_ns(pid, &init_pid_ns);
	else
		p = ccsecurity_exports.find_task_by_vpid(pid);
#else
	p = find_task_by_pid(pid);
#endif
	if (p) {
		domain = ccs_task_domain(p);
		ccs_flags = p->ccs_flags;
	}
	ccs_tasklist_unlock();
	if (!domain)
		return;
	if (!task_info) {
		ccs_io_printf(head, "%u %u ", pid, domain->profile);
		ccs_set_string(head, domain->domainname->name);
	} else {
		ccs_io_printf(head, "%u manager=%s execute_handler=%s "
			      "state[0]=%u state[1]=%u state[2]=%u", pid,
			      ccs_yesno(ccs_flags &
					CCS_TASK_IS_MANAGER),
			      ccs_yesno(ccs_flags &
					CCS_TASK_IS_EXECUTE_HANDLER),
			      (u8) (ccs_flags >> 24),
			      (u8) (ccs_flags >> 16),
			      (u8) (ccs_flags >> 8));
	}
}

static const char *ccs_transition_type[CCS_MAX_TRANSITION_TYPE] = {
	[CCS_TRANSITION_CONTROL_NO_INITIALIZE]
	= CCS_KEYWORD_NO_INITIALIZE_DOMAIN,
	[CCS_TRANSITION_CONTROL_INITIALIZE] = CCS_KEYWORD_INITIALIZE_DOMAIN,
	[CCS_TRANSITION_CONTROL_NO_KEEP] = CCS_KEYWORD_NO_KEEP_DOMAIN,
	[CCS_TRANSITION_CONTROL_KEEP] = CCS_KEYWORD_KEEP_DOMAIN
};

static const char *ccs_group_name[CCS_MAX_GROUP] = {
	[CCS_PATH_GROUP] = CCS_KEYWORD_PATH_GROUP,
	[CCS_NUMBER_GROUP] = CCS_KEYWORD_NUMBER_GROUP,
	[CCS_ADDRESS_GROUP] = CCS_KEYWORD_ADDRESS_GROUP
};

/**
 * ccs_write_exception - Write exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_exception(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	const bool is_delete = ccs_str_starts(&data, CCS_KEYWORD_DELETE);
	u8 i;
	static const struct {
		const char *keyword;
		int (*write) (char *, const bool);
	} ccs_callback[4] = {
		{ CCS_KEYWORD_AGGREGATOR, ccs_write_aggregator },
		{ CCS_KEYWORD_FILE_PATTERN, ccs_write_pattern },
		{ CCS_KEYWORD_DENY_REWRITE, ccs_write_no_rewrite },
		{ CCS_KEYWORD_DENY_AUTOBIND, ccs_write_reserved_port }
	};
	for (i = 0; i < 4; i++)
		if (ccs_str_starts(&data, ccs_callback[i].keyword))
			return ccs_callback[i].write(data, is_delete);
	for (i = 0; i < CCS_MAX_TRANSITION_TYPE; i++)
		if (ccs_str_starts(&data, ccs_transition_type[i]))
			return ccs_write_transition_control(data, is_delete,
							    i);
	for (i = 0; i < CCS_MAX_GROUP; i++)
		if (ccs_str_starts(&data, ccs_group_name[i]))
			return ccs_write_group(data, is_delete, i);
	return ccs_write_domain2(data, &ccs_global_domain, is_delete);
}

/**
 * ccs_read_group - Read "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @idx:  Index number.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_group(struct ccs_io_buffer *head, const int idx)
{
	list_for_each_cookie(head->r.group, &ccs_group_list[idx]) {
		struct ccs_group *group =
			list_entry(head->r.group, typeof(*group), head.list);
		list_for_each_cookie(head->r.acl, &group->member_list) {
			struct ccs_acl_head *ptr =
				list_entry(head->r.acl, typeof(*ptr), list);
			if (ptr->is_deleted)
				continue;
			if (!ccs_flush(head))
				return false;
			ccs_set_string(head, ccs_group_name[idx]);
			ccs_set_string(head, group->group_name->name);
			if (idx == CCS_PATH_GROUP) {
				ccs_set_space(head);
				ccs_set_string(head, container_of
					       (ptr, struct ccs_path_group,
						head)->member_name->name);
			} else if (idx == CCS_NUMBER_GROUP) {
				ccs_print_number_union(head, &container_of
						       (ptr, struct ccs_number_group,
							head)->number);
			} else if (idx == CCS_ADDRESS_GROUP) {
				char buffer[128];
				struct ccs_address_group *member =
					container_of(ptr, typeof(*member),
						     head);
				if (member->is_ipv6)
					ccs_print_ipv6(buffer, sizeof(buffer),
						       member->min.ipv6,
						       member->max.ipv6);
				else
					ccs_print_ipv4(buffer, sizeof(buffer),
						       member->min.ipv4,
						       member->max.ipv4);
				ccs_io_printf(head, " %s", buffer);
			}
			ccs_set_lf(head);
		}
		head->r.acl = NULL;
	}
	head->r.group = NULL;
	return true;
}

/**
 * ccs_read_policy - Read "struct ccs_..._entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @idx:  Index number.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_policy(struct ccs_io_buffer *head, const int idx)
{
	list_for_each_cookie(head->r.acl, &ccs_policy_list[idx]) {
		struct ccs_acl_head *acl =
			container_of(head->r.acl, typeof(*acl), list);
		if (acl->is_deleted)
			continue;
		if (!ccs_flush(head))
			return false;
		switch (idx) {
		case CCS_ID_TRANSITION_CONTROL:
			{
				struct ccs_transition_control *ptr =
					container_of(acl, typeof(*ptr), head);
				ccs_set_string(head,
					       ccs_transition_type[ptr->type]);
				ccs_set_string(head, ptr->program ?
					       ptr->program->name : "any");
				ccs_set_string(head, " from ");
				ccs_set_string(head, ptr->domainname ?
					       ptr->domainname->name : "any");
			}
			break;
		case CCS_ID_AGGREGATOR:
			{
				struct ccs_aggregator *ptr =
					container_of(acl, typeof(*ptr), head);
				ccs_set_string(head, CCS_KEYWORD_AGGREGATOR);
				ccs_set_string(head, ptr->original_name->name);
				ccs_set_space(head);
				ccs_set_string(head,
					       ptr->aggregated_name->name);
			}
			break;
		case CCS_ID_PATTERN:
			{
				struct ccs_pattern *ptr =
					container_of(acl, typeof(*ptr), head);
				ccs_set_string(head, CCS_KEYWORD_FILE_PATTERN);
				ccs_set_string(head, ptr->pattern->name);
			}
			break;
		case CCS_ID_NO_REWRITE:
			{
				struct ccs_no_rewrite *ptr =
					container_of(acl, typeof(*ptr), head);
				ccs_set_string(head, CCS_KEYWORD_DENY_REWRITE);
				ccs_set_string(head, ptr->pattern->name);
			}
			break;
		case CCS_ID_RESERVEDPORT:
			{
				struct ccs_reserved *ptr =
					container_of(acl, typeof(*ptr), head);
				const u16 min_port = ptr->min_port;
				const u16 max_port = ptr->max_port;
				ccs_set_string(head,
					       CCS_KEYWORD_DENY_AUTOBIND);
				ccs_io_printf(head, "%u", min_port);
				if (min_port != max_port)
					ccs_io_printf(head, "-%u", max_port);
			}
			break;
		default:
			continue;
		}
		ccs_set_lf(head);
	}
	head->r.acl = NULL;
	return true;
}

/**
 * ccs_read_exception - Read exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_exception(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	while (head->r.step < CCS_MAX_POLICY &&
	       ccs_read_policy(head, head->r.step))
		head->r.step++;
	if (head->r.step < CCS_MAX_POLICY)
		return;
	while (head->r.step < CCS_MAX_POLICY + CCS_MAX_GROUP &&
	       ccs_read_group(head, head->r.step - CCS_MAX_POLICY))
		head->r.step++;
	if (head->r.step < CCS_MAX_POLICY + CCS_MAX_GROUP)
		return;
	head->r.eof = ccs_read_domain2(head, &ccs_global_domain);
}

/* Wait queue for ccs_query_list. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_query_wait);

/* Lock for manipulating ccs_query_list. */
static DEFINE_SPINLOCK(ccs_query_list_lock);

/* Structure for query. */
struct ccs_query {
	struct list_head list;
	char *query;
	int query_len;
	unsigned int serial;
	int timer;
	int answer;
};

/* The list for "struct ccs_query". */
static LIST_HEAD(ccs_query_list);

/* Number of "struct file" referring /proc/ccs/query interface. */
static atomic_t ccs_query_observers = ATOMIC_INIT(0);

static void ccs_truncate(char *str)
{
	while (* (unsigned char *) str > (unsigned char) ' ')
		str++;
	*str = '\0';
}

/**
 * ccs_supervisor - Ask for the supervisor's decision.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @fmt: The printf()'s format string, followed by parameters.
 *
 * Returns 0 if the supervisor decided to permit the access request which
 * violated the policy in enforcing mode, CCS_RETRY_REQUEST if the supervisor
 * decided to retry the access request which violated the policy in enforcing
 * mode, 0 if it is not in enforcing mode, -EPERM otherwise.
 */
int ccs_supervisor(struct ccs_request_info *r, const char *fmt, ...)
{
	va_list args;
	int error = -EPERM;
	int pos;
	int len;
	static unsigned int ccs_serial;
	struct ccs_query *entry = NULL;
	bool quota_exceeded = false;
	char *header;
	struct ccs_domain_info * const domain = ccs_current_domain();
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 80;
	va_end(args);
	if (r->mode == CCS_CONFIG_LEARNING) {
		char *buffer;
		char *realpath = NULL;
		char *argv0 = NULL;
		char *symlink = NULL;
		char *handler = NULL;
		const struct ccs_preference *pref;
		if (!ccs_domain_quota_ok(r))
			return 0;
		header = ccs_init_log(&len, r);
		if (!header)
			return 0;
		pref = ccs_profile(r->profile)->learning;
		/* strstr() will return NULL if ordering is wrong. */
		if (r->param_type == CCS_TYPE_PATH_ACL &&
		    r->param.path.operation == CCS_TYPE_EXECUTE) {
			if (pref->learning_exec_argv0) {
				argv0 = strstr(header, " argv[]={ \"");
				if (argv0) {
					argv0 += 10;
					ccs_truncate(argv0);
				}
			}
			if (pref->learning_exec_realpath) {
				realpath = strstr(header,
						  " exec={ realpath=\"");
				if (realpath) {
					realpath += 8;
					ccs_truncate(realpath);
				}
			}
		} else if (r->param_type == CCS_TYPE_PATH_ACL &&
			   r->param.path.operation == CCS_TYPE_SYMLINK &&
			   pref->learning_symlink_target) {
			symlink = strstr(header, " symlink.target=\"");
			if (symlink)
				ccs_truncate(symlink + 1);
		}
		handler = strstr(header, "type=execute_handler");
		if (handler)
			ccs_truncate(handler);
		buffer = kmalloc(len, CCS_GFP_FLAGS);
		if (buffer) {
			va_start(args, fmt);
			vsnprintf(buffer, len - 1, fmt, args);
			va_end(args);
			if (handler || realpath || argv0 || symlink) {
				ccs_addprintf(buffer, len, " if");
				if (handler)
					ccs_addprintf(buffer, len, " task.%s",
						      handler);
				if (realpath)
					ccs_addprintf(buffer, len, " exec.%s",
						      realpath);
				if (argv0)
					ccs_addprintf(buffer, len,
						      " exec.argv[0]=%s",
						      argv0);
				if (symlink)
					ccs_addprintf(buffer, len, "%s",
						      symlink);
			}
			ccs_normalize_line(buffer);
			ccs_write_domain2(buffer, domain, false);
			kfree(buffer);
		}
		kfree(header);
		return 0;
	}
	if (r->mode != CCS_CONFIG_ENFORCING)
		return 0;
	if (!atomic_read(&ccs_query_observers)) {
		int i;
		if (current->ccs_flags & CCS_DONT_SLEEP_ON_ENFORCE_ERROR)
			return -EPERM;
		for (i = 0; i < ccs_profile(domain->profile)->enforcing->
			     enforcing_penalty; i++) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
		}
		return -EPERM;
	}
	header = ccs_init_log(&len, r);
	if (!header)
		goto out;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (!entry)
		goto out;
	len = ccs_round2(len);
	entry->query = kzalloc(len, CCS_GFP_FLAGS);
	if (!entry->query)
		goto out;
	spin_lock(&ccs_query_list_lock);
	if (ccs_quota_for_query && ccs_query_memory_size + len +
	    sizeof(*entry) >= ccs_quota_for_query) {
		quota_exceeded = true;
	} else {
		ccs_query_memory_size += len + sizeof(*entry);
		entry->serial = ccs_serial++;
	}
	spin_unlock(&ccs_query_list_lock);
	if (quota_exceeded)
		goto out;
	pos = snprintf(entry->query, len - 1, "Q%u-%hu\n%s",
		       entry->serial, r->retry, header);
	kfree(header);
	header = NULL;
	va_start(args, fmt);
	vsnprintf(entry->query + pos, len - 1 - pos, fmt, args);
	entry->query_len = strlen(entry->query) + 1;
	va_end(args);
	spin_lock(&ccs_query_list_lock);
	list_add_tail(&entry->list, &ccs_query_list);
	spin_unlock(&ccs_query_list_lock);
	/* Give 10 seconds for supervisor's opinion. */
	for (entry->timer = 0;
	     atomic_read(&ccs_query_observers) && entry->timer < 100;
	     entry->timer++) {
		wake_up(&ccs_query_wait);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ / 10);
		if (entry->answer)
			break;
	}
	spin_lock(&ccs_query_list_lock);
	list_del(&entry->list);
	ccs_query_memory_size -= len + sizeof(*entry);
	spin_unlock(&ccs_query_list_lock);
	switch (entry->answer) {
	case 3: /* Asked to retry by administrator. */
		error = CCS_RETRY_REQUEST;
		r->retry++;
		break;
	case 1:
		/* Granted by administrator. */
		error = 0;
		break;
	case 0:
		/* Timed out. */
		break;
	default:
		/* Rejected by administrator. */
		break;
	}
 out:
	if (entry)
		kfree(entry->query);
	kfree(entry);
	kfree(header);
	return error;
}

/**
 * ccs_poll_query - poll() for /proc/ccs/query.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read, 0 otherwise.
 *
 * Waits for access requests which violated policy in enforcing mode.
 */
static int ccs_poll_query(struct file *file, poll_table *wait)
{
	struct list_head *tmp;
	bool found = false;
	u8 i;
	for (i = 0; i < 2; i++) {
		spin_lock(&ccs_query_list_lock);
		list_for_each(tmp, &ccs_query_list) {
			struct ccs_query *ptr =
				list_entry(tmp, typeof(*ptr), list);
			if (ptr->answer)
				continue;
			found = true;
			break;
		}
		spin_unlock(&ccs_query_list_lock);
		if (found)
			return POLLIN | POLLRDNORM;
		if (i)
			break;
		poll_wait(file, &ccs_query_wait, wait);
	}
	return 0;
}

/**
 * ccs_read_query - Read access requests which violated policy in enforcing mode.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 */
static void ccs_read_query(struct ccs_io_buffer *head)
{
	struct list_head *tmp;
	int pos = 0;
	int len = 0;
	char *buf;
	if (head->r.w_pos)
		return;
	if (head->read_buf) {
		kfree(head->read_buf);
		head->read_buf = NULL;
	}
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->answer)
			continue;
		if (pos++ != head->r.query_index)
			continue;
		len = ptr->query_len;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	if (!len) {
		head->r.query_index = 0;
		return;
	}
	buf = kzalloc(len, CCS_GFP_FLAGS);
	if (!buf)
		return;
	pos = 0;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->answer)
			continue;
		if (pos++ != head->r.query_index)
			continue;
		/*
		 * Some query can be skipped because ccs_query_list
		 * can change, but I don't care.
		 */
		if (len == ptr->query_len)
			memmove(buf, ptr->query, len);
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	if (buf[0]) {
		head->read_buf = buf;
		head->r.w[head->r.w_pos++] = buf;
		head->r.query_index++;
	} else {
		kfree(buf);
	}
}

/**
 * ccs_write_answer - Write the supervisor's decision.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_write_answer(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct list_head *tmp;
	unsigned int serial;
	unsigned int answer;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		ptr->timer = 0;
	}
	spin_unlock(&ccs_query_list_lock);
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2)
		return -EINVAL;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->serial != serial)
			continue;
		if (!ptr->answer)
			ptr->answer = answer;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	return 0;
}

/**
 * ccs_read_version: Get version.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 */
static void ccs_read_version(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	ccs_set_string(head, "1.7.2");
	head->r.eof = true;
}

/**
 * ccs_read_self_domain - Get the current process's domainname.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 */
static void ccs_read_self_domain(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	/*
	 * ccs_current_domain()->domainname != NULL because every process
	 * belongs to a domain and the domain's name cannot be NULL.
	 */
	ccs_io_printf(head, "%s", ccs_current_domain()->domainname->name);
	head->r.eof = true;
}

/**
 * ccs_open_control - open() for /proc/ccs/ interface.
 *
 * @type: Type of interface.
 * @file: Pointer to "struct file".
 *
 * Associates policy handler and returns 0 on success, -ENOMEM otherwise.
 */
int ccs_open_control(const u8 type, struct file *file)
{
	struct ccs_io_buffer *head = kzalloc(sizeof(*head), CCS_GFP_FLAGS);
	if (!head)
		return -ENOMEM;
	mutex_init(&head->io_sem);
	head->type = type;
	switch (type) {
	case CCS_DOMAINPOLICY: /* /proc/ccs/domain_policy */
		head->write = ccs_write_domain;
		head->read = ccs_read_domain;
		break;
	case CCS_EXCEPTIONPOLICY: /* /proc/ccs/exception_policy */
		head->write = ccs_write_exception;
		head->read = ccs_read_exception;
		break;
#ifdef CONFIG_CCSECURITY_AUDIT
	case CCS_GRANTLOG: /* /proc/ccs/grant_log */
	case CCS_REJECTLOG: /* /proc/ccs/reject_log */
		head->poll = ccs_poll_log;
		head->read = ccs_read_log;
		break;
#endif
	case CCS_SELFDOMAIN: /* /proc/ccs/self_domain */
		head->read = ccs_read_self_domain;
		break;
	case CCS_DOMAIN_STATUS: /* /proc/ccs/.domain_status */
		head->write = ccs_write_domain_profile;
		head->read = ccs_read_domain_profile;
		break;
	case CCS_EXECUTE_HANDLER: /* /proc/ccs/.execute_handler */
		/* Allow execute_handler to read process's status. */
		if (!(current->ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER)) {
			kfree(head);
			return -EPERM;
		}
		/* fall through */
	case CCS_PROCESS_STATUS: /* /proc/ccs/.process_status */
		head->write = ccs_write_pid;
		head->read = ccs_read_pid;
		break;
	case CCS_VERSION: /* /proc/ccs/version */
		head->read = ccs_read_version;
		head->readbuf_size = 128;
		break;
	case CCS_MEMINFO: /* /proc/ccs/meminfo */
		head->write = ccs_write_memory_quota;
		head->read = ccs_read_memory_counter;
		head->readbuf_size = 512;
		break;
	case CCS_PROFILE: /* /proc/ccs/profile */
		head->write = ccs_write_profile;
		head->read = ccs_read_profile;
		break;
	case CCS_QUERY: /* /proc/ccs/query */
		head->poll = ccs_poll_query;
		head->write = ccs_write_answer;
		head->read = ccs_read_query;
		break;
	case CCS_MANAGER: /* /proc/ccs/manager */
		head->write = ccs_write_manager;
		head->read = ccs_read_manager;
		break;
	}
	if (!(file->f_mode & FMODE_READ)) {
		/*
		 * No need to allocate read_buf since it is not opened
		 * for reading.
		 */
		head->read = NULL;
		head->poll = NULL;
	} else if (!head->poll) {
		/* Don't allocate read_buf for poll() access. */
		if (!head->readbuf_size)
			head->readbuf_size = 4096;
		head->read_buf = kzalloc(head->readbuf_size, CCS_GFP_FLAGS);
		if (!head->read_buf) {
			kfree(head);
			return -ENOMEM;
		}
	}
	if (!(file->f_mode & FMODE_WRITE)) {
		/*
		 * No need to allocate write_buf since it is not opened
		 * for writing.
		 */
		head->write = NULL;
	} else if (head->write) {
		head->writebuf_size = 4096;
		head->write_buf = kzalloc(head->writebuf_size, CCS_GFP_FLAGS);
		if (!head->write_buf) {
			kfree(head->read_buf);
			kfree(head);
			return -ENOMEM;
		}
	}
	if (type != CCS_QUERY &&
	    type != CCS_GRANTLOG && type != CCS_REJECTLOG)
		head->reader_idx = ccs_lock();
	file->private_data = head;
	/*
	 * Call the handler now if the file is /proc/ccs/self_domain
	 * so that the user can use "cat < /proc/ccs/self_domain" to
	 * know the current process's domainname.
	 */
	if (type == CCS_SELFDOMAIN)
		ccs_read_control(file, NULL, 0);
	/*
	 * If the file is /proc/ccs/query , increment the observer counter.
	 * The obserber counter is used by ccs_supervisor() to see if
	 * there is some process monitoring /proc/ccs/query.
	 */
	else if (type == CCS_QUERY)
		atomic_inc(&ccs_query_observers);
	return 0;
}

/**
 * ccs_poll_control - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Waits for read readiness.
 * /proc/ccs/query is handled by /usr/sbin/ccs-queryd and
 * /proc/ccs/grant_log and /proc/ccs/reject_log are handled by
 * /usr/sbin/ccs-auditd .
 */
int ccs_poll_control(struct file *file, poll_table *wait)
{
	struct ccs_io_buffer *head = file->private_data;
	if (!head->poll)
		return -ENOSYS;
	return head->poll(file, wait);
}

/**
 * ccs_read_control - read() for /proc/ccs/ interface.
 *
 * @file:       Pointer to "struct file".
 * @buffer:     Poiner to buffer to write to.
 * @buffer_len: Size of @buffer.
 *
 * Returns bytes read on success, negative value otherwise.
 */
int ccs_read_control(struct file *file, char __user *buffer,
		     const int buffer_len)
{
	int len;
	struct ccs_io_buffer *head = file->private_data;
	int idx;
	if (!head->read)
		return -ENOSYS;
	if (!access_ok(VERIFY_WRITE, buffer, buffer_len))
		return -EFAULT;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	head->read_user_buf = buffer;
	head->read_user_buf_avail = buffer_len;
	idx = ccs_read_lock();
	if (ccs_flush(head))
		/* Call the policy handler. */
		head->read(head);
	ccs_flush(head);
	ccs_read_unlock(idx);
	len = head->read_user_buf - buffer;
	mutex_unlock(&head->io_sem);
	return len;
}

/**
 * ccs_write_control - write() for /proc/ccs/ interface.
 *
 * @file:       Pointer to "struct file".
 * @buffer:     Pointer to buffer to read from.
 * @buffer_len: Size of @buffer.
 *
 * Returns @buffer_len on success, negative value otherwise.
 */
int ccs_write_control(struct file *file, const char __user *buffer,
		      const int buffer_len)
{
	struct ccs_io_buffer *head = file->private_data;
	int error = buffer_len;
	int avail_len = buffer_len;
	char *cp0 = head->write_buf;
	int idx;
	if (!head->write)
		return -ENOSYS;
	if (!access_ok(VERIFY_READ, buffer, buffer_len))
		return -EFAULT;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	idx = ccs_read_lock();
	/* Don't allow updating policies by non manager programs. */
	if (head->write != ccs_write_pid && head->write != ccs_write_domain &&
	    !ccs_manager()) {
		ccs_read_unlock(idx);
		mutex_unlock(&head->io_sem);
		return -EPERM;
	}
	/* Read a line and dispatch it to the policy handler. */
	while (avail_len > 0) {
		char c;
		if (head->w.avail >= head->writebuf_size - 1) {
			const int len = head->writebuf_size * 2;
			char *cp = kzalloc(len, CCS_GFP_FLAGS);
			if (!cp) {
				error = -ENOMEM;
				break;
			}
			memmove(cp, cp0, head->w.avail);
			kfree(cp0);
			head->write_buf = cp;
			cp0 = cp;
			head->writebuf_size = len;
		}
		if (get_user(c, buffer)) {
			error = -EFAULT;
			break;
		}
		buffer++;
		avail_len--;
		cp0[head->w.avail++] = c;
		if (c != '\n')
			continue;
		cp0[head->w.avail - 1] = '\0';
		head->w.avail = 0;
		ccs_normalize_line(cp0);
		head->write(head);
	}
	ccs_read_unlock(idx);
	mutex_unlock(&head->io_sem);
	return error;
}

/**
 * ccs_close_control - close() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 *
 * Releases memory and returns 0.
 */
int ccs_close_control(struct file *file)
{
	struct ccs_io_buffer *head = file->private_data;
	const bool is_write = head->write_buf != NULL;
	const u8 type = head->type;
	/*
	 * If the file is /proc/ccs/query , decrement the observer counter.
	 */
	if (type == CCS_QUERY)
		atomic_dec(&ccs_query_observers);
	if (type != CCS_QUERY &&
	    type != CCS_GRANTLOG && type != CCS_REJECTLOG)
		ccs_unlock(head->reader_idx);
	/* Release memory used for policy I/O. */
	kfree(head->read_buf);
	head->read_buf = NULL;
	kfree(head->write_buf);
	head->write_buf = NULL;
	kfree(head);
	head = NULL;
	file->private_data = NULL;
	if (is_write)
		ccs_run_gc();
	return 0;
}

void __init ccs_policy_io_init(void)
{
	ccsecurity_ops.check_profile = ccs_check_profile;
}
