/*
 * security/ccsecurity/policy_io.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

/* Lock for protecting ccs_profile->comment  */
static DEFINE_SPINLOCK(ccs_profile_comment_lock);

static bool ccs_profile_entry_used[CCS_MAX_CONTROL_INDEX +
				   CCS_MAX_CAPABILITY_INDEX + 1];

/* String table for functionality that takes 4 modes. */
static const char *ccs_mode_4[4] = {
	"disabled", "learning", "permissive", "enforcing"
};
/* String table for functionality that takes 2 modes. */
static const char *ccs_mode_2[4] = {
	"disabled", "enabled", "enabled", "enabled"
};

/* Table for profile. */
static struct {
	const char *keyword;
	unsigned int current_value;
	const unsigned int max_value;
} ccs_control_array[CCS_MAX_CONTROL_INDEX] = {
	[CCS_MAC_FOR_FILE]        = { "MAC_FOR_FILE",        0, 3 },
	[CCS_MAC_FOR_IOCTL]       = { "MAC_FOR_IOCTL",       0, 3 },
	[CCS_MAC_FOR_ARGV0]       = { "MAC_FOR_ARGV0",       0, 3 },
	[CCS_MAC_FOR_ENV]         = { "MAC_FOR_ENV",         0, 3 },
	[CCS_MAC_FOR_NETWORK]     = { "MAC_FOR_NETWORK",     0, 3 },
	[CCS_MAC_FOR_SIGNAL]      = { "MAC_FOR_SIGNAL",      0, 3 },
	[CCS_MAC_FOR_NAMESPACE]   = { "MAC_FOR_NAMESPACE",   0, 3 },
	[CCS_RESTRICT_AUTOBIND]   = { "RESTRICT_AUTOBIND",   0, 1 },
	[CCS_MAX_ACCEPT_ENTRY]
	= { "MAX_ACCEPT_ENTRY", CONFIG_CCSECURITY_MAX_ACCEPT_ENTRY, INT_MAX },
#ifdef CONFIG_CCSECURITY_AUDIT
	[CCS_MAX_GRANT_LOG]
	= { "MAX_GRANT_LOG", CONFIG_CCSECURITY_MAX_GRANT_LOG, INT_MAX },
	[CCS_MAX_REJECT_LOG]
	= { "MAX_REJECT_LOG", CONFIG_CCSECURITY_MAX_REJECT_LOG, INT_MAX },
#endif
	[CCS_VERBOSE]             = { "TOMOYO_VERBOSE",      1, 1 },
	[CCS_SLEEP_PERIOD]
	= { "SLEEP_PERIOD",        0, 3000 }, /* in 0.1 second */
};

/* Permit policy management by non-root user? */
static bool ccs_manage_by_non_root;

/**
 * ccs_quiet_setup - Set CCS_VERBOSE=0 by default.
 *
 * @str: Unused.
 *
 * Returns 0.
 */
static int __init ccs_quiet_setup(char *str)
{
	ccs_control_array[CCS_VERBOSE].current_value = 0;
	return 0;
}

__setup("CCS_QUIET", ccs_quiet_setup);

/**
 * ccs_io_printf - Transactional printf() to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @fmt:  The printf()'s format string, followed by parameters.
 *
 * Returns true on success, false otherwise.
 *
 * The snprintf() will truncate, but ccs_io_printf() won't.
 */
bool ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
{
	va_list args;
	int len;
	int pos = head->read_avail;
	int size = head->readbuf_size - pos;
	if (size <= 0)
		return false;
	va_start(args, fmt);
	len = vsnprintf(head->read_buf + pos, size, fmt, args);
	va_end(args);
	if (pos + len >= head->readbuf_size)
		return false;
	head->read_avail += len;
	return true;
}

/**
 * ccs_find_or_assign_new_profile - Create a new profile.
 *
 * @profile: Profile number to create.
 *
 * Returns pointer to "struct ccs_profile" on success, NULL otherwise.
 */
struct ccs_profile *ccs_find_or_assign_new_profile(const unsigned int
						   profile)
{
	struct ccs_profile *ptr;
	struct ccs_profile *entry;
	int i;
	if (profile >= MAX_PROFILES)
		return NULL;
	ptr = ccs_profile_ptr[profile];
	if (ptr)
		return ptr;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	ptr = ccs_profile_ptr[profile];
	if (!ptr && ccs_memory_ok(entry, sizeof(*entry))) {
		ptr = entry;
		for (i = 0; i < CCS_MAX_CONTROL_INDEX; i++)
			ptr->value[i] = ccs_control_array[i].current_value;
		/*
		 * Needn't to initialize "ptr->capability_value"
		 * because they are always 0.
		 */
		mb(); /* Avoid out-of-order execution. */
		ccs_profile_ptr[profile] = ptr;
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	kfree(entry);
	return ptr;
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
	unsigned int value;
	char *cp;
	struct ccs_profile *ccs_profile;
	i = simple_strtoul(data, &cp, 10);
	if (data != cp) {
		if (*cp != '-')
			return -EINVAL;
		data = cp + 1;
	}
	ccs_profile = ccs_find_or_assign_new_profile(i);
	if (!ccs_profile)
		return -EINVAL;
	cp = strchr(data, '=');
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	if (!strcmp(data, "COMMENT")) {
		const struct ccs_path_info *new_comment
			= ccs_get_name(cp + 1);
		const struct ccs_path_info *old_comment;
		/* Protect reader from ccs_put_name(). */
		/***** CRITICAL SECTION START *****/
		spin_lock(&ccs_profile_comment_lock);
		old_comment = ccs_profile->comment;
		ccs_profile->comment = new_comment;
		spin_unlock(&ccs_profile_comment_lock);
		/***** CRITICAL SECTION END *****/
		ccs_put_name(old_comment);
		ccs_profile_entry_used[0] = true;
		return 0;
	}
	if (ccs_str_starts(&data, KEYWORD_MAC_FOR_CAPABILITY)) {
		if (sscanf(cp + 1, "%u", &value) != 1) {
			for (i = 0; i < 4; i++) {
				if (strcmp(cp + 1, ccs_mode_4[i]))
					continue;
				value = i;
				break;
			}
			if (i == 4)
				return -EINVAL;
		}
		if (value > 3)
			value = 3;
		for (i = 0; i < CCS_MAX_CAPABILITY_INDEX; i++) {
			if (strcmp(data, ccs_capability_control_keyword[i]))
				continue;
			ccs_profile->capability_value[i] = value;
			ccs_profile_entry_used[i + 1 + CCS_MAX_CONTROL_INDEX]
				= true;
			return 0;
		}
		return -EINVAL;
	}
	for (i = 0; i < CCS_MAX_CONTROL_INDEX; i++) {
		if (strcmp(data, ccs_control_array[i].keyword))
			continue;
		if (sscanf(cp + 1, "%u", &value) != 1) {
			int j;
			const char **modes;
			switch (i) {
			case CCS_RESTRICT_AUTOBIND:
			case CCS_VERBOSE:
				modes = ccs_mode_2;
				break;
			default:
				modes = ccs_mode_4;
				break;
			}
			for (j = 0; j < 4; j++) {
				if (strcmp(cp + 1, modes[j]))
					continue;
				value = j;
				break;
			}
			if (j == 4)
				return -EINVAL;
		} else if (value > ccs_control_array[i].max_value) {
			value = ccs_control_array[i].max_value;
		}
		ccs_profile->value[i] = value;
		ccs_profile_entry_used[i + 1] = true;
		return 0;
	}
	return -EINVAL;
}

/**
 * ccs_read_profile - Read profile table.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_read_profile(struct ccs_io_buffer *head)
{
	static const int ccs_total
		= CCS_MAX_CONTROL_INDEX + CCS_MAX_CAPABILITY_INDEX + 1;
	int step;
	if (head->read_eof)
		return 0;
	for (step = head->read_step; step < MAX_PROFILES * ccs_total; step++) {
		const u8 index = step / ccs_total;
		u8 type = step % ccs_total;
		const struct ccs_profile *ccs_profile = ccs_profile_ptr[index];
		head->read_step = step;
		if (!ccs_profile)
			continue;
		if (!ccs_profile_entry_used[type])
			continue;
		if (!type) { /* Print profile' comment tag. */
			bool done;
			/***** CRITICAL SECTION START *****/
			spin_lock(&ccs_profile_comment_lock);
			done = ccs_io_printf(head, "%u-COMMENT=%s\n",
					     index, ccs_profile->comment ?
					     ccs_profile->comment->name : "");
			spin_unlock(&ccs_profile_comment_lock);
			/***** CRITICAL SECTION END *****/
			if (!done)
				break;
			continue;
		}
		type--;
		if (type >= CCS_MAX_CONTROL_INDEX) {
			const int i = type - CCS_MAX_CONTROL_INDEX;
			const u8 value = ccs_profile->capability_value[i];
			if (!ccs_io_printf(head,
					   "%u-" KEYWORD_MAC_FOR_CAPABILITY
					   "%s=%s\n", index,
					   ccs_capability_control_keyword[i],
					   ccs_mode_4[value]))
				break;
		} else {
			const unsigned int value = ccs_profile->value[type];
			const char **modes = NULL;
			const char *keyword = ccs_control_array[type].keyword;
			switch (ccs_control_array[type].max_value) {
			case 3:
				modes = ccs_mode_4;
				break;
			case 1:
				modes = ccs_mode_2;
				break;
			}
			if (modes) {
				if (!ccs_io_printf(head, "%u-%s=%s\n", index,
						   keyword, modes[value]))
					break;
			} else {
				if (!ccs_io_printf(head, "%u-%s=%u\n", index,
						   keyword, value))
					break;
			}
		}
	}
	if (step == MAX_PROFILES * ccs_total)
		head->read_eof = true;
	return 0;
}

/* The list for "struct ccs_policy_manager_entry". */
LIST_HEAD(ccs_policy_manager_list);

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
	struct ccs_policy_manager_entry *entry = NULL;
	struct ccs_policy_manager_entry *ptr;
	const struct ccs_path_info *saved_manager;
	int error = is_delete ? -ENOENT : -ENOMEM;
	bool is_domain = false;
	if (ccs_is_domain_def(manager)) {
		if (!ccs_is_correct_domain(manager))
			return -EINVAL;
		is_domain = true;
	} else {
		if (!ccs_is_correct_path(manager, 1, -1, -1))
			return -EINVAL;
	}
	saved_manager = ccs_get_name(manager);
	if (!saved_manager)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_policy_manager_list, list) {
		if (ptr->manager != saved_manager)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->manager = saved_manager;
		saved_manager = NULL;
		entry->is_domain = is_domain;
		list_add_tail_rcu(&entry->list, &ccs_policy_manager_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_manager);
	kfree(entry);
	return error;
}

/**
 * ccs_write_manager_policy - Write manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_manager_policy(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	bool is_delete = ccs_str_starts(&data, KEYWORD_DELETE);
	if (!strcmp(data, "manage_by_non_root")) {
		ccs_manage_by_non_root = !is_delete;
		return 0;
	}
	return ccs_update_manager_entry(data, is_delete);
}

/**
 * ccs_read_manager_policy - Read manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_read_manager_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	ccs_check_read_lock();
	if (head->read_eof)
		return 0;
	list_for_each_cookie(pos, head->read_var2, &ccs_policy_manager_list) {
		struct ccs_policy_manager_entry *ptr;
		ptr = list_entry(pos, struct ccs_policy_manager_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, "%s\n", ptr->manager->name))
			return 0;
	}
	head->read_eof = true;
	return 0;
}

/**
 * ccs_is_policy_manager - Check whether the current process is a policy manager.
 *
 * Returns true if the current process is permitted to modify policy
 * via /proc/ccs/ interface.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_policy_manager(void)
{
	struct ccs_policy_manager_entry *ptr;
	const char *exe;
	struct task_struct *task = current;
	const struct ccs_path_info *domainname
		= ccs_current_domain()->domainname;
	bool found = false;
	ccs_check_read_lock();
	if (!ccs_policy_loaded)
		return true;
	if (task->ccs_flags & CCS_TASK_IS_POLICY_MANAGER)
		return true;
	if (!ccs_manage_by_non_root && (current_uid() || current_euid()))
		return false;
	list_for_each_entry_rcu(ptr, &ccs_policy_manager_list, list) {
		if (!ptr->is_deleted && ptr->is_domain
		    && !ccs_pathcmp(domainname, ptr->manager)) {
			/* Set manager flag. */
			task->ccs_flags |= CCS_TASK_IS_POLICY_MANAGER;
			return true;
		}
	}
	exe = ccs_get_exe();
	if (!exe)
		return false;
	list_for_each_entry_rcu(ptr, &ccs_policy_manager_list, list) {
		if (!ptr->is_deleted && !ptr->is_domain
		    && !strcmp(exe, ptr->manager->name)) {
			found = true;
			/* Set manager flag. */
			task->ccs_flags |= CCS_TASK_IS_POLICY_MANAGER;
			break;
		}
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
	if (cp) {
		while (1) {
			char *cp2 = strstr(cp + 3, " if ");
			if (!cp2)
				break;
			cp = cp2;
		}
		*cp++ = '\0';
	} else {
		cp = strstr(data, " ; set ");
		if (cp)
			*cp++ = '\0';
	}
	return cp;
}

/**
 * ccs_is_select_one - Parse select command.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_select_one(struct ccs_io_buffer *head, const char *data)
{
	unsigned int pid;
	struct ccs_domain_info *domain = NULL;
	ccs_check_read_lock();
	if (!strcmp(data, "allow_execute")) {
		head->read_execute_only = true;
		return true;
	}
	if (sscanf(data, "pid=%u", &pid) == 1) {
		struct task_struct *p;
		/***** CRITICAL SECTION START *****/
		read_lock(&tasklist_lock);
		p = find_task_by_pid(pid);
		if (p)
			domain = ccs_task_domain(p);
		read_unlock(&tasklist_lock);
		/***** CRITICAL SECTION END *****/
	} else if (!strncmp(data, "domain=", 7)) {
		if (ccs_is_domain_def(data + 7))
			domain = ccs_find_domain(data + 7);
	} else
		return false;
	head->write_var1 = domain;
	/* Accessing read_buf is safe because head->io_sem is held. */
	if (!head->read_buf)
		return true; /* Do nothing if open(O_WRONLY). */
	head->read_avail = 0;
	ccs_io_printf(head, "# select %s\n", data);
	head->read_single_domain = true;
	head->read_eof = !domain;
	if (domain) {
		struct ccs_domain_info *d;
		head->read_var1 = NULL;
		list_for_each_entry_rcu(d, &ccs_domain_list, list) {
			if (d == domain)
				break;
			head->read_var1 = &d->list;
		}
		head->read_var2 = NULL;
		head->read_bit = 0;
		head->read_step = 0;
		if (domain->is_deleted)
			ccs_io_printf(head, "# This is a deleted domain.\n");
	}
	return true;
}

/**
 * ccs_write_domain_policy - Write domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_domain_policy(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct ccs_domain_info *domain = head->write_var1;
	bool is_delete = false;
	bool is_select = false;
	unsigned int profile;
	struct ccs_condition *cond = NULL;
	char *cp;
	int error;
	if (ccs_str_starts(&data, KEYWORD_DELETE))
		is_delete = true;
	else if (ccs_str_starts(&data, KEYWORD_SELECT))
		is_select = true;
	if (is_select && ccs_is_select_one(head, data))
		return 0;
	/* Don't allow updating policies by non manager programs. */
	if (!ccs_is_policy_manager())
		return -EPERM;
	if (ccs_is_domain_def(data)) {
		domain = NULL;
		if (is_delete)
			ccs_delete_domain(data);
		else if (is_select)
			domain = ccs_find_domain(data);
		else
			domain = ccs_find_or_assign_new_domain(data, 0);
		head->write_var1 = domain;
		return 0;
	}
	if (!domain)
		return -EINVAL;

	if (sscanf(data, KEYWORD_USE_PROFILE "%u", &profile) == 1
	    && profile < MAX_PROFILES) {
		if (ccs_profile_ptr[profile] || !ccs_policy_loaded)
			domain->profile = (u8) profile;
		return 0;
	}
	if (!strcmp(data, KEYWORD_IGNORE_GLOBAL_ALLOW_READ)) {
		domain->ignore_global_allow_read = !is_delete;
		return 0;
	}
	if (!strcmp(data, KEYWORD_IGNORE_GLOBAL_ALLOW_ENV)) {
		domain->ignore_global_allow_env = !is_delete;
		return 0;
	}
	cp = ccs_find_condition_part(data);
	if (cp) {
		cond = ccs_get_condition(cp);
		if (!cond)
			return -EINVAL;
	}
	if (ccs_str_starts(&data, KEYWORD_ALLOW_CAPABILITY))
		error = ccs_write_capability_policy(data, domain, cond,
						    is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_NETWORK))
		error = ccs_write_network_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_SIGNAL))
		error = ccs_write_signal_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_ARGV0))
		error = ccs_write_argv0_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_ENV))
		error = ccs_write_env_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_IOCTL))
		error = ccs_write_ioctl_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_MOUNT))
		error = ccs_write_mount_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_UNMOUNT))
		error = ccs_write_umount_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_CHROOT))
		error = ccs_write_chroot_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_PIVOT_ROOT))
		error = ccs_write_pivot_root_policy(data, domain, cond,
						    is_delete);
	else
		error = ccs_write_file_policy(data, domain, cond, is_delete);
	if (cond)
		ccs_put_condition(cond);
	return error;
}

static bool ccs_print_name_union(struct ccs_io_buffer *head, bool is_group,
				 union ccs_name_union *group)
{
	const int pos = head->read_avail;
	if (pos && head->read_buf[pos - 1] == ' ')
		head->read_avail--;
	if (is_group)
		return ccs_io_printf(head, " @%s", group->group->group_name->name);
	return ccs_io_printf(head, " %s", group->filename->name);
}

static bool ccs_print_number_union(struct ccs_io_buffer *head, bool is_group,
				   union ccs_number_union *group)
{
	unsigned int min;
	unsigned int max;
	if (is_group)
		return ccs_io_printf(head, " @%s", group->group->group_name->name);
	min = group->value.min;
	max = group->value.max;
	if (min == max)
		return ccs_io_printf(head, " %u", min);
	return ccs_io_printf(head, " %u-%u", min, max);
}

/**
 * ccs_print_single_path_acl - Print a single path ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_single_path_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_single_path_acl(struct ccs_io_buffer *head,
				      struct ccs_single_path_acl_record *ptr,
				      const struct ccs_condition *cond)
{
	int pos;
	u8 bit;
	const u16 perm = ptr->perm;
	for (bit = head->read_bit; bit < MAX_SINGLE_PATH_OPERATION; bit++) {
		const char *msg;
		if (!(perm & (1 << bit)))
			continue;
		if (head->read_execute_only && bit != TYPE_EXECUTE_ACL)
			continue;
		/* Print "read/write" instead of "read" and "write". */
		if ((bit == TYPE_READ_ACL || bit == TYPE_WRITE_ACL)
		    && (perm & (1 << TYPE_READ_WRITE_ACL)))
			continue;
		msg = ccs_sp2keyword(bit);
		pos = head->read_avail;
		if (!ccs_io_printf(head, "allow_%s", msg) ||
		    !ccs_print_name_union(head, ptr->name_is_group,
					  &ptr->name) ||
		    !ccs_print_condition(head, cond))
			goto out;
	}
	head->read_bit = 0;
	return true;
 out:
	head->read_bit = bit;
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_mkdev_acl - Print a mkdev ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_mkdev_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_mkdev_acl(struct ccs_io_buffer *head,
				struct ccs_mkdev_acl_record *ptr,
				const struct ccs_condition *cond)
{
	int pos;
	u8 bit;
	const u16 perm = ptr->perm;
	for (bit = head->read_bit; bit < MAX_MKDEV_OPERATION; bit++) {
		const char *msg;
		if (!(perm & (1 << bit)))
			continue;
		msg = ccs_mkdev2keyword(bit);
		pos = head->read_avail;
		if (!ccs_io_printf(head, "allow_%s", msg) ||
		    !ccs_print_name_union(head, ptr->name_is_group,
					  &ptr->name) ||
		    !ccs_print_number_union(head, ptr->major_is_group,
					    &ptr->major) ||
		    !ccs_print_number_union(head, ptr->minor_is_group,
					    &ptr->minor) ||
		    !ccs_print_condition(head, cond))
			goto out;
	}
	head->read_bit = 0;
	return true;
 out:
	head->read_bit = bit;
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_double_path_acl - Print a double path ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_double_path_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_double_path_acl(struct ccs_io_buffer *head,
				      struct ccs_double_path_acl_record *ptr,
				      const struct ccs_condition *cond)
{
	int pos;
	u8 bit;
	const u8 perm = ptr->perm;
	for (bit = head->read_bit; bit < MAX_DOUBLE_PATH_OPERATION; bit++) {
		const char *msg;
		if (!(perm & (1 << bit)))
			continue;
		msg = ccs_dp2keyword(bit);
		pos = head->read_avail;
		if (!ccs_io_printf(head, "allow_%s", msg) ||
		    !ccs_print_name_union(head, ptr->name1_is_group,
					  &ptr->name1) ||
		    !ccs_print_name_union(head, ptr->name2_is_group,
					  &ptr->name2) ||
		    !ccs_print_condition(head, cond))
			goto out;
	}
	head->read_bit = 0;
	return true;
 out:
	head->read_bit = bit;
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_ioctl_acl - Print an ioctl ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ioctl_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_ioctl_acl(struct ccs_io_buffer *head,
				struct ccs_ioctl_acl_record *ptr,
				const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_IOCTL) ||
	    !ccs_print_name_union(head, ptr->name_is_group, &ptr->name) ||
	    !ccs_print_number_union(head, ptr->cmd_is_group, &ptr->cmd) ||
	    !ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_argv0_acl - Print an argv[0] ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_argv0_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_argv0_acl(struct ccs_io_buffer *head,
				struct ccs_argv0_acl_record *ptr,
				const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_ARGV0 "%s %s",
			   ptr->filename->name, ptr->argv0->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_env_acl - Print an evironment variable name's ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_env_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_env_acl(struct ccs_io_buffer *head,
			      struct ccs_env_acl_record *ptr,
			      const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_ENV "%s", ptr->env->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_capability_acl - Print a capability ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_capability_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_capability_acl(struct ccs_io_buffer *head,
				     struct ccs_capability_acl_record *ptr,
				     const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_CAPABILITY "%s",
			   ccs_cap2keyword(ptr->operation)))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_ipv4_entry - Print IPv4 address of a network ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ip_network_acl_record".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_ipv4_entry(struct ccs_io_buffer *head,
				 struct ccs_ip_network_acl_record *ptr)
{
	const u32 min_address = ptr->address.ipv4.min;
	const u32 max_address = ptr->address.ipv4.max;
	if (!ccs_io_printf(head, "%u.%u.%u.%u", HIPQUAD(min_address)))
		return false;
	if (min_address != max_address
	    && !ccs_io_printf(head, "-%u.%u.%u.%u", HIPQUAD(max_address)))
		return false;
	return true;
}

/**
 * ccs_print_ipv6_entry - Print IPv6 address of a network ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ip_network_acl_record".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_ipv6_entry(struct ccs_io_buffer *head,
				 struct ccs_ip_network_acl_record *ptr)
{
	char buf[64];
	const struct in6_addr *min_address = ptr->address.ipv6.min;
	const struct in6_addr *max_address = ptr->address.ipv6.max;
	ccs_print_ipv6(buf, sizeof(buf), min_address);
	if (!ccs_io_printf(head, "%s", buf))
		return false;
	if (min_address != max_address) {
		ccs_print_ipv6(buf, sizeof(buf), max_address);
		if (!ccs_io_printf(head, "-%s", buf))
			return false;
	}
	return true;
}

/**
 * ccs_print_network_acl - Print a network ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ip_network_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_network_acl(struct ccs_io_buffer *head,
				  struct ccs_ip_network_acl_record *ptr,
				  const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_NETWORK "%s ",
			   ccs_net2keyword(ptr->operation_type)))
		goto out;
	switch (ptr->record_type) {
	case IP_RECORD_TYPE_ADDRESS_GROUP:
		if (!ccs_io_printf(head, "@%s",
				   ptr->address.group->group_name->name))
			goto out;
		break;
	case IP_RECORD_TYPE_IPv4:
		if (!ccs_print_ipv4_entry(head, ptr))
			goto out;
		break;
	case IP_RECORD_TYPE_IPv6:
		if (!ccs_print_ipv6_entry(head, ptr))
			goto out;
		break;
	}
	if (!ccs_print_number_union(head, ptr->port_is_group, &ptr->port) ||
	    !ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_signal_acl - Print a signal ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct signale_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_signal_acl(struct ccs_io_buffer *head,
				 struct ccs_signal_acl_record *ptr,
				 const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_SIGNAL "%u %s",
			   ptr->sig, ptr->domainname->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_execute_handler_record - Print an execute handler ACL entry.
 *
 * @head:    Pointer to "struct ccs_io_buffer".
 * @keyword: Name of the keyword.
 * @ptr:     Pointer to "struct ccs_execute_handler_record".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_execute_handler_record(struct ccs_io_buffer *head,
					     const char *keyword,
					     struct ccs_execute_handler_record *
					     ptr)
{
	return ccs_io_printf(head, "%s %s\n", keyword, ptr->handler->name);
}

/**
 * ccs_print_mount_acl - Print a mount ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_mount_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_mount_acl(struct ccs_io_buffer *head,
				struct ccs_mount_acl_record *ptr,
				const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_MOUNT "%s %s %s 0x%lX\n",
			   ptr->dev_name->name, ptr->dir_name->name,
			   ptr->fs_type->name, ptr->flags))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_umount_acl - Print a mount ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_umount_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_umount_acl(struct ccs_io_buffer *head,
				 struct ccs_umount_acl_record *ptr,
				 const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_UNMOUNT "%s\n",
			   ptr->dir->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_chroot_acl - Print a chroot ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_chroot_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_chroot_acl(struct ccs_io_buffer *head,
				 struct ccs_chroot_acl_record *ptr,
				 const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_CHROOT "%s\n",
			   ptr->dir->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_pivot_root_acl - Print a pivot_root ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_pivot_root_acl_record".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_pivot_root_acl(struct ccs_io_buffer *head,
				     struct ccs_pivot_root_acl_record *ptr,
				     const struct ccs_condition *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_PIVOT_ROOT "%s %s\n",
			   ptr->new_root->name, ptr->old_root->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_entry - Print an ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to an ACL entry.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_entry(struct ccs_io_buffer *head,
			    struct ccs_acl_info *ptr)
{
	const struct ccs_condition *cond = ptr->cond;
	const u8 acl_type = ccs_acl_type2(ptr);
	if (acl_type & ACL_DELETED)
		return true;
	if (acl_type == TYPE_SINGLE_PATH_ACL) {
		struct ccs_single_path_acl_record *acl
			= container_of(ptr, struct ccs_single_path_acl_record,
				       head);
		return ccs_print_single_path_acl(head, acl, cond);
	}
	if (acl_type == TYPE_EXECUTE_HANDLER) {
		struct ccs_execute_handler_record *acl
			= container_of(ptr, struct ccs_execute_handler_record,
				       head);
		const char *keyword = KEYWORD_EXECUTE_HANDLER;
		return ccs_print_execute_handler_record(head, keyword, acl);
	}
	if (acl_type == TYPE_DENIED_EXECUTE_HANDLER) {
		struct ccs_execute_handler_record *acl
			= container_of(ptr, struct ccs_execute_handler_record,
				       head);
		const char *keyword = KEYWORD_DENIED_EXECUTE_HANDLER;
		return ccs_print_execute_handler_record(head, keyword, acl);
	}
	if (head->read_execute_only)
		return true;
	if (acl_type == TYPE_MKDEV_ACL) {
		struct ccs_mkdev_acl_record *acl
			= container_of(ptr, struct ccs_mkdev_acl_record, head);
		return ccs_print_mkdev_acl(head, acl, cond);
	}
	if (acl_type == TYPE_DOUBLE_PATH_ACL) {
		struct ccs_double_path_acl_record *acl
			= container_of(ptr, struct ccs_double_path_acl_record,
				       head);
		return ccs_print_double_path_acl(head, acl, cond);
	}
	if (acl_type == TYPE_IOCTL_ACL) {
		struct ccs_ioctl_acl_record *acl
			= container_of(ptr, struct ccs_ioctl_acl_record, head);
		return ccs_print_ioctl_acl(head, acl, cond);
	}
	if (acl_type == TYPE_ARGV0_ACL) {
		struct ccs_argv0_acl_record *acl
			= container_of(ptr, struct ccs_argv0_acl_record, head);
		return ccs_print_argv0_acl(head, acl, cond);
	}
	if (acl_type == TYPE_ENV_ACL) {
		struct ccs_env_acl_record *acl
			= container_of(ptr, struct ccs_env_acl_record, head);
		return ccs_print_env_acl(head, acl, cond);
	}
	if (acl_type == TYPE_CAPABILITY_ACL) {
		struct ccs_capability_acl_record *acl
			= container_of(ptr, struct ccs_capability_acl_record,
				       head);
		return ccs_print_capability_acl(head, acl, cond);
	}
	if (acl_type == TYPE_IP_NETWORK_ACL) {
		struct ccs_ip_network_acl_record *acl
			= container_of(ptr, struct ccs_ip_network_acl_record,
				       head);
		return ccs_print_network_acl(head, acl, cond);
	}
	if (acl_type == TYPE_SIGNAL_ACL) {
		struct ccs_signal_acl_record *acl
			= container_of(ptr, struct ccs_signal_acl_record, head);
		return ccs_print_signal_acl(head, acl, cond);
	}
	if (acl_type == TYPE_MOUNT_ACL) {
		struct ccs_mount_acl_record *acl
			= container_of(ptr, struct ccs_mount_acl_record, head);
		return ccs_print_mount_acl(head, acl, cond);
	}
	if (acl_type == TYPE_UMOUNT_ACL) {
		struct ccs_umount_acl_record *acl
			= container_of(ptr, struct ccs_umount_acl_record, head);
		return ccs_print_umount_acl(head, acl, cond);
	}
	if (acl_type == TYPE_CHROOT_ACL) {
		struct ccs_chroot_acl_record *acl
			= container_of(ptr, struct ccs_chroot_acl_record, head);
		return ccs_print_chroot_acl(head, acl, cond);
	}
	if (acl_type == TYPE_PIVOT_ROOT_ACL) {
		struct ccs_pivot_root_acl_record *acl
			= container_of(ptr, struct ccs_pivot_root_acl_record,
				       head);
		return ccs_print_pivot_root_acl(head, acl, cond);
	}
	/* Workaround for gcc 3.2.2's inline bug. */
	if (acl_type & ACL_DELETED)
		return true;
	BUG(); /* This must not happen. */
	return false;
}

/**
 * ccs_read_domain_policy - Read domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_read_domain_policy(struct ccs_io_buffer *head)
{
	struct list_head *dpos;
	struct list_head *apos;
	ccs_check_read_lock();
	if (head->read_eof)
		return 0;
	if (head->read_step == 0)
		head->read_step = 1;
	list_for_each_cookie(dpos, head->read_var1, &ccs_domain_list) {
		struct ccs_domain_info *domain;
		const char *quota_exceeded = "";
		const char *transition_failed = "";
		const char *ignore_global_allow_read = "";
		const char *ignore_global_allow_env = "";
		domain = list_entry(dpos, struct ccs_domain_info, list);
		if (head->read_step != 1)
			goto acl_loop;
		if (domain->is_deleted && !head->read_single_domain)
			continue;
		/* Print domainname and flags. */
		if (domain->quota_warned)
			quota_exceeded = "quota_exceeded\n";
		if (domain->domain_transition_failed)
			transition_failed = "transition_failed\n";
		if (domain->ignore_global_allow_read)
			ignore_global_allow_read
				= KEYWORD_IGNORE_GLOBAL_ALLOW_READ "\n";
		if (domain->ignore_global_allow_env)
			ignore_global_allow_env
				= KEYWORD_IGNORE_GLOBAL_ALLOW_ENV "\n";
		if (!ccs_io_printf(head, "%s\n" KEYWORD_USE_PROFILE "%u\n"
				   "%s%s%s%s\n", domain->domainname->name,
				   domain->profile, quota_exceeded,
				   transition_failed,
				   ignore_global_allow_read,
				   ignore_global_allow_env))
			return 0;
		head->read_step = 2;
 acl_loop:
		if (head->read_step == 3)
			goto tail_mark;
		/* Print ACL entries in the domain. */
		list_for_each_cookie(apos, head->read_var2,
				     &domain->acl_info_list) {
			struct ccs_acl_info *ptr
				= list_entry(apos, struct ccs_acl_info, list);
			if (!ccs_print_entry(head, ptr))
				return 0;
		}
		head->read_step = 3;
 tail_mark:
		if (!ccs_io_printf(head, "\n"))
			return 0;
		head->read_step = 1;
		if (head->read_single_domain)
			break;
	}
	head->read_eof = true;
	return 0;
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
 *     /usr/lib/ccs/loadpolicy -d
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_domain_profile(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	char *cp = strchr(data, ' ');
	struct ccs_domain_info *domain;
	unsigned int profile;
	ccs_check_read_lock();
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	profile = simple_strtoul(data, NULL, 10);
	if (profile >= MAX_PROFILES)
		return -EINVAL;
	domain = ccs_find_domain(cp + 1);
	if (domain && (ccs_profile_ptr[profile] || !ccs_policy_loaded))
		domain->profile = (u8) profile;
	return 0;
}

/**
 * ccs_read_domain_profile - Read only domainname and profile.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns list of profile number and domainname pairs.
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
static int ccs_read_domain_profile(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	ccs_check_read_lock();
	if (head->read_eof)
		return 0;
	list_for_each_cookie(pos, head->read_var1, &ccs_domain_list) {
		struct ccs_domain_info *domain;
		domain = list_entry(pos, struct ccs_domain_info, list);
		if (domain->is_deleted)
			continue;
		if (!ccs_io_printf(head, "%u %s\n", domain->profile,
				   domain->domainname->name))
			return 0;
	}
	head->read_eof = true;
	return 0;
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
	head->read_eof = false;
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
static int ccs_read_pid(struct ccs_io_buffer *head)
{
	char *buf = head->write_buf;
	bool task_info = false;
	unsigned int pid;
	struct task_struct *p;
	struct ccs_domain_info *domain = NULL;
	u32 ccs_flags = 0;
	ccs_check_read_lock();
	/* Accessing write_buf is safe because head->io_sem is held. */
	if (!buf)
		goto done; /* Do nothing if open(O_RDONLY). */
	if (head->read_avail || head->read_eof)
		goto done;
	head->read_eof = true;
	if (ccs_str_starts(&buf, "info "))
		task_info = true;
	pid = (unsigned int) simple_strtoul(buf, NULL, 10);
	/***** CRITICAL SECTION START *****/
	read_lock(&tasklist_lock);
	p = find_task_by_pid(pid);
	if (p) {
		domain = ccs_task_domain(p);
		ccs_flags = p->ccs_flags;
	}
	read_unlock(&tasklist_lock);
	/***** CRITICAL SECTION END *****/
	if (!domain)
		goto done;
	if (!task_info)
		ccs_io_printf(head, "%u %u %s", pid, domain->profile,
			      domain->domainname->name);
	else
		ccs_io_printf(head, "%u manager=%s execute_handler=%s "
			      "state[0]=%u state[1]=%u state[2]=%u", pid,
			      ccs_flags & CCS_TASK_IS_POLICY_MANAGER ?
			      "yes" : "no",
			      ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER ?
			      "yes" : "no",
			      (u8) (ccs_flags >> 24),
			      (u8) (ccs_flags >> 16),
			      (u8) (ccs_flags >> 8));
 done:
	return 0;
}

/**
 * ccs_write_exception_policy - Write exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_exception_policy(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	bool is_delete = ccs_str_starts(&data, KEYWORD_DELETE);
	if (ccs_str_starts(&data, KEYWORD_KEEP_DOMAIN))
		return ccs_write_domain_keeper_policy(data, false, is_delete);
	if (ccs_str_starts(&data, KEYWORD_NO_KEEP_DOMAIN))
		return ccs_write_domain_keeper_policy(data, true, is_delete);
	if (ccs_str_starts(&data, KEYWORD_INITIALIZE_DOMAIN))
		return ccs_write_domain_initializer_policy(data, false,
							   is_delete);
	if (ccs_str_starts(&data, KEYWORD_NO_INITIALIZE_DOMAIN))
		return ccs_write_domain_initializer_policy(data, true,
							   is_delete);
	if (ccs_str_starts(&data, KEYWORD_AGGREGATOR))
		return ccs_write_aggregator_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ALLOW_READ))
		return ccs_write_globally_readable_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ALLOW_ENV))
		return ccs_write_globally_usable_env_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_FILE_PATTERN))
		return ccs_write_pattern_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_PATH_GROUP))
		return ccs_write_path_group_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_NUMBER_GROUP))
		return ccs_write_number_group_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_DENY_REWRITE))
		return ccs_write_no_rewrite_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ADDRESS_GROUP))
		return ccs_write_address_group_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_DENY_AUTOBIND))
		return ccs_write_reserved_port_policy(data, is_delete);
	return -EINVAL;
}

/**
 * ccs_read_exception_policy - Read exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_read_exception_policy(struct ccs_io_buffer *head)
{
	ccs_check_read_lock();
	if (!head->read_eof) {
		switch (head->read_step) {
		case 0:
			head->read_var2 = NULL;
			head->read_step = 1;
		case 1:
			if (!ccs_read_domain_keeper_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 2;
		case 2:
			if (!ccs_read_globally_readable_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 3;
		case 3:
			if (!ccs_read_globally_usable_env_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 4;
		case 4:
			if (!ccs_read_domain_initializer_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 6;
		case 6:
			if (!ccs_read_aggregator_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 7;
		case 7:
			if (!ccs_read_file_pattern(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 8;
		case 8:
			if (!ccs_read_no_rewrite_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 9;
		case 9:
			if (!ccs_read_path_group_policy(head))
				break;
			head->read_var1 = NULL;
			head->read_var2 = NULL;
			head->read_step = 10;
		case 10:
			if (!ccs_read_number_group_policy(head))
				break;
			head->read_var1 = NULL;
			head->read_var2 = NULL;
			head->read_step = 11;
		case 11:
			if (!ccs_read_address_group_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 12;
		case 12:
			if (!ccs_read_reserved_port_policy(head))
				break;
			head->read_eof = true;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

/* Wait queue for ccs_query_list. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_query_wait);

/* Lock for manipulating ccs_query_list. */
static DEFINE_SPINLOCK(ccs_query_list_lock);

/* Structure for query. */
struct ccs_query_entry {
	struct list_head list;
	char *query;
	int query_len;
	unsigned int serial;
	int timer;
	int answer;
};

/* The list for "struct ccs_query_entry". */
static LIST_HEAD(ccs_query_list);

/* Number of "struct file" referring /proc/ccs/query interface. */
static atomic_t ccs_query_observers = ATOMIC_INIT(0);

/**
 * ccs_check_supervisor - Ask for the supervisor's decision.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @fmt:     The printf()'s format string, followed by parameters.
 *
 * Returns 0 if the supervisor decided to permit the access request which
 * violated the policy in enforcing mode, 1 if the supervisor decided to
 * retry the access request which violated the policy in enforcing mode,
 * -EPERM otherwise.
 */
int ccs_check_supervisor(struct ccs_request_info *r, const char *fmt, ...)
{
	va_list args;
	int error = -EPERM;
	int pos;
	int len;
	static unsigned int ccs_serial;
	struct ccs_query_entry *ccs_query_entry = NULL;
	bool quota_exceeded = false;
	char *header;
	if (!r->domain)
		r->domain = ccs_current_domain();
	if (!atomic_read(&ccs_query_observers)) {
		int i;
		if (current->ccs_flags & CCS_DONT_SLEEP_ON_ENFORCE_ERROR)
			return -EPERM;
		for (i = 0; i < ccs_check_flags(r->domain, CCS_SLEEP_PERIOD);
		     i++) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
		}
		return -EPERM;
	}
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 32;
	va_end(args);
	header = ccs_init_audit_log(&len, r);
	if (!header)
		goto out;
	ccs_query_entry = kzalloc(sizeof(*ccs_query_entry), GFP_KERNEL);
	if (!ccs_query_entry)
		goto out;
	ccs_query_entry->query = kzalloc(len, GFP_KERNEL);
	if (!ccs_query_entry->query)
		goto out;
	INIT_LIST_HEAD(&ccs_query_entry->list);
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	if (ccs_quota_for_query && ccs_query_memory_size + len +
	    sizeof(*ccs_query_entry) >= ccs_quota_for_query) {
		quota_exceeded = true;
	} else {
		ccs_query_memory_size += len + sizeof(*ccs_query_entry);
		ccs_query_entry->serial = ccs_serial++;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	if (quota_exceeded)
		goto out;
	pos = snprintf(ccs_query_entry->query, len - 1, "Q%u-%hu\n%s",
		       ccs_query_entry->serial, r->retry, header);
	kfree(header);
	header = NULL;
	va_start(args, fmt);
	vsnprintf(ccs_query_entry->query + pos, len - 1 - pos, fmt, args);
	ccs_query_entry->query_len = strlen(ccs_query_entry->query) + 1;
	va_end(args);
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_add_tail(&ccs_query_entry->list, &ccs_query_list);
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	/* Give 10 seconds for supervisor's opinion. */
	for (ccs_query_entry->timer = 0;
	     atomic_read(&ccs_query_observers) && ccs_query_entry->timer < 100;
	     ccs_query_entry->timer++) {
		wake_up(&ccs_query_wait);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ / 10);
		if (ccs_query_entry->answer)
			break;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_del(&ccs_query_entry->list);
	ccs_query_memory_size -= len + sizeof(*ccs_query_entry);
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	switch (ccs_query_entry->answer) {
	case 3: /* Asked to retry by administrator. */
		error = 1;
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
	if (ccs_query_entry)
		kfree(ccs_query_entry->query);
	kfree(ccs_query_entry);
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
		/***** CRITICAL SECTION START *****/
		spin_lock(&ccs_query_list_lock);
		list_for_each(tmp, &ccs_query_list) {
			struct ccs_query_entry *ptr
				= list_entry(tmp, struct ccs_query_entry, list);
			if (ptr->answer)
				continue;
			found = true;
			break;
		}
		spin_unlock(&ccs_query_list_lock);
		/***** CRITICAL SECTION END *****/
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
 *
 * Returns 0.
 */
static int ccs_read_query(struct ccs_io_buffer *head)
{
	struct list_head *tmp;
	int pos = 0;
	int len = 0;
	char *buf;
	if (head->read_avail)
		return 0;
	if (head->read_buf) {
		kfree(head->read_buf);
		head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		if (ptr->answer)
			continue;
		if (pos++ != head->read_step)
			continue;
		len = ptr->query_len;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	if (!len) {
		head->read_step = 0;
		return 0;
	}
	buf = kzalloc(len, GFP_KERNEL);
	if (!buf)
		return 0;
	pos = 0;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		if (ptr->answer)
			continue;
		if (pos++ != head->read_step)
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
	/***** CRITICAL SECTION END *****/
	if (buf[0]) {
		head->read_avail = len;
		head->readbuf_size = head->read_avail;
		head->read_buf = buf;
		head->read_step++;
	} else {
		kfree(buf);
	}
	return 0;
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
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		ptr->timer = 0;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2)
		return -EINVAL;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		if (ptr->serial != serial)
			continue;
		if (!ptr->answer)
			ptr->answer = answer;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

/**
 * ccs_read_version: Get version.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns version information.
 */
static int ccs_read_version(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		ccs_io_printf(head, "1.7.0-pre");
		head->read_eof = true;
	}
	return 0;
}

/**
 * ccs_read_self_domain - Get the current process's domainname.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns the current process's domainname.
 */
static int ccs_read_self_domain(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		/*
		 * ccs_current_domain()->domainname != NULL
		 * because every process belongs to a domain and
		 * the domain's name cannot be NULL.
		 */
		ccs_io_printf(head, "%s",
			      ccs_current_domain()->domainname->name);
		head->read_eof = true;
	}
	return 0;
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
	struct ccs_io_buffer *head = kzalloc(sizeof(*head), GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	mutex_init(&head->io_sem);
	head->type = type;
	switch (type) {
	case CCS_DOMAINPOLICY: /* /proc/ccs/domain_policy */
		head->write = ccs_write_domain_policy;
		head->read = ccs_read_domain_policy;
		break;
	case CCS_EXCEPTIONPOLICY: /* /proc/ccs/exception_policy */
		head->write = ccs_write_exception_policy;
		head->read = ccs_read_exception_policy;
		break;
#ifdef CONFIG_CCSECURITY_AUDIT
	case CCS_GRANTLOG: /* /proc/ccs/grant_log */
		head->poll = ccs_poll_grant_log;
		head->read = ccs_read_grant_log;
		break;
	case CCS_REJECTLOG: /* /proc/ccs/reject_log */
		head->poll = ccs_poll_reject_log;
		head->read = ccs_read_reject_log;
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
		head->write = ccs_write_manager_policy;
		head->read = ccs_read_manager_policy;
		break;
	}
	if (!(file->f_mode & FMODE_READ)) {
		/*
		 * No need to allocate read_buf since it is not opened
		 * for reading.
		 */
		head->read = NULL;
		head->poll = NULL;
	} else if (type != CCS_QUERY &&
		   type != CCS_GRANTLOG && type != CCS_REJECTLOG) {
		/*
		 * Don't allocate buffer for reading if the file is one of
		 * /proc/ccs/grant_log , /proc/ccs/reject_log , /proc/ccs/query.
		 */
		if (!head->readbuf_size)
			head->readbuf_size = 4096 * 2;
		head->read_buf = kzalloc(head->readbuf_size, GFP_KERNEL);
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
		head->writebuf_size = 4096 * 2;
		head->write_buf = kzalloc(head->writebuf_size, GFP_KERNEL);
		if (!head->write_buf) {
			kfree(head->read_buf);
			kfree(head);
			return -ENOMEM;
		}
	}
	if (type != CCS_QUERY &&
	    type != CCS_GRANTLOG && type != CCS_REJECTLOG)
		head->reader_idx = ccs_read_lock();
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
	 * The obserber counter is used by ccs_check_supervisor() to see if
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
 * /proc/ccs/query is handled by /usr/lib/ccs/ccs-queryd and
 * /proc/ccs/grant_log and /proc/ccs/reject_log are handled by
 * /usr/lib/ccs/ccs-auditd.
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
	int len = 0;
	struct ccs_io_buffer *head = file->private_data;
	char *cp;
	if (!head->read)
		return -ENOSYS;
	if (!access_ok(VERIFY_WRITE, buffer, buffer_len))
		return -EFAULT;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	/* Call the policy handler. */
	len = head->read(head);
	if (len < 0)
		goto out;
	/* Write to buffer. */
	len = head->read_avail;
	if (len > buffer_len)
		len = buffer_len;
	if (!len)
		goto out;
	/* head->read_buf changes by some functions. */
	cp = head->read_buf;
	if (copy_to_user(buffer, cp, len)) {
		len = -EFAULT;
		goto out;
	}
	head->read_avail -= len;
	memmove(cp, cp + len, head->read_avail);
 out:
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
	if (!head->write)
		return -ENOSYS;
	if (!access_ok(VERIFY_READ, buffer, buffer_len))
		return -EFAULT;
	/* Don't allow updating policies by non manager programs. */
	if (head->write != ccs_write_pid &&
	    head->write != ccs_write_domain_policy &&
	    !ccs_is_policy_manager())
		return -EPERM;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	/* Read a line and dispatch it to the policy handler. */
	while (avail_len > 0) {
		char c;
		if (head->write_avail >= head->writebuf_size - 1) {
			error = -ENOMEM;
			break;
		} else if (get_user(c, buffer)) {
			error = -EFAULT;
			break;
		}
		buffer++;
		avail_len--;
		cp0[head->write_avail++] = c;
		if (c != '\n')
			continue;
		cp0[head->write_avail - 1] = '\0';
		head->write_avail = 0;
		ccs_normalize_line(cp0);
		head->write(head);
	}
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
		ccs_read_unlock(head->reader_idx);
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
