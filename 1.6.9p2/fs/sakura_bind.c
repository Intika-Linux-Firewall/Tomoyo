/*
 * fs/sakura_bind.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9   2011/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>

/* Structure for "deny_autobind" keyword. */
struct ccs_reserved_entry {
	struct list1_head list;
	bool is_deleted;             /* Delete flag.                         */
	u16 min_port;                /* Start of port number range.          */
	u16 max_port;                /* End of port number range.            */
};

/* The list for "struct ccs_reserved_entry". */
static LIST1_HEAD(ccs_reservedport_list);

/**
 * ccs_update_reserved_entry - Update "struct ccs_reserved_entry" list.
 *
 * @min_port: Start of port number range.
 * @max_port: End of port number range.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_reserved_entry(const u16 min_port, const u16 max_port,
				     const bool is_delete)
{
	struct ccs_reserved_entry *new_entry;
	struct ccs_reserved_entry *ptr;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_reservedport_list, list) {
		if (ptr->min_port != min_port || max_port != ptr->max_port)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->min_port = min_port;
	new_entry->max_port = max_port;
	list1_add_tail_mb(&new_entry->list, &ccs_reservedport_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
	return error;
}

/**
 * ccs_lport_reserved - Check permission for bind()'s automatic port number selection.
 *
 * @port: Port number.
 *
 * Returns true on success, false otherwise.
 */
bool ccs_lport_reserved(const u16 port)
{
	/***** CRITICAL SECTION START *****/
	struct ccs_reserved_entry *ptr;
	if (!ccs_check_flags(NULL, CCS_RESTRICT_AUTOBIND))
		return false;
	list1_for_each_entry(ptr, &ccs_reservedport_list, list) {
		if (ptr->min_port <= port && port <= ptr->max_port &&
		    !ptr->is_deleted)
			return true;
	}
	return false;
	/***** CRITICAL SECTION END *****/
}
EXPORT_SYMBOL(ccs_lport_reserved); /* for net/ipv4/ and net/ipv6/ */

/**
 * ccs_write_reserved_port_policy - Write "struct ccs_reserved_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_reserved_port_policy(char *data, const bool is_delete)
{
	unsigned int from;
	unsigned int to;
	if (strchr(data, ' '))
		goto out;
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536)
			return ccs_update_reserved_entry(from, to, is_delete);
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536)
			return ccs_update_reserved_entry(from, from, is_delete);
	}
 out:
	printk(KERN_WARNING "%s: ERROR: Invalid port range '%s'\n",
	       __func__, data);
	return -EINVAL;
}

/**
 * ccs_read_reserved_port_policy - Read "struct ccs_reserved_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_reserved_port_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	char buffer[16];
	memset(buffer, 0, sizeof(buffer));
	list1_for_each_cookie(pos, head->read_var2, &ccs_reservedport_list) {
		u16 min_port;
		u16 max_port;
		struct ccs_reserved_entry *ptr;
		ptr = list1_entry(pos, struct ccs_reserved_entry, list);
		if (ptr->is_deleted)
			continue;
		min_port = ptr->min_port;
		max_port = ptr->max_port;
		snprintf(buffer, sizeof(buffer) - 1, "%u%c%u", min_port,
			 min_port != max_port ? '-' : '\0', max_port);
		if (!ccs_io_printf(head, KEYWORD_DENY_AUTOBIND "%s\n", buffer))
			goto out;
	}
	return true;
 out:
	return false;
}
