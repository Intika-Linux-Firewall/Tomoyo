/*
 * fs/sakura_bind.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.3-pre   2007/12/17
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>

/***** The structure for reserved ports. *****/

struct reserved_entry {
	struct list1_head list;
	bool is_deleted;             /* Delete flag.                          */
	u16 min_port;                /* Start of port number range.           */
	u16 max_port;                /* End of port number range.             */
};

/*************************  NETWORK RESERVED ACL HANDLER  *************************/

static LIST1_HEAD(reservedport_list);

static int AddReservedEntry(const u16 min_port, const u16 max_port, const bool is_delete)
{
	struct reserved_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &reservedport_list, list) {
		if (ptr->min_port == min_port && max_port == ptr->max_port) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->min_port = min_port;
	new_entry->max_port = max_port;
	list1_add_tail_mb(&new_entry->list, &reservedport_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

int SAKURA_MayAutobind(const u16 port)
{
	/* Must not sleep, for called inside spin_lock. */
	struct reserved_entry *ptr;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_AUTOBIND)) return 0;
	list1_for_each_entry(ptr, &reservedport_list, list) {
		if (ptr->min_port <= port && port <= ptr->max_port && !ptr->is_deleted) return -EPERM;
	}
	return 0;
}

int AddReservedPortPolicy(char *data, const bool is_delete)
{
	unsigned int from, to;
	if (strchr(data, ' ')) goto out;
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return AddReservedEntry(from, to, is_delete);
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536) return AddReservedEntry(from, from, is_delete);
	}
 out:
	printk("%s: ERROR: Invalid port range '%s'\n", __FUNCTION__, data);
	return -EINVAL;
}

int ReadReservedPortPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &reservedport_list) {
		struct reserved_entry *ptr;
		ptr = list1_entry(pos, struct reserved_entry, list);
		if (ptr->is_deleted) continue;
		if (ptr->min_port != ptr->max_port) {
			if (io_printf(head, KEYWORD_DENY_AUTOBIND "%u-%u\n", ptr->min_port, ptr->max_port)) return -ENOMEM;
		} else {
			if (io_printf(head, KEYWORD_DENY_AUTOBIND "%u\n", ptr->min_port)) return -ENOMEM;
		}
	}
	return 0;
}

/***** SAKURA Linux end. *****/
