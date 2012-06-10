/*
 * fs/sakura_bind.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4.1   2007/06/05
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
	struct reserved_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;              /* Delete flag.                          */
	u16 min_port;                /* Start of port number range.           */
	u16 max_port;                /* End of port number range.             */
};

/*************************  NETWORK RESERVED ACL HANDLER  *************************/

static struct reserved_entry *reservedport_list = NULL;

static int AddReservedEntry(const u16 min_port, const u16 max_port, const int is_delete)
{
	struct reserved_entry *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	int error = -ENOMEM;
	for (ptr = reservedport_list; ptr; ptr = ptr->next) {
		if (ptr->min_port == min_port && max_port == ptr->max_port) {
			ptr->is_deleted = is_delete;
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
	mb(); /* Instead of using spinlock. */
	if ((ptr = reservedport_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		reservedport_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

int SAKURA_MayAutobind(const u16 port)
{
	/* Must not sleep, for called inside spin_lock. */
	struct reserved_entry *ptr;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_AUTOBIND)) return 0;
	for (ptr = reservedport_list; ptr; ptr = ptr->next) {
		if (ptr->min_port <= port && port <= ptr->max_port && !ptr->is_deleted) return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(SAKURA_MayAutobind);

int AddReservedPortPolicy(char *data, const int is_delete)
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
	struct reserved_entry *ptr = head->read_var2;
	if (!ptr) ptr = reservedport_list;
	while (ptr) {
		head->read_var2 = ptr;
		if (!ptr->is_deleted) {
			if (ptr->min_port != ptr->max_port) {
				if (io_printf(head, KEYWORD_DENY_AUTOBIND "%u-%u\n", ptr->min_port, ptr->max_port)) break;
			} else {
				if (io_printf(head, KEYWORD_DENY_AUTOBIND "%u\n", ptr->min_port)) break;
			}
		}
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/***** SAKURA Linux end. *****/
