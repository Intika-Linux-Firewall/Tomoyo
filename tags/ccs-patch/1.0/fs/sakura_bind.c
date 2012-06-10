/*
 * fs/sakura_bind.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
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

typedef struct reserved_entry {
	struct reserved_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;              /* Delete flag.                          */
	unsigned short int min_port; /* Start of port number range.           */
	unsigned short int max_port; /* End of port number range.             */
} RESERVED_ENTRY;

/*************************  NETWORK RESERVED ACL HANDLER  *************************/

static RESERVED_ENTRY reservedport_list = { NULL, 0, 0, 0 };

static int AddReservedEntry(const unsigned short int min_port, const unsigned short int max_port)
{
	RESERVED_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	/* I don't want to add if it was already added. */
	for (ptr = reservedport_list.next; ptr; ptr = ptr->next) {
		if (ptr->min_port <= min_port && max_port <= ptr->max_port && !ptr->is_deleted) return 0;
	}
	if ((new_entry = (RESERVED_ENTRY *) alloc_element(sizeof(RESERVED_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(RESERVED_ENTRY));
	new_entry->next = NULL;
	new_entry->is_deleted = 0;
	new_entry->min_port = min_port;
	new_entry->max_port = max_port;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &reservedport_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	if (min_port != max_port) printk("SAKURA-NOTICE: Port %u-%u reserved.\n", min_port, max_port);
	else printk("SAKURA-NOTICE: Port %u reserved.\n", min_port);
	return 0;
}

int SAKURA_MayAutobind(const unsigned short int port)
{
	/* Must not sleep, for called inside spin_lock. */
	RESERVED_ENTRY *ptr;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_AUTOBIND)) return 0;
	for (ptr = reservedport_list.next; ptr; ptr = ptr->next) {
		if (ptr->min_port <= port && port <= ptr->max_port && !ptr->is_deleted) return -EPERM;
	}
	return 0;
}

int AddReservedPortPolicy(char *data)
{
	unsigned int from, to;
	if (!isRoot()) return -EPERM;
	NormalizeLine(data);
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return AddReservedEntry(from, to);
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536) return AddReservedEntry(from, from);
	}
	printk("%s: ERROR: Invalid port range '%s'\n", __FUNCTION__, data);
	return -EINVAL;
}

static int DelReservedEntry(const unsigned short int min_port, const unsigned short int max_port)
{
	RESERVED_ENTRY *ptr;
	for (ptr = reservedport_list.next; ptr; ptr = ptr->next) {
		if (ptr->min_port == min_port && max_port == ptr->max_port && !ptr->is_deleted) {
			ptr->is_deleted = 1;
			if (min_port != max_port) printk("SAKURA-NOTICE: Port %u-%u freed.\n", min_port, max_port);
			else printk("SAKURA-NOTICE: Port %u freed.\n", min_port);
			return 0;
		}
	}
	return -EINVAL;
}

int DelReservedPortPolicy(char *data)
{
	unsigned int from, to;
	if (!isRoot()) return -EPERM;
	NormalizeLine(data);
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return DelReservedEntry(from, to);
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536) return DelReservedEntry(from, from);
	}
	printk("%s: ERROR: Invalid port range '%s'\n", __FUNCTION__, data);
	return -EINVAL;
}

int ReadReservedPortPolicy(IO_BUFFER *head)
{
	RESERVED_ENTRY *ptr = (RESERVED_ENTRY *) head->read_var2;
	if (!ptr) ptr = reservedport_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted) {
			if (ptr->min_port != ptr->max_port) {
				if (io_printf(head, KEYWORD_DENY_AUTOBIND "%d-%d\n", ptr->min_port, ptr->max_port)) break;
			} else {
				if (io_printf(head, KEYWORD_DENY_AUTOBIND "%d\n", ptr->min_port)) break;
			}
		}
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(SAKURA_MayAutobind);

/***** SAKURA Linux end. *****/
