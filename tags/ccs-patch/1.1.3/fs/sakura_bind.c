/*
 * fs/sakura_bind.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1.3   2006/07/13
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

static int AddReservedEntry(const unsigned short int min_port, const unsigned short int max_port, const int is_delete)
{
	RESERVED_ENTRY *new_entry, *ptr;
	if (!is_delete) {
		static spinlock_t lock = SPIN_LOCK_UNLOCKED;
		/* I don't want to add if it was already added. */
		for (ptr = reservedport_list.next; ptr; ptr = ptr->next) {
			if (ptr->min_port == min_port && max_port == ptr->max_port) { ptr->is_deleted = 0; return 0; }
		}
		if ((new_entry = (RESERVED_ENTRY *) alloc_element(sizeof(RESERVED_ENTRY))) == NULL) return -ENOMEM;
		new_entry->min_port = min_port;
		new_entry->max_port = max_port;
		/***** CRITICAL SECTION START *****/
		spin_lock(&lock);
		for (ptr = &reservedport_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
		spin_unlock(&lock);
		/***** CRITICAL SECTION END *****/
	} else {
		for (ptr = reservedport_list.next; ptr; ptr = ptr->next) {
			if (ptr->min_port == min_port && max_port == ptr->max_port) ptr->is_deleted = 1;
		}
	}
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

int AddReservedPortPolicy(char *data, const int is_delete)
{
	unsigned int from, to;
	NormalizeLine(data);
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return AddReservedEntry(from, to, is_delete);
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536) return AddReservedEntry(from, from, is_delete);
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
				if (io_printf(head, KEYWORD_DENY_AUTOBIND "%u-%u\n", ptr->min_port, ptr->max_port)) break;
			} else {
				if (io_printf(head, KEYWORD_DENY_AUTOBIND "%u\n", ptr->min_port)) break;
			}
		}
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(SAKURA_MayAutobind);

/***** SAKURA Linux end. *****/
