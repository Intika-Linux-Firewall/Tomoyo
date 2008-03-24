/*
 * fs/tomoyo_audit.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/03/24
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>

/**
 * ccs_dump_bprm - Dump "struct linux_binprm" for auditing.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns the contents of @bprm on success, NULL otherwise.
 */
static char *ccs_dump_bprm(struct linux_binprm *bprm)
{
	static const int buffer_len = PAGE_SIZE * 2;
	char *buffer = ccs_alloc(buffer_len);
	char *cp, *last_start;
	int len;
	unsigned long pos = bprm->p;
	int i = pos / PAGE_SIZE, offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool truncated = false;
	if (!buffer)
		return NULL;
	len = snprintf(buffer, buffer_len - 1,
		       "argc=%d envc=%d argv[]={ ", argv_count, envp_count);
	cp = buffer + len;
	if (!argv_count) {
		memmove(cp, "} envp[]={ ", 11);
		cp += 11;
	}
	if (!envp_count)
		*cp++ = '}';
	last_start = cp;
	while (argv_count || envp_count) {
		struct page *page;
		const char *kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page,
				   NULL) <= 0)
			goto out;
		pos += PAGE_SIZE - offset;
#else
		page = bprm->page[i];
#endif
		/* Map */
		kaddr = kmap(page);
		if (!kaddr) { /* Mapping failed. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
			put_page(page);
#endif
			goto out;
		}
		/* Read. */
		while (offset < PAGE_SIZE) {
			const unsigned char c = kaddr[offset++];
			if (cp == last_start)
				*cp++ = '"';
			if (cp >= buffer + buffer_len - 32) {
				/* Preserve some room for "..." string. */
				truncated = true;
			} else if (c == '\\') {
				*cp++ = '\\';
				*cp++ = '\\';
			} else if (c > ' ' && c < 127) {
				*cp++ = c;
			} else if (!c) {
				*cp++ = '"';
				*cp++ = ' ';
				last_start = cp;
			} else {
				*cp++ = '\\';
				*cp++ = (c >> 6) + '0';
				*cp++ = ((c >> 3) & 7) + '0';
				*cp++ = (c & 7) + '0';
			}
			if (c)
				continue;
			if (argv_count) {
				if (--argv_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
					memmove(cp, "} envp[]={ ", 11);
					cp += 11;
					if (!envp_count)
						goto no_envp;
					last_start = cp;
				}
			} else if (envp_count) {
				if (--envp_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
 no_envp:
					*cp++ = '}';
					*cp++ = '\0';
				}
			} else {
				break;
			}
		}
		/* Unmap. */
		kunmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		put_page(page);
#endif
		i++;
		offset = 0;
	}
	return buffer;
 out:
	snprintf(buffer, buffer_len - 1,
		 "argc=%d envc=%d argv[]={ ... } envp[]= { ... }",
		 argv_count, envp_count);
	return buffer;
}

static DECLARE_WAIT_QUEUE_HEAD(grant_log_wait);
static DECLARE_WAIT_QUEUE_HEAD(reject_log_wait);

static DEFINE_SPINLOCK(audit_log_lock);

/* Structure for audit log. */
struct log_entry {
	struct list_head list;
	char *log;
};

/* The list for "struct log_entry". */
static LIST_HEAD(grant_log);

/* The list for "struct log_entry". */
static LIST_HEAD(reject_log);

static int grant_log_count;
static int reject_log_count;

/**
 * ccs_init_audit_log - Allocate buffer for audit logs.
 *
 * @len:     Required size.
 * @profile: Profile number.
 * @mode:    Access control mode.
 * @bprm:    Pointer to "struct linux_binprm". May be NULL.
 *
 * Returns pointer to allocated memory.
 *
 * The @len is updated to add the header lines' size on success.
 */
char *ccs_init_audit_log(int *len, const u8 profile, const u8 mode,
			 struct linux_binprm *bprm)
{
	static const char *mode_4[4] = {
		"disabled", "learning", "permissive", "enforcing"
	};
	char *buf;
	char *bprm_info = "";
	struct timeval tv;
	struct task_struct *task = current;
	u32 tomoyo_flags = task->tomoyo_flags;
	const char *domainname = current->domain_info->domainname->name;
	do_gettimeofday(&tv);
	*len += strlen(domainname) + 256;
	if (bprm) {
		bprm_info = ccs_dump_bprm(bprm);
		if (!bprm_info)
			return NULL;
		*len += strlen(bprm_info);
	}
	buf = ccs_alloc(*len);
	if (buf)
		snprintf(buf, (*len) - 1,
			 "#timestamp=%lu profile=%u mode=%s pid=%d uid=%d "
			 "gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d "
			 "fsgid=%d state[0]=%u state[1]=%u state[2]=%u %s\n"
			 "%s\n", tv.tv_sec, profile, mode_4[mode], task->pid,
			 task->uid, task->gid, task->euid, task->egid,
			 task->suid, task->sgid, task->fsuid, task->fsgid,
			 (u8) (tomoyo_flags >> 24), (u8) (tomoyo_flags >> 16),
			 (u8) (tomoyo_flags >> 8), bprm_info, domainname);
	if (bprm)
		ccs_free(bprm_info);
	return buf;
}

/**
 * get_max_grant_log - Get max number of spoolable grant logs.
 *
 * Returns max number of spoolable grant logs.
 */
static unsigned int get_max_grant_log(void)
{
	return ccs_check_flags(CCS_TOMOYO_MAX_GRANT_LOG);
}

/**
 * get_max_reject_log - Get max number of spoolable reject logs.
 *
 * Returns max number of spoolable reject logs.
 */
static unsigned int get_max_reject_log(void)
{
	return ccs_check_flags(CCS_TOMOYO_MAX_REJECT_LOG);
}

/**
 * ccs_write_audit_log - Write audit log.
 *
 * @buf:        Pointer to audit log.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 *
 * Caller must allocate @buf with ccs_init_audit_log().
 */
int ccs_write_audit_log(char *buf, const bool is_granted)
{
	struct log_entry *new_entry = ccs_alloc(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	INIT_LIST_HEAD(&new_entry->list);
	new_entry->log = buf;
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (is_granted) {
		if (grant_log_count < get_max_grant_log()) {
			list_add_tail(&new_entry->list, &grant_log);
			grant_log_count++;
			buf = NULL;
			ccs_update_counter(CCS_UPDATES_COUNTER_GRANT_LOG);
		}
	} else {
		if (reject_log_count < get_max_reject_log()) {
			list_add_tail(&new_entry->list, &reject_log);
			reject_log_count++;
			buf = NULL;
			ccs_update_counter(CCS_UPDATES_COUNTER_REJECT_LOG);
		}
	}
	spin_unlock(&audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (is_granted)
		wake_up(&grant_log_wait);
	else
		wake_up(&reject_log_wait);
	if (!buf)
		return 0;
	ccs_free(new_entry);
 out:
	ccs_free(buf);
	return -ENOMEM;
}

/**
 * ccs_can_save_audit_log - Check whether the kernel can save new audit log.
 *
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 if the kernel can save, -ENOMEM otherwise.
 */
int ccs_can_save_audit_log(const bool is_granted)
{
	if (is_granted) {
		if (grant_log_count < get_max_grant_log())
			return 0;
	} else {
		if (reject_log_count < get_max_reject_log())
			return 0;
	}
	return -ENOMEM;
}

/**
 * ccs_read_grant_log - Read a grant log.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
int ccs_read_grant_log(struct ccs_io_buffer *head)
{
	struct log_entry *ptr = NULL;
	if (head->read_avail)
		return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf);
		head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (!list_empty(&grant_log)) {
		ptr = list_entry(grant_log.next, struct log_entry, list);
		list_del(&ptr->list);
		grant_log_count--;
	}
	spin_unlock(&audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (ptr) {
		head->read_buf = ptr->log;
		head->read_avail = strlen(ptr->log) + 1;
		head->readbuf_size = head->read_avail;
		ccs_free(ptr);
	}
	return 0;
}

/**
 * ccs_poll_grant_log - Wait for a grant log.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read a grant log.
 */
int ccs_poll_grant_log(struct file *file, poll_table *wait)
{
	if (grant_log_count)
		return POLLIN | POLLRDNORM;
	poll_wait(file, &grant_log_wait, wait);
	if (grant_log_count)
		return POLLIN | POLLRDNORM;
	return 0;
}

/**
 * ccs_read_reject_log - Read a reject log.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
int ccs_read_reject_log(struct ccs_io_buffer *head)
{
	struct log_entry *ptr = NULL;
	if (head->read_avail)
		return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf);
		head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (!list_empty(&reject_log)) {
		ptr = list_entry(reject_log.next, struct log_entry, list);
		list_del(&ptr->list);
		reject_log_count--;
	}
	spin_unlock(&audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (ptr) {
		head->read_buf = ptr->log;
		head->read_avail = strlen(ptr->log) + 1;
		head->readbuf_size = head->read_avail;
		ccs_free(ptr);
	}
	return 0;
}

/**
 * ccs_poll_reject_log - Wait for a reject log.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read a reject log.
 */
int ccs_poll_reject_log(struct file *file, poll_table *wait)
{
	if (reject_log_count)
		return POLLIN | POLLRDNORM;
	poll_wait(file, &reject_log_wait, wait);
	if (reject_log_count)
		return POLLIN | POLLRDNORM;
	return 0;
}
