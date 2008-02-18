/*
 * fs/tomoyo_audit.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/02/18
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>

static char *DumpBprm(struct linux_binprm *bprm)
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
	if (!buffer) return NULL;
	len = snprintf(buffer, buffer_len - 1, "argc=%d envc=%d argv[]={ ", argv_count, envp_count);
	cp = buffer + len;
	if (!argv_count) {
		memmove(cp, "} envp[]={ ", 11);
		cp += 11;
	}
	if (!envp_count) *cp++ = '}';
	last_start = cp;
	while (argv_count || envp_count) {
		struct page *page;
		const char *kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0) goto out;
		pos += PAGE_SIZE - offset;
#else
		page = bprm->page[i];
#endif
		/* Map */
		kaddr = kmap(page);
		if (!kaddr) { /* Mapping failed. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
			put_page(page);
#endif
			goto out;
		}
		/* Read. */
		while (offset < PAGE_SIZE) {
			const unsigned char c = kaddr[offset++];
			if (cp == last_start) *cp++ = '"';
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
			if (c) continue;
			if (argv_count) {
				if (--argv_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
					memmove(cp, "} envp[]={ ", 11);
					cp += 11;
					if (!envp_count) goto no_envp;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		put_page(page);
#endif
		i++;
		offset = 0;
	}
	return buffer;
 out:
	snprintf(buffer, buffer_len - 1, "argc=%d envc=%d argv[]={ ... } envp[]= { ... }", argv_count, envp_count);
	return buffer;
}

/*************************  AUDIT FUNCTIONS  *************************/

static DECLARE_WAIT_QUEUE_HEAD(grant_log_wait);
static DECLARE_WAIT_QUEUE_HEAD(reject_log_wait);

static spinlock_t audit_log_lock = SPIN_LOCK_UNLOCKED;

struct log_entry {
	struct list_head list;
	char *log;
};

static LIST_HEAD(grant_log);
static LIST_HEAD(reject_log);

static int grant_log_count = 0, reject_log_count = 0;

char *InitAuditLog(int *len, const u8 profile, const u8 mode, struct linux_binprm *bprm)
{
	char *buf;
	char *bprm_info = "";
	struct timeval tv;
	struct task_struct *task = current;
	u32 tomoyo_flags = task->tomoyo_flags;
	const char *domainname = current->domain_info->domainname->name;
	do_gettimeofday(&tv);
	*len += strlen(domainname) + 256;
	if (bprm) {
		bprm_info = DumpBprm(bprm);
		if (!bprm_info) return NULL;
		*len += strlen(bprm_info);
	}
	if ((buf = ccs_alloc(*len)) != NULL) snprintf(buf, (*len) - 1, "#timestamp=%lu profile=%u mode=%u pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d state[0]=%u state[1]=%u state[2]=%u %s\n%s\n", tv.tv_sec, profile, mode, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, (u8) (tomoyo_flags >> 24), (u8) (tomoyo_flags >> 16), (u8) (tomoyo_flags >> 8), bprm_info, domainname);
	if (bprm) ccs_free(bprm_info);
	return buf;
}

static unsigned int GetMaxGrantLog(void)
{
	return CheckCCSFlags(CCS_TOMOYO_MAX_GRANT_LOG);
}

static unsigned int GetMaxRejectLog(void)
{
	return CheckCCSFlags(CCS_TOMOYO_MAX_REJECT_LOG);
}

/*
 * Write audit log.
 * Caller must allocate buf with InitAuditLog().
 */
int WriteAuditLog(char *buf, const bool is_granted)
{
	struct log_entry *new_entry = ccs_alloc(sizeof(*new_entry));
	if (!new_entry) goto out;
	INIT_LIST_HEAD(&new_entry->list);
	new_entry->log = buf;
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (is_granted) {
		if (grant_log_count < GetMaxGrantLog()) {
			list_add_tail(&new_entry->list, &grant_log);
			grant_log_count++;
			buf = NULL;
			UpdateCounter(CCS_UPDATES_COUNTER_GRANT_LOG);
		}
	} else {
		if (reject_log_count < GetMaxRejectLog()) {
			list_add_tail(&new_entry->list, &reject_log);
			reject_log_count++;
			buf = NULL;
			UpdateCounter(CCS_UPDATES_COUNTER_REJECT_LOG);
		}
	}
	spin_unlock(&audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (is_granted) wake_up(&grant_log_wait);
	else wake_up(&reject_log_wait);
	if (!buf) return 0;
	ccs_free(new_entry);
 out: ;
	ccs_free(buf);
	return -ENOMEM;
}

int CanSaveAuditLog(const bool is_granted)
{
	if (is_granted) {
		if (grant_log_count < GetMaxGrantLog()) return 0;
	} else {
		if (reject_log_count < GetMaxRejectLog()) return 0;
	}
	return -ENOMEM;
}

int ReadGrantLog(struct io_buffer *head)
{
	struct log_entry *ptr = NULL;
	if (head->read_avail) return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf); head->read_buf = NULL;
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
		head->readbuf_size = head->read_avail = strlen(ptr->log) + 1;
		ccs_free(ptr);
	}
	return 0;
}

int PollGrantLog(struct file *file, poll_table *wait)
{
	if (grant_log_count) return POLLIN | POLLRDNORM;
	poll_wait(file, &grant_log_wait, wait);
	if (grant_log_count) return POLLIN | POLLRDNORM;
	return 0;
}

int ReadRejectLog(struct io_buffer *head)
{
	struct log_entry *ptr = NULL;
	if (head->read_avail) return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf); head->read_buf = NULL;
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
		head->readbuf_size = head->read_avail = strlen(ptr->log) + 1;
		ccs_free(ptr);
	}
	return 0;
}

int PollRejectLog(struct file *file, poll_table *wait)
{
	if (reject_log_count) return POLLIN | POLLRDNORM;
	poll_wait(file, &reject_log_wait, wait);
	if (reject_log_count) return POLLIN | POLLRDNORM;
	return 0;
}

/***** TOMOYO Linux end. *****/
