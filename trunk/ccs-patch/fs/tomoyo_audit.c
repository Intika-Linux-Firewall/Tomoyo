/*
 * fs/tomoyo_audit.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.3.2   2007/02/14
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>

/*************************  AUDIT FUNCTIONS  *************************/

static DECLARE_WAIT_QUEUE_HEAD(grant_log_wait);
static DECLARE_WAIT_QUEUE_HEAD(reject_log_wait);

static spinlock_t audit_log_lock = SPIN_LOCK_UNLOCKED;

typedef struct log_entry {
	struct list_head list;
	char *log;
} LOG_ENTRY;

static LIST_HEAD(grant_log);
static LIST_HEAD(reject_log);

static int grant_log_count = 0, reject_log_count = 0;

char *InitAuditLog(int *len)
{
	char *buf;
	struct timeval tv;
	struct task_struct *task = current;
	const char *domainname = current->domain_info->domainname->name;
	do_gettimeofday(&tv);
	*len += strlen(domainname) + 256;
	if ((buf = ccs_alloc(*len)) != NULL) snprintf(buf, (*len) - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domainname);
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
int WriteAuditLog(char *buf, const int is_granted)
{
	/***** CRITICAL SECTION START *****/
	LOG_ENTRY *new_entry = (LOG_ENTRY *) ccs_alloc(sizeof(LOG_ENTRY));
	if (!new_entry) goto out;
	INIT_LIST_HEAD(&new_entry->list);
	new_entry->log = buf;
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

int CanSaveAuditLog(const int is_granted)
{
	if (is_granted) {
		if (grant_log_count < GetMaxGrantLog()) return 0;
	} else {
		if (reject_log_count < GetMaxRejectLog()) return 0;
	}
	return -ENOMEM;
}

int ReadGrantLog(IO_BUFFER *head)
{
	LOG_ENTRY *ptr = NULL;
	if (head->read_avail) return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf); head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (!list_empty(&grant_log)) {
		ptr = list_entry(grant_log.next, LOG_ENTRY, list);
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

int ReadRejectLog(IO_BUFFER *head)
{
	LOG_ENTRY *ptr = NULL;
	if (head->read_avail) return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf); head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (!list_empty(&reject_log)) {
		ptr = list_entry(reject_log.next, LOG_ENTRY, list);
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
