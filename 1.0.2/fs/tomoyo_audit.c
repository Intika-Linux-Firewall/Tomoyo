/*
 * fs/tomoyo_audit.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
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

static const char *grant_log[MAX_GRANT_LOG];
static int grant_log_count = 0;

static const char *reject_log[MAX_REJECT_LOG];
static int reject_log_count = 0;

/*
 * Write audit log.
 * Caller must allocate buf with kmalloc(), and mustn't call kfree().
 */
int WriteAuditLog(const char *buf, const int is_granted)
{
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (is_granted) {
		int max = GetMaxGrantLog();
		if (max > MAX_GRANT_LOG) max = MAX_GRANT_LOG;
		if (grant_log_count < max) {
			grant_log[grant_log_count] = buf;
			mb();
			grant_log_count++;
			buf = NULL;
		}
	} else {
		int max = GetMaxRejectLog();
		if (max > MAX_REJECT_LOG) max = MAX_REJECT_LOG;
		if (reject_log_count < max) {
			reject_log[reject_log_count] = buf;
			mb();
			reject_log_count++;
			buf = NULL;
		}
	}
	spin_unlock(&audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (is_granted) wake_up(&grant_log_wait);
	else wake_up(&reject_log_wait);
	if (!buf) return 0;
	kfree(buf);
	return -ENOMEM;
}

int CanSaveAuditLog(const int is_granted)
{
	if (is_granted) {
		int max = GetMaxGrantLog();
		if (max > MAX_GRANT_LOG) max = MAX_GRANT_LOG;
		if (grant_log_count < max) return 0;
	} else {
		int max = GetMaxRejectLog();
		if (max > MAX_REJECT_LOG) max = MAX_REJECT_LOG;
		if (reject_log_count < max) return 0;
	}
	return -ENOMEM;
}

int ReadGrantLog(IO_BUFFER *head)
{
	const char *ptr = NULL;
	if (head->read_avail) return 0;
	if (head->read_buf) {
		kfree(head->read_buf); head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (grant_log_count) {
		ptr = grant_log[0];
		grant_log_count--;
		memmove(grant_log, grant_log + 1, grant_log_count * sizeof(grant_log[0]));
	}
	spin_unlock(&audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (ptr) {
		head->read_buf = (char *) ptr;
		head->readbuf_size = head->read_avail = strlen(ptr) + 1;
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
	const char *ptr = NULL;
	if (head->read_avail) return 0;
	if (head->read_buf) {
		kfree(head->read_buf); head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&audit_log_lock);
	if (reject_log_count) {
		ptr = reject_log[0];
		reject_log_count--;
		memmove(reject_log, reject_log + 1, reject_log_count * sizeof(reject_log[0]));
	}
	spin_unlock(&audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (ptr) {
		head->read_buf = (char *) ptr;
		head->readbuf_size = head->read_avail = strlen(ptr) + 1;
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
