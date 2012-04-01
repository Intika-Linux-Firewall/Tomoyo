/*
 * fs/tomoyo_audit.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/highmem.h>

/**
 * ccs_print_bprm - Print "struct linux_binprm" for auditing.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @dump: Pointer to "struct ccs_page_dump".
 *
 * Returns the contents of @bprm on success, NULL otherwise.
 */
static char *ccs_print_bprm(struct linux_binprm *bprm,
			    struct ccs_page_dump *dump)
{
	static const int ccs_buffer_len = 4096 * 2;
	char *buffer = ccs_alloc(ccs_buffer_len, false);
	char *cp;
	char *last_start;
	int len;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool truncated = false;
	if (!buffer)
		return NULL;
	len = snprintf(buffer, ccs_buffer_len - 1,
		       "argc=%d envc=%d argv[]={ ", argv_count, envp_count);
	cp = buffer + len;
	if (!argv_count) {
		memmove(cp, "} envp[]={ ", 11);
		cp += 11;
	}
	last_start = cp;
	while (argv_count || envp_count) {
		if (!ccs_dump_page(bprm, pos, dump))
			goto out;
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (offset < PAGE_SIZE) {
			const char *kaddr = dump->data;
			const unsigned char c = kaddr[offset++];
			if (cp == last_start)
				*cp++ = '"';
			if (cp >= buffer + ccs_buffer_len - 32) {
				/* Reserve some room for "..." string. */
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
					last_start = cp;
					truncated = false;
				}
			} else if (envp_count) {
				if (--envp_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
				}
			}
			if (!argv_count && !envp_count)
				break;
		}
		offset = 0;
	}
	*cp++ = '}';
	*cp = '\0';
	return buffer;
 out:
	snprintf(buffer, ccs_buffer_len - 1,
		 "argc=%d envc=%d argv[]={ ... } envp[]= { ... }",
		 argv_count, envp_count);
	return buffer;
}

/**
 * ccs_init_audit_log - Allocate buffer for audit logs.
 *
 * @len: Required size.
 * @r:   Pointer to "struct ccs_request_info".
 *
 * Returns pointer to allocated memory.
 *
 * The @len is updated to add the header lines' size on success.
 */
char *ccs_init_audit_log(int *len, struct ccs_request_info *r)
{
	static const char *ccs_mode_4[4] = {
		"disabled", "learning", "permissive", "enforcing"
	};
	char *buf;
	char *bprm_info = "";
	const char *symlink_head = "";
	const char *symlink_tail = "";
	const char *symlink_info = "";
	struct timeval tv;
	u32 ccs_flags = current->ccs_flags;
	const char *domainname;
	if (!r->domain)
		r->domain = ccs_current_domain();
	domainname = r->domain->domainname->name;
	do_gettimeofday(&tv);
	*len += strlen(domainname) + 256;
	if (r->ee) {
		bprm_info = ccs_print_bprm(r->ee->bprm, &r->ee->dump);
		if (!bprm_info)
			return NULL;
		*len += strlen(bprm_info);
	}
	if (r->obj && r->obj->symlink_target) {
		symlink_head = "symlink.target=\"";
		symlink_info = r->obj->symlink_target->name;
		symlink_tail = "\" ";
		*len += 18 + strlen(symlink_info);
	}
	buf = ccs_alloc(*len, true);
	if (buf)
		snprintf(buf, (*len) - 1,
			 "#timestamp=%lu profile=%u mode=%s pid=%d uid=%d "
			 "gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d "
			 "fsgid=%d state[0]=%u state[1]=%u state[2]=%u "
			 "%s%s%s%s\n%s\n",
			 tv.tv_sec, r->profile, ccs_mode_4[r->mode],
			 (pid_t) sys_getpid(), current_uid(), current_gid(),
			 current_euid(), current_egid(), current_suid(),
			 current_sgid(), current_fsuid(), current_fsgid(),
			 (u8) (ccs_flags >> 24), (u8) (ccs_flags >> 16),
			 (u8) (ccs_flags >> 8), symlink_head, symlink_info,
			 symlink_tail, bprm_info, domainname);
	if (r->ee)
		ccs_free(bprm_info);
	return buf;
}

/**
 * ccs_update_task_state - Update task's state.
 *
 * @r:          Pointer to "struct ccs_request_info".
 */
static void ccs_update_task_state(struct ccs_request_info *r)
{
	/*
	 * Don't change the lowest byte because it is reserved for
	 * CCS_CHECK_READ_FOR_OPEN_EXEC / CCS_DONT_SLEEP_ON_ENFORCE_ERROR /
	 * CCS_TASK_IS_EXECUTE_HANDLER / CCS_TASK_IS_POLICY_MANAGER.
	 */
	const struct ccs_condition_list *ptr = r->cond;
	if (ptr) {
		struct task_struct *task = current;
		const u8 flags = ptr->post_state[3];
		u32 ccs_flags = task->ccs_flags;
		if (flags & 1) {
			ccs_flags &= ~0xFF000000;
			ccs_flags |= ptr->post_state[0] << 24;
		}
		if (flags & 2) {
			ccs_flags &= ~0x00FF0000;
			ccs_flags |= ptr->post_state[1] << 16;
		}
		if (flags & 4) {
			ccs_flags &= ~0x0000FF00;
			ccs_flags |= ptr->post_state[2] << 8;
		}
		task->ccs_flags = ccs_flags;
		r->cond = NULL;
	}
}

#ifndef CONFIG_TOMOYO_AUDIT

/**
 * ccs_write_audit_log - Write audit log.
 *
 * @is_granted: True if this is a granted log.
 * @r:          Pointer to "struct ccs_request_info".
 * @fmt:        The printf()'s format string, followed by parameters.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 */
int ccs_write_audit_log(const bool is_granted, struct ccs_request_info *r,
			const char *fmt, ...)
{
	ccs_update_task_state(r);
	return 0;
}

#else

static DECLARE_WAIT_QUEUE_HEAD(ccs_grant_log_wait);
static DECLARE_WAIT_QUEUE_HEAD(ccs_reject_log_wait);

static DEFINE_SPINLOCK(ccs_audit_log_lock);

/* Structure for audit log. */
struct ccs_log_entry {
	struct list_head list;
	char *log;
};

/* The list for "struct ccs_log_entry". */
static LIST_HEAD(ccs_grant_log);

/* The list for "struct ccs_log_entry". */
static LIST_HEAD(ccs_reject_log);

static int ccs_grant_log_count;
static int ccs_reject_log_count;

/**
 * ccs_can_save_audit_log - Check whether the kernel can save new audit log.
 *
 * @domain:     Pointer to "struct ccs_domain_info".
 *              NULL for ccs_current_domain().
 * @is_granted: True if this is a granted log.
 *
 * Returns true if the kernel can save, false otherwise.
 */
static bool ccs_can_save_audit_log(const struct ccs_domain_info *domain,
				   const bool is_granted)
{
	if (is_granted)
		return ccs_grant_log_count
			< ccs_check_flags(domain, CCS_MAX_GRANT_LOG);
	return ccs_reject_log_count
		< ccs_check_flags(domain, CCS_MAX_REJECT_LOG);
}

/**
 * ccs_write_audit_log - Write audit log.
 *
 * @is_granted: True if this is a granted log.
 * @r:          Pointer to "struct ccs_request_info".
 * @fmt:        The printf()'s format string, followed by parameters.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 */
int ccs_write_audit_log(const bool is_granted, struct ccs_request_info *r,
			const char *fmt, ...)
{
	va_list args;
	int error = -ENOMEM;
	int pos;
	int len;
	char *buf;
	struct ccs_log_entry *new_entry;
	if (!r->domain)
		r->domain = ccs_current_domain();
	if (!ccs_can_save_audit_log(r->domain, is_granted))
		goto out;
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 32;
	va_end(args);
	buf = ccs_init_audit_log(&len, r);
	if (!buf)
		goto out;
	pos = strlen(buf);
	va_start(args, fmt);
	vsnprintf(buf + pos, len - pos - 1, fmt, args);
	va_end(args);
	new_entry = ccs_alloc(sizeof(*new_entry), true);
	if (!new_entry) {
		ccs_free(buf);
		goto out;
	}
	new_entry->log = buf;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_audit_log_lock);
	if (is_granted) {
		list_add_tail(&new_entry->list, &ccs_grant_log);
		ccs_grant_log_count++;
		ccs_update_counter(CCS_UPDATES_COUNTER_GRANT_LOG);
	} else {
		list_add_tail(&new_entry->list, &ccs_reject_log);
		ccs_reject_log_count++;
		ccs_update_counter(CCS_UPDATES_COUNTER_REJECT_LOG);
	}
	spin_unlock(&ccs_audit_log_lock);
	/***** CRITICAL SECTION END *****/
	if (is_granted)
		wake_up(&ccs_grant_log_wait);
	else
		wake_up(&ccs_reject_log_wait);
	error = 0;
 out:
	ccs_update_task_state(r);
	return error;
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
	struct ccs_log_entry *ptr = NULL;
	if (head->read_avail)
		return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf);
		head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_audit_log_lock);
	if (!list_empty(&ccs_grant_log)) {
		ptr = list_entry(ccs_grant_log.next, struct ccs_log_entry,
				 list);
		list_del(&ptr->list);
		ccs_grant_log_count--;
	}
	spin_unlock(&ccs_audit_log_lock);
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
 * @wait: Pointer to "poll_table". May be NULL.
 *
 * Returns POLLIN | POLLRDNORM if ready to read a grant log, 0 otherwise.
 */
unsigned int ccs_poll_grant_log(struct file *file, poll_table *wait)
{
	if (ccs_grant_log_count)
		return POLLIN | POLLRDNORM;
	poll_wait(file, &ccs_grant_log_wait, wait);
	if (ccs_grant_log_count)
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
	struct ccs_log_entry *ptr = NULL;
	if (head->read_avail)
		return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf);
		head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_audit_log_lock);
	if (!list_empty(&ccs_reject_log)) {
		ptr = list_entry(ccs_reject_log.next, struct ccs_log_entry,
				 list);
		list_del(&ptr->list);
		ccs_reject_log_count--;
	}
	spin_unlock(&ccs_audit_log_lock);
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
 * @wait: Pointer to "poll_table". May be NULL.
 *
 * Returns POLLIN | POLLRDNORM if ready to read a reject log, 0 otherwise.
 */
unsigned int ccs_poll_reject_log(struct file *file, poll_table *wait)
{
	if (ccs_reject_log_count)
		return POLLIN | POLLRDNORM;
	poll_wait(file, &ccs_reject_log_wait, wait);
	if (ccs_reject_log_count)
		return POLLIN | POLLRDNORM;
	return 0;
}
#endif
