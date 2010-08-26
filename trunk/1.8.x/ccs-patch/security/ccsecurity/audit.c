/*
 * security/ccsecurity/audit.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include "internal.h"

/**
 * ccs_print_bprm - Print "struct linux_binprm" for auditing.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @dump: Pointer to "struct ccs_page_dump".
 *
 * Returns the contents of @bprm on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_bprm(struct linux_binprm *bprm,
			    struct ccs_page_dump *dump)
{
	static const int ccs_buffer_len = 4096 * 2;
	char *buffer = kzalloc(ccs_buffer_len, CCS_GFP_FLAGS);
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
	len = snprintf(buffer, ccs_buffer_len - 1, "argv[]={ ");
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
	snprintf(buffer, ccs_buffer_len - 1, "argv[]={ ... } envp[]= { ... }");
	return buffer;
}

/**
 * ccs_filetype - Get string representation of file type.
 *
 * @mode: Mode value for stat().
 *
 * Returns file type string.
 */
static inline const char *ccs_filetype(const mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case 0:
		return "file";
	case S_IFDIR:
		return "directory";
	case S_IFLNK:
		return "symlink";
	case S_IFIFO:
		return "fifo";
	case S_IFSOCK:
		return "socket";
	case S_IFBLK:
		return "block";
	case S_IFCHR:
		return "char";
	}
	return "unknown"; /* This should not happen. */
}

/**
 * ccs_print_header - Get header line of audit log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns string representation.
 *
 * This function uses kmalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_header(struct ccs_request_info *r)
{
	struct timeval tv;
	struct ccs_obj_info *obj = r->obj;
	const u32 ccs_flags = current->ccs_flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	const pid_t gpid = (pid_t) ccsecurity_exports.sys_getpid();
#else
	const pid_t gpid = task_pid_nr(current);
#endif
	static const int ccs_buffer_len = 4096;
	char *buffer = kmalloc(ccs_buffer_len, CCS_GFP_FLAGS);
	int pos;
	u8 i;
	if (!buffer)
		return NULL;
	do_gettimeofday(&tv);
	pos = snprintf(buffer, ccs_buffer_len - 1,
		       "#timestamp=%lu profile=%u mode=%s "
		       "(global-pid=%u)", tv.tv_sec, r->profile,
		       ccs_mode[r->mode], gpid);
	if (ccs_profile(r->profile)->preference.audit_task_info) {
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" task={ pid=%u ppid=%u uid=%u gid=%u euid=%u"
				" egid=%u suid=%u sgid=%u fsuid=%u fsgid=%u"
				" type%s=execute_handler }",
				(pid_t) ccsecurity_exports.sys_getpid(),
				(pid_t) ccsecurity_exports.sys_getppid(),
				current_uid(), current_gid(), current_euid(),
				current_egid(), current_suid(), current_sgid(),
				current_fsuid(), current_fsgid(), ccs_flags &
				CCS_TASK_IS_EXECUTE_HANDLER ? "" : "!");
	}
	if (!obj || !ccs_profile(r->profile)->preference.audit_path_info)
		goto no_obj_info;
	if (!obj->validate_done) {
		ccs_get_attributes(obj);
		obj->validate_done = true;
	}
	for (i = 0; i < CCS_MAX_STAT; i++) {
		struct ccs_mini_stat *stat;
		unsigned int dev;
		mode_t mode;
		if (!obj->stat_valid[i])
			continue;
		stat = &obj->stat[i];
		dev = stat->dev;
		mode = stat->mode;
		if (i & 1) {
			pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
					" path%u.parent={ uid=%u gid=%u "
					"ino=%lu perm=0%o }", (i >> 1) + 1,
					stat->uid, stat->gid, stat->ino,
					stat->mode & S_IALLUGO);
			continue;
		}
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" path%u={ uid=%u gid=%u ino=%lu major=%u"
				" minor=%u perm=0%o type=%s", (i >> 1) + 1,
				stat->uid, stat->gid, stat->ino,
				MAJOR(dev), MINOR(dev), mode & S_IALLUGO,
				ccs_filetype(mode));
		if (S_ISCHR(mode) || S_ISBLK(mode)) {
			dev = stat->rdev;
			pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
					" dev_major=%u dev_minor=%u",
					MAJOR(dev), MINOR(dev));
		}
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos, " }");
	}
 no_obj_info:
	if (pos < ccs_buffer_len - 1)
		return buffer;
	kfree(buffer);
	return NULL;
}

/**
 * ccs_init_log - Allocate buffer for audit logs.
 *
 * @len: Required size.
 * @r:   Pointer to "struct ccs_request_info".
 *
 * Returns pointer to allocated memory.
 *
 * The @len is updated to add the header lines' size on success.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_init_log(int *len, struct ccs_request_info *r)
{
	char *buf = NULL;
	char *bprm_info = NULL;
	char *realpath = NULL;
	const char *symlink = NULL;
	const char *header = NULL;
	int pos;
	const char *domainname = ccs_current_domain()->domainname->name;
	header = ccs_print_header(r);
	if (!header)
		return NULL;
	*len += strlen(domainname) + strlen(header) + 10;
	if (r->ee) {
		struct file *file = r->ee->bprm->file;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
		struct path path = { file->f_vfsmnt, file->f_dentry };
		realpath = ccs_realpath_from_path(&path);
#else
		realpath = ccs_realpath_from_path(&file->f_path);
#endif
		bprm_info = ccs_print_bprm(r->ee->bprm, &r->ee->dump);
		if (!realpath || !bprm_info)
			goto out;
		*len += strlen(realpath) + 80 + strlen(bprm_info);
	} else if (r->obj && r->obj->symlink_target) {
		symlink = r->obj->symlink_target->name;
		*len += 18 + strlen(symlink);
	}
	buf = kzalloc(*len, CCS_GFP_FLAGS);
	if (!buf)
		goto out;
	pos = snprintf(buf, (*len) - 1, "%s", header);
	if (realpath) {
		struct linux_binprm *bprm = r->ee->bprm;
		pos += snprintf(buf + pos, (*len) - 1 - pos,
				" exec={ realpath=\"%s\" argc=%d envc=%d %s }",
				realpath, bprm->argc, bprm->envc, bprm_info);
	} else if (symlink)
		pos += snprintf(buf + pos, (*len) - 1 - pos,
				" symlink.target=\"%s\"", symlink);
	snprintf(buf + pos, (*len) - 1 - pos, "\n%s\n", domainname);
 out:
	kfree(realpath);
	kfree(bprm_info);
	kfree(header);
	return buf;
}

/**
 * ccs_update_task_domain - Update task's domain.
 *
 * @r: Pointer to "struct ccs_request_info".
 */
static void ccs_update_task_domain(struct ccs_request_info *r)
{
	static char ccs_transition_buf[CCS_EXEC_TMPSIZE];
	static DEFINE_MUTEX(ccs_transition_mutex);
	const struct ccs_domain_info *domain;
	char *buf;
	const struct ccs_acl_info *acl = r->matched_acl;
	r->matched_acl = NULL;
	if (!acl || !acl->cond || !acl->cond->transit)
		return;
	buf = kmalloc(CCS_EXEC_TMPSIZE, CCS_GFP_FLAGS);
	if (!buf) {
		if (mutex_lock_interruptible(&ccs_transition_mutex))
			goto out;
		buf = ccs_transition_buf;
	}
	domain = ccs_current_domain();
	snprintf(buf, CCS_EXEC_TMPSIZE - 1, "%s %s", domain->domainname->name,
		 acl->cond->transit->name);
	if (!ccs_assign_domain(buf, r->profile, domain->group, true)) {
 out:
		printk(KERN_WARNING
		       "ERROR: Unable to transit to '%s' domain.\n", buf);
		force_sig(SIGKILL, current);
	}
	if (buf != ccs_transition_buf)
		kfree(buf);
	else
		mutex_unlock(&ccs_transition_mutex);
}

#ifndef CONFIG_CCSECURITY_AUDIT

/**
 * ccs_write_log - Write audit log.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @fmt: The printf()'s format string, followed by parameters.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 */
int ccs_write_log(struct ccs_request_info *r, const char *fmt, ...)
{
	ccs_update_task_domain(r);
	return 0;
}

#else

static wait_queue_head_t ccs_log_wait[2] = {
	__WAIT_QUEUE_HEAD_INITIALIZER(ccs_log_wait[0]),
	__WAIT_QUEUE_HEAD_INITIALIZER(ccs_log_wait[1]),
};

static DEFINE_SPINLOCK(ccs_log_lock);

/* Structure for audit log. */
struct ccs_log {
	struct list_head list;
	char *log;
	int size;
};

/* The list for "struct ccs_log". */
static struct list_head ccs_log[2] = {
	LIST_HEAD_INIT(ccs_log[0]), LIST_HEAD_INIT(ccs_log[1]),
};

static unsigned int ccs_log_count[2];

/**
 * ccs_get_audit - Get audit mode.
 *
 * @profile:    Profile number.
 * @index:      Index number of functionality.
 * @cond:       Pointer to "struct ccs_condition". Maybe NULL.
 * @is_granted: True if granted log, false otherwise.
 *
 * Returns mode.
 */
static bool ccs_get_audit(const u8 profile, const u8 index,
			  const struct ccs_acl_info *matched_acl,
			  const bool is_granted)
{
	u8 mode;
	const u8 category = ccs_index2category[index] + CCS_MAX_MAC_INDEX
		+ CCS_MAX_CAPABILITY_INDEX;
	if (!ccs_policy_loaded)
		return false;
	if (is_granted && matched_acl && matched_acl->cond &&
	    matched_acl->cond->audit)
		return matched_acl->cond->audit == 2;
	mode = ccs_profile(profile)->config[index];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = ccs_profile(profile)->config[category];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = ccs_profile(profile)->default_config;
	if (is_granted)
		return mode & CCS_CONFIG_WANT_GRANT_LOG;
	return mode & CCS_CONFIG_WANT_REJECT_LOG;
}

/**
 * ccs_write_log - Write audit log.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @fmt: The printf()'s format string, followed by parameters.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 */
int ccs_write_log(struct ccs_request_info *r, const char *fmt, ...)
{
	va_list args;
	int error = -ENOMEM;
	int pos;
	int len;
	char *buf;
	struct ccs_log *entry;
	bool quota_exceeded = false;
	struct ccs_preference *pref =
		&ccs_profile(ccs_current_domain()->profile)->preference;
	const bool is_granted = r->granted;
	if (is_granted)
		len = pref->audit_max_grant_log;
	else
		len = pref->audit_max_reject_log;
	if (ccs_log_count[is_granted] >= len ||
	    !ccs_get_audit(r->profile, r->type, r->matched_acl, is_granted))
		goto out;
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 32;
	va_end(args);
	buf = ccs_init_log(&len, r);
	if (!buf)
		goto out;
	pos = strlen(buf);
	va_start(args, fmt);
	vsnprintf(buf + pos, len - pos - 1, fmt, args);
	va_end(args);
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (!entry) {
		kfree(buf);
		goto out;
	}
	entry->log = buf;
	/*
	 * The entry->size is used for memory quota checks.
	 * Don't go beyond strlen(entry->log).
	 */
	entry->size = ccs_round2(len) + ccs_round2(sizeof(*entry));
	spin_lock(&ccs_log_lock);
	if (ccs_quota_for_log && ccs_log_memory_size
	    + entry->size >= ccs_quota_for_log) {
		quota_exceeded = true;
	} else {
		ccs_log_memory_size += entry->size;
		list_add_tail(&entry->list, &ccs_log[is_granted]);
		ccs_log_count[is_granted]++;
	}
	spin_unlock(&ccs_log_lock);
	if (quota_exceeded) {
		kfree(buf);
		kfree(entry);
		goto out;
	}
	wake_up(&ccs_log_wait[is_granted]);
	error = 0;
 out:
	ccs_update_task_domain(r);
	return error;
}

/**
 * ccs_read_log - Read an audit log.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 */
void ccs_read_log(struct ccs_io_buffer *head)
{
	struct ccs_log *ptr = NULL;
	const bool is_granted = head->type == CCS_GRANTLOG;
	if (head->r.w_pos)
		return;
	if (head->read_buf) {
		kfree(head->read_buf);
		head->read_buf = NULL;
	}
	spin_lock(&ccs_log_lock);
	if (!list_empty(&ccs_log[is_granted])) {
		ptr = list_entry(ccs_log[is_granted].next, typeof(*ptr), list);
		list_del(&ptr->list);
		ccs_log_count[is_granted]--;
		ccs_log_memory_size -= ptr->size;
	}
	spin_unlock(&ccs_log_lock);
	if (ptr) {
		head->read_buf = ptr->log;
		head->r.w[head->r.w_pos++] = head->read_buf;
		kfree(ptr);
	}
}

/**
 * ccs_poll_log - Wait for an audit log.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read a grant log.
 */
int ccs_poll_log(struct file *file, poll_table *wait)
{
	struct ccs_io_buffer *head = file->private_data;
	const bool is_granted = head->type == CCS_GRANTLOG;
	if (ccs_log_count[is_granted])
		return POLLIN | POLLRDNORM;
	poll_wait(file, &ccs_log_wait[is_granted], wait);
	if (ccs_log_count[is_granted])
		return POLLIN | POLLRDNORM;
	return 0;
}

#endif
