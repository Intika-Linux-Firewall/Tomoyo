/*
 * security/ccsecurity/proc_if.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
 */

#include "internal.h"

/**
 * ccs_check_task_acl - Check permission for task operation.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true if granted, false otherwise.
 */
static bool ccs_check_task_acl(struct ccs_request_info *r,
			       const struct ccs_acl_info *ptr)
{
	const struct ccs_task_acl *acl = container_of(ptr, typeof(*acl), head);
	return !ccs_pathcmp(r->param.task.domainname, acl->domainname);
}

/**
 * ccs_write_self - write() for /proc/ccs/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname to transit to.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 *
 * If domain transition was permitted but the domain transition failed, this
 * function returns error rather than terminating current thread with SIGKILL.
 */
static ssize_t ccs_write_self(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char *data;
	int error;
	if (!count || count >= CCS_EXEC_TMPSIZE - 10)
		return -ENOMEM;
	data = kzalloc(count + 1, CCS_GFP_FLAGS);
	if (!data)
		return -ENOMEM;
	if (copy_from_user(data, buf, count)) {
		error = -EFAULT;
		goto out;
	}
	ccs_normalize_line(data);
	if (ccs_correct_domain(data)) {
		const int idx = ccs_read_lock();
		struct ccs_path_info name;
		struct ccs_request_info r;
		name.name = data;
		ccs_fill_path_info(&name);
		/* Check "task manual_domain_transition" permission. */
		ccs_init_request_info(&r, CCS_MAC_FILE_EXECUTE);
		r.param_type = CCS_TYPE_MANUAL_TASK_ACL;
		r.param.task.domainname = &name;
		ccs_check_acl(&r, ccs_check_task_acl);
		if (!r.granted)
			error = -EPERM;
		else
			error = ccs_assign_domain(data, true) ? 0 : -ENOENT;
		ccs_read_unlock(idx);
	} else
		error = -EINVAL;
out:
	kfree(data);
	return error ? error : count;
}

/**
 * ccs_read_self - read() for /proc/ccs/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname which current thread belongs to.
 * @count: Size of @buf.
 * @ppos:  Bytes read by now.
 *
 * Returns read size on success, negative value otherwise.
 */
static ssize_t ccs_read_self(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos)
{
	const char *domain = ccs_current_domain()->domainname->name;
	loff_t len = strlen(domain);
	loff_t pos = *ppos;
	if (pos >= len || !count)
		return 0;
	len -= pos;
	if (count < len)
		len = count;
	if (copy_to_user(buf, domain + pos, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

/* Operations for /proc/ccs/self_domain interface. */
static const struct file_operations ccs_self_operations = {
	.write = ccs_write_self,
	.read  = ccs_read_self,
};

/**
 * ccs_open - open() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_open(struct inode *inode, struct file *file)
{
	return ccs_open_control(((u8 *) PDE(inode)->data) - ((u8 *) NULL),
				file);
}

/**
 * ccs_release - close() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_release(struct inode *inode, struct file *file)
{
	return ccs_close_control(file->private_data);
}

/**
 * ccs_poll - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns 0 on success, negative value otherwise.
 */
static unsigned int ccs_poll(struct file *file, poll_table *wait)
{
	return ccs_poll_control(file, wait);
}

/**
 * ccs_read - read() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns bytes read on success, negative value otherwise.
 */
static ssize_t ccs_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	return ccs_read_control(file->private_data, buf, count);
}

/**
 * ccs_write - write() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 */
static ssize_t ccs_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	return ccs_write_control(file->private_data, buf, count);
}

/* Operations for /proc/ccs/ interface. */
static const struct file_operations ccs_operations = {
	.open    = ccs_open,
	.release = ccs_release,
	.poll    = ccs_poll,
	.read    = ccs_read,
	.write   = ccs_write,
};

/**
 * ccs_create_entry - Create interface files under /proc/ccs/ directory.
 *
 * @name:   The name of the interface file.
 * @mode:   The permission of the interface file.
 * @parent: The parent directory.
 * @key:    Type of interface.
 *
 * Returns nothing.
 */
static void __init ccs_create_entry(const char *name, const mode_t mode,
				    struct proc_dir_entry *parent,
				    const u8 key)
{
	struct proc_dir_entry *entry = create_proc_entry(name, mode, parent);
	if (entry) {
		entry->proc_fops = &ccs_operations;
		entry->data = ((u8 *) NULL) + key;
	}
}

/**
 * ccs_proc_init - Initialize /proc/ccs/ interface.
 *
 * Returns 0.
 */
static void __init ccs_proc_init(void)
{
	struct proc_dir_entry *ccs_dir = proc_mkdir("ccs", NULL);
	ccs_create_entry("query",            0600, ccs_dir, CCS_QUERY);
	ccs_create_entry("domain_policy",    0600, ccs_dir, CCS_DOMAINPOLICY);
	ccs_create_entry("exception_policy", 0600, ccs_dir,
			 CCS_EXCEPTIONPOLICY);
	ccs_create_entry("audit",            0400, ccs_dir, CCS_AUDIT);
	ccs_create_entry(".process_status",  0600, ccs_dir,
			 CCS_PROCESS_STATUS);
	ccs_create_entry("stat",             0644, ccs_dir, CCS_STAT);
	ccs_create_entry("profile",          0600, ccs_dir, CCS_PROFILE);
	ccs_create_entry("manager",          0600, ccs_dir, CCS_MANAGER);
	ccs_create_entry("version",          0400, ccs_dir, CCS_VERSION);
	ccs_create_entry(".execute_handler", 0666, ccs_dir,
			 CCS_EXECUTE_HANDLER);
	{
		struct proc_dir_entry *e = create_proc_entry("self_domain",
							     0666, ccs_dir);
		if (e)
			e->proc_fops = &ccs_self_operations;
	}
}

/**
 * ccs_init_module - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init ccs_init_module(void)
{
	if (ccsecurity_ops.disabled)
		return -EINVAL;
	if (init_srcu_struct(&ccs_ss))
		panic("Out of memory.");
	ccs_mm_init();
	ccs_capability_init();
	ccs_file_init();
	ccs_network_init();
	ccs_signal_init();
	ccs_mount_init();
	ccs_policy_io_init();
	ccs_domain_init();
	ccs_proc_init();
	ccs_load_builtin_policy();
	return 0;
}

MODULE_LICENSE("GPL");
module_init(ccs_init_module);
