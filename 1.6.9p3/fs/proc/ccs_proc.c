/*
 * fs/proc/ccs_proc.c
 *
 * /proc interface for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ccs_proc.h>
#include <linux/ccs_common.h>

#if defined(CONFIG_SAKURA) || defined(CONFIG_TOMOYO)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 23)
#if !defined(RHEL_VERSION) || RHEL_VERSION != 3 || !defined(RHEL_UPDATE) || RHEL_UPDATE != 9
/**
 * PDE - Get "struct proc_dir_entry".
 *
 * @inode: Pointer to "struct inode".
 *
 * Returns pointer to "struct proc_dir_entry"
 *
 * This is for compatibility with older kernels.
 */
static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
	return (struct proc_dir_entry *) inode->u.generic_ip;
}
#endif
#endif

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
	return ccs_close_control(file);
}

/**
 * ccs_poll - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table". May be NULL.
 *
 * Returns POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM if ready to read/write,
 * POLLOUT | POLLWRNORM otherwise.
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
	return ccs_read_control(file, buf, count);
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
	return ccs_write_control(file, buf, count);
}

/* Operations for /proc/ccs/interface. */
static struct file_operations ccs_operations = {
	.open    = ccs_open,
	.release = ccs_release,
	.poll    = ccs_poll,
	.read    = ccs_read,
	.write   = ccs_write,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
/**
 * proc_notify_change - Update inode's attributes and reflect to the dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @iattr:  Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * The 2.4 kernels don't allow chmod()/chown() for files in /proc ,
 * while the 2.6 kernels allow.
 * To permit management of /proc/ccs/ interface by non-root user,
 * I modified to allow chmod()/chown() of /proc/ccs/ interface like 2.6 kernels
 * by adding "struct inode_operations"->setattr hook.
 */
static int proc_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PDE(inode);
	int error;

	error = inode_change_ok(inode, iattr);
	if (error)
		goto out;

	error = inode_setattr(inode, iattr);
	if (error)
		goto out;

	de->uid = inode->i_uid;
	de->gid = inode->i_gid;
	de->mode = inode->i_mode;
 out:
	return error;
}

/* The inode operations for /proc/ccs/ directory. */
static struct inode_operations ccs_dir_inode_operations;

/* The inode operations for files under /proc/ccs/ directory. */
static struct inode_operations ccs_file_inode_operations;
#endif

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
				    struct proc_dir_entry *parent, const u8 key)
{
	struct proc_dir_entry *entry = create_proc_entry(name, mode, parent);
	if (entry) {
		entry->proc_fops = &ccs_operations;
		entry->data = ((u8 *) NULL) + key;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
		if (entry->proc_iops)
			ccs_file_inode_operations = *entry->proc_iops;
		if (!ccs_file_inode_operations.setattr)
			ccs_file_inode_operations.setattr = proc_notify_change;
		entry->proc_iops = &ccs_file_inode_operations;
#endif
	}
}

/**
 * ccs_proc_init - Initialize /proc/ccs/ interface.
 *
 * Returns 0.
 */
static int __init ccs_proc_init(void)
{
	struct proc_dir_entry *ccs_dir = proc_mkdir("ccs", NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	if (ccs_dir->proc_iops)
		ccs_dir_inode_operations = *ccs_dir->proc_iops;
	if (!ccs_dir_inode_operations.setattr)
		ccs_dir_inode_operations.setattr = proc_notify_change;
	ccs_dir->proc_iops = &ccs_dir_inode_operations;
#endif
	ccs_create_entry("query",            0600, ccs_dir, CCS_QUERY);
#ifdef CONFIG_SAKURA
	ccs_create_entry("system_policy",    0600, ccs_dir, CCS_SYSTEMPOLICY);
#endif
#ifdef CONFIG_TOMOYO
	ccs_create_entry("domain_policy",    0600, ccs_dir, CCS_DOMAINPOLICY);
	ccs_create_entry("exception_policy", 0600, ccs_dir,
			 CCS_EXCEPTIONPOLICY);
#ifdef CONFIG_TOMOYO_AUDIT
	ccs_create_entry("grant_log",        0400, ccs_dir, CCS_GRANTLOG);
	ccs_create_entry("reject_log",       0400, ccs_dir, CCS_REJECTLOG);
#endif
#endif
	ccs_create_entry("self_domain",      0400, ccs_dir, CCS_SELFDOMAIN);
	ccs_create_entry(".domain_status",   0600, ccs_dir, CCS_DOMAIN_STATUS);
	ccs_create_entry(".process_status",  0600, ccs_dir, CCS_PROCESS_STATUS);
	ccs_create_entry("meminfo",          0600, ccs_dir, CCS_MEMINFO);
	ccs_create_entry("profile",          0600, ccs_dir, CCS_PROFILE);
	ccs_create_entry("manager",          0600, ccs_dir, CCS_MANAGER);
	ccs_create_entry(".updates_counter", 0400, ccs_dir, CCS_UPDATESCOUNTER);
	ccs_create_entry("version",          0400, ccs_dir, CCS_VERSION);
	ccs_create_entry(".execute_handler", 0666, ccs_dir,
			 CCS_EXECUTE_HANDLER);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
__initcall(ccs_proc_init);
#else
core_initcall(ccs_proc_init);
#endif

#endif
