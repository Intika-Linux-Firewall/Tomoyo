/*
 * fs/ccsecurity/load_policy.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/07/03
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define __KERNEL_SYSCALLS__
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#include <linux/mount.h>
static const int ccs_lookup_flags = LOOKUP_FOLLOW;
#else
static const int ccs_lookup_flags = LOOKUP_FOLLOW | LOOKUP_POSITIVE;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#include <linux/unistd.h>
#endif
#include "internal.h"

/* Path to the policy loader. The default is /sbin/ccs-init. */
static const char *ccs_loader;

/**
 * ccs_loader_setup - Specify the policy loader to use.
 *
 * @str: Path to the policy loader.
 *
 * Returns 0.
 */
static int __init ccs_loader_setup(char *str)
{
	ccs_loader = str;
	return 0;
}

__setup("CCS_loader=", ccs_loader_setup);

/**
 * ccs_policy_loader_exists - Check whether /sbin/ccs-init exists.
 *
 * Returns true if /sbin/ccs-init exists, false otherwise.
 */
static bool ccs_policy_loader_exists(void)
{
	/*
	 * Don't activate MAC if the path given by 'CCS_loader=' option doesn't
	 * exist. If the initrd includes /sbin/init but real-root-dev has not
	 * mounted on / yet, activating MAC will block the system since
	 * policies are not loaded yet.
	 * Thus, let do_execve() call this function everytime.
	 */
	struct nameidata nd;
	if (!ccs_loader)
		ccs_loader = "/sbin/ccs-init";
	if (path_lookup(ccs_loader, ccs_lookup_flags, &nd)) {
		printk(KERN_INFO "Not activating Mandatory Access Control now "
		       "since %s doesn't exist.\n", ccs_loader);
		return false;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	path_put(&nd.path);
#else
	path_release(&nd);
#endif
	return true;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
/**
 * ccs_run_loader - Start /sbin/ccs-init .
 *
 * @unused: Not used.
 *
 * Returns PID of /sbin/ccs-init on success, negative value otherwise.
 */
static int ccs_run_loader(void *unused)
{
	char *argv[2];
	char *envp[3];
	printk(KERN_INFO "Calling %s to load policy. Please wait.\n",
	       ccs_loader);
	argv[0] = (char *) ccs_loader;
	argv[1] = NULL;
	envp[0] = "HOME=/";
	envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;
	return exec_usermodehelper(argv[0], argv, envp);
}
#endif

/**
 * ccs_load_policy - Run external policy loader to load policy.
 *
 * @filename: The program about to start.
 *
 * This function checks whether @filename is /sbin/init , and if so
 * invoke /sbin/ccs-init and wait for the termination of /sbin/ccs-init
 * and then continues invocation of /sbin/init.
 * /sbin/ccs-init reads policy files in /etc/ccs/ directory and
 * writes to /proc/ccs/ interfaces.
 *
 * Returns nothing.
 */
void ccs_load_policy(const char *filename)
{
	if (ccs_policy_loaded)
		return;
	/*
	 * Check filename is /sbin/init or /sbin/ccs-start.
	 * /sbin/ccs-start is a dummy filename in case where /sbin/init can't
	 * be passed.
	 * You can create /sbin/ccs-start by "ln -s /bin/true /sbin/ccs-start".
	 */
	if (strcmp(filename, "/sbin/init") &&
	    strcmp(filename, "/sbin/ccs-start"))
		return;
	if (!ccs_policy_loader_exists())
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	{
		char *argv[2];
		char *envp[3];
		printk(KERN_INFO "Calling %s to load policy. Please wait.\n",
		       ccs_loader);
		argv[0] = (char *) ccs_loader;
		argv[1] = NULL;
		envp[0] = "HOME=/";
		envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
		envp[2] = NULL;
		call_usermodehelper(argv[0], argv, envp, 1);
	}
#elif defined(TASK_DEAD)
	{
		/* Copied from kernel/kmod.c */
		struct task_struct *task = current;
		pid_t pid = kernel_thread(ccs_run_loader, NULL, 0);
		sigset_t tmpsig;
		spin_lock_irq(&task->sighand->siglock);
		tmpsig = task->blocked;
		siginitsetinv(&task->blocked,
			      sigmask(SIGKILL) | sigmask(SIGSTOP));
		recalc_sigpending();
		spin_unlock_irq(&current->sighand->siglock);
		if (pid >= 0)
			waitpid(pid, NULL, __WCLONE);
		spin_lock_irq(&task->sighand->siglock);
		task->blocked = tmpsig;
		recalc_sigpending();
		spin_unlock_irq(&task->sighand->siglock);
	}
#else
	{
		/* Copied from kernel/kmod.c */
		struct task_struct *task = current;
		pid_t pid = kernel_thread(ccs_run_loader, NULL, 0);
		sigset_t tmpsig;
		spin_lock_irq(&task->sigmask_lock);
		tmpsig = task->blocked;
		siginitsetinv(&task->blocked,
			      sigmask(SIGKILL) | sigmask(SIGSTOP));
		recalc_sigpending(task);
		spin_unlock_irq(&task->sigmask_lock);
		if (pid >= 0)
			waitpid(pid, NULL, __WCLONE);
		spin_lock_irq(&task->sigmask_lock);
		task->blocked = tmpsig;
		recalc_sigpending(task);
		spin_unlock_irq(&task->sigmask_lock);
	}
#endif
	printk(KERN_INFO "SAKURA: 1.7.0-pre   2009/07/03\n");
	printk(KERN_INFO "TOMOYO: 1.7.0-pre   2009/07/03\n");
	printk(KERN_INFO "Mandatory Access Control activated.\n");
	ccs_policy_loaded = true;
	{ /* Check all profiles currently assigned to domains are defined. */
		struct ccs_domain_info *domain;
		list_for_each_entry_rcu(domain, &ccs_domain_list, list) {
			const u8 profile = domain->profile;
			if (ccs_profile_ptr[profile])
				continue;
			panic("Profile %u (used by '%s') not defined.\n",
			      profile, domain->domainname->name);
		}
	}
}

