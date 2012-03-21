/*
 * security/ccsecurity/permission.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2012/03/15
 */

#include "internal.h"

/***** SECTION1: Constants definition *****/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)

/*
 * may_open() receives open flags modified by open_to_namei_flags() until
 * 2.6.32. We stop here in case some distributions backported ACC_MODE changes,
 * for we can't determine whether may_open() receives open flags modified by
 * open_to_namei_flags() or not.
 */
#ifdef ACC_MODE
#error ACC_MODE already defined.
#endif
#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

#if defined(RHEL_MAJOR) && RHEL_MAJOR == 6
/* RHEL6 passes unmodified flags since 2.6.32-71.14.1.el6 . */
#undef ACC_MODE
#define ACC_MODE(x) ("\004\002\006"[(x)&O_ACCMODE])
#endif

#endif

/* String table for special mount operations. */
static const char * const ccs_mounts[CCS_MAX_SPECIAL_MOUNT] = {
	[CCS_MOUNT_BIND]            = "--bind",
	[CCS_MOUNT_MOVE]            = "--move",
	[CCS_MOUNT_REMOUNT]         = "--remount",
	[CCS_MOUNT_MAKE_UNBINDABLE] = "--make-unbindable",
	[CCS_MOUNT_MAKE_PRIVATE]    = "--make-private",
	[CCS_MOUNT_MAKE_SLAVE]      = "--make-slave",
	[CCS_MOUNT_MAKE_SHARED]     = "--make-shared",
};

#ifdef CONFIG_CCSECURITY_CAPABILITY

/*
 * Mapping table from "enum ccs_capability_acl_index" to "enum ccs_mac_index".
 */
static const u8 ccs_c2mac[CCS_MAX_CAPABILITY_INDEX] = {
	[CCS_USE_ROUTE_SOCKET]  = CCS_MAC_USE_NETLINK_SOCKET,
	[CCS_USE_PACKET_SOCKET] = CCS_MAC_USE_PACKET_SOCKET,
	[CCS_SYS_REBOOT]        = CCS_MAC_USE_REBOOT,
	[CCS_SYS_VHANGUP]       = CCS_MAC_USE_VHANGUP,
	[CCS_SYS_SETTIME]       = CCS_MAC_SET_TIME,
	[CCS_SYS_NICE]          = CCS_MAC_SET_PRIORITY,
	[CCS_SYS_SETHOSTNAME]   = CCS_MAC_SET_HOSTNAME,
	[CCS_USE_KERNEL_MODULE] = CCS_MAC_USE_KERNEL_MODULE,
	[CCS_SYS_KEXEC_LOAD]    = CCS_MAC_USE_NEW_KERNEL,
};

#endif

/* Type of condition argument. */
enum ccs_arg_type {
	CCS_ARG_TYPE_NONE,
	CCS_ARG_TYPE_NUMBER,
	CCS_ARG_TYPE_NAME,
	CCS_ARG_TYPE_GROUP,
	CCS_ARG_TYPE_BITOP,
#ifdef CONFIG_CCSECURITY_NETWORK
	CCS_ARG_TYPE_IPV4ADDR,
	CCS_ARG_TYPE_IPV6ADDR,
#endif
} __packed;

/***** SECTION2: Structure definition *****/

/* Structure for holding inet domain socket's address. */
struct ccs_inet_addr_info {
	u16 port;          /* In network byte order. */
	const u8 *address; /* In network byte order. */
	bool is_ipv6;
};

/* Structure for holding unix domain socket's address. */
struct ccs_unix_addr_info {
	u8 *addr; /* This may not be '\0' terminated string. */
	unsigned int addr_len;
};

/* Structure for holding socket address. */
struct ccs_addr_info {
	u8 operation;
	struct ccs_inet_addr_info inet;
	struct ccs_unix_addr_info unix0;
};

/* Structure for holding single condition component. */
struct ccs_cond_arg {
	enum ccs_arg_type type;
	unsigned long value[2];
	const struct ccs_path_info *name;
	const struct ccs_group *group;
	struct in6_addr ip[2];
};

/***** SECTION3: Prototype definition section *****/

static bool ccs_alphabet_char(const char c);
static bool ccs_byte_range(const char *str);
static bool ccs_check_entry(struct ccs_request_info *r,
			    const struct ccs_acl_info *ptr);
static bool ccs_condition(struct ccs_request_info *r,
			  const struct ccs_condition *cond);
static bool ccs_decimal(const char c);
static bool ccs_file_matches_pattern(const char *filename,
				     const char *filename_end,
				     const char *pattern,
				     const char *pattern_end);
static bool ccs_file_matches_pattern2(const char *filename,
				      const char *filename_end,
				      const char *pattern,
				      const char *pattern_end);
static bool ccs_hexadecimal(const char c);
static bool ccs_number_matches_group(const unsigned long min,
				     const unsigned long max,
				     const struct ccs_group *group);
static bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
				     const struct ccs_path_info *pattern);
static bool ccs_path_matches_pattern2(const char *f, const char *p);
static bool ccs_path_matches_group(const struct ccs_path_info *pathname,
				   const struct ccs_group *group);
static int __ccs_chmod_permission(struct dentry *dentry,
				  struct vfsmount *vfsmnt, mode_t mode);
static int __ccs_chown_permission(struct dentry *dentry,
				  struct vfsmount *vfsmnt, uid_t user,
				  gid_t group);
static int __ccs_chroot_permission(struct path *path);
static int __ccs_fcntl_permission(struct file *file, unsigned int cmd,
				  unsigned long arg);
static int __ccs_ioctl_permission(struct file *filp, unsigned int cmd,
				  unsigned long arg);
static int __ccs_link_permission(struct dentry *old_dentry,
				 struct dentry *new_dentry,
				 struct vfsmount *mnt);
static int __ccs_mkdir_permission(struct dentry *dentry, struct vfsmount *mnt,
				  unsigned int mode);
static int __ccs_mknod_permission(struct dentry *dentry, struct vfsmount *mnt,
				  const unsigned int mode, unsigned int dev);
static int __ccs_mount_permission(char *dev_name, struct path *path,
				  const char *type, unsigned long flags,
				  void *data_page);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
static int __ccs_open_exec_permission(struct dentry *dentry,
				      struct vfsmount *mnt);
#endif
static int __ccs_open_permission(struct dentry *dentry, struct vfsmount *mnt,
				 const int flag);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) && defined(CONFIG_SYSCTL_SYSCALL)
static int ccs_sysctl_permission(enum ccs_mac_index type,
				 const struct ccs_path_info *filename);
static int __ccs_parse_table(int __user *name, int nlen, void __user *oldval,
			     void __user *newval, struct ctl_table *table);
#endif
static int __ccs_pivot_root_permission(struct path *old_path,
				       struct path *new_path);
static int __ccs_rename_permission(struct dentry *old_dentry,
				   struct dentry *new_dentry,
				   struct vfsmount *mnt);
static int __ccs_rmdir_permission(struct dentry *dentry, struct vfsmount *mnt);
static int __ccs_search_binary_handler(struct linux_binprm *bprm,
				       struct pt_regs *regs);
static int __ccs_symlink_permission(struct dentry *dentry,
				    struct vfsmount *mnt, const char *from);
static int __ccs_truncate_permission(struct dentry *dentry,
				     struct vfsmount *mnt);
static int __ccs_umount_permission(struct vfsmount *mnt, int flags);
static int __ccs_unlink_permission(struct dentry *dentry,
				   struct vfsmount *mnt);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
static int __ccs_uselib_permission(struct dentry *dentry,
				   struct vfsmount *mnt);
#endif
static int ccs_execute_path(struct linux_binprm *bprm, struct path *path);
static int ccs_execute(struct ccs_request_info *r);
static int ccs_kern_path(const char *pathname, int flags, struct path *path);
static int ccs_mkdev_perm(const u8 operation, struct dentry *dentry,
			  struct vfsmount *mnt, const unsigned int mode,
			  unsigned int dev);
static int ccs_mount_acl(const char *dev_name, struct path *dir,
			 const char *type, unsigned long flags,
			 const char *data);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static int ccs_new_open_permission(struct file *filp);
#endif
static int ccs_path2_perm(const enum ccs_mac_index operation,
			  struct dentry *dentry1, struct vfsmount *mnt1,
			  struct dentry *dentry2, struct vfsmount *mnt2);
static int ccs_path_number_perm(const enum ccs_mac_index type,
				struct dentry *dentry, struct vfsmount *vfsmnt,
				unsigned long number);
static int ccs_path_perm(const enum ccs_mac_index operation,
			 struct dentry *dentry, struct vfsmount *mnt);
static int ccs_start_execve(struct linux_binprm *bprm,
			    struct ccs_request_info **rp);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
static void __ccs_clear_open_mode(void);
static void __ccs_save_open_mode(int mode);
#endif
static void ccs_check_auto_domain_transition(void);
static void ccs_clear_request_info(struct ccs_request_info *r);
static void ccs_finish_execve(int retval, struct ccs_request_info *r);

#ifdef CONFIG_CCSECURITY_ENVIRON
static int ccs_env_perm(struct ccs_request_info *r, const char *name,
			const char *value);
static int ccs_environ(struct ccs_request_info *r);
#endif

#ifdef CONFIG_CCSECURITY_CAPABILITY
static bool __ccs_capable(const u8 operation);
static bool ccs_kernel_service(void);
static int __ccs_socket_create_permission(int family, int type, int protocol);
#endif

#ifdef CONFIG_CCSECURITY_NETWORK
static bool ccs_ip_matches_group(const bool is_ipv6, const u8 *address,
				 const struct ccs_group *group);
static bool ccs_kernel_service(void);
static int __ccs_socket_bind_permission(struct socket *sock,
					struct sockaddr *addr, int addr_len);
static int __ccs_socket_connect_permission(struct socket *sock,
					   struct sockaddr *addr,
					   int addr_len);
static int __ccs_socket_listen_permission(struct socket *sock);
static int __ccs_socket_post_accept_permission(struct socket *sock,
					       struct socket *newsock);
static int __ccs_socket_sendmsg_permission(struct socket *sock,
					   struct msghdr *msg, int size);
static int ccs_check_inet_address(const struct sockaddr *addr,
				  const unsigned int addr_len, const u16 port,
				  struct ccs_addr_info *address);
static int ccs_check_unix_address(struct sockaddr *addr,
				  const unsigned int addr_len,
				  struct ccs_addr_info *address);
static int ccs_inet_entry(const struct ccs_addr_info *address);
static int ccs_unix_entry(const struct ccs_addr_info *address);
static u8 ccs_sock_family(struct sock *sk);
#endif

#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
static int __ccs_socket_post_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb,
						int flags);
#endif

#ifdef CONFIG_CCSECURITY_PTRACE
static int __ccs_ptrace_permission(long request, long pid);
#endif
#ifdef CONFIG_CCSECURITY_SIGNAL
static int __ccs_signal_permission(const int sig);
static int ccs_signal_permission0(const int pid, const int sig);
static int ccs_signal_permission1(pid_t tgid, pid_t pid, int sig);
#endif

#ifdef CONFIG_CCSECURITY_GETATTR
static int __ccs_getattr_permission(struct vfsmount *mnt,
				    struct dentry *dentry);
#endif

#ifdef CONFIG_CCSECURITY_EXECUTE_HANDLER
static int ccs_try_alt_exec(struct ccs_request_info *r);
static void ccs_unescape(unsigned char *dest);
#endif

/***** SECTION4: Standalone functions section *****/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

/**
 * ccs_copy_argv - Wrapper for copy_strings_kernel().
 *
 * @arg:  String to copy.
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns return value of copy_strings_kernel().
 */
static inline int ccs_copy_argv(const char *arg, struct linux_binprm *bprm)
{
	const int ret = copy_strings_kernel(1, &arg, bprm);
	if (ret >= 0)
		bprm->argc++;
	return ret;
}

#else

/**
 * ccs_copy_argv - Wrapper for copy_strings_kernel().
 *
 * @arg:  String to copy.
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns return value of copy_strings_kernel().
 */
static inline int ccs_copy_argv(char *arg, struct linux_binprm *bprm)
{
	const int ret = copy_strings_kernel(1, &arg, bprm);
	if (ret >= 0)
		bprm->argc++;
	return ret;
}

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)

/**
 * get_fs_root - Get reference on root directory.
 *
 * @fs:   Pointer to "struct fs_struct".
 * @root: Pointer to "struct path".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void get_fs_root(struct fs_struct *fs, struct path *root)
{
	read_lock(&fs->lock);
	*root = fs->root;
	path_get(root);
	read_unlock(&fs->lock);
}

#endif

/**
 * ccs_put_filesystem - Wrapper for put_filesystem().
 *
 * @fstype: Pointer to "struct file_system_type".
 *
 * Returns nothing.
 *
 * Since put_filesystem() is not exported, I embed put_filesystem() here.
 */
static inline void ccs_put_filesystem(struct file_system_type *fstype)
{
	module_put(fstype->owner);
}

/***** SECTION5: Variables definition section *****/

/* The initial domain. */
struct ccs_domain_info ccs_kernel_domain;

/* The list for "struct ccs_domain_info". */
LIST_HEAD(ccs_domain_list);

/* The list for ACL policy. */
struct list_head ccs_acl_list[CCS_MAX_MAC_INDEX];

/* NULL value. */
struct ccs_path_info ccs_null_name;

/***** SECTION6: Dependent functions section *****/

/**
 * ccs_path_matches_group - Check whether the given pathname matches members of the given pathname group.
 *
 * @pathname: The name of pathname.
 * @group:    Pointer to "struct ccs_string_group".
 *
 * Returns true if @pathname matches pathnames in @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_path_matches_group(const struct ccs_path_info *pathname,
				   const struct ccs_group *group)
{
	struct ccs_string_group *member;
	list_for_each_entry_srcu(member, &group->member_list, head.list,
				 &ccs_ss) {
		if (member->head.is_deleted)
			continue;
		if (!ccs_path_matches_pattern(pathname, member->member_name))
			continue;
		return true;
	}
	return false;
}

/**
 * ccs_number_matches_group - Check whether the given number matches members of the given number group.
 *
 * @min:   Min number.
 * @max:   Max number.
 * @group: Pointer to "struct ccs_number_group".
 *
 * Returns true if @min and @max partially overlaps @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_number_matches_group(const unsigned long min,
				     const unsigned long max,
				     const struct ccs_group *group)
{
	struct ccs_number_group *member;
	bool matched = false;
	list_for_each_entry_srcu(member, &group->member_list, head.list,
				 &ccs_ss) {
		if (member->head.is_deleted)
			continue;
		if (min > member->value[1] || max < member->value[0])
			continue;
		matched = true;
		break;
	}
	return matched;
}

/**
 * ccs_check_entry - Do permission check.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true on match, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_check_entry(struct ccs_request_info *r,
			    const struct ccs_acl_info *ptr)
{
	return !ptr->is_deleted && ccs_condition(r, ptr->cond);
}

/**
 * ccs_check_acl_list - Do permission check.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_acl_list(struct ccs_request_info *r)
{
	struct ccs_acl_info *ptr;
	int error = 0;
	struct list_head * const list = &ccs_acl_list[r->type];
	r->matched_acl = NULL;
	list_for_each_entry_srcu(ptr, list, list, &ccs_ss) {
		struct ccs_acl_info *ptr2;
retry:
		if (!ccs_check_entry(r, ptr)) {
			if (unlikely(r->failed_by_oom))
				goto oom;
			continue;
		}
		r->matched_acl = ptr;
		r->audit = ptr->audit;
		r->result = CCS_MATCHING_UNMATCHED;
		list_for_each_entry_srcu(ptr2, &ptr->acl_info_list, list,
					 &ccs_ss) {
			r->transition_candidate = NULL;
			r->handler_path_candidate = NULL;
			if (!ccs_check_entry(r, ptr2)) {
				if (unlikely(r->failed_by_oom))
					goto oom;
				continue;
			}
			if (ptr2->is_deny) {
				r->result = CCS_MATCHING_DENIED;
				break;
			}
			r->result = CCS_MATCHING_ALLOWED;
			/* Set the first matching domain transition entry. */
			if (r->transition_candidate && !r->transition)
				r->transition = r->transition_candidate;
			/* Set the first matching execute handler entry. */
			if (r->handler_path_candidate && !r->handler_path)
				r->handler_path = r->handler_path_candidate;
			break;
		}
		error = ccs_audit_log(r);
		/* Ignore out of memory during audit. */
		r->failed_by_oom = false;
		if (!error)
			continue;
		if (error == CCS_RETRY_REQUEST)
			goto retry;
		break;
	}
	return error;
oom:
	/*
	 * If conditions could not be checked due to out of memory,
	 * reject the request with -ENOMEM, for we don't know whether
	 * there was a possibility of matching "deny" lines or not.
	 */
	{
		static struct timeval ccs_last_tv;
		struct timeval tv;
		do_gettimeofday(&tv);
		if (tv.tv_sec != ccs_last_tv.tv_sec) {
			ccs_last_tv = tv;
			printk(KERN_INFO "CCSecurity: Rejecting access "
			       "request due to out of memory.\n");
		}
	}
	return -ENOMEM;
}

/**
 * ccs_check_acl - Do permission check.
 *
 * @r:     Pointer to "struct ccs_request_info".
 * @clear: True to cleanup @r before return, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_acl(struct ccs_request_info *r, const bool clear)
{
	int error;
	const int idx = ccs_read_lock();
	error = ccs_check_acl_list(r);
	ccs_read_unlock(idx);
	if (clear)
		ccs_clear_request_info(r);
	return error;
}

/**
 * ccs_execute - Check permission for "execute".
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_execute(struct ccs_request_info *r)
{
	int retval;

	/* Get symlink's dentry/vfsmount. */
	retval = ccs_execute_path(r->bprm, &r->obj.path[1]);
	if (retval < 0)
		return retval;
	ccs_populate_patharg(r, false);
	if (!r->param.s[1])
		return -ENOMEM;

	/* Check execute permission. */
	r->type = CCS_MAC_EXECUTE;
	retval = ccs_check_acl(r, false);
	if (retval < 0)
		return retval;
#ifdef CONFIG_CCSECURITY_EXECUTE_HANDLER
	/*
	 * Switch to execute handler if matched. To avoid infinite execute
	 * handler loop, don't use execute handler if the current process is
	 * marked as execute handler.
	 */
	if (r->handler_path && r->handler_path != &ccs_null_name &&
	    !(ccs_current_flags() & CCS_TASK_IS_EXECUTE_HANDLER)) {
		retval = ccs_try_alt_exec(r);
		if (retval < 0)
			return retval;
	}
#endif
	/*
	 * Tell GC that I started execve().
	 * Also, tell open_exec() to check read permission.
	 */
	ccs_current_security()->ccs_flags |= CCS_TASK_IS_IN_EXECVE;
	if (!r->transition || r->transition == &ccs_null_name)
		/* Keep current domain. */
		return 0;
	/*
	 * Make ccs_current_security()->ccs_flags visible to GC before changing
	 * ccs_current_security()->ccs_domain_info.
	 */
	smp_wmb();
	/*
	 * Transit to the specified domain.
	 * It will be reverted if execve() failed.
	 */
	if (ccs_transit_domain(r->transition->name))
		return 0;
	printk(KERN_WARNING "ERROR: Domain '%s' not ready.\n",
	       r->transition->name);
	return -ENOMEM;
}

#ifdef CONFIG_CCSECURITY_EXECUTE_HANDLER

/**
 * ccs_unescape - Unescape escaped string.
 *
 * @dest: String to unescape.
 *
 * Returns nothing.
 */
static void ccs_unescape(unsigned char *dest)
{
	unsigned char *src = dest;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	while (1) {
		c = *src++;
		if (!c)
			break;
		if (c != '\\') {
			*dest++ = c;
			continue;
		}
		c = *src++;
		if (c < '0' || c > '3')
			break;
		d = *src++;
		if (d < '0' || d > '7')
			break;
		e = *src++;
		if (e < '0' || e > '7')
			break;
		*dest++ = ((c - '0') << 6) + ((d - '0') << 3) + (e - '0');
	}
	*dest = '\0';
}

/**
 * ccs_try_alt_exec - Try to start execute handler.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_try_alt_exec(struct ccs_request_info *r)
{
	/*
	 * Contents of modified bprm.
	 * The envp[] in original bprm is moved to argv[] so that
	 * the alternatively executed program won't be affected by
	 * some dangerous environment variables like LD_PRELOAD.
	 *
	 * modified bprm->argc
	 *    = original bprm->argc + original bprm->envc + 7
	 * modified bprm->envc
	 *    = 0
	 *
	 * modified bprm->argv[0]
	 *    = the program's name specified by *_execute_handler
	 * modified bprm->argv[1]
	 *    = ccs_current_domain()->domainname->name
	 * modified bprm->argv[2]
	 *    = the current process's name
	 * modified bprm->argv[3]
	 *    = the current process's information (e.g. uid/gid).
	 * modified bprm->argv[4]
	 *    = original bprm->filename
	 * modified bprm->argv[5]
	 *    = original bprm->argc in string expression
	 * modified bprm->argv[6]
	 *    = original bprm->envc in string expression
	 * modified bprm->argv[7]
	 *    = original bprm->argv[0]
	 *  ...
	 * modified bprm->argv[bprm->argc + 6]
	 *     = original bprm->argv[bprm->argc - 1]
	 * modified bprm->argv[bprm->argc + 7]
	 *     = original bprm->envp[0]
	 *  ...
	 * modified bprm->argv[bprm->envc + bprm->argc + 6]
	 *     = original bprm->envp[bprm->envc - 1]
	 */
	struct linux_binprm *bprm = r->bprm;
	struct file *filp;
	int retval;
	const int original_argc = bprm->argc;
	const int original_envc = bprm->envc;

	ccs_clear_request_info(r);

	/* Close the requested program's dentry. */
	r->obj.path[0].dentry = NULL;
	r->obj.path[0].mnt = NULL;
	r->obj.validate_done = false;
	allow_write_access(bprm->file);
	fput(bprm->file);
	bprm->file = NULL;

	/* Invalidate page dump cache. */
	r->dump.page = NULL;

	/* Move envp[] to argv[] */
	bprm->argc += bprm->envc;
	bprm->envc = 0;

	/* Set argv[6] */
	{
		snprintf(r->tmp, CCS_EXEC_TMPSIZE - 1, "%d", original_envc);
		retval = ccs_copy_argv(r->tmp, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[5] */
	{
		snprintf(r->tmp, CCS_EXEC_TMPSIZE - 1, "%d", original_argc);
		retval = ccs_copy_argv(r->tmp, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[4] */
	{
		retval = ccs_copy_argv(bprm->filename, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[3] */
	{
		snprintf(r->tmp, CCS_EXEC_TMPSIZE - 1,
			 "pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d "
			 "sgid=%d fsuid=%d fsgid=%d", ccs_sys_getpid(),
			 current_uid(), current_gid(), current_euid(),
			 current_egid(), current_suid(), current_sgid(),
			 current_fsuid(), current_fsgid());
		retval = ccs_copy_argv(r->tmp, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[2] */
	{
		char *exe = ccs_get_exe();
		if (exe) {
			retval = ccs_copy_argv(exe, bprm);
			kfree(exe);
		} else {
			retval = -ENOMEM;
		}
		if (retval < 0)
			goto out;
	}

	/* Set argv[1] */
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
		retval = ccs_copy_argv(ccs_current_domain()->domainname->name,
				       bprm);
#else
		snprintf(r->tmp, CCS_EXEC_TMPSIZE - 1, "%s",
			 ccs_current_domain()->domainname->name);
		retval = ccs_copy_argv(r->tmp, bprm);
#endif
		if (retval < 0)
			goto out;
	}

	/* Set argv[0] */
	{
		struct path root;
		char *cp;
		int root_len;
		int handler_len;
		get_fs_root(current->fs, &root);
		cp = ccs_realpath(&root);
		path_put(&root);
		if (!cp) {
			retval = -ENOMEM;
			goto out;
		}
		root_len = strlen(cp);
		retval = strncmp(r->handler_path->name, cp, root_len);
		root_len--;
		kfree(cp);
		if (retval) {
			retval = -ENOENT;
			goto out;
		}
		handler_len = r->handler_path->total_len + 1;
		/* r->handler is released by ccs_finish_execve(). */
		r->handler = kmalloc(handler_len, GFP_NOFS);
		if (!r->handler) {
			retval = -ENOMEM;
			goto out;
		}
		/* Adjust root directory for open_exec(). */
		memmove(r->handler, r->handler_path->name + root_len,
			handler_len - root_len);
		ccs_unescape(r->handler);
		retval = -ENOENT;
		if (*r->handler != '/')
			goto out;
		retval = ccs_copy_argv(r->handler, bprm);
		if (retval < 0)
			goto out;
	}

	/*
	 * OK, now restart the process with execute handler program's dentry.
	 */
	filp = open_exec(r->handler);
	if (IS_ERR(filp)) {
		retval = PTR_ERR(filp);
		goto out;
	}
	r->obj.path[0].dentry = filp->f_dentry;
	r->obj.path[0].mnt = filp->f_vfsmnt;
	bprm->file = filp;
	bprm->filename = r->handler;
	bprm->interp = bprm->filename;
	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;
	ccs_populate_patharg(r, true);
	if (!r->param.s[0])
		retval = -ENOMEM;
	else if (ccs_pathcmp(r->param.s[0], r->handler_path)) {
		/* Failed to verify execute handler. */
		static u8 counter = 20;
		if (counter) {
			counter--;
			printk(KERN_WARNING "Failed to verify: %s\n",
			       r->handler_path->name);
		}
		retval = -EINVAL;
	}
out:
	return retval;
}

#endif

/**
 * ccs_dump_page - Dump a page to buffer.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @pos:  Location to dump.
 * @dump: Poiner to "struct ccs_page_dump".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		   struct ccs_page_dump *dump)
{
	struct page *page;
	/* dump->data is released by ccs_start_execve(). */
	if (!dump->data) {
		dump->data = kzalloc(PAGE_SIZE, GFP_NOFS);
		if (!dump->data)
			return false;
	}
	/* Same with get_arg_page(bprm, pos, 0) in fs/exec.c */
#ifdef CONFIG_MMU
	if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0)
		return false;
#else
	page = bprm->page[pos / PAGE_SIZE];
#endif
	if (page != dump->page) {
		const unsigned int offset = pos % PAGE_SIZE;
		/*
		 * Maybe kmap()/kunmap() should be used here.
		 * But remove_arg_zero() uses kmap_atomic()/kunmap_atomic().
		 * So do I.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
		char *kaddr = kmap_atomic(page);
#else
		char *kaddr = kmap_atomic(page, KM_USER0);
#endif
		dump->page = page;
		memcpy(dump->data + offset, kaddr + offset,
		       PAGE_SIZE - offset);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
		kunmap_atomic(kaddr);
#else
		kunmap_atomic(kaddr, KM_USER0);
#endif
	}
	/* Same with put_arg_page(page) in fs/exec.c */
#ifdef CONFIG_MMU
	put_page(page);
#endif
	return true;
}

/**
 * ccs_start_execve - Prepare for execve() operation.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @rp:   Pointer to "struct ccs_request_info *".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_start_execve(struct linux_binprm *bprm,
			    struct ccs_request_info **rp)
{
	int retval;
	struct ccs_security *task = ccs_current_security();
	struct ccs_request_info *r;
	int idx;
	*rp = NULL;
	r = kzalloc(sizeof(*r), GFP_NOFS);
	if (!r)
		return -ENOMEM;
	r->tmp = kzalloc(CCS_EXEC_TMPSIZE, GFP_NOFS);
	if (!r->tmp) {
		kfree(r);
		return -ENOMEM;
	}
	idx = ccs_read_lock();
	/* r->dump->data is allocated by ccs_dump_page(). */
	r->previous_domain = task->ccs_domain_info;
	/* Clear manager flag. */
	task->ccs_flags &= ~CCS_TASK_IS_MANAGER;
	*rp = r;
	r->bprm = bprm;
	r->obj.path[0].dentry = bprm->file->f_dentry;
	r->obj.path[0].mnt = bprm->file->f_vfsmnt;
	retval = ccs_execute(r);
#ifdef CONFIG_CCSECURITY_ENVIRON
	if (!retval && bprm->envc)
		retval = ccs_environ(r);
#endif
	ccs_clear_request_info(r);
	/* Drop refcount obtained by ccs_execute_path(). */
	if (r->obj.path[1].dentry) {
		path_put(&r->obj.path[1]);
		r->obj.path[1].dentry = NULL;
	}
	ccs_read_unlock(idx);
	kfree(r->tmp);
	r->tmp = NULL;
	kfree(r->dump.data);
	r->dump.data = NULL;
	return retval;
}

/**
 * ccs_finish_execve - Clean up execve() operation.
 *
 * @retval: Return code of an execve() operation.
 * @r:      Pointer to "struct ccs_request_info".
 *
 * Returns nothing.
 */
static void ccs_finish_execve(int retval, struct ccs_request_info *r)
{
	struct ccs_security *task;
	if (!r)
		return;
	task = ccs_current_security();
	if (retval < 0) {
		task->ccs_domain_info = r->previous_domain;
		/*
		 * Make task->ccs_domain_info visible to GC before changing
		 * task->ccs_flags.
		 */
		smp_wmb();
	} else {
		/* Mark the current process as execute handler. */
		if (r->handler)
			task->ccs_flags |= CCS_TASK_IS_EXECUTE_HANDLER;
		/* Mark the current process as normal process. */
		else
			task->ccs_flags &= ~CCS_TASK_IS_EXECUTE_HANDLER;
	}
	/* Tell GC that I finished execve(). */
	task->ccs_flags &= ~CCS_TASK_IS_IN_EXECVE;
	ccs_clear_request_info(r);
	kfree(r->handler);
	kfree(r);
}

/**
 * __ccs_search_binary_handler - Main routine for do_execve().
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @regs: Pointer to "struct pt_regs".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Performs permission checks for do_execve() and domain transition.
 * Domain transition by "struct ccs_acl_info" will be reverted
 * if do_execve() failed.
 * Garbage collector does not remove "struct ccs_domain_info" from
 * ccs_domain_list nor kfree("struct ccs_domain_info") if the current thread is
 * marked as CCS_TASK_IS_IN_EXECVE.
 */
static int __ccs_search_binary_handler(struct linux_binprm *bprm,
				       struct pt_regs *regs)
{
	struct ccs_request_info *r;
	int retval;
#ifndef CONFIG_CCSECURITY_OMIT_USERSPACE_LOADER
	if (!ccs_policy_loaded)
		ccsecurity_exports.load_policy(bprm->filename);
#endif
	retval = ccs_start_execve(bprm, &r);
	if (!retval)
		retval = search_binary_handler(bprm, regs);
	ccs_finish_execve(retval, r);
	return retval;
}

/**
 * ccs_permission_init - Register permission check hooks.
 *
 * Returns nothing.
 */
void __init ccs_permission_init(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
	ccsecurity_ops.save_open_mode = __ccs_save_open_mode;
	ccsecurity_ops.clear_open_mode = __ccs_clear_open_mode;
	ccsecurity_ops.open_permission = __ccs_open_permission;
#else
	ccsecurity_ops.open_permission = ccs_new_open_permission;
#endif
	ccsecurity_ops.fcntl_permission = __ccs_fcntl_permission;
	ccsecurity_ops.ioctl_permission = __ccs_ioctl_permission;
	ccsecurity_ops.chmod_permission = __ccs_chmod_permission;
	ccsecurity_ops.chown_permission = __ccs_chown_permission;
#ifdef CONFIG_CCSECURITY_GETATTR
	ccsecurity_ops.getattr_permission = __ccs_getattr_permission;
#endif
	ccsecurity_ops.pivot_root_permission = __ccs_pivot_root_permission;
	ccsecurity_ops.chroot_permission = __ccs_chroot_permission;
	ccsecurity_ops.umount_permission = __ccs_umount_permission;
	ccsecurity_ops.mknod_permission = __ccs_mknod_permission;
	ccsecurity_ops.mkdir_permission = __ccs_mkdir_permission;
	ccsecurity_ops.rmdir_permission = __ccs_rmdir_permission;
	ccsecurity_ops.unlink_permission = __ccs_unlink_permission;
	ccsecurity_ops.symlink_permission = __ccs_symlink_permission;
	ccsecurity_ops.truncate_permission = __ccs_truncate_permission;
	ccsecurity_ops.rename_permission = __ccs_rename_permission;
	ccsecurity_ops.link_permission = __ccs_link_permission;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	ccsecurity_ops.open_exec_permission = __ccs_open_exec_permission;
	ccsecurity_ops.uselib_permission = __ccs_uselib_permission;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) && defined(CONFIG_SYSCTL_SYSCALL)
	ccsecurity_ops.parse_table = __ccs_parse_table;
#endif
	ccsecurity_ops.mount_permission = __ccs_mount_permission;
#ifdef CONFIG_CCSECURITY_CAPABILITY
	ccsecurity_ops.capable = __ccs_capable;
	ccsecurity_ops.socket_create_permission =
		__ccs_socket_create_permission;
#endif
#ifdef CONFIG_CCSECURITY_NETWORK
	ccsecurity_ops.socket_listen_permission =
		__ccs_socket_listen_permission;
	ccsecurity_ops.socket_connect_permission =
		__ccs_socket_connect_permission;
	ccsecurity_ops.socket_bind_permission = __ccs_socket_bind_permission;
	ccsecurity_ops.socket_post_accept_permission =
		__ccs_socket_post_accept_permission;
	ccsecurity_ops.socket_sendmsg_permission =
		__ccs_socket_sendmsg_permission;
#endif
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	ccsecurity_ops.socket_post_recvmsg_permission =
		__ccs_socket_post_recvmsg_permission;
#endif
#ifdef CONFIG_CCSECURITY_PTRACE
	ccsecurity_ops.ptrace_permission = __ccs_ptrace_permission;
#endif
#ifdef CONFIG_CCSECURITY_SIGNAL
	ccsecurity_ops.kill_permission = ccs_signal_permission0;
	ccsecurity_ops.tgkill_permission = ccs_signal_permission1;
	ccsecurity_ops.tkill_permission = ccs_signal_permission0;
	ccsecurity_ops.sigqueue_permission = ccs_signal_permission0;
	ccsecurity_ops.tgsigqueue_permission = ccs_signal_permission1;
#endif
	ccsecurity_ops.search_binary_handler = __ccs_search_binary_handler;
}

/**
 * ccs_kern_path - Wrapper for kern_path().
 *
 * @pathname: Pathname to resolve. Maybe NULL.
 * @flags:    Lookup flags.
 * @path:     Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_kern_path(const char *pathname, int flags, struct path *path)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	if (!pathname || kern_path(pathname, flags, path))
		return -ENOENT;
#else
	struct nameidata nd;
	if (!pathname || path_lookup(pathname, flags, &nd))
		return -ENOENT;
	*path = nd.path;
#endif
	return 0;
}

/**
 * ccs_execute_path - Get dentry/vfsmount of a program.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_execute_path(struct linux_binprm *bprm, struct path *path)
{
	/*
	 * Follow symlinks if the requested pathname is on procfs, for
	 * /proc/\$/exe is meaningless.
	 */
	const unsigned int follow =
		(bprm->file->f_dentry->d_sb->s_magic == PROC_SUPER_MAGIC) ?
		LOOKUP_FOLLOW : 0;
	if (ccs_kern_path(bprm->filename, follow, path))
		return -ENOENT;
	return 0;
}

/**
 * ccs_mount_acl - Check permission for mount() operation.
 *
 * @dev_name: Name of device file or mount source. Maybe NULL.
 * @dir:      Pointer to "struct path".
 * @type:     Name of filesystem type. Maybe NULL.
 * @flags:    Mount options.
 * @data:     Mount options not in @flags. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_mount_acl(const char *dev_name, struct path *dir,
			 const char *type, unsigned long flags,
			 const char *data)
{
	struct ccs_request_info r = { };
	struct ccs_path_info rtype = { };
	struct ccs_path_info rdata = { };
	bool check_dev = false;
	bool check_data = false;
	int error;

	/* Compare fstype in order to determine type of dev_name argument. */
	if (type == ccs_mounts[CCS_MOUNT_REMOUNT]) {
		/* do_remount() case. */
		if (data && !(dir->mnt->mnt_sb->s_type->fs_flags &
			      FS_BINARY_MOUNTDATA))
			check_data = true;
	} else if (type == ccs_mounts[CCS_MOUNT_BIND]) {
		/* do_loopback() case. */
		check_dev = true;
	} else if (type == ccs_mounts[CCS_MOUNT_MAKE_UNBINDABLE] ||
		   type == ccs_mounts[CCS_MOUNT_MAKE_PRIVATE] ||
		   type == ccs_mounts[CCS_MOUNT_MAKE_SLAVE] ||
		   type == ccs_mounts[CCS_MOUNT_MAKE_SHARED]) {
		/* do_change_type() case. */
	} else if (type == ccs_mounts[CCS_MOUNT_MOVE]) {
		/* do_move_mount() case. */
		check_dev = true;
	} else {
		/* do_new_mount() case. */
		struct file_system_type *fstype;
		if (!type)
			return -EINVAL;
		fstype = get_fs_type(type);
		if (!fstype)
			return -ENODEV;
		if (fstype->fs_flags & FS_REQUIRES_DEV)
			check_dev = true;
		if (data && !(fstype->fs_flags & FS_BINARY_MOUNTDATA))
			check_data = true;
		ccs_put_filesystem(fstype);
	}
	/* Start filling arguments. */
	r.type = CCS_MAC_MOUNT;
	/* Remember mount options. */
	r.param.i[0] = flags;
	/*
	 * Remember mount point.
	 * r.param.s[1] is calculated from r.obj.path[1] as needed.
	 */
	r.obj.path[1] = *dir;
	/* Remember fstype. */
	rtype.name = ccs_encode(type);
	if (!rtype.name)
		return -ENOMEM;
	ccs_fill_path_info(&rtype);
	r.param.s[2] = &rtype;
	if (check_data) {
		/* Remember data argument. */
		rdata.name = ccs_encode(data);
		if (!rdata.name) {
			error = -ENOMEM;
			goto out;
		}
		ccs_fill_path_info(&rdata);
		r.param.s[3] = &rdata;
	}
	if (check_dev) {
		/*
		 * Remember device file or mount source.
		 * r.param.s[0] is calculated from r.obj.path[0] as needed.
		 */
		if (ccs_kern_path(dev_name, LOOKUP_FOLLOW, &r.obj.path[0])) {
			error = -ENOENT;
			goto out;
		}
	}
	error = ccs_check_acl(&r, false);
	/* Drop refcount obtained by ccs_kern_path(). */
	if (check_dev)
		path_put(&r.obj.path[0]);
out:
	kfree(rtype.name);
	kfree(rdata.name);
	ccs_clear_request_info(&r);
	return error;
}

/**
 * __ccs_mount_permission - Check permission for mount() operation.
 *
 * @dev_name:  Name of device file. Maybe NULL.
 * @path:      Pointer to "struct path".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Mount options not in @flags. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_mount_permission(char *dev_name, struct path *path,
				  const char *type, unsigned long flags,
				  void *data_page)
{
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;
	if (flags & MS_REMOUNT) {
		type = ccs_mounts[CCS_MOUNT_REMOUNT];
		flags &= ~MS_REMOUNT;
	} else if (flags & MS_BIND) {
		type = ccs_mounts[CCS_MOUNT_BIND];
		flags &= ~MS_BIND;
	} else if (flags & MS_SHARED) {
		if (flags & (MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
			return -EINVAL;
		type = ccs_mounts[CCS_MOUNT_MAKE_SHARED];
		flags &= ~MS_SHARED;
	} else if (flags & MS_PRIVATE) {
		if (flags & (MS_SHARED | MS_SLAVE | MS_UNBINDABLE))
			return -EINVAL;
		type = ccs_mounts[CCS_MOUNT_MAKE_PRIVATE];
		flags &= ~MS_PRIVATE;
	} else if (flags & MS_SLAVE) {
		if (flags & (MS_SHARED | MS_PRIVATE | MS_UNBINDABLE))
			return -EINVAL;
		type = ccs_mounts[CCS_MOUNT_MAKE_SLAVE];
		flags &= ~MS_SLAVE;
	} else if (flags & MS_UNBINDABLE) {
		if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE))
			return -EINVAL;
		type = ccs_mounts[CCS_MOUNT_MAKE_UNBINDABLE];
		flags &= ~MS_UNBINDABLE;
	} else if (flags & MS_MOVE) {
		type = ccs_mounts[CCS_MOUNT_MOVE];
		flags &= ~MS_MOVE;
	}
	/*
	 * do_mount() terminates data_page with '\0' if data_page != NULL.
	 * Therefore, it is safe to pass data_page argument to ccs_mount_acl()
	 * as "const char *" rather than "void *".
	 */
	ccs_check_auto_domain_transition();
	return ccs_mount_acl(dev_name, path, type, flags, data_page);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)

/**
 * __ccs_save_open_mode - Remember original flags passed to sys_open().
 *
 * @mode: Flags passed to sys_open().
 *
 * Returns nothing.
 *
 * TOMOYO does not check "file write" if open(path, O_TRUNC | O_RDONLY) was
 * requested because write() is not permitted. Instead, TOMOYO checks
 * "file truncate" if O_TRUNC is passed.
 *
 * TOMOYO does not check "file read" and "file write" if open(path, 3) was
 * requested because read()/write() are not permitted. Instead, TOMOYO checks
 * "file ioctl" when ioctl() is requested.
 */
static void __ccs_save_open_mode(int mode)
{
	if ((mode & 3) == 3)
		ccs_current_security()->ccs_flags |= CCS_OPEN_FOR_IOCTL_ONLY;
}

/**
 * __ccs_clear_open_mode - Forget original flags passed to sys_open().
 *
 * Returns nothing.
 */
static void __ccs_clear_open_mode(void)
{
	ccs_current_security()->ccs_flags &= ~CCS_OPEN_FOR_IOCTL_ONLY;
}

#endif

/**
 * __ccs_open_permission - Check permission for "read" and "write".
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @flag:   Flags for open().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_open_permission(struct dentry *dentry, struct vfsmount *mnt,
				 const int flag)
{
	struct ccs_request_info r = { };
	const u32 ccs_flags = ccs_current_flags();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	const u8 acc_mode = (flag & 3) == 3 ? 0 : ACC_MODE(flag);
#else
	const u8 acc_mode = (ccs_flags & CCS_OPEN_FOR_IOCTL_ONLY) ? 0 :
		ACC_MODE(flag);
#endif
	int error = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	if (current->in_execve && !(ccs_flags & CCS_TASK_IS_IN_EXECVE))
		return 0;
#endif
#ifndef CONFIG_CCSECURITY_GETATTR
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		return 0;
#endif
	r.obj.path[0].dentry = dentry;
	r.obj.path[0].mnt = mnt;
	if (!(ccs_flags & CCS_TASK_IS_IN_EXECVE))
		ccs_check_auto_domain_transition();
	if (acc_mode & MAY_READ) {
		r.type = CCS_MAC_READ;
		error = ccs_check_acl(&r, false);
	}
	if (!error && (acc_mode & MAY_WRITE)) {
		r.type = (flag & O_APPEND) ? CCS_MAC_APPEND :
			CCS_MAC_WRITE;
		error = ccs_check_acl(&r, false);
	}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
	if (!error && (flag & O_TRUNC)) {
		r.type = CCS_MAC_TRUNCATE;
		error = ccs_check_acl(&r, false);
	}
#endif
	ccs_clear_request_info(&r);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)

/**
 * ccs_new_open_permission - Check permission for "read" and "write".
 *
 * @filp: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_new_open_permission(struct file *filp)
{
	return __ccs_open_permission(filp->f_path.dentry, filp->f_path.mnt,
				     filp->f_flags);
}

#endif

/**
 * ccs_path_perm - Check permission for "unlink", "rmdir", "truncate", "append", "getattr" and "chroot".
 *
 * @operation: One of values in "enum ccs_mac_index".
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_perm(const enum ccs_mac_index operation,
			 struct dentry *dentry, struct vfsmount *mnt)
{
	struct ccs_request_info r = { };
	ccs_check_auto_domain_transition();
	r.type = operation;
	r.obj.path[0].dentry = dentry;
	r.obj.path[0].mnt = mnt;
	return ccs_check_acl(&r, true);
}

/**
 * ccs_mkdev_perm - Check permission for "mkblock" and "mkchar".
 *
 * @operation: Type of operation. (CCS_MAC_MKCHAR or CCS_MAC_MKBLOCK)
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount". Maybe NULL.
 * @mode:      Create mode.
 * @dev:       Device number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_mkdev_perm(const u8 operation, struct dentry *dentry,
			  struct vfsmount *mnt, const unsigned int mode,
			  unsigned int dev)
{
	struct ccs_request_info r = { };
	ccs_check_auto_domain_transition();
	r.obj.path[0].dentry = dentry;
	r.obj.path[0].mnt = mnt;
	dev = new_decode_dev(dev);
	r.type = operation;
	r.param.i[0] = mode;
	r.param.i[1] = MAJOR(dev);
	r.param.i[2] = MINOR(dev);
	return ccs_check_acl(&r, true);
}

/**
 * ccs_path2_perm - Check permission for "rename", "link" and "pivot_root".
 *
 * @operation: One of values in "enum ccs_mac_index".
 * @dentry1:   Pointer to "struct dentry".
 * @mnt1:      Pointer to "struct vfsmount". Maybe NULL.
 * @dentry2:   Pointer to "struct dentry".
 * @mnt2:      Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path2_perm(const enum ccs_mac_index operation,
			  struct dentry *dentry1, struct vfsmount *mnt1,
			  struct dentry *dentry2, struct vfsmount *mnt2)
{
	struct ccs_request_info r = { };
	ccs_check_auto_domain_transition();
	r.type = operation;
	r.obj.path[0].dentry = dentry1;
	r.obj.path[0].mnt = mnt1;
	r.obj.path[1].dentry = dentry2;
	r.obj.path[1].mnt = mnt2;
	return ccs_check_acl(&r, true);
}

/**
 * __ccs_symlink_permission - Check permission for "symlink".
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @target: Content of symlink.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_symlink_permission(struct dentry *dentry,
				    struct vfsmount *mnt, const char *target)
{
	struct ccs_request_info r = { };
	ccs_check_auto_domain_transition();
	r.type = CCS_MAC_SYMLINK;
	r.obj.path[0].dentry = dentry;
	r.obj.path[0].mnt = mnt;
	r.obj.pathname[1].name = ccs_encode(target);
	if (!r.obj.pathname[1].name)
		return -ENOMEM;
	ccs_fill_path_info(&r.obj.pathname[1]);
	r.param.s[1] = &r.obj.pathname[1];
	return ccs_check_acl(&r, true);
}

/**
 * ccs_path_number_perm - Check permission for "create", "mkdir", "mkfifo", "mksock", "ioctl", "chmod", "chown", "chgrp" and "unmount".
 *
 * @type:   One of values in "enum ccs_mac_index".
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount". Maybe NULL.
 * @number: Number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_number_perm(const enum ccs_mac_index type,
				struct dentry *dentry, struct vfsmount *vfsmnt,
				unsigned long number)
{
	struct ccs_request_info r = { };
	ccs_check_auto_domain_transition();
	r.type = type;
	r.obj.path[0].dentry = dentry;
	r.obj.path[0].mnt = vfsmnt;
	r.param.i[0] = number;
	return ccs_check_acl(&r, true);
}

/**
 * __ccs_ioctl_permission - Check permission for "ioctl".
 *
 * @filp: Pointer to "struct file".
 * @cmd:  Ioctl command number.
 * @arg:  Param for @cmd.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_ioctl_permission(struct file *filp, unsigned int cmd,
				  unsigned long arg)
{
	return ccs_path_number_perm(CCS_MAC_IOCTL, filp->f_dentry,
				    filp->f_vfsmnt, cmd);
}

/**
 * __ccs_chmod_permission - Check permission for "chmod".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_chmod_permission(struct dentry *dentry,
				  struct vfsmount *vfsmnt, mode_t mode)
{
	if (mode == (mode_t) -1)
		return 0;
	return ccs_path_number_perm(CCS_MAC_CHMOD, dentry, vfsmnt,
				    mode & S_IALLUGO);
}

/**
 * __ccs_chown_permission - Check permission for "chown/chgrp".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount". Maybe NULL.
 * @user:   User ID.
 * @group:  Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_chown_permission(struct dentry *dentry,
				  struct vfsmount *vfsmnt, uid_t user,
				  gid_t group)
{
	int error = 0;
	if (user == (uid_t) -1 && group == (gid_t) -1)
		return 0;
	if (user != (uid_t) -1)
		error = ccs_path_number_perm(CCS_MAC_CHOWN, dentry,
					     vfsmnt, user);
	if (!error && group != (gid_t) -1)
		error = ccs_path_number_perm(CCS_MAC_CHGRP, dentry,
					     vfsmnt, group);
	return error;
}

/**
 * __ccs_fcntl_permission - Check permission for changing O_APPEND flag.
 *
 * @file: Pointer to "struct file".
 * @cmd:  Command number.
 * @arg:  Value for @cmd.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_fcntl_permission(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	if (!(cmd == F_SETFL && ((arg ^ file->f_flags) & O_APPEND)))
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	return __ccs_open_permission(file->f_dentry, file->f_vfsmnt,
				     O_WRONLY | (arg & O_APPEND));
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 6
	return __ccs_open_permission(file->f_dentry, file->f_vfsmnt,
				     O_WRONLY | (arg & O_APPEND));
#else
	return __ccs_open_permission(file->f_dentry, file->f_vfsmnt,
				     (O_WRONLY + 1) | (arg & O_APPEND));
#endif
}

/**
 * __ccs_pivot_root_permission - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path".
 * @new_path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_pivot_root_permission(struct path *old_path,
				       struct path *new_path)
{
	return ccs_path2_perm(CCS_MAC_PIVOT_ROOT, new_path->dentry,
			      new_path->mnt, old_path->dentry, old_path->mnt);
}

/**
 * __ccs_chroot_permission - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_chroot_permission(struct path *path)
{
	return ccs_path_perm(CCS_MAC_CHROOT, path->dentry, path->mnt);
}

/**
 * __ccs_umount_permission - Check permission for unmount.
 *
 * @mnt:   Pointer to "struct vfsmount".
 * @flags: Unmount flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_umount_permission(struct vfsmount *mnt, int flags)
{
	return ccs_path_number_perm(CCS_MAC_UMOUNT, mnt->mnt_root, mnt, flags);
}

/**
 * __ccs_mknod_permission - Check permission for vfs_mknod().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Device type and permission.
 * @dev:    Device number for block or character device.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_mknod_permission(struct dentry *dentry, struct vfsmount *mnt,
				  const unsigned int mode, unsigned int dev)
{
	int error = 0;
	const unsigned int perm = mode & S_IALLUGO;
	switch (mode & S_IFMT) {
	case S_IFCHR:
		error = ccs_mkdev_perm(CCS_MAC_MKCHAR, dentry, mnt, perm,
				       dev);
		break;
	case S_IFBLK:
		error = ccs_mkdev_perm(CCS_MAC_MKBLOCK, dentry, mnt, perm,
				       dev);
		break;
	case S_IFIFO:
		error = ccs_path_number_perm(CCS_MAC_MKFIFO, dentry, mnt,
					     perm);
		break;
	case S_IFSOCK:
		error = ccs_path_number_perm(CCS_MAC_MKSOCK, dentry, mnt,
					     perm);
		break;
	case 0:
	case S_IFREG:
		error = ccs_path_number_perm(CCS_MAC_CREATE, dentry, mnt,
					     perm);
		break;
	}
	return error;
}

/**
 * __ccs_mkdir_permission - Check permission for vfs_mkdir().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_mkdir_permission(struct dentry *dentry, struct vfsmount *mnt,
				  unsigned int mode)
{
	return ccs_path_number_perm(CCS_MAC_MKDIR, dentry, mnt, mode);
}

/**
 * __ccs_rmdir_permission - Check permission for vfs_rmdir().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_rmdir_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	return ccs_path_perm(CCS_MAC_RMDIR, dentry, mnt);
}

/**
 * __ccs_unlink_permission - Check permission for vfs_unlink().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_unlink_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	return ccs_path_perm(CCS_MAC_UNLINK, dentry, mnt);
}

#ifdef CONFIG_CCSECURITY_GETATTR

/**
 * __ccs_getattr_permission - Check permission for vfs_getattr().
 *
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_getattr_permission(struct vfsmount *mnt,
				    struct dentry *dentry)
{
	return ccs_path_perm(CCS_MAC_GETATTR, dentry, mnt);
}

#endif

/**
 * __ccs_truncate_permission - Check permission for notify_change().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_truncate_permission(struct dentry *dentry,
				     struct vfsmount *mnt)
{
	return ccs_path_perm(CCS_MAC_TRUNCATE, dentry, mnt);
}

/**
 * __ccs_rename_permission - Check permission for vfs_rename().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @new_dentry: Pointer to "struct dentry".
 * @mnt:        Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_rename_permission(struct dentry *old_dentry,
				   struct dentry *new_dentry,
				   struct vfsmount *mnt)
{
	return ccs_path2_perm(CCS_MAC_RENAME, old_dentry, mnt, new_dentry,
			      mnt);
}

/**
 * __ccs_link_permission - Check permission for vfs_link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @new_dentry: Pointer to "struct dentry".
 * @mnt:        Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_link_permission(struct dentry *old_dentry,
				 struct dentry *new_dentry,
				 struct vfsmount *mnt)
{
	return ccs_path2_perm(CCS_MAC_LINK, old_dentry, mnt, new_dentry,
			      mnt);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)

/**
 * __ccs_open_exec_permission - Check permission for open_exec().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_open_exec_permission(struct dentry *dentry,
				      struct vfsmount *mnt)
{
	return (ccs_current_flags() & CCS_TASK_IS_IN_EXECVE) ?
		__ccs_open_permission(dentry, mnt, O_RDONLY + 1) : 0;
}

/**
 * __ccs_uselib_permission - Check permission for sys_uselib().
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_uselib_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	return __ccs_open_permission(dentry, mnt, O_RDONLY + 1);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) && defined(CONFIG_SYSCTL_SYSCALL)

/**
 * ccs_sysctl_permission - Check permission for sysctl operation.
 *
 * @type:     One of values in "enum ccs_mac_index".
 * @filename: Filename to check.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_sysctl_permission(enum ccs_mac_index type,
				 const struct ccs_path_info *filename)
{
	struct ccs_request_info r = { };
	r.type = type;
	r.param.s[0] = filename;
	return ccs_check_acl(&r, true);
}

/**
 * __ccs_parse_table - Check permission for parse_table().
 *
 * @name:   Pointer to "int __user".
 * @nlen:   Number of elements in @name.
 * @oldval: Pointer to "void __user".
 * @newval: Pointer to "void __user".
 * @table:  Pointer to "struct ctl_table".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Note that this function is racy because this function checks values in
 * userspace memory which could be changed after permission check.
 */
static int __ccs_parse_table(int __user *name, int nlen, void __user *oldval,
			     void __user *newval, struct ctl_table *table)
{
	int n;
	int error = -ENOMEM;
	int op = 0;
	struct ccs_path_info buf;
	char *buffer = NULL;
	if (oldval)
		op |= 004;
	if (newval)
		op |= 002;
	if (!op) /* Neither read nor write */
		return 0;
	buffer = kmalloc(PAGE_SIZE, GFP_NOFS);
	if (!buffer)
		goto out;
	snprintf(buffer, PAGE_SIZE - 1, "proc:/sys");
repeat:
	if (!nlen) {
		error = -ENOTDIR;
		goto out;
	}
	if (get_user(n, name)) {
		error = -EFAULT;
		goto out;
	}
	for ( ; table->ctl_name || table->procname; table++) {
		int pos;
		const char *cp;
		if (!n || n != table->ctl_name)
			continue;
		pos = strlen(buffer);
		cp = table->procname;
		error = -ENOMEM;
		if (cp) {
			int len = strlen(cp);
			if (len + 2 > PAGE_SIZE - 1)
				goto out;
			buffer[pos++] = '/';
			memmove(buffer + pos, cp, len + 1);
		} else {
			/* Assume nobody assigns "=\$=" for procname. */
			snprintf(buffer + pos, PAGE_SIZE - pos - 1,
				 "/=%d=", table->ctl_name);
			if (!memchr(buffer, '\0', PAGE_SIZE - 2))
				goto out;
		}
		if (!table->child)
			goto no_child;
		name++;
		nlen--;
		table = table->child;
		goto repeat;
no_child:
		/* printk("sysctl='%s'\n", buffer); */
		buf.name = ccs_encode(buffer);
		if (!buf.name)
			goto out;
		ccs_fill_path_info(&buf);
		if (op & MAY_READ)
			error = ccs_sysctl_permission(CCS_MAC_READ, &buf);
		else
			error = 0;
		if (!error && (op & MAY_WRITE))
			error = ccs_sysctl_permission(CCS_MAC_WRITE,
						      &buf);
		kfree(buf.name);
		goto out;
	}
	error = -ENOTDIR;
out:
	kfree(buffer);
	return error;
}

#endif

#ifdef CONFIG_CCSECURITY_NETWORK

/**
 * ccs_ip_matches_group - Check whether the given IP address matches members of the given IP group.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @group:   Pointer to "struct ccs_ip_group".
 *
 * Returns true if @address matches addresses in @group group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_ip_matches_group(const bool is_ipv6, const u8 *address,
				 const struct ccs_group *group)
{
	struct ccs_ip_group *member;
	bool matched = false;
	const u8 size = is_ipv6 ? 16 : 4;
	list_for_each_entry_srcu(member, &group->member_list, head.list,
				 &ccs_ss) {
		if (member->head.is_deleted)
			continue;
		if (member->is_ipv6 != is_ipv6)
			continue;
		if (memcmp(&member->ip[0], address, size) > 0 ||
		    memcmp(address, &member->ip[1], size) > 0)
			continue;
		matched = true;
		break;
	}
	return matched;
}

/**
 * ccs_inet_entry - Check permission for INET network operation.
 *
 * @address: Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inet_entry(const struct ccs_addr_info *address)
{
	struct ccs_request_info r = { };
	ccs_check_auto_domain_transition();
	r.type = address->operation;
	r.param.is_ipv6 = address->inet.is_ipv6;
	r.param.ip = address->inet.address;
	r.param.i[0] = ntohs(address->inet.port);
	return ccs_check_acl(&r, true);
}

/**
 * ccs_check_inet_address - Check permission for inet domain socket's operation.
 *
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 * @port:     Port number.
 * @address:  Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_inet_address(const struct sockaddr *addr,
				  const unsigned int addr_len, const u16 port,
				  struct ccs_addr_info *address)
{
	struct ccs_inet_addr_info *i = &address->inet;
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			goto skip;
		i->is_ipv6 = true;
		i->address =
			((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr;
		i->port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			goto skip;
		i->is_ipv6 = false;
		i->address = (u8 *) &((struct sockaddr_in *) addr)->sin_addr;
		i->port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	if (address->operation == CCS_MAC_INET_RAW_BIND ||
	    address->operation == CCS_MAC_INET_RAW_SEND ||
	    address->operation == CCS_MAC_INET_RAW_RECV)
		i->port = htons(port);
	return ccs_inet_entry(address);
skip:
	return 0;
}

/**
 * ccs_unix_entry - Check permission for UNIX network operation.
 *
 * @address: Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_unix_entry(const struct ccs_addr_info *address)
{
	int error;
	char *buf = address->unix0.addr;
	int len = address->unix0.addr_len - sizeof(sa_family_t);
	if (len <= 0) {
		buf = "anonymous";
		len = 9;
	} else if (buf[0]) {
		len = strnlen(buf, len);
	}
	buf = ccs_encode2(buf, len);
	if (buf) {
		struct ccs_path_info addr;
		struct ccs_request_info r = { };
		addr.name = buf;
		ccs_fill_path_info(&addr);
		r.type = address->operation;
		r.param.s[0] = &addr;
		error = ccs_check_acl(&r, true);
		kfree(buf);
	} else
		error = -ENOMEM;
	return error;
}

/**
 * ccs_check_unix_address - Check permission for unix domain socket's operation.
 *
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 * @address:  Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_unix_address(struct sockaddr *addr,
				  const unsigned int addr_len,
				  struct ccs_addr_info *address)
{
	struct ccs_unix_addr_info *u = &address->unix0;
	if (addr->sa_family != AF_UNIX)
		return 0;
	u->addr = ((struct sockaddr_un *) addr)->sun_path;
	u->addr_len = addr_len;
	return ccs_unix_entry(address);
}

/**
 * ccs_sock_family - Get socket's family.
 *
 * @sk: Pointer to "struct sock".
 *
 * Returns one of PF_INET, PF_INET6, PF_UNIX or 0.
 */
static u8 ccs_sock_family(struct sock *sk)
{
	u8 family;
	if (ccs_kernel_service())
		return 0;
	family = sk->sk_family;
	switch (family) {
	case PF_INET:
	case PF_INET6:
	case PF_UNIX:
		return family;
	default:
		return 0;
	}
}

/**
 * __ccs_socket_listen_permission - Check permission for listening a socket.
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_listen_permission(struct socket *sock)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	struct sockaddr_storage addr;
	int addr_len;
	if (!family || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	{
		const int error = sock->ops->getname(sock, (struct sockaddr *)
						     &addr, &addr_len, 0);
		if (error)
			return error;
	}
	if (family == PF_INET || family == PF_INET6)
		address.operation = CCS_MAC_INET_STREAM_LISTEN;
	else if (type == SOCK_STREAM)
		address.operation = CCS_MAC_UNIX_STREAM_LISTEN;
	else
		address.operation = CCS_MAC_UNIX_SEQPACKET_LISTEN;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *) &addr,
					      addr_len, &address);
	return ccs_check_inet_address((struct sockaddr *) &addr, addr_len, 0,
				      &address);
}

/**
 * __ccs_socket_connect_permission - Check permission for setting the remote address of a socket.
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_connect_permission(struct socket *sock,
					   struct sockaddr *addr, int addr_len)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	if (!family)
		return 0;
	switch (sock->type) {
	case SOCK_DGRAM:
		address.operation = family == PF_UNIX ?
			CCS_MAC_UNIX_DGRAM_SEND :
			CCS_MAC_INET_DGRAM_SEND;
		break;
	case SOCK_RAW:
		address.operation = CCS_MAC_INET_RAW_SEND;
		break;
	case SOCK_STREAM:
		address.operation = family == PF_UNIX ?
			CCS_MAC_UNIX_STREAM_CONNECT :
			CCS_MAC_INET_STREAM_CONNECT;
		break;
	case SOCK_SEQPACKET:
		address.operation = CCS_MAC_UNIX_SEQPACKET_CONNECT;
		break;
	default:
		return 0;
	}
	if (family == PF_UNIX)
		return ccs_check_unix_address(addr, addr_len, &address);
	return ccs_check_inet_address(addr, addr_len, sock->sk->sk_protocol,
				      &address);
}

/**
 * __ccs_socket_bind_permission - Check permission for setting the local address of a socket.
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_bind_permission(struct socket *sock,
					struct sockaddr *addr, int addr_len)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!family)
		return 0;
	switch (type) {
	case SOCK_STREAM:
		address.operation = family == PF_UNIX ?
			CCS_MAC_UNIX_STREAM_BIND :
			CCS_MAC_INET_STREAM_BIND;
		break;
	case SOCK_DGRAM:
		address.operation = family == PF_UNIX ?
			CCS_MAC_UNIX_DGRAM_BIND :
			CCS_MAC_INET_DGRAM_BIND;
		break;
	case SOCK_RAW:
		address.operation = CCS_MAC_INET_RAW_BIND;
		break;
	case SOCK_SEQPACKET:
		address.operation = CCS_MAC_UNIX_SEQPACKET_BIND;
		break;
	default:
		return 0;
	}
	if (family == PF_UNIX)
		return ccs_check_unix_address(addr, addr_len, &address);
	return ccs_check_inet_address(addr, addr_len, sock->sk->sk_protocol,
				      &address);
}

/**
 * __ccs_socket_sendmsg_permission - Check permission for sending a datagram.
 *
 * @sock: Pointer to "struct socket".
 * @msg:  Pointer to "struct msghdr".
 * @size: Unused.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_sendmsg_permission(struct socket *sock,
					   struct msghdr *msg, int size)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!msg->msg_name || !family ||
	    (type != SOCK_DGRAM && type != SOCK_RAW))
		return 0;
	if (family == PF_UNIX)
		address.operation = CCS_MAC_UNIX_DGRAM_SEND;
	else if (type == SOCK_DGRAM)
		address.operation = CCS_MAC_INET_DGRAM_SEND;
	else
		address.operation = CCS_MAC_INET_RAW_SEND;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *)
					      msg->msg_name, msg->msg_namelen,
					      &address);
	return ccs_check_inet_address((struct sockaddr *) msg->msg_name,
				      msg->msg_namelen, sock->sk->sk_protocol,
				      &address);
}

/**
 * __ccs_socket_post_accept_permission - Check permission for accepting a socket.
 *
 * @sock:    Pointer to "struct socket".
 * @newsock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_post_accept_permission(struct socket *sock,
					       struct socket *newsock)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	struct sockaddr_storage addr;
	int addr_len;
	if (!family || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	{
		const int error = newsock->ops->getname(newsock,
							(struct sockaddr *)
							&addr, &addr_len, 2);
		if (error)
			return error;
	}
	if (family == PF_INET || family == PF_INET6)
		address.operation = CCS_MAC_INET_STREAM_ACCEPT;
	else if (type == SOCK_STREAM)
		address.operation = CCS_MAC_UNIX_STREAM_ACCEPT;
	else
		address.operation = CCS_MAC_UNIX_SEQPACKET_ACCEPT;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *) &addr,
					      addr_len, &address);
	return ccs_check_inet_address((struct sockaddr *) &addr, addr_len, 0,
				      &address);
}

#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG

/**
 * __ccs_socket_post_recvmsg_permission - Check permission for receiving a datagram.
 *
 * @sk:    Pointer to "struct sock".
 * @skb:   Pointer to "struct sk_buff".
 * @flags: Flags passed to skb_recv_datagram().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_post_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb, int flags)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sk);
	const unsigned int type = sk->sk_type;
	struct sockaddr_storage addr;
	if (!family || (type != SOCK_DGRAM && type != SOCK_RAW))
		return 0;
	if (family == PF_UNIX)
		address.operation = CCS_MAC_UNIX_DGRAM_RECV;
	else if (type == SOCK_DGRAM)
		address.operation = CCS_MAC_INET_DGRAM_RECV;
	else
		address.operation = CCS_MAC_INET_RAW_RECV;
	switch (family) {
	case PF_INET6:
		{
			struct in6_addr *sin6 = (struct in6_addr *) &addr;
			address.inet.is_ipv6 = true;
			if (type == SOCK_DGRAM &&
			    skb->protocol == htons(ETH_P_IP))
				ipv6_addr_set(sin6, 0, 0, htonl(0xffff),
					      ip_hdr(skb)->saddr);
			else
				*sin6 = ipv6_hdr(skb)->saddr;
			break;
		}
	case PF_INET:
		{
			struct in_addr *sin4 = (struct in_addr *) &addr;
			address.inet.is_ipv6 = false;
			sin4->s_addr = ip_hdr(skb)->saddr;
			break;
		}
	default: /* == PF_UNIX */
		{
			struct unix_address *u = unix_sk(skb->sk)->addr;
			unsigned int addr_len;
			if (u && u->len <= sizeof(addr)) {
				addr_len = u->len;
				memcpy(&addr, u->name, addr_len);
			} else {
				addr_len = 0;
				addr.ss_family = AF_UNIX;
			}
			if (ccs_check_unix_address((struct sockaddr *) &addr,
						   addr_len, &address))
				goto out;
			return 0;
		}
	}
	address.inet.address = (u8 *) &addr;
	if (type == SOCK_DGRAM)
		address.inet.port = udp_hdr(skb)->source;
	else
		address.inet.port = htons(sk->sk_protocol);
	if (ccs_inet_entry(&address))
		goto out;
	return 0;
out:
	/*
	 * Remove from queue if MSG_PEEK is used so that
	 * the head message from unwanted source in receive queue will not
	 * prevent the caller from picking up next message from wanted source
	 * when the caller is using MSG_PEEK flag for picking up.
	 */
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
		bool slow = false;
		if (type == SOCK_DGRAM && family != PF_UNIX)
			slow = lock_sock_fast(sk);
#else
		if (type == SOCK_DGRAM && family != PF_UNIX)
			lock_sock(sk);
#endif
		skb_kill_datagram(sk, skb, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
		if (type == SOCK_DGRAM && family != PF_UNIX)
			unlock_sock_fast(sk, slow);
#else
		if (type == SOCK_DGRAM && family != PF_UNIX)
			release_sock(sk);
#endif
	}
	return -EPERM;
}

#endif

#endif

#if defined(CONFIG_CCSECURITY_CAPABILITY) || defined(CONFIG_CCSECURITY_NETWORK)

/**
 * ccs_kernel_service - Check whether I'm kernel service or not.
 *
 * Returns true if I'm kernel service, false otherwise.
 */
static bool ccs_kernel_service(void)
{
	/* Nothing to do if I am a kernel service. */
	return segment_eq(get_fs(), KERNEL_DS);
}

#endif

#ifdef CONFIG_CCSECURITY_CAPABILITY

/**
 * ccs_capable - Check permission for capability.
 *
 * @operation: Type of operation.
 *
 * Returns true on success, false otherwise.
 */
static bool __ccs_capable(const u8 operation)
{
	struct ccs_request_info r = { };
	r.type = ccs_c2mac[operation];
	return !ccs_check_acl(&r, true);
}

/**
 * __ccs_socket_create_permission - Check permission for creating a socket.
 *
 * @family:   Protocol family.
 * @type:     Unused.
 * @protocol: Unused.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_create_permission(int family, int type, int protocol)
{
	if (ccs_kernel_service())
		return 0;
	if (family == PF_PACKET && !ccs_capable(CCS_USE_PACKET_SOCKET))
		return -EPERM;
	if (family == PF_NETLINK && !ccs_capable(CCS_USE_ROUTE_SOCKET))
		return -EPERM;
	return 0;
}

#endif

/**
 * ccs_manager - Check whether the current process is a policy manager.
 *
 * Returns true if the current process is permitted to modify policy
 * via /proc/ccs/ interface.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_manager(void)
{
	struct ccs_security *task;
	if (!ccs_policy_loaded)
		return true;
	task = ccs_current_security();
	if (task->ccs_flags & CCS_TASK_IS_MANAGER)
		return true;
	{
		struct ccs_request_info r = { };
		r.type = CCS_MAC_MODIFY_POLICY;
		if (ccs_check_acl(&r, true) == 0) {
			/* Set manager flag. */
			task->ccs_flags |= CCS_TASK_IS_MANAGER;
			return true;
		}
	}
	{ /* Reduce error messages. */
		static pid_t ccs_last_pid;
		const pid_t pid = current->pid;
		if (ccs_last_pid != pid) {
			const char *exe = ccs_get_exe();
			printk(KERN_WARNING "'%s' (pid=%u domain='%s') is"
			       " not permitted to update policies.\n", exe,
			       pid, task->ccs_domain_info->domainname->name);
			ccs_last_pid = pid;
			kfree(exe);
		}
	}
	return false;
}

#ifdef CONFIG_CCSECURITY_PTRACE

/**
 * __ccs_ptrace_permission - Check permission for ptrace().
 *
 * @request: Command number.
 * @pid:     Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_ptrace_permission(long request, long pid)
{
	struct ccs_domain_info *dest;
	int error = -ESRCH;
	const int idx = ccs_read_lock();
	ccs_check_auto_domain_transition();
	if (request == PTRACE_TRACEME) {
		dest = ccs_current_domain();
	} else {
		struct task_struct *p;
		ccs_tasklist_lock();
		p = ccsecurity_exports.find_task_by_vpid((pid_t) pid);
		if (p)
			dest = ccs_task_domain(p);
		else
			dest = NULL;
		ccs_tasklist_unlock();
	}
	if (dest) {
		struct ccs_request_info r = { };
		r.type = CCS_MAC_PTRACE;
		r.param.i[0] = request;
		r.param.s[0] = dest->domainname;
		error = ccs_check_acl(&r, true);
	}
	ccs_read_unlock(idx);
	return error;
}

#endif

#ifdef CONFIG_CCSECURITY_SIGNAL

/**
 * __ccs_signal_permission - Check permission for signal.
 *
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int __ccs_signal_permission(const int sig)
{
	struct ccs_request_info r = { };
	const int idx = ccs_read_lock();
	int error;
	ccs_check_auto_domain_transition();
	r.type = CCS_MAC_SIGNAL;
	r.param.i[0] = sig;
	error = ccs_check_acl(&r, true);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_signal_permission0 - Check permission for signal.
 *
 * @pid: Unused.
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_signal_permission0(const int pid, const int sig)
{
	return __ccs_signal_permission(sig);
}

/**
 * ccs_signal_permission1 - Permission check for signal().
 *
 * @tgid: Unused.
 * @pid:  Unused.
 * @sig:  Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_signal_permission1(pid_t tgid, pid_t pid, int sig)
{
	return __ccs_signal_permission(sig);
}

#endif

#ifdef CONFIG_CCSECURITY_ENVIRON

/**
 * ccs_env_perm - Check permission for environment variable's name.
 *
 * @r:     Pointer to "struct ccs_request_info".
 * @name:  Name of environment variable. Maybe "".
 * @value: Value of environment variable. Maybe "".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_env_perm(struct ccs_request_info *r, const char *name,
			const char *value)
{
	struct ccs_path_info n;
	struct ccs_path_info v;
	n.name = name;
	ccs_fill_path_info(&n);
	v.name = value;
	ccs_fill_path_info(&v);
	r->type = CCS_MAC_ENVIRON;
	r->param.s[2] = &n;
	r->param.s[3] = &v;
	return ccs_check_acl(r, false);
}

/**
 * ccs_environ - Check permission for environment variable names.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_environ(struct ccs_request_info *r)
{
	struct linux_binprm *bprm = r->bprm;
	/* env_page.data is allocated by ccs_dump_page(). */
	struct ccs_page_dump env_page = { };
	char *arg_ptr; /* Size is CCS_EXEC_TMPSIZE bytes */
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	int error = -ENOMEM;
	arg_ptr = kzalloc(CCS_EXEC_TMPSIZE, GFP_NOFS);
	if (!arg_ptr) {
		r->failed_by_oom = true;
		goto out;
	}
	while (error == -ENOMEM) {
		if (!ccs_dump_page(bprm, pos, &env_page)) {
			r->failed_by_oom = true;
			goto out;
		}
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (argv_count && offset < PAGE_SIZE) {
			if (!env_page.data[offset++])
				argv_count--;
		}
		if (argv_count) {
			offset = 0;
			continue;
		}
		while (offset < PAGE_SIZE) {
			char *value;
			const unsigned char c = env_page.data[offset++];
			if (c && arg_len < CCS_EXEC_TMPSIZE - 10) {
				if (c > ' ' && c < 127 && c != '\\') {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++]
						= ((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
			} else {
				arg_ptr[arg_len] = '\0';
			}
			if (c)
				continue;
			value = strchr(arg_ptr, '=');
			if (value)
				*value++ = '\0';
			else
				value = "";
			if (ccs_env_perm(r, arg_ptr, value)) {
				error = -EPERM;
				break;
			}
			if (!--envp_count) {
				error = 0;
				break;
			}
			arg_len = 0;
		}
		offset = 0;
	}
out:
	kfree(env_page.data);
	kfree(arg_ptr);
	return error;
}

#endif

/**
 * ccs_path_matches_group_or_pattern - Check whether the given pathname matches the given group or the given pattern.
 *
 * @path:    Pointer to "struct ccs_path_info".
 * @group:   Pointer to "struct ccs_group". Maybe NULL.
 * @pattern: Poiner to "struct ccs_path_info". Maybe NULL.
 * @match:   True if positive match, false othwerwise.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_path_matches_group_or_pattern
(const struct ccs_path_info *path, const struct ccs_group *group,
 const struct ccs_path_info *pattern, const bool match)
{
	if (group)
		return ccs_path_matches_group(path, group) == match;
	else if (pattern != &ccs_null_name)
		return ccs_path_matches_pattern(path, pattern) == match;
	else
		return !match;
}

/**
 * ccs_check_argv - Check argv[] in "struct linux_binbrm".
 *
 * @r:     Pointer to "struct ccs_request_info".
 * @index: Index number to check.
 * @group: Pointer to "struct ccs_group". Maybe NULL.
 * @value: Poiner to "struct ccs_path_info". NULL if @group != NULL.
 * @match: True if positive match, false othwerwise.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_check_argv(struct ccs_request_info *r, unsigned long index,
			   const struct ccs_group *group,
			   const struct ccs_path_info *value,
			   const bool match)
{
	struct linux_binprm *bprm = r->bprm;
	struct ccs_page_dump *dump = &r->dump;
	char *arg_ptr = r->tmp;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	struct ccs_path_info arg;
	if (index > bprm->argc)
		return false;
	while (1) {
		if (!ccs_dump_page(bprm, pos, dump)) {
			r->failed_by_oom = true;
			return false;
		}
		pos += PAGE_SIZE - offset;
		while (offset < PAGE_SIZE) {
			const unsigned char c = dump->data[offset++];
			if (index) {
				if (!c)
					index--;
				continue;
			}
			if (c && arg_len < CCS_EXEC_TMPSIZE - 10) {
				if (c > ' ' && c < 127 && c != '\\') {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++] =
						((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
				continue;
			}
			arg_ptr[arg_len] = '\0';
			arg.name = arg_ptr;
			ccs_fill_path_info(&arg);
			return ccs_path_matches_group_or_pattern
				(&arg, group, value, match);
		}
		offset = 0;
	}
}

/**
 * ccs_check_envp - Check envp[] in "struct linux_binbrm".
 *
 * @r:     Pointer to "struct ccs_request_info".
 * @name:  Pointer to "struct ccs_path_info".
 * @group: Pointer to "struct ccs_group". Maybe NULL.
 * @value: Pointer to "struct ccs_path_info". NULL if @group != NULL.
 * @match: True if positive match, false othwerwise.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_check_envp(struct ccs_request_info *r,
			   const struct ccs_path_info *name,
			   const struct ccs_group *group,
			   const struct ccs_path_info *value,
			   const bool match)
{
	struct linux_binprm *bprm = r->bprm;
	struct ccs_page_dump *dump = &r->dump;
	char *arg_ptr = r->tmp;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool result = (value != &ccs_null_name) == match;
	struct ccs_path_info env;
	char *cp;
	while (envp_count) {
		if (!ccs_dump_page(bprm, pos, dump)) {
			r->failed_by_oom = true;
			return false;
		}
		pos += PAGE_SIZE - offset;
		while (envp_count && offset < PAGE_SIZE) {
			const unsigned char c = dump->data[offset++];
			if (argv_count) {
				if (!c)
					argv_count--;
				continue;
			}
			if (c && arg_len < CCS_EXEC_TMPSIZE - 10) {
				if (c > ' ' && c < 127 && c != '\\') {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++] =
						((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
			} else {
				arg_ptr[arg_len] = '\0';
			}
			if (c)
				continue;
			arg_len = 0;
			envp_count--;
			/* Check. */
			cp = strchr(arg_ptr, '=');
			if (!cp)
				cp = "";
			else
				*cp++ = '\0';
			env.name = arg_ptr;
			ccs_fill_path_info(&env);
			if (!ccs_path_matches_pattern(&env, name))
				continue;
			result = true;
			env.name = cp;
			ccs_fill_path_info(&env);
			if (ccs_path_matches_group_or_pattern
			    (&env, group, value, match))
				continue;
			return false;
		}
		offset = 0;
	}
	return result;
}

/**
 * ccs_get_attributes - Revalidate "struct inode".
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns nothing.
 */
void ccs_get_attributes(struct ccs_request_info *r)
{
	u8 i;
	struct dentry *dentry = NULL;

	if (r->obj.validate_done)
		return;
	for (i = 0; i < CCS_MAX_PATH_STAT; i++) {
		struct inode *inode;
		switch (i) {
		case CCS_PATH1:
			dentry = r->obj.path[0].dentry;
			if (!dentry)
				continue;
			break;
		case CCS_PATH2:
			dentry = r->obj.path[1].dentry;
			if (!dentry)
				continue;
			break;
		default:
			if (!dentry)
				continue;
			dentry = dget_parent(dentry);
			break;
		}
		inode = dentry->d_inode;
		if (inode) {
			struct ccs_mini_stat *stat = &r->obj.stat[i];
			stat->uid  = inode->i_uid;
			stat->gid  = inode->i_gid;
			stat->ino  = inode->i_ino;
			stat->mode = inode->i_mode;
			stat->dev  = inode->i_sb->s_dev;
			stat->rdev = inode->i_rdev;
			stat->fsmagic = dentry->d_sb->s_magic;
			r->obj.stat_valid[i] = true;
		}
		if (i & 1) /* parent directory */
			dput(dentry);
	}
	r->obj.validate_done = true;
}

/**
 * ccs_populate_patharg - Calculate pathname for permission check and audit logs.
 *
 * @r:     Pointer to "struct ccs_request_info".
 * @first: True for first pathname, false for second pathname.
 *
 * Returns nothing.
 */
void ccs_populate_patharg(struct ccs_request_info *r, const bool first)
{
	struct ccs_path_info *buf = &r->obj.pathname[!first];
	struct path *path = &r->obj.path[!first];
	if (!buf->name && path->dentry) {
		int len;
		buf->name = ccs_realpath(path);
		/* Set OOM flag if failed. */
		if (!buf->name) {
			r->failed_by_oom = true;
			return;
		}
		len = strlen(buf->name) - 1;
		if (len >= 0 && buf->name[len] != '/' &&
		    (r->type == CCS_MAC_MKDIR ||
		     r->type == CCS_MAC_RMDIR ||
		     r->type == CCS_MAC_CHROOT ||
		     r->type == CCS_MAC_PIVOT_ROOT ||
		     ((r->type == CCS_MAC_RENAME ||
		       r->type == CCS_MAC_LINK) &&
		      r->obj.path[0].dentry && r->obj.path[0].dentry->d_inode
		      && S_ISDIR(r->obj.path[0].dentry->d_inode->i_mode)))) {
			/*
			 * This is OK because ccs_encode() reserves space for
			 * appending "/".
			 */
			((char *) buf->name)[len++] = '/';
			((char *) buf->name)[len] = '\0';
		}
		ccs_fill_path_info(buf);
	}
	if (!r->param.s[!first] && buf->name)
		r->param.s[!first] = buf;
}

/**
 * ccs_cond2arg - Assign values to condition variables.
 *
 * @arg:   Pointer to "struct ccs_cond_arg".
 * @cmd:   One of values in "enum ccs_conditions_index".
 * @condp: Pointer to "union ccs_condition_element *".
 * @r:     Pointer to "struct ccs_request_info".
 *
 * Returns true on success, false othwerwise.
 *
 * This function should not fail. But it can fail if (for example) out of
 * memory has occured while calculating ccs_populate_patharg() or
 * ccs_get_exename().
 */
static bool ccs_cond2arg(struct ccs_cond_arg *arg,
			 const enum ccs_conditions_index cmd,
			 const union ccs_condition_element **condp,
			 struct ccs_request_info *r)
{
	struct ccs_mini_stat *stat;
	unsigned long value;
	const struct linux_binprm *bprm = r->bprm;
	const struct ccs_request_param *param = &r->param;
	arg->type = CCS_ARG_TYPE_NUMBER;
	switch (cmd) {
	case CCS_SELF_UID:
		value = current_uid();
		break;
	case CCS_SELF_EUID:
		value = current_euid();
		break;
	case CCS_SELF_SUID:
		value = current_suid();
		break;
	case CCS_SELF_FSUID:
		value = current_fsuid();
		break;
	case CCS_SELF_GID:
		value = current_gid();
		break;
	case CCS_SELF_EGID:
		value = current_egid();
		break;
	case CCS_SELF_SGID:
		value = current_sgid();
		break;
	case CCS_SELF_FSGID:
		value = current_fsgid();
		break;
	case CCS_SELF_PID:
		value = ccs_sys_getpid();
		break;
	case CCS_SELF_PPID:
		value = ccs_sys_getppid();
		break;
	case CCS_OBJ_IS_SOCKET:
		value = S_IFSOCK;
		break;
	case CCS_OBJ_IS_SYMLINK:
		value = S_IFLNK;
		break;
	case CCS_OBJ_IS_FILE:
		value = S_IFREG;
		break;
	case CCS_OBJ_IS_BLOCK_DEV:
		value = S_IFBLK;
		break;
	case CCS_OBJ_IS_DIRECTORY:
		value = S_IFDIR;
		break;
	case CCS_OBJ_IS_CHAR_DEV:
		value = S_IFCHR;
		break;
	case CCS_OBJ_IS_FIFO:
		value = S_IFIFO;
		break;
	case CCS_EXEC_ARGC:
		if (!bprm)
			return false;
		value = bprm->argc;
		break;
	case CCS_EXEC_ENVC:
		if (!bprm)
			return false;
		value = bprm->envc;
		break;
	case CCS_TASK_TYPE:
		value = ((u8) ccs_current_flags()) &
			CCS_TASK_IS_EXECUTE_HANDLER;
		break;
	case CCS_TASK_EXECUTE_HANDLER:
		value = CCS_TASK_IS_EXECUTE_HANDLER;
		break;
	case CCS_ARGV_ENTRY:
	case CCS_IMM_NUMBER_ENTRY1:
		value = (*condp)->value;
		(*condp)++;
		break;
	case CCS_COND_NARG0:
		value = param->i[0];
		break;
	case CCS_COND_NARG1:
		value = param->i[1];
		break;
	case CCS_COND_NARG2:
		value = param->i[2];
		break;
	case CCS_HANDLER_PATH:
	case CCS_TRANSIT_DOMAIN:
	case CCS_COND_IPARG:
		/* Values are loaded by caller. Just return a dummy. */
		arg->type = CCS_ARG_TYPE_NONE;
		value = 0;
		break;
	default:
		goto not_single_value;
	}
	arg->value[0] = value;
	arg->value[1] = value;
	return true;
not_single_value:
	if (cmd == CCS_IMM_NUMBER_ENTRY2) {
		arg->value[0] = (*condp)->value;
		(*condp)++;
		arg->value[1] = (*condp)->value;
		(*condp)++;
		return true;
	}
	switch (cmd) {
	case CCS_COND_SARG0:
		if (!r->param.s[0])
			ccs_populate_patharg(r, true);
		arg->name = r->param.s[0];
		break;
	case CCS_COND_SARG1:
		if (!r->param.s[1])
			ccs_populate_patharg(r, false);
		arg->name = r->param.s[1];
		break;
	case CCS_COND_SARG2:
		arg->name = r->param.s[2];
		break;
	case CCS_COND_SARG3:
		arg->name = r->param.s[3];
		break;
	case CCS_ENVP_ENTRY:
	case CCS_IMM_NAME_ENTRY:
		arg->name = (*condp)->path;
		(*condp)++;
		break;
	case CCS_SELF_EXE:
		if (!r->exename.name) {
			ccs_get_exename(&r->exename);
			/* Set OOM flag if failed. */
			if (!r->exename.name)
				r->failed_by_oom = true;
		}
		arg->name = &r->exename;
		break;
	case CCS_COND_DOMAIN:
		arg->name = r->param.s[0];
		break;
	case CCS_SELF_DOMAIN:
		arg->name = ccs_current_domain()->domainname;
		break;
	default:
		goto not_single_name;
	}
	if (!arg->name)
		return false;
	arg->type = CCS_ARG_TYPE_NAME;
	return true;
not_single_name:
	if (cmd == CCS_IMM_GROUP) {
		arg->type = CCS_ARG_TYPE_GROUP;
		arg->group = (*condp)->group;
		(*condp)++;
		return true;
	}
#ifdef CONFIG_CCSECURITY_NETWORK
	if (cmd == CCS_IMM_IPV4ADDR_ENTRY1) {
		arg->type = CCS_ARG_TYPE_IPV4ADDR;
		memmove(&arg->ip[0], &(*condp)->ip, 4);
		memmove(&arg->ip[1], &(*condp)->ip, 4);
		(*condp)++;
		return true;
	}
	if (cmd == CCS_IMM_IPV4ADDR_ENTRY2) {
		arg->type = CCS_ARG_TYPE_IPV4ADDR;
		memmove(&arg->ip[0], &(*condp)->ip, 4);
		(*condp)++;
		memmove(&arg->ip[1], &(*condp)->ip, 4);
		(*condp)++;
		return true;
	}
	if (cmd == CCS_IMM_IPV6ADDR_ENTRY1) {
		arg->type = CCS_ARG_TYPE_IPV6ADDR;
		memmove(&arg->ip[0], &(*condp)->ip, 16);
		memmove(&arg->ip[1], &(*condp)->ip, 16);
		*condp = (void *)
			(((u8 *) *condp) + sizeof(struct in6_addr));
		return true;
	}
	if (cmd == CCS_IMM_IPV6ADDR_ENTRY2) {
		arg->type = CCS_ARG_TYPE_IPV6ADDR;
		memmove(&arg->ip[0], &(*condp)->ip, 16);
		*condp = (void *)
			(((u8 *) *condp) + sizeof(struct in6_addr));
		memmove(&arg->ip[1], &(*condp)->ip, 16);
		*condp = (void *)
			(((u8 *) *condp) + sizeof(struct in6_addr));
		return true;
	}
#endif
	switch (cmd) {
	case CCS_MODE_SETUID:
		value = S_ISUID;
		break;
	case CCS_MODE_SETGID:
		value = S_ISGID;
		break;
	case CCS_MODE_STICKY:
		value = S_ISVTX;
		break;
	case CCS_MODE_OWNER_READ:
		value = S_IRUSR;
		break;
	case CCS_MODE_OWNER_WRITE:
		value = S_IWUSR;
		break;
	case CCS_MODE_OWNER_EXECUTE:
		value = S_IXUSR;
		break;
	case CCS_MODE_GROUP_READ:
		value = S_IRGRP;
		break;
	case CCS_MODE_GROUP_WRITE:
		value = S_IWGRP;
		break;
	case CCS_MODE_GROUP_EXECUTE:
		value = S_IXGRP;
		break;
	case CCS_MODE_OTHERS_READ:
		value = S_IROTH;
		break;
	case CCS_MODE_OTHERS_WRITE:
		value = S_IWOTH;
		break;
	case CCS_MODE_OTHERS_EXECUTE:
		value = S_IXOTH;
		break;
	default:
		goto not_bitop;
	}
	arg->type = CCS_ARG_TYPE_BITOP;
	arg->value[0] = value;
	return true;
not_bitop:
	arg->type = CCS_ARG_TYPE_NUMBER;
	if (!r->obj.path[0].dentry && !r->obj.path[1].dentry)
		return false;
	ccs_get_attributes(r);
	value = (cmd - CCS_PATH_ATTRIBUTE_START) >> 4;
	if (value > 3)
		return false;
	stat = &r->obj.stat[value];
	if (!stat)
		return false;
	switch ((cmd - CCS_PATH_ATTRIBUTE_START) & 0xF) {
	case CCS_PATH_ATTRIBUTE_UID:
		value = stat->uid;
		break;
	case CCS_PATH_ATTRIBUTE_GID:
		value = stat->gid;
		break;
	case CCS_PATH_ATTRIBUTE_INO:
		value = stat->ino;
		break;
	case CCS_PATH_ATTRIBUTE_MAJOR:
		value = MAJOR(stat->dev);
		break;
	case CCS_PATH_ATTRIBUTE_MINOR:
		value = MINOR(stat->dev);
		break;
	case CCS_PATH_ATTRIBUTE_TYPE:
		value = stat->mode & S_IFMT;
		break;
	case CCS_PATH_ATTRIBUTE_DEV_MAJOR:
		value = MAJOR(stat->rdev);
		break;
	case CCS_PATH_ATTRIBUTE_DEV_MINOR:
		value = MINOR(stat->rdev);
		break;
	case CCS_PATH_ATTRIBUTE_PERM:
		value = stat->mode & S_IALLUGO;
		break;
	case CCS_PATH_ATTRIBUTE_FSMAGIC:
		value = stat->fsmagic;
		break;
	default:
		return false;
	}
	arg->value[0] = value;
	arg->value[1] = value;
	return true;
}

/**
 * ccs_condition - Check condition part.
 *
 * @r:    Pointer to "struct ccs_request_info".
 * @cond: Pointer to "struct ccs_condition". Maybe NULL.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_condition(struct ccs_request_info *r,
			  const struct ccs_condition *cond)
{
	const union ccs_condition_element *condp;
	if (!cond)
		return true;
	condp = (typeof(condp)) (cond + 1);
	while ((void *) condp < (void *) ((u8 *) cond) + cond->size) {
		struct ccs_cond_arg left;
		struct ccs_cond_arg right;
		const enum ccs_conditions_index left_op = condp->left;
		const enum ccs_conditions_index right_op = condp->right;
		const bool match = !condp->is_not;
		condp++;
		if (!ccs_cond2arg(&left, left_op, &condp, r) ||
		    !ccs_cond2arg(&right, right_op, &condp, r)) {
			/*
			 * Something wrong (e.g. out of memory or invalid
			 * argument) occured. We can't check permission.
			 */
			return false;
		}
		if (left.type == CCS_ARG_TYPE_NUMBER) {
			if (left_op == CCS_ARGV_ENTRY) {
				if (!r->bprm)
					return false;
				else if (right.type == CCS_ARG_TYPE_NAME)
					right.group = NULL;
				else if (right.type == CCS_ARG_TYPE_GROUP)
					right.name = NULL;
				else
					return false;
				if (ccs_check_argv(r, left.value[0],
						   right.group, right.name,
						   match))
					continue;
				return false;
			}
			if (right.type == CCS_ARG_TYPE_NUMBER) {
				if ((left.value[0] <= right.value[1] &&
				     left.value[1] >= right.value[0]) == match)
					continue;
				return false;
			}
			if (right.type == CCS_ARG_TYPE_GROUP) {
				if (ccs_number_matches_group
				    (left.value[0], left.value[1], right.group)
				    == match)
					continue;
				return false;
			}
			if (right.type == CCS_ARG_TYPE_BITOP) {
				if (!(left.value[0] & right.value[0]) ==
				    !match)
					continue;
				return false;
			}
			return false;
		}
		if (left.type == CCS_ARG_TYPE_NAME) {
			if (right.type == CCS_ARG_TYPE_NAME)
				right.group = NULL;
			else if (right.type == CCS_ARG_TYPE_GROUP)
				right.name = NULL;
			else
				return false;
			if (left_op == CCS_ENVP_ENTRY) {
				if (r->bprm && ccs_check_envp
				    (r, left.name, right.group, right.name,
				     match))
					continue;
			} else if (ccs_path_matches_group_or_pattern
				   (left.name, right.group, right.name, match))
				continue;
			return false;
		}
		if (left.type != CCS_ARG_TYPE_NONE)
			return false;
		/* Check IPv4 or IPv6 address expressions. */
		if (left_op == CCS_COND_IPARG) {
#ifdef CONFIG_CCSECURITY_NETWORK
			if (right.type == CCS_ARG_TYPE_GROUP) {
				if (ccs_ip_matches_group
				    (r->param.is_ipv6, r->param.ip,
				     right.group) == match)
					continue;
			} else if (right.type == CCS_ARG_TYPE_IPV6ADDR) {
				if (r->param.is_ipv6 &&
				    (memcmp(r->param.ip, &right.ip[0],
					    16) >= 0 &&
				     memcmp(r->param.ip, &right.ip[1],
					    16) <= 0) == match)
					continue;
			} else if (right.type == CCS_ARG_TYPE_IPV4ADDR) {
				if (!r->param.is_ipv6 &&
				    (memcmp(r->param.ip, &right.ip[0],
					    4) >= 0 &&
				     memcmp(r->param.ip, &right.ip[1],
					    4) <= 0) == match)
					continue;
			}
#endif
			return false;
		}
		if (left_op == CCS_HANDLER_PATH) {
			r->handler_path_candidate = right.name;
			continue;
		}
		if (left_op == CCS_TRANSIT_DOMAIN) {
			r->transition_candidate = right.name;
			continue;
		}
		return false;
	}
	return true;
}

/**
 * ccs_check_auto_domain_transition - Check "auto_domain_transition" entry.
 *
 * Returns nothing.
 *
 * If "auto_domain_transition" keyword was specified and transition to that
 * domain failed, the current thread will be killed by SIGKILL.
 */
static void ccs_check_auto_domain_transition(void)
{
#ifdef CONFIG_CCSECURITY_AUTO_DOMAIN_TRANSITION
	struct ccs_request_info r = { };
	const int idx = ccs_read_lock();
	r.type = CCS_MAC_AUTO_DOMAIN_TRANSITION;
	ccs_check_acl(&r, true);
	if (r.result != CCS_MATCHING_ALLOWED ||
	    ccs_transit_domain(r.transition->name))
		goto done;
	printk(KERN_WARNING "ERROR: Unable to transit to '%s' domain.\n",
	       r.transition->name);
	force_sig(SIGKILL, current);
done:
	ccs_read_unlock(idx);
#endif
}

/**
 * ccs_byte_range - Check whether the string is a \ooo style octal value.
 *
 * @str: Pointer to the string.
 *
 * Returns true if @str is a \ooo style octal value, false otherwise.
 */
static bool ccs_byte_range(const char *str)
{
	return *str >= '0' && *str++ <= '3' &&
		*str >= '0' && *str++ <= '7' &&
		*str >= '0' && *str <= '7';
}

/**
 * ccs_decimal - Check whether the character is a decimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a decimal character, false otherwise.
 */
static bool ccs_decimal(const char c)
{
	return c >= '0' && c <= '9';
}

/**
 * ccs_hexadecimal - Check whether the character is a hexadecimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a hexadecimal character, false otherwise.
 */
static bool ccs_hexadecimal(const char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

/**
 * ccs_alphabet_char - Check whether the character is an alphabet.
 *
 * @c: The character to check.
 *
 * Returns true if @c is an alphabet character, false otherwise.
 */
static bool ccs_alphabet_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/**
 * ccs_file_matches_pattern2 - Pattern matching without '/' character and "\-" pattern.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern2(const char *filename,
				      const char *filename_end,
				      const char *pattern,
				      const char *pattern_end)
{
	while (filename < filename_end && pattern < pattern_end) {
		char c;
		if (*pattern != '\\') {
			if (*filename++ != *pattern++)
				return false;
			continue;
		}
		c = *filename;
		pattern++;
		switch (*pattern) {
			int i;
			int j;
		case '?':
			if (c == '/') {
				return false;
			} else if (c == '\\') {
				if (ccs_byte_range(filename + 1))
					filename += 3;
				else
					return false;
			}
			break;
		case '+':
			if (!ccs_decimal(c))
				return false;
			break;
		case 'x':
			if (!ccs_hexadecimal(c))
				return false;
			break;
		case 'a':
			if (!ccs_alphabet_char(c))
				return false;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
			if (c == '\\' && ccs_byte_range(filename + 1)
			    && !strncmp(filename + 1, pattern, 3)) {
				filename += 3;
				pattern += 2;
				break;
			}
			return false; /* Not matched. */
		case '*':
		case '@':
			for (i = 0; i <= filename_end - filename; i++) {
				if (ccs_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
				c = filename[i];
				if (c == '.' && *pattern == '@')
					break;
				if (c != '\\')
					continue;
				if (ccs_byte_range(filename + i + 1))
					i += 3;
				else
					break; /* Bad pattern. */
			}
			return false; /* Not matched. */
		default:
			j = 0;
			c = *pattern;
			if (c == '$') {
				while (ccs_decimal(filename[j]))
					j++;
			} else if (c == 'X') {
				while (ccs_hexadecimal(filename[j]))
					j++;
			} else if (c == 'A') {
				while (ccs_alphabet_char(filename[j]))
					j++;
			}
			for (i = 1; i <= j; i++) {
				if (ccs_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
			}
			return false; /* Not matched or bad pattern. */
		}
		filename++;
		pattern++;
	}
	while (*pattern == '\\' &&
	       (*(pattern + 1) == '*' || *(pattern + 1) == '@'))
		pattern += 2;
	return filename == filename_end && pattern == pattern_end;
}

/**
 * ccs_file_matches_pattern - Pattern matching without '/' character.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern(const char *filename,
				     const char *filename_end,
				     const char *pattern,
				     const char *pattern_end)
{
	const char *pattern_start = pattern;
	bool first = true;
	bool result;
	while (pattern < pattern_end - 1) {
		/* Split at "\-" pattern. */
		if (*pattern++ != '\\' || *pattern++ != '-')
			continue;
		result = ccs_file_matches_pattern2(filename, filename_end,
						   pattern_start, pattern - 2);
		if (first)
			result = !result;
		if (result)
			return false;
		first = false;
		pattern_start = pattern;
	}
	result = ccs_file_matches_pattern2(filename, filename_end,
					   pattern_start, pattern_end);
	return first ? result : !result;
}

/**
 * ccs_path_matches_pattern2 - Do pathname pattern matching.
 *
 * @f: The start of string to check.
 * @p: The start of pattern to compare.
 *
 * Returns true if @f matches @p, false otherwise.
 */
static bool ccs_path_matches_pattern2(const char *f, const char *p)
{
	const char *f_delimiter;
	const char *p_delimiter;
	while (*f && *p) {
		f_delimiter = strchr(f, '/');
		if (!f_delimiter)
			f_delimiter = f + strlen(f);
		p_delimiter = strchr(p, '/');
		if (!p_delimiter)
			p_delimiter = p + strlen(p);
		if (*p == '\\' && *(p + 1) == '{')
			goto recursive;
		if (!ccs_file_matches_pattern(f, f_delimiter, p, p_delimiter))
			return false;
		f = f_delimiter;
		if (*f)
			f++;
		p = p_delimiter;
		if (*p)
			p++;
	}
	/* Ignore trailing "\*" and "\@" in @pattern. */
	while (*p == '\\' &&
	       (*(p + 1) == '*' || *(p + 1) == '@'))
		p += 2;
	return !*f && !*p;
recursive:
	/*
	 * The "\{" pattern is permitted only after '/' character.
	 * This guarantees that below "*(p - 1)" is safe.
	 * Also, the "\}" pattern is permitted only before '/' character
	 * so that "\{" + "\}" pair will not break the "\-" operator.
	 */
	if (*(p - 1) != '/' || p_delimiter <= p + 3 || *p_delimiter != '/' ||
	    *(p_delimiter - 1) != '}' || *(p_delimiter - 2) != '\\')
		return false; /* Bad pattern. */
	do {
		/* Compare current component with pattern. */
		if (!ccs_file_matches_pattern(f, f_delimiter, p + 2,
					      p_delimiter - 2))
			break;
		/* Proceed to next component. */
		f = f_delimiter;
		if (!*f)
			break;
		f++;
		/* Continue comparison. */
		if (ccs_path_matches_pattern2(f, p_delimiter + 1))
			return true;
		f_delimiter = strchr(f, '/');
	} while (f_delimiter);
	return false; /* Not matched. */
}

/**
 * ccs_path_matches_pattern - Check whether the given filename matches the given pattern.
 *
 * @filename: The filename to check.
 * @pattern:  The pattern to compare.
 *
 * Returns true if matches, false otherwise.
 *
 * The following patterns are available.
 *   \ooo   Octal representation of a byte.
 *   \*     Zero or more repetitions of characters other than '/'.
 *   \@     Zero or more repetitions of characters other than '/' or '.'.
 *   \?     1 byte character other than '/'.
 *   \$     One or more repetitions of decimal digits.
 *   \+     1 decimal digit.
 *   \X     One or more repetitions of hexadecimal digits.
 *   \x     1 hexadecimal digit.
 *   \A     One or more repetitions of alphabet characters.
 *   \a     1 alphabet character.
 *
 *   \-     Subtraction operator.
 *
 *   /\{dir\}/   '/' + 'One or more repetitions of dir/' (e.g. /dir/ /dir/dir/
 *               /dir/dir/dir/ ).
 */
static bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
				     const struct ccs_path_info *pattern)
{
	const char *f = filename->name;
	const char *p = pattern->name;
	const int len = pattern->const_len;
	/* If @pattern doesn't contain pattern, I can use strcmp(). */
	if (!pattern->is_patterned)
		return !ccs_pathcmp(filename, pattern);
	/* Don't compare directory and non-directory. */
	if (filename->is_dir != pattern->is_dir)
		return false;
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	return ccs_path_matches_pattern2(f, p);
}

/**
 * ccs_clear_request_info - Release memory allocated during permission check.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns nothing.
 */
static void ccs_clear_request_info(struct ccs_request_info *r)
{
	u8 i;
	/*
	 * r->obj.pathname[0] (which is referenced by r->obj.s[0]) and
	 * r->obj.pathname[1] (which is referenced by r->obj.s[1]) may contain
	 * pathnames allocated using ccs_populate_patharg() or ccs_mount_acl().
	 * Their callers do not allocate memory until pathnames becomes needed
	 * for checking condition or auditing requests.
	 *
	 * r->obj.s[2] and r->obj.s[3] are used by
	 * ccs_mount_acl()/ccs_env_perm() and are allocated/released by their
	 * callers.
	 */
	for (i = 0; i < 2; i++) {
		kfree(r->obj.pathname[i].name);
		r->obj.pathname[i].name = NULL;
	}
	kfree(r->exename.name);
	r->exename.name = NULL;
}
