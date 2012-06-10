/*
 * fs/sakura_mount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.2   2006/09/03
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#include <linux/namespace.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namei.h>
#else
static inline void module_put(struct module *module)
{
	if (module) __MOD_DEC_USE_COUNT(module);
}
#endif

extern const char *ccs_log_level;

/***** KEYWORDS for mount restrictions. *****/

#define MOUNT_BIND_KEYWORD    "--bind"    /* Allow to call 'mount --bind /source_dir /dest_dir' */
#define MOUNT_MOVE_KEYWORD    "--move"    /* Allow to call 'mount --move /old_dir    /new_dir ' */
#define MOUNT_REMOUNT_KEYWORD "--remount" /* Allow to call 'mount -o remount /dir             ' */
#define MOUNT_MAKE_UNBINDABLE_KEYWORD "--make-unbindable" /* Allow to call 'mount --make-unbindable /dir' */
#define MOUNT_MAKE_PRIVATE_KEYWORD    "--make-private"    /* Allow to call 'mount --make-private /dir'    */
#define MOUNT_MAKE_SLAVE_KEYWORD      "--make-slave"      /* Allow to call 'mount --make-slave /dir'      */
#define MOUNT_MAKE_SHARED_KEYWORD     "--make-shared"     /* Allow to call 'mount --make-shared /dir'     */

/***** The structure for mount restrictions. *****/

typedef struct mount_entry {
	struct mount_entry *next;      /* Pointer to next record. NULL if none. */
	int is_deleted;                /* Delete flag.                          */
	const char *dev_name;          /* Device file pattern. Never NULL.      */
	const char *dir_name;          /* Mount point pattern. Never NULL.      */
	const char *fs_type;           /* Filesystem type. Never NULL.          */
	unsigned int disabled_options; /* Options to forcefully disable.        */
	unsigned int enabled_options;  /* Options to forcefully enable.         */
} MOUNTS_ENTRY;

/*************************  MOUNT RESTRICTION HANDLER  *************************/

static void ParseMountOptions(char *arg, unsigned int *enabled_options, unsigned int *disabled_options)
{
	char *sp = arg, *cp;
	unsigned int enable = 0, disable = 0;
	while ((cp = strsep(&sp, " ,")) != NULL) {
		if (strcmp(cp, "rw") == 0)          disable |= MS_RDONLY;
		else if (strcmp(cp, "ro") == 0)     enable  |= MS_RDONLY;
		else if (strcmp(cp, "suid") == 0)   disable |= MS_NOSUID;
		else if (strcmp(cp, "nosuid") == 0) enable  |= MS_NOSUID;
		else if (strcmp(cp, "dev") == 0)    disable |= MS_NODEV;
		else if (strcmp(cp, "nodev") == 0)  enable  |= MS_NODEV;
		else if (strcmp(cp, "exec") == 0)   disable |= MS_NOEXEC;
		else if (strcmp(cp, "noexec") == 0) enable  |= MS_NOEXEC;
		else if (strcmp(cp, "atime") == 0)      disable |= MS_NOATIME;
		else if (strcmp(cp, "noatime") == 0)    enable  |= MS_NOATIME;
		else if (strcmp(cp, "diratime") == 0)   disable |= MS_NODIRATIME;
		else if (strcmp(cp, "nodiratime") == 0) enable  |= MS_NODIRATIME;
		else if (strcmp(cp, "norecurse") == 0)  disable |= MS_REC;
		else if (strcmp(cp, "recurse") == 0)    enable  |= MS_REC;
	}
	*enabled_options = enable;
	*disabled_options = disable;
}

static void MakeMountOptions(char *buffer, const int buffer_len, const unsigned int enabled, const unsigned int disabled)
{
	memset(buffer, 0, buffer_len);
	if (enabled == 0 && disabled == 0) {
		snprintf(buffer, buffer_len - 1, "defaults");
	} else {
		snprintf(buffer, buffer_len - 1, "%s%s%s%s%s%s%s",
				 enabled & MS_RDONLY     ? "ro "     :     (disabled & MS_RDONLY     ? "rw "        : ""),
				 enabled & MS_NOSUID     ? "nosuid " :     (disabled & MS_NOSUID     ? "suid "      : ""),
				 enabled & MS_NODEV      ? "nodev "  :     (disabled & MS_NODEV      ? "dev "       : ""),
				 enabled & MS_NOEXEC     ? "noexec " :     (disabled & MS_NOEXEC     ? "exec "      : ""),
				 enabled & MS_NOATIME    ? "noatime" :     (disabled & MS_NOATIME    ? "atime"      : ""),
				 enabled & MS_NODIRATIME ? "nodiratime " : (disabled & MS_NODIRATIME ? "diratime "  : ""),
				 enabled & MS_REC        ? "recurse " :    (disabled & MS_REC        ? "norecurse " : ""));
	}
}

static void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}

static MOUNTS_ENTRY mount_list = { NULL, 0, "", "", "", 0, 0 };

static int AddMountACL(const char *dev_name, const char *dir_name, const char *fs_type, const unsigned int enable, const unsigned int disable)
{
	MOUNTS_ENTRY *new_entry, *ptr;
	const char *fs, *dev, *dir;
	if (enable & disable) return -EINVAL; /* options mismatch. */
	if ((fs = SaveName(fs_type)) == NULL) goto out;
	if (!dev_name) dev_name = "<NULL>"; /* Map dev_name to "<NULL>" for if no dev_name given. */
	if (strcmp(fs, MOUNT_REMOUNT_KEYWORD) == 0) dev_name = "any"; /* Fix dev_name to "any" for remount permission. */
	if (strcmp(fs, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
		strcmp(fs, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
		strcmp(fs, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
		strcmp(fs, MOUNT_MAKE_SHARED_KEYWORD) == 0) dev_name = "any";
	if ((dev = SaveName(dev_name)) == NULL) goto out;
	if (strendswith(dir_name, "/") == 0 || (dir = SaveName(dir_name)) == NULL) goto out;
	
	/* I don't want to add if it was already added. */
	for (ptr = mount_list.next; ptr; ptr = ptr->next) {
		if (strcmp(ptr->dev_name, dev) == 0 && strcmp(ptr->dir_name, dir) == 0 && strcmp(ptr->fs_type, fs) == 0) {
			if (ptr->is_deleted) {
				ptr->enabled_options = enable;
				ptr->disabled_options = disable;
				ptr->is_deleted = 0;
			} else {
				if ((ptr->enabled_options & disable) || (ptr->disabled_options | enable)) goto out; /* options mismatch. */
				if ((ptr->enabled_options & enable) == enable && (ptr->disabled_options & disable) == disable) goto out; /* No changes. */
				ptr->enabled_options |= enable;
				ptr->disabled_options |= disable;
			}
			break;
		}
	}

	if (!ptr) {
		if ((new_entry = (MOUNTS_ENTRY *) alloc_element(sizeof(MOUNTS_ENTRY))) == NULL) goto out;
		new_entry->dev_name = dev;
		new_entry->dir_name = dir;
		new_entry->fs_type = fs;
		new_entry->enabled_options = enable;
		new_entry->disabled_options = disable;
		{
			static spinlock_t lock = SPIN_LOCK_UNLOCKED;
			/***** CRITICAL SECTION START *****/
			spin_lock(&lock);
			for (ptr = &mount_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
			spin_unlock(&lock);
			/***** CRITICAL SECTION END *****/
		}
		ptr = new_entry;
	}
	{
		struct file_system_type *type = NULL;
		char options[64];
		MakeMountOptions(options, sizeof(options), ptr->enabled_options, ptr->disabled_options);
		if (strcmp(fs, MOUNT_REMOUNT_KEYWORD) == 0) {
			printk("%sAllow remount %s with options %s.\n", ccs_log_level, dir, options);
		} else if (strcmp(fs, MOUNT_BIND_KEYWORD) == 0 || strcmp(fs, MOUNT_MOVE_KEYWORD) == 0) {
			printk("%sAllow mount %s %s %s\n", ccs_log_level, fs, dev, dir);
		} else if (strcmp(fs, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
				   strcmp(fs, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
				   strcmp(fs, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
				   strcmp(fs, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
			printk("%sAllow mount %s %s with options %s.\n", ccs_log_level, fs, dir, options);
		} else if ((type = get_fs_type(fs)) != NULL && (type->fs_flags & FS_REQUIRES_DEV) != 0) {
			printk("%sAllow mount -t %s %s %s with options %s.\n", ccs_log_level, fs, dev, dir, options);
		} else {
			printk("%sAllow mount %s on %s with options %s.\n", ccs_log_level, fs, dir, options);
		}
		if (type) put_filesystem(type);
	}
 out:
	return 0;
}

int CheckMountPermission(char *dev_name, char *dir_name, char *type, unsigned long *flags)
{
	const int is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_MOUNT);
	int error_flag = 1;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_MOUNT)) return 0;
	if (!type) type = "<NULL>";
	if ((*flags & MS_MGC_MSK) == MS_MGC_VAL) *flags &= ~MS_MGC_MSK;
	switch (*flags & (MS_REMOUNT | MS_MOVE | MS_BIND)) {
	case MS_REMOUNT:
	case MS_MOVE:
	case MS_BIND:
	case 0:
		break;
	default:
		printk("SAKURA-ERROR: %s%s%sare given for single mount operation.\n",
			   *flags & MS_REMOUNT ? "'remount' " : "",
			   *flags & MS_MOVE    ? "'move' " : "",
			   *flags & MS_BIND    ? "'bind' " : "");
		return -EINVAL;
	}
	switch (*flags & (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED)) {
	case MS_UNBINDABLE:
	case MS_PRIVATE:
	case MS_SLAVE:
	case MS_SHARED:
	case 0:
		break;
	default:
		printk("SAKURA-ERROR: %s%s%s%sare given for single mount operation.\n",
			   *flags & MS_UNBINDABLE ? "'unbindable' " : "",
			   *flags & MS_PRIVATE    ? "'private' " : "",
			   *flags & MS_SLAVE      ? "'slave' " : "",
			   *flags & MS_SHARED     ? "'shared' " : "");
		return -EINVAL;
	}
	if (*flags & MS_REMOUNT) {
		*flags &= ~MS_REMOUNT;
		error_flag = CheckMountPermission(dev_name, dir_name, MOUNT_REMOUNT_KEYWORD, flags);
		*flags |= MS_REMOUNT;
	} else if (*flags & MS_MOVE) {
		*flags &= ~MS_MOVE;
		error_flag = CheckMountPermission(dev_name, dir_name, MOUNT_MOVE_KEYWORD, flags);
		*flags |= MS_MOVE;
	} else if (*flags & MS_BIND) {
		*flags &= ~MS_BIND;
		error_flag = CheckMountPermission(dev_name, dir_name, MOUNT_BIND_KEYWORD, flags);
		*flags |= MS_BIND;
	} else if (*flags & MS_UNBINDABLE) {
		*flags &= ~MS_UNBINDABLE;
		error_flag = CheckMountPermission(dev_name, dir_name, MOUNT_MAKE_UNBINDABLE_KEYWORD, flags);
		*flags |= MS_UNBINDABLE;
	} else if (*flags & MS_PRIVATE) {
		*flags &= ~MS_PRIVATE;
		error_flag = CheckMountPermission(dev_name, dir_name, MOUNT_MAKE_PRIVATE_KEYWORD, flags);
		*flags |= MS_PRIVATE;
	} else if (*flags & MS_SLAVE) {
		*flags &= ~MS_SLAVE;
		error_flag = CheckMountPermission(dev_name, dir_name, MOUNT_MAKE_SLAVE_KEYWORD, flags);
		*flags |= MS_SLAVE;
	} else if (*flags & MS_SHARED) {
		*flags &= ~MS_SHARED;
		error_flag = CheckMountPermission(dev_name, dir_name, MOUNT_MAKE_SHARED_KEYWORD, flags);
		*flags |= MS_SHARED;
	} else {
		goto normal_mount;
	}
	if (error_flag) {
		if (is_enforce) return -EPERM;
		return 0;
	}
 normal_mount: ;
	{
		MOUNTS_ENTRY *ptr;
		struct file_system_type *fstype = NULL;
		const char *requested_dir_name = NULL;
		const char *requested_dev_name = NULL;
		int need_dev = 0;
		
		if ((requested_dir_name = realpath(dir_name)) == NULL) goto cleanup;

		/* Compare fs name. */
		if (strcmp(type, MOUNT_REMOUNT_KEYWORD) == 0) {
			/* Needn't to resolve dev_name */
		} else if (strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
			/* Needn't to resolve dev_name */
		} else if (strcmp(type, MOUNT_BIND_KEYWORD) == 0 || strcmp(type, MOUNT_MOVE_KEYWORD) == 0) {
			if ((requested_dev_name = realpath(dev_name)) == NULL) goto cleanup;
			need_dev = -1;
		} else if ((fstype = get_fs_type(type)) != NULL) {
			if (fstype->fs_flags & FS_REQUIRES_DEV) {
				if ((requested_dev_name = realpath(dev_name)) == NULL) goto cleanup;
				need_dev = 1;
			}
		} else {
			goto cleanup;
		}
		for (ptr = mount_list.next; ptr; ptr = ptr->next) {
			if (ptr->is_deleted) continue;
			
			/* Compare fs name. */
			if (strcmp(type, ptr->fs_type)) continue;
			
			/* Compare mount point. */
			if (PathMatchesToPattern(requested_dir_name, ptr->dir_name) == 0) continue;
			
			/* Compare device name. */
			if (requested_dev_name && PathMatchesToPattern(requested_dev_name, ptr->dev_name) == 0) continue;
			
			/* OK. */
			error_flag = 0;
			*flags &= ~ptr->disabled_options;
			*flags |= ptr->enabled_options;
			
			if (need_dev > 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount -t %s %s %s' accepted.\n", type, requested_dev_name, requested_dir_name);
			} else if (need_dev < 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount %s %s %s' accepted.\n", type, requested_dev_name, requested_dir_name);
			} else if (strcmp(type, MOUNT_REMOUNT_KEYWORD) == 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount -o remount %s' accepted.\n", requested_dir_name);
			} else if (strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
					   strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
					   strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
					   strcmp(type, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount %s %s' accepted.\n", type, requested_dir_name);
			} else {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount %s on %s' accepted.\n", type, requested_dir_name);
			}
			break;
		}
		if (error_flag && !is_enforce && CheckCCSAccept(CCS_SAKURA_RESTRICT_MOUNT)) {
			AddMountACL(need_dev ? requested_dev_name : dev_name, requested_dir_name, type, 0, 0);
		}
	cleanup:
		if (requested_dev_name) ccs_free(requested_dev_name);
		if (requested_dir_name) ccs_free(requested_dir_name);
		if (fstype) put_filesystem(fstype);
	}

	if (error_flag) {
		int error = -EPERM;
		const int is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_MOUNT);
		const char *realname1 = realpath(dev_name), *realname2 = realpath(dir_name), *exename = GetEXE();
		if (strcmp(type, MOUNT_REMOUNT_KEYWORD) == 0) {
			printk("SAKURA-%s: mount -o remount %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), realname2 ? realname2 : dir_name, current->pid, exename);
			if (is_enforce && CheckSupervisor("# %s is requesting\nmount -o remount %s\n", exename, realname2 ? realname2 : dir_name) == 0) error = 0;
		} else if (strcmp(type, MOUNT_BIND_KEYWORD) == 0 || strcmp(type, MOUNT_MOVE_KEYWORD) == 0) {
			printk("SAKURA-%s: mount %s %s %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name, current->pid, exename);
			if (is_enforce && CheckSupervisor("# %s is requesting\nmount %s %s %s\n", exename, type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name) == 0) error = 0;
		} else if (strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
			printk("SAKURA-%s: mount %s %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), type, realname2 ? realname2 : dir_name, current->pid, exename);
			if (is_enforce && CheckSupervisor("# %s is requesting\nmount %s %s", exename, type, realname2 ? realname2 : dir_name) == 0) error = 0;
		} else {
			printk("SAKURA-%s: mount -t %s %s %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name, current->pid, exename);
			if (is_enforce && CheckSupervisor("# %s is requesting\nmount -t %s %s %s\n", exename, type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name) == 0) error = 0;
		}
		if (exename) ccs_free(exename);
		if (realname2) ccs_free(realname2);
		if (realname1) ccs_free(realname1);
		if (is_enforce) return error;
	}
	return 0;
}

int AddMountPolicy(char *data, const int is_delete)
{
	MOUNTS_ENTRY *ptr;
	char *cp, *cp2;
	const char *fs, *dev, *dir;
	unsigned int enable = 0, disable = 0;
	NormalizeLine(data);
	cp2 = data; if ((cp = strchr(cp2, ' ')) == NULL) goto out; *cp = '\0'; dev = cp2;
	cp2 = cp + 1; if ((cp = strchr(cp2, ' ')) == NULL) goto out; *cp = '\0'; dir = cp2;
	cp2 = cp + 1;
	if ((cp = strchr(cp2, ' ')) != NULL) {
		*cp = '\0';
		ParseMountOptions(cp + 1, &enable, &disable);
	}
	fs = cp2;
	if (!is_delete) return AddMountACL(dev, dir, fs, enable, disable);
	for (ptr = mount_list.next; ptr; ptr = ptr->next) {
		if (strcmp(ptr->dev_name, dev) == 0 && strcmp(ptr->dir_name, dir) == 0 && strcmp(ptr->fs_type, fs) == 0 &&
			ptr->disabled_options == disable && ptr->enabled_options == enable) {
			ptr->is_deleted = 1;
		}
	}
	return 0;
 out:
	return -EINVAL;
}

int ReadMountPolicy(IO_BUFFER *head)
{
	MOUNTS_ENTRY *ptr = (MOUNTS_ENTRY *) head->read_var2;
	if (!ptr) ptr = mount_list.next;
	while (ptr) {
		char options[64];
		head->read_var2 = (void *) ptr;
		MakeMountOptions(options, sizeof(options), ptr->enabled_options, ptr->disabled_options);
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_ALLOW_MOUNT "%s %s %s %s\n", ptr->dev_name, ptr->dir_name, ptr->fs_type, options)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(CheckMountPermission);

/***** SAKURA Linux end. *****/
