/*
 * fs/tomoyo_cond.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.3   2006/11/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/realpath.h>
#include <linux/version.h>

char *FindConditionPart(char *data)
{
	char *cp = strstr(data, " if "), *cp2;
	if (cp) {
		while ((cp2 = strstr(cp + 4, " if ")) != NULL) cp = cp2;
		*cp++ = '\0';
	}
	return cp;
}

#define VALUE_TYPE_DECIMAL     1
#define VALUE_TYPE_OCTAL       2
#define VALUE_TYPE_HEXADECIMAL 3

static int parse_ulong(unsigned long *result, const char **str)
{
	const char *cp = *str;
	char *ep;
	int base = 10;
	if (*cp == '0') {
		char c = * (cp + 1);
		if (c == 'x' || c == 'X') {
			base = 16; cp += 2;
		} else if (c >= '0' && c <= '7') {
			base = 8; cp++;
		}
	}
	*result = simple_strtoul(cp, &ep, base);
	if (cp == ep) return 0;
	*str = ep;
	return (base == 16 ? VALUE_TYPE_HEXADECIMAL : (base == 8 ? VALUE_TYPE_OCTAL : VALUE_TYPE_DECIMAL));
}

static void print_ulong(char *buffer, const int buffer_len, const unsigned long value, const int type)
{
	if (type == VALUE_TYPE_DECIMAL) {
		snprintf(buffer, buffer_len, "%lu", value);
	} else if (type == VALUE_TYPE_OCTAL) {
		snprintf(buffer, buffer_len, "0%lo", value);
	} else {
		snprintf(buffer, buffer_len, "0x%lX", value);
	}
}
			
static struct condition_list {
	struct condition_list *next;
	int length;
	/* "unsigned long condition[length]" comes here.*/
} head = { NULL, 0 };

#define TASK_UID          0
#define TASK_EUID         1
#define TASK_SUID         2
#define TASK_FSUID        3
#define TASK_GID          4
#define TASK_EGID         5
#define TASK_SGID         6
#define TASK_FSGID        7
#define TASK_PID          8
#define TASK_PPID         9
#define PATH1_UID        10
#define PATH1_GID        11
#define PATH1_INO        12
#define PATH1_PARENT_UID 13
#define PATH1_PARENT_GID 14
#define PATH1_PARENT_INO 15
#define PATH2_PARENT_UID 16
#define PATH2_PARENT_GID 17
#define PATH2_PARENT_INO 18
#define MAX_KEYWORD      19

static struct {
	const char *keyword;
	const int keyword_len; /* strlen(keyword) */
} condition_control_keyword[MAX_KEYWORD] = {
	[TASK_UID]         = { "task.uid",           8 },
	[TASK_EUID]        = { "task.euid",          9 },
	[TASK_SUID]        = { "task.suid",          9 },
	[TASK_FSUID]       = { "task.fsuid",        10 },
	[TASK_GID]         = { "task.gid",           8 },
	[TASK_EGID]        = { "task.egid",          9 },
	[TASK_SGID]        = { "task.sgid",          9 },
	[TASK_FSGID]       = { "task.fsgid",        10 },
	[TASK_PID]         = { "task.pid",           8 },
	[TASK_PPID]        = { "task.ppid",          9 },
	[PATH1_UID]        = { "path1.uid",          9 },
	[PATH1_GID]        = { "path1.gid",          9 },
	[PATH1_INO]        = { "path1.ino",          9 },
	[PATH1_PARENT_UID] = { "path1.parent.uid",  16 },
	[PATH1_PARENT_GID] = { "path1.parent.gid",  16 },
	[PATH1_PARENT_INO] = { "path1.parent.ino",  16 },
	[PATH2_PARENT_UID] = { "path2.parent.uid",  16 },
	[PATH2_PARENT_GID] = { "path2.parent.gid",  16 },
	[PATH2_PARENT_INO] = { "path2.parent.ino",  16 }
};

const struct condition_list *FindOrAssignNewCondition(const char *condition)
{
	const char *start;
	struct condition_list *ptr, *new_ptr;
	unsigned long *ptr2;
	int counter = 0, size;
	int left, right;
	unsigned long left_min = 0, left_max = 0, right_min = 0, right_max = 0;
	if (strncmp(condition, "if ", 3)) return NULL;
	condition += 3;
	start = condition;
	while (*condition) {
		if (*condition == ' ') condition++;
		for (left = 0; left < MAX_KEYWORD; left++) {
			if (strncmp(condition, condition_control_keyword[left].keyword, condition_control_keyword[left].keyword_len) == 0) {
				condition += condition_control_keyword[left].keyword_len;
				break;
			}
		}
		if (left == MAX_KEYWORD) {
			if (!parse_ulong(&left_min, &condition)) goto out;
			counter++; // body
			if (*condition == '-') {
				condition++;
				if (!parse_ulong(&left_max, &condition) || left_min > left_max) goto out;
				counter++; // body
			}
		}
		if (strncmp(condition, "!=", 2) == 0) condition += 2;
		else if (*condition == '=') condition++;
		else goto out;
		counter++; // header
		for (right = 0; right < MAX_KEYWORD; right++) {
			if (strncmp(condition, condition_control_keyword[right].keyword, condition_control_keyword[right].keyword_len) == 0) {
				condition += condition_control_keyword[right].keyword_len;
				break;
			}
		}
		if (right == MAX_KEYWORD) {
			if (!parse_ulong(&right_min, &condition)) goto out;
			counter++; // body
			if (*condition == '-') {
				condition++;
				if (!parse_ulong(&right_max, &condition) || right_min > right_max) goto out;
				counter++; // body
			}
		}
	}
	size = sizeof(struct condition_list) + counter * sizeof(unsigned long);
	new_ptr = (struct condition_list *) ccs_alloc(size);
	if (!new_ptr) return NULL;
	new_ptr->length = counter;
	ptr2 = (unsigned long *) (((u8 *) new_ptr) + sizeof(struct condition_list));
	condition = start;
	while (*condition) {
		unsigned int match = 0;
		if (*condition == ' ') condition++;
		for (left = 0; left < MAX_KEYWORD; left++) {
			if (strncmp(condition, condition_control_keyword[left].keyword, condition_control_keyword[left].keyword_len) == 0) {
				condition += condition_control_keyword[left].keyword_len;
				break;
			}
		}
		if (left == MAX_KEYWORD) {
			match |= parse_ulong(&left_min, &condition) << 2;
			counter--; // body
			if (*condition == '-') {
				condition++;
				match |= parse_ulong(&left_max, &condition) << 4;
				counter--; // body
				left++;
			}
		}
		if (strncmp(condition, "!=", 2) == 0) {
			condition += 2;
		} else if (*condition == '=') {
			match |= 1; condition++;
		} else {
			goto out2;
		}
		counter--; // header
		for (right = 0; right < MAX_KEYWORD; right++) {
			if (strncmp(condition, condition_control_keyword[right].keyword, condition_control_keyword[right].keyword_len) == 0) {
				condition += condition_control_keyword[right].keyword_len;
				break;
			}
		}
		if (right == MAX_KEYWORD) {
			match |= parse_ulong(&right_min, &condition) << 6;
			counter--; // body
			if (*condition == '-') {
				condition++;
				match |= parse_ulong(&right_max, &condition) << 8;
				counter--; // body
				right++;
			}
		}
		if (counter < 0) goto out2;
		*ptr2++ = (match << 16) | (left << 8) | right;
		if (left >= MAX_KEYWORD) *ptr2++ = left_min;
		if (left == MAX_KEYWORD + 1) *ptr2++ = left_max;
		if (right >= MAX_KEYWORD) *ptr2++ = right_min;
		if (right == MAX_KEYWORD + 1) *ptr2++ = right_max;
	}
	{
		static DECLARE_MUTEX(lock);
		struct condition_list *prev = NULL;
		down(&lock);
		for (ptr = &head; ptr; prev = ptr, ptr = ptr->next) {
			if (ptr->length != new_ptr->length) continue;
			if (memcmp(((u8 *) ptr) + sizeof(struct condition_list *), ((u8 *) new_ptr) + sizeof(struct condition_list *), size - sizeof(struct condition_list *))) continue;
			/* Same entry found. Share this entry. */
			ccs_free(new_ptr);
			new_ptr = ptr;
			goto ok;
		}
		/* Same entry not found. Save this entry. */
		ptr = (struct condition_list *) alloc_element(size);
		if (ptr) memmove(ptr, new_ptr, size);
		ccs_free(new_ptr);
		new_ptr = ptr;
		/* Append to chain. */
		prev->next = new_ptr;
	ok:
		up(&lock);
	}
	return new_ptr;
 out2:
	ccs_free(new_ptr);
 out:
	return NULL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static void GetAttributes(struct obj_info *obj)
{
	struct dentry *dentry;
	struct inode *inode;

	dentry = obj->path1_dentry;
	if ((inode = dentry->d_inode) != NULL) {
		if (inode->i_op && inode->i_op->revalidate && inode->i_op->revalidate(dentry)) {
			// Nothing to do.
		} else {
			obj->path1_stat.uid = inode->i_uid;
			obj->path1_stat.gid = inode->i_gid;
			obj->path1_stat.ino = inode->i_ino;
			obj->path1_valid = 1;
		}
	}

	spin_lock(&dcache_lock);
	dentry = dget(obj->path1_dentry->d_parent);
	spin_unlock(&dcache_lock);
	inode = dentry->d_inode;
	if (inode) {
		if (inode->i_op && inode->i_op->revalidate && inode->i_op->revalidate(dentry)) {
			// Nothing to do.
		} else {
			obj->path1_parent_stat.uid = inode->i_uid;
			obj->path1_parent_stat.gid = inode->i_gid;
			obj->path1_parent_stat.ino = inode->i_ino;
			obj->path1_parent_valid = 1;
		}
	}
	dput(dentry);
	
	if (obj->path2_vfsmnt) {
		spin_lock(&dcache_lock);
		dentry = dget(obj->path2_dentry->d_parent);
		spin_unlock(&dcache_lock);
		inode = dentry->d_inode;
		if (inode) {
			if (inode->i_op && inode->i_op->revalidate && inode->i_op->revalidate(dentry)) {
				// Nothing to do.
			} else {
				obj->path2_parent_stat.uid = inode->i_uid;
				obj->path2_parent_stat.gid = inode->i_gid;
				obj->path2_parent_stat.ino = inode->i_ino;
				obj->path2_parent_valid = 1;
			}
		}
		dput(dentry);
	}
}
#else
static void GetAttributes(struct obj_info *obj)
{
	struct vfsmount *mnt;
	struct dentry *dentry;
	struct inode *inode;
	struct kstat stat;
	
	mnt = obj->path1_vfsmnt;
	dentry = obj->path1_dentry;
	inode = dentry->d_inode;
	if (inode) {
		if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
			// Nothing to do.
		} else {
			obj->path1_stat.uid = stat.uid;
			obj->path1_stat.gid = stat.gid;
			obj->path1_stat.ino = stat.ino;
			obj->path1_valid = 1;
		}
	}
	
	dentry = dget_parent(obj->path1_dentry);
	inode = dentry->d_inode;
	if (inode) {
		if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
			// Nothing to do.
		} else {
			obj->path1_parent_stat.uid = stat.uid;
			obj->path1_parent_stat.gid = stat.gid;
			obj->path1_parent_stat.ino = stat.ino;
			obj->path1_parent_valid = 1;
		}
	}
	dput(dentry);
	
	if ((mnt = obj->path2_vfsmnt) != NULL) {
		dentry = dget_parent(obj->path2_dentry);
		inode = dentry->d_inode;
		if (inode) {
			if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
				// Nothing to do.
			} else {
				obj->path2_parent_stat.uid = stat.uid;
				obj->path2_parent_stat.gid = stat.gid;
				obj->path2_parent_stat.ino = stat.ino;
				obj->path2_parent_valid = 1;
			}
		}
		dput(dentry);
	}
}
#endif

int CheckCondition(const struct condition_list *ptr, struct obj_info *obj)
{
	extern asmlinkage long sys_getppid(void);
	struct task_struct *task = current;
	int i;
	unsigned long left_min = 0, left_max = 0, right_min = 0, right_max = 0;
	const unsigned long *ptr2;
	if (!ptr) return 0;
	ptr2 = (unsigned long *) (((u8 *) ptr) + sizeof(struct condition_list));
	for (i = 0; i < ptr->length; i++) {
		const u8 match = ((*ptr2) >> 16) & 1, left = (*ptr2) >> 8, right = *ptr2;
		ptr2++;
		if ((left >= PATH1_UID && left < MAX_KEYWORD) || (right >= PATH1_UID && right < MAX_KEYWORD)) {
			if (!obj) goto out;
			if (!obj->validate_done) {
				GetAttributes(obj);
				obj->validate_done = 1;
			}
		}
		switch (left) {
		case TASK_UID:   left_min = left_max = task->uid; break;
		case TASK_EUID:  left_min = left_max = task->euid; break;
		case TASK_SUID:  left_min = left_max = task->suid; break;
		case TASK_FSUID: left_min = left_max = task->fsuid; break;
		case TASK_GID:   left_min = left_max = task->gid; break;
		case TASK_EGID:  left_min = left_max = task->egid; break;
		case TASK_SGID:  left_min = left_max = task->sgid; break;
		case TASK_FSGID: left_min = left_max = task->fsgid; break;
		case TASK_PID:   left_min = left_max = task->pid; break;
		case TASK_PPID:  left_min = left_max = sys_getppid(); break;
		case PATH1_UID:
			if (!obj->path1_valid) goto out;
			left_min = left_max = obj->path1_stat.uid; break;
		case PATH1_GID:
			if (!obj->path1_valid) goto out;
			left_min = left_max = obj->path1_stat.gid; break;
		case PATH1_INO:
			if (!obj->path1_valid) goto out;
			left_min = left_max = obj->path1_stat.ino; break;
		case PATH1_PARENT_UID:
			if (!obj->path1_parent_valid) goto out;
			left_min = left_max = obj->path1_parent_stat.uid; break;
		case PATH1_PARENT_GID:
			if (!obj->path1_parent_valid) goto out;
			left_min = left_max = obj->path1_parent_stat.gid; break;
		case PATH1_PARENT_INO:
			if (!obj->path1_parent_valid) goto out;
			left_min = left_max = obj->path1_parent_stat.ino; break;
		case PATH2_PARENT_UID:
			if (!obj->path2_parent_valid) goto out;
			left_min = left_max = obj->path2_parent_stat.uid; break;
		case PATH2_PARENT_GID:
			if (!obj->path2_parent_valid) goto out;
			left_min = left_max = obj->path2_parent_stat.gid; break;
		case PATH2_PARENT_INO:
			if (!obj->path2_parent_valid) goto out;
			left_min = left_max = obj->path2_parent_stat.ino; break;
		case MAX_KEYWORD:     left_min = left_max = *ptr2++; i++; break;
		case MAX_KEYWORD + 1: left_min = *ptr2++; left_max = *ptr2++; i += 2; break;
		}
		switch (right) {
		case TASK_UID:   right_min = right_max = task->uid; break;
		case TASK_EUID:  right_min = right_max = task->euid; break;
		case TASK_SUID:  right_min = right_max = task->suid; break;
		case TASK_FSUID: right_min = right_max = task->fsuid; break;
		case TASK_GID:   right_min = right_max = task->gid; break;
		case TASK_EGID:  right_min = right_max = task->egid; break;
		case TASK_SGID:  right_min = right_max = task->sgid; break;
		case TASK_FSGID: right_min = right_max = task->fsgid; break;
		case TASK_PID:   right_min = right_max = task->pid; break;
		case TASK_PPID:  right_min = right_max = sys_getppid(); break;
		case PATH1_UID:
			if (!obj->path1_valid) goto out;
			right_min = right_max = obj->path1_stat.uid; break;
		case PATH1_GID:
			if (!obj->path1_valid) goto out;
			right_min = right_max = obj->path1_stat.gid; break;
		case PATH1_INO:
			if (!obj->path1_valid) goto out;
			right_min = right_max = obj->path1_stat.ino; break;
		case PATH1_PARENT_UID:
			if (!obj->path1_parent_valid) goto out;
			right_min = right_max = obj->path1_parent_stat.uid; break;
		case PATH1_PARENT_GID:
			if (!obj->path1_parent_valid) goto out;
			right_min = right_max = obj->path1_parent_stat.gid; break;
		case PATH1_PARENT_INO:
			if (!obj->path1_parent_valid) goto out;
			right_min = right_max = obj->path1_parent_stat.ino; break;
		case PATH2_PARENT_UID:
			if (!obj->path2_parent_valid) goto out;
			right_min = right_max = obj->path2_parent_stat.uid; break;
		case PATH2_PARENT_GID:
			if (!obj->path2_parent_valid) goto out;
			right_min = right_max = obj->path2_parent_stat.gid; break;
		case PATH2_PARENT_INO:
			if (!obj->path2_parent_valid) goto out;
			right_min = right_max = obj->path2_parent_stat.ino; break;
		case MAX_KEYWORD:     right_min = right_max = *ptr2++; i++; break;
		case MAX_KEYWORD + 1: right_min = *ptr2++; right_max = *ptr2++; i += 2; break;
		}
		if (match) {
			if (left_min <= right_max && left_max >= right_min) continue;
		} else {
			if (left_min > right_max || left_max < right_min) continue;
		}
	out:
		return -EPERM;
	}
	return 0;
}

int DumpCondition(IO_BUFFER *head, const struct condition_list *ptr)
{
	if (ptr) {
		int i;
		const unsigned long *ptr2 = (unsigned long *) (((u8 *) ptr) + sizeof(struct condition_list));
		char buffer[32];
		memset(buffer, 0, sizeof(buffer));
		for (i = 0; i < ptr->length; i++) {
			const u16 match = (*ptr2) >> 16;
			const u8 left = (*ptr2) >> 8, right = *ptr2;
			ptr2++;
			if (io_printf(head, "%s", i ? " " : " if ")) break;
			if (left < MAX_KEYWORD) {
				if (io_printf(head, "%s", condition_control_keyword[left].keyword)) break;
			} else {
				print_ulong(buffer, sizeof(buffer) - 1, *ptr2++, (match >> 2) & 3);
				if (io_printf(head, "%s", buffer)) break;
				i++;
				if (left == MAX_KEYWORD + 1) {
					print_ulong(buffer, sizeof(buffer) - 1, *ptr2++, (match >> 4) & 3);
					if (io_printf(head, "-%s", buffer)) break;
					i++;
				}
			}
			if (io_printf(head, "%s", (match & 1) ? "=" : "!=")) break;
			if (right < MAX_KEYWORD) {
				if (io_printf(head, "%s", condition_control_keyword[right].keyword)) break;
			} else {
				print_ulong(buffer, sizeof(buffer) - 1, *ptr2++, (match >> 6) & 3);
				if (io_printf(head, "%s", buffer)) break;
				i++;
				if (right == MAX_KEYWORD + 1) {
					print_ulong(buffer, sizeof(buffer) - 1, *ptr2++, (match >> 8) & 3);
					if (io_printf(head, "-%s", buffer)) break;
					i++;
				}
			}
		}
		if (i < ptr->length) return -ENOMEM;
	}
	return io_printf(head, "\n") ? -ENOMEM : 0;
}

/***** TOMOYO Linux end. *****/
