/*
 * fs/tomoyo_cond.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/03/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/realpath.h>
#include <linux/version.h>

#include <linux/tomoyo.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>

static bool ScanBprm(struct linux_binprm *bprm, const bool is_argv, unsigned long index, const struct path_info *name, const struct path_info *value, bool *failed, struct ccs_page_buffer *tmp)
{
	/*
	  if exec.argc=3                  // if (argc == 3)
	  if exec.argv[1]="-c"            // if (argc >= 2 && strcmp(argv[1], "-c") == 0)
	  if exec.argv[1]!="-c"           // if (argc < 2 || strcmp(argv[1], "-c"))
	  if exec.envc=10-20              // if (envc >= 10 && envc <= 20)
	  if exec.envc!=10-20             // if (envc < 10 || envc > 20)
	  if exec.envp["HOME"]!=NULL      // if (getenv("HOME"))
	  if exec.envp["HOME"]=NULL       // if (!getenv("HOME"))
	  if exec.envp["HOME"]="/"        // if (getenv("HOME") && strcmp(getenv("HOME"), "/") == 0)
	  if exec.envp["HOME"]!="/"       // if (!getenv("HOME") || strcmp(getenv("HOME", "/"))
	*/
	char *arg_ptr = tmp->buffer;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int i = pos / PAGE_SIZE, offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool result = false;
	while (argv_count || envp_count) {
		struct page *page;
		const char *kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0) {
			*failed = true;
			printk("get_user_pages() failed\n");
			goto out;
		}
		pos += PAGE_SIZE - offset;
#else
		page = bprm->page[i];
#endif
		/* Map. */
		kaddr = kmap(page);
		if (!kaddr) { /* Mapping failed. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
			put_page(page);
#endif
			*failed = true;
			printk("kmap() failed\n");
			goto out;
		}
		while (offset < PAGE_SIZE) {
			/* Read. */
			struct path_info arg;
			const unsigned char c = kaddr[offset++];
			arg.name = arg_ptr;
			if (c && arg_len < CCS_MAX_PATHNAME_LEN - 10) {
				if (c == '\\') {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = '\\';
				} else if (c > ' ' && c < 127) {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++] = ((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
			} else {
				arg_ptr[arg_len] = '\0';
			}
			if (c) continue;
			/* Check. */
			if (argv_count) {
				if (is_argv && bprm->argc - argv_count == index) {
					fill_path_info(&arg);
					result = PathMatchesToPattern(&arg, value);
					argv_count = envp_count = 0;
					break;
				}
				if (--argv_count == 0 && is_argv) {
					envp_count = 0;
					break;
				}
			} else if (envp_count) {
				char *cp = strchr(arg_ptr, '=');
				if (cp) {
					*cp = '\0';
					fill_path_info(&arg);
					if (PathMatchesToPattern(&arg, name)) {
						if (value) {
							arg.name = cp + 1;
							fill_path_info(&arg);
							if (PathMatchesToPattern(&arg, value)) result = true;
						} else {
							result = true;
						}
						if (result) {
							envp_count = 0;
							break;
						}
					}
				}
				if (--envp_count == 0) break;
			} else {
				break;
			}
			arg_len = 0;
		}
		/* Unmap. */
		kunmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		put_page(page);
#endif
		i++;
		offset = 0;
	}
 out:
	return result;
}

#define VALUE_TYPE_DECIMAL     1
#define VALUE_TYPE_OCTAL       2
#define VALUE_TYPE_HEXADECIMAL 3

/* Don't use u8 because we use "<< 8". */
static u16 parse_ulong(unsigned long *result, char **str)
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

union element {
	const struct path_info *string;
	unsigned long value;
};

struct condition_list {
	struct list1_head list;
	u32 length;
	u8 post_state[4];
	/* "union element condition[length]" comes here.*/
};

static LIST1_HEAD(condition_list);

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
#define EXEC_ARGC        19
#define EXEC_ENVC        20
#define EXEC_ARGV        21
#define EXEC_ENVP        22
#define TASK_STATE_0     23
#define TASK_STATE_1     24
#define TASK_STATE_2     25
#define MAX_KEYWORD      26

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
	[PATH2_PARENT_INO] = { "path2.parent.ino",  16 },
	[EXEC_ARGC]        = { "exec.argc",          9 },
	[EXEC_ENVC]        = { "exec.envc",          9 },
	[EXEC_ARGV]        = { "exec.argv[",        10 },
	[EXEC_ENVP]        = { "exec.envp[\"",      11 },
	[TASK_STATE_0]     = { "task.state[0]",     13 },
	[TASK_STATE_1]     = { "task.state[1]",     13 },
	[TASK_STATE_2]     = { "task.state[2]",     13 },
};

const struct condition_list *FindOrAssignNewCondition(char *condition)
{
	char *start = condition;
	struct condition_list *new_ptr;
	union element *ptr2;
	u32 counter = 0, size;
	u8 left, right, i;
	unsigned long left_min = 0, left_max = 0, right_min = 0, right_max = 0;
	const struct path_info *left_name = NULL, *right_name = NULL;
	u8 post_state[4] = { 0, 0, 0, 0 };
	if ((condition = strstr(condition, "; set ")) != NULL) {
		*condition = '\0';
		condition += 6;
		while (1) {
			while (*condition == ' ') condition++;
			if (!*condition) break;
			if (strncmp(condition, "task.state[0]=", 14) == 0) i = 0;
			else if (strncmp(condition, "task.state[1]=", 14) == 0) i = 1;
			else if (strncmp(condition, "task.state[2]=", 14) == 0) i = 2;
			else goto out;
			condition += 14;
			if (post_state[3] & (1 << i)) goto out;
			post_state[3] |= 1 << i;
			if (!parse_ulong(&right_min, &condition) || right_min > 255) goto out;
			post_state[i] = (u8) right_min;
		}
	}
	condition = start;
	if (strncmp(condition, "if ", 3) == 0) condition += 3;
	else if (*condition) return NULL;
	start = condition;
	while (1) {
		while (*condition == ' ') condition++;
		if (!*condition) break;
		for (left = 0; left < MAX_KEYWORD; left++) {
			if (strncmp(condition, condition_control_keyword[left].keyword, condition_control_keyword[left].keyword_len) == 0) {
				condition += condition_control_keyword[left].keyword_len;
				break;
			}
		}
		if (left == EXEC_ARGV) {
			if (!parse_ulong(&left_min, &condition)) goto out;
			if (*condition++ != ']') goto out;
			counter++; /* body */
		} else if (left == EXEC_ENVP) {
			char *tmp = condition;
			while (1) {
				const char c = *condition;
				/*
				 * Since environment variable names don't contain '=',
				 * I can treat '"]=' and '"]!=' sequences as delimiters.
				 */
				if (strncmp(condition, "\"]=", 3) == 0 || strncmp(condition, "\"]!=", 4) == 0) break;
				if (!c || c == ' ') goto out;
				condition++;
			}
			*condition = '\0';
			if (!SaveName(tmp)) goto out;
			counter++; /* body */
			*condition = '"';
			condition += 2;
		} else if (left == MAX_KEYWORD) {
			if (!parse_ulong(&left_min, &condition)) goto out;
			counter++; /* body */
			if (*condition == '-') {
				condition++;
				if (!parse_ulong(&left_max, &condition) || left_min > left_max) goto out;
				counter++; /* body */
			}
		}
		if (strncmp(condition, "!=", 2) == 0) condition += 2;
		else if (*condition == '=') condition++;
		else goto out;
		counter++; /* header */
		if (left == EXEC_ENVP && strncmp(condition, "NULL", 4) == 0) {
			char c;
			condition += 4;
			c = *condition;
			counter++; /* body */
			if (!c || c == ' ') continue;
			goto out;
		} else if (left == EXEC_ARGV || left == EXEC_ENVP) {
			char c;
			char *tmp;
			if (*condition++ != '"') goto out;
			tmp = condition;
			while (1) {
				c = *condition++;
				if (!c || c == ' ') goto out;
				if (c != '"') continue;
				c = *condition;
				if (!c || c == ' ') break;
			}
			c = *--condition;
			*condition = '\0';
			if (!SaveName(tmp)) goto out;
			counter++; /* body */
			*condition = c;
			condition++;
			continue;
		}
		for (right = 0; right < MAX_KEYWORD; right++) {
			if (strncmp(condition, condition_control_keyword[right].keyword, condition_control_keyword[right].keyword_len) == 0) {
				condition += condition_control_keyword[right].keyword_len;
				break;
			}
		}
		if (right == MAX_KEYWORD) {
			if (!parse_ulong(&right_min, &condition)) goto out;
			counter++; /* body */
			if (*condition == '-') {
				condition++;
				if (!parse_ulong(&right_max, &condition) || right_min > right_max) goto out;
				counter++; /* body */
			}
		}
	}
	size = sizeof(*new_ptr) + counter * sizeof(union element);
	new_ptr = ccs_alloc(size);
	if (!new_ptr) return NULL;
	new_ptr->length = counter;
	for (i = 0; i < 4; i++) new_ptr->post_state[i] = post_state[i];
	ptr2 = (union element *) (((u8 *) new_ptr) + sizeof(*new_ptr));
	condition = start;
	while (1) {
		unsigned int match = 0;
		while (*condition == ' ') condition++;
		if (!*condition) break;
		for (left = 0; left < MAX_KEYWORD; left++) {
			if (strncmp(condition, condition_control_keyword[left].keyword, condition_control_keyword[left].keyword_len) == 0) {
				condition += condition_control_keyword[left].keyword_len;
				break;
			}
		}
		if (left == EXEC_ARGV) {
			if (!parse_ulong(&left_min, &condition)) goto out;
			if (*condition++ != ']') goto out;
			counter--; /* body */
		} else if (left == EXEC_ENVP) {
			char *tmp = condition;
			while (1) {
				char c = *condition;
				/*
				 * Since environment variable names don't contain '=',
				 * I can treat "\"]=" and "\"]!=" sequences as delimiters.
				 */
				if (strncmp(condition, "\"]=", 3) == 0 || strncmp(condition, "\"]!=", 4) == 0) break;
				if (!c || c == ' ') goto out;
				condition++;
			}
			*condition = '\0';
			left_name = SaveName(tmp);
			BUG_ON(!left_name);
			counter--; /* body */
			*condition = '\"';
			condition += 2;
		} else if (left == MAX_KEYWORD) {
			match |= parse_ulong(&left_min, &condition) << 2;
			counter--; /* body */
			if (*condition == '-') {
				condition++;
				match |= parse_ulong(&left_max, &condition) << 4;
				counter--; /* body */
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
		counter--; /* header */
		if (left == EXEC_ENVP && strncmp(condition, "NULL", 4) == 0) {
			char c;
			condition += 4;
			right_name = NULL;
			counter--; /* body */
			c = *condition;
			if (c && c != ' ') goto out;
			right = 0;
			goto skip_right;
		} else if (left == EXEC_ARGV || left == EXEC_ENVP) {
			char c;
			char *tmp;
			if (*condition++ != '"') goto out;
			tmp = condition;
			while (1) {
				c = *condition++;
				if (!c || c == ' ') goto out;
				if (c != '"') continue;
				c = *condition;
				if (!c || c == ' ') break;
			}
			c = *--condition;
			*condition = '\0';
			right_name = SaveName(tmp);
			BUG_ON(!right_name);
			counter--; /* body */
			*condition = c;
			condition++;
			right = 0;
			goto skip_right;
		}
		for (right = 0; right < MAX_KEYWORD; right++) {
			if (strncmp(condition, condition_control_keyword[right].keyword, condition_control_keyword[right].keyword_len) == 0) {
				condition += condition_control_keyword[right].keyword_len;
				break;
			}
		}
		if (right == MAX_KEYWORD) {
			match |= parse_ulong(&right_min, &condition) << 6;
			counter--; /* body */
			if (*condition == '-') {
				condition++;
				match |= parse_ulong(&right_max, &condition) << 8;
				counter--; /* body */
				right++;
			}
		}
skip_right:
		if (counter < 0) {
			WARN_ON(counter < 0);
			goto out2;
		}
		ptr2->value = (match << 16) | (left << 8) | right;
		ptr2++;
		if (left == EXEC_ARGV) { ptr2->value = left_min; ptr2++; }
		if (left == EXEC_ENVP) { ptr2->string = left_name; ptr2++; }
		if (left == EXEC_ARGV || left == EXEC_ENVP) { ptr2->string = right_name; ptr2++; }
		if (left >= MAX_KEYWORD) { ptr2->value = left_min; ptr2++; }
		if (left == MAX_KEYWORD + 1) { ptr2->value = left_max; ptr2++; }
		if (right >= MAX_KEYWORD) { ptr2->value = right_min; ptr2++; }
		if (right == MAX_KEYWORD + 1) { ptr2->value = right_max; ptr2++; }
	}
	WARN_ON(counter);
	{
		static DEFINE_MUTEX(lock);
		struct condition_list *ptr;
		mutex_lock(&lock);
		list1_for_each_entry(ptr, &condition_list, list) {
			/* Don't compare if size differs. */
			if (ptr->length != new_ptr->length) continue;
			/* Compare ptr and new_ptr except ptr->list and new_ptr->list . */
			if (memcmp(((u8 *) ptr) + sizeof(ptr->list), ((u8 *) new_ptr) + sizeof(new_ptr->list), size - sizeof(ptr->list))) continue;
			/* Same entry found. Share this entry. */
			ccs_free(new_ptr);
			new_ptr = ptr;
			goto ok;
		}
		/* Same entry not found. Save this entry. */
		ptr = alloc_element(size);
		if (ptr) {
			memmove(ptr, new_ptr, size);
			/* Append to chain. */
			list1_add_tail_mb(&ptr->list, &condition_list);
		}
		ccs_free(new_ptr);
		new_ptr = ptr;
	ok:
		mutex_unlock(&lock);
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
			/* Nothing to do. */
		} else {
			obj->path1_stat.uid = inode->i_uid;
			obj->path1_stat.gid = inode->i_gid;
			obj->path1_stat.ino = inode->i_ino;
			obj->path1_valid = true;
		}
	}

	spin_lock(&dcache_lock);
	dentry = dget(obj->path1_dentry->d_parent);
	spin_unlock(&dcache_lock);
	inode = dentry->d_inode;
	if (inode) {
		if (inode->i_op && inode->i_op->revalidate && inode->i_op->revalidate(dentry)) {
			/* Nothing to do. */
		} else {
			obj->path1_parent_stat.uid = inode->i_uid;
			obj->path1_parent_stat.gid = inode->i_gid;
			obj->path1_parent_stat.ino = inode->i_ino;
			obj->path1_parent_valid = true;
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
				/* Nothing to do. */
			} else {
				obj->path2_parent_stat.uid = inode->i_uid;
				obj->path2_parent_stat.gid = inode->i_gid;
				obj->path2_parent_stat.ino = inode->i_ino;
				obj->path2_parent_valid = true;
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
			/* Nothing to do. */
		} else {
			obj->path1_stat.uid = stat.uid;
			obj->path1_stat.gid = stat.gid;
			obj->path1_stat.ino = stat.ino;
			obj->path1_valid = true;
		}
	}

	dentry = dget_parent(obj->path1_dentry);
	inode = dentry->d_inode;
	if (inode) {
		if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
			/* Nothing to do. */
		} else {
			obj->path1_parent_stat.uid = stat.uid;
			obj->path1_parent_stat.gid = stat.gid;
			obj->path1_parent_stat.ino = stat.ino;
			obj->path1_parent_valid = true;
		}
	}
	dput(dentry);

	if ((mnt = obj->path2_vfsmnt) != NULL) {
		dentry = dget_parent(obj->path2_dentry);
		inode = dentry->d_inode;
		if (inode) {
			if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
				/* Nothing to do. */
			} else {
				obj->path2_parent_stat.uid = stat.uid;
				obj->path2_parent_stat.gid = stat.gid;
				obj->path2_parent_stat.ino = stat.ino;
				obj->path2_parent_valid = true;
			}
		}
		dput(dentry);
	}
}
#endif

bool CheckCondition(const struct acl_info *acl, struct obj_info *obj)
{
	struct task_struct *task = current;
	u32 i;
	unsigned long left_min = 0, left_max = 0, right_min = 0, right_max = 0;
	const union element *ptr2;
	const struct condition_list *ptr = GetConditionPart(acl);
	struct linux_binprm *bprm;
	bool failed = false;
	if (!ptr) return true;
	bprm = obj->bprm;
	ptr2 = (union element *) (((u8 *) ptr) + sizeof(*ptr));
	for (i = 0; i < ptr->length; i++) {
		const bool match = ((ptr2->value) >> 16) & 1;
		const u8 left = (ptr2->value) >> 8, right = ptr2->value;
		ptr2++;
		if (left == EXEC_ARGV) {
			bool result;
			unsigned long index;
			const struct path_info *value;
			index = ptr2->value; ptr2++; i++;
			value = ptr2->string; ptr2++; i++;
			if (!bprm) goto out;
			result = ScanBprm(bprm, true, index, NULL, value, &failed, obj->tmp);
			if (failed) goto out;
			if (!match) result = !result;
			if (result) continue;
			goto out;
		} else if (left == EXEC_ENVP) {
			bool result;
			const struct path_info *name, *value;
			name = ptr2->string; ptr2++; i++;
			value = ptr2->string; ptr2++; i++;
			if (!bprm) goto out;
			result = ScanBprm(bprm, false, 0, name, value, &failed, obj->tmp);
			if (failed) goto out;
			if (value) {
				if (!match) result = !result;
			} else {
				if (match) result = !result;
			}
			if (result) continue;
			goto out;
		}
		if ((left >= PATH1_UID && left < MAX_KEYWORD) || (right >= PATH1_UID && right < MAX_KEYWORD)) {
			if (!obj) goto out;
			if (!obj->validate_done) {
				GetAttributes(obj);
				obj->validate_done = true;
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
		case EXEC_ARGC:
			if (!bprm) goto out;
			left_min = left_max = bprm->argc; i++; break;
		case EXEC_ENVC:
			if (!bprm) goto out;
			left_min = left_max = bprm->envc; i++; break;
		case TASK_STATE_0: left_min = left_max = (u8) (task->tomoyo_flags >> 24); break;
		case TASK_STATE_1: left_min = left_max = (u8) (task->tomoyo_flags >> 16); break;
		case TASK_STATE_2: left_min = left_max = (u8) (task->tomoyo_flags >> 8); break;
		case MAX_KEYWORD:     left_min = left_max = ptr2->value; ptr2++; i++; break;
		case MAX_KEYWORD + 1: left_min = ptr2->value; ptr2++; left_max = ptr2->value; ptr2++; i += 2; break;
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
		case EXEC_ARGC:
			if (!bprm) goto out;
			right_min = right_max = bprm->argc; i++; break;
		case EXEC_ENVC:
			if (!bprm) goto out;
			right_min = right_max = bprm->envc; i++; break;
		case TASK_STATE_0: right_min = right_max = (u8) (task->tomoyo_flags >> 24); break;
		case TASK_STATE_1: right_min = right_max = (u8) (task->tomoyo_flags >> 16); break;
		case TASK_STATE_2: right_min = right_max = (u8) (task->tomoyo_flags >> 8); break;
		case MAX_KEYWORD:     right_min = right_max = ptr2->value; ptr2++; i++; break;
		case MAX_KEYWORD + 1: right_min = ptr2->value; ptr2++; right_max = ptr2->value; ptr2++; i += 2; break;
		}
		if (match) {
			if (left_min <= right_max && left_max >= right_min) continue;
		} else {
			if (left_min > right_max || left_max < right_min) continue;
		}
	out:
		return false;
	}
	return true;
}

void UpdateCondition(const struct acl_info *acl)
{
	/* Don't change lower bits because TOMOYO_CHECK_READ_FOR_OPEN_EXEC
	   and CCS_DONT_SLEEP_ON_ENFORCE_ERROR needs them. */
	const struct condition_list *ptr = GetConditionPart(acl);
	struct task_struct *task;
	u32 tomoyo_flags = current->tomoyo_flags;
	const u8 flags = ptr ? ptr->post_state[3] : 0;
	if (!flags) return;
	task = current;
	tomoyo_flags = task->tomoyo_flags;
	if (flags & 1) { tomoyo_flags &= ~0xFF000000; tomoyo_flags |= ptr->post_state[0] << 24; }
	if (flags & 2) { tomoyo_flags &= ~0x00FF0000; tomoyo_flags |= ptr->post_state[1] << 16; }
	if (flags & 4) { tomoyo_flags &= ~0x0000FF00; tomoyo_flags |= ptr->post_state[2] << 8; }
	task->tomoyo_flags = tomoyo_flags;
}

int DumpCondition(struct io_buffer *head, const struct condition_list *ptr)
{
	if (ptr) {
		u32 i;
		const union element *ptr2 = (union element *) (((u8 *) ptr) + sizeof(*ptr));
		char buffer[32];
		memset(buffer, 0, sizeof(buffer));
		for (i = 0; i < ptr->length; i++) {
			const u16 match = (ptr2->value) >> 16;
			const u8 left = (ptr2->value) >> 8, right = ptr2->value;
			ptr2++;
			if (io_printf(head, "%s", i ? " " : " if ")) break;
			if (left == EXEC_ARGV) {
				unsigned long index = ptr2->value; ptr2++;
				if (io_printf(head, "%s%lu]", condition_control_keyword[left].keyword, index)) break;
				i++;
			} else if (left == EXEC_ENVP) {
				const struct path_info *name = ptr2->string; ptr2++;
				if (io_printf(head, "%s%s\"]", condition_control_keyword[left].keyword, name->name)) break;
				i++;
			} else if (left < MAX_KEYWORD) {
				if (io_printf(head, "%s", condition_control_keyword[left].keyword)) break;
			} else {
				print_ulong(buffer, sizeof(buffer) - 1, ptr2->value, (match >> 2) & 3); ptr2++;
				if (io_printf(head, "%s", buffer)) break;
				i++;
				if (left == MAX_KEYWORD + 1) {
					print_ulong(buffer, sizeof(buffer) - 1, ptr2->value, (match >> 4) & 3); ptr2++;
					if (io_printf(head, "-%s", buffer)) break;
					i++;
				}
			}
			if (io_printf(head, "%s", (match & 1) ? "=" : "!=")) break;
			if (left == EXEC_ARGV || left == EXEC_ENVP) {
				const struct path_info *name = ptr2->string; ptr2++;
				if (name) {
					if (io_printf(head, "\"%s\"", name->name)) break;
				} else {
					if (io_printf(head, "NULL")) break;
				}
				i++;
			} else if (right < MAX_KEYWORD) {
				if (io_printf(head, "%s", condition_control_keyword[right].keyword)) break;
			} else {
				print_ulong(buffer, sizeof(buffer) - 1, ptr2->value, (match >> 6) & 3); ptr2++;
				if (io_printf(head, "%s", buffer)) break;
				i++;
				if (right == MAX_KEYWORD + 1) {
					print_ulong(buffer, sizeof(buffer) - 1, ptr2->value, (match >> 8) & 3); ptr2++;
					if (io_printf(head, "-%s", buffer)) break;
					i++;
				}
			}
		}
		if (i < ptr->length) return -ENOMEM;
		if ((i = ptr->post_state[3]) != 0) {
			unsigned int j;
			if (io_printf(head, " ; set")) return -ENOMEM;
			for (j = 0; j < 3; j++) {
				if (i & (1 << j)) {
					if (io_printf(head, " task.state[%u]=%u", j, ptr->post_state[j])) return -ENOMEM;
				}
			}
		}
	}
	return io_printf(head, "\n") ? -ENOMEM : 0;
}

/***** TOMOYO Linux end. *****/
