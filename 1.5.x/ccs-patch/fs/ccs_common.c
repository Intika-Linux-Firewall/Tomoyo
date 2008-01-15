/*
 * fs/ccs_common.c
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.2   2007/12/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <stdarg.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namei.h>
#include <linux/mount.h>
static const int lookup_flags = LOOKUP_FOLLOW;
#else
static const int lookup_flags = LOOKUP_FOLLOW | LOOKUP_POSITIVE;
#endif
#include <linux/realpath.h>
#include <linux/ccs_common.h>
#include <linux/ccs_proc.h>
#include <linux/tomoyo.h>

#ifdef CONFIG_TOMOYO_MAX_ACCEPT_ENTRY
#define MAX_ACCEPT_ENTRY (CONFIG_TOMOYO_MAX_ACCEPT_ENTRY)
#else
#define MAX_ACCEPT_ENTRY 2048
#endif
#ifdef CONFIG_TOMOYO_MAX_GRANT_LOG
#define MAX_GRANT_LOG (CONFIG_TOMOYO_MAX_GRANT_LOG)
#else
#define MAX_GRANT_LOG 1024
#endif
#ifdef CONFIG_TOMOYO_MAX_REJECT_LOG
#define MAX_REJECT_LOG (CONFIG_TOMOYO_MAX_REJECT_LOG)
#else
#define MAX_REJECT_LOG 1024
#endif

/*************************  VARIABLES  *************************/

/* /sbin/init started? */
int sbin_init_started = 0;

const char *ccs_log_level = KERN_DEBUG;

static struct {
	const char *keyword;
	unsigned int current_value;
	const unsigned int max_value;
} ccs_control_array[CCS_MAX_CONTROL_INDEX] = {
	[CCS_PROFILE_COMMENT]            = { "COMMENT",             0, 0 }, /* Reserved for string. */
	[CCS_TOMOYO_MAC_FOR_FILE]        = { "MAC_FOR_FILE",        0, 3 },
	[CCS_TOMOYO_MAC_FOR_ARGV0]       = { "MAC_FOR_ARGV0",       0, 3 },
	[CCS_TOMOYO_MAC_FOR_NETWORK]     = { "MAC_FOR_NETWORK",     0, 3 },
	[CCS_TOMOYO_MAC_FOR_SIGNAL]      = { "MAC_FOR_SIGNAL",      0, 3 },
	[CCS_SAKURA_DENY_CONCEAL_MOUNT]  = { "DENY_CONCEAL_MOUNT",  0, 3 },
	[CCS_SAKURA_RESTRICT_CHROOT]     = { "RESTRICT_CHROOT",     0, 3 },
	[CCS_SAKURA_RESTRICT_MOUNT]      = { "RESTRICT_MOUNT",      0, 3 },
	[CCS_SAKURA_RESTRICT_UNMOUNT]    = { "RESTRICT_UNMOUNT",    0, 3 },
	[CCS_SAKURA_RESTRICT_PIVOT_ROOT] = { "RESTRICT_PIVOT_ROOT", 0, 3 },
	[CCS_SAKURA_RESTRICT_AUTOBIND]   = { "RESTRICT_AUTOBIND",   0, 1 },
	[CCS_TOMOYO_MAX_ACCEPT_ENTRY]    = { "MAX_ACCEPT_ENTRY",    MAX_ACCEPT_ENTRY, INT_MAX },
	[CCS_TOMOYO_MAX_GRANT_LOG]       = { "MAX_GRANT_LOG",       MAX_GRANT_LOG, INT_MAX },
	[CCS_TOMOYO_MAX_REJECT_LOG]      = { "MAX_REJECT_LOG",      MAX_REJECT_LOG, INT_MAX },
	[CCS_TOMOYO_VERBOSE]             = { "TOMOYO_VERBOSE",      1, 1 },
	[CCS_ALLOW_ENFORCE_GRACE]        = { "ALLOW_ENFORCE_GRACE", 0, 1 },
};

struct profile {
	unsigned int value[CCS_MAX_CONTROL_INDEX];
	const struct path_info *comment;
};

static struct profile *profile_ptr[MAX_PROFILES];

/*************************  UTILITY FUNCTIONS  *************************/

#ifdef CONFIG_TOMOYO
static int __init TOMOYO_Quiet_Setup(char *str)
{
	ccs_control_array[CCS_TOMOYO_VERBOSE].current_value = 0;
	return 0;
}

__setup("TOMOYO_QUIET", TOMOYO_Quiet_Setup);
#endif

/* Am I root? */
static int isRoot(void)
{
	return !current->uid && !current->euid;
}

/*
 * Format string.
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 */
static void NormalizeLine(unsigned char *buffer)
{
	unsigned char *sp = buffer, *dp = buffer;
	int first = 1;
	while (*sp && (*sp <= ' ' || *sp >= 127)) sp++;
	while (*sp) {
		if (!first) *dp++ = ' ';
		first = 0;
		while (*sp > ' ' && *sp < 127) *dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127)) sp++;
	}
	*dp = '\0';
}

/*
 *  Check whether the given filename follows the naming rules.
 *  Returns nonzero if follows, zero otherwise.
 */
int IsCorrectPath(const char *filename, const int start_type, const int pattern_type, const int end_type, const char *function)
{
	int contains_pattern = 0;
	char c, d, e;
	const char *original_filename = filename;
	if (!filename) goto out;
	c = *filename;
	if (start_type == 1) { /* Must start with '/' */
		if (c != '/') goto out;
	} else if (start_type == -1) { /* Must not start with '/' */
		if (c == '/') goto out;
	}
	if (c) c = * (strchr(filename, '\0') - 1);
	if (end_type == 1) { /* Must end with '/' */
		if (c != '/') goto out;
	} else if (end_type == -1) { /* Must not end with '/' */
		if (c == '/') goto out;
	}
	while ((c = *filename++) != '\0') {
		if (c == '\\') {
			switch ((c = *filename++)) {
			case '\\':  /* "\\" */
				continue;
			case '$':   /* "\$" */
			case '+':   /* "\+" */
			case '?':   /* "\?" */
			case '*':   /* "\*" */
			case '@':   /* "\@" */
			case 'x':   /* "\x" */
			case 'X':   /* "\X" */
			case 'a':   /* "\a" */
			case 'A':   /* "\A" */
			case '-':   /* "\-" */
				if (pattern_type == -1) break; /* Must not contain pattern */
				contains_pattern = 1;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				if ((d = *filename++) >= '0' && d <= '7' && (e = *filename++) >= '0' && e <= '7') {
					const unsigned char f =
						(((unsigned char) (c - '0')) << 6) +
						(((unsigned char) (d - '0')) << 3) +
						(((unsigned char) (e - '0')));
					if (f && (f <= ' ' || f >= 127)) continue; /* pattern is not \000 */
				}
			}
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (pattern_type == 1) { /* Must contain pattern */
		if (!contains_pattern) goto out;
	}
	return 1;
 out:
	printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", function, original_filename);
	return 0;
}

/*
 *  Check whether the given domainname follows the naming rules.
 *  Returns nonzero if follows, zero otherwise.
 */
int IsCorrectDomain(const unsigned char *domainname, const char *function)
{
	unsigned char c, d, e;
	const char *org_domainname = domainname;
	if (!domainname || strncmp(domainname, ROOT_NAME, ROOT_NAME_LEN)) goto out;
	domainname += ROOT_NAME_LEN;
	if (!*domainname) return 1;
	do {
		if (*domainname++ != ' ') goto out;
		if (*domainname++ != '/') goto out;
		while ((c = *domainname) != '\0' && c != ' ') {
			domainname++;
			if (c == '\\') {
				switch ((c = *domainname++)) {
				case '\\':  /* "\\" */
					continue;
				case '0':   /* "\ooo" */
				case '1':
				case '2':
				case '3':
					if ((d = *domainname++) >= '0' && d <= '7' && (e = *domainname++) >= '0' && e <= '7') {
						const unsigned char f =
							(((unsigned char) (c - '0')) << 6) +
							(((unsigned char) (d - '0')) << 3) +
							(((unsigned char) (e - '0')));
						if (f && (f <= ' ' || f >= 127)) continue; /* pattern is not \000 */
					}
				}
				goto out;
			} else if (c < ' ' || c >= 127) {
				goto out;
			}
		}
	} while (*domainname);
	return 1;
 out:
	printk(KERN_DEBUG "%s: Invalid domainname '%s'\n", function, org_domainname);
	return 0;
}

int IsDomainDef(const unsigned char *buffer)
{
	/* while (*buffer && (*buffer <= ' ' || *buffer >= 127)) buffer++; */
	return strncmp(buffer, ROOT_NAME, ROOT_NAME_LEN) == 0;
}

struct domain_info *FindDomain(const char *domainname0)
{
	struct domain_info *domain;
	static int first = 1;
	struct path_info domainname;
	domainname.name = domainname0;
	fill_path_info(&domainname);
	if (first) {
		KERNEL_DOMAIN.domainname = SaveName(ROOT_NAME);
		first = 0;
	}
	for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
		if (!domain->is_deleted && !pathcmp(&domainname, domain->domainname)) return domain;
	}
	return NULL;
}

static int PathDepth(const char *pathname)
{
	int i = 0;
	if (pathname) {
		char *ep = strchr(pathname, '\0');
		if (pathname < ep--) {
			if (*ep != '/') i++;
			while (pathname <= ep) if (*ep-- == '/') i += 2;
		}
	}
	return i;
}

static int const_part_length(const char *filename)
{
	int len = 0;
	if (filename) {
		char c;
		while ((c = *filename++) != '\0') {
			if (c != '\\') { len++; continue; }
			switch (c = *filename++) {
			case '\\':  /* "\\" */
				len += 2; continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				if ((c = *filename++) >= '0' && c <= '7' && (c = *filename++) >= '0' && c <= '7') { len += 4; continue; }
			}
			break;
		}
	}
	return len;
}

void fill_path_info(struct path_info *ptr)
{
	const char *name = ptr->name;
	const int len = strlen(name);
	ptr->total_len = len;
	ptr->const_len = const_part_length(name);
	ptr->is_dir = len && (name[len - 1] == '/');
	ptr->is_patterned = (ptr->const_len < len);
	ptr->hash = full_name_hash(name, len);
	ptr->depth = PathDepth(name);
}

static int FileMatchesToPattern2(const char *filename, const char *filename_end, const char *pattern, const char *pattern_end)
{
	while (filename < filename_end && pattern < pattern_end) {
		if (*pattern != '\\') {
			if (*filename++ != *pattern++) return 0;
		} else {
			char c = *filename;
			pattern++;
			switch (*pattern) {
			case '?':
				if (c == '/') {
					return 0;
				} else if (c == '\\') {
					if ((c = filename[1]) == '\\') {
						filename++; /* safe because filename is \\ */
					} else if (c >= '0' && c <= '3' && (c = filename[2]) >= '0' && c <= '7' && (c = filename[3]) >= '0' && c <= '7') {
						filename += 3; /* safe because filename is \ooo */
					} else {
						return 0;
					}
				}
				break;
			case '\\':
				if (c != '\\') return 0;
				if (*++filename != '\\') return 0; /* safe because *filename != '\0' */
				break;
			case '+':
				if (c < '0' || c > '9') return 0;
				break;
			case 'x':
				if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) return 0;
				break;
			case 'a':
				if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return 0;
				break;
			case '0':
			case '1':
			case '2':
			case '3':
				if (c == '\\' && (c = filename[1]) >= '0' && c <= '3' && c == *pattern
					&& (c = filename[2]) >= '0' && c <= '7' && c == pattern[1]
					&& (c = filename[3]) >= '0' && c <= '7' && c == pattern[2]) {
					filename += 3; /* safe because filename is \ooo */
					pattern += 2; /* safe because pattern is \ooo  */
					break;
				}
				return 0; /* Not matched. */
			case '*':
			case '@':
				{
					int i;
					for (i = 0; i <= filename_end - filename; i++) {
						if (FileMatchesToPattern2(filename + i, filename_end, pattern + 1, pattern_end)) return 1;
						if ((c = filename[i]) == '.' && *pattern == '@') break;
						if (c == '\\') {
							if ((c = filename[i + 1]) == '\\') {
								i++; /* safe because filename is \\ */
							} else if (c >= '0' && c <= '3' && (c = filename[i + 2]) >= '0' && c <= '7' && (c = filename[i + 3]) >= '0' && c <= '7') {
								i += 3; /* safe because filename is \ooo */
							} else {
								break; /* Bad pattern. */
							}
						}
					}
					return 0; /* Not matched. */
				}
			default:
				{
					int i, j = 0;
					if ((c = *pattern) == '$') {
						while ((c = filename[j]) >= '0' && c <= '9') j++;
					} else if (c == 'X') {
						while (((c = filename[j]) >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) j++;
					} else if (c == 'A') {
						while (((c = filename[j]) >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) j++;
					}
					for (i = 1; i <= j; i++) {
						if (FileMatchesToPattern2(filename + i, filename_end, pattern + 1, pattern_end)) return 1;
					}
				}
				return 0; /* Not matched or bad pattern. */
			}
			filename++; /* safe because *filename != '\0' */
			pattern++; /* safe because *pattern != '\0' */
		}
	}
	while (*pattern == '\\' && (*(pattern + 1) == '*' || *(pattern + 1) == '@')) pattern += 2;
	return (filename == filename_end && pattern == pattern_end);
}

static int FileMatchesToPattern(const char *filename, const char *filename_end, const char *pattern, const char *pattern_end)
{
	const char *pattern_start = pattern;
	int first = 1;
	int result;
	while (pattern < pattern_end - 1) {
		if (*pattern++ != '\\' || *pattern++ != '-') continue;
		result = FileMatchesToPattern2(filename, filename_end, pattern_start, pattern - 2);
		if (first) result = !result;
		if (result) return 0;
		first = 0;
		pattern_start = pattern;
	}
	result = FileMatchesToPattern2(filename, filename_end, pattern_start, pattern_end);
	return first ? result : !result;
}

/*
 *  Check whether the given pathname matches to the given pattern.
 *  Returns nonzero if matches, zero otherwise.
 *
 *  The following patterns are available.
 *    \\     \ itself.
 *    \ooo   Octal representation of a byte.
 *    \*     More than or equals to 0 character other than '/'.
 *    \@     More than or equals to 0 character other than '/' or '.'.
 *    \?     1 byte character other than '/'.
 *    \$     More than or equals to 1 decimal digit.
 *    \+     1 decimal digit.
 *    \X     More than or equals to 1 hexadecimal digit.
 *    \x     1 hexadecimal digit.
 *    \A     More than or equals to 1 alphabet character.
 *    \a     1 alphabet character.
 *    \-     Subtraction operator.
 */

int PathMatchesToPattern(const struct path_info *pathname0, const struct path_info *pattern0)
{
	/* if (!pathname || !pattern) return 0; */
	const char *pathname = pathname0->name, *pattern = pattern0->name;
	const int len = pattern0->const_len;
	if (!pattern0->is_patterned) return !pathcmp(pathname0, pattern0);
	if (pathname0->depth != pattern0->depth) return 0;
	if (strncmp(pathname, pattern, len)) return 0;
	pathname += len; pattern += len;
	while (*pathname && *pattern) {
		const char *pathname_delimiter = strchr(pathname, '/'), *pattern_delimiter = strchr(pattern, '/');
		if (!pathname_delimiter) pathname_delimiter = strchr(pathname, '\0');
		if (!pattern_delimiter) pattern_delimiter = strchr(pattern, '\0');
		if (!FileMatchesToPattern(pathname, pathname_delimiter, pattern, pattern_delimiter)) return 0;
		pathname = *pathname_delimiter ? pathname_delimiter + 1 : pathname_delimiter;
		pattern = *pattern_delimiter ? pattern_delimiter + 1 : pattern_delimiter;
	}
	while (*pattern == '\\' && (*(pattern + 1) == '*' || *(pattern + 1) == '@')) pattern += 2;
	return (!*pathname && !*pattern);
}

/*
 *  Transactional printf() to struct io_buffer structure.
 *  snprintf() will truncate, but io_printf() won't.
 *  Returns zero on success, nonzero otherwise.
 */
int io_printf(struct io_buffer *head, const char *fmt, ...)
{
	va_list args;
	int len, pos = head->read_avail, size = head->readbuf_size - pos;
	if (size <= 0) return -ENOMEM;
	va_start(args, fmt);
	len = vsnprintf(head->read_buf + pos, size, fmt, args);
	va_end(args);
	if (pos + len >= head->readbuf_size) return -ENOMEM;
	head->read_avail += len;
	return 0;
}

/*
 * Get realpath() of current process.
 * This function uses ccs_alloc(), so caller must ccs_free() if this function didn't return NULL.
 */
const char *GetEXE(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	const char *cp = NULL;
	if (!mm) return NULL;
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
			cp = realpath_from_dentry(vma->vm_file->f_dentry, vma->vm_file->f_vfsmnt);
			break;
		}
	}
	up_read(&mm->mmap_sem);
	return cp;
}

const char *GetMSG(const int is_enforce)
{
	if (is_enforce) return "ERROR"; else return "WARNING";
}

/*************************  DOMAIN POLICY HANDLER  *************************/

/* Check whether the given access control is enabled. */
unsigned int CheckCCSFlags(const unsigned int index)
{
	const u8 profile = current->domain_info->profile;
	return sbin_init_started && index < CCS_MAX_CONTROL_INDEX
#if MAX_PROFILES != 256
		&& profile < MAX_PROFILES
#endif
		&& profile_ptr[profile] ? profile_ptr[profile]->value[index] : 0;
}
EXPORT_SYMBOL(CheckCCSFlags);

unsigned int TomoyoVerboseMode(void)
{
	return CheckCCSFlags(CCS_TOMOYO_VERBOSE);
}

/* Check whether the given access control is enforce mode. */
unsigned int CheckCCSEnforce(const unsigned int index)
{
	return CheckCCSFlags(index) == 3;
}
EXPORT_SYMBOL(CheckCCSEnforce);

unsigned int CheckDomainQuota(struct domain_info * const domain)
{
	unsigned int count = 0;
	struct acl_info *ptr;
	if (!domain) return 1;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (!ptr->is_deleted) count++;
	}
	if (count < CheckCCSFlags(CCS_TOMOYO_MAX_ACCEPT_ENTRY)) return 1;
	if (!domain->quota_warned) {
		domain->quota_warned = 1;
		printk("TOMOYO-WARNING: Domain '%s' has so many ACLs to hold. Stopped learning mode.\n", domain->domainname->name);
	}
	return 0;
}

/* Check whether the given access control is learning mode. */
unsigned int CheckCCSAccept(const unsigned int index, struct domain_info * const domain)
{
	if (CheckCCSFlags(index) != 1) return 0;
	return CheckDomainQuota(domain);
}
EXPORT_SYMBOL(CheckCCSAccept);

static struct profile *FindOrAssignNewProfile(const unsigned int profile)
{
	static DECLARE_MUTEX(profile_lock);
	struct profile *ptr = NULL;
	down(&profile_lock);
	if (profile < MAX_PROFILES && (ptr = profile_ptr[profile]) == NULL) {
		if ((ptr = alloc_element(sizeof(*ptr))) != NULL) {
			int i;
			for (i = 0; i < CCS_MAX_CONTROL_INDEX; i++) ptr->value[i] = ccs_control_array[i].current_value;
			mb(); /* Instead of using spinlock. */
			profile_ptr[profile] = ptr;
		}
	}
	up(&profile_lock);
	return ptr;
}

static int SetProfile(struct io_buffer *head)
{
	char *data = head->write_buf;
	unsigned int i, value;
	char *cp;
	struct profile *profile;
	if (!isRoot()) return -EPERM;
	i = simple_strtoul(data, &cp, 10);
	if (data != cp) {
		if (*cp != '-') return -EINVAL;
		data= cp + 1;
	}
	profile = FindOrAssignNewProfile(i);
	if (!profile) return -EINVAL;
	cp = strchr(data, '=');
	if (!cp) return -EINVAL;
	*cp = '\0';
	UpdateCounter(CCS_UPDATES_COUNTER_PROFILE);
	if (strcmp(data, ccs_control_array[CCS_PROFILE_COMMENT].keyword) == 0) {
		profile->comment = SaveName(cp + 1);
		return 0;
	}
	if (sscanf(cp + 1, "%u", &value) != 1) return -EINVAL;
#ifdef CONFIG_TOMOYO
	if (strncmp(data, KEYWORD_MAC_FOR_CAPABILITY, KEYWORD_MAC_FOR_CAPABILITY_LEN) == 0) {
		return SetCapabilityStatus(data + KEYWORD_MAC_FOR_CAPABILITY_LEN, value, i);
	}
#endif
	for (i = 0; i < CCS_MAX_CONTROL_INDEX; i++) {
		if (strcmp(data, ccs_control_array[i].keyword)) continue;
		if (value > ccs_control_array[i].max_value) value = ccs_control_array[i].max_value;
		profile->value[i] = value;
		return 0;
	}
	return -EINVAL;
}

static int ReadProfile(struct io_buffer *head)
{
	if (!head->read_eof) {
		if (!isRoot()) return -EPERM;
		if (!head->read_var2) {
			int step;
			for (step = head->read_step; step < MAX_PROFILES * CCS_MAX_CONTROL_INDEX; step++) {
				const int i = step / CCS_MAX_CONTROL_INDEX, j = step % CCS_MAX_CONTROL_INDEX;
				const struct profile *profile = profile_ptr[i];
				head->read_step = step;
				if (!profile) continue;
				switch (j) {
				case -1: /* Dummy */
#ifndef CONFIG_SAKURA
				case CCS_SAKURA_DENY_CONCEAL_MOUNT:
				case CCS_SAKURA_RESTRICT_CHROOT:
				case CCS_SAKURA_RESTRICT_MOUNT:
				case CCS_SAKURA_RESTRICT_UNMOUNT:
				case CCS_SAKURA_RESTRICT_PIVOT_ROOT:
				case CCS_SAKURA_RESTRICT_AUTOBIND:
#endif
#ifndef CONFIG_TOMOYO
				case CCS_TOMOYO_MAC_FOR_FILE:
				case CCS_TOMOYO_MAC_FOR_ARGV0:
				case CCS_TOMOYO_MAC_FOR_NETWORK:
				case CCS_TOMOYO_MAC_FOR_SIGNAL:
				case CCS_TOMOYO_MAX_ACCEPT_ENTRY:
				case CCS_TOMOYO_MAX_GRANT_LOG:
				case CCS_TOMOYO_MAX_REJECT_LOG:
				case CCS_TOMOYO_VERBOSE:
#endif
					continue;
				}
				if (j == CCS_PROFILE_COMMENT) {
					if (io_printf(head, "%u-%s=%s\n", i, ccs_control_array[CCS_PROFILE_COMMENT].keyword, profile->comment ? profile->comment->name : "")) break;
				} else {
					if (io_printf(head, "%u-%s=%u\n", i, ccs_control_array[j].keyword, profile->value[j])) break;
				}
			}
			if (step == MAX_PROFILES * CCS_MAX_CONTROL_INDEX) {
				head->read_var2 = "";
				head->read_step = 0;
			}
		}
		if (head->read_var2) {
#ifdef CONFIG_TOMOYO
			if (ReadCapabilityStatus(head) == 0)
#endif
				head->read_eof = 1;
		}
	}
	return 0;
}

/*************************  POLICY MANAGER HANDLER  *************************/

struct policy_manager_entry {
	struct policy_manager_entry *next;
	const struct path_info *manager;
	u8 is_domain;
	u8 is_deleted;
};

static struct policy_manager_entry *policy_manager_list = NULL;

static int AddManagerEntry(const char *manager, u8 is_delete)
{
	struct policy_manager_entry *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_manager;
	int error = -ENOMEM;
	u8 is_domain = 0;
	if (!isRoot()) return -EPERM;
	if (IsDomainDef(manager)) {
		if (!IsCorrectDomain(manager, __FUNCTION__)) return -EINVAL;
		is_domain = 1;
	} else {
		if (!IsCorrectPath(manager, 1, -1, -1, __FUNCTION__)) return -EINVAL;
	}
	if ((saved_manager = SaveName(manager)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = policy_manager_list; ptr; ptr = ptr->next) {
		if (ptr->manager == saved_manager) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->manager = saved_manager;
	new_entry->is_domain = is_domain;
	mb(); /* Instead of using spinlock. */
	if ((ptr = policy_manager_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		policy_manager_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	if (!error) UpdateCounter(CCS_UPDATES_COUNTER_MANAGER);
	return error;
}

static int AddManagerPolicy(struct io_buffer *head)
{
	const char *data = head->write_buf;
	int is_delete = 0;
	if (!isRoot()) return -EPERM;
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		is_delete = 1;
	}
	return AddManagerEntry(data, is_delete);
}

static int ReadManagerPolicy(struct io_buffer *head)
{
	if (!head->read_eof) {
		struct policy_manager_entry *ptr = head->read_var2;
		if (!isRoot()) return -EPERM;
		if (!ptr) ptr = policy_manager_list;
		while (ptr) {
			head->read_var2 = ptr;
			if (!ptr->is_deleted && io_printf(head, "%s\n", ptr->manager->name)) break;
			ptr = ptr->next;
		}
		if (!ptr) head->read_eof = 1;
	}
	return 0;
}

/* Check whether the current process is a policy manager. */
static int IsPolicyManager(void)
{
	struct policy_manager_entry *ptr;
	const char *exe;
	const struct path_info *domainname = current->domain_info->domainname;
	if (!sbin_init_started) return 1;
	for (ptr = policy_manager_list; ptr; ptr = ptr->next) {
		if (!ptr->is_deleted && ptr->is_domain && !pathcmp(domainname, ptr->manager)) return 1;
	}
	if ((exe = GetEXE()) == NULL) return 0;
	for (ptr = policy_manager_list; ptr; ptr = ptr->next) {
		if (!ptr->is_deleted && !ptr->is_domain && !strcmp(exe, ptr->manager->name)) break;
	}
	if (!ptr) { /* Reduce error messages. */
		static pid_t last_pid = 0;
		const pid_t pid = current->pid;
		if (last_pid != pid) {
			printk("%s ( %s ) is not permitted to update policies.\n", domainname->name, exe);
			last_pid = pid;
		}
	}
	ccs_free(exe);
	return ptr ? 1 : 0;
}

#ifdef CONFIG_TOMOYO

/*************************  DOMAIN POLICY HANDLER  *************************/

static int AddDomainPolicy(struct io_buffer *head)
{
	char *data = head->write_buf;
	struct domain_info *domain = head->write_var1;
	int is_delete = 0, is_select = 0, is_undelete = 0;
	unsigned int profile;
	if (!isRoot()) return -EPERM;
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		is_delete = 1;
	} else if (strncmp(data, KEYWORD_SELECT, KEYWORD_SELECT_LEN) == 0) {
		data += KEYWORD_SELECT_LEN;
		is_select = 1;
	} else if (strncmp(data, KEYWORD_UNDELETE, KEYWORD_UNDELETE_LEN) == 0) {
		data += KEYWORD_UNDELETE_LEN;
		is_undelete = 1;
	}
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	if (IsDomainDef(data)) {
		if (is_delete) {
			DeleteDomain(data);
			domain = NULL;
		} else if (is_select) {
			domain = FindDomain(data);
		} else if (is_undelete) {
			domain = UndeleteDomain(data);
		} else {
			domain = FindOrAssignNewDomain(data, 0);
		}
		head->write_var1 = domain;
		return 0;
	}
	if (!domain) return -EINVAL;
	if (sscanf(data, KEYWORD_USE_PROFILE "%u", &profile) == 1 && profile < MAX_PROFILES) {
		if (profile_ptr[profile] || !sbin_init_started) domain->profile = (u8) profile;
	} else if (strncmp(data, KEYWORD_ALLOW_CAPABILITY, KEYWORD_ALLOW_CAPABILITY_LEN) == 0) {
		return AddCapabilityPolicy(data + KEYWORD_ALLOW_CAPABILITY_LEN, domain, is_delete);
	} else if (strncmp(data, KEYWORD_ALLOW_NETWORK, KEYWORD_ALLOW_NETWORK_LEN) == 0) {
		return AddNetworkPolicy(data + KEYWORD_ALLOW_NETWORK_LEN, domain, is_delete);
	} else if (strncmp(data, KEYWORD_ALLOW_SIGNAL, KEYWORD_ALLOW_SIGNAL_LEN) == 0) {
		return AddSignalPolicy(data + KEYWORD_ALLOW_SIGNAL_LEN, domain, is_delete);
	} else if (strncmp(data, KEYWORD_ALLOW_ARGV0, KEYWORD_ALLOW_ARGV0_LEN) == 0) {
		return AddArgv0Policy(data + KEYWORD_ALLOW_ARGV0_LEN, domain, is_delete);
	} else {
		return AddFilePolicy(data, domain, is_delete);
	}
	return -EINVAL;
}

static int ReadDomainPolicy(struct io_buffer *head)
{
	if (!head->read_eof) {
		struct domain_info *domain = head->read_var1;
		switch (head->read_step) {
		case 0: break;
		case 1: goto step1;
		case 2: goto step2;
		case 3: goto step3;
		default: return -EINVAL;
		}
		if (!isRoot()) return -EPERM;
		for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
			struct acl_info *ptr;
			if (domain->is_deleted) continue;
			head->read_var1 = domain;
			head->read_var2 = NULL; head->read_step = 1;
		step1:
			if (io_printf(head, "%s\n" KEYWORD_USE_PROFILE "%u\n%s\n", domain->domainname->name, domain->profile, domain->quota_warned ? "quota_exceeded\n" : "")) break;
			head->read_var2 = domain->first_acl_ptr; head->read_step = 2;
		step2:
			for (ptr = head->read_var2; ptr; ptr = ptr->next) {
				const u8 acl_type = ptr->type;
				const int pos = head->read_avail;
				head->read_var2 = ptr;
				if (ptr->is_deleted) continue;
				if (acl_type == TYPE_FILE_ACL) {
					struct file_acl_record *ptr2 = (struct file_acl_record *) ptr;
					const unsigned char b = ptr2->u_is_group;
					if (io_printf(head, "%d %s%s", ptr2->perm,
						      b ? "@" : "",
						      b ? ptr2->u.group->group_name->name : ptr2->u.filename->name)
					    || DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
				} else if (acl_type == TYPE_ARGV0_ACL) {
					struct argv0_acl_record *ptr2 = (struct argv0_acl_record *) ptr;
					if (io_printf(head, KEYWORD_ALLOW_ARGV0 "%s %s",
						      ptr2->filename->name, ptr2->argv0->name) ||
					    DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
				} else if (acl_type == TYPE_CAPABILITY_ACL) {
					struct capability_acl_record *ptr2 = (struct capability_acl_record *) ptr;
					if (io_printf(head, KEYWORD_ALLOW_CAPABILITY "%s", capability2keyword(ptr2->capability)) ||
					    DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
				} else if (acl_type == TYPE_IP_NETWORK_ACL) {
					struct ip_network_acl_record *ptr2 = (struct ip_network_acl_record *) ptr;
					if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s ", network2keyword(ptr2->operation_type))) break;
					switch (ptr2->record_type) {
					case IP_RECORD_TYPE_ADDRESS_GROUP:
						if (io_printf(head, "@%s", ptr2->u.group->group_name->name)) goto print_ip_record_out;
						break;
					case IP_RECORD_TYPE_IPv4:
						{
							const u32 min_address = ptr2->u.ipv4.min, max_address = ptr2->u.ipv4.max;
							if (io_printf(head, "%u.%u.%u.%u", HIPQUAD(min_address))) goto print_ip_record_out;
							if (min_address != max_address && io_printf(head, "-%u.%u.%u.%u", HIPQUAD(max_address))) goto print_ip_record_out;
						}
						break;
					case IP_RECORD_TYPE_IPv6:
						{
							char buf[64];
							const u16 *min_address = ptr2->u.ipv6.min, *max_address = ptr2->u.ipv6.max;
							print_ipv6(buf, sizeof(buf), min_address);
							if (io_printf(head, "%s", buf)) goto print_ip_record_out;
							if (memcmp(min_address, max_address, 16)) {
								print_ipv6(buf, sizeof(buf), max_address);
								if (io_printf(head, "-%s", buf)) goto print_ip_record_out;
							}
						}
						break;
					}
					{
						const u16 min_port = ptr2->min_port, max_port = ptr2->max_port;
						if (io_printf(head, " %u", min_port)) goto print_ip_record_out;
						if (min_port != max_port && io_printf(head, "-%u", max_port)) goto print_ip_record_out;
					}
					if (DumpCondition(head, ptr->cond)) {
					print_ip_record_out: ;
					head->read_avail = pos; break;
					}
				} else if (acl_type == TYPE_SIGNAL_ACL) {
					struct signal_acl_record *ptr2 = (struct signal_acl_record *) ptr;
					if (io_printf(head, KEYWORD_ALLOW_SIGNAL "%u %s", ptr2->sig, ptr2->domainname->name) ||
					    DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
				} else {
					const char *keyword = acltype2keyword(acl_type);
					if (keyword) {
						if (acltype2paths(acl_type) == 2) {
							struct double_acl_record *ptr2 = (struct double_acl_record *) ptr;
							const u8 b0 = ptr2->u1_is_group, b1 = ptr2->u2_is_group;
							if (io_printf(head, "allow_%s %s%s %s%s", keyword, 
								      b0 ? "@" : "", b0 ? ptr2->u1.group1->group_name->name : ptr2->u1.filename1->name,
								      b1 ? "@" : "", b1 ? ptr2->u2.group2->group_name->name : ptr2->u2.filename2->name)
							    || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						} else {
							struct single_acl_record *ptr2 = (struct single_acl_record *) ptr;
							const u8 b = ptr2->u_is_group;
							if (io_printf(head, "allow_%s %s%s", keyword,
								      b ? "@" : "", b ? ptr2->u.group->group_name->name : ptr2->u.filename->name)
							    || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						}
					}
				}
			}
			if (ptr) break;
			head->read_var2 = NULL; head->read_step = 3;
		step3:
			if (io_printf(head, "\n")) break;
		}
		if (!domain) head->read_eof = 1;
	}
	return 0;
}

#endif

static int UpdateDomainProfile(struct io_buffer *head)
{
	char *data = head->write_buf;
	char *cp = strchr(data, ' ');
	struct domain_info *domain;
	unsigned int profile;
	if (!isRoot()) return -EPERM;
	if (!cp) return -EINVAL;
	*cp = '\0';
	domain = FindDomain(cp + 1);
	profile = simple_strtoul(data, NULL, 10);
	if (domain && profile < MAX_PROFILES && (profile_ptr[profile] || !sbin_init_started)) domain->profile = (u8) profile;
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

static int ReadDomainProfile(struct io_buffer *head)
{
	if (!head->read_eof) {
		struct domain_info *domain;
		if (head->read_step == 0) {
			head->read_var1 = &KERNEL_DOMAIN;
			head->read_step = 1;
		}
		if (!isRoot()) return -EPERM;
		for (domain = head->read_var1; domain; domain = domain->next) {
			if (domain->is_deleted) continue;
			head->read_var1 = domain;
			if (io_printf(head, "%u %s\n", domain->profile, domain->domainname->name)) break;
		}
		if (!domain) head->read_eof = 1;
	}
	return 0;
}

static int WritePID(struct io_buffer *head)
{
	head->read_step = (int) simple_strtoul(head->write_buf, NULL, 10);
	head->read_eof = 0;
	return 0;
}

static int ReadPID(struct io_buffer *head)
{
	if (head->read_avail == 0 && !head->read_eof) {
		const int pid = head->read_step;
		struct task_struct *p;
		struct domain_info *domain = NULL;
		/***** CRITICAL SECTION START *****/
		read_lock(&tasklist_lock);
		p = find_task_by_pid(pid);
		if (p) domain = p->domain_info;
		read_unlock(&tasklist_lock);
		/***** CRITICAL SECTION END *****/
		if (domain) io_printf(head, "%d %u %s", pid, domain->profile, domain->domainname->name);
		head->read_eof = 1;
	}
	return 0;
}

/*************************  EXCEPTION POLICY HANDLER  *************************/

#ifdef CONFIG_TOMOYO

static int AddExceptionPolicy(struct io_buffer *head)
{
	char *data = head->write_buf;
	int is_delete = 0;
	if (!isRoot()) return -EPERM;
	UpdateCounter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		is_delete = 1;
	}
	if (strncmp(data, KEYWORD_KEEP_DOMAIN, KEYWORD_KEEP_DOMAIN_LEN) == 0) {
		return AddDomainKeeperPolicy(data + KEYWORD_KEEP_DOMAIN_LEN, 0, is_delete);
	} else if (strncmp(data, KEYWORD_NO_KEEP_DOMAIN, KEYWORD_NO_KEEP_DOMAIN_LEN) == 0) {
		return AddDomainKeeperPolicy(data + KEYWORD_NO_KEEP_DOMAIN_LEN, 1, is_delete);
	} else if (strncmp(data, KEYWORD_INITIALIZE_DOMAIN, KEYWORD_INITIALIZE_DOMAIN_LEN) == 0) {
		return AddDomainInitializerPolicy(data + KEYWORD_INITIALIZE_DOMAIN_LEN, 0, is_delete);
	} else if (strncmp(data, KEYWORD_NO_INITIALIZE_DOMAIN, KEYWORD_NO_INITIALIZE_DOMAIN_LEN) == 0) {
		return AddDomainInitializerPolicy(data + KEYWORD_NO_INITIALIZE_DOMAIN_LEN, 1, is_delete);
	} else if (strncmp(data, KEYWORD_ALIAS, KEYWORD_ALIAS_LEN) == 0) {
		return AddAliasPolicy(data + KEYWORD_ALIAS_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_AGGREGATOR, KEYWORD_AGGREGATOR_LEN) == 0) {
		return AddAggregatorPolicy(data + KEYWORD_AGGREGATOR_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_ALLOW_READ, KEYWORD_ALLOW_READ_LEN) == 0) {
		return AddGloballyReadablePolicy(data + KEYWORD_ALLOW_READ_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_FILE_PATTERN, KEYWORD_FILE_PATTERN_LEN) == 0) {
		return AddPatternPolicy(data + KEYWORD_FILE_PATTERN_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_PATH_GROUP, KEYWORD_PATH_GROUP_LEN) == 0) {
		return AddGroupPolicy(data + KEYWORD_PATH_GROUP_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_DENY_REWRITE, KEYWORD_DENY_REWRITE_LEN) == 0) {
		return AddNoRewritePolicy(data + KEYWORD_DENY_REWRITE_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_ADDRESS_GROUP, KEYWORD_ADDRESS_GROUP_LEN) == 0) {
		return AddAddressGroupPolicy(data + KEYWORD_ADDRESS_GROUP_LEN, is_delete);
	}
	return -EINVAL;
}

static int ReadExceptionPolicy(struct io_buffer *head)
{
	if (!head->read_eof) {
		switch (head->read_step) {
		case 0:
			if (!isRoot()) return -EPERM;
			head->read_var2 = NULL; head->read_step = 1;
		case 1:
			if (ReadDomainKeeperPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 2;
		case 2:
			if (ReadGloballyReadablePolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 3;
		case 3:
			if (ReadDomainInitializerPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 4;
		case 4:
			if (ReadAliasPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 5;
		case 5:
			if (ReadAggregatorPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 6;
		case 6:
			if (ReadPatternPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 7;
		case 7:
			if (ReadNoRewritePolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 8;
		case 8:
			if (ReadGroupPolicy(head)) break;
			head->read_var1 = head->read_var2 = NULL; head->read_step = 9;
		case 9:
			if (ReadAddressGroupPolicy(head)) break;
			head->read_eof = 1;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

#endif

/*************************  SYSTEM POLICY HANDLER  *************************/

#ifdef CONFIG_SAKURA

static int AddSystemPolicy(struct io_buffer *head)
{
	char *data = head->write_buf;
	int is_delete = 0;
	if (!isRoot()) return -EPERM;
	UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		is_delete = 1;
	}
	if (strncmp(data, KEYWORD_ALLOW_MOUNT, KEYWORD_ALLOW_MOUNT_LEN) == 0)
		return AddMountPolicy(data + KEYWORD_ALLOW_MOUNT_LEN, is_delete);
	if (strncmp(data, KEYWORD_DENY_UNMOUNT, KEYWORD_DENY_UNMOUNT_LEN) == 0)
		return AddNoUmountPolicy(data + KEYWORD_DENY_UNMOUNT_LEN, is_delete);
	if (strncmp(data, KEYWORD_ALLOW_CHROOT, KEYWORD_ALLOW_CHROOT_LEN) == 0)
		return AddChrootPolicy(data + KEYWORD_ALLOW_CHROOT_LEN, is_delete);
	if (strncmp(data, KEYWORD_ALLOW_PIVOT_ROOT, KEYWORD_ALLOW_PIVOT_ROOT_LEN) == 0)
		return AddPivotRootPolicy(data + KEYWORD_ALLOW_PIVOT_ROOT_LEN, is_delete);
	if (strncmp(data, KEYWORD_DENY_AUTOBIND, KEYWORD_DENY_AUTOBIND_LEN) == 0)
		return AddReservedPortPolicy(data + KEYWORD_DENY_AUTOBIND_LEN, is_delete);
	return -EINVAL;
}

static int ReadSystemPolicy(struct io_buffer *head)
{
	if (!head->read_eof) {
		switch (head->read_step) {
		case 0:
			if (!isRoot()) return -EPERM;
			head->read_var2 = NULL; head->read_step = 1;
		case 1:
			if (ReadMountPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 2;
		case 2:
			if (ReadNoUmountPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 3;
		case 3:
			if (ReadChrootPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 4;
		case 4:
			if (ReadPivotRootPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 5;
		case 5:
			if (ReadReservedPortPolicy(head)) break;
			head->read_eof = 1;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

#endif

/*************************  POLICY LOADER  *************************/

static int profile_loaded = 0;

static const char *ccs_loader = NULL;

static int __init CCS_loader_Setup(char *str)
{
	ccs_loader = str;
	return 0;
}

__setup("CCS_loader=", CCS_loader_Setup);

void CCS_LoadPolicy(const char *filename)
{
	if (sbin_init_started) return;
	/*
	 * Check filename is /sbin/init or /sbin/ccs-start .
	 * /sbin/ccs-start is a dummy filename in case where /sbin/init can't be passed.
	 * You can create /sbin/ccs-start by "ln -s /bin/true /sbin/ccs-start", for
	 * only the pathname is needed to activate Mandatory Access Control.
	 */
	if (strcmp(filename, "/sbin/init") != 0 && strcmp(filename, "/sbin/ccs-start") != 0) return;
	/*
	 * Don't activate MAC if the path given by 'CCS_loader=' option doesn't exist.
	 * If initrd.img includes /sbin/init but real-root-dev has not mounted on / yet,
	 * activating MAC will block the system since policies are not loaded yet.
	 * So let do_execve() call this function everytime.
	 */
	{
		struct nameidata nd;
		if (!ccs_loader) ccs_loader = "/sbin/ccs-init";
		if (path_lookup(ccs_loader, lookup_flags, &nd)) {
			printk("Not activating Mandatory Access Control now since %s doesn't exist.\n", ccs_loader);
			return;
		}
		path_release(&nd);
	}
	if (!profile_loaded) {
		char *argv[2], *envp[3];
		printk("Calling %s to load policy. Please wait.\n", ccs_loader);
		argv[0] = (char *) ccs_loader;
		argv[1] = NULL;
		envp[0] = "HOME=/";
		envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
		envp[2] = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
		call_usermodehelper(argv[0], argv, envp, 1);
#else
		call_usermodehelper(argv[0], argv, envp);
#endif
		while (!profile_loaded) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
		}
	}
#ifdef CONFIG_SAKURA
	printk("SAKURA: 1.5.2   2007/12/05\n");
#endif
#ifdef CONFIG_TOMOYO
	printk("TOMOYO: 1.5.2   2007/12/05\n");
#endif
	//if (!profile_loaded) panic("No profiles loaded. Run policy loader using 'init=' option.\n");
	printk("Mandatory Access Control activated.\n");
	sbin_init_started = 1;
	ccs_log_level = KERN_WARNING;
	{ /* Check all profiles currently assigned to domains are defined. */
		struct domain_info *domain;
		for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
			const u8 profile = domain->profile;
			if (!profile_ptr[profile]) panic("Profile %u (used by '%s') not defined.\n", profile, domain->domainname->name); 
		}
	}
}


/*************************  MAC Decision Delayer  *************************/

static DECLARE_WAIT_QUEUE_HEAD(query_wait);

static spinlock_t query_lock = SPIN_LOCK_UNLOCKED;

struct query_entry {
	struct list_head list;
	char *query;
	int query_len;
	unsigned int serial;
	int timer;
	int answer;
};

static LIST_HEAD(query_list);
static atomic_t queryd_watcher = ATOMIC_INIT(0);

int CheckSupervisor(const char *fmt, ...)
{
	va_list args;
	int error = -EPERM;
	int pos, len;
	static unsigned int serial = 0;
	struct query_entry *query_entry;
	if (!CheckCCSFlags(CCS_ALLOW_ENFORCE_GRACE)) return -EPERM;
	if (!atomic_read(&queryd_watcher)) return -EPERM;
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 32;
	va_end(args);
	if ((query_entry = ccs_alloc(sizeof(*query_entry))) == NULL ||
		(query_entry->query = ccs_alloc(len)) == NULL) goto out;
	INIT_LIST_HEAD(&query_entry->list);
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	query_entry->serial = serial++;
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	pos = snprintf(query_entry->query, len - 1, "Q%u\n", query_entry->serial);
	va_start(args, fmt);
	vsnprintf(query_entry->query + pos, len - 1 - pos, fmt, args);
	query_entry->query_len = strlen(query_entry->query) + 1;
	va_end(args);
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	list_add_tail(&query_entry->list, &query_list);
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	UpdateCounter(CCS_UPDATES_COUNTER_QUERY);
	/* Give 10 seconds for supervisor's opinion. */
	for (query_entry->timer = 0; atomic_read(&queryd_watcher) && CheckCCSFlags(CCS_ALLOW_ENFORCE_GRACE) && query_entry->timer < 100; query_entry->timer++) {
		wake_up(&query_wait);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ / 10);
		if (query_entry->answer) break;
	}
	UpdateCounter(CCS_UPDATES_COUNTER_QUERY);
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	list_del(&query_entry->list);
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	switch (query_entry->answer) {
	case 1:
		/* Granted by administrator. */
		error = 0;
		break;
	case 0:
		/* Timed out. */
		break;
	default:
		/* Rejected by administrator. */
		break;
	}
 out: ;
	if (query_entry) ccs_free(query_entry->query);
	ccs_free(query_entry);
	return error;
}

static int PollQuery(struct file *file, poll_table *wait)
{
	int found;
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	found = !list_empty(&query_list);
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	if (found) return POLLIN | POLLRDNORM;
	poll_wait(file, &query_wait, wait);
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	found = !list_empty(&query_list);
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	if (found) return POLLIN | POLLRDNORM;
	return 0;
}

static int ReadQuery(struct io_buffer *head)
{
	struct list_head *tmp;
	int pos = 0, len = 0;
	char *buf;
	if (head->read_avail) return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf); head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	list_for_each(tmp, &query_list) {
		struct query_entry *ptr = list_entry(tmp, struct query_entry, list);
		if (pos++ == head->read_step) {
			len = ptr->query_len;
			break;
		}
	}
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	if (!len) {
		head->read_step = 0;
		return 0;
	}
	if ((buf = ccs_alloc(len)) != NULL) {
		pos = 0;
		/***** CRITICAL SECTION START *****/
		spin_lock(&query_lock);
		list_for_each(tmp, &query_list) {
			struct query_entry *ptr = list_entry(tmp, struct query_entry, list);
			if (pos++ == head->read_step) {
				/* Some query can be skiipped since query_list can change, but I don't care. */
				if (len == ptr->query_len) memmove(buf, ptr->query, len);
				break;
			}
		}
		spin_unlock(&query_lock);
		/***** CRITICAL SECTION END *****/
		if (buf[0]) {
			head->readbuf_size = head->read_avail = len;
			head->read_buf = buf;
			head->read_step++;
		} else {
			ccs_free(buf);
		}
	}
	return 0;
}

static int WriteAnswer(struct io_buffer *head)
{
	char *data = head->write_buf;
	struct list_head *tmp;
	unsigned int serial, answer;
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	list_for_each(tmp, &query_list) {
		struct query_entry *ptr = list_entry(tmp, struct query_entry, list);
		ptr->timer = 0;
	}
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2) return -EINVAL;
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	list_for_each(tmp, &query_list) {
		struct query_entry *ptr = list_entry(tmp, struct query_entry, list);
		if (ptr->serial != serial) continue;
		if (!ptr->answer) ptr->answer = answer;
		break;
	}
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

/*************************  /proc INTERFACE HANDLER  *************************/

/* Policy updates counter. */
static unsigned int updates_counter[MAX_CCS_UPDATES_COUNTER];
static spinlock_t updates_counter_lock = SPIN_LOCK_UNLOCKED;

void UpdateCounter(const unsigned char index)
{
	/***** CRITICAL SECTION START *****/
	spin_lock(&updates_counter_lock);
	if (index < MAX_CCS_UPDATES_COUNTER) updates_counter[index]++;
	spin_unlock(&updates_counter_lock);
	/***** CRITICAL SECTION END *****/
}

static int ReadUpdatesCounter(struct io_buffer *head)
{
	if (!head->read_eof) {
		unsigned int counter[MAX_CCS_UPDATES_COUNTER];
		/***** CRITICAL SECTION START *****/
		spin_lock(&updates_counter_lock);
		memmove(counter, updates_counter, sizeof(updates_counter));
		memset(updates_counter, 0, sizeof(updates_counter));
		spin_unlock(&updates_counter_lock);
		/***** CRITICAL SECTION END *****/
		io_printf(head,
				  "/proc/ccs/system_policy:    %10u\n"
				  "/proc/ccs/domain_policy:    %10u\n"
				  "/proc/ccs/exception_policy: %10u\n"
				  "/proc/ccs/profile:          %10u\n"
				  "/proc/ccs/query:            %10u\n"
				  "/proc/ccs/manager:          %10u\n"
				  "/proc/ccs/grant_log:        %10u\n"
				  "/proc/ccs/reject_log:       %10u\n",
				  counter[CCS_UPDATES_COUNTER_SYSTEM_POLICY],
				  counter[CCS_UPDATES_COUNTER_DOMAIN_POLICY],
				  counter[CCS_UPDATES_COUNTER_EXCEPTION_POLICY],
				  counter[CCS_UPDATES_COUNTER_PROFILE],
				  counter[CCS_UPDATES_COUNTER_QUERY],
				  counter[CCS_UPDATES_COUNTER_MANAGER],
				  counter[CCS_UPDATES_COUNTER_GRANT_LOG],
				  counter[CCS_UPDATES_COUNTER_REJECT_LOG]);
		head->read_eof = 1;
	}
	return 0;
}

static int ReadVersion(struct io_buffer *head)
{
	if (!head->read_eof) {
		if (io_printf(head, "1.5.2") == 0) head->read_eof = 1;
	}
	return 0;
}

static int ReadMemoryCounter(struct io_buffer *head)
{
	if (!head->read_eof) {
		const int shared = GetMemoryUsedForSaveName(), private = GetMemoryUsedForElements(), dynamic = GetMemoryUsedForDynamic();
		if (io_printf(head, "Shared:  %10u\nPrivate: %10u\nDynamic: %10u\nTotal:   %10u\n", shared, private, dynamic, shared + private + dynamic) == 0) head->read_eof = 1;
	}
	return 0;
}

static int ReadSelfDomain(struct io_buffer *head)
{
	if (!head->read_eof) {
		io_printf(head, "%s", current->domain_info->domainname->name);
		head->read_eof = 1;
	}
	return 0;
}

int CCS_OpenControl(const int type, struct file *file)
{
	struct io_buffer *head = ccs_alloc(sizeof(*head));
	if (!head) return -ENOMEM;
	init_MUTEX(&head->read_sem);
	init_MUTEX(&head->write_sem);
	switch (type) {
#ifdef CONFIG_SAKURA
	case CCS_SYSTEMPOLICY:
		head->write = AddSystemPolicy;
		head->read = ReadSystemPolicy;
		break;
#endif
#ifdef CONFIG_TOMOYO
	case CCS_DOMAINPOLICY:
		head->write = AddDomainPolicy;
		head->read = ReadDomainPolicy;
		break;
	case CCS_EXCEPTIONPOLICY:
		head->write = AddExceptionPolicy;
		head->read = ReadExceptionPolicy;
		break;
	case CCS_GRANTLOG:
		head->poll = PollGrantLog;
		head->read = ReadGrantLog;
		break;
	case CCS_REJECTLOG:
		head->poll = PollRejectLog;
		head->read = ReadRejectLog;
		break;
#endif
	case CCS_SELFDOMAIN:
		head->read = ReadSelfDomain;
		break;
	case CCS_DOMAIN_STATUS:
		head->write = UpdateDomainProfile;
		head->read = ReadDomainProfile;
		break;
	case CCS_PROCESS_STATUS:
		head->write = WritePID;
		head->read = ReadPID;
		break;
	case CCS_VERSION:
		head->read = ReadVersion;
		head->readbuf_size = 128;
		break;
	case CCS_MEMINFO:
		head->read = ReadMemoryCounter;
		head->readbuf_size = 128;
		break;
	case CCS_PROFILE:
		head->write = SetProfile;
		head->read = ReadProfile;
		break;
	case CCS_QUERY:
		head->poll = PollQuery;
		head->write = WriteAnswer;
		head->read = ReadQuery;
		break;
	case CCS_MANAGER:
		head->write = AddManagerPolicy;
		head->read = ReadManagerPolicy;
		break;
	case CCS_UPDATESCOUNTER:
		head->read = ReadUpdatesCounter;
		break;
	}
	if (type != CCS_GRANTLOG && type != CCS_REJECTLOG && type != CCS_QUERY) {
		if (!head->readbuf_size) head->readbuf_size = PAGE_SIZE * 2;
		if ((head->read_buf = ccs_alloc(head->readbuf_size)) == NULL) {
			ccs_free(head);
			return -ENOMEM;
		}
	}
	if (head->write) {
		head->writebuf_size = PAGE_SIZE * 2;
		if ((head->write_buf = ccs_alloc(head->writebuf_size)) == NULL) {
			ccs_free(head->read_buf);
			ccs_free(head);
			return -ENOMEM;
		}
	}
	file->private_data = head;
	if (type == CCS_SELFDOMAIN) CCS_ReadControl(file, NULL, 0);
	else if (head->write == WriteAnswer) atomic_inc(&queryd_watcher);
	return 0;
}

static int CopyToUser(struct io_buffer *head, char __user * buffer, int buffer_len)
{
	int len = head->read_avail;
	char *cp = head->read_buf;
	if (len > buffer_len) len = buffer_len;
	if (len) {
		if (copy_to_user(buffer, cp, len)) return -EFAULT;
		head->read_avail -= len;
		memmove(cp, cp + len, head->read_avail);
	}
	return len;
}

int CCS_PollControl(struct file *file, poll_table *wait)
{
	struct io_buffer *head = file->private_data;
	if (!head->poll) return -ENOSYS;
	return head->poll(file, wait);
}

int CCS_ReadControl(struct file *file, char __user *buffer, const int buffer_len)
{
	int len = 0;
	struct io_buffer *head = file->private_data;
	if (!head->read) return -ENOSYS;
	if (!access_ok(VERIFY_WRITE, buffer, buffer_len)) return -EFAULT;
	if (down_interruptible(&head->read_sem)) return -EINTR;
	len = head->read(head);
	if (len >= 0) len = CopyToUser(head, buffer, buffer_len);
	up(&head->read_sem);
	return len;
}

int CCS_WriteControl(struct file *file, const char __user *buffer, const int buffer_len)
{
	struct io_buffer *head = file->private_data;
	int error = buffer_len;
	int avail_len = buffer_len;
	char *cp0 = head->write_buf;
	if (!head->write) return -ENOSYS;
	if (!access_ok(VERIFY_READ, buffer, buffer_len)) return -EFAULT;
	if (!isRoot()) return -EPERM;
	if (head->write != WritePID && !IsPolicyManager()) {
		return -EPERM; /* Forbid updating policies for non manager programs. */
	}
	if (down_interruptible(&head->write_sem)) return -EINTR;
	while (avail_len > 0) {
		char c;
		if (head->write_avail >= head->writebuf_size - 1) {
			error = -ENOMEM;
			break;
		} else if (get_user(c, buffer)) {
			error = -EFAULT;
			break;
		}
		buffer++; avail_len--;
		cp0[head->write_avail++] = c;
		if (c != '\n') continue;
		cp0[head->write_avail - 1] = '\0';
		head->write_avail = 0;
		NormalizeLine(cp0);
		head->write(head);
	}
	up(&head->write_sem);
	return error;
}


int CCS_CloseControl(struct file *file)
{
	struct io_buffer *head = file->private_data;
	if (head->write == WriteAnswer) atomic_dec(&queryd_watcher);
	else if (head->read == ReadMemoryCounter) profile_loaded = 1;
	ccs_free(head->read_buf); head->read_buf = NULL;
	ccs_free(head->write_buf); head->write_buf = NULL;
	ccs_free(head); head = NULL;
	file->private_data = NULL;
	return 0;
}
