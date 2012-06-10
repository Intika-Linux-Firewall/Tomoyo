/*
 * fs/ccs_common.c
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.3.1   2007/01/05
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
#include <linux/version.h>
#include <linux/realpath.h>
#include <linux/ccs_common.h>
#include <linux/ccs_proc.h>
#include <linux/tomoyo.h>

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
	[CCS_TOMOYO_MAC_FOR_BINDPORT]    = { "MAC_FOR_BINDPORT",    0, 3 },
	[CCS_TOMOYO_MAC_FOR_CONNECTPORT] = { "MAC_FOR_CONNECTPORT", 0, 3 },
	[CCS_TOMOYO_MAC_FOR_SIGNAL]      = { "MAC_FOR_SIGNAL",      0, 3 },
	[CCS_SAKURA_DENY_CONCEAL_MOUNT]  = { "DENY_CONCEAL_MOUNT",  0, 3 },
	[CCS_SAKURA_RESTRICT_CHROOT]     = { "RESTRICT_CHROOT",     0, 3 },
	[CCS_SAKURA_RESTRICT_MOUNT]      = { "RESTRICT_MOUNT",      0, 3 },
	[CCS_SAKURA_RESTRICT_UNMOUNT]    = { "RESTRICT_UNMOUNT",    0, 3 },
	[CCS_SAKURA_DENY_PIVOT_ROOT]     = { "DENY_PIVOT_ROOT",     0, 3 },
	[CCS_SAKURA_TRACE_READONLY]      = { "TRACE_READONLY",      0, 1 },
	[CCS_SAKURA_RESTRICT_AUTOBIND]   = { "RESTRICT_AUTOBIND",   0, 1 },
	[CCS_TOMOYO_MAX_ACCEPT_FILES]    = { "MAX_ACCEPT_FILES",    MAX_ACCEPT_FILES, INT_MAX },
	[CCS_TOMOYO_MAX_GRANT_LOG]       = { "MAX_GRANT_LOG",       MAX_GRANT_LOG, INT_MAX },
	[CCS_TOMOYO_MAX_REJECT_LOG]      = { "MAX_REJECT_LOG",      MAX_REJECT_LOG, INT_MAX },
	[CCS_TOMOYO_VERBOSE]             = { "TOMOYO_VERBOSE",      1, 1 },
	[CCS_ALLOW_ENFORCE_GRACE]        = { "ALLOW_ENFORCE_GRACE", 0, 1 },
};

typedef struct {
	unsigned int value[CCS_MAX_CONTROL_INDEX];
	const char *comment;
} PROFILE;

static PROFILE *profile_ptr[MAX_PROFILES];

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

int strendswith(const char *name, const char *tail)
{
	int len;
	if (!name || !tail) return 0;
	len = strlen(name) - strlen(tail);
	return len >= 0 && strcmp(name + len, tail) == 0;
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

int PathDepth(const char *pathname)
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

static int FileMatchesToPattern(const char *filename, const char *filename_end, const char *pattern, const char *pattern_end)
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
						if (FileMatchesToPattern(filename + i, filename_end, pattern + 1, pattern_end)) return 1;
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
						if (FileMatchesToPattern(filename + i, filename_end, pattern + 1, pattern_end)) return 1;
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
 */

int PathMatchesToPattern(const char *pathname, const char *pattern)
{
	if (!pathname || !pattern) return 0;
	/* if pattern doesn't contain '\', I can use strcmp(). */
	if (!strchr(pattern, '\\')) return !strcmp(pathname, pattern);
	if (PathDepth(pathname) != PathDepth(pattern)) return 0;
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
 *  Transactional printf() to IO_BUFFER structure.
 *  snprintf() will truncate, but io_printf() won't.
 *  Returns zero on success, nonzero otherwise.
 */
int io_printf(IO_BUFFER *head, const char *fmt, ...)
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
	if (current->mm) {
		struct vm_area_struct *vma = current->mm->mmap;
		while (vma) {
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
				char *buf = ccs_alloc(PAGE_SIZE);
				if (buf == NULL) return NULL;
				if (realpath_from_dentry(vma->vm_file->f_dentry, vma->vm_file->f_vfsmnt, buf, PAGE_SIZE - 1) == 0) return (const char *) buf;
				ccs_free(buf); return NULL;
			}
			vma = vma->vm_next;
		}
	}
	return NULL;
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
	return sbin_init_started && index < CCS_MAX_CONTROL_INDEX && profile < MAX_PROFILES && profile_ptr[profile] ? profile_ptr[profile]->value[index] : 0;
}

unsigned int TomoyoVerboseMode(void)
{
	return CheckCCSFlags(CCS_TOMOYO_VERBOSE);
}

/* Check whether the given access control is enforce mode. */
unsigned int CheckCCSEnforce(const unsigned int index)
{
	return CheckCCSFlags(index) == 3;
}

/* Check whether the given access control is accept mode. */
unsigned int CheckCCSAccept(const unsigned int index)
{
	return CheckCCSFlags(index) == 1;
}

unsigned int GetMaxAutoAppendFiles(void)
{
	return CheckCCSFlags(CCS_TOMOYO_MAX_ACCEPT_FILES);
}

unsigned int GetMaxGrantLog(void)
{
	return CheckCCSFlags(CCS_TOMOYO_MAX_GRANT_LOG);
}

unsigned int GetMaxRejectLog(void)
{
	return CheckCCSFlags(CCS_TOMOYO_MAX_REJECT_LOG);
}

static PROFILE *FindOrAssignNewProfile(const unsigned int profile)
{
	static DECLARE_MUTEX(profile_lock);
	PROFILE *ptr = NULL;
	down(&profile_lock);
	if (profile < MAX_PROFILES && (ptr = profile_ptr[profile]) == NULL) {
		if ((ptr = (PROFILE *) alloc_element(sizeof(PROFILE))) != NULL) {
			int i;
			for (i = 0; i < CCS_MAX_CONTROL_INDEX; i++) ptr->value[i] = ccs_control_array[i].current_value;
			mb(); /* Instead of using spinlock. */
			profile_ptr[profile] = ptr;
		}
	}
	up(&profile_lock);
	return ptr;
}

static int profile_loaded = 0;

static int SetStatus(IO_BUFFER *head)
{
	char *data = head->write_buf;
	unsigned int i, value;
	char *cp;
	PROFILE *profile;
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
	profile_loaded = 1;
	UpdateCounter(CCS_UPDATES_COUNTER_STATUS);
	if (strcmp(data, ccs_control_array[CCS_PROFILE_COMMENT].keyword) == 0) {
		profile->comment = SaveName(cp + 1);
		return 0;
	}
	if (sscanf(cp + 1, "%u", &value) != 1) return -EINVAL;
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
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

static int ReadStatus(IO_BUFFER *head)
{
	if (!head->read_eof) {
		if (!isRoot()) return -EPERM;
		if (!head->read_var2) {
			int step;
			for (step = head->read_step; step < MAX_PROFILES * CCS_MAX_CONTROL_INDEX; step++) {
				const int i = step / CCS_MAX_CONTROL_INDEX, j = step % CCS_MAX_CONTROL_INDEX;
				const PROFILE *profile = profile_ptr[i];
				head->read_step = step;
				if (!profile) continue;
				switch (j) {
				case -1: // Dummy
#ifndef CONFIG_TOMOYO_MAC_FOR_FILE
				case CCS_TOMOYO_MAC_FOR_FILE:
				case CCS_TOMOYO_MAX_ACCEPT_FILES:
#endif
#ifndef CONFIG_TOMOYO_MAC_FOR_ARGV0
				case CCS_TOMOYO_MAC_FOR_ARGV0:
#endif
#ifndef CONFIG_TOMOYO_MAC_FOR_NETWORKPORT
				case CCS_TOMOYO_MAC_FOR_BINDPORT:
				case CCS_TOMOYO_MAC_FOR_CONNECTPORT:
#endif
#ifndef CONFIG_TOMOYO_MAC_FOR_NETWORK
				case CCS_TOMOYO_MAC_FOR_NETWORK:
#endif
#ifndef CONFIG_TOMOYO_MAC_FOR_SIGNAL
				case CCS_TOMOYO_MAC_FOR_SIGNAL:
#endif
#ifndef CONFIG_SAKURA_DENY_CONCEAL_MOUNT
				case CCS_SAKURA_DENY_CONCEAL_MOUNT:
#endif
#ifndef CONFIG_SAKURA_RESTRICT_CHROOT
				case CCS_SAKURA_RESTRICT_CHROOT:
#endif
#ifndef CONFIG_SAKURA_RESTRICT_MOUNT
				case CCS_SAKURA_RESTRICT_MOUNT:
#endif
#ifndef CONFIG_SAKURA_RESTRICT_UNMOUNT
				case CCS_SAKURA_RESTRICT_UNMOUNT:
#endif
#ifndef CONFIG_SAKURA_DENY_PIVOT_ROOT
				case CCS_SAKURA_DENY_PIVOT_ROOT:
#endif
#ifndef CONFIG_SAKURA_TRACE_READONLY
				case CCS_SAKURA_TRACE_READONLY:
#endif
#ifndef CONFIG_SAKURA_RESTRICT_AUTOBIND
				case CCS_SAKURA_RESTRICT_AUTOBIND:
#endif
#ifndef CONFIG_TOMOYO
				case CCS_TOMOYO_MAX_GRANT_LOG:
				case CCS_TOMOYO_MAX_REJECT_LOG:
				case CCS_TOMOYO_VERBOSE:
#endif
					continue;
				}
				if (j == CCS_PROFILE_COMMENT) {
					const char *comment = profile->comment;
					if (!comment) comment = "";
					if (io_printf(head, "%u-%s=%s\n", i, ccs_control_array[CCS_PROFILE_COMMENT].keyword, comment)) break;
				} else {
					if (io_printf(head, "%u-%s=%u\n", i, ccs_control_array[j].keyword, profile->value[j])) break;
				}
			}
			if (step == MAX_PROFILES * CCS_MAX_CONTROL_INDEX) {
				head->read_var2 = (void *) "";
				head->read_step = 0;
			}
		}
		if (head->read_var2) {
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
			if (ReadCapabilityStatus(head) == 0) head->read_eof = 1;
#else
			head->read_eof = 1;
#endif
		}
	}
	return 0;
}

/*************************  POLICY MANAGER HANDLER  *************************/

typedef struct policy_manager_entry {
	struct policy_manager_entry *next; /* Pointer to next record. NULL if none. */
	const char *exe;                   /* Filename. Never NULL.                 */
} POLICY_MANAGER_ENTRY;

static POLICY_MANAGER_ENTRY policy_manager_list = { NULL, "" };

static int AddManagerPolicy(IO_BUFFER *head)
{
	const char *exe = head->write_buf;
	POLICY_MANAGER_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_exe;
	if (!isRoot()) return -EPERM;
	if (!IsCorrectPath(exe, 1, -1, -1, __FUNCTION__)) return -EINVAL;
	UpdateCounter(CCS_UPDATES_COUNTER_MANAGER);
	/* I don't want to add if it was already added. */
	for (ptr = policy_manager_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->exe, exe) == 0) return 0;
	if ((saved_exe = SaveName(exe)) == NULL || (new_entry = (POLICY_MANAGER_ENTRY *) alloc_element(sizeof(POLICY_MANAGER_ENTRY))) == NULL) return -ENOMEM;
	new_entry->exe = saved_exe;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &policy_manager_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

static int ReadManagerPolicy(IO_BUFFER *head)
{
	if (!head->read_eof) {
		POLICY_MANAGER_ENTRY *ptr = (POLICY_MANAGER_ENTRY *) head->read_var2;
		if (!isRoot()) return -EPERM;
		if (!ptr) ptr = policy_manager_list.next;
		while (ptr) {
			head->read_var2 = (void *) ptr;
			if (io_printf(head, "%s\n", ptr->exe)) break;
			ptr = ptr->next;
		}
		if (!ptr) head->read_eof = 1;
	}
	return 0;
}

/* Check whether the current process is a policy manager. */
static int IsPolicyManager(void)
{
	POLICY_MANAGER_ENTRY *ptr;
	const char *exe;
	if (!sbin_init_started) return 1;
	if ((exe = GetEXE()) == NULL) return 0;
	for (ptr = policy_manager_list.next; ptr; ptr = ptr->next) {
		if (strcmp(exe, ptr->exe) == 0) break;
	}
	if (!ptr) { /* Reduce error messages. */
		static pid_t last_pid = 0;
		const pid_t pid = current->pid;
		if (last_pid != pid) {
			printk("%s is not permitted to update policies.\n", exe);
			last_pid = pid;
		}
	}
	ccs_free(exe);
	return ptr ? 1 : 0;
}

#ifdef CONFIG_TOMOYO

/*************************  DOMAIN POLICY HANDLER  *************************/

static int AddDomainPolicy(IO_BUFFER *head)
{
	char *data = head->write_buf;
	struct domain_info *domain = head->write_var1;
	int is_delete = 0, is_select = 0;
	unsigned int profile;
	if (!isRoot()) return -EPERM;
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		is_delete = 1;
	} else if (strncmp(data, KEYWORD_SELECT, KEYWORD_SELECT_LEN) == 0) {
		data += KEYWORD_SELECT_LEN;
		is_select = 1;
	}
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	if (IsDomainDef(data)) {
		if (is_delete) {
			DeleteDomain(data);
			domain = NULL;
		} else if (is_select) {
			domain = FindDomain(data);
		} else {
			domain = FindOrAssignNewDomain(data, 0);
		}
		head->write_var1 = domain;
		return 0;
	}
	if (!domain) return -EINVAL;
	if (sscanf(data, KEYWORD_USE_PROFILE "%u", &profile) == 1 && profile < MAX_PROFILES) {
		if (profile_ptr[profile] || !sbin_init_started) domain->profile = (u8) profile;
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
	} else if (strncmp(data, KEYWORD_ALLOW_CAPABILITY, KEYWORD_ALLOW_CAPABILITY_LEN) == 0) {
		return AddCapabilityPolicy(data + KEYWORD_ALLOW_CAPABILITY_LEN, domain, is_delete);
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_NETWORKPORT
	} else if (strncmp(data, KEYWORD_ALLOW_BIND, KEYWORD_ALLOW_BIND_LEN) == 0 ||
			   strncmp(data, KEYWORD_ALLOW_CONNECT, KEYWORD_ALLOW_CONNECT_LEN) == 0) {
		return AddPortPolicy(data, domain, is_delete);
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_NETWORK
	} else if (strncmp(data, KEYWORD_ALLOW_NETWORK, KEYWORD_ALLOW_NETWORK_LEN) == 0) {
		return AddNetworkPolicy(data + KEYWORD_ALLOW_NETWORK_LEN, domain, is_delete);
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_SIGNAL
	} else if (strncmp(data, KEYWORD_ALLOW_SIGNAL, KEYWORD_ALLOW_SIGNAL_LEN) == 0) {
		return AddSignalPolicy(data + KEYWORD_ALLOW_SIGNAL_LEN, domain, is_delete);
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_ARGV0
	} else if (strncmp(data, KEYWORD_ALLOW_ARGV0, KEYWORD_ALLOW_ARGV0_LEN) == 0) {
		return AddArgv0Policy(data + KEYWORD_ALLOW_ARGV0_LEN, domain, is_delete);
#endif
	} else {
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
		return AddFilePolicy(data, domain, is_delete);
#endif
	}
	return -EINVAL;
}

static int ReadDomainPolicy(IO_BUFFER *head)
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
			if (GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_DELETED) continue;
			head->read_var1 = domain;
			head->read_var2 = NULL; head->read_step = 1;
		step1:
			if (io_printf(head, "%s\n" KEYWORD_USE_PROFILE "%u\n\n", domain->domainname, domain->profile)) break;
			head->read_var2 = (void *) domain->first_acl_ptr; head->read_step = 2;
		step2:
			for (ptr = (struct acl_info *) head->read_var2; ptr; ptr = ptr->next) {
				const unsigned int acl_type = GET_ACL_TYPE(ptr->type_hash);
				const int pos = head->read_avail;
				head->read_var2 = (void *) ptr;
				if (0) {
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
				} else if (acl_type == TYPE_FILE_ACL) {
					if (io_printf(head, "%d %s", ((FILE_ACL_RECORD *) ptr)->perm, ((FILE_ACL_RECORD *) ptr)->filename)
						|| DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_ARGV0
				} else if (acl_type == TYPE_ARGV0_ACL) {
					if (io_printf(head, KEYWORD_ALLOW_ARGV0 "%s %s", ((ARGV0_ACL_RECORD *) ptr)->filename, ((ARGV0_ACL_RECORD *) ptr)->argv0) ||
						DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
				} else if (acl_type == TYPE_CAPABILITY_ACL) {
					if (io_printf(head, KEYWORD_ALLOW_CAPABILITY "%s", capability2keyword(GET_ACL_HASH(ptr->type_hash))) ||
						DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_NETWORKPORT
				} else if (acl_type == TYPE_BIND_ACL || acl_type == TYPE_CONNECT_ACL) {
					const int is_stream = GET_ACL_HASH(ptr->type_hash);
					const u16 min_port = ((NETWORK_ACL_RECORD *) ptr)->min_port, max_port = ((NETWORK_ACL_RECORD *) ptr)->max_port;
					if (min_port != max_port) {
						if (io_printf(head, "%s%s/%u-%u", acl_type == TYPE_CONNECT_ACL ? KEYWORD_ALLOW_CONNECT : KEYWORD_ALLOW_BIND, is_stream ? "TCP" : "UDP", min_port, max_port) ||
							DumpCondition(head, ptr->cond)) {
							head->read_avail = pos; break;
						}
					} else {
						if (io_printf(head, "%s%s/%u", acl_type == TYPE_CONNECT_ACL ? KEYWORD_ALLOW_CONNECT : KEYWORD_ALLOW_BIND, is_stream ? "TCP" : "UDP", min_port) ||
							DumpCondition(head, ptr->cond)) {
							head->read_avail = pos; break;
						}
					}
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_NETWORK
				} else if (acl_type == TYPE_IPv4_NETWORK_ACL) {
					const char *keyword = network2keyword(GET_ACL_HASH(ptr->type_hash));
					const u32 min_address = ((IPv4_NETWORK_ACL_RECORD *) ptr)->min_address, max_address = ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_address;
					const u16 min_port = ((IPv4_NETWORK_ACL_RECORD *) ptr)->min_port, max_port = ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_port;
					if (min_address != max_address) {
						if (min_port != max_port) {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %u.%u.%u.%u-%u.%u.%u.%u %u-%u", keyword, HIPQUAD(min_address), HIPQUAD(max_address), min_port, max_port) || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						} else {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %u.%u.%u.%u-%u.%u.%u.%u %u", keyword, HIPQUAD(min_address), HIPQUAD(max_address), min_port) || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						}
					} else {
						if (min_port != max_port) {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %u.%u.%u.%u %u-%u", keyword, HIPQUAD(min_address), min_port, max_port) || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						} else {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %u.%u.%u.%u %u", keyword, HIPQUAD(min_address), min_port) || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						}
					}
				} else if (acl_type == TYPE_IPv6_NETWORK_ACL) {
					const char *keyword = network2keyword(GET_ACL_HASH(ptr->type_hash));
					const u8 *min_address = ((IPv6_NETWORK_ACL_RECORD *) ptr)->min_address, *max_address = ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_address;
					const u16 min_port = ((IPv6_NETWORK_ACL_RECORD *) ptr)->min_port, max_port = ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_port;
					char buf1[64], buf2[64];
					print_ipv6(buf1, sizeof(buf1), (const u16 *) min_address);
					print_ipv6(buf2, sizeof(buf2), (const u16 *) max_address);
					if (memcmp(min_address, max_address, 16)) {
						if (min_port != max_port) {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %s-%s %u-%u", keyword, buf1, buf2, min_port, max_port)|| DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						} else {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %s-%s %u", keyword, buf1, buf2, min_port) || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						}
					} else {
						if (min_port != max_port) {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %s %u-%u", keyword, buf1, min_port, max_port) || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						} else {
							if (io_printf(head, KEYWORD_ALLOW_NETWORK "%s %s %u", keyword, buf1, min_port) || DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						}
					}
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_SIGNAL
				} else if (acl_type == TYPE_SIGNAL_ACL) {
					if (io_printf(head, KEYWORD_ALLOW_SIGNAL "%u %s", GET_ACL_HASH(ptr->type_hash), ((SIGNAL_ACL_RECORD *) ptr)->domainname) ||
						DumpCondition(head, ptr->cond)) {
						head->read_avail = pos; break;
					}
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
				} else {
					const char *keyword = acltype2keyword(acl_type);
					if (keyword) {
						if (acltype2paths(acl_type) == 2) {
							if (io_printf(head, "allow_%s %s %s", keyword, ((DOUBLE_ACL_RECORD *) ptr)->filename1, ((DOUBLE_ACL_RECORD *) ptr)->filename2)
								|| DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						} else {
							if (io_printf(head, "allow_%s %s", keyword, ((SINGLE_ACL_RECORD *) ptr)->filename)
								|| DumpCondition(head, ptr->cond)) {
								head->read_avail = pos; break;
							}
						}
					}
#endif
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

static int ReadDomainProfile(IO_BUFFER *head)
{
	if (!head->read_eof) {
		struct domain_info *domain;
		if (head->read_step == 0) {
			head->read_var1 = &KERNEL_DOMAIN;
			head->read_step = 1;
		}
		if (!isRoot()) return -EPERM;
		for (domain = head->read_var1; domain; domain = domain->next) {
			if (GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_DELETED) continue;
			head->read_var1 = domain;
			if (io_printf(head, "%u %s\n", domain->profile, domain->domainname)) break;
		}
		if (!domain) head->read_eof = 1;
	}
	return 0;
}

static int WritePID(IO_BUFFER *head)
{
	head->read_step = (int) simple_strtoul(head->write_buf, NULL, 10);
	head->read_eof = 0;
	return 0;
}

static int ReadPID(IO_BUFFER *head)
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
		if (domain) io_printf(head, "%d %u %s", pid, domain->profile, domain->domainname);
		head->read_eof = 1;
	}
	return 0;
}

static int UpdateDomainProfile(IO_BUFFER *head)
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

#endif

/*************************  EXCEPTION POLICY HANDLER  *************************/

#ifdef CONFIG_TOMOYO

static int AddExceptionPolicy(IO_BUFFER *head)
{
	char *data = head->write_buf;
	int is_delete = 0;
	if (!isRoot()) return -EPERM;
	UpdateCounter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		is_delete = 1;
	}
	if (strncmp(data, KEYWORD_DOMAIN_KEEPER, KEYWORD_DOMAIN_KEEPER_LEN) == 0) {
		return AddDomainKeeperPolicy(data + KEYWORD_DOMAIN_KEEPER_LEN, is_delete);
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
	} else if (strncmp(data, KEYWORD_ALLOW_READ, KEYWORD_ALLOW_READ_LEN) == 0) {
		return AddGloballyReadablePolicy(data + KEYWORD_ALLOW_READ_LEN, is_delete);
#endif
	} else if (strncmp(data, KEYWORD_INITIALIZER, KEYWORD_INITIALIZER_LEN) == 0) {
		return AddInitializerPolicy(data + KEYWORD_INITIALIZER_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_ALIAS, KEYWORD_ALIAS_LEN) == 0) {
		return AddAliasPolicy(data + KEYWORD_ALIAS_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_AGGREGATOR, KEYWORD_AGGREGATOR_LEN) == 0) {
		return AddAggregatorPolicy(data + KEYWORD_AGGREGATOR_LEN, is_delete);
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
	} else if (strncmp(data, KEYWORD_FILE_PATTERN, KEYWORD_FILE_PATTERN_LEN) == 0) {
		return AddPatternPolicy(data + KEYWORD_FILE_PATTERN_LEN, is_delete);
	} else if (strncmp(data, KEYWORD_DENY_REWRITE, KEYWORD_DENY_REWRITE_LEN) == 0) {
		return AddNoRewritePolicy(data + KEYWORD_DENY_REWRITE_LEN, is_delete);
#endif
	}
	return -EINVAL;
}

static int ReadExceptionPolicy(IO_BUFFER *head)
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
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
			if (ReadGloballyReadablePolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 3;
		case 3:
			if (ReadInitializerPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 4;
		case 4:
			if (ReadAliasPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 5;
		case 5:
			if (ReadAggregatorPolicy(head)) break;
			head->read_var2 = NULL; head->read_step = 6;
		case 6:
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
			if (ReadPatternPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 7;
		case 7:
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
			if (ReadNoRewritePolicy(head)) break;
#endif
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

static int AddSystemPolicy(IO_BUFFER *head)
{
	char *data = head->write_buf;
	int is_delete = 0;
	if (!isRoot()) return -EPERM;
	UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		is_delete = 1;
	}
#ifdef CONFIG_SAKURA_RESTRICT_MOUNT
	if (strncmp(data, KEYWORD_ALLOW_MOUNT, KEYWORD_ALLOW_MOUNT_LEN) == 0)
		return AddMountPolicy(data + KEYWORD_ALLOW_MOUNT_LEN, is_delete);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_UNMOUNT
	if (strncmp(data, KEYWORD_DENY_UNMOUNT, KEYWORD_DENY_UNMOUNT_LEN) == 0)
		return AddNoUmountPolicy(data + KEYWORD_DENY_UNMOUNT_LEN, is_delete);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_CHROOT
	if (strncmp(data, KEYWORD_ALLOW_CHROOT, KEYWORD_ALLOW_CHROOT_LEN) == 0)
		return AddChrootPolicy(data + KEYWORD_ALLOW_CHROOT_LEN, is_delete);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_AUTOBIND
	if (strncmp(data, KEYWORD_DENY_AUTOBIND, KEYWORD_DENY_AUTOBIND_LEN) == 0)
		return AddReservedPortPolicy(data + KEYWORD_DENY_AUTOBIND_LEN, is_delete);
#endif
	return -EINVAL;
}

static int ReadSystemPolicy(IO_BUFFER *head)
{
	if (!head->read_eof) {
		switch (head->read_step) {
		case 0:
			if (!isRoot()) return -EPERM;
			head->read_var2 = NULL; head->read_step = 1;
		case 1:
#ifdef CONFIG_SAKURA_RESTRICT_MOUNT
			if (ReadMountPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 2;
		case 2:
#ifdef CONFIG_SAKURA_RESTRICT_UNMOUNT
			if (ReadNoUmountPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 3;
		case 3:
#ifdef CONFIG_SAKURA_RESTRICT_CHROOT
			if (ReadChrootPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 4;
		case 4:
#ifdef CONFIG_SAKURA_RESTRICT_AUTOBIND
			if (ReadReservedPortPolicy(head)) break;
#endif
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
		if (!ccs_loader) ccs_loader = "/.init";
		if (path_lookup(ccs_loader, lookup_flags, &nd)) {
			printk("Not activating Mandatory Access Control now since %s doesn't exist.\n", ccs_loader);
			return;
		}
		path_release(&nd);
	}
	
#ifdef CONFIG_SAKURA
	printk("SAKURA: 1.3.1   2007/01/05\n");
#endif
#ifdef CONFIG_TOMOYO
	printk("TOMOYO: 1.3.1   2007/01/05\n");
#endif
	if (!profile_loaded) panic("No profiles loaded. Run policy loader using 'init=' option.\n");
	printk("Mandatory Access Control activated.\n");
	sbin_init_started = 1;
	ccs_log_level = KERN_WARNING;
	{ /* Check all profiles currently assigned to domains are defined. */
		struct domain_info *domain;
		for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
			const u8 profile = domain->profile;
			if (!profile_ptr[profile]) panic("Profile %u (used by '%s') not defined.\n", profile, domain->domainname); 
		}
	}
}


/*************************  MAC Decision Delayer  *************************/

static DECLARE_WAIT_QUEUE_HEAD(query_wait);

static spinlock_t query_lock = SPIN_LOCK_UNLOCKED;

typedef struct query_entry {
	struct list_head list;
	char *query;
	int query_len;
	unsigned int serial;
	int timer;
	int answer;
} QUERY_ENTRY;

static LIST_HEAD(query_list);
static atomic_t queryd_watcher = ATOMIC_INIT(0);

int CheckSupervisor(const char *fmt, ...)
{
	va_list args;
	int error = -EPERM;
	int pos, len;
	static unsigned int serial = 0;
	QUERY_ENTRY *query_entry;
	if (!CheckCCSFlags(CCS_ALLOW_ENFORCE_GRACE)) return -EPERM;
	if (!atomic_read(&queryd_watcher)) return -EPERM;
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 32;
	va_end(args);
	if ((query_entry = (QUERY_ENTRY *) ccs_alloc(sizeof(QUERY_ENTRY))) == NULL ||
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

static int ReadQuery(IO_BUFFER *head)
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
		QUERY_ENTRY *ptr = list_entry(tmp, QUERY_ENTRY, list);
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
	if ((buf = (char *) ccs_alloc(len)) != NULL) {
		pos = 0;
		/***** CRITICAL SECTION START *****/
		spin_lock(&query_lock);
		list_for_each(tmp, &query_list) {
			QUERY_ENTRY *ptr = list_entry(tmp, QUERY_ENTRY, list);
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

static int WriteAnswer(IO_BUFFER *head)
{
	char *data = head->write_buf;
	struct list_head *tmp;
	unsigned int serial, answer;
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	list_for_each(tmp, &query_list) {
		QUERY_ENTRY *ptr = list_entry(tmp, QUERY_ENTRY, list);
		ptr->timer = 0;
	}
	spin_unlock(&query_lock);
	/***** CRITICAL SECTION END *****/
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2) return -EINVAL;
	/***** CRITICAL SECTION START *****/
	spin_lock(&query_lock);
	list_for_each(tmp, &query_list) {
		QUERY_ENTRY *ptr = list_entry(tmp, QUERY_ENTRY, list);
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

static int ReadUpdatesCounter(IO_BUFFER *head)
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
				  "/proc/ccs/policy/system_policy:    %10u\n"
				  "/proc/ccs/policy/domain_policy:    %10u\n"
				  "/proc/ccs/policy/exception_policy: %10u\n"
				  "/proc/ccs/status:                  %10u\n"
				  "/proc/ccs/policy/query:            %10u\n"
				  "/proc/ccs/policy/manager:          %10u\n"
				  "/proc/ccs/info/grant_log:          %10u\n"
				  "/proc/ccs/info/reject_log:         %10u\n",
				  counter[CCS_UPDATES_COUNTER_SYSTEM_POLICY],
				  counter[CCS_UPDATES_COUNTER_DOMAIN_POLICY],
				  counter[CCS_UPDATES_COUNTER_EXCEPTION_POLICY],
				  counter[CCS_UPDATES_COUNTER_STATUS],
				  counter[CCS_UPDATES_COUNTER_QUERY],
				  counter[CCS_UPDATES_COUNTER_MANAGER],
				  counter[CCS_UPDATES_COUNTER_GRANT_LOG],
				  counter[CCS_UPDATES_COUNTER_REJECT_LOG]);
		head->read_eof = 1;
	}
	return 0;
}

static int ReadMemoryCounter(IO_BUFFER *head)
{
	if (!head->read_eof) {
		const int shared = GetMemoryUsedForSaveName(), private = GetMemoryUsedForElements(), dynamic = GetMemoryUsedForDynamic();
		if (io_printf(head, "Shared:  %10u\nPrivate: %10u\nDynamic: %10u\nTotal:   %10u\n", shared, private, dynamic, shared + private + dynamic) == 0) head->read_eof = 1;
	}
	return 0;
}

int CCS_OpenControl(const int type, struct file *file)
{
	IO_BUFFER *head = (IO_BUFFER *) ccs_alloc(sizeof(IO_BUFFER));
	if (!head) return -ENOMEM;
	init_MUTEX(&head->read_sem);
	init_MUTEX(&head->write_sem);
	switch (type) {
#ifdef CONFIG_TOMOYO
	case CCS_POLICY_DOMAINPOLICY:
		head->write = AddDomainPolicy;
		head->read = ReadDomainPolicy;
		break;
	case CCS_POLICY_EXCEPTIONPOLICY:
		head->write = AddExceptionPolicy;
		head->read = ReadExceptionPolicy;
		break;
	case CCS_POLICY_DOMAIN_STATUS:
		head->write = UpdateDomainProfile;
		head->read = ReadDomainProfile;
		break;
	case CCS_INFO_PROCESS_STATUS:
		head->write = WritePID;
		head->read = ReadPID;
		break;
#ifdef CONFIG_TOMOYO_AUDIT
	case CCS_INFO_GRANTLOG:
		head->poll = PollGrantLog;
		head->read = ReadGrantLog;
		break;
	case CCS_INFO_REJECTLOG:
		head->poll = PollRejectLog;
		head->read = ReadRejectLog;
		break;
#endif
	case CCS_INFO_SELFDOMAIN:
		head->read = ReadSelfDomain;
		break;
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
	case CCS_INFO_MAPPING:
		if (!sbin_init_started) head->write = SetPermissionMapping;
		head->read = ReadPermissionMapping;
		break;
#endif
#endif
#ifdef CONFIG_SAKURA
	case CCS_POLICY_SYSTEMPOLICY:
		head->write = AddSystemPolicy;
		head->read = ReadSystemPolicy;
		break;
#endif
	case CCS_INFO_MEMINFO:
		head->read = ReadMemoryCounter;
		head->readbuf_size = 128;
		break;
	case CCS_STATUS:
		head->write = SetStatus;
		head->read = ReadStatus;
		break;
	case CCS_POLICY_QUERY:
		head->poll = PollQuery;
		head->write = WriteAnswer;
		head->read = ReadQuery;
		break;
	case CCS_POLICY_MANAGER:
		head->write = AddManagerPolicy;
		head->read = ReadManagerPolicy;
		break;
	case CCS_INFO_UPDATESCOUNTER:
		head->read = ReadUpdatesCounter;
		break;
	}
	if (type != CCS_INFO_GRANTLOG && type != CCS_INFO_REJECTLOG && type != CCS_POLICY_QUERY) {
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
	if (type == CCS_INFO_SELFDOMAIN) CCS_ReadControl(file, NULL, 0);
	else if (head->write == WriteAnswer) atomic_inc(&queryd_watcher);
	return 0;
}

static int CopyToUser(IO_BUFFER *head, char __user * buffer, int buffer_len)
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
	IO_BUFFER *head = (IO_BUFFER *) file->private_data;
	if (!head->poll) return -ENOSYS;
	return head->poll(file, wait);
}

int CCS_ReadControl(struct file *file, char __user *buffer, const int buffer_len)
{
	int len = 0;
	IO_BUFFER *head = (IO_BUFFER *) file->private_data;
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
	IO_BUFFER *head = (IO_BUFFER *) file->private_data;
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
	IO_BUFFER *head = file->private_data;
	if (head->write == WriteAnswer) atomic_dec(&queryd_watcher);
	ccs_free(head->read_buf); head->read_buf = NULL;
	ccs_free(head->write_buf); head->write_buf = NULL;
	ccs_free(head); head = NULL;
	file->private_data = NULL;
	return 0;
}

EXPORT_SYMBOL(CheckCCSFlags);
EXPORT_SYMBOL(CheckCCSEnforce);
EXPORT_SYMBOL(CheckCCSAccept);
