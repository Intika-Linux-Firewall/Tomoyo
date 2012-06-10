/*
 * fs/ccs_common.c
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
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
#include <linux/realpath.h>
#include <linux/ccs_common.h>
#include <linux/ccs_proc.h>

/*************************  PROTOTYPES  *************************/

static int AddPolicyManagerPolicy(char *exe, void **dummy);
static int IsPolicyManager(void);
static int LoadPolicyManager(void);
#ifdef CONFIG_TOMOYO
static int AddDomainPolicy(char *data, void **domain);
static int LoadDomainPolicy(void);
static int ReadDomainPolicy(IO_BUFFER *head);
static int AddExceptionPolicy(char *data, void **dummy);
static int LoadExceptionPolicy(void);
static int ReadExceptionPolicy(IO_BUFFER *head);
#endif
#ifdef CONFIG_SAKURA
static int LoadSystemPolicy(void);
static int ReadSystemPolicy(IO_BUFFER *head);
#endif
static int ReadMemoryCounter(IO_BUFFER *head);
static int CopyToUser(IO_BUFFER *head, char __user * buffer, int buffer_len);

/*************************  VARIABLES  *************************/

/* /sbin/init started? */
extern int sbin_init_started;

static struct {
	const unsigned int assertion_index;
	const char *keyword;
	unsigned int current_value;
	const unsigned int max_value;
} ccs_control_array[] = {
	{ CCS_TOMOYO_MAC_FOR_FILE,        "MAC_FOR_FILE",        0, 3 },              /* domain_policy.txt */
	{ CCS_TOMOYO_MAC_FOR_BINDPORT,    "MAC_FOR_BINDPORT",    0, 3 },              /* domain_policy.txt */
	{ CCS_TOMOYO_MAC_FOR_CONNECTPORT, "MAC_FOR_CONNECTPORT", 0, 3 },              /* domain_policy.txt */
	{ CCS_TOMOYO_MAC_FOR_SIGNAL,      "MAC_FOR_SIGNAL",      0, 3 },              /* domain_policy.txt */
	{ CCS_SAKURA_DENY_CONCEAL_MOUNT,  "DENY_CONCEAL_MOUNT",  0, 3 },
	{ CCS_SAKURA_RESTRICT_CHROOT,     "RESTRICT_CHROOT",     0, 3 },              /* system_policy.txt */
	{ CCS_SAKURA_RESTRICT_MOUNT,      "RESTRICT_MOUNT",      0, 3 },              /* system_policy.txt */
	{ CCS_SAKURA_RESTRICT_UNMOUNT,    "RESTRICT_UNMOUNT",    0, 3 },              /* system_policy.txt */
	{ CCS_SAKURA_DENY_PIVOT_ROOT,     "DENY_PIVOT_ROOT",     0, 3 },
	{ CCS_SAKURA_TRACE_READONLY,      "TRACE_READONLY",      0, 1 },
	{ CCS_SAKURA_RESTRICT_AUTOBIND,   "RESTRICT_AUTOBIND",   0, 1 },              /* system_policy.txt */
	{ CCS_TOMOYO_MAX_ACCEPT_FILES,    "MAX_ACCEPT_FILES",    MAX_ACCEPT_FILES, UINT_MAX },
	{ CCS_TOMOYO_MAX_GRANT_LOG,       "MAX_GRANT_LOG",       MAX_GRANT_LOG, MAX_GRANT_LOG },
	{ CCS_TOMOYO_MAX_REJECT_LOG,      "MAX_REJECT_LOG",      MAX_REJECT_LOG, MAX_REJECT_LOG },
	{ CCS_TOMOYO_VERBOSE,             "TOMOYO_VERBOSE",      1, 1 },
	{ 0, NULL, 0, 0 }
};

/*************************  UTILITY FUNCTIONS  *************************/

static int __init TOMOYO_Quiet_Setup(char *str)
{
	ccs_control_array[CCS_TOMOYO_VERBOSE].current_value = 0;
	return 0;
}

__setup("TOMOYO_QUIET", TOMOYO_Quiet_Setup);

/* Am I root? */
int isRoot(void)
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
void NormalizeLine(unsigned char *buffer)
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
int IsCorrectPath(const char *filename, const int may_contain_pattern)
{
	if (filename && *filename == '/') {
		char c, d, e;
		while ((c = *filename++) != '\0') {
			if (c == '\\') {
				switch ((c = *filename++)) {
				case '\\':  /* "\\" */
					continue;
				case '$':   /* "\$" */
				case '+':   /* "\+" */
				case '?':   /* "\?" */
					if (may_contain_pattern) continue;
					break;
				case '*':   /* "\*" */
					if (may_contain_pattern) {
						while (*filename && *filename != '/') filename++;
						if (!*filename || *filename == '/') continue;
					}
					break;
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
				return 0;
			} else if (c <= ' ' || c >= 127) {
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

/*
 *  Check whether the given pathname matches to the given pattern.
 *  Returns nonzero if matches, zero otherwise.
 *
 *  The following patterns are available.
 *    \\     \ itself.
 *    \$     More than or equals to 1 digit.
 *    \+     1 digit.
 *    \*     More than or equals to 0 character until '/' or end.
 *    \?     1 character other than '/'.
 *    \ooo   Octal representation of a byte. ooo is Between 001 and 040 or 177 and 377.
 */
int PathMatchesToPattern(const char *pathname, const char *pattern)
{
	if (!pathname || !pattern) return 0;
	/* if pattern doesn't contain \ , I can use strcmp(). */
	if (!strchr(pattern, '\\')) return !strcmp(pathname, pattern);
	while (*pathname && *pattern) {
		if (*pattern == '\\') {
			pattern++;
			switch (*pattern) {
			case '\\':
				if (*pathname != '\\') return 0;
				pathname++; /* safe because *pathname != '\0' */
				if (*pathname != '\\') return 0;
				pathname++; /* safe because *pathname != '\0' */
				break;
			case '$':
				if (*pathname < '0' || *pathname > '9') return 0;
				pathname++; /* safe because *pathname != '\0' */
				while (*pathname >= '0' && *pathname <= '9') pathname++;
				break;
			case '+':
				if (*pathname < '0' || *pathname > '9') return 0;
				pathname++; /* safe because *pathname != '\0' */
				break;
			case '*':
				while (*pathname && *pathname != '/') pathname++;
				break;
			case '?':
				if (*pathname == '/') return 0;
				pathname++; /* safe because *pathname != '\0' */
				break;
			case '0':
			case '1':
			case '2':
			case '3':
				{   /* Is this \ooo pattern? */
					char c = *pattern, d, e;
					if ((d = *(pattern + 1)) >= '0' && d <= '7' && (e = *(pattern + 2)) >= '0' && e <= '7' /* pattern is \ooo */
						&& (c != '0' || d != '0' || e != '0')    /* pattern is not \000 */
						&& *pathname == '\\' && *(pathname + 1) == c && *(pathname + 2) == d && *(pathname + 3) == e) {
						pathname += 4;  /* safe because pathname is \ooo */
						pattern += 2;   /* safe because pattern is \ooo  */
						break;
					}
					return 0;   /* Not matched. */
				}
			default:
				return 0;   /* Bad pattern. */
			}
			pattern++;
		} else {
			if (*pathname != *pattern) return 0;
			pathname++; pattern++;
		}
	}
	/* Skip trailing '\*'s in pattern string. */
	if (!*pathname) while (*pattern == '\\' && *(pattern + 1) == '*') pattern += 2;
	return (!*pathname && !*pattern);
}

/*
 *  Read policy file and dispatch.
 */
int ReadFileAndProcess(struct file *file, int (*func) (char *, void **))
{
	char *buffer, *cp;
	void *ptr = NULL;
	int len;
	unsigned long offset = 0;
	if (!file || !func) return -EINVAL;
	if ((buffer = kmalloc(PAGE_SIZE * 2, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buffer, 0, PAGE_SIZE * 2);
	/* Reads one line and process it. Ends when no more '\n' found. */
	while ((len = kernel_read(file, offset, buffer, PAGE_SIZE * 2)) > 0 && (cp = memchr(buffer, '\n', len)) != NULL) {
		*cp = '\0';
		offset += cp - buffer + 1;
		NormalizeLine(buffer);
		func(buffer, &ptr);
	}
	kfree(buffer);
	return 0;
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
 * This function uses kmalloc(), so caller must kfree() if this function didn't return NULL.
 */
const char *GetEXE(void)
{
	if (current->mm) {
		struct vm_area_struct *vma = current->mm->mmap;
		while (vma) {
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
				char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
				if (buf == NULL) return NULL;
				memset(buf, 0, PAGE_SIZE);
				if (realpath_from_dentry(vma->vm_file->f_dentry, vma->vm_file->f_vfsmnt, buf, PAGE_SIZE - 1) == 0) return (const char *) buf;
				kfree(buf); return NULL;
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

unsigned int TomoyoVerboseMode(void)
{
	return ccs_control_array[CCS_TOMOYO_VERBOSE].current_value;
}

/*************************  DOMAIN POLICY HANDLER  *************************/

/* Default mode is "disable all mandatory access control functions". */
/* You must create profiles and choose one using CCS= options to the kernel command line. */
static unsigned int ccs_profile_index = 0;
static int skip_domain_policy_loading = 0;

static int __init CCS_Setup(char *str)
{
	if (sscanf(str, "%u", &ccs_profile_index) != 1) printk("Invalid value for CCS= .");
	return 0;
}

__setup("CCS=", CCS_Setup);

static int __init TOMOYO_NOLOAD_Setup(char *str)
{
	skip_domain_policy_loading = 1;
	return 0;
}

__setup("TOMOYO_NOLOAD", TOMOYO_NOLOAD_Setup);

/* Check whether the given access control is enabled. */
unsigned int CheckCCSFlags(const unsigned int index)
{
	if (index < (sizeof(ccs_control_array) / sizeof(ccs_control_array[0])) - 1)
		return ccs_control_array[index].current_value;
	printk("%s: Index %u is out of range. Fix the kernel source.\n", __FUNCTION__, index);
	return 0;
}

/* Check whether the given access control is enforce mode. */
unsigned int CheckCCSEnforce(const unsigned int index)
{
	if (index < (sizeof(ccs_control_array) / sizeof(ccs_control_array[0])) - 1)
		return ccs_control_array[index].current_value == 3;
	printk("%s: Index %u is out of range. Fix the kernel source.\n", __FUNCTION__, index);
	return 0;
}

/* Check whether the given access control is accept mode. */
unsigned int CheckCCSAccept(const unsigned int index)
{
	if (index < (sizeof(ccs_control_array) / sizeof(ccs_control_array[0])) - 1)
		return ccs_control_array[index].current_value == 1;
	printk("%s: Index %u is out of range. Fix the kernel source.\n", __FUNCTION__, index);
	return 0;
}

unsigned int GetMaxAutoAppendFiles(void) {
	return ccs_control_array[CCS_TOMOYO_MAX_ACCEPT_FILES].current_value;
}

unsigned int GetMaxGrantLog(void) {
	return ccs_control_array[CCS_TOMOYO_MAX_GRANT_LOG].current_value;
}

unsigned int GetMaxRejectLog(void) {
	return ccs_control_array[CCS_TOMOYO_MAX_REJECT_LOG].current_value;
}

static int SetStatus(char *data, void **dummy)
{
	unsigned int value;
	int i;
	char *cp = strrchr(data, '=');
	if (!isRoot()) return -EPERM;
	if (!cp) return -EINVAL;
	*cp = '\0';
	if (sscanf(cp + 1, "%u", &value) != 1) return -EINVAL;
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
	if (strncmp(data, KEYWORD_MAC_FOR_CAPABILITY, KEYWORD_MAC_FOR_CAPABILITY_LEN) == 0) {
		return SetCapabilityStatus(data + KEYWORD_MAC_FOR_CAPABILITY_LEN, value);
	}
#endif
	for (i = 0; ccs_control_array[i].keyword; i++) {
		if (strcmp(data, ccs_control_array[i].keyword) == 0) {
			if (value > ccs_control_array[i].max_value) value = ccs_control_array[i].max_value;
			ccs_control_array[i].current_value = value;
			break;
		}
	}
	return ccs_control_array[i].keyword ? 0 : -EINVAL;
}

static int LoadProfile(void)
{
	struct file *f;
	static char buffer[64];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/root/security/profile%u.txt", ccs_profile_index);
	f = filp_open(buffer, O_RDONLY, 0600);
	if (!IS_ERR(f)) {
		if (f->f_dentry->d_inode->i_size > 0 && ReadFileAndProcess(f, SetStatus) < 0) panic("%s: FATAL: Failed to load.\n", __FUNCTION__);
		filp_close(f, NULL);
		printk("%s: Loading profiles done.\n", __FUNCTION__);
	} else {
		printk("%s: Can't load %s\n", __FUNCTION__, buffer);
	}
	return 0;
}

static int ReadStatus(IO_BUFFER *head)
{
	if (!head->read_eof) {
		int i;
		if (!isRoot()) return -EPERM;
		if (!head->read_var2) {
			for (i = head->read_step; ccs_control_array[i].keyword; i++) {
				if (io_printf(head, "%s=%u\n", ccs_control_array[i].keyword, ccs_control_array[i].current_value)) break;
				head->read_step = i;
			}
			if (!ccs_control_array[i].keyword) {
				head->read_var2 = (void *) 1;
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

/* Definition file for programs that can update policies via /proc interface . */
#define POLICY_MANAGER_FILE           "/root/security/manager.txt"

typedef struct policy_manager_entry {
	struct policy_manager_entry *next; /* Pointer to next record. NULL if none. */
	const char *exe;                   /* Filename. Never NULL.                 */
} POLICY_MANAGER_ENTRY;

static POLICY_MANAGER_ENTRY policy_manager_list = { NULL, "" };

static int AddPolicyManagerPolicy(char *exe, void **dummy)
{
	POLICY_MANAGER_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_exe;
	if (!isRoot()) return -EPERM;
	if (!IsCorrectPath(exe, 0) || strendswith(exe, "/")) {
		printk(KERN_DEBUG "%s: Invalid filename '%s'\n", __FUNCTION__, exe);
		return -EINVAL;
	}
	/* I don't want to add if it was already added. */
	for (ptr = policy_manager_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->exe, exe) == 0) return 0;
	if ((saved_exe = SaveName(exe)) == NULL || (new_entry = (POLICY_MANAGER_ENTRY *) alloc_element(sizeof(POLICY_MANAGER_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(POLICY_MANAGER_ENTRY));
	new_entry->next = NULL;
	new_entry->exe = saved_exe;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &policy_manager_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

/* Check whether the current process is a policy manager. */
static int IsPolicyManager(void)
{
	POLICY_MANAGER_ENTRY *ptr;
	const char *exe;
	if (!policy_manager_list.next) return 0;
	if ((exe = GetEXE()) == NULL) return 0;
	for (ptr = policy_manager_list.next; ptr; ptr = ptr->next) {
		if (strcmp(exe, ptr->exe) == 0) break;
	}
	kfree(exe);
	return ptr ? 1 : 0;
}

static int LoadPolicyManager(void)
{
	struct file *f = filp_open(POLICY_MANAGER_FILE, O_RDONLY, 0600);
	if (!IS_ERR(f)) {
		if (f->f_dentry->d_inode->i_size > 0 && ReadFileAndProcess(f, AddPolicyManagerPolicy) < 0) panic("%s: Failed to load.\n", __FUNCTION__);
		filp_close(f, NULL);
		printk("%s: Loading policy managers done.\n", __FUNCTION__);
	}
	if (!policy_manager_list.next) printk("%s: No program can update policy via /proc interface.\n", __FUNCTION__);
	return 0;
}

/*************************  DOMAIN POLICY HANDLER  *************************/

#ifdef CONFIG_TOMOYO

/* Definition file for domains policy. */
#define DOMAIN_POLICY_FILE           "/root/security/domain_policy.txt"

static int AddDomainPolicy(char *data, void **domain)
{
	if (!isRoot()) return -EPERM;
	if (IsDomainDef(data)) {
		*domain = FindOrAssignNewDomain(data);
		return 0;
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
	} else if (strncmp(data, KEYWORD_ALLOW_CAPABILITY, KEYWORD_ALLOW_CAPABILITY_LEN) == 0) {
		return AddCapabilityPolicy(data + KEYWORD_ALLOW_CAPABILITY_LEN, domain);
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_BINDPORT
	} else if (strncmp(data, KEYWORD_ALLOW_BIND, KEYWORD_ALLOW_BIND_LEN) == 0) {
		return AddBindPolicy(data + KEYWORD_ALLOW_BIND_LEN, domain);
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_CONNECTPORT
	} else if (strncmp(data, KEYWORD_ALLOW_CONNECT, KEYWORD_ALLOW_CONNECT_LEN) == 0) {
		return AddConnectPolicy(data + KEYWORD_ALLOW_CONNECT_LEN, domain);
#endif
#ifdef CONFIG_TOMOYO_MAC_FOR_SIGNAL
	} else if (strncmp(data, KEYWORD_ALLOW_SIGNAL, KEYWORD_ALLOW_SIGNAL_LEN) == 0) {
		return AddSignalPolicy(data + KEYWORD_ALLOW_SIGNAL_LEN, domain);
#endif
	} else {
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
		return AddFilePolicy(data, domain);
#endif
	}
	return -EINVAL;
}

static int LoadDomainPolicy(void)
{
	struct file *f = filp_open(DOMAIN_POLICY_FILE, O_RDONLY, 0600);
	if (!IS_ERR(f)) {
		if (f->f_dentry->d_inode->i_size > 0 && ReadFileAndProcess(f, AddDomainPolicy) < 0) panic("%s: FATAL: Failed to load.\n", __FUNCTION__);
		filp_close(f, NULL);
		printk("%s: Loading domain policy done.\n", __FUNCTION__);
	} else {
		ccs_control_array[CCS_TOMOYO_VERBOSE].current_value = 0;
		printk("%s: Can't load domain policy.\n", __FUNCTION__);
	}
	return 0;
}

static int ReadDomainPolicy(IO_BUFFER *head)
{
	if (!head->read_eof) {
		struct domain_info *domain = (struct domain_info *) head->read_var1;
		switch (head->read_step) {
		case 0: break;
		case 1: goto step1;
		case 2: goto step2;
		case 3: goto step3;
		case 4: goto step4;
		case 5: goto step5;
		case 6: goto step6;
		case 7: goto step7;
		default: return -EINVAL;
		}
		if (!isRoot()) return -EPERM;
		for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
			if (domain->attribute & DOMAIN_ATTRIBUTE_DELETED) continue;
			head->read_var1 = (void *) domain;
			head->read_var2 = NULL; head->read_step = 1;
		step1:
			if (io_printf(head, "%s\n\n", domain->domainname)) break;
			head->read_var2 = NULL; head->read_step = 2;
		step2:
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
			if (ReadFilePolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 3;
		step3:
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
			if (ReadCapabilityPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 4;
		step4:
#ifdef CONFIG_TOMOYO_MAC_FOR_BINDPORT
			if (ReadBindPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 5;
		step5:
#ifdef CONFIG_TOMOYO_MAC_FOR_CONNECTPORT
			if (ReadConnectPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 6;
		step6:
#ifdef CONFIG_TOMOYO_MAC_FOR_SIGNAL
			if (ReadSignalPolicy(head)) break;
#endif
			head->read_var2 = NULL; head->read_step = 7;
		step7:
			if (io_printf(head, "\n")) break;
		}
		if (!domain) head->read_eof = 1;
	}
	return 0;
}

#endif

/*************************  SYSTEM POLICY HANDLER  *************************/

#ifdef CONFIG_TOMOYO

/* Definition file for exception policy. */
#define EXCEPTION_POLICY_FILE           "/root/security/exception_policy.txt"

static int AddExceptionPolicy(char *data, void **domain)
{
	if (!isRoot()) return -EPERM;
	if (strncmp(data, KEYWORD_TRUST_DOMAIN, KEYWORD_TRUST_DOMAIN_LEN) == 0) {
		return AddTrustedPatternPolicy(data + KEYWORD_TRUST_DOMAIN_LEN);
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
	} else if (strncmp(data, KEYWORD_ALLOW_READ, KEYWORD_ALLOW_READ_LEN) == 0) {
		return AddGloballyReadablePolicy(data + KEYWORD_ALLOW_READ_LEN);
#endif
	} else if (strncmp(data, KEYWORD_INITIALIZER, KEYWORD_INITIALIZER_LEN) == 0) {
		return AddInitializerPolicy(data + KEYWORD_INITIALIZER_LEN);
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
	} else if (strncmp(data, KEYWORD_FILE_PATTERN, KEYWORD_FILE_PATTERN_LEN) == 0) {
		return AddPatternPolicy(data + KEYWORD_FILE_PATTERN_LEN);
#endif
	} else if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
		if (strncmp(data, KEYWORD_TRUST_DOMAIN, KEYWORD_TRUST_DOMAIN_LEN) == 0) {
			return DelTrustedPatternPolicy(data + KEYWORD_TRUST_DOMAIN_LEN);
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
		} else if (strncmp(data, KEYWORD_ALLOW_READ, KEYWORD_ALLOW_READ_LEN) == 0) {
			return DelGloballyReadablePolicy(data + KEYWORD_ALLOW_READ_LEN);
#endif
		} else if (strncmp(data, KEYWORD_INITIALIZER, KEYWORD_INITIALIZER_LEN) == 0) {
			return DelInitializerPolicy(data + KEYWORD_INITIALIZER_LEN);
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
		} else if (strncmp(data, KEYWORD_FILE_PATTERN, KEYWORD_FILE_PATTERN_LEN) == 0) {
			return DelPatternPolicy(data + KEYWORD_FILE_PATTERN_LEN);
#endif
		}
	}
	return -EINVAL;
}

static int LoadExceptionPolicy(void)
{
	struct file *f = filp_open(EXCEPTION_POLICY_FILE, O_RDONLY, 0600);
	if (!IS_ERR(f)) {
		if (f->f_dentry->d_inode->i_size > 0 && ReadFileAndProcess(f, AddExceptionPolicy) < 0) panic("%s: FATAL: Failed to load.\n", __FUNCTION__);
		filp_close(f, NULL);
		printk("%s: Loading exception policy done.\n", __FUNCTION__);
	} else {
		printk("%s: Can't load exception policy.\n", __FUNCTION__);
	}
	return 0;
}

static int ReadExceptionPolicy(IO_BUFFER *head)
{
	if (!head->read_eof) {
		switch (head->read_step) {
		case 0:
			if (!isRoot()) return -EPERM;
			head->read_var2 = NULL; head->read_step = 1;
		case 1:
			if (ReadTrustedPatternPolicy(head)) break;
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
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
			if (ReadPatternPolicy(head)) break;
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

/* Definition file for system policy. */
#define SYSTEM_POLICY_FILE           "/root/security/system_policy.txt"

static int AddSystemPolicy(char *data, void **domain)
{
	if (!isRoot()) return -EPERM;
#ifdef CONFIG_SAKURA_RESTRICT_MOUNT
	if (strncmp(data, KEYWORD_ALLOW_MOUNT, KEYWORD_ALLOW_MOUNT_LEN) == 0)
		return AddMountPolicy(data + KEYWORD_ALLOW_MOUNT_LEN);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_UNMOUNT
	if (strncmp(data, KEYWORD_DENY_UNMOUNT, KEYWORD_DENY_UNMOUNT_LEN) == 0)
		return AddNoUmountPolicy(data + KEYWORD_DENY_UNMOUNT_LEN);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_CHROOT
	if (strncmp(data, KEYWORD_ALLOW_CHROOT, KEYWORD_ALLOW_CHROOT_LEN) == 0)
		return AddChrootPolicy(data + KEYWORD_ALLOW_CHROOT_LEN);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_AUTOBIND
	if (strncmp(data, KEYWORD_DENY_AUTOBIND, KEYWORD_DENY_AUTOBIND_LEN) == 0)
		return AddReservedPortPolicy(data + KEYWORD_DENY_AUTOBIND_LEN);
#endif
	if (strncmp(data, KEYWORD_DELETE, KEYWORD_DELETE_LEN) == 0) {
		data += KEYWORD_DELETE_LEN;
#ifdef CONFIG_SAKURA_RESTRICT_MOUNT
		if (strncmp(data, KEYWORD_ALLOW_MOUNT, KEYWORD_ALLOW_MOUNT_LEN) == 0)
			return DelMountPolicy(data + KEYWORD_ALLOW_MOUNT_LEN);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_UNMOUNT
		if (strncmp(data, KEYWORD_DENY_UNMOUNT, KEYWORD_DENY_UNMOUNT_LEN) == 0)
			return DelNoUmountPolicy(data + KEYWORD_DENY_UNMOUNT_LEN);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_CHROOT
		if (strncmp(data, KEYWORD_ALLOW_CHROOT, KEYWORD_ALLOW_CHROOT_LEN) == 0)
			return DelChrootPolicy(data + KEYWORD_ALLOW_CHROOT_LEN);
#endif
#ifdef CONFIG_SAKURA_RESTRICT_AUTOBIND
		if (strncmp(data, KEYWORD_DENY_AUTOBIND, KEYWORD_DENY_AUTOBIND_LEN) == 0)
			return DelReservedPortPolicy(data + KEYWORD_DENY_AUTOBIND_LEN);
#endif
	}
	return -EINVAL;
}

static int LoadSystemPolicy(void)
{
	struct file *f = filp_open(SYSTEM_POLICY_FILE, O_RDONLY, 0600);
	if (!IS_ERR(f)) {
		if (f->f_dentry->d_inode->i_size > 0 && ReadFileAndProcess(f, AddSystemPolicy) < 0) panic("%s: FATAL: Failed to load.\n", __FUNCTION__);
		filp_close(f, NULL);
		printk("%s: Loading system policy done.\n", __FUNCTION__);
	} else {
		printk("%s: Can't load system policy.\n", __FUNCTION__);
	}
	return 0;
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

void CCS_LoadPolicy(void)
{
	static int init_started = 0;
	if (!init_started) {
		init_started = 1;
		{
			int i;
			for (i = 0; ccs_control_array[i].keyword; i++) {
				if (ccs_control_array[i].assertion_index == i) continue;
				panic("%s: FATAL: Control array index is broken. Fix the kernel source.\n", __FUNCTION__);
			}
		}
		LoadPolicyManager();
#ifdef CONFIG_SAKURA
		printk("SAKURA: 1.0 2005/11/11\n");
		printk("SAKURA Linux is loading policy. Please wait.\n");
		LoadSystemPolicy();
#endif
#ifdef CONFIG_TOMOYO
		printk("TOMOYO: 1.0 2005/11/11\n");
		printk("TOMOYO Linux is loading policy. Please wait.\n");
		LoadExceptionPolicy();
		if (skip_domain_policy_loading == 0) LoadDomainPolicy();
		{
			struct domain_info *domain;
			int domain_count = 0;
			int acl_count = 0;
			for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
				FILE_ACL_RECORD *ptr = domain->first_acl_ptr;
				while (ptr) { ptr = ptr->next; acl_count++; };
				domain_count++;
			}
			printk("TOMOYO: %d domains. %d ACL entries. %d KB shared. %d KB private.\n", domain_count, acl_count, GetMemoryUsedForSaveName(), GetMemoryUsedForElements());
		}
#endif
		LoadProfile();
		printk("Mandatory Access Control activated.\n");
		sbin_init_started = 1;
	}
}

/*************************  /proc INTERFACE HANDLER  *************************/

static int ReadMemoryCounter(IO_BUFFER *head)
{
	if (!head->read_eof) {
		const int shared = GetMemoryUsedForSaveName() * 1024, private = GetMemoryUsedForElements() * 1024;
		if (io_printf(head, "Shared:  %10u\nPrivate: %10u\nTotal:   %10u\n", shared, private, shared + private) == 0) head->read_eof = 1;
	}
	return 0;
}

int CCS_OpenControl(const int type, struct file *file)
{
	IO_BUFFER *head = (IO_BUFFER *) kmalloc(sizeof(IO_BUFFER), GFP_KERNEL);
	if (!head) return -ENOMEM;
	memset(head, 0, sizeof(IO_BUFFER));
	head->readbuf_size = PAGE_SIZE * 2;
	if ((head->read_buf = kmalloc(head->readbuf_size, GFP_KERNEL)) == NULL) {
		kfree(head);
		return -ENOMEM;
	}
	head->writebuf_size = PAGE_SIZE * 2;
	if ((head->write_buf = kmalloc(head->writebuf_size, GFP_KERNEL)) == NULL) {
		kfree(head->read_buf);
		kfree(head);
		return -ENOMEM;
	}
	memset(head->read_buf, 0, head->readbuf_size);
	memset(head->write_buf, 0, head->writebuf_size);
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
	case CCS_POLICY_DELETEDOMAIN:
		head->write = DeleteDomain;
		break;
	case CCS_POLICY_UPDATEDOMAIN:
		head->write = UpdateDomain;
		break;
	case CCS_INFO_TRUSTEDPIDS:
		head->read = ReadTrustedPIDs;
		break;
	case CCS_INFO_DELETEDPIDS:
		head->read = ReadDeletedPIDs;
		break;
	case CCS_INFO_GRANTLOG:
		head->poll = PollGrantLog;
		head->read = ReadGrantLog;
		break;
	case CCS_INFO_REJECTLOG:
		head->poll = PollRejectLog;
		head->read = ReadRejectLog;
		break;
#endif
#ifdef CONFIG_SAKURA
	case CCS_POLICY_SYSTEMPOLICY:
		head->write = AddSystemPolicy;
		head->read = ReadSystemPolicy;
		break;
#endif
	case CCS_INFO_MEMINFO:
		head->read = ReadMemoryCounter;
		break;
	case CCS_STATUS:
		head->write = SetStatus;
		head->read = ReadStatus;
		break;
	}
	file->private_data = head;
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
	void *ptr = NULL;
	int error = buffer_len;
	int avail_len = buffer_len;
	char *cp0 = head->write_buf;
	if (!head->write) return -ENOSYS;
	if (!access_ok(VERIFY_READ, buffer, buffer_len)) return -EFAULT;
	if (!IsPolicyManager()) {
		printk("This program is not permitted to update policies.\n");
		return -EPERM; /* Forbid updating policies for non manager programs. */
	}
	if (down_interruptible(&head->write_sem)) return -EINTR;
	if (head->write_step) ptr = head->write_var1;
	head->write_step = 1;
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
		head->write(cp0, &ptr);
	}
	head->write_var1 = ptr;
	up(&head->write_sem);
	return error;
}


int CCS_CloseControl(struct file *file)
{
	IO_BUFFER *head = file->private_data;
	kfree(head->read_buf); head->read_buf = NULL;
	kfree(head->write_buf); head->write_buf = NULL;
	kfree(head); head = NULL;
	file->private_data = NULL;
	return 0;
}

EXPORT_SYMBOL(CheckCCSFlags);
EXPORT_SYMBOL(CheckCCSEnforce);
EXPORT_SYMBOL(CheckCCSAccept);
