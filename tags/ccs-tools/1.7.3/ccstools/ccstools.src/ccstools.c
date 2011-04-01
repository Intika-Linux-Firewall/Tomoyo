/*
 * ccstools.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

/* Prototypes */

static _Bool is_byte_range(const char *str);
static _Bool is_decimal(const char c);
static _Bool is_hexadecimal(const char c);
static _Bool is_alphabet_char(const char c);
static u8 make_byte(const u8 c1, const u8 c2, const u8 c3);
static inline unsigned long partial_name_hash(unsigned long c,
					      unsigned long prevhash);
static inline unsigned int full_name_hash(const unsigned char *name,
					  unsigned int len);
static void *alloc_element(const unsigned int size);
static int const_part_length(const char *filename);
static int domainname_compare(const void *a, const void *b);
static int path_info_compare(const void *a, const void *b);
static void sort_domain_policy(struct domain_policy *dp);

/* Utility functions */

void out_of_memory(void)
{
	fprintf(stderr, "Out of memory. Aborted.\n");
	exit(1);
}

_Bool str_starts(char *str, const char *begin)
{
	const int len = strlen(begin);
	if (strncmp(str, begin, len))
		return false;
	memmove(str, str + len, strlen(str + len) + 1);
	return true;
}

static _Bool is_byte_range(const char *str)
{
	return *str >= '0' && *str++ <= '3' &&
		*str >= '0' && *str++ <= '7' &&
		*str >= '0' && *str <= '7';
}

static _Bool is_decimal(const char c)
{
	return c >= '0' && c <= '9';
}

static _Bool is_hexadecimal(const char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

static _Bool is_alphabet_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static u8 make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

void normalize_line(unsigned char *line)
{
	unsigned char *sp = line;
	unsigned char *dp = line;
	_Bool first = true;
	while (*sp && (*sp <= ' ' || 127 <= *sp))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (' ' < *sp && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || 127 <= *sp))
			sp++;
	}
	*dp = '\0';
}

char *make_filename(const char *prefix, const time_t time)
{
	struct tm *tm = localtime(&time);
	static char filename[1024];
	memset(filename, 0, sizeof(filename));
	snprintf(filename, sizeof(filename) - 1,
		 "%s.%02d-%02d-%02d.%02d:%02d:%02d.conf",
		 prefix, tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
		 tm->tm_hour, tm->tm_min, tm->tm_sec);
	return filename;
}

/* Copied from kernel source. */
static inline unsigned long partial_name_hash(unsigned long c,
					      unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/* Copied from kernel source. */
static inline unsigned int full_name_hash(const unsigned char *name,
					  unsigned int len)
{
	unsigned long hash = 0;
	while (len--)
		hash = partial_name_hash(*name++, hash);
	return (unsigned int) hash;
}

static void *alloc_element(const unsigned int size)
{
	static char *buf = NULL;
	static unsigned int buf_used_len = PAGE_SIZE;
	char *ptr = NULL;
	if (size > PAGE_SIZE)
		return NULL;
	if (buf_used_len + size > PAGE_SIZE) {
		ptr = malloc(PAGE_SIZE);
		if (!ptr)
			out_of_memory();
		buf = ptr;
		memset(buf, 0, PAGE_SIZE);
		buf_used_len = size;
		ptr = buf;
	} else if (size) {
		int i;
		ptr = buf + buf_used_len;
		buf_used_len += size;
		for (i = 0; i < size; i++)
			if (ptr[i])
				out_of_memory();
	}
	return ptr;
}

static int const_part_length(const char *filename)
{
	int len = 0;
	if (filename) {
		while (true) {
			char c = *filename++;
			if (!c)
				break;
			if (c != '\\') {
				len++;
				continue;
			}
			c = *filename++;
			switch (c) {
			case '\\':  /* "\\" */
				len += 2;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				c = *filename++;
				if (c < '0' || c > '7')
					break;
				c = *filename++;
				if (c < '0' || c > '7')
					break;
				len += 4;
				continue;
			}
			break;
		}
	}
	return len;
}

_Bool is_domain_def(const unsigned char *domainname)
{
	return !strncmp(domainname, ROOT_NAME, ROOT_NAME_LEN) &&
		(domainname[ROOT_NAME_LEN] == '\0'
		 || domainname[ROOT_NAME_LEN] == ' ');
}

_Bool is_correct_domain(const unsigned char *domainname)
{
	if (!domainname || strncmp(domainname, ROOT_NAME, ROOT_NAME_LEN))
		goto out;
	domainname += ROOT_NAME_LEN;
	if (!*domainname)
		return true;
	do {
		if (*domainname++ != ' ')
			goto out;
		if (*domainname++ != '/')
			goto out;
		while (true) {
			unsigned char c = *domainname;
			if (!c || c == ' ')
				break;
			domainname++;
			if (c == '\\') {
				unsigned char d;
				unsigned char e;
				u8 f;
				c = *domainname++;
				switch (c) {
				case '\\':  /* "\\" */
					continue;
				case '0':   /* "\ooo" */
				case '1':
				case '2':
				case '3':
					d = *domainname++;
					if (d < '0' || d > '7')
						break;
					e = *domainname++;
					if (e < '0' || e > '7')
						break;
					f = (((u8) (c - '0')) << 6) +
						(((u8) (d - '0')) << 3) +
						(((u8) (e - '0')));
					/* pattern is not \000 */
					if (f && (f <= ' ' || f >= 127))
						continue;
				}
				goto out;
			} else if (c < ' ' || c >= 127) {
				goto out;
			}
		}
	} while (*domainname);
	return true;
out:
	return false;
}

void fprintf_encoded(FILE *fp, const char *pathname)
{
	while (true) {
		unsigned char c = *(const unsigned char *) pathname++;
		if (!c)
			break;
		if (c == '\\') {
			fputc('\\', fp);
			fputc('\\', fp);
		} else if (c > ' ' && c < 127) {
			fputc(c, fp);
		} else {
			fprintf(fp, "\\%c%c%c", (c >> 6) + '0',
				((c >> 3) & 7) + '0', (c & 7) + '0');
		}
	}
}

_Bool decode(const char *ascii, char *bin)
{
	while (true) {
		char c = *ascii++;
		*bin++ = c;
		if (!c)
			break;
		if (c == '\\') {
			char d;
			char e;
			u8 f;
			c = *ascii++;
			switch (c) {
			case '\\':      /* "\\" */
				continue;
			case '0':       /* "\ooo" */
			case '1':
			case '2':
			case '3':
				d = *ascii++;
				if (d < '0' || d > '7')
					break;
				e = *ascii++;
				if (e < '0' || e > '7')
					break;
				f = (u8) ((c - '0') << 6) +
					(((u8) (d - '0')) << 3) +
					(((u8) (e - '0')));
				if (f && (f <= ' ' || f >= 127)) {
					*(bin - 1) = f;
					continue; /* pattern is not \000 */
				}
			}
			return false;
		} else if (c <= ' ' || c >= 127) {
			return false;
		}
	}
	return true;
}

_Bool is_correct_path(const char *filename, const s8 start_type,
		     const s8 pattern_type, const s8 end_type)
{
	const char *const start = filename;
	_Bool in_repetition = false;
	_Bool contains_pattern = false;
	unsigned char c;
	if (!filename)
		goto out;
	c = *filename;
	if (start_type == 1) { /* Must start with '/' */
		if (c != '/')
			goto out;
	} else if (start_type == -1) { /* Must not start with '/' */
		if (c == '/')
			goto out;
	}
	if (c)
		c = *(filename + strlen(filename) - 1);
	if (end_type == 1) { /* Must end with '/' */
		if (c != '/')
			goto out;
	} else if (end_type == -1) { /* Must not end with '/' */
		if (c == '/')
			goto out;
	}
	while (true) {
		c = *filename++;
		if (!c)
			break;
		if (c == '\\') {
			unsigned char d;
			unsigned char e;
			c = *filename++;
			switch (c) {
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
				if (pattern_type == -1)
					break; /* Must not contain pattern */
				contains_pattern = true;
				continue;
			case '{':   /* "/\{" */
				if (filename - 3 < start ||
				    *(filename - 3) != '/')
					break;
				if (pattern_type == -1)
					break; /* Must not contain pattern */
				contains_pattern = true;
				in_repetition = true;
				continue;
			case '}':   /* "\}/" */
				if (*filename != '/')
					break;
				if (!in_repetition)
					break;
				in_repetition = false;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				d = *filename++;
				if (d < '0' || d > '7')
					break;
				e = *filename++;
				if (e < '0' || e > '7')
					break;
				c = make_byte(c, d, e);
				if (c && (c <= ' ' || c >= 127))
					continue; /* pattern is not \000 */
			}
			goto out;
		} else if (in_repetition && c == '/') {
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (pattern_type == 1) { /* Must contain pattern */
		if (!contains_pattern)
			goto out;
	}
	if (in_repetition)
		goto out;
	return true;
out:
	return false;
}

static _Bool file_matches_pattern2(const char *filename,
				  const char *filename_end,
				  const char *pattern, const char *pattern_end)
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
				if (filename[1] == '\\')
					filename++;
				else if (is_byte_range(filename + 1))
					filename += 3;
				else
					return false;
			}
			break;
		case '\\':
			if (c != '\\')
				return false;
			if (*++filename != '\\')
				return false;
			break;
		case '+':
			if (!is_decimal(c))
				return false;
			break;
		case 'x':
			if (!is_hexadecimal(c))
				return false;
			break;
		case 'a':
			if (!is_alphabet_char(c))
				return false;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
			if (c == '\\' && is_byte_range(filename + 1)
			    && !strncmp(filename + 1, pattern, 3)) {
				filename += 3;
				pattern += 2;
				break;
			}
			return false; /* Not matched. */
		case '*':
		case '@':
			for (i = 0; i <= filename_end - filename; i++) {
				if (file_matches_pattern2(filename + i,
							  filename_end,
							  pattern + 1,
							  pattern_end))
					return true;
				c = filename[i];
				if (c == '.' && *pattern == '@')
					break;
				if (c != '\\')
					continue;
				if (filename[i + 1] == '\\')
					i++;
				else if (is_byte_range(filename + i + 1))
					i += 3;
				else
					break; /* Bad pattern. */
			}
			return false; /* Not matched. */
		default:
			j = 0;
			c = *pattern;
			if (c == '$') {
				while (is_decimal(filename[j]))
					j++;
			} else if (c == 'X') {
				while (is_hexadecimal(filename[j]))
					j++;
			} else if (c == 'A') {
				while (is_alphabet_char(filename[j]))
					j++;
			}
			for (i = 1; i <= j; i++) {
				if (file_matches_pattern2(filename + i,
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

static _Bool file_matches_pattern(const char *filename,
				  const char *filename_end,
				  const char *pattern, const char *pattern_end)
{
	const char *pattern_start = pattern;
	_Bool first = true;
	_Bool result;
	while (pattern < pattern_end - 1) {
		/* Split at "\-" pattern. */
		if (*pattern++ != '\\' || *pattern++ != '-')
			continue;
		result = file_matches_pattern2(filename, filename_end,
					       pattern_start, pattern - 2);
		if (first)
			result = !result;
		if (result)
			return false;
		first = false;
		pattern_start = pattern;
	}
	result = file_matches_pattern2(filename, filename_end,
				       pattern_start, pattern_end);
	return first ? result : !result;
}

static _Bool path_matches_pattern2(const char *f, const char *p)
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
		if (!file_matches_pattern(f, f_delimiter, p, p_delimiter))
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
		if (!file_matches_pattern(f, f_delimiter, p + 2,
					  p_delimiter - 2))
			break;
		/* Proceed to next component. */
		f = f_delimiter;
		if (!*f)
			break;
		f++;
		/* Continue comparison. */
		if (path_matches_pattern2(f, p_delimiter + 1))
			return true;
		f_delimiter = strchr(f, '/');
	} while (f_delimiter);
	return false; /* Not matched. */
}

_Bool path_matches_pattern(const struct path_info *filename,
			   const struct path_info *pattern)
{
	/*
	if (!filename || !pattern)
		return false;
	*/
	const char *f = filename->name;
	const char *p = pattern->name;
	const int len = pattern->const_len;
	/* If @pattern doesn't contain pattern, I can use strcmp(). */
	if (!pattern->is_patterned)
		return !pathcmp(filename, pattern);
	/* Don't compare directory and non-directory. */
	if (filename->is_dir != pattern->is_dir)
		return false;
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	return path_matches_pattern2(f, p);
}

int string_compare(const void *a, const void *b)
{
	return strcmp(*(char **) a, *(char **) b);
}

_Bool pathcmp(const struct path_info *a, const struct path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
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
}

static unsigned int memsize(const unsigned int size)
{
	if (size <= 1048576)
		return ((size / PAGE_SIZE) + 1) * PAGE_SIZE;
	return 0;
}

const struct path_info *savename(const char *name)
{
	static struct free_memory_block_list fmb_list = { NULL, NULL, 0 };
	/* The list of names. */
	static struct savename_entry name_list[SAVENAME_MAX_HASH];
	struct savename_entry *ptr;
	struct savename_entry *prev = NULL;
	unsigned int hash;
	struct free_memory_block_list *fmb = &fmb_list;
	int len;
	static _Bool first_call = true;
	if (!name)
		return NULL;
	len = strlen(name) + 1;
	hash = full_name_hash((const unsigned char *) name, len - 1);
	if (first_call) {
		int i;
		first_call = false;
		memset(&name_list, 0, sizeof(name_list));
		for (i = 0; i < SAVENAME_MAX_HASH; i++) {
			name_list[i].entry.name = "/";
			fill_path_info(&name_list[i].entry);
		}
	}
	ptr = &name_list[hash % SAVENAME_MAX_HASH];
	while (ptr) {
		if (hash == ptr->entry.hash && !strcmp(name, ptr->entry.name))
			goto out;
		prev = ptr;
		ptr = ptr->next;
	}
	while (len > fmb->len) {
		char *cp;
		if (fmb->next) {
			fmb = fmb->next;
			continue;
		}
		cp = malloc(memsize(len));
		if (!cp)
			out_of_memory();
		fmb->next = alloc_element(sizeof(*fmb->next));
		if (!fmb->next)
			out_of_memory();
		memset(cp, 0, memsize(len));
		fmb = fmb->next;
		fmb->ptr = cp;
		fmb->len = memsize(len);
	}
	ptr = alloc_element(sizeof(*ptr));
	if (!ptr)
		out_of_memory();
	memset(ptr, 0, sizeof(struct savename_entry));
	ptr->entry.name = fmb->ptr;
	memmove(fmb->ptr, name, len);
	fill_path_info(&ptr->entry);
	fmb->ptr += len;
	fmb->len -= len;
	prev->next = ptr; /* prev != NULL because name_list is not empty. */
	if (!fmb->len) {
		struct free_memory_block_list *ptr = &fmb_list;
		while (ptr->next != fmb)
			ptr = ptr->next;
		ptr->next = fmb->next;
	}
out:
	return ptr ? &ptr->entry : NULL;
}

_Bool move_proc_to_file(const char *src, const char *dest)
{
	FILE *proc_fp;
	FILE *file_fp = stdout;
	proc_fp = open_read(src);
	if (!proc_fp) {
		fprintf(stderr, "Can't open %s\n", src);
		return false;
	}
	if (dest) {
		file_fp = fopen(dest, "w");
		if (!file_fp) {
			fprintf(stderr, "Can't open %s\n", dest);
			fclose(proc_fp);
			return false;
		}
	}
	while (true) {
		int c = fgetc(proc_fp);
		if (network_mode && !c)
			break;
		if (c == EOF)
			break;
		fputc(c, file_fp);
	}
	fclose(proc_fp);
	if (file_fp != stdout)
		fclose(file_fp);
	return true;
}

_Bool is_identical_file(const char *file1, const char *file2)
{
	char buffer1[4096];
	char buffer2[4096];
	struct stat sb1;
	struct stat sb2;
	const int fd1 = open(file1, O_RDONLY);
	const int fd2 = open(file2, O_RDONLY);
	int len1;
	int len2;
	/* Don't compare if file1 is a symlink to file2. */
	if (fstat(fd1, &sb1) || fstat(fd2, &sb2) || sb1.st_ino == sb2.st_ino)
		goto out;
	do {
		len1 = read(fd1, buffer1, sizeof(buffer1));
		len2 = read(fd2, buffer2, sizeof(buffer2));
		if (len1 < 0 || len1 != len2)
			goto out;
		if (memcmp(buffer1, buffer2, len1))
			goto out;
	} while (len1);
	close(fd1);
	close(fd2);
	return true;
out:
	close(fd1);
	close(fd2);
	return false;
}

void clear_domain_policy(struct domain_policy *dp)
{
	int index;
	for (index = 0; index < dp->list_len; index++) {
		free(dp->list[index].string_ptr);
		dp->list[index].string_ptr = NULL;
		dp->list[index].string_count = 0;
	}
	free(dp->list);
	dp->list = NULL;
	dp->list_len = 0;
}

int find_domain_by_ptr(struct domain_policy *dp,
		       const struct path_info *domainname)
{
	int i;
	for (i = 0; i < dp->list_len; i++) {
		if (dp->list[i].domainname == domainname)
			return i;
	}
	return EOF;
}

const char *domain_name(const struct domain_policy *dp, const int index)
{
	return dp->list[index].domainname->name;
}

static int domainname_compare(const void *a, const void *b)
{
	return strcmp(((struct domain_info *) a)->domainname->name,
		      ((struct domain_info *) b)->domainname->name);
}

static int path_info_compare(const void *a, const void *b)
{
	const char *a0 = (*(struct path_info **) a)->name;
	const char *b0 = (*(struct path_info **) b)->name;
	return strcmp(a0, b0);
}

static void sort_domain_policy(struct domain_policy *dp)
{
	int i;
	qsort(dp->list, dp->list_len, sizeof(struct domain_info),
	      domainname_compare);
	for (i = 0; i < dp->list_len; i++)
		qsort(dp->list[i].string_ptr, dp->list[i].string_count,
		      sizeof(struct path_info *), path_info_compare);
}

void read_domain_policy(struct domain_policy *dp, const char *filename)
{
	FILE *fp = stdin;
	if (filename) {
		fp = open_read(filename);
		if (!fp) {
			fprintf(stderr, "Can't open %s\n", filename);
			return;
		}
	}
	get();
	handle_domain_policy(dp, fp, true);
	put();
	if (fp != stdin)
		fclose(fp);
	sort_domain_policy(dp);
}

void delete_domain(struct domain_policy *dp, const int index)
{
	if (index >= 0 && index < dp->list_len) {
		int i;
		free(dp->list[index].string_ptr);
		for (i = index; i < dp->list_len - 1; i++)
			dp->list[i] = dp->list[i + 1];
		dp->list_len--;
	}
}

void handle_domain_policy(struct domain_policy *dp, FILE *fp, _Bool is_write)
{
	int i;
	int index = EOF;
	if (!is_write)
		goto read_policy;
	while (true) {
		char *line = freadline(fp);
		_Bool is_delete = false;
		_Bool is_select = false;
		unsigned int profile;
		if (!line)
			break;
		if (str_starts(line, "delete "))
			is_delete = true;
		else if (str_starts(line, "select "))
			is_select = true;
		str_starts(line, "domain=");
		if (is_domain_def(line)) {
			if (is_delete) {
				index = find_domain(dp, line, false, false);
				if (index >= 0)
					delete_domain(dp, index);
				index = EOF;
				continue;
			}
			if (is_select) {
				index = find_domain(dp, line, false, false);
				continue;
			}
			index = find_or_assign_new_domain(dp, line, false,
							  false);
			continue;
		}
		if (index == EOF || !line[0])
			continue;
		if (sscanf(line, KEYWORD_USE_PROFILE "%u", &profile) == 1) {
			dp->list[index].profile = (u8) profile;
			dp->list[index].profile_assigned = 1;
		} else if (is_delete)
			del_string_entry(dp, line, index);
		else
			add_string_entry(dp, line, index);
	}
	return;
read_policy:
	for (i = 0; i < dp->list_len; i++) {
		int j;
		const struct path_info **string_ptr
			= dp->list[i].string_ptr;
		const int string_count = dp->list[i].string_count;
		fprintf(fp, "%s\n", domain_name(dp, i));
		if (dp->list[i].profile_assigned)
			fprintf(fp, KEYWORD_USE_PROFILE "%u\n",
				dp->list[i].profile);
		fprintf(fp, "\n");
		for (j = 0; j < string_count; j++)
			fprintf(fp, "%s\n", string_ptr[j]->name);
		fprintf(fp, "\n");
	}
}

/* Variables */

static _Bool buffer_locked = false;

/* Main functions */

void get(void)
{
	if (buffer_locked)
		out_of_memory();
	buffer_locked = true;
}

void put(void)
{
	if (!buffer_locked)
		out_of_memory();
	buffer_locked = false;
}

char *shprintf(const char *fmt, ...)
{
	if (!buffer_locked)
		out_of_memory();
	while (true) {
		static char *policy = NULL;
		static int max_policy_len = 0;
		va_list args;
		int len;
		va_start(args, fmt);
		len = vsnprintf(policy, max_policy_len, fmt, args);
		va_end(args);
		if (len < 0)
			out_of_memory();
		if (len >= max_policy_len) {
			char *cp;
			max_policy_len = len + 1;
			cp = realloc(policy, max_policy_len);
			if (!cp)
				out_of_memory();
			policy = cp;
		} else
			return policy;
	}
}

char *freadline(FILE *fp)
{
	static char *policy = NULL;
	int pos = 0;
	if (!buffer_locked)
		out_of_memory();
	while (true) {
		static int max_policy_len = 0;
		const int c = fgetc(fp);
		if (c == EOF)
			return NULL;
		if (network_mode && !c)
			return NULL;
		if (pos == max_policy_len) {
			char *cp;
			max_policy_len += 4096;
			cp = realloc(policy, max_policy_len);
			if (!cp)
				out_of_memory();
			policy = cp;
		}
		policy[pos++] = (char) c;
		if (c == '\n') {
			policy[--pos] = '\0';
			break;
		}
	}
	normalize_line(policy);
	return policy;
}

_Bool check_remote_host(void)
{
	int ccs_major = 0;
	int ccs_minor = 0;
	int ccs_rev = 0;
	FILE *fp = open_read("version");
	if (!fp ||
	    fscanf(fp, "%u.%u.%u", &ccs_major, &ccs_minor, &ccs_rev) < 2 ||
	    ccs_major != 1 || ccs_minor != 7) {
		const u32 ip = ntohl(network_ip);
		fprintf(stderr, "Can't connect to %u.%u.%u.%u:%u\n",
			(u8) (ip >> 24), (u8) (ip >> 16),
			(u8) (ip >> 8), (u8) ip, ntohs(network_port));
		if (fp)
			fclose(fp);
		return false;
	}
	fclose(fp);
	return true;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	const char *argv0 = argv[0];
	if (!argv0) {
		fprintf(stderr, "Function not specified.\n");
		return 1;
	}
	if (strrchr(argv0, '/'))
		argv0 = strrchr(argv0, '/') + 1;
	if (!strcmp(argv0, "ccs-sortpolicy"))
		ret = sortpolicy_main(argc, argv);
	else if (!strcmp(argv0, "ccs-setprofile"))
		ret = setprofile_main(argc, argv);
	else if (!strcmp(argv0, "ccs-setlevel"))
		ret = setlevel_main(argc, argv);
	else if (!strcmp(argv0, "ccs-selectpolicy"))
		ret = selectpolicy_main(argc, argv);
	else if (!strcmp(argv0, "ccs-diffpolicy"))
		ret = diffpolicy_main(argc, argv);
	else if (!strcmp(argv0, "ccs-savepolicy"))
		ret = savepolicy_main(argc, argv);
	else if (!strcmp(argv0, "ccs-pathmatch"))
		ret = pathmatch_main(argc, argv);
	else if (!strcmp(argv0, "ccs-loadpolicy"))
		ret = loadpolicy_main(argc, argv);
	else if (!strcmp(argv0, "ccs-ld-watch"))
		ret = ldwatch_main(argc, argv);
	else if (!strcmp(argv0, "ccs-findtemp"))
		ret = findtemp_main(argc, argv);
	else if (!strcmp(argv0, "ccs-editpolicy"))
		ret = editpolicy_main(argc, argv);
	else if (!strcmp(argv0, "ccs-checkpolicy"))
		ret = checkpolicy_main(argc, argv);
	else if (!strcmp(argv0, "ccs-pstree"))
		ret = pstree_main(argc, argv);
	else if (!strcmp(argv0, "ccs-queryd"))
		ret = queryd_main(argc, argv);
	else if (!strcmp(argv0, "ccs-auditd"))
		ret = auditd_main(argc, argv);
	else if (!strcmp(argv0, "ccs-patternize"))
		ret = patternize_main(argc, argv);
	else
		goto show_version;
	return ret;
show_version:
	/*
	 * Unlike busybox, I don't use argv[1] if argv[0] is the name of this
	 * program because it is dangerous to allow updating policies via
	 * unchecked argv[1].
	 * You should use either "symbolic links" or "hard links".
	 */
	printf("ccstools version 1.7.3 build 2011/04/01\n");
	fprintf(stderr, "Function %s not implemented.\n", argv0);
	return 1;
}
