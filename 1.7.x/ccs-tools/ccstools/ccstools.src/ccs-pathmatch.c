/*
 * ccs_pathmatch.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/04/06
 *
 */
#include "ccstools.h"

static unsigned char ccs_revalidate_path(const char *ccs_path)
{
	struct stat buf;
	unsigned char type = DT_UNKNOWN;
	if (!lstat(ccs_path, &buf)) {
		if (S_ISREG(buf.st_mode))
			type = DT_REG;
		else if (S_ISDIR(buf.st_mode))
			type = DT_DIR;
		else if (S_ISLNK(buf.st_mode))
			type = DT_LNK;
	}
	return type;
}

static int ccs_scandir_filter(const struct dirent *buf)
{
	return strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

static struct ccs_path_info ccs_target;
static _Bool ccs_print_path_needs_separator = false;

static _Bool ccs_print_path(const char *path, const int type)
{
	struct ccs_path_info name;
	int len;
	char *cp;
	len = strlen(path) * 4 + 4;
	cp = malloc(len);
	if (!cp)
		ccs_out_of_memory();
	name.name = cp;
	while (true) {
		const unsigned char c = *(const unsigned char *) path++;
		if (!c) {
			if (type == DT_DIR)
				*cp++ = '/';
			*cp++ = '\0';
			break;
		} else if (c == '\\') {
			*cp++ = '\\';
			*cp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	ccs_fill_path_info(&name);
	if (ccs_path_matches_pattern(&name, &ccs_target)) {
		if (ccs_print_path_needs_separator)
			putchar(' ');
		ccs_print_path_needs_separator = true;
		printf("%s", name.name);
	}
	len = name.total_len >= ccs_target.const_len ? ccs_target.const_len :
		name.total_len;
	len = strncmp(name.name, ccs_target.name, len);
	free((void *) name.name);
	return !len;
}

static char ccs_path[8192];

static void ccs_scan_dir(void)
{
	struct dirent **namelist;
	int n = scandir(ccs_path, &namelist, ccs_scandir_filter, 0);
	int len;
	int i;
	if (n < 0)
		return;
	len = strlen(ccs_path);
	if (len == 1)
		len = 0;
	for (i = 0; i < n; i++) {
		unsigned char type = namelist[i]->d_type;
		snprintf(ccs_path + len, sizeof(ccs_path) - len - 1, "/%s",
			 namelist[i]->d_name);
		if (type == DT_UNKNOWN)
			type = ccs_revalidate_path(ccs_path);
		if (ccs_print_path(ccs_path, type) && type == DT_DIR)
			ccs_scan_dir();
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static void ccs_do_pathmatch_main(char *find)
{
	if (!strcmp(find, "/"))
		putchar('/');
	else if (ccs_is_correct_path(find, 1, 0, 0)) {
		ccs_target.name = find;
		ccs_fill_path_info(&ccs_target);
		ccs_print_path_needs_separator = false;
		memset(ccs_path, 0, sizeof(ccs_path));
		strncpy(ccs_path, "/", sizeof(ccs_path) - 1);
		ccs_scan_dir();
	}
	putchar('\n');
}

int ccs_pathmatch_main(int argc, char *argv[])
{
	if (argc > 1) {
		int i;
		for (i = 1; i < argc; i++)
			ccs_do_pathmatch_main(argv[i]);
	} else {
		ccs_get();
		while (true) {
			char *line = ccs_freadline(stdin);
			if (!line)
				break;
			ccs_do_pathmatch_main(line);
		}
		ccs_put();
	}
	return 0;
}
