/*
 * pathmatch.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.2.0+   2010/02/25
 *
 */
#include "tomoyotools.h"

static unsigned char revalidate_path(const char *path)
{
	struct stat buf;
	unsigned char type = DT_UNKNOWN;
	if (!lstat(path, &buf)) {
		if (S_ISREG(buf.st_mode))
			type = DT_REG;
		else if (S_ISDIR(buf.st_mode))
			type = DT_DIR;
		else if (S_ISLNK(buf.st_mode))
			type = DT_LNK;
	}
	return type;
}

static int scandir_filter(const struct dirent *buf)
{
	return strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

static struct path_info target;
static _Bool print_path_needs_separator = false;

static _Bool print_path(const char *path, const int type)
{
	struct path_info name;
	int len;
	char *cp;
	len = strlen(path) * 4 + 4;
	cp = malloc(len);
	if (!cp)
		out_of_memory();
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
	fill_path_info(&name);
	if (path_matches_pattern(&name, &target)) {
		if (print_path_needs_separator)
			putchar(' ');
		print_path_needs_separator = true;
		printf("%s", name.name);
	}
	len = name.total_len >= target.const_len ? target.const_len :
		name.total_len;
	len = strncmp(name.name, target.name, len);
	free((void *) name.name);
	return !len;
}

static char path[8192];

static void scan_dir(void)
{
	struct dirent **namelist;
	int n = scandir(path, &namelist, scandir_filter, 0);
	int len;
	int i;
	if (n < 0)
		return;
	len = strlen(path);
	if (len == 1)
		len = 0;
	for (i = 0; i < n; i++) {
		unsigned char type = namelist[i]->d_type;
		snprintf(path + len, sizeof(path) - len - 1, "/%s",
			 namelist[i]->d_name);
		if (type == DT_UNKNOWN)
			type = revalidate_path(path);
		if (print_path(path, type) && type == DT_DIR)
			scan_dir();
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static void do_pathmatch_main(char *find)
{
	if (!strcmp(find, "/"))
		putchar('/');
	else if (is_correct_path(find, 1, 0, 0)) {
		target.name = find;
		fill_path_info(&target);
		print_path_needs_separator = false;
		memset(path, 0, sizeof(path));
		strncpy(path, "/", sizeof(path) - 1);
		scan_dir();
	}
	putchar('\n');
}

int pathmatch_main(int argc, char *argv[])
{
	if (argc > 1) {
		int i;
		for (i = 1; i < argc; i++)
			do_pathmatch_main(argv[i]);
	} else {
		get();
		while (freadline(stdin))
			do_pathmatch_main(shared_buffer);
		put();
	}
	return 0;
}
