/*
 * tomoyo-pathmatch.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.3.0   2010/08/02
 *
 */
#include "tomoyotools.h"

static unsigned char tomoyo_revalidate_path(const char *tomoyo_path)
{
	struct stat buf;
	unsigned char type = DT_UNKNOWN;
	if (!lstat(tomoyo_path, &buf)) {
		if (S_ISREG(buf.st_mode))
			type = DT_REG;
		else if (S_ISDIR(buf.st_mode))
			type = DT_DIR;
		else if (S_ISLNK(buf.st_mode))
			type = DT_LNK;
	}
	return type;
}

static int tomoyo_scandir_filter(const struct dirent *buf)
{
	return strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

static struct tomoyo_path_info tomoyo_target;
static _Bool tomoyo_print_path_needs_separator = false;

static _Bool tomoyo_print_path(const char *path, const int type)
{
	struct tomoyo_path_info name;
	int len;
	char *cp;
	len = strlen(path) * 4 + 4;
	cp = malloc(len);
	if (!cp)
		tomoyo_out_of_memory();
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
	tomoyo_fill_path_info(&name);
	if (tomoyo_path_matches_pattern(&name, &tomoyo_target)) {
		if (tomoyo_print_path_needs_separator)
			putchar(' ');
		tomoyo_print_path_needs_separator = true;
		printf("%s", name.name);
	}
	len = name.total_len >= tomoyo_target.const_len ? tomoyo_target.const_len :
		name.total_len;
	len = strncmp(name.name, tomoyo_target.name, len);
	free((void *) name.name);
	return !len;
}

static char tomoyo_path[8192];

static void tomoyo_scan_dir(void)
{
	struct dirent **namelist;
	int n = scandir(tomoyo_path, &namelist, tomoyo_scandir_filter, 0);
	int len;
	int i;
	if (n < 0)
		return;
	len = strlen(tomoyo_path);
	if (len == 1)
		len = 0;
	for (i = 0; i < n; i++) {
		unsigned char type = namelist[i]->d_type;
		snprintf(tomoyo_path + len, sizeof(tomoyo_path) - len - 1, "/%s",
			 namelist[i]->d_name);
		if (type == DT_UNKNOWN)
			type = tomoyo_revalidate_path(tomoyo_path);
		if (tomoyo_print_path(tomoyo_path, type) && type == DT_DIR)
			tomoyo_scan_dir();
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static void tomoyo_do_pathmatch_main(char *find)
{
	if (!strcmp(find, "/"))
		putchar('/');
	else if (tomoyo_correct_path(find)) {
		tomoyo_target.name = find;
		tomoyo_fill_path_info(&tomoyo_target);
		tomoyo_print_path_needs_separator = false;
		memset(tomoyo_path, 0, sizeof(tomoyo_path));
		strncpy(tomoyo_path, "/", sizeof(tomoyo_path) - 1);
		tomoyo_scan_dir();
	}
	putchar('\n');
}

int main(int argc, char *argv[])
{
	if (argc > 1) {
		int i;
		for (i = 1; i < argc; i++)
			tomoyo_do_pathmatch_main(argv[i]);
	} else {
		tomoyo_get();
		while (true) {
			char *line = tomoyo_freadline(stdin);
			if (!line)
				break;
			tomoyo_do_pathmatch_main(line);
		}
		tomoyo_put();
	}
	return 0;
}
