/*
 * editpolicy_color.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0   2010/11/11
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "ccstools.h"
#include "editpolicy.h"

#ifdef COLOR_ON

void ccs_editpolicy_color_init(void)
{
	static struct ccs_color_env_t {
		enum ccs_color_pair tag;
		short int fore;
		short int back;
		const char *name;
	} color_env[] = {
		{ CCS_DOMAIN_HEAD,      COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_HEAD" },
		{ CCS_DOMAIN_CURSOR,    COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_CURSOR" },
		{ CCS_EXCEPTION_HEAD,   COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_HEAD" },
		{ CCS_EXCEPTION_CURSOR, COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_CURSOR" },
		{ CCS_ACL_HEAD,         COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_HEAD" },
		{ CCS_ACL_CURSOR,       COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_CURSOR" },
		{ CCS_PROFILE_HEAD,     COLOR_WHITE,
		  COLOR_RED,        "PROFILE_HEAD" },
		{ CCS_PROFILE_CURSOR,   COLOR_WHITE,
		  COLOR_RED,        "PROFILE_CURSOR" },
		{ CCS_MANAGER_HEAD,     COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_HEAD" },
		{ CCS_MANAGER_CURSOR,   COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_CURSOR" },
		{ CCS_MEMORY_HEAD,      COLOR_BLACK,
		  COLOR_YELLOW,     "MEMORY_HEAD" },
		{ CCS_MEMORY_CURSOR,    COLOR_BLACK,
		  COLOR_YELLOW,     "MEMORY_CURSOR" },
		{ CCS_NORMAL,           COLOR_WHITE,
		  COLOR_BLACK,      NULL }
	};
	FILE *fp = fopen(CCS_CONFIG_FILE, "r");
	int i;
	if (!fp)
		goto use_default;
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp);
		char *cp;
		if (!line)
			break;
		if (!ccs_str_starts(line, "editpolicy.line_color "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		ccs_normalize_line(line);
		ccs_normalize_line(cp);
		if (!*line || !*cp)
			continue;
		for (i = 0; color_env[i].name; i++) {
			short int fore;
			short int back;
			if (strcmp(line, color_env[i].name))
				continue;
			if (strlen(cp) != 2)
				break;
			fore = (*cp++) - '0'; /* foreground color */
			back = (*cp) - '0';   /* background color */
			if (fore < 0 || fore > 7 || back < 0 || back > 7)
				break;
			color_env[i].fore = fore;
			color_env[i].back = back;
			break;
		}
	}
	ccs_put();
	fclose(fp);
use_default:
	start_color();
	for (i = 0; color_env[i].name; i++) {
		struct ccs_color_env_t *colorp = &color_env[i];
		init_pair(colorp->tag, colorp->fore, colorp->back);
	}
	init_pair(CCS_DISP_ERR, COLOR_RED, COLOR_BLACK); /* error message */
}

static void ccs_editpolicy_color_save(const _Bool flg)
{
	static attr_t save_color = CCS_NORMAL;
	if (flg)
		save_color = getattrs(stdscr);
	else
		attrset(save_color);
}

void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(COLOR_PAIR(attr));
	else
		attroff(COLOR_PAIR(attr));
}

void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(attr);
	else
		attroff(attr);
}

void ccs_editpolicy_sttr_save(void)
{
	ccs_editpolicy_color_save(true);
}

void ccs_editpolicy_sttr_restore(void)
{
	ccs_editpolicy_color_save(false);
}

int ccs_editpolicy_color_head(const int screen)
{
	switch (screen) {
	case CCS_SCREEN_DOMAIN_LIST:
		return CCS_DOMAIN_HEAD;
	case CCS_SCREEN_EXCEPTION_LIST:
		return CCS_EXCEPTION_HEAD;
	case CCS_SCREEN_PROFILE_LIST:
		return CCS_PROFILE_HEAD;
	case CCS_SCREEN_MANAGER_LIST:
		return CCS_MANAGER_HEAD;
	case CCS_SCREEN_MEMINFO_LIST:
		return CCS_MEMORY_HEAD;
	default:
		return CCS_ACL_HEAD;
	}
}

int ccs_editpolicy_color_cursor(const int screen)
{
	switch (screen) {
	case CCS_SCREEN_DOMAIN_LIST:
		return CCS_DOMAIN_CURSOR;
	case CCS_SCREEN_EXCEPTION_LIST:
		return CCS_EXCEPTION_CURSOR;
	case CCS_SCREEN_PROFILE_LIST:
		return CCS_PROFILE_CURSOR;
	case CCS_SCREEN_MANAGER_LIST:
		return CCS_MANAGER_CURSOR;
	case CCS_SCREEN_MEMINFO_LIST:
		return CCS_MEMORY_CURSOR;
	default:
		return CCS_ACL_CURSOR;
	}
}

void ccs_editpolicy_line_draw(const int screen)
{
	static int ccs_before_current[CCS_MAXSCREEN] = { -1, -1, -1, -1,
							 -1, -1, -1 };
	static int ccs_before_y[CCS_MAXSCREEN]       = { -1, -1, -1, -1,
							 -1, -1, -1 };
	int current = ccs_editpolicy_get_current();
	int y;
	int x;

	if (current == EOF)
		return;

	getyx(stdscr, y, x);
	if (-1 < ccs_before_current[screen] &&
	    current != ccs_before_current[screen]){
		move(CCS_HEADER_LINES + ccs_before_y[screen], 0);
		chgat(-1, A_NORMAL, CCS_NORMAL, NULL);
	}

	move(y, x);
	chgat(-1, A_NORMAL, ccs_editpolicy_color_cursor(screen), NULL);
	touchwin(stdscr);

	ccs_before_current[screen] = current;
	ccs_before_y[screen] = ccs_current_y[screen];
}

#else

void ccs_editpolicy_color_init(void)
{
}
void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
}
void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
}
void ccs_editpolicy_sttr_save(void)
{
}
void ccs_editpolicy_sttr_restore(void)
{
}
int ccs_editpolicy_color_head(const int screen)
{
}
int ccs_editpolicy_color_cursor(const int screen)
{
}
void ccs_editpolicy_line_draw(const int screen)
{
}

#endif
