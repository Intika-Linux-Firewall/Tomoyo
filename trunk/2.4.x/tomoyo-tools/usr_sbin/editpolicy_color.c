/*
 * editpolicy_color.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/06/26
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
#include "tomoyotools.h"
#include "editpolicy.h"

#ifdef COLOR_ON

/**
 * tomoyo_editpolicy_color_init - Initialize line coloring table.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_color_init(void)
{
	static struct tomoyo_color_env_t {
		enum tomoyo_color_pair tag;
		short int fore;
		short int back;
		const char *name;
	} color_env[] = {
		{ TOMOYO_DOMAIN_HEAD,      COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_HEAD" },
		{ TOMOYO_DOMAIN_CURSOR,    COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_CURSOR" },
		{ TOMOYO_EXCEPTION_HEAD,   COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_HEAD" },
		{ TOMOYO_EXCEPTION_CURSOR, COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_CURSOR" },
		{ TOMOYO_ACL_HEAD,         COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_HEAD" },
		{ TOMOYO_ACL_CURSOR,       COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_CURSOR" },
		{ TOMOYO_PROFILE_HEAD,     COLOR_WHITE,
		  COLOR_RED,        "PROFILE_HEAD" },
		{ TOMOYO_PROFILE_CURSOR,   COLOR_WHITE,
		  COLOR_RED,        "PROFILE_CURSOR" },
		{ TOMOYO_MANAGER_HEAD,     COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_HEAD" },
		{ TOMOYO_MANAGER_CURSOR,   COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_CURSOR" },
		{ TOMOYO_STAT_HEAD,        COLOR_BLACK,
		  COLOR_YELLOW,     "STAT_HEAD" },
		{ TOMOYO_STAT_CURSOR,      COLOR_BLACK,
		  COLOR_YELLOW,     "STAT_CURSOR" },
		{ TOMOYO_DEFAULT_COLOR,    COLOR_WHITE,
		  COLOR_BLACK,      "DEFAULT_COLOR" },
		{ TOMOYO_NORMAL,           COLOR_WHITE,
		  COLOR_BLACK,      NULL }
	};
	FILE *fp = fopen(TOMOYO_EDITPOLICY_CONF, "r");
	int i;
	if (!fp)
		goto use_default;
	tomoyo_get();
	while (true) {
		char *line = tomoyo_freadline(fp);
		char *cp;
		if (!line)
			break;
		if (!tomoyo_str_starts(line, "line_color "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		tomoyo_normalize_line(line);
		tomoyo_normalize_line(cp);
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
	tomoyo_put();
	fclose(fp);
use_default:
	start_color();
	for (i = 0; color_env[i].name; i++) {
		struct tomoyo_color_env_t *colorp = &color_env[i];
		init_pair(colorp->tag, colorp->fore, colorp->back);
	}
	init_pair(TOMOYO_DISP_ERR, COLOR_RED, COLOR_BLACK); /* error message */
	bkgdset(A_NORMAL | COLOR_PAIR(TOMOYO_DEFAULT_COLOR) | ' ');
	for (i = 0; i < TOMOYO_MAXSCREEN; i++)
		tomoyo_screen[i].saved_color_current = -1;
}

/**
 * tomoyo_editpolicy_color_save - Save or load current color.
 *
 * @flg: True if save request, false otherwise.
 *
 * Returns nothing.
 */
static void tomoyo_editpolicy_color_save(const _Bool flg)
{
	static attr_t save_color = TOMOYO_DEFAULT_COLOR;
	if (flg)
		save_color = getattrs(stdscr);
	else
		attrset(save_color);
}

/**
 * tomoyo_editpolicy_color_change - Change current color.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(COLOR_PAIR(attr));
	else
		attroff(COLOR_PAIR(attr));
}

/**
 * tomoyo_editpolicy_attr_change - Change current attribute.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(attr);
	else
		attroff(attr);
}

/**
 * tomoyo_editpolicy_sttr_save - Save current color.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_sttr_save(void)
{
	tomoyo_editpolicy_color_save(true);
}

/**
 * tomoyo_editpolicy_sttr_restore - Load current color.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_sttr_restore(void)
{
	tomoyo_editpolicy_color_save(false);
}

/**
 * tomoyo_editpolicy_color_head - Get color to use for header line.
 *
 * Returns one of values in "enum tomoyo_color_pair".
 */
enum tomoyo_color_pair tomoyo_editpolicy_color_head(void)
{
	switch (tomoyo_current_screen) {
	case TOMOYO_SCREEN_DOMAIN_LIST:
		return TOMOYO_DOMAIN_HEAD;
	case TOMOYO_SCREEN_EXCEPTION_LIST:
		return TOMOYO_EXCEPTION_HEAD;
	case TOMOYO_SCREEN_PROFILE_LIST:
		return TOMOYO_PROFILE_HEAD;
	case TOMOYO_SCREEN_MANAGER_LIST:
		return TOMOYO_MANAGER_HEAD;
	case TOMOYO_SCREEN_STAT_LIST:
		return TOMOYO_STAT_HEAD;
	default:
		return TOMOYO_ACL_HEAD;
	}
}

/**
 * tomoyo_editpolicy_color_cursor - Get color to use for cursor line.
 *
 * Returns one of values in "enum tomoyo_color_pair".
 */
static inline enum tomoyo_color_pair tomoyo_editpolicy_color_cursor(void)
{
	switch (tomoyo_current_screen) {
	case TOMOYO_SCREEN_DOMAIN_LIST:
		return TOMOYO_DOMAIN_CURSOR;
	case TOMOYO_SCREEN_EXCEPTION_LIST:
		return TOMOYO_EXCEPTION_CURSOR;
	case TOMOYO_SCREEN_PROFILE_LIST:
		return TOMOYO_PROFILE_CURSOR;
	case TOMOYO_SCREEN_MANAGER_LIST:
		return TOMOYO_MANAGER_CURSOR;
	case TOMOYO_SCREEN_STAT_LIST:
		return TOMOYO_STAT_CURSOR;
	default:
		return TOMOYO_ACL_CURSOR;
	}
}

/**
 * tomoyo_editpolicy_line_draw - Update colored line.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_line_draw(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	const int current = tomoyo_editpolicy_get_current();
	int y;
	int x;

	if (current == EOF)
		return;

	getyx(stdscr, y, x);
	if (-1 < ptr->saved_color_current &&
	    current != ptr->saved_color_current) {
		move(TOMOYO_HEADER_LINES + ptr->saved_color_y, 0);
		chgat(-1, A_NORMAL, TOMOYO_DEFAULT_COLOR, NULL);
	}

	move(y, x);
	chgat(-1, A_NORMAL, tomoyo_editpolicy_color_cursor(), NULL);
	touchwin(stdscr);

	ptr->saved_color_current = current;
	ptr->saved_color_y = ptr->y;
}

#else

/**
 * tomoyo_editpolicy_color_init - Initialize line coloring table.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_color_init(void)
{
}

/**
 * tomoyo_editpolicy_color_change - Change current color.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
}

/**
 * tomoyo_editpolicy_attr_change - Change current attribute.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
}

/**
 * tomoyo_editpolicy_sttr_save - Save current color.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_sttr_save(void)
{
}

/**
 * tomoyo_editpolicy_sttr_restore - Load current color.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_sttr_restore(void)
{
}

/**
 * tomoyo_editpolicy_color_head - Get color to use for header line.
 *
 * Returns one of values in "enum tomoyo_color_pair".
 */
enum tomoyo_color_pair tomoyo_editpolicy_color_head(void)
{
	return TOMOYO_DEFAULT_COLOR;
}

/**
 * tomoyo_editpolicy_line_draw - Update colored line.
 *
 * Returns nothing.
 */
void tomoyo_editpolicy_line_draw(void)
{
}

#endif
