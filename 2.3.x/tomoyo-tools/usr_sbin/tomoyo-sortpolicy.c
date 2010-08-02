/*
 * tomoyo-sortpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.3.0   2010/08/02
 *
 */
#include "tomoyotools.h"

int main(int argc, char *argv[])
{
	struct tomoyo_domain_policy dp = { NULL, 0, NULL };
	tomoyo_read_domain_policy(&dp, NULL);
	tomoyo_write_domain_policy(&dp, 1);
	tomoyo_clear_domain_policy(&dp);
	return 0;
}
