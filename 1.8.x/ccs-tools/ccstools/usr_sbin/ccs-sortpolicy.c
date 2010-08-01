/*
 * ccs-sortpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
 *
 */
#include "ccstools.h"

int main(int argc, char *argv[])
{
	struct ccs_domain_policy dp = { NULL, 0, NULL };
	ccs_read_domain_policy(&dp, NULL);
	ccs_write_domain_policy(&dp, 1);
	ccs_clear_domain_policy(&dp);
	return 0;
}
