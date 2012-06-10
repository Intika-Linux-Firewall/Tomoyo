/*
 * fs/sakura_pivot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1.2   2006/06/02
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>

/*************************  PIVOTROOT PROTECTOR  *************************/

int CheckPivotRootPermission(void)
{
	const int is_enforce = CheckCCSEnforce(CCS_SAKURA_DENY_PIVOT_ROOT);
	if (!CheckCCSFlags(CCS_SAKURA_DENY_PIVOT_ROOT)) return 0;
	printk("SAKURA-%s: pivotroot : Permission denied.\n", GetMSG(is_enforce));
	if (is_enforce) return CheckSupervisor("# pivot_root is requested.\n");
	return 0;
}

EXPORT_SYMBOL(CheckPivotRootPermission);

/***** SAKURA Linux end. *****/
