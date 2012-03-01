/*
 * include/linux/ccs_proc.h
 *
 * /proc/ccs/ interface for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9   2011/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_CCS_PROC_H
#define _LINUX_CCS_PROC_H

#ifndef __user
#define __user
#endif

/* Indexes for /proc/ccs/ interfaces. */
enum ccs_proc_interface_index {
	CCS_DOMAINPOLICY,
	CCS_EXCEPTIONPOLICY,
	CCS_SYSTEMPOLICY,
	CCS_DOMAIN_STATUS,
	CCS_PROCESS_STATUS,
	CCS_MEMINFO,
#ifdef CONFIG_TOMOYO_AUDIT
	CCS_GRANTLOG,
	CCS_REJECTLOG,
#endif
	CCS_SELFDOMAIN,
	CCS_VERSION,
	CCS_PROFILE,
	CCS_QUERY,
	CCS_MANAGER,
	CCS_UPDATESCOUNTER,
	CCS_EXECUTE_HANDLER
};

#endif
