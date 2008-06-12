/*
 * include/linux/ccs_proc.h
 *
 * /proc/ccs/ interface for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.2-rc   2008/06/12
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
#define CCS_DOMAINPOLICY          0
#define CCS_EXCEPTIONPOLICY       1
#define CCS_SYSTEMPOLICY          2
#define CCS_DOMAIN_STATUS         3
#define CCS_PROCESS_STATUS        4
#define CCS_MEMINFO               5
#define CCS_GRANTLOG              6
#define CCS_REJECTLOG             7
#define CCS_SELFDOMAIN            8
#define CCS_VERSION               9
#define CCS_PROFILE              10
#define CCS_QUERY                11
#define CCS_MANAGER              12
#define CCS_UPDATESCOUNTER       13

#endif
