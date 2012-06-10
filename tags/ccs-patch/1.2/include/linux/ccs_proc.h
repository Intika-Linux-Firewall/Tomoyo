/*
 * include/linux/ccs_proc.h
 *
 * /proc interface for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.2   2006/09/03
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

/*************************  Indexes for /proc interfaces.  *************************/

#define CCS_POLICY_DOMAINPOLICY          0
#define CCS_POLICY_EXCEPTIONPOLICY       1
#define CCS_POLICY_SYSTEMPOLICY          2
#define CCS_INFO_TRUSTEDPIDS             3
#define CCS_INFO_DELETEDPIDS             4
#define CCS_INFO_MEMINFO                 5
#define CCS_INFO_GRANTLOG                6
#define CCS_INFO_REJECTLOG               7
#define CCS_INFO_SELFDOMAIN              8
#define CCS_INFO_MAPPING                 9
#define CCS_STATUS                      10
#define CCS_POLICY_QUERY                11

#endif
