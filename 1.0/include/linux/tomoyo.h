/*
 * include/linux/tomoyo.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/*
 * A brief description about TOMOYO:
 *
 *  TOMOYO stands for "Task Oriented Management Obviates Your Onus".
 *  TOMOYO is intended to provide the Domain-Based MAC utilizing task_struct.
 *
 *  The biggest feature of TOMOYO is that TOMOYO has "accept mode".
 *  The accept mode can automatically generate policy definition,
 *  and dramatically reduces the policy definition labors.
 *
 *  TOMOYO is applicable to figuring out the system's behavior, for
 *  TOMOYO uses the canonicalized absolute pathnames and TreeView style domain transitions.
 */

#ifndef _LINUX_TOMOYO_H
#define _LINUX_TOMOYO_H

/***** TOMOYO Linux start. *****/

#ifdef CONFIG_TOMOYO
/* Find the next domain to transit to. */
struct domain_info *GetNextDomain(const char *filename, int *errno);
#else
static inline struct domain_info *GetNextDomain(const char *filename, int *errno) { return current->domain_info; }
#endif

#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
/* Check whether the given filename is allowed to read/write/execute. */
int CheckFilePerm(const char *filename, const unsigned short int perm, const int is_realpath, const char *operation);
/* Check whether the given dentry is allowed to write. */
int CheckWritePermission(struct dentry *dentry, struct vfsmount *mnt, const int is_dir, const char *operation);
#else
static inline int CheckFilePerm(const char *filename, const unsigned short int perm, const int is_realpath, const char *operation) { return 0; }
static inline int CheckWritePermission(struct dentry *dentry, struct vfsmount *mnt, const int is_dir, const char *operation) { return 0; }
#endif

/* Check whether the given port number is allowed to bind. */
#ifdef CONFIG_TOMOYO_MAC_FOR_BINDPORT
int CheckBindEntry(const int is_stream, const unsigned short int port);
#else
static inline int CheckBindEntry(const int is_stream, const unsigned short int port) { return 0; }
#endif

/* Check whether the given port number is allowed to connect. */
#ifdef CONFIG_TOMOYO_MAC_FOR_CONNECTPORT
int CheckConnectEntry(const int is_stream, const unsigned short int port);
#else
static inline int CheckConnectEntry(const int is_stream, const unsigned short int port) { return 0; }
#endif

/* Check whether the given signal is allowed to use. */
#ifdef CONFIG_TOMOYO_MAC_FOR_SIGNAL
int CheckSignalACL(const int sig, const int pid);
#else
static inline int CheckSignalACL(const int sig, const int pid) { return 0; }
#endif

/* Check whether the given capability is allowed to use. */
#ifdef CONFIG_TOMOYO_MAC_FOR_CAPABILITY
int CheckCapabilityACL(const unsigned int capability);
#else
static inline int CheckCapabilityACL(const unsigned int capability) { return 0; }
#endif

/*************************  Index numbers for Capability Controls.  *************************/

/* The following constants are used for checking capabilities. */

#define TOMOYO_INET_STREAM_SOCKET_CREATE         0  /* socket(PF_INET or PF_INET6, SOCK_STREAM, *)                 */
#define TOMOYO_INET_STREAM_SOCKET_LISTEN         1  /* listen() for PF_INET or PF_INET6, SOCK_STREAM               */
#define TOMOYO_INET_STREAM_SOCKET_CONNECT        2  /* connect() for PF_INET or PF_INET6, SOCK_STREAM              */
#define TOMOYO_USE_INET_DGRAM_SOCKET             3  /* socket(PF_INET or PF_INET6, SOCK_DGRAM, *)                  */
#define TOMOYO_USE_INET_RAW_SOCKET               4  /* socket(PF_INET or PF_INET6, SOCK_RAW, *)                    */
#define TOMOYO_USE_ROUTE_SOCKET                  5  /* socket(PF_ROUTE, *, *)                                      */
#define TOMOYO_USE_PACKET_SOCKET                 6  /* socket(PF_PACKET, *, *)                                     */
#define TOMOYO_SYS_MOUNT                         7  /* sys_mount()                                                 */
#define TOMOYO_SYS_UMOUNT                        8  /* sys_umount()                                                */
#define TOMOYO_SYS_REBOOT                        9  /* sys_reboot()                                                */
#define TOMOYO_SYS_CHROOT                       10  /* sys_chroot()                                                */
#define TOMOYO_SYS_KILL                         11  /* sys_kill(), sys_tkill(), sys_tgkill()                       */
#define TOMOYO_SYS_VHANGUP                      12  /* sys_vhangup()                                               */
#define TOMOYO_SYS_SETTIME                      13  /* do_settimeofday(), sys_adjtimex()                           */
#define TOMOYO_SYS_NICE                         14  /* sys_nice(), sys_setpriority()                               */
#define TOMOYO_SYS_SETHOSTNAME                  15  /* sys_sethostname(), sys_setdomainname()                      */
#define TOMOYO_USE_KERNEL_MODULE                16  /* sys_create_module(), sys_init_module(), sys_delete_module() */
#define TOMOYO_CREATE_FIFO                      17  /* sys_mknod(S_IFIFO)                                          */
#define TOMOYO_CREATE_BLOCK_DEV                 18  /* sys_mknod(S_IFBLK)                                          */
#define TOMOYO_CREATE_CHAR_DEV                  19  /* sys_mknod(S_IFCHR)                                          */
#define TOMOYO_CREATE_UNIX_SOCKET               20  /* sys_mknod(S_IFSOCK)                                         */
#define TOMOYO_SYS_LINK                         21  /* sys_link()                                                  */
#define TOMOYO_SYS_SYMLINK                      22  /* sys_symlink()                                               */
#define TOMOYO_SYS_RENAME                       23  /* sys_rename()                                                */
#define TOMOYO_SYS_UNLINK                       24  /* sys_unlink()                                                */
#define TOMOYO_SYS_CHMOD                        25  /* sys_chmod(), sys_fchmod()                                   */
#define TOMOYO_SYS_CHOWN                        26  /* sys_chown(), sys_fchown(), sys_lchown()                     */
#define TOMOYO_SYS_IOCTL                        27  /* sys_ioctl(), compat_sys_ioctl()                             */

/***** TOMOYO Linux end. *****/
#endif
