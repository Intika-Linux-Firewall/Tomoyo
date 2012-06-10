Summary: The Linux kernel (the core of the Linux operating system)

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.

%define buildup 1
%define buildsmp 1

%define builddoc 0

# Versions of various parts

#
# Polite request for people who spin their own kernel rpms:
# please modify the "release" field in a way that identifies
# that the kernel isn't the stock distribution kernel, for example by
# adding some text to the end of the version number.
#
%define sublevel 12
%define kversion 2.6.%{sublevel}
%define rpmversion 2.6.%{sublevel}
#define rhbsys  %([ -r /etc/beehive-root -o -n "%{?__beehive_build}" ] && echo || echo .`whoami`)
#define release %(R="$Revision: 1.1381 $"; RR="${R##: }"; echo ${RR%%?})_FC3%{rhbsys}
%define release 2.3.legacy_FC3_tomoyo_1.4.1
%define signmodules 0
%define make_target bzImage

%define KVERREL %{PACKAGE_VERSION}-%{PACKAGE_RELEASE}

# groups of related archs
%define all_x86 i586 i686

# Override generic defaults with per-arch defaults 

%ifarch noarch
%define builddoc 1
%define buildup 0
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-*.config
%endif

# Second, per-architecture exclusions (ifarch)

%ifarch %{all_x86}
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-i?86*.config
%define image_install_path boot
%define signmodules 1
%endif

%ifarch x86_64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-x86_64*.config
%define image_install_path boot
%define signmodules 1
%endif

%ifarch ppc64
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc64*.config
%define image_install_path boot
%define signmodules 1
%define make_target bzImage zImage.stub
%endif

%ifarch ppc64iseries
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc64*.config
%define image_install_path boot
%define signmodules 1
%define make_target bzImage
%endif

%ifarch s390
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-s390*.config
%define image_install_path boot
%endif

%ifarch s390x
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-s390x.config
%define image_install_path boot
%endif

%ifarch sparc
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-sparc.config
%define buildsmp 0
%endif

%ifarch sparc64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-sparc64*.config
%endif

%ifarch ppc
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc*.config
%define buildsmp 1
%define image_install_path boot
%endif

%ifarch ia64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ia64.config
%define buildsmp 0
%define image_install_path boot/efi/EFI/redhat
%define signmodules 1
%endif

# TOMOYO Linux
%define signmodules 0

#
# Three sets of minimum package version requirements in the form of Conflicts:
# to versions below the minimum
#

#
# First the general kernel 2.6 required versions as per
# Documentation/Changes
#
%define kernel_dot_org_conflicts  ppp <= 2.3.15, pcmcia-cs <= 3.1.20, isdn4k-utils <= 3.0, mount < 2.10r-5, nfs-utils < 1.0.3, e2fsprogs < 1.29, util-linux < 2.10, jfsutils < 1.0.14, reiserfsprogs < 3.6.3, xfsprogs < 2.1.0, procps < 2.0.9, oprofile < 0.5.3

# 
# Then a series of requirements that are distribution specific, either 
# because we add patches for something, or the older versions have 
# problems with the newer kernel or lack certain things that make 
# integration in the distro harder than needed.
#
%define package_conflicts  cipe < 1.4.5, kudzu <= 0.92, initscripts < 7.23, dev < 3.2-7, iptables < 1.2.5-3, bcm5820 < 1.81, nvidia-rh72 <= 1.0 selinux-policy-targeted < 1.17.30-3.16

#
# Several packages had bugs in them that became obvious when the NPTL
# threading code got integrated. 
#
%define nptl_conflicts SysVinit < 2.84-13, pam < 0.75-48, vixie-cron < 3.0.1-73, privoxy < 3.0.0-8, spamassassin < 2.44-4.8.x,  cups < 1.1.17-13

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
%define kernel_prereq  fileutils, module-init-tools, initscripts >= 5.83, mkinitrd >= 4.1.18.1-1

Name: kernel
Group: System Environment/Kernel
License: GPLv2
Version: %{rpmversion}
Release: %{release}
ExclusiveArch: noarch %{all_x86} x86_64 ppc64 ppc64iseries ppc
ExclusiveOS: Linux
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{nptl_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReqProv: no

#
# List the packages used during the kernel build
#
BuildPreReq: module-init-tools, patch >= 2.5.4, bash >= 2.03, sh-utils, tar
BuildPreReq: bzip2, findutils, gzip, m4, perl, make >= 3.78, gnupg, diffutils
BuildRequires: gcc >= 3.4.2, binutils >= 2.12, redhat-rpm-config
BuildConflicts: rhbuildsys(DiskFree) < 500Mb


Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-%{kversion}.tar.bz2

Source10: COPYING.modules
Source11: genkey

Source20: kernel-%{kversion}-i586.config
Source21: kernel-%{kversion}-i586-smp.config
Source22: kernel-%{kversion}-i686.config
Source23: kernel-%{kversion}-i686-smp.config
Source24: kernel-%{kversion}-x86_64.config
Source25: kernel-%{kversion}-x86_64-smp.config
Source26: kernel-%{kversion}-ppc64.config
Source27: kernel-%{kversion}-ppc64iseries.config
Source28: kernel-%{kversion}-s390.config
Source29: kernel-%{kversion}-s390x.config
#Source30: kernel-%{kversion}-sparc.config
#Source31: kernel-%{kversion}-sparc64.config
#Source32: kernel-%{kversion}-sparc64-smp.config
Source33: kernel-%{kversion}-ppc.config
Source34: kernel-%{kversion}-ppc-smp.config
Source35: kernel-%{kversion}-ia64.config

#
# Patches 0 through 100 are meant for core subsystem upgrades
#
Patch1: patch-2.6.12.5.bz2
Patch2: patch-2.6.12.6pre.patch

# Patches 100 through 500 are meant for architecture patches

# 200 - 299   x86(-64)

Patch200: linux-2.6.10-x86-tune-p4.patch
Patch201: linux-2.6-x86_64-disable-tlb-flush-filter.patch

# 300 - 399   ppc(64)
Patch300: linux-2.6.2-ppc64-build.patch
Patch301: linux-2.6.12-serial-of.patch
Patch302: linux-2.6.10-ppc-headerabuse.patch
Patch303: linux-2.6-windtunnel-printk.patch

# 400 - 499   ia64
Patch400: linux-2.6.3-ia64-build.patch

# 500 - 599   s390(x)
Patch500: linux-2.6.1-s390-compile.patch
Patch501: linux-2.6.9-s390-autoraid.patch
Patch502: linux-2.6.9-s390-zfcp_port-fix.patch

# 600 - 699   sparc(64)
Patch600: linux-2.6.3-sparc-addbzimage.patch

#
# Patches 500 through 1000 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#
Patch800: linux-2.4.0-nonintconfig.patch
Patch801: linux-2.6.0-must_check.patch

Patch810: linux-2.6.11-execshield.patch
Patch811: linux-2.6.10-x86_64-read-implies-exec32.patch
Patch813: linux-2.6.11-execshield-vdso.patch

# Module signing infrastructure.
Patch900: linux-2.6.7-modsign-core.patch
Patch901: linux-2.6.7-modsign-crypto.patch
Patch902: linux-2.6.7-modsign-ksign.patch
Patch903: linux-2.6.7-modsign-mpilib.patch
Patch904: linux-2.6.7-modsign-script.patch
Patch905: linux-2.6.7-modsign-include.patch

# Tux http accelerator.
Patch910: linux-2.6.11-tux.patch

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#
Patch1000: linux-2.4.0-test11-vidfail.patch
Patch1010: linux-2.6.10-periodic-slab-debug.patch
Patch1011: linux-2.6.11-slab-backtrace.patch
Patch1020: linux-2.6.4-stackusage.patch

Patch1050: linux-2.6.11-devmem.patch

Patch1060: linux-2.6.3-crash-driver.patch
Patch1070: linux-2.6.0-sleepon.patch

# SCSI bits.
Patch1101: linux-2.6.9-scsi-advansys-enabler.patch
Patch1102: linux-2.6.9-scsi-megaraid-legacy.patch
Patch1103: linux-2.6.12-scsi-blacklist.patch
Patch1104: linux-2.6.12-scsicam-geom-fix.patch
Patch1105: linux-2.6-scsi-sym2-alloc_lcb_tags-atomic.patch
Patch1106: linux-2.6-scsi-aic-dma39bit.patch

# NFS bits.
Patch1200: linux-2.6.9-NFSD-non-null-getxattr.patch
Patch1201: linux-2.6.8-lockd-racewarn2.patch
Patch1202: linux-2.6.9-lockd-block-nosleep.patch
Patch1203: linux-2.6.9-lockd-reclaims.patch
Patch1204: linux-2.6.12-nfsd-ctlbits.patch
Patch1205: linux-2.6-nfs-enoent.patch

# NIC driver updates
Patch1300: linux-2.6.9-net-tr-irqlock-fix.patch
Patch1301: linux-2.6.12-net-sundance-ip100A.patch
Patch1302: linux-2.6.12-net-make-orinoco-suck-less.patch
Patch1304: linux-2.6.12-net-atm-lanai-nodev-rmmod.patch

# USB bits
Patch1400: linux-2.6.12-usb-old_scheme_first.patch
Patch1401: linux-2.6.12-rc3-ehci-misc-updates.patch
Patch1402: linux-2.6.11-random-ehci-patch.patch
Patch1403: linux-2.6-usbmon-deficiency-workaround.patch
Patch1404: linux-2.6-usbhid-wireless-security-lock.patch
Patch1405: linux-2.6-usb-transcend-nosense.patch

# Netdump and Diskdump bits.
Patch1500: linux-2.6-crashdump-common.patch
Patch1501: linux-2.6-netdump.patch
Patch1502: linux-2.6-netconsole.patch
Patch1503: linux-2.6-diskdump.patch
Patch1504: linux-2.6-crashdump-reboot-exports.patch
Patch1505: linux-2.6-dump_smp_call_function.patch

# Misc bits.
Patch1600: linux-2.6.11-i2c-config.patch
Patch1601: linux-2.6.11-atkbd-dell-multimedia.patch
Patch1602: linux-2.6.11-isdn-icn-nodev.patch
Patch1603: linux-2.6.11-panic-stackdump.patch
Patch1604: linux-2.6.10-revert-module-invalidparam.patch
Patch1605: linux-2.6.12rc-ac-ide-fixes.patch
Patch1606: linux-2.6-ide-tune-locking.patch
Patch1607: linux-2.6-ide-scsi-check_condition.patch
Patch1608: linux-2.6.9-module_version.patch
Patch1609: linux-2.6.9-spinlock-debug-panic.patch
Patch1610: linux-2.6.11-default-elevator.patch
Patch1611: linux-2.6.11-taint-check.patch
Patch1612: linux-2.6-procfs-i_nlink-miscalculate.patch
Patch1613: linux-2.6.11-libata-promise-pata-on-sata.patch
Patch1614: linux-2.6.12-input-kill-stupid-messages.patch
Patch1615: linux-2.6.12-audit-merge.patch
Patch1616: linux-2.6.13-rc3-audit-git.patch
Patch1617: linux-2.6.11-serial-tickle-nmi.patch
Patch1618: linux-2.6.12-missing-exports.patch
Patch1619: linux-2.6.11-radeon-backlight.patch
Patch1620: linux-2.6.12-firedire-init-breakage.patch 
Patch1621: linux-2.6.12-pwc-warning.patch
Patch1622: linux-2.6.12-ns558-nodev-rmmod.patch
Patch1623: linux-2.6-appletouch-update.patch
Patch1624: linux-2.6-powernow-k8-update.patch
Patch1625: linux-2.6-selinux-addrlen-checks.patch
Patch1626: linux-2.6-input-alps-typo.patch
Patch1627: linux-2.6-exec-bogus-bugon.patch
Patch1628: linux-2.6-pwc-powerup-by-default.patch
Patch1629: linux-2.6-md-stacked-drivers.patch
Patch1630: linux-2.6-ibmcam-v4noblue.patch
Patch1631: linux-2.6-libata-intel-combined-quirk.patch

Patch2000: linux-2.6.11-vm-taint.patch
Patch2001: linux-2.6.9-vm-oomkiller-debugging.patch
Patch2002: linux-2.6.12-vm-singlebiterror.patch

Patch2100: linux-2.6-acpi-20050729.patch.bz2
Patch2102: linux-2.6-acpi-rollup-20050902.patch
Patch2103: linux-2.6-acpi-hotkey-fix.patch
Patch2110: linux-2.6.11-acpi-thinkpad-c2c3.patch

Patch2200: linux-2.6-alsa-snd-intel8x0m-semaphore.patch

Patch2999: linux-2.6.3-printopen.patch

Patch3000: linux-2.6-CAN-2005-2490.patch
Patch3001: linux-2.6-CAN-2005-2492.patch
Patch3002: linux-2.6-CAN-2005-2973.patch
Patch3003: linux-2.6-CAN-2005-3179.patch
Patch3004: linux-2.6-CAN-2005-3180.patch
Patch3005: linux-2.6-CAN-2005-3181.patch

#
# External drivers that are about to get accepted upstream
#

# Intel Centrino wireless drivers.
Patch3020: linux-2.6.9-ipw2100.patch
Patch3021: linux-2.6.9-ipw2200.patch
Patch3022: linux-2.6.9-ieee80211.patch

# Fedora Legacy security patches

Patch4000: linux-2.6.12-CAN-2005-2709-sysctl-unregister.patch
Patch4001: linux-2.6.12-CVE-2005-3044.patch
Patch4002: linux-2.6.12-ipvs-conn-flush.patch
Patch4003: linux-2.6.9-mq.patch
Patch4004: linux-2.6.9-CVE-2005-3358-mempolicy.patch
Patch4005: linux-2.6.9-CVE-2005-3784-auto-reap.patch
Patch4006: linux-2.6.9-CVE-2005-3806-ip6-flowlabel-dos.patch
Patch4007: linux-2.6.9-CVE-2005-3857-printk-dos.patch
Patch4008: linux-2.6.9-CVE-2005-4605-proc-info-leak.patch
Patch4009: linux-2.6.12-CVE-2002-2185.patch
Patch4010: linux-2.6.12-CVE-2005-3527.patch
Patch4011: linux-2.6.12-CVE-2005-3805.patch
Patch4012: linux-2.6-CVE-2006-0095.patch
Patch4013: linux-2.6.12-CVE-2006-0454.patch
Patch4014: linux-2.6.12-CVE-2005-3807.patch

#
# 10000 to 20000 is for stuff that has to come last due to the
# amount of drivers they touch. But only these should go here. 
# Not patches you're too lazy for to put in the proper place.
#

Patch10000: linux-2.6.0-compile.patch
Patch10001: linux-2.6-compile-fixes.patch

# END OF PATCH DEFINITIONS

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

%description 
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

%package doc
Summary: Various documentation bits found in the kernel source.
Group: Documentation

%description doc
This package contains documentation files from the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files. 

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.


%package smp
Summary: The Linux kernel compiled for SMP machines.

Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}smp
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{nptl_conflicts}
# upto and including kernel 2.4.9 rpms, the 4Gb+ kernel was called kernel-enterprise
# now that the smp kernel offers this capability, obsolete the old kernel
Obsoletes: kernel-enterprise < 2.4.10
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReqProv: no

%description smp
This package includes a SMP version of the Linux kernel. It is
required only on machines with two or more CPUs as well as machines with
hyperthreading technology.

Install the kernel-smp package if your machine uses two or more CPUs.

%prep
if [ ! -d kernel-%{kversion}/vanilla ]; then
%setup -q -n %{name}-%{version} -c
rm -f pax_global_header
mv linux-%{kversion} vanilla
else
 cd kernel-%{kversion}
fi
rm -rf linux-%{kversion}
cp -rl vanilla linux-%{kversion}

cd linux-%{kversion}

#
# Patches 0 through 100 are meant for core subsystem upgrades
# 
%patch1 -p1
%patch2 -p1

#
# Patches to back out
#

#
# Architecture patches
#

#
# x86(-64)
#
# Compile 686 kernels tuned for Pentium4.
%patch200 -p1
# AMD errata 122
%patch201 -p1

# 
# ppc64
#

# Patch for Kconfig and Makefile build issues
%patch300 -p1
%patch301 -p1
%patch302 -p1
%patch303 -p1

#
# ia64
#

# Basic build fixes
%patch400 -p1


#
# s390
#

# Basic build fixes
%patch500 -p1
# Auto raidstart for S390
%patch501 -p1
# Recover after aborted nameserver request.
%patch502 -p1

#
# sparc/sparc64
#
%patch600 -p1

#
# Patches 500 through 1000 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#


# This patch adds a "make nonint_oldconfig" which is non-interactive and
# also gives a list of missing options at the end. Useful for automated
# builds (as used in the buildsystem).
%patch800 -p1

#
# Patch that adds a __must_check attribute for functions for which checking
# the return value is mantadory (eg copy_from_user)
#
%patch801 -p1


# Exec shield 
%patch810 -p1

# Revert x86-64 read-implies-exec on 32 bit processes.
%patch811 -p1 -R

# Fix up the vdso.
%patch813 -p1

#
# GPG signed kernel modules
#
%patch900 -p1
%patch901 -p1
%patch902 -p1
%patch903 -p1
%patch904 -p1
%patch905 -p1

# Tux
%patch910 -p1

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#


# add vidfail capability; 
# without this patch specifying a framebuffer on the kernel prompt would
# make the boot stop if there's no supported framebuffer device; this is bad
# for the installer cd that wants to automatically fall back to textmode
# in that case
%patch1000 -p1

# Periodically scan slab caches for corruption.
%patch1010 -p1
# Stack backtrace if we find corruption.
%patch1011 -p1

#
# Fix the extreme stack usage in some kernel functions
#
%patch1020 -p1

#
# Make /dev/mem a need-to-know function 
#
%patch1050 -p1

#
# /dev/crash driver for the crashdump analysis tool
#
%patch1060 -p1

#
# Most^WAll users of sleep_on are broken; fix a bunch
#
%patch1070 -p1

#
# SCSI Bits.
#
# Enable Advansys driver
%patch1101 -p1
# Enable both new and old megaraid drivers.
%patch1102 -p1
# Blacklist some SCSI devices that don't like having LUNs probed.
%patch1103 -p1
# SCSI CAM geometry fix.
%patch1104 -p1
# Fix up sleeping in invalid context in sym2 driver.
%patch1105 -p1
# Fix aic7xxx >4GB
%patch1106 -p1

#
# Various upstream NFS/NFSD fixes.
#
%patch1200 -p1
%patch1201 -p1
%patch1202 -p1
%patch1203 -p1
%patch1204 -p1
%patch1205 -p1

# NIC driver fixes.
# Use correct spinlock functions in token ring net code
%patch1300 -p1
# New PCI ID for sundance driver.
%patch1301 -p1
# Make orinoco driver suck less.
%patch1302 -p1
# Fix rmmod lanai
%patch1304 -p1

# USB Bits.
# Enable both old and new style USB initialisation.
#%patch1400 -p1
# Fix port power switching for EHCI
#%patch1401 -p1
# Do something else originally described as "Alan's hint for ehci"
#%patch1402 -p1
%patch1403 -p1
%patch1404 -p1
%patch1405 -p1

# netdump bits
%patch1500 -p1
%patch1501 -p1
%patch1502 -p1
%patch1503 -p1
%patch1504 -p1
%patch1505 -p1

#
# Various SELinux fixes from 2.6.10rc
#

# Misc fixes
# Make some I2C drivers arch dependant.
%patch1600 -p1
# Make multimedia buttons on Dell Inspiron 8200 work.
%patch1601 -p1
# ISDN ICN driver barfs if probed with no cards present.
%patch1602 -p1
# Print stack trace when we panic.
%patch1603 -p1
# Don't barf on obsolete module parameters.
%patch1604 -p1
# Numerous IDE fixes.
%patch1605 -p1
%patch1606 -p1
%patch1607 -p1
# Add missing MODULE_VERSION tags to some modules.
%patch1608 -p1
# Make spinlock debugging panic instead of continue.
%patch1609 -p1
# Make CFQ default elevator again
%patch1610 -p1
# Check tainted bit on oops.
%patch1611 -p1
# Fix up miscalculated i_nlink in /proc
%patch1612 -p1
# Support PATA on Promise SATA.
%patch1613 -p1
# The input layer spews crap no-one cares about.
%patch1614 -p1
# Audit code from git tree which was imported into 2.6.12-git1
%patch1615 -p1
# Audit code from git tree which is still in 2.6.12-mm
%patch1616 -p1
# Tickle the NMI whilst doing serial writes.
%patch1617 -p1
# Missing EXPORT_SYMBOL's
%patch1618 -p1
# Radeon on thinkpad backlight power-management goodness.
%patch1619 -p1
# Fix ochi1394 smp init.
%patch1620 -p1
# Fix warning in pwc driver.
%patch1621 -p1
# Fix oops in ns558 on rmmod
%patch1622 -p1
# Fix Appletouch tapping.
%patch1623 -p1
# powernow-k8 driver update from 2.6.13rc7
%patch1624 -p1
# Fix addrlen checks in selinux_socket_connect
%patch1625 -p1
# ALPS typo fix.
%patch1626 -p1
# Remove bogus BUG_ON in fs/exec.c
%patch1627 -p1
# Power up the pwc camera by default.
%patch1628 -p1
# Cut down stack usage in md layer. (#167173)
#%patch1629 -p1
# Fix no blue/fuzzy video on ibmcam (#148832)
%patch1630 -p1
# Fix up the SATA vs IDE issue.
%patch1631 -p1


#
# VM related fixes.
#
# Display taint bits on VM error.
%patch2000 -p1
# Extra debugging on OOM Kill.
%patch2001 -p1
# Spot single bit errors in slab corruption.
%patch2002 -p1


# ACPI update.
%patch2100 -p1
# Various ACPI fixes from post 2.6.13
%patch2102 -p1
# Fix ACPI hotkey problem.
%patch2103 -p1
# Blacklist another 'No C2/C3 states' Thinkpad R40e BIOS.
%patch2110 -p1

# Fix 'semaphore is not ready' error in snd-intel8x0m
%patch2200 -p1

#
# Local hack (off for any shipped kernels) to printk all files opened 
# the first 180 seconds after boot for debugging userspace startup 
# speeds
#
#%patch2999 -p1

%patch3000 -p1
%patch3001 -p1
%patch3002 -p1
%patch3003 -p1
%patch3004 -p1
%patch3005 -p1

#
# External drivers that are about to get accepted upstream
#

# Intel wireless
%patch3020 -p1
%patch3021 -p1
%patch3022 -p1

# Fedora Legacy security updates
%patch4000 -p2
%patch4001 -p2
%patch4002 -p1
%patch4003 -p1
%patch4004 -p1
%patch4005 -p1
%patch4006 -p1
%patch4007 -p1
%patch4008 -p1
%patch4009 -p2
%patch4010 -p2
%patch4011 -p2
%patch4012 -p1
%patch4013 -p2
%patch4014 -p2

#
# Patches 5000 to 6000 are reserved for new drivers that are about to
# be merged upstream
#


#
# final stuff
#

#
# misc small stuff to make things compile or otherwise improve performance
#
%patch10000 -p1
%patch10001 -p1

# TOMOYO Linux
tar -zxf %_sourcedir/ccs-patch-1.4.1-20070605.tar.gz
sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -2.3.legacy_FC3/" -- Makefile
patch -sp1 < ccs-patch-2.6.12-2.3.legacy_FC3.txt

# END OF PATCH APPLICATIONS

cp %{SOURCE10} Documentation/

mkdir configs

cp -fv %{all_arch_configs} .


# now run oldconfig over all the config files
for i in *.config
do 
	mv $i .config 
	# TOMOYO Linux
	cat config.ccs >> .config
	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
	Arch=`head -1 .config | cut -b 3-`
	make ARCH=$Arch nonint_oldconfig > /dev/null
	echo "# $Arch" > configs/$i
	cat .config >> configs/$i 
done

# make sure the kernel has the sublevel we know it has. This looks weird
# but for -pre and -rc versions we need it since we only want to use
# the higher version when the final kernel is released.
perl -p -i -e "s/^SUBLEVEL.*/SUBLEVEL = %{sublevel}/" Makefile
perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -prep/" Makefile

# get rid of unwanted files resulting from patch fuzz
find . -name "*.orig" -exec rm -fv {} \;
find . -name "*~" -exec rm -fv {} \;

###
### build
###
%build

#
# Create gpg keys for signing the modules
#

gpg --homedir . --batch --gen-key %{SOURCE11}  
gpg --homedir . --export --keyring ./kernel.pub Red > extract.pub 
make linux-%{kversion}/scripts/bin2c
linux-%{kversion}/scripts/bin2c ksign_def_public_key __initdata < extract.pub > linux-%{kversion}/crypto/signature/key.h

cd linux-%{kversion}



BuildKernel() {

    # Pick the right config file for the kernel we're building
    if [ -n "$1" ] ; then
	Config=kernel-%{kversion}-%{_target_cpu}-$1.config
    else
	Config=kernel-%{kversion}-%{_target_cpu}.config
    fi

    KernelVer=%{version}-%{release}$1
    echo BUILDING A KERNEL FOR $1 %{_target_cpu}...

    # make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}$1/" Makefile

    # and now to start the build process

    make -s mrproper
    cp configs/$Config .config

    Arch=`head -1 .config | cut -b 3-`
    echo USING ARCH=$Arch

    make -s ARCH=$Arch nonint_oldconfig > /dev/null
    make -s ARCH=$Arch include/linux/version.h 

    make -s ARCH=$Arch %{?_smp_mflags} %{make_target}
    make -s ARCH=$Arch %{?_smp_mflags} modules || exit 1
    make ARCH=$Arch buildcheck
    
    # Start installing the results

%if "%{_enable_debug_packages}" == "1"
    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/boot
%endif
    mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
    install -m 644 .config $RPM_BUILD_ROOT/boot/config-$KernelVer
    install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-$KernelVer
    cp arch/$Arch/boot/bzImage $RPM_BUILD_ROOT/%{image_install_path}/vmlinuz-$KernelVer
	if [ -f arch/$Arch/boot/zImage.stub ]; then
      cp arch/$Arch/boot/zImage.stub $RPM_BUILD_ROOT/%{image_install_path}/zImage.stub-$KernelVer || :
	fi

    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
    make -s ARCH=$Arch INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=$KernelVer
 
    # And save the headers/makefiles etc for building modules against
    #
    # This all looks scary, but the end result is supposed to be:
    # * all arch relevant include/ files
    # * all Makefile/Kconfig files
    # * all script/ files 

    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/source
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    (cd $RPM_BUILD_ROOT/lib/modules/$KernelVer ; ln -s build source)
    # first copy everything
    cp --parents `find  -type f -name Makefile -o -name "Kconfig*"` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build 
    cp Module.symvers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    # then drop all but the needed Makefiles/Kconfig files
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Documentation
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cp arch/%{_arch}/kernel/asm-offsets.s $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch}/kernel || :
    cp .config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp -a scripts $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
	if [ -d arch/%{_arch}/scripts ]; then
      cp -a arch/%{_arch}/scripts $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch} || :
	fi
	if [ -f arch/%{_arch}/*lds ]; then
      cp -a arch/%{_arch}/*lds $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch}/ || :
	fi
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*.o
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*/*.o
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cd include
    cp -a acpi config linux math-emu media net pcmcia rxrpc scsi sound video asm asm-generic $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cp -a `readlink asm` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
	if [ "$Arch" = "x86_64" ]; then
		cp -a asm-i386 $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
	fi
    # Make sure the Makefile and version.h have a matching timestamp so that
    # external modules can be built
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/version.h
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/autoconf.h
    cd .. 

    #
    # save the vmlinux file for kernel debugging into the kernel-debuginfo rpm
    #
%if "%{_enable_debug_packages}" == "1"
    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer
%endif

    # gpg sign the modules
%if %{signmodules}
    gcc -o scripts/modsign/mod-extract scripts/modsign/mod-extract.c -Wall
	KEYFLAGS="--no-default-keyring --homedir .." 
	KEYFLAGS="$KEYFLAGS --secret-keyring ../kernel.sec" 
	KEYFLAGS="$KEYFLAGS --keyring ../kernel.pub" 
	export KEYFLAGS 
    for i in ` find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f`
	do
		sh ./scripts/modsign/modsign.sh $i Red
        mv -f $i.signed $i
    done
	unset KEYFLAGS
%endif

    # mark modules executable so that strip-to-file can strip them
    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f  | xargs chmod u+x

    # detect missing or incorrect license tags
    for i in `find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" `
	do
		echo -n "$i " 
		/sbin/modinfo -l $i >> modinfo
	done
    cat modinfo |\
		grep -v "^GPL" |
		grep -v "^Dual BSD/GPL" |\
		grep -v "^Dual MPL/GPL" |\
		grep -v "^GPL and additional rights" |\
		grep -v "^GPL v2" && exit 1 
    rm -f modinfo
    # remove files that will be auto generated by depmod at rpm -i time
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.*
}

###
# DO it...
###

# prepare directories
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/boot

%if %{buildup}
BuildKernel
%endif

%if %{buildsmp}
BuildKernel smp
%endif

###
### install
###

%install

cd linux-%{kversion}

%if %{builddoc}
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}/Documentation

# sometimes non-world-readable files sneak into the kernel source tree
chmod -R a+r *
# copy the source over
tar cf - Documentation | tar xf - -C $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}
%endif

###
### clean
###

%clean
rm -rf $RPM_BUILD_ROOT

###
### scripts
###

# load the loop module for upgrades...in case the old modules get removed we have
# loopback in the kernel so that mkinitrd will work.
%pre 
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
exit 0

%pre smp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
exit 0

%post 
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --package kernel --mkinitrd --depmod --install %{KVERREL}

%post smp
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --package kernel-smp --mkinitrd --depmod --install %{KVERREL}smp

%preun 
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}

%preun smp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}smp

###
### file lists
###

%if %{buildup}
%files 
%defattr(-,root,root)
/%{image_install_path}/*-%{KVERREL}
/boot/System.map-%{KVERREL}
/boot/config-%{KVERREL}
%dir /lib/modules/%{KVERREL}
/lib/modules/%{KVERREL}/kernel
%verify(not mtime) /lib/modules/%{KVERREL}/build
%endif

%if %{buildsmp}
%files smp
%defattr(-,root,root)
/%{image_install_path}/*-%{KVERREL}smp
/boot/System.map-%{KVERREL}smp
/boot/config-%{KVERREL}smp
%dir /lib/modules/%{KVERREL}smp
/lib/modules/%{KVERREL}smp/kernel
/lib/modules/%{KVERREL}smp/build
/lib/modules/%{KVERREL}smp/source
%verify(not mtime) /lib/modules/%{KVERREL}smp/build
%endif

# only some architecture builds need kernel-doc

%if %{builddoc}
%files doc
%defattr(-,root,root)
%{_datadir}/doc/kernel-doc-%{kversion}/Documentation/*
%dir %{_datadir}/doc/kernel-doc-%{kversion}/Documentation
%dir %{_datadir}/doc/kernel-doc-%{kversion}
%endif

%changelog
* Sat Feb 18 2006 Marc Deslauriers <marcdeslauriers@videotron.ca> 2.6.12-2.3.legacy_FC3
- Corrected upstream reference in CVE-2006-0454 patch

* Thu Jul 03 2003 Arjan van de Ven <arjanv@redhat.com>
- 2.6 start

