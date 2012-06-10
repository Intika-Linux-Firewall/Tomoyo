Summary: The Linux kernel (the core of the Linux operating system)

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.

%define buildup 1
# Only used on archs without run-time support (ie ppc, sparc64)
%define buildsmp 0
%define buildpae 0
# Whether to apply the Xen patches, leave this enabled.
%define includexen 1
# Whether to build the Xen kernels, disable if you want.
%define buildxen 1
%define builddoc 0
%define buildkdump 1
%define buildheaders 0
%define builddebug 0

# Versions of various parts

# After branching, please hardcode these values as the
# %dist and %rhel tags are not reliable yet
# For example dist -> .el5 and rhel -> 5
#% define dist .XX
#% define rhel Y

#
# Polite request for people who spin their own kernel rpms:
# please modify the "release" field in a way that identifies
# that the kernel isn't the stock distribution kernel, for example by
# adding some text to the end of the version number.
#
%define sublevel 20
%define kversion 2.6.%{sublevel}
%define rpmversion 2.6.%{sublevel}
%define release %(R="$Revision: 1.2316 $"; RR="${R##: }"; echo ${RR%%?})%{?dist}.fc5_tomoyo_1.4.1
%define signmodules 0
%define xen_hv_cset 11774
%define make_target bzImage
%define kernel_image x86
%define xen_flags verbose=y crash_debug=y
%define xen_target vmlinuz
%define xen_image vmlinuz

%define KVERREL %{PACKAGE_VERSION}-%{PACKAGE_RELEASE}
%define hdrarch %_target_cpu

# groups of related archs
#OLPC stuff
%if 0%{?olpc}
%define buildxen 0
%define buildkdump 0
%endif
# Don't build 586 kernels for RHEL builds.
%if 0%{?rhel}
%define all_x86 i386 i686
# we differ here b/c of the reloc patches
%ifarch i686 x86_64
%define buildkdump 0
%endif
%else
%define all_x86 i386 i586 i686
%endif

# Override generic defaults with per-arch defaults

%ifarch noarch
%define builddoc 1
%define buildup 0
%define buildheaders 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-*.config
%endif

# Do debug builds on i686, x86_64
%ifarch i686 x86_64
%define builddebug 1
%endif

# kdump only builds on i686, x86_64, ppc64 ...
%ifnarch i686 x86_64 ppc64 ppc64iseries
%define buildkdump 0
%endif

# Xen only builds on i686, x86_64 and ia64 ...
%ifnarch i686 x86_64 ia64
%define buildxen 0
%endif

# Second, per-architecture exclusions (ifarch)

%ifarch ppc64iseries i686 i586
%define buildheaders 0
%endif

%ifarch %{all_x86}
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-i?86*.config
%define image_install_path boot
%define signmodules 1
%define hdrarch i386
%endif

%ifarch i586 i686
%define buildsmp 1
# we build always xen HV with pae
%define xen_flags verbose=y crash_debug=y pae=y
%endif

%ifarch x86_64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-x86_64*.config
%define image_install_path boot
%define signmodules 1
%endif

%ifarch ppc64 ppc64iseries
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc64*.config
%define image_install_path boot
%define signmodules 1
%define make_target vmlinux
%define kernel_image vmlinux
%define kernel_image_elf 1
%define hdrarch powerpc
%endif

%ifarch s390
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-s390*.config
%define image_install_path boot
%define make_target image
%define kernel_image arch/s390/boot/image
%endif

%ifarch s390x
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-s390x.config
%define image_install_path boot
%define make_target image
%define kernel_image arch/s390/boot/image
%define hdrarch s390
%endif

%ifarch sparc
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-sparc.config
%define make_target image
%define kernel_image image
%endif

%ifarch sparc64
%define buildsmp 1
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-sparc64*.config
%define make_target image
%define kernel_image image
%endif

%ifarch ppc
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc{-,.}*config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%define kernel_image_elf 1
%define buildsmp 1
%define hdrarch powerpc
%endif

%ifarch ia64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ia64*.config
%define image_install_path boot/efi/EFI/redhat
%define signmodules 1
%define make_target compressed
%define kernel_image vmlinux.gz
# ia64 xen HV doesn't building with debug=y at the moment
%define xen_flags verbose=y crash_debug=y
%define xen_target compressed
%define xen_image vmlinux.gz
%endif

# To temporarily exclude an architecture from being built, add it to
# %nobuildarches. Do _NOT_ use the ExclusiveArch: line, because if we
# don't build kernel-headers then the new build system will no longer let
# us use the previous build of that package -- it'll just be completely AWOL.
# Which is a BadThing(tm).

# We don't build a kernel on i386 or s390x -- we only do kernel-headers there.
# We also don't support s390, iseries and ia64 on Fedora.
%define nobuildarches i386 s390 s390x ppc64iseries ia64

%ifarch %nobuildarches
%define buildup 0
%define buildsmp 0
%define buildpae 0
%define buildxen 0
%define buildkdump 0
%define _enable_debug_packages 0
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
%define kernel_dot_org_conflicts  ppp < 2.4.3-3, isdn4k-utils < 3.2-32, nfs-utils < 1.0.7-12, e2fsprogs < 1.37-4, util-linux < 2.12, jfsutils < 1.1.7-2, reiserfs-utils < 3.6.19-2, xfsprogs < 2.6.13-4, procps < 3.2.5-6.3, oprofile < 0.9.1-2

#
# Then a series of requirements that are distribution specific, either
# because we add patches for something, or the older versions have
# problems with the newer kernel or lack certain things that make
# integration in the distro harder than needed.
#
%define package_conflicts kudzu < 1.2.5, initscripts < 7.23, udev < 063-6, iptables < 1.3.2-1, ipw2200-firmware < 2.4, selinux-policy-targeted < 1.25.3-14

#
# The ld.so.conf.d file we install uses syntax older ldconfig's don't grok.
#
%define xen_conflicts glibc < 2.3.5-1, xen < 3.0.1

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 4.2.21-1

Name: kernel
Group: System Environment/Kernel
License: GPLv2
Version: %{rpmversion}
Release: %{release}
%if 0%{?olpc}
ExclusiveArch: i386 i586
%else
# DO NOT CHANGE THIS LINE TO TEMPORARILY EXCLUDE AN ARCHITECTURE BUILD.
# SET %nobuildarches (ABOVE) INSTEAD
ExclusiveArch: noarch %{all_x86} x86_64 ppc ppc64 ppc64iseries ia64 sparc sparc64 s390 s390x
%endif
ExclusiveOS: Linux
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
# KMP - We need this for the moment
#AutoReqProv: no
AutoReqProv: yes


#
# List the packages used during the kernel build
#
BuildPreReq: module-init-tools, patch >= 2.5.4, bash >= 2.03, sh-utils, tar
BuildPreReq: bzip2, findutils, gzip, m4, perl, make >= 3.78, diffutils
%if %{signmodules}
BuildPreReq: gnupg
%endif
BuildRequires: gcc >= 3.4.2, binutils >= 2.12, redhat-rpm-config
%if %{buildheaders}
BuildRequires: unifdef
%endif
BuildConflicts: rhbuildsys(DiskFree) < 500Mb


Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-%{kversion}.tar.bz2
Source1: xen-3.0.3-%{xen_hv_cset}.tar.bz2
Source2: Config.mk

Source10: COPYING.modules
Source11: genkey
Source12: kabitool
Source14: find-provides
Source15: merge.pl

Source20: kernel-%{kversion}-i586.config
Source21: kernel-%{kversion}-i586-smp.config
Source22: kernel-%{kversion}-i686.config
Source23: kernel-%{kversion}-i686-debug.config
Source24: kernel-%{kversion}-i686-smp.config
Source25: kernel-%{kversion}-i686-smp-debug.config
Source26: kernel-%{kversion}-i686-kdump.config

Source27: kernel-%{kversion}-x86_64.config
Source28: kernel-%{kversion}-x86_64-debug.config
Source29: kernel-%{kversion}-x86_64-kdump.config

Source30: kernel-%{kversion}-ppc.config
Source31: kernel-%{kversion}-ppc-smp.config
Source32: kernel-%{kversion}-ppc64.config
Source33: kernel-%{kversion}-ppc64iseries.config
Source34: kernel-%{kversion}-ppc64-kdump.config

Source35: kernel-%{kversion}-s390.config
Source36: kernel-%{kversion}-s390x.config

Source37: kernel-%{kversion}-ia64.config

Source38: kernel-%{kversion}-i686-xen0.config
Source39: kernel-%{kversion}-i686-xenU.config
Source40: kernel-%{kversion}-i686-xen.config
Source41: kernel-%{kversion}-x86_64-xen0.config
Source42: kernel-%{kversion}-x86_64-xenU.config
Source43: kernel-%{kversion}-x86_64-xen.config

#Source66: kernel-%{kversion}-sparc.config
#Source67: kernel-%{kversion}-sparc64.config
#Source68: kernel-%{kversion}-sparc64-smp.config

#
# Patches 0 through 100 are meant for core subsystem upgrades
#
Patch1: patch-2.6.20.1.bz2
Patch2: patch-2.6.20.1-2.bz2
Patch3: patch-2.6.20.2-3.bz2
Patch4: patch-2.6.20.3-4.bz2
Patch5: patch-2.6.20.4-5.bz2
Patch6: patch-2.6.20.5-6.bz2
Patch7: patch-2.6.20.6-7.bz2
Patch8: patch-2.6.20.7-8.bz2
Patch9: patch-2.6.20.8-9.bz2
Patch10: linux-2.6.20.10-unoffical.patch

# Patches 10 through 99 are for things that are going upstream really soon.

# enable sysrq-c on all kernels, not only kexec
Patch70: linux-2.6-sysrq-c.patch

# Patches 100 through 500 are meant for architecture patches

# 200 - 299   x86(-64)

Patch200: linux-2.6-x86-tune-generic.patch
Patch201: linux-2.6-x86-vga-vidfail.patch
Patch202: linux-2.6-x86-64-edac-support.patch
Patch203: linux-2.6-x86_64-silence-up-apic-errors.patch
Patch204: linux-2.6-x86-apic-auto.patch
Patch205: linux-2.6-x86_64_edac_update.patch
Patch206: linux-2.6-20_x86_64_xapic_8_bit_dest.patch

# 300 - 399   ppc(64)
Patch301: linux-2.6-cell-mambo-drivers.patch
Patch302: linux-2.6-hvc-console.patch
Patch303: linux-2.6-ppc-rtas-check.patch
Patch310: linux-2.6-g5-therm-shutdown.patch
Patch311: linux-2.6-power6-no-ci-large-page.patch
Patch312: linux-2.6-mac-raid-autorun.patch

# 400 - 499   ia64

# 500 - 599   s390(x)

# 600 - 699   sparc(64)

#
# Patches 800 through 899 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#
Patch800: linux-2.6-build-nonintconfig.patch

# Exec-shield.
Patch810: linux-2.6-execshield.patch
Patch811: linux-2.6-warn-c-p-a.patch

# Module signing infrastructure.
Patch900: linux-2.6-modsign-mpilib.patch
Patch901: linux-2.6-modsign-crypto.patch
Patch902: linux-2.6-modsign-include.patch
Patch903: linux-2.6-modsign-verify.patch
Patch904: linux-2.6-modsign-ksign.patch
Patch905: linux-2.6-modsign-core.patch
Patch906: linux-2.6-modsign-script.patch

# Tux http accelerator.
Patch910: linux-2.6-tux.patch

# 950 - 999 Xen
Patch950: linux-2.6-xen.patch
Patch952: linux-2.6-xen-x86_64-silence-up-apic-errors.patch
Patch954: linux-2.6-xen-execshield.patch
Patch955: linux-2.6-xen-tux.patch
Patch961: linux-2.6-xen-pae-handle-64bit-addresses-correctly.patch

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#

Patch1010: linux-2.6-debug-sizeof-structs.patch
Patch1011: linux-2.6-debug-slab-backtrace.patch
Patch1013: linux-2.6-debug-taint-vm.patch
Patch1015: linux-2.6-debug-spinlock-taint.patch
Patch1016: linux-2.6-debug-Wundef.patch
Patch1018: linux-2.6-debug-sleep-in-irq-warning.patch
Patch1019: linux-2.6-debug-must_check.patch
Patch1020: linux-2.6-debug-no-quiet.patch
Patch1021: linux-2.6-debug-boot-delay.patch
Patch1022: linux-2.6-debug-sysfs-crash-debugging.patch
Patch1023: linux-2.6-debug-sysfs-crash-debugging-xen.patch

# Restrict /dev/mem usage.
Patch1050: linux-2.6-devmem.patch
Patch1051: linux-2.6-devmem-xen.patch

# Provide read only /dev/crash driver.
Patch1060: linux-2.6-crash-driver.patch
Patch1061: linux-2.6-crash-driver-xen.patch

Patch1070: linux-2.6-sleepon.patch

# SCSI bits.
Patch1106: linux-2.6-scsi-cpqarray-set-master.patch

# NFS bits.
Patch1201: linux-2.6-NFSD-badness.patch

# core networking changes.

# NIC driver fixes

# Filesystem stuff.
# Squashfs
Patch1400: linux-2.6-squashfs.patch

# GFS/DLM
Patch1410: linux-2.6-gfs2-update.patch
Patch1411: linux-2.6-gfs2-tux.patch
Patch1412: linux-2.6-gfs2-locking-exports.patch
Patch1413: linux-2.6-gfs2-update2.patch
Patch1414: linux-2.6-gfs2-update3.patch

# NFS superblock sharing / CacheFS
Patch1431: linux-2.6-cachefiles.patch

# Various NFS changes.

# Device mapper / MD layer

# Misc bits.
Patch1600: linux-2.6-module_version.patch
Patch1601: linux-2.6-sha_alignment.patch
Patch1650: linux-2.6-serial-460800.patch
Patch1681: linux-2.6-xfs-umount-fix.patch
Patch1682: linux-2.6-xfs_attr2.patch
Patch1690: linux-2.6-PT_LOAD-align.patch
Patch1720: linux-2.6-proc-self-maps-fix.patch
Patch1740: linux-2.6-softlockup-disable.patch
Patch1750: linux-2.6-usb-storage-reboot.patch
Patch1770: linux-2.6-optimise-spinlock-debug.patch
Patch1771: linux-2.6-silence-noise.patch
Patch1780: linux-2.6-drivers-add-qlogic-firmware.patch
Patch1781: linux-2.6-raid-autorun.patch
Patch1782: linux-2.6-drivers_pci_no_msi_mmconf.patch

# hold on to these
#Patch: linux-2.6-simplify_assign_irq_vector.patch
#Patch: linux-2.6-no_handler_for_vector_fix.patch

# 2.6.20 fixes for testing
Patch1790: linux-2.6-jfs_fix_deadlock.patch

# post 2.6.20.5
Patch1800: linux-2.6-20.5y-dm_crypt_disable_barriers.patch
Patch1802: linux-2.6-20.5z-mmap_dont_spam_logs.patch
Patch1805: linux-2.6-proposed-i82875p-edac-fix.patch
Patch1807: linux-2.6-20.7a-fib_rules_fix_return_value.patch
Patch1809: linux-2.6-21-rc6-readahead.patch
Patch1810: linux-2.6-i386_pci-add_debugging.patch

# SELinux/audit patches.
Patch1850: linux-2.6-selinux-mprotect-checks.patch

# Warn about usage of various obsolete functionality that may go away.
Patch1900: linux-2.6-obsolete-oss-warning.patch

# no external module should use these symbols.
Patch1910: linux-2.6-unexport-symbols.patch

# VM bits.
Patch2001: linux-2.6-vm-silence-atomic-alloc-failures.patch

# Tweak some defaults.
Patch2100: linux-2.6-defaults-fat-utf8.patch
Patch2101: linux-2.6-defaults-firmware-loader-timeout.patch
Patch2102: linux-2.6-defaults-phys-start.patch
Patch2103: linux-2.6-defaults-unicode-vt.patch
Patch2105: linux-2.6-defaults-nonmi.patch

# SATA Bits
Patch2200: linux-2.6-sata-promise-pata-ports.patch

# ACPI bits

#
# 10000 to 20000 is for stuff that has to come last due to the
# amount of drivers they touch. But only these should go here.
# Not patches you're too lazy for to put in the proper place.
#

Patch10000: linux-2.6-compile-fixes.patch

# Xen hypervisor patches (20000+)
Patch20000: xen-printf-rate-limit.patch
Patch20001: xen-version-strings.patch
Patch20002: xen-grant-security.patch
Patch20003: xen-amd-v-menu-timer-issue.patch
Patch20004: xen-pae-handle-64bit-addresses-correctly.patch
Patch20005: xen-fix-vcpu-hotplug-statistics.patch
Patch20007: xen-amd-v-hvm-fix-for-windows-hibernate.patch
Patch20008: xen-make-windows-vista-work.patch
Patch20011: xen-fix-swiotlb-for-b44-module-xen-patch.patch
Patch20012: xen-fix-for-smp-xen-guest-slow-boot-issue-on-amd-systems.patch
Patch20013: xen-hvm-crashes-on-ia32e-smp.patch
Patch20014: xen-make-ballooning-work-right.patch
Patch20015: xen-oprofile-on-intel-core.patch
Patch20016: xen-emulation-accesses-faulting-on-page-boundary.patch
Patch20018: xen-race-condition-concerning-vlapic-interrupts.patch
Patch20019: xen-emulate-pit-channels-for-vbios-support.patch
Patch20020: xen-greater-than-4g-guest-fix.patch
Patch20021: xen-make-hvm-hypercall-table-nr_hypercalls-entries-big.patch
Patch20022: xen-replace-inappropriate-domain_crash_synchronous-use.patch
Patch20023: xen-register-pit-handlers-to-the-correct-domain.patch
Patch20024: xen-quick-fix-for-cannot-allocate-memory.patch
Patch20025: xen-fix-tlb-flushing-in-shadow-pagetable-mode.patch
Patch20026: xen-enable-xen-booting-on-machines-with-64g.patch

Patch21008: linux-2.6-xen-fix-spinlock-when-removing-xennet-device.patch
Patch21011: linux-2.6-xen-privcmd-range-check-hypercall-index.patch
Patch21024: linux-2.6-xen-netback-reenable-tx-queueing.patch
Patch21027: linux-2.6-xen-avoid-touching-watchdog-when-gone-too-long.patch
Patch21036: linux-2.6-xen-iscsi-oops-on-x86_64-xen-domu.patch
Patch21038: linux-2.6-xen-make-netfront-device-permanent.patch
Patch21048: linux-2.6-xen-blkback-fix-first_sect-check.patch
Patch21056: linux-2.6-xen-fix-2tb-overflow-in-virtual-disk-driver.patch
Patch21059: linux-2.6-xen-netback-fix-transmit-credit-scheduler-wrap.patch
Patch21069: linux-2.6-xen-blkback-copy-shared-data-before-verification.patch
Patch21070: linux-2.6-xen-blkback-fix-potential-grant-entry-leaks-on-error.patch
Patch21081: linux-2.6-xen-properly-close-blkfront-on-non-existant-file.patch
Patch21087: linux-2.6-xen-copy-shared-data-before-verification.patch
Patch21104: linux-2.6-xen-fix-swiotlb-for-b44-module-kernel-patch.patch
Patch21112: linux-2.6-xen-make-ballooning-work-right.patch
Patch21147: linux-2.6-xen-fix-agp-on-x86_64-under-xen.patch
Patch21162: linux-2.6-xen-blktap-fix-potential-grant-entry-leaks-on-error.patch
Patch21165: linux-2.6-xen-use-swiotlb-mask-for-coherent-mappings-too.patch
Patch21188: linux-2.6-xen-fix-nosegneg-detection.patch
Patch21208: linux-2.6-xen-add-packet_auxdata-cmsg.patch

# END OF PATCH DEFINITIONS

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

%ifarch x86_64
Obsoletes: kernel-smp
%endif

%description
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

%if 0%{?olpc}
Provides: kmod-sysprof = 1.0.3
%endif

%package devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel = %{rpmversion}-%{release}
Prereq: /usr/bin/find
%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.


%package smp
Summary: The Linux kernel compiled for SMP machines.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}smp
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
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

%package smp-devel
Summary: Development package for building kernel modules to match the SMP kernel.
Group: System Environment/Kernel
Provides: kernel-smp-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}smp
Provides: kernel-devel = %{rpmversion}-%{release}smp
AutoReqProv: no
Prereq: /usr/bin/find
%description smp-devel
This package provides kernel headers and makefiles sufficient to build modules
against the SMP kernel package.

%package smp-debug
Summary: The SMP Linux kernel compiled with extra debugging enabled.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}smp-debug
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
AutoReq: no
AutoProv: yes
%description smp-debug
This package includes a SMP version of the Linux kernel. It is
required only on machines with two or more CPUs as well as machines with
hyperthreading technology.

Install the kernel-smp package if your machine uses two or more CPUs.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.

%package smp-debug-devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
Provides: kernel-smp-debug-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}smp-debug
Provides: kernel-devel = %{rpmversion}-%{release}smp-debug
AutoReqProv: no
Prereq: /usr/bin/find
%description smp-debug-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.


%package doc
Summary: Various documentation bits found in the kernel source.
Group: Documentation
%description doc
This package contains documentation files from the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files.

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.


%package debug
Summary: The Linux kernel compiled with extra debugging enabled.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}debug
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
AutoReq: no
AutoProv: yes
%description debug
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.

%package debug-devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
Provides: kernel-debug-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}debug
Provides: kernel-devel = %{rpmversion}-%{release}debug
AutoReqProv: no
Prereq: /usr/bin/find
%description debug-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.



%package xen0
Summary: The Linux kernel compiled for Xen guest0 VM operations
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}xen0
Prereq: %{kernel_prereq}
Requires: xen
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{xen_conflicts}
# the hypervisor kernel needs a newer mkinitrd than everything else right now
Conflicts: mkinitrd <= 4.2.0
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReqProv: no
%description xen0
This package includes a version of the Linux kernel which
runs in Xen's guest0 VM and provides device services to
the unprivileged guests.

Install this package in your Xen guest0 environment.

%package xen0-devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Provides: kernel-xen0-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}xen0
Provides: kernel-devel = %{rpmversion}-%{release}xen0
Prereq: /usr/bin/find
%description xen0-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.


%package xen
Summary: The Linux kernel compiled for Xen VM operations with PAE support
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}xen
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{xen_conflicts}
# the xen kernel needs a newer mkinitrd than everything else right now
Conflicts: mkinitrd <= 4.2.0
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReqProv: no
%description xen
This package includes a version of the Linux kernel which runs in
Xen's VM with PAE support and provides device services to the
unprivileged guests.

Install this package in your Xen guest0 environment.

%package xen-devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Provides: kernel-xen-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}xen
Provides: kernel-devel = %{rpmversion}-%{release}xen
Prereq: /usr/bin/find
%description xen-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.

%package xenU
Summary: The Linux kernel compiled for unprivileged Xen guest VMs
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}xenU
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{xen_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReqProv: no
%description xenU
This package includes a version of the Linux kernel which
runs in Xen unprivileged guest VMs.  This should be installed
both inside the unprivileged guest (for the modules) and in
the guest0 domain.

%package xenU-devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Provides: kernel-xenU-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}xenU
Provides: kernel-devel = %{rpmversion}-%{release}xenU
Prereq: /usr/bin/find
%description xenU-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.


%package kdump
Summary: A minimal Linux kernel compiled for kernel crash dumps.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}kdump
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReqProv: no
%description kdump
This package includes a kdump version of the Linux kernel. It is
required only on machines which will use the kexec-base kernel crash dump
mechanism.

%package kdump-devel
Summary: Development package for building kernel modules to match the kdump kernel.
Group: System Environment/Kernel
Provides: kernel-kdump-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}kdump
Provides: kernel-devel = %{rpmversion}-%{release}kdump
AutoReqProv: no
Prereq: /usr/bin/find
%description kdump-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kdump kernel package.

%prep
#if a rhel kernel, apply the rhel config options
%if 0%{?rhel}
  for i in %{all_arch_configs}
  do
    mv $i $i.tmp
    $RPM_SOURCE_DIR/merge.pl $RPM_SOURCE_DIR/config-rhel-generic $i.tmp > $i
    rm $i.tmp
  done
  for i in $RPM_SOURCE_DIR/kernel-%{kversion}-{i586,i686,i686-PAE,x86_64}*.config
  do
    echo i is this file  $i
    mv $i $i.tmp
    $RPM_SOURCE_DIR/merge.pl $RPM_SOURCE_DIR/config-rhel-x86-generic $i.tmp > $i
    rm $i.tmp
  done
%endif
#if a olpc kernel, apply the olpc config options
%if 0%{?olpc}
  for i in %{all_arch_configs}
  do
    mv $i $i.tmp
    $RPM_SOURCE_DIR/merge.pl $RPM_SOURCE_DIR/config-olpc-generic $i.tmp > $i
    rm $i.tmp
  done
%endif

# First we unpack the kernel tarball.
# If this isn't the first make prep, we use links to the existing clean tarball
# which speeds things up quite a bit.
if [ ! -d kernel-%{kversion}/vanilla ]; then
  # Ok, first time we do a make prep.
  rm -f pax_global_header
%setup -q -n %{name}-%{version} -c
  mv linux-%{kversion} vanilla
else
  # We already have a vanilla dir.
  cd kernel-%{kversion}
  if [ -d linux-%{kversion}.%{_target_cpu} ]; then
     # Just in case we ctrl-c'd a prep already
     rm -rf deleteme
     # Move away the stale away, and delete in background.
     mv linux-%{kversion}.%{_target_cpu} deleteme
     rm -rf deleteme &
  fi
fi
cp -rl vanilla linux-%{kversion}.%{_target_cpu}

cd linux-%{kversion}.%{_target_cpu}

# Update to latest upstream.
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1

# Patches 10 through 100 are meant for core subsystem upgrades

# sysrq works always
%patch70 -p1

# Architecture patches

#
# x86(-64)
#
# Compile 686 kernels tuned for Pentium4.
%patch200 -p1
# add vidfail capability;
# without this patch specifying a framebuffer on the kernel prompt would
# make the boot stop if there's no supported framebuffer device; this is bad
# for the installer cd that wants to automatically fall back to textmode
# in that case
%patch201 -p1
# EDAC support for K8
%patch202 -p1
# Suppress APIC errors on UP x86-64.
%patch203 -p1
# Use heuristics to determine whether to enable lapic on i386.
#%patch204 -p1
# K8 EDAC update for DDR2 and new CPUs
%patch205 -p1
# 8-bit dest field for xAPIC
%patch206 -p1

#
# PowerPC
#
# Support the IBM Mambo simulator; core as well as disk and network drivers.
#%patch301 -p1
# Make HVC console generic; support simulator console device using it.
#%patch302 -p1
# Check properly for successful RTAS instantiation
%patch303 -p1
# Alleviate G5 thermal shutdown problems
%patch310 -p1
# Disable cache-inhibited 64KiB pages on POWER6
#%patch311 -p1

# S390

#
# Patches 800 through 899 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#


# This patch adds a "make nonint_oldconfig" which is non-interactive and
# also gives a list of missing options at the end. Useful for automated
# builds (as used in the buildsystem).
%patch800 -p1

# Exec shield
%patch810 -p1
#%patch811 -p1

#
# GPG signed kernel modules
#
%patch900 -p1
%patch901 -p1
%patch902 -p1
%patch903 -p1
%patch904 -p1
%patch905 -p1
%patch906 -p1

# Tux
#%patch910 -p1

#
# Xen
#
%if %{includexen}
#
# Apply the main xen patch...
#%patch951 -p1
%patch950 -p1 -b .p.xen
#
# ... and back out all the tpm additions, they need fixing
#
for f in `find drivers/char/tpm -type f -name "*.p.xen"` ; do \
    g=`dirname $f`/`basename $f .p.xen`; \
    mv "$f" "$g"; \
    if [ ! -s "$g" ] ; then rm -f "$g" ; fi; \
done
# Delete the rest of the backup files, they just confuse the build later
find -name "*.p.xen" | xargs rm -f

%patch952 -p1
# Xen exec-shield bits
%patch954 -p1
%patch955 -p1
%patch961 -p1
%endif

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#


# Various low-impact patches to aid debugging.
%patch1010 -p1
%patch1011 -p1
%patch1013 -p1
%patch1015 -p1
%patch1016 -p1
%patch1018 -p1
%patch1019 -p1
# Disable the 'quiet' boot switch for better bug reports.
#%patch1020 -p1
%patch1021 -p1
%patch1022 -p1
%if %{includexen}
%patch1023 -p1
%endif

#
# Make /dev/mem a need-to-know function
#
%patch1050 -p1
%if %{includexen}
%patch1051 -p1
%endif

#
# /dev/crash driver for the crashdump analysis tool
#
%patch1060 -p1
%if %{includexen}
%patch1061 -p1
%endif

#
# Most^WAll users of sleep_on are broken; fix a bunch
#
%patch1070 -p1

#
# SCSI Bits.
#
# fix cpqarray pci enable
%patch1106 -p1

#
# Various NFS/NFSD fixes.
#
# Fix badness.
%patch1201 -p1

# core networking changes.

# NIC driver fixes

# Filesystem patches.
# Squashfs
%patch1400 -p1

# GFS2 fixes
%patch1410 -p1
# GFS2/DLM tux
#%patch1411 -p1
# GFS2/DLM locking exports
%patch1412 -p1
# additional gfs2 updates
%patch1413 -p1
%patch1414 -p1

#nfs sharing / cachefs
%patch1431 -p1

# NFS

# Device mapper / MD layer

# Misc fixes
# Add missing MODULE_VERSION tags to some modules.
%patch1600 -p1
# Fix SHA1 alignment problem on ia64
%patch1601 -p1
# Allow to use 480600 baud on 16C950 UARTs
%patch1650 -p1
# Fix XFS umount bug.
%patch1681 -p1
# Fix attr2 corruption with btree data extents
%patch1682 -p1
# Align kernel data segment to page boundary.
%patch1690 -p1
# setuid /proc/self/maps fix.
%patch1720 -p1
# Add a safety net to softlockup so that it doesn't prevent installs.
%patch1740 -p1
# USB storage not seen upon reboot
%patch1750 -p1
# Speed up spinlock debug.
%patch1770 -p1
# Silence some useless messages that still get printed with 'quiet'
%patch1771 -p1
# qlogic firmware
%patch1780 -p1
# restore START_ARRAY ioctl
%patch1781 -p1
# disable PCI MSI and MMCONFIG by default
%patch1782 -p1

# 2.6.20 test fixes
%patch1790 -p1

# post 2.6.20.6
%patch1800 -p1
%patch1802 -p1
%patch1805 -p1
%patch1807 -p1
%patch1809 -p1
%patch1810 -p1

# Fix the SELinux mprotect checks on executable mappings
%patch1850 -p1

# Warn about obsolete functionality usage.
%patch1900 -p1
# Remove kernel-internal functionality that nothing external should use.
%patch1910 -p1

#
# VM related fixes.
#
# Silence GFP_ATOMIC failures.
%patch2001 -p1

# Changes to upstream defaults.
# Use UTF-8 by default on VFAT.
%patch2100 -p1
# Increase timeout on firmware loader.
%patch2101 -p1
# Change PHYSICAL_START
%patch2102 -p1

# Use unicode VT's by default.
%patch2103 -p1
# Disable NMI watchdog by default.
%patch2105 -p1

# ACPI patches

# SATA
# PATA ports on Promise.
%patch2200 -p1

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

%patch21008 -p1
%patch21011 -p1
%patch21024 -p1
%patch21027 -p1
%patch21036 -p1
%patch21038 -p1
%patch21048 -p1
%patch21056 -p1
%patch21059 -p1
%patch21069 -p1
%patch21070 -p1
%patch21081 -p1
%patch21087 -p1
%patch21104 -p1
%patch21112 -p1
%patch21147 -p1
%patch21162 -p1
%patch21165 -p1
%patch21188 -p1
%patch21208 -p1

# TOMOYO Linux
tar -zxf $RPM_SOURCE_DIR/ccs-patch-1.4.1-20070605.tar.gz
sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -1.2316.fc5/" -- Makefile
patch -sp1 < ccs-patch-2.6.20-1.2316.fc5.txt

# END OF PATCH APPLICATIONS

cp %{SOURCE10} Documentation/

mkdir configs

cp -f %{all_arch_configs} .


%if 0%{?olpc}
# don't need these for OLPC
rm -f kernel-%{kversion}-*PAE*.config
rm -f kernel-%{kversion}-*xen*.config
rm -f kernel-%{kversion}-*kdump*.config
%endif

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

# If we don't have many patches to apply, sometimes the deleteme
# trick still hasn't completed, and things go bang at this point
# when find traverses into directories that get deleted.
# So we serialise until the dir has gone away.
cd ..
while [ -d deleteme ];
do
	sleep 1
done

# get rid of unwanted files resulting from patch fuzz
find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null


# Unpack the Xen tarball.
%if %{includexen}
cp %{SOURCE2} .
if [ -d xen ]; then
  rm -rf xen
fi
%setup -D -T -q -n %{name}-%{version} -a1
cd xen
# Any necessary hypervisor patches go here
%patch20000 -p1
%patch20001 -p1
%patch20002 -p1
%patch20003 -p1
%patch20004 -p1
%patch20005 -p1
%patch20007 -p1
%patch20008 -p1
%patch20011 -p1
%patch20012 -p1
%patch20013 -p1
%patch20014 -p1
%patch20015 -p1
%patch20016 -p1
%patch20018 -p1
%patch20019 -p1
%patch20020 -p1
%patch20021 -p1
%patch20022 -p1
%patch20023 -p1
%patch20024 -p1
%patch20025 -p1
%patch20026 -p1

# Update the Makefile version strings
sed -i -e 's/\(^export XEN_BUILDER.*$\)/\1'%{?dist}'/' Makefile
sed -i -e 's/\(^export XEN_BUILDVERSION.*$\)/\1'-%{PACKAGE_RELEASE}'/' Makefile
%endif


###
### build
###
%build
#
# Create gpg keys for signing the modules
#

%if %{signmodules}
gpg --homedir . --batch --gen-key %{SOURCE11}
gpg --homedir . --export --keyring ./kernel.pub Red > extract.pub
make linux-%{kversion}.%{_target_cpu}/scripts/bin2c
linux-%{kversion}.%{_target_cpu}/scripts/bin2c ksign_def_public_key __initdata < extract.pub > linux-%{kversion}.%{_target_cpu}/crypto/signature/key.h
%endif

BuildKernel() {
    MakeTarget=$1
    KernelImage=$2
    Flavour=$3

    # Pick the right config file for the kernel we're building
    if [ -n "$Flavour" ] ; then
      Config=kernel-%{kversion}-%{_target_cpu}-$Flavour.config
      DevelDir=/usr/src/kernels/%{KVERREL}-$Flavour-%{_target_cpu}
      DevelLink=/usr/src/kernels/%{KVERREL}$Flavour-%{_target_cpu}
    else
      Config=kernel-%{kversion}-%{_target_cpu}.config
      DevelDir=/usr/src/kernels/%{KVERREL}-%{_target_cpu}
      DevelLink=
    fi

    KernelVer=%{version}-%{release}$Flavour
    echo BUILDING A KERNEL FOR $Flavour %{_target_cpu}...

    # make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}$Flavour/" Makefile

    # and now to start the build process

    make -s mrproper
    cp configs/$Config .config

    Arch=`head -1 .config | cut -b 3-`
    echo USING ARCH=$Arch

    if [ "$KernelImage" == "x86" ]; then
       KernelImage=arch/$Arch/boot/bzImage
    fi

    make -s ARCH=$Arch nonint_oldconfig > /dev/null
    make -s ARCH=$Arch %{?_smp_mflags} $MakeTarget
    make -s ARCH=$Arch %{?_smp_mflags} modules || exit 1

    # Start installing the results

%if "%{_enable_debug_packages}" == "1"
    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/boot
    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/%{image_install_path}
%endif
    mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
    install -m 644 .config $RPM_BUILD_ROOT/boot/config-$KernelVer
    install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-$KernelVer
    touch $RPM_BUILD_ROOT/boot/initrd-$KernelVer.img
    cp $KernelImage $RPM_BUILD_ROOT/%{image_install_path}/vmlinuz-$KernelVer
    if [ -f arch/$Arch/boot/zImage.stub ]; then
      cp arch/$Arch/boot/zImage.stub $RPM_BUILD_ROOT/%{image_install_path}/zImage.stub-$KernelVer || :
    fi

    if [ "$Flavour" == "kdump" ]; then
        cp vmlinux $RPM_BUILD_ROOT/%{image_install_path}/vmlinux-$KernelVer
        rm -f $RPM_BUILD_ROOT/%{image_install_path}/vmlinuz-$KernelVer
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
    # dirs for additional modules per module-init-tools, kbuild/modules.txt
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/extra
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/updates
    # first copy everything
    cp --parents `find  -type f -name "Makefile*" -o -name "Kconfig*"` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
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
    cp -a acpi config keys linux math-emu media mtd net pcmcia rdma rxrpc scsi sound video asm asm-generic $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cp -a `readlink asm` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    if [ "$Arch" = "x86_64" ]; then
      cp -a asm-i386 $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    fi
    # While arch/powerpc/include/asm is still a symlink to the old
    # include/asm-ppc{64,} directory, include that in kernel-devel too.
    if [ "$Arch" = "powerpc" -a -r ../arch/powerpc/include/asm ]; then
      cp -a `readlink ../arch/powerpc/include/asm` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
      mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/$Arch/include
      pushd $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/$Arch/include
      ln -sf ../../../include/asm-ppc* asm
      popd
    fi
%if %{includexen}
    cp -a xen $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
%endif

    # Make sure the Makefile and version.h have a matching timestamp so that
    # external modules can be built
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/version.h
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/autoconf.h
    # Copy .config to include/config/auto.conf so "make prepare" is unnecessary.
    cp $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/config/auto.conf
    cd ..

    #
    # save the vmlinux file for kernel debugging into the kernel-debuginfo rpm
    #
%if "%{_enable_debug_packages}" == "1"
    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer
%endif

    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f >modnames

    # gpg sign the modules
%if %{signmodules}
    gcc -o scripts/modsign/mod-extract scripts/modsign/mod-extract.c -Wall
    KEYFLAGS="--no-default-keyring --homedir .."
    KEYFLAGS="$KEYFLAGS --secret-keyring ../kernel.sec"
    KEYFLAGS="$KEYFLAGS --keyring ../kernel.pub"
    export KEYFLAGS

    for i in `cat modnames`
    do
      sh ./scripts/modsign/modsign.sh $i Red
      mv -f $i.signed $i
    done
    unset KEYFLAGS
%endif
    # mark modules executable so that strip-to-file can strip them
    cat modnames | xargs chmod u+x

    # detect missing or incorrect license tags
    for i in `cat modnames`
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
    rm -f modnames
    # remove files that will be auto generated by depmod at rpm -i time
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.*

    # Move the devel headers out of the root file system
    mkdir -p $RPM_BUILD_ROOT/usr/src/kernels
    mv $RPM_BUILD_ROOT/lib/modules/$KernelVer/build $RPM_BUILD_ROOT/$DevelDir
    ln -sf ../../..$DevelDir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    [ -z "$DevelLink" ] || ln -sf `basename $DevelDir` $RPM_BUILD_ROOT/$DevelLink
}

###
# DO it...
###

# prepare directories
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/boot

%if %{includexen}
%if %{buildxen}
  cd xen
  mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
# FixMe: Juan Quintela (when no PAE is not needed anymore)
  make debug=y verbose=y crash_debug=y pae=y
  install -m 644 xen.gz $RPM_BUILD_ROOT/boot/xen.gz-%{KVERREL}-PAE
  install -m 755 xen-syms $RPM_BUILD_ROOT/boot/xen-syms-%{KVERREL}-PAE
  make clean
  make debug=y verbose=y crash_debug=y
  install -m 644 xen.gz $RPM_BUILD_ROOT/boot/xen.gz-%{KVERREL}
  install -m 755 xen-syms $RPM_BUILD_ROOT/boot/xen-syms-%{KVERREL}
  cd ..
%endif
%endif

cd linux-%{kversion}.%{_target_cpu}

%if %{builddebug}
BuildKernel %make_target %kernel_image debug
%endif

%if %{buildup}
BuildKernel %make_target %kernel_image
%endif

%if %{buildsmp}
BuildKernel %make_target %kernel_image smp
%if %{builddebug}
BuildKernel %make_target %kernel_image smp-debug
%endif
%endif

%if %{includexen}
%if %{buildxen}
BuildKernel %xen_target %xen_image xen
BuildKernel %xen_target %xen_image xen0
BuildKernel %xen_target %xen_image xenU
%endif
%endif

%if %{buildkdump}
BuildKernel %make_target %kernel_image kdump
%endif

###
### install
###

%install

cd linux-%{kversion}.%{_target_cpu}

%if %{includexen}
%if %{buildxen}
mkdir -p $RPM_BUILD_ROOT/etc/ld.so.conf.d
rm -f $RPM_BUILD_ROOT/etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf
cat > $RPM_BUILD_ROOT/etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf <<\EOF
# This directive teaches ldconfig to search in nosegneg subdirectories
# and cache the DSOs there with extra bit 0 set in their hwcap match
# fields.  In Xen guest kernels, the vDSO tells the dynamic linker to
# search in nosegneg subdirectories and to match this extra hwcap bit
# in the ld.so.cache file.
hwcap 0 nosegneg
EOF
chmod 444 $RPM_BUILD_ROOT/etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf
%endif
%endif

%if %{builddoc}
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}/Documentation

# sometimes non-world-readable files sneak into the kernel source tree
chmod -R a+r *
# copy the source over
tar cf - Documentation | tar xf - -C $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}
%endif

%if %{buildheaders}
# Install kernel headers
make ARCH=%{hdrarch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_install

# Manually go through the 'headers_check' process for every file, but
# don't die if it fails
chmod +x scripts/hdrcheck.sh
echo -e '*****\n*****\nHEADER EXPORT WARNINGS:\n*****' > hdrwarnings.txt
for FILE in `find $RPM_BUILD_ROOT/usr/include` ; do
    scripts/hdrcheck.sh $RPM_BUILD_ROOT/usr/include $FILE /dev/null >> hdrwarnings.txt || :
done
echo -e '*****\n*****' >> hdrwarnings.txt
if grep -q exist hdrwarnings.txt; then
   sed s:^$RPM_BUILD_ROOT/usr/include/:: hdrwarnings.txt
   # Temporarily cause a build failure if header inconsistencies.
   # exit 1
fi

# glibc provides scsi headers for itself, for now
rm -rf $RPM_BUILD_ROOT/usr/include/scsi
rm -f $RPM_BUILD_ROOT/usr/include/asm*/atomic.h
rm -f $RPM_BUILD_ROOT/usr/include/asm*/io.h
rm -f $RPM_BUILD_ROOT/usr/include/asm*/irq.h
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
if [ `uname -i` == "x86_64" ]; then
  if [ -f /etc/sysconfig/kernel ]; then
    /bin/sed -i -e 's/^DEFAULTKERNEL=kernel-smp$/DEFAULTKERNEL=kernel/' /etc/sysconfig/kernel
  fi
fi
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade %{rpmversion}-%{release}
/sbin/new-kernel-pkg --package kernel --mkinitrd --depmod --install %{KVERREL}

%post devel
[ -f /etc/sysconfig/kernel ] && . /etc/sysconfig/kernel
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post smp
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade %{rpmversion}-%{release}smp
/sbin/new-kernel-pkg --package kernel-smp --mkinitrd --depmod --install %{KVERREL}smp

%post smp-devel
[ -f /etc/sysconfig/kernel ] && . /etc/sysconfig/kernel
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post smp-debug
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade %{rpmversion}-%{release}smp-debug
/sbin/new-kernel-pkg --package kernel-smp-debug --mkinitrd --depmod --install %{KVERREL}smp-debug

%post xen0
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade %{rpmversion}-%{release}-xen0
/sbin/new-kernel-pkg --package kernel-xen0 --mkinitrd --depmod --install --multiboot=/boot/xen.gz-%{KVERREL} %{KVERREL}xen0
[ ! -x /sbin/ldconfig ] || /sbin/ldconfig -X

%post xen0-devel
[ -f /etc/sysconfig/kernel ] && . /etc/sysconfig/kernel
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-xen0-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post xenU
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade %{rpmversion}-%{release}-xenU
/sbin/new-kernel-pkg --package kernel-xenU --mkinitrd --depmod --install %{KVERREL}xenU
[ ! -x /sbin/ldconfig ] || /sbin/ldconfig -X

%post xenU-devel
[ -f /etc/sysconfig/kernel ] && . /etc/sysconfig/kernel
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-xenU-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post xen
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade %{rpmversion}-%{release}-xen
if [ -e /proc/xen/xsd_kva -o ! -d /proc/xen ]; then 
	/sbin/new-kernel-pkg --package kernel-xen --mkinitrd --depmod --install --multiboot=/boot/xen.gz-%{KVERREL}-PAE %{KVERREL}xen
else 
	/sbin/new-kernel-pkg --package kernel-xen --mkinitrd --depmod --install %{KVERREL}xen
fi
[ ! -x /sbin/ldconfig ] || /sbin/ldconfig -X

%post xen-devel
[ -f /etc/sysconfig/kernel ] && . /etc/sysconfig/kernel
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-xen-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post kdump
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade %{rpmversion}-%{release}-kdump
/sbin/new-kernel-pkg --package kernel-kdump --mkinitrd --depmod --install %{KVERREL}kdump

%post kdump-devel
[ -f /etc/sysconfig/kernel ] && . /etc/sysconfig/kernel
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-kdump-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post debug
/sbin/new-kernel-pkg --package kernel-debug --mkinitrd --depmod --install %{KVERREL}debug || exit $?


%preun
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}

%preun smp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}smp

%preun smp-debug
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}smp-debug

%preun kdump
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}kdump

%preun debug
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}debug || exit $?

%preun xen0
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}xen0

%preun xenU
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}xenU

%preun xen
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}xen


###
### file lists
###

%if %{buildup}

%files 
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}
/boot/System.map-%{KVERREL}
/boot/config-%{KVERREL}
%dir /lib/modules/%{KVERREL}
/lib/modules/%{KVERREL}/kernel
/lib/modules/%{KVERREL}/build
/lib/modules/%{KVERREL}/source
/lib/modules/%{KVERREL}/extra
/lib/modules/%{KVERREL}/updates
%ghost /boot/initrd-%{KVERREL}.img

%files devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-%{_target_cpu}

%if %{builddebug}

%files debug
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}debug
/boot/System.map-%{KVERREL}debug
/boot/config-%{KVERREL}debug
%dir /lib/modules/%{KVERREL}debug
/lib/modules/%{KVERREL}debug/kernel
/lib/modules/%{KVERREL}debug/build
/lib/modules/%{KVERREL}debug/source
/lib/modules/%{KVERREL}debug/extra
/lib/modules/%{KVERREL}debug/updates
%ghost /boot/initrd-%{KVERREL}debug.img

%files debug-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-debug-%{_target_cpu}
/usr/src/kernels/%{KVERREL}debug-%{_target_cpu}

%endif
#builddebug

%endif
# buildup

%if %{buildsmp}

%files smp
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}smp
/boot/System.map-%{KVERREL}smp
/boot/config-%{KVERREL}smp
%dir /lib/modules/%{KVERREL}smp
/lib/modules/%{KVERREL}smp/kernel
/lib/modules/%{KVERREL}smp/build
/lib/modules/%{KVERREL}smp/source
/lib/modules/%{KVERREL}smp/extra
/lib/modules/%{KVERREL}smp/updates
%ghost /boot/initrd-%{KVERREL}smp.img

%files smp-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu}
/usr/src/kernels/%{KVERREL}smp-%{_target_cpu}

%if %{builddebug}

%files smp-debug
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}smp-debug
/boot/System.map-%{KVERREL}smp-debug
/boot/config-%{KVERREL}smp-debug
%dir /lib/modules/%{KVERREL}smp-debug
/lib/modules/%{KVERREL}smp-debug/kernel
/lib/modules/%{KVERREL}smp-debug/build
/lib/modules/%{KVERREL}smp-debug/source
/lib/modules/%{KVERREL}smp-debug/extra
/lib/modules/%{KVERREL}smp-debug/updates
%ghost /boot/initrd-%{KVERREL}smp-debug.img

%files smp-debug-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-smp-debug-%{_target_cpu}
/usr/src/kernels/%{KVERREL}smp-debug-%{_target_cpu}

%endif
# builddebug

%endif
# buildsmp

%if %{includexen}
%if %{buildxen}
%files xen0
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}xen0
/boot/System.map-%{KVERREL}xen0
/boot/config-%{KVERREL}xen0
/boot/xen.gz-%{KVERREL}
/boot/xen-syms-%{KVERREL}
%dir /lib/modules/%{KVERREL}xen0
/lib/modules/%{KVERREL}xen0/kernel
%verify(not mtime) /lib/modules/%{KVERREL}xen0/build
/lib/modules/%{KVERREL}xen0/source
/etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf
/lib/modules/%{KVERREL}xen0/extra
/lib/modules/%{KVERREL}xen0/updates
%ghost /boot/initrd-%{KVERREL}xen0.img

%files xen0-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-xen0-%{_target_cpu}
/usr/src/kernels/%{KVERREL}xen0-%{_target_cpu}

%files xenU
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}xenU
/boot/System.map-%{KVERREL}xenU
/boot/config-%{KVERREL}xenU
%dir /lib/modules/%{KVERREL}xenU
/lib/modules/%{KVERREL}xenU/kernel
%verify(not mtime) /lib/modules/%{KVERREL}xenU/build
/lib/modules/%{KVERREL}xenU/source
/etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf
/lib/modules/%{KVERREL}xenU/extra
/lib/modules/%{KVERREL}xenU/updates
%ghost /boot/initrd-%{KVERREL}xenU.img

%files xenU-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-xenU-%{_target_cpu}
/usr/src/kernels/%{KVERREL}xenU-%{_target_cpu}

%files xen
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}xen
/boot/System.map-%{KVERREL}xen
/boot/config-%{KVERREL}xen
/boot/xen.gz-%{KVERREL}-PAE
/boot/xen-syms-%{KVERREL}-PAE
%dir /lib/modules/%{KVERREL}xen
/lib/modules/%{KVERREL}xen/kernel
%verify(not mtime) /lib/modules/%{KVERREL}xen/build
/lib/modules/%{KVERREL}xen/source
/etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf
/lib/modules/%{KVERREL}xen/extra
/lib/modules/%{KVERREL}xen/updates
%ghost /boot/initrd-%{KVERREL}xen.img

%files xen-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-xen-%{_target_cpu}
/usr/src/kernels/%{KVERREL}xen-%{_target_cpu}

%endif
%endif

%if %{buildkdump}

%files kdump
%defattr(-,root,root)
/%{image_install_path}/vmlinux-%{KVERREL}kdump
/boot/System.map-%{KVERREL}kdump
/boot/config-%{KVERREL}kdump
%dir /lib/modules/%{KVERREL}kdump
/lib/modules/%{KVERREL}kdump/kernel
/lib/modules/%{KVERREL}kdump/build
/lib/modules/%{KVERREL}kdump/source
/lib/modules/%{KVERREL}kdump/extra
/lib/modules/%{KVERREL}kdump/updates
%ghost /boot/initrd-%{KVERREL}kdump.img

%files kdump-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-kdump-%{_target_cpu}
/usr/src/kernels/%{KVERREL}kdump-%{_target_cpu}
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
* Fri Apr 27 2007 Chuck Ebbert <cebbert@redhat.com>		1.2316
- 2.6.20.10 (from mailing list)

* Tue Mar 14 2006 Dave Jones <davej@redhat.com>
- FC5 final kernel
- 2.6.16-rc6-git3

