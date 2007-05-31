Summary: The Linux kernel (the core of the Linux operating system)

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows and
# no contrary --with/--without arguments are given on the command line.

%define buildup 1
%define buildsmp 1
%define buildBOOT 1
%define buildbigmem 1
%define buildjensen 0




# Versions of various parts

#
# Polite request for people who spin their own kernel rpms:
# please modify the "release" field in a way that identifies
# that the kernel isn't the stock RHL kernel, for example by
# adding some text to the end of the version number.
#
%define release 46.9.legacy_tomoyo_1.4.1
%define sublevel 20
%define kversion 2.4.%{sublevel}
# /usr/src/%{kslnk} -> /usr/src/linux-%{KVERREL}
%define kslnk linux-2.4

# groups of related archs
%define all_x86 i386 i686 i586 athlon
#define all_x86 i686 i386 i586 athlon

%define nptlarchs %{all_x86}
#define nptlarchs noarch

# disable build root strip policy
%define __spec_install_post /usr/lib/rpm/brp-compress || :
#
# RPM foo magic
%define _missing_doc_files_terminate_build    0
%define _unpackaged_files_terminate_build 0
%define debug_package %{nil}

# Enable this to build a board-specific kernel configuration 
# some architectures have LOTS of different setups and this 
# is a way to deal with that cleanly.
#
#define targetboard assabet
%define dashtargetboard %{?targetboard:-%{targetboard}}
%define withtargetboard 0
%{?targetboard: %{expand: %%define withtargetboard 1}}
	
# Override generic defaults with per-arch defaults (which can
# themselves be overridden with --with/--without).  These must
# ONLY be "0", never "1"

# First, architecture-specific kernels off on all other archs (ifnarch)
%ifnarch i686
%define buildbigmem 0
%endif
%ifnarch alpha
# jensen kernel, only for alpha.  Old, broken broken alpha.
%define buildjensen 0
%endif
%ifnarch i386 alpha 
%define buildBOOT 0
%endif
# For board-specific kernels, build only the normal kernel (which may actually be smp, not up).
%if %{withtargetboard}
%define buildsmp 0
%define buildBOOT 0
%define buildbigmem 0
%define buildjensen 0
%endif

# Second, per-architecture exclusions (ifarch)
%ifarch i386
%define buildsmp 0
%define buildup 1
%endif
%ifarch i586
%define buildsmp 1
%endif
%ifarch ia64
%define buildBOOT 0
%endif


# we can't test values inline, only whether a macro exists
%{expand: %%define buildup_%{buildup} yadda}
%{expand: %%define buildsmp_%{buildsmp} yadda}
%{expand: %%define buildBOOT_%{buildBOOT} yadda}
%{expand: %%define buildbigmem_%{buildbigmem} yadda}
%{expand: %%define buildjensen_%{buildjensen} yadda}
%{expand: %%define ikd_%{ikd} yadda}
%{expand: %%define ibcs_%{ibcs} yadda}
%{expand: %%define debuglevel_%{debugging} yadda}

%{expand: %%define kernel_conflicts  ppp <= 2.3.15, pcmcia-cs <= 3.1.20, isdn4k-utils <= 3.0, mount < 2.10r-5, nfs-utils < 0.3.1, cipe < 1.4.5, tux < 2.1.0, kudzu <= 0.92, e2fsprogs < 1.22, initscripts < 5.84, dev < 3.2-7, iptables < 1.2.5-3, bcm5820 < 1.81, nvidia-rh72 <= 1.0, oprofile < 0.4}


%define BOOT_kernel_prereq fileutils, modutils >=  2.4.18
%define kernel_prereq %{BOOT_kernel_prereq}, initscripts >= 5.83, mkinitrd >= 3.2.6
%ifarch ia64
%define initrd_dir /boot/efi/redhat
%else
%define initrd_dir /boot
%endif

%ifarch %{all_x86} x86_64
%define kernel_glob vmlinu?-%{KVERREL}
%endif
%ifarch ia64
# <sigh>, no GLOB_BRACE for filelists, efi needs to be done separately
%define kernel_glob vmlinuz-%{KVERREL}
%endif
%ifarch alpha
%define kernel_glob vmlinu?-%{KVERREL}
%endif

Name: kernel
Version: %{kversion}
Release: %{release}%{?targetboard:%{targetboard}}%{?debuglevel_1:.dbg}
%define KVERREL %{PACKAGE_VERSION}-%{PACKAGE_RELEASE}
License: GPL
Group: System Environment/Kernel
ExclusiveArch: %{all_x86}
ExclusiveOS: Linux
Obsoletes: kernel-modules, kernel-sparc
Provides: module-info, kernel = %{version}
# BuildProvides: rhbuildsys(ParallelBuild) <= 8
BuildConflicts: rhbuildsys(DiskFree) < 500Mb
%ifarch %{all_x86} ia64 x86_64
Provides: kernel-drm = 4.1.0, kernel-drm = 4.2.0, kernel-drm = 4.3.0, kernel-drm = 4.2.99.3
%endif
Autoreqprov: no
Prereq: %{kernel_prereq}
Conflicts: %{kernel_conflicts}

BuildPreReq: patch >= 2.5.4, bash >= 2.03, sh-utils, gnupg, tar
BuildPreReq: bzip2, findutils, dev, gzip, m4


BuildRequires: gcc >= 2.96-98

Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.4/linux-%{kversion}.tar.bz2

Source10: COPYING.modules
Source11: module-info
Source14: kernel-2.4-BuildASM.sh
Source15: linux-rhconfig.h
Source16: linux-merge-config.awk
Source17: linux-merge-modules.awk
Source18: genkey
Source19: device.awk

Source20: kernel-%{kversion}-i386.config
Source21: kernel-%{kversion}-i386-smp.config
Source22: kernel-%{kversion}-i386-BOOT.config
Source23: kernel-%{kversion}-alpha.config
Source24: kernel-%{kversion}-alpha-smp.config
Source25: kernel-%{kversion}-sparc.config
Source26: kernel-%{kversion}-sparc-smp.config
Source27: kernel-%{kversion}-sparc64.config
Source28: kernel-%{kversion}-sparc64-smp.config
Source29: kernel-%{kversion}-i686.config
Source30: kernel-%{kversion}-i686-smp.config
Source31: kernel-%{kversion}-alpha-BOOT.config
Source32: kernel-%{kversion}-sparc-BOOT.config
Source33: kernel-%{kversion}-sparc64-BOOT.config
Source34: kernel-%{kversion}-i586.config
Source35: kernel-%{kversion}-i586-smp.config
# since there are no space issues, a -BOOT is rather pointless
Source36: kernel-%{kversion}-ia64.config
Source37: kernel-%{kversion}-ia64-smp.config
Source38: kernel-%{kversion}-i686-bigmem.config
Source40: kernel-%{kversion}-athlon.config
Source41: kernel-%{kversion}-athlon-smp.config
Source42: kernel-%{kversion}-alpha-jensen.config
Source47: kernel-%{kversion}-ia64-BOOT.config
Source48: kernel-%{kversion}-x86_64.config
Source49: kernel-%{kversion}-x86_64-smp.config
Source50: installkernel.iSeries
Source51: installcmdline.iSeries

# the following is for embedded systems where the %{targetboard} variable
# is set
%if %{withtargetboard}
####Source70: kernel-%{kversion}-%{_target_cpu}-%{targetboard}.config
%endif

####Source80: linux-2.4.7-ikd.patch

#
# Patches 0 through 100 are meant for core subsystem upgrades
#

Patch1: patch-2.4.21-pre3.bz2
Patch2: linux-2.4.20-selected-ac-bits.patch
Patch3: linux-2.4.18-unselected-ac-bits.patch
Patch4: linux-2.4.18-noramfs.patch
Patch5: linux-2.4.20-later-ac-updates.patch

# 
# Patches 100 through 400 are architecture specific patches
# Each architecture has 20 slots reserved.
#

# IA64


# Alpha


# Sparc / Sparc64

# x86

Patch200: linux-2.4.20-amd-golem.patch
Patch201: linux-2.4.26-nvidia.nforce2.patch

# X86-64 is 220 - 239

Patch219: linux-2.4.20-x86_64-updates.patch
Patch220: linux-2.4.20-x86_64.patch
Patch221: linux-2.4.20-x86_64-fixes.patch

# arm

# sh

# mips


#
# Patches 400 through 599 are the TUX patches
#

Patch400: linux-2.4.15-tux2.patch


#
# Patches 600 through 1000 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#

Patch600: linux-2.4.0-nonintconfig.patch
Patch611: linux-2.4.18-cpu-partitioning.patch
Patch620: linux-2.4.18-flock.patch
Patch630: linux-2.4.7-quotareturn.patch
Patch640: linux-2.2.16-rhconfig.patch
Patch650: linux-2.4.2-changeloop.patch
Patch651: linux-2.4.18-loopfixes.patch
Patch660: linux-2.4.20-edd.patch
Patch661: linux-2.4.20-edd-allocate.patch
Patch670: linux-2.4.20-modulealloc.patch
Patch680: linux-2.4.20-intel-acpi-safe-update.patch
Patch681: linux-2.4.20-acpi-relaxed-aml.patch
Patch682: linux-2.4.20-acpi-fixes.patch
Patch690: linux-2.4.20-ldt.patch
Patch700: linux-2.4.2-scsi_scan.patch
Patch720: linux-2.4.9-kksymoops.patch
Patch721: linux-2.4.9-kallsyms.patch
Patch750: linux-2.4.19-vmacache.patch
Patch760: linux-2.4.20-swapoff-match.patch
Patch800: linux-2.4.20-vmplayground.patch
Patch801: linux-2.4.20-pagereferenced.patch
Patch802: linux-2.4.20-statm.patch
Patch803: linux-2.4.20-rmap15c.patch
Patch804: linux-2.4.20-additional-vm-tuning.patch
Patch805: linux-2.4.20-inodes.patch
Patch806: linux-2.4.20-elevator.patch
Patch807: linux-2.4.20-rmap-updates.patch
Patch808: linux-2.4.20-launder_page-pagecount-race.patch
Patch809: linux-2.4.21-repnop-barrier.patch
Patch810: linux-2.4.21-atomic-pageflags.patch
Patch811: linux-2.4.20-vmbackports.patch

Patch850: linux-2.4.18-dmi-hall-of-shame.patch
Patch860: linux-2.4.20-440gx.patch
Patch880: linux-2.4.18-sendfile64.patch
Patch890: linux-2.4.18-laptopbits.patch
Patch900: linux-2.4.20-oopsmeharder.patch
Patch910: linux-2.4.20-iptREJECTfix.patch
Patch911: linux-2.4.20-conntrack-fix.patch
Patch920: linux-2.4.21-wait-kbd-disable.patch
Patch930: linux-2.4.20-bonding-noip.patch
Patch940: linux-2.4.22-kmod.patch
Patch950: linux-2.4.25pre-selected-bits.patch
Patch960: linux-2.4.26pre-selected-bits.patch
Patch970: linux-2.4.25pre-selected-patches.legacy.patch
Patch980: linux-2.4.26pre-selected-patches.legacy.patch
Patch990: linux-2.4.27pre-fix-x86-clear_fpu-macro.patch
Patch991: linux-2.4.27pre-nfs-fchown.patch

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#

Patch1000: linux-2.4.18-nousb.patch
Patch1010: linux-2.4.20-silraid.patch
Patch1030: linux-2.4.0-test11-vidfail.patch
Patch1040: linux-2.4.0-e820.patch
Patch1050: linux-2.4.0-raid5xor.patch
Patch1060: linux-2.4.20-orinoco.patch
Patch1070: linux-2.4.2-page_bitmap.patch
Patch1080: linux-2.4.0-apic-quiet.patch
Patch1090: linux-2.4.20-irixnfs.patch
Patch1100: linux-2.4.3-pcipenalty.patch
Patch1110: linux-2.4.7-usb-bug50218.patch
Patch1120: linux-2.4.2-keyboardsilence.patch
Patch1130: linux-2.4.20-pwcupdate.patch
Patch1140: linux-2.4.20-lowlat.patch
Patch1150: linux-2.4.20-cpufreq.patch
Patch1151: linux-2.4.20-cpufreq.sec.patch
Patch1170: linux-2.4.7-scsitimeout.patch
Patch1180: linux-2.4.9-freevxfs.patch
Patch1190: linux-2.4.20-drm43.patch
Patch1200: linux-2.4.9-nmiprofiling.patch
Patch1210: linux-2.4.18-moreunnamed.patch
Patch1240: linux-2.4.17-usb-55878.patch
Patch1250: linux-2.4.20-lvm-updates.patch
Patch1251: linux-2.4.17-lvm-bulkcopy.patch
Patch1252: linux-2.4.17-lvm-pvmove.patch
Patch1253: linux-2.4.20-mempool.patch
Patch1255: linux-2.4.18-lvm-VFSlock.patch
Patch1261: linux-2.4.18-input-35215.patch
Patch1270: linux-2.4.9-pcmcia-ethtool.patch
Patch1271: linux-2.4.18-ethtool.patch
Patch1280: linux-2.4.20-speakup.patch
Patch1300: linux-2.4.20-odirect.patch
Patch1310: linux-2.4.20-stackcoloring.patch
Patch1330: linux-2.4.18-scsi-whitelist.patch
Patch1340: linux-2.4.9-scsilun0.patch
Patch1350: linux-2.4.18-netdump.patch
Patch1360: linux-2.4.20-cenatek.patch
Patch1370: linux-2.4.20-serverworks.patch
Patch1380: linux-2.4.9-fstat.patch
Patch1390: linux-2.4.18-irixnfs.patch
Patch1391: linux-2.4.18-nfs-default-size.patch
Patch1392: linux-2.4.23-03-fix_osx.dif
Patch1410: linux-2.4.20-sbp2-smpfixes.patch
Patch1420: linux-2.4.7-suspend.patch
Patch1450: linux-2.4.18-orinoco.patch
Patch1560: linux-2.4.18-scsidevices.patch
Patch1580: linux-2.4.18-sillysymlinkfarms.patch
Patch1590: linux-2.4.20-bluetooth.patch
Patch1600: linux-2.4.20-nethashfix.patch
Patch1610: linux-2.4.20-32bitemu.patch
Patch1620: linux-2.4.18-kiobuf.patch
Patch2300: linux-2.4.9-ide-tape.patch
Patch2310: linux-2.4.18-usb-bug56856.patch
Patch2320: linux-2.4.18-usb-bug50225.patch
Patch2330: linux-2.4.20-usb-bug81091.patch
Patch2340: linux-2.4.20-usb-bug82546.patch
Patch2350: linux-2.4.20-usb-bug72604.patch
Patch2360: linux-2.4.20-usb-bug84814.patch
Patch2361: linux-2.4.20-usb-bug84814bis.patch
Patch2380: linux-2.4.17-watchdog-nowayout.patch
Patch2400: linux-2.4.18-feral-qlogic-isp.patch
Patch2410: linux-2.4.9-feral-qlogic-isp-config.patch
Patch2420: linux-2.4.18-gericom.patch
Patch2430: linux-2.4.20-oprofile.patch
Patch2431: linux-2.4.20-hyperthreading-oprofile.patch
Patch2432: linux-2.4.20-oprofile-hammer.patch
Patch2450: linux-2.4.20-pre1-nr_frags.patch
Patch2460: linux-2.4.20-andrea-fix-pausing.patch
Patch2470: linux-2.4.20-xattr-ext3.patch
Patch2471: linux-2.4.20-xattr-mbcache.patch
Patch2480: linux-2.4.20-acl.patch
Patch2481: linux-2.4.20-acl-intermezzo-fix.patch
Patch2485: linux-2.4.20-acl-xattr.patch
Patch2487: linux-2.4.20-acl-ext3.patch
Patch2488: linux-2.4.20-acl-ms-posixacl.patch
Patch2490: linux-2.4.20-ext3-updates.patch
Patch2500: linux-2.4.20-siimage-fixes.patch
Patch2510: linux-2.4.20-ide-dma-timeout.patch
Patch2520: linux-2.4.22-audio.patch
Patch2530: linux-2.4.22-ide.patch
Patch2540: linux-2.4.23-icmp6-socket-contention-bug.patch
Patch2550: linux-2.4.22-i2c-fixes.patch
Patch2560: linux-2.4.20-rtcleak.patch
Patch2570: linux-misc-viro-fixes.patch
Patch2580: linux-2.4.27pre-e1000-fix.patch
Patch2590: linux-usb-sparse.patch
Patch2595: linux-2.4.20-CAN-2004-1056-drm_lock.patch
Patch2600: linux-2.4.29-CAN-2004-0814-tty_ldisc.patch
Patch2601: linux-2.4.29-CAN-2004-0814-tty_ldisc-nptl.patch
Patch2605: linux-2.4.20-elf-loader-setuid.patch
Patch2610: linux-2.4.20-smbfs-overflows.patch
Patch2615: linux-2.4.20-CAN-2004-1074-aout-leak.patch
Patch2620: linux-2.4.20-nfsd-signed.patch
Patch2625: linux-2.4.20-nfsd-xdr-write-wrap.patch
Patch2630: linux-2.4.20-CAN-2004-1016-cmsg.patch
Patch2635: linux-2.4.20-CAN-2004-1068-dgram_recvmsg.patch
Patch2640: linux-2.4.20-ip-options-leak.patch
Patch2645: linux-2.4.26-CAN-2004-1234-binfmt_elf.patch
Patch2650: linux-2.4.21-CAN-2004-1017-io_edgeport.patch
Patch2655: linux-2.4.20-CAN-2004-1058-proc_pid_cmdline_race.patch
Patch2660: linux-2.4.20-CAN-2004-1333-vtresize.patch
Patch2665: linux-2.4.20-CAN-2005-0384-pppd_dos.patch
Patch2670: linux-2.4.20-CAN-2005-0400-ext2_mkdir_leak.patch
Patch2675: linux-2.4.20-ipfrag-flush.patch
Patch2680: linux-2.4.20-CAN-2005-0504-moxa_rawio.patch
Patch2685: linux-2.4.20-CAN-2005-0749-elf_dos.patch
Patch2690: linux-2.4.20-CAN-2005-0750-bluetooth.patch
Patch2695: linux-2.4.20-CAN-2005-0815-isofs_range_flaw.patch

#
# Patches 5000 to 5800 are reserved for new drivers
#
Patch5000: linux-2.4.9-addon.patch
Patch5010: linux-2.4.18-megarac.patch
Patch5020: linux-2.4.20-ipmi.patch
Patch5030: linux-2.4.18-wvlan-cs.patch
Patch5050: linux-2.4.18-ecc.patch
Patch5090: linux-2.4.6-bcm5820.patch
Patch5091: linux-2.4.6-bcm5820-2.patch
Patch5092: linux-2.4.7-bcm5820-16.patch
Patch5093: linux-2.4.7-bcm5820-17.patch
Patch5094: linux-2.4.18-bcm5820-update.patch
Patch5120: linux-2.4.18-iscsi.patch
Patch5180: linux-2.4.7-tulip.patch
Patch5190: linux-2.4.0-cipe-1.4.5.patch
Patch5191: linux-2.4.2-cipe.patch
Patch5192: linux-2.4.9-cipenat.patch
Patch5193: linux-2.4.18-cipe-moreinterfaces.patch
Patch5200: linux-2.4.20-lm_sensors.patch
Patch5210: linux-2.4.9-qla2200.patch
Patch5220: linux-2.4.9-aep.patch
Patch5240: linux-2.4.18-aic79xx.patch
Patch5250: linux-2.4.18-afs.patch
Patch5260: linux-2.4.18-loop-cryptoapi.patch
Patch5261: linux-2.4.18-cryptoapi.patch
Patch5270: linux-2.4.18-audigy.patch


#
# Patches 5800 to 6000 are the HA/IPVS patches
#

#
# Patches 6000 and later are reserved for %if {something} patches
#



# debugging

Patch7000: linux-2.4.18-mmap-sem-debug.patch
Patch7001: linux-2.4.18-mmap-sem-debug-i386.patch
Patch7010: linux-2.4.18-gfp-valid.patch


#
# 10000 to 20000 is for stuff that has to come last due to the
# amount of drivers they touch. But only theese should go here. 
# Not patches you're too lazy for to put in the proper place.
#

# file offset handling fixes
Patch10000: linux-2.4.21-file-offset-fixes.patch
Patch10001: linux-RHEL-missing-fixes.patch

# fix a lot of warnings in the plain kernel and previous patches
Patch10010: linux-2.4.1-compilefailure.patch

# several small tweaks not worth their own patch
Patch10020: linux-2.4.18-smallpatches.patch

# add missing MODULE_LICENSE() tags
Patch10030: linux-2.4.18-missing-license-tags.patch

# threading backport and O(1) scheduler backport; last because they need to
# be ifarch'd and touch a lot of code
Patch11000: linux-2.4.20-o1-sched+threading-backport.patch
Patch11001: linux-2.4.20-noresched.patch
Patch11002: linux-2.4.20-futex-debug.patch
Patch11003: linux-2.4.20-softlockup.patch
Patch11004: linux-2.4.20-ptrace.patch
Patch11005: linux-2.4.22-security-nptl.patch
Patch11006: linux-2.4.20-ntpl-signal-delivery-fix.patch
Patch11030: linux-2.4.20-noscheduler.patch
Patch11031: linux-2.4.20-ptrace-hammer.patch
Patch11032: linux-2.4.22-security.patch
Patch11033: linux-fork_c_cleanup_mm.patch

# Fedora Legacy security patches
Patch11034: linux-2.4.29-rc1-sys_uselib-race-CAN-2004-1235.patch
Patch11035: 2.4.29_expand_stack.patch
Patch11036: linux-2.4.22-CVE-2004-0791.patch
Patch11037: linux-2.4.22-CVE-2005-1263.patch
Patch11038: linux-2.4.21-CAN-2005-2458.patch
Patch11039: linux-2.4.22-CVE-2005-2490.patch
Patch11040: linux-2.4.20-CVE-2005-2708.patch
Patch11041: linux-2.4.21-sysctl-unregister.patch
Patch11042: linux-2.4.22-CVE-2005-2973.patch
Patch11043: linux-2.4.22-CVE-2005-3180.patch
Patch11044: linux-2.4.22-CVE-2005-3275.patch
Patch11045: linux-2.4.22-CVE-2005-3276.patch
Patch11046: linux-2.6.9-CVE-2005-3806-ip6-flowlabel-dos.patch
Patch11047: linux-2.6.9-CVE-2005-3857-printk-dos.patch
Patch11048: linux-2.4.29-CVE-2005-0124.patch
Patch11049: linux-2.4.29-CVE-2005-3273.patch
Patch11050: linux-2.4.20-CVE-2002-2185.patch

# END OF PATCH DEFINITIONS

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

%package source
Summary: The source code for the Linux kernel.
Group: Development/System
Prereq: fileutils
Requires: gawk
Requires: gcc >= 2.96-98

%package doc
Summary: Various documentation bits found in the kernel source.
Group: Documentation

%description 
The kernel package contains the Linux kernel (vmlinuz), the core of your
Red Hat Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

%description source
The kernel-source package contains the source code files for the Linux
kernel. These source files are needed to build custom/third party device
drivers. The source files can also be used to build a custom kernel that is
better tuned to your particular hardware, if you are so inclined (and you
know what you're doing).

%description doc
This package contains documentation files form the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files. 

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.

%package smp
Summary: The Linux kernel compiled for SMP machines.
Group: System Environment/Kernel
Provides: module-info, kernel = %{version}
%ifarch %{all_x86} ia64 x86_64
Provides: kernel-drm = 4.1.0, kernel-drm = 4.2.0, kernel-drm = 4.3.0, kernel-drm = 4.2.99.3
%endif
Prereq: %{kernel_prereq}
Conflicts: %{kernel_conflicts}

%description smp
This package includes a SMP version of the Linux kernel. It is
required only on machines with two or more CPUs, although it should
work fine on single-CPU boxes.

Install the kernel-smp package if your machine uses two or more CPUs.

%package bigmem
Summary: The Linux Kernel for machines with more than 4 Gigabyte of memory.
Group: System Environment/Kernel
Provides: module-info, kernel = %{version}
%ifarch %{all_x86} ia64 x86_64
Provides: kernel-drm = 4.1.0, kernel-drm = 4.2.0, kernel-drm = 4.3.0, kernel-drm = 4.2.99.3
%endif
Prereq: %{kernel_prereq}
Conflicts: %{kernel_conflicts}
Obsoletes: kernel-enterprise <= 2.4.10


%description bigmem
This package includes a kernel that has appropriate configuration options
enabled for Pentium III machines with 4 Gigabyte of memory or more.

%package BOOT
Summary: The version of the Linux kernel used on installation boot disks.
Group: System Environment/Kernel
Provides: kernel = %{version}
Prereq: %{BOOT_kernel_prereq}
Conflicts: %{kernel_conflicts}

%description BOOT
This package includes a trimmed down version of the Linux kernel.
This kernel is used on the installation boot disks only and should not
be used for an installed system, as many features in this kernel are
turned off because of the size constraints.

%package BOOTsmp
Summary: The Linux kernel used on installation boot disks for SMP machines.
Group: System Environment/Kernel
Provides: kernel = %{version}
Prereq: %{BOOT_kernel_prereq}
Conflicts: %{kernel_conflicts}

%description BOOTsmp
This package includes a trimmed down version of the Linux kernel. This
kernel is used on the installation boot disks only and should not be used
for an installed system, as many features in this kernel are turned off
because of the size constraints. This kernel is used when booting SMP
machines that have trouble coming up to life with the uniprocessor kernel.

%package jensen
Summary: The Linux Kernel compiled for the Alpha Jensen platform.
Group: System Environment/Kernel
Provides: kernel = %{version}
Prereq: %{kernel_prereq}
Conflicts: %{kernel_conflicts}

%description jensen
This package includes a kernel that has appropriate configuration
options enabled for use on the Alpha Jensen platform.  The Jensen
platform is not supported in the normal generic alpha kernel support.

%prep

%setup -q -n %{name}-%{version} -c
cd linux-%{version}

#
# Patches 0 through 100 are meant for core subsystem upgrades
# 

# update to 2.4.20-ac1
%patch1 -p1
%patch2 -p1
# and the bits we don't want removed again
%patch4 -p1
%patch5 -p1

#
# User Mode Linux
# The original patch is copied (mostly) intact from Jeff's SF site,
# because he keeps changing it and we want to track that.
#
# %patch6 -p1
# %patch7 -p1

# 
# Patches 100 through 400 are architecture specific patches
# Each architecture has 20 slots reserved.
#

# IA64

# Alpha

# Sparc / Sparc64


# x86
# fix for AMD x86-64 APIC issue running x86 kernels
%patch200 -p1
# Fixup for C1 Halt Disconnect problem on nForce2 systems.
%patch201 -p1

#
# X86-64
#
%patch219 -p1
%patch220 -p1
%patch221 -p1

# arm

# mips

#
# Patches 400 through 500 are the TUX patches
#

%patch400 -p1



#
# Patches 600 through 1000 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#


# This patch adds a "make oldconfig_nonint" which is non-interactive and
# also gives a list of missing options at the end. Useful for automated
# builds (as used in the Red Hat buildsystem).
%patch600 -p1

#
# Allow PAM to limit certain users to certain cpu's.
#
# %patch611 -p1

#
# flock() accounting is broken; disable for 2.4 kernels
#
%patch620 -p1

# tty_write_message needs \r\n -- makes quota messages look nicer
%patch630 -p1
#
# Make "make oldconfig" smarter and have it use the config file for the
# currently running kernel as default.
#
%patch640 -p1
# Al Viro's loopback patch 
%patch650 -p1
%patch651 -p1


#
# Backport of the 2.5 EDD feature to find the boot device (used for lilo
# etc)
#
%patch660 -p1
%patch661 -p1

#
# Allocate modules not with vmalloc to reduce tlb usage
#
# %patch670 -p1
# FIXME

#
# ACPI
#
# %patch680 -p1
# %patch681 -p1
# %patch682 -p1

#
# Optimize LDT allocation to allow > 1200 threaded processes
# (Manfred Spraul; backport from 2.5)
#
%patch690 -p1

# fix lun probing on multilun RAID chassis
%patch700 -p1

#
# kksymoops - automatically decode oopses/backtraces from within the kernel
%patch720 -p1
%ifarch %{all_x86}  x86_64
%patch721 -p1
%endif

#
# One shot vma hole patch from Ingo
#
# %patch750 -p1

#
# Fix swapoff not to require the exact same dentry you used to swapon
#
%patch760 -p1


#
# update the list of vendors who can't program a bios
#
%patch850 -p1
#
# the 440GX bioses deserve a special nomination in this area
#
%patch860 -p1



# add sendfile64 from 2.5
%patch880 -p1

#
# add some laptop power consumption improvements
#
%patch890 -p1

#
# Fix netfilter --reject-with tcp-reset
#
%patch910 -p1

#
# Drop reference to conntrack after removing confirmed expectation.
#
%patch911 -p1

#
# Wait for keyboard controller to drain before sending disable
#
%patch920 -p1

#
# Fix bonding on interfaces with no IP address
#
%patch930 -p1

# Clear all flags in exec_usermodehelper
%patch940 -p1

# Various fixes from 2.4.25/26pre/27pre
%patch950 -p1
%patch960 -p1
%patch970 -p1
%patch980 -p1

# Local DoS fix in clear_fpu macro
%patch990 -p1

# Fix NFS fchown bug
%patch991 -p1

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#

#
# Add a "nousb" kernel option to disable all USB loading. On some older
# machines and ACPI-only boxes trying to use ANY usb crashes the machine.
# Bug #66760.
#
%patch1000 -p1

#
# Add support for the Silicon Image(tm) Medley(tm) raid
#
%patch1010 -p1

# add vidfail capability; 
# without this patch specifying a framebuffer on the kernel prompt would
# make the boot stop if there's no supported framebuffer device; this is bad
# for the installer floppy that wants to automatically fall back to textmode
# in that case
%patch1030 -p1
#
# add e820 reporting in /proc; needed for anaconda to find out which
# kernels to install
#
%patch1040 -p1
# raid5 xor fix for PIII/P4, should go away shortly
%patch1050 -p1

#
# Update orinoco driver to 0.13a version; this fixed the "BAP" problem
# fix broken; patch disabled
# %patch1060 -p1

# conservative zone bitmaps to prevent potential memory corruption
%patch1070 -p1
#
# Silence the APIC errors a bit; they are harmless mostly and can happen
# in normal use.
#
%patch1080 -p1

#
# NFS patch fron trond:
# A patch that papers over a glibc bug. In glibc-2.2 and above, they use
# the new getdents64() syscall even for the 32-bit readdir. As a result, they
# have problems coping with the unsigned 64-bit d_off values that may get
# returned by some NFSv3 servers.
# NOTE: You might still have to set the '32bitclients' export option on
# some IRIX servers.

%patch1090 -p1

#
# change IRQ penalty for IRQ 12
# This tries to avoid assigning cardbus irq's to irq12 which is "special"
# for certain laptops that emulate PS/2 hardware via SMM mode.
#
%patch1100 -p1
#
# Silence the PS/2 code for USB keyboards
# It's not uncommon to have no PS/2 keyboard these days
#
%patch1120 -p1

#
# downgrade the pwc webcam driver to a working version
#
%patch1130 -p1

#
# Andrew Morton's low latency patch
#
%patch1140 -p1

#
# CPUFREQ: speedstep(tm) and powernow(tm) support
#
%patch1150 -p1
%patch1151 -p1

#
# make the scsi timeout longer; 30 seconds is too short for big raid arrays
# with lots of large concurrent requests in flight
#
%patch1170 -p1
#
# make freevxfs autoload when doing mount -t vxfs /dev/foo /mnt/bar
#
%patch1180 -p1

#
# DRM update
#
%patch1190 -p1

#
# use the nmi interrupt for profiling; this allows the kernel profiler
# to profile even with interrupts disabled. Note: you have to specify the
# nmi watchdog now as well for profiling to work:
# vmlinuz profile=1 nmi_watchdog=1
#
%patch1200 -p1
#
# allow more unnamed mounts by borrowing old, unused major devices
# This is needed if you want more than 255 NFS mounts; some people use the
# "one mount per user" automount setup and they need this if they have more
# than 255 users.
#
%patch1210 -p1


#
# LVM updates:
#
# add important bugfixes from Sistina's LVM-1.0.3
%patch1250 -p1
# Add bulk-copy-via-kiobufs code
%patch1251 -p1
# Add locked copy-and-remap pvmove code
%patch1252 -p1
# Add mempool code
%patch1253 -p1
#
# LVM atomic snapshot patch: quiesce the filesystem automatically when
# taking snapshots.
%patch1255 -p1
#
# Gamepad (all kbds and mice were affected, but we kludged arount it in hplug)
# autoload the proper modules
%patch1261 -p1
#
# add ethtool ioctl support to more network drivers
#
#%patch1270 -p1
#%patch1271 -p1

#
# Speakup: braille terminal things
#
# %patch1280 -p1

#
# change O_DIRECT handling
#
%patch1300 -p1


#
# Improve CPU cache efficiency by coloring the cachelines of the userspace
# stack
#
%patch1310 -p1

#
# add some devices to the scsi whitelist for multi-lun scanning
#
# %patch1330 -p1
#
# allow ioctls to lun0 even if there's no lun0 (needed for some FC kit)
#
%patch1340 -p1

#
# Netdump / Netconsole - crashdumps and kernel messages over
# the network via a lightweight UDP stack that can run with interrupts
# disabled
#
%patch1350 -p1

#
# add cenatek PCI ID's to the ide layer
#
%patch1360 -p1

# 
# Disable an advanced serverworks chipset feature because it interacts
#
%patch1370 -p1

# some broken and defective applications assume that they can fstat() on a
# pipe and meaningful interpret the value of i_size. Apparently the
# arbitrary value 2.2 put there was good enough so we try to emulate that,
# since we prefer to keep compatibility within the RHL 7.x series. This is
# a gross hack that will go away as soon as possible.
#
%patch1380 -p1
#
# IRIX seems to return 64 bit cookies for readdir. glibc uses the 64 bit
# getdents even for 32 bit readdir and then the 64 bit cookies goes awol.
# Work around this by truncating/rounding this in the kernel
#
### %patch1390 -p1
### FIXME ####
#
# NFS mounts with the default [rw]size on 2.4.18 pick up the server's max 
# size, which for some (32768) is far too large.  Instead, use the client's
# default size at 4096 if it was unspecified and the server's is larger.
#
%patch1391 -p1
#

# this fixes the nfs cookie handling to allow over 8-byte cookies
# needed for support of osx 10.3 and freebsd.
%patch1392 -p1

#
# Fix some firewire deadlocks (fixes from upstream maintainter)
#
%patch1410 -p1

# 
# Some bioses "forget" to restore pci config space properly on resume;
# the following patch helps them a bit with this
#
%patch1420 -p1

#
# Older orinoco_cs patch that fixes some laptops
#
%patch1450 -p1

#
# O_Profile
#
# %patch1480 -p1

#
# Make use of all of the 256 scsi devices available
#
%patch1560 -p1

#
# Some people build symlink farms where a symlink points to a link points to
# a link points...
# In order to avoid stack overflows, the kernel cuts of at 5 recursions.
# However some people think they need more, for those people there is
# now a stack=overflowmeharder option.
#
%patch1580 -p1

#
# Bluetooth updates
#
%patch1590 -p1

#
# Fix the remote hash attack in the TCP/IP layer
#
%patch1600 -p1

#
# fix the 32 bit emulation layer for amd64
#
%patch1610 -p1

#
# Don't overly waste memory in the rawio code
#
%patch1620 -p1

# ide-tape bites back (bugs 36628, 62267)
# %patch2300 -p1
# yay alan merged it

# 56856 - SDDR-31 media check
%patch2310 -p1
# 50225 - ALi in IBM i1200
# Alan took an earlier version. Works for us too, but let's keep the slot.
#%patch2320 -p1
# 81091 - Installation BUGs when unmounting usbdevfs (workaround)
%patch2330 -p1
# 82546 - Yukihiro's pet, will disappear eventually
%patch2340 -p1
# 72604 - Work around broken Olympus cameras
%patch2350 -p1
# 84814 - usb-ohci and its utterly broken locking
%patch2360 -p1
# 96984 - little regression for 84814 related to ADSL modems
%patch2361 -p1

# feral qlogic driver patches
%patch2400 -p1
%patch2410 -p1

#
# Laptop battery monitor improvements for Gericom / Advent 7006 laptops
#
%patch2420 -p1

# oprofile backport from 2.5

%patch2430 -p1
%patch2431 -p1
%patch2432 -p1

# fix setting of nr_frags on memory allocation in the network stack
%patch2450 -p1

#
# Andrea Arcangeli's fix for a nasty stall bug
#

%patch2460 -p1

#Added Extended Attributes to extfs
# %patch2470 -p1
# %patch2471 -p1

# Added ACLs
# %patch2480 -p1
# %patch2481 -p1
# %patch2485 -p1
# %patch2487 -p1
# %patch2488 -p1

# Misc ext3 bug-fixes
%patch2490 -p1

#
# Silicon Image IDE driver bugfix for machines >= 4Gb ram
#
%patch2500 -p1

#
# Attempt to fix DMA timeout problem (#97356)
#
%patch2510 -p1

#
# Sound updates
#
%patch2520 -p1

#
# IDE updates
#
%patch2530 -p1

#
# icmp6 socket contention bugfix
#
%patch2540 -p1

# Fix memory deref's in i2c ioctl & memory leak.
%patch2550 -p1

# Don't leak data in RTC IOCTLs.
%patch2560 -p1

# Misc userspace pointer reference bug fixes
%patch2570 -p1
  
# e1000 information leak
%patch2580 -p1

# usb sparse fixes
%patch2590 -p1

# drm lock fixes
%patch2595 -p1

# smbfs overfow fixes
%patch2610 -p1

# CAN-2004-1074 aout fixes
%patch2615 -p1

# NFS fixes
%patch2620 -p1
%patch2625 -p1

# CAN-2004-1016 cmsg validation fixes
%patch2630 -p1

# CAN-2004-1068 dgram_recvmsg patch
%patch2635 -p1

# fix ip options leakage
%patch2640 -p1

# CAN-2004-1234 elf loader patch
%patch2645 -p1

# edgeport driver patch
%patch2650 -p1

# proc_pid_cmdline race fix
%patch2655 -p1

# vtresize patch
%patch2660 -p1

# pppd remote DoS patch
%patch2665 -p1

# ext2 mkdir leak patch
%patch2670 -p1

# ipfrag flush patch
%patch2675 -p1

# moxy CAP_SYS_RAWIO patch
%patch2680 -p1

# load_elf_library DoS patch
%patch2685 -p2

# bluetooth patch
%patch2690 -p1

# isofs range checking flaw
%patch2695 -p1

#
# Patches 5000 to 6000 are reserved for new drivers
#
# generic drivers/addon infrastructure
%patch5000 -p1
# (ugly) driver for the Dell megarac remote access cards
%patch5010 -p1

# The linux IPMI driver
%patch5020 -p1

# Broadcom BCM5700/5701 Gigabit driver 
# wvlan_cs driver
%patch5030 -p1
# ECC reporting module
%patch5050 -p1
# Disable Broadcom driver at least until there is a proper fix
## Broadcom 5820 driver
#%patch5090 -p1
#%patch5091 -p1
#%patch5092 -p1
#%patch5093 -p1
#%patch5094 -p1

# iSCSI driver, and fix
%patch5120 -p1

# add tulip_old driver (2.4.3 version)
%patch5180 -p1
# cipe 1.4.5
%patch5190 -p1
%patch5191 -p1
%patch5192 -p1
%patch5193 -p1
# LM-Sensors 2.6.5
%patch5200 -p1
# qla2x00
%patch5210 -p1
# AEP SSL Accelerator card
%patch5220 -p1
# aic79xx driver
%patch5240 -p1
#
# preliminary snapshot of a new AFS client
#
%patch5250 -p1

#
# Patches 5800 to 6000 are the HA/IPVS patches
#


#
# Patches 6000 and later are reserved for %if {something} patches
#

#
# Patches to support AES loop device
#
%patch5260 -p1
%patch5261 -p1

#
# Soundblaster Live! Audigy driver
#
%patch5270 -p1

#
# debug mmap semaphore recursion deadlocks
# by keeping track of who owns what

#%patch7000 -p1
#%ifarch %{all_x86}
#%patch7001 -p1
#%endif


#
# Catch "bogus" GFP_XXXX allocation flags; those result in 
# otherwise hard to debug bugs
#
#%patch7010 -p1



#
# final stuff
#

# file offset handling fixes
%patch10000 -p1
# lots of RHEL patches we were missing before
%patch10001 -p1 

#
# lots of small fixes to warnings and other silly bugs
#
%patch10010 -p1

# several small tweaks
%patch10020 -p1

# 
# Add MODULE_LICENSE() to the modules missing it
#
%patch10030 -p1

#
# VM Tuning: rmap15b
#

%ifnarch x86_64
%patch800 -p1 
%patch801 -p1
%patch802 -p1
#
# Make "top" more efficient
#
#
# rmap15c update
# 
%patch803 -p1
# launder_page race (bug 100739)
%patch808 -p1
# barrier for rep_nop (bug 102133)
%patch809 -p1
# Atomic update of page->flags
%patch810 -p1

#
# some tweaks
#

%endif

%patch11001 -p1
%patch805 -p1
#
# akpm's elevator tuning
#
%patch806 -p1

%ifarch %{nptlarchs}
# O(1) scheduler
# threading backport:
%patch11000 -p1
# %patch11002 -p1
# %patch11003 -p1
%patch11004 -p1
%patch11005 -p1
# (bug 100439)
%patch11006 -p1
%patch804 -p1
# NPTL Fix for terminal layer races
%patch2601 -p1
%patch11045 -p2
%else
%patch11030 -p1
%patch11031 -p1
%patch11032 -p1
%patch11033 -p1
# 811 is a non-NPTL version of patch 804
%patch811 -p1
# Fix for terminal layer races
%patch2600 -p1
%endif
# elf-loader-setuid patch
%patch2605 -p1
# update -rmap VM to the latest
%patch807 -p1

# x86-64.. when done needs to move to the right place
# %patch220 -p1

#CAN-2004-1235 patch
%patch11034 -p1
#expand_stack patch
%patch11035 -p1
%patch11036 -p1
%patch11037 -p2
%patch11038 -p1
%patch11039 -p2
%patch11040 -p2
%patch11041 -p1
%patch11042 -p2
%patch11043 -p2
%patch11044 -p2
%patch11046 -p1
%patch11047 -p1
%patch11048 -p1
%patch11049 -p1
%patch11050 -p2

# TOMOYO Linux
tar -zxf %_sourcedir/ccs-patch-1.4.1-20070605.tar.gz
sed -i -e "s/^SUBLEVEL.*/SUBLEVEL = 20/" -e "s/^EXTRAVERSION.*/EXTRAVERSION = -46.9.legacycustom/" -- Makefile
patch -sp1 < ccs-patch-2.4.20-46.9.legacy.txt

# END OF PATCH APPLICATIONS

cp %{SOURCE10} Documentation/
chmod +x arch/sparc*/kernel/check_asm.sh

mkdir configs
%ifarch %{all_x86} x86_64
cp -fv $RPM_SOURCE_DIR/kernel-%{kversion}-i?86*.config configs
cp -fv $RPM_SOURCE_DIR/kernel-%{kversion}-athlon*.config configs
cp -fv $RPM_SOURCE_DIR/kernel-%{kversion}-x86_64*.config configs
%else
%ifarch sparc sparc64
cp -fv $RPM_SOURCE_DIR/kernel-%{kversion}-sparc*.config configs
%else
cp -fv $RPM_SOURCE_DIR/kernel-%{kversion}-%{_target_cpu}*.config configs
%endif
%endif

# make sure the kernel has the sublevel we know it has...
perl -p -i -e "s/^SUBLEVEL.*/SUBLEVEL = %{sublevel}/" Makefile

# get rid of unwanted files
find . -name "*.orig" -exec rm -fv {} \;
find . -name "*~" -exec rm -fv {} \;

chmod 755 arch/*/kernel/check_asm.sh

###
### build
###
%build

# if RPM_BUILD_NCPUS unset, set it
if [ -z "$RPM_BUILD_NCPUS" ] ; then
    RPM_BUILD_NCPUS=`egrep -c "^cpu[0-9]+" /proc/stat || :` 
    if [ $RPM_BUILD_NCPUS -eq 0 ] ; then
	RPM_BUILD_NCPUS=1
    fi
    if [ $RPM_BUILD_NCPUS -gt 8 ] ; then
	RPM_BUILD_NCPUS=8
    fi
fi


cd linux-%{version}

cat > genkey <<EOF
%pubring `pwd`/kernel.pub
%secring `pwd`/kernel.sec
Key-Type: DSA
Key-Length: 512
Name-Real: Red Hat, Inc.
Name-Comment: Kernel Module GPG key
%commit
EOF

AddPatches () {
    # $1 is BOOT/bigmem/debug/foo
    case "$1" in
    debug) patch -p1 < $RPM_SOURCE_DIR/linux-2.4.7-ikd.patch ;;
    esac
    # remove any backup files that were created
    find . -name "*.orig" -exec rm -fv {} \;
    find . -name "*~" -exec rm -fv {} \;
}

RemovePatches () {
    # $1 is BOOT/bigmem/debug/foo
    case "$1" in
    debug) patch -p1 -R < $RPM_SOURCE_DIR/linux-2.4.7-ikd.patch ;;
    esac
    # remove any backup files that were created
    find . -name "*.orig" -exec rm -fv {} \;
    find . -name "*~" -exec rm -fv {} \;
}

DependKernel() {
    # is this a special kernel we want to build?
    if [ -n "$2" ] ; then
	Config=$1-$2
	KernelVer=%{version}-%{release}$2
	echo MAKE DEPEND FOR $2 $1 KERNEL...
    else
	Config=$1%{dashtargetboard}
	KernelVer=%{version}-%{release}
	echo MAKE DEPEND FOR up $1 KERNEL...
    fi
    make -s mrproper
# We used to copy the config file to arch/.../defconfig, but for some time now
# the Configure script has been smart enough to override this with the
# config file found in configs/kernel-%{kversion}-${config}.config when it
# finds a valid /boot/kernel.h file.  As a result, making an RPM on a
# machine that has a valid kernel.h file will result in scripts/Configure
# overriding our config entries with whatever it thinks is appropriate
# (aka, if you try an i386 build on a machine with an i686 smp kernel.h file
# then you will get an i686 smp kernel in an i386 package).  So, instead we
# put our config file in .config, which is considered the ultimate source
# of default config information by make oldconfig.  Also, copy the config
# files out of the configs directory instead of the RPM_SOURCE_DIR.  It
# doesn't make any sense to put them in there and then not use them,
# especially when we could have a patch that modifies the config files
# as part of the bigmem patch set (or any other patch, it just makes
# us more flexible to use the configs from the configs directory).  Finally,
# since make mrproper wants to wipe out .config files, we move our mrproper
# up before we copy the config files around.
    cp configs/kernel-%{kversion}-$Config.config .config
	# TOMOYO Linux
	cat config.ccs >> .config
	# make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}$2/" Makefile
%ifarch sparc sparc64     
    make -s ARCH=$1 oldconfig_nonint
    make -s ARCH=$1 dep
    make -s ARCH=$1 include/linux/version.h 
%else
    # We do it twice, because make oldconfig tends to get stuff wrong.
    make -s oldconfig_nonint
    make -s oldconfig_nonint
    make -s -j $RPM_BUILD_NCPUS dep
    make -s include/linux/version.h 
%endif
}

BuildKernel() {
    if [ -n "$1" ] ; then
	Config=%{_target_cpu}-$1
	KernelVer=%{version}-%{release}$1
	DependKernel %{_target_cpu} $1
	echo BUILDING A KERNEL FOR $1 %{_target_cpu}...
    else
	Config=%{_target_cpu}%{dashtargetboard}
	KernelVer=%{version}-%{release}
	DependKernel %{_target_cpu}
	echo BUILDING THE NORMAL KERNEL for %{_target_cpu}...
    fi

%ifarch %{all_x86} x86_64
    make -s -j $RPM_BUILD_NCPUS CFLAGS_KERNEL="-Wno-unused" bzImage 
%else
    make -s -j $RPM_BUILD_NCPUS boot 
%endif
    make -s -j $RPM_BUILD_NCPUS CFLAGS_KERNEL="-Wno-unused" modules || exit 1
    
    # first make sure we are not loosing any .ver files to make mrporper's
    # removal of zero sized files.
    find include/linux/modules -size 0 | while read file ; do \
	echo > $file
    done
    # Start installing stuff
    mkdir -p $RPM_BUILD_ROOT/boot
    install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-$KernelVer
    install -m 644 $RPM_SOURCE_DIR/module-info $RPM_BUILD_ROOT/boot/module-info-$KernelVer
    install -m 644 configs/kernel-%{kversion}-$Config.config $RPM_BUILD_ROOT/boot/config-$KernelVer
    mkdir -p $RPM_BUILD_ROOT/dev/shm
%ifarch %{all_x86}
   cp arch/i386/boot/bzImage $RPM_BUILD_ROOT/boot/vmlinuz-$KernelVer
   cp vmlinux $RPM_BUILD_ROOT/boot/vmlinux-$KernelVer
%else
%ifarch x86_64
   cp arch/x86_64/boot/bzImage $RPM_BUILD_ROOT/boot/vmlinuz-$KernelVer
   cp vmlinux $RPM_BUILD_ROOT/boot/vmlinux-$KernelVer
%else
%ifarch ia64
    gzip -cfv vmlinux > vmlinuz
    mkdir -p $RPM_BUILD_ROOT/boot/efi/redhat
    install -m 755 vmlinux $RPM_BUILD_ROOT/boot/efi/redhat/vmlinux-$KernelVer
    install -m 755 vmlinuz $RPM_BUILD_ROOT/boot/efi/redhat/vmlinuz-$KernelVer
    ln -s efi/vmlinux-$KernelVer $RPM_BUILD_ROOT/boot/vmlinux-$KernelVer
    ln -s efi/vmlinuz-$KernelVer $RPM_BUILD_ROOT/boot/vmlinuz-$KernelVer
%else
    gzip -cfv vmlinux > vmlinuz
    install -m 644 vmlinuz $RPM_BUILD_ROOT/boot/vmlinuz-$KernelVer
%endif
    install -m 755 vmlinux $RPM_BUILD_ROOT/boot/vmlinux-$KernelVer
%endif
%endif


    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
    make -s INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=$KernelVer

##   mark the modules executable
#    if [ "$1" != "BOOT" ] ; then
#    	find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.o" -type f  | xargs chmod u+x
#    fi
    
##  mark the vmlinux* non-executable to fool strip-to-file
    chmod a-x $RPM_BUILD_ROOT/boot/vmlinux*

#   now separate out the debug info from the modules/vmlinux
#   /usr/lib/rpm/find-debuginfo.sh %{_builddir}/%{?buildsubdir} || :

#   and compress the modules for space
#    if [ "$1" != "BOOT" ] ; then
#    	find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.o" -type f  | xargs gzip -9
#    fi

#   remove files that will be generated by depmod at rpm -i time
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.*
#   remove legacy pcmcia symlink that's no longer useful
%ifarch %{nptlarchs}
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/pcmcia
%endif


}

SaveHeaders() {
    echo "SAVING HEADERS for $1 $2"
    # deal with the kernel headers that are version specific
    mkdir -p $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/savedheaders/$2/$1
    install -m 644 include/linux/autoconf.h \
	$RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/savedheaders/$2/$1/autoconf.h
    install -m 644 include/linux/version.h \
	$RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/savedheaders/$2/$1/version.h
    mv include/linux/modules \
	$RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/savedheaders/$2/$1/
    echo $2 $1 ../../savedheaders/$2/$1/ >> $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/savedheaders/list
}

###
# DO it...
###

rm -rf $RPM_BUILD_ROOT

%if %{buildjensen}
BuildKernel jensen
%endif

%if %{buildbigmem}
BuildKernel bigmem
SaveHeaders bigmem %{_target_cpu}
%endif

%if %{buildsmp}
BuildKernel smp
SaveHeaders smp %{_target_cpu}
%endif

%if %{buildBOOT}
BuildKernel BOOT
SaveHeaders BOOT %{_target_cpu}
%endif

%ifarch i386
DependKernel i586
SaveHeaders up i586
DependKernel i686
SaveHeaders up i686
DependKernel athlon
SaveHeaders up athlon
%endif
%ifarch sparc
DependKernel sparc64
SaveHeaders up sparc64
%endif

%ifarch i386 
DependKernel i586 smp
SaveHeaders smp i586
DependKernel i686 smp
SaveHeaders smp i686
DependKernel i686 bigmem
SaveHeaders bigmem i686
DependKernel athlon smp
SaveHeaders smp athlon
%endif
%ifarch sparc
DependKernel sparc64 smp
SaveHeaders smp sparc64
%endif

# UNIPROCESSOR KERNEL
%if %{buildup}
BuildKernel
%ifarch i386 alpha sparc ia64
SaveHeaders up %{_target_cpu}
%endif
%endif



###
### install
###

%install

cd linux-%{version}
mkdir -p $RPM_BUILD_ROOT/{boot,sbin}

for i in $RPM_BUILD_ROOT/lib/modules/*; do
  rm -f $i/build 
  ln -sf ../../../usr/src/linux-%{KVERREL} $i/build
done

%ifarch athlon i586 i686 sparc64
# these don't need much
rm -rf $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/savedheaders
exit 0
%endif

mkdir -p $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
rm -f drivers/net/hamradio/soundmodem/gentbl scripts/mkdep
tar cf - . | tar xf - -C $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}custom/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/Makefile
ln -sf linux-%{KVERREL} $RPM_BUILD_ROOT/usr/src/linux
install -m 644 %{SOURCE10}  $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}

#clean up the destination
make -s mrproper -C $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
cp configs/kernel-%{kversion}-%{_target_cpu}%{dashtargetboard}.config $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/.config
make -s oldconfig_nonint -C $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
make -s symlinks -C $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
make -s include/linux/version.h -C $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}

#this generates modversions info which we want to include and we may as
#well include the depends stuff as well, after we fix the paths
make -s depend -C $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
find $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL} -name ".*depend" | \
while read file ; do
    mv $file $file.old
    sed -e "s|[^ ]*\(/usr/src/linux\)|\1|g" < $file.old > $file
    rm -f $file.old
done

# Try to put some smarter autoconf.h and version.h files in place
pushd $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/include/linux ; {
rm -rf modules modversions.h autoconf.h version.h
cat > modversions.h <<EOF
#ifndef _LINUX_MODVERSIONS_H
#define _LINUX_MODVERSIONS_H
#include <linux/rhconfig.h>
#include <linux/modsetver.h>
EOF
echo '#include <linux/rhconfig.h>' > autoconf.h
list=`find ../../savedheaders/* -name '*.ver' -exec basename '{}' \; | sort`
mkdir modules
for l in $list; do
    sed 's,$,modules/'$l, ../../savedheaders/list | awk -f %{SOURCE17} > modules/$l
    touch -r modules/$l modules/`basename $l .ver`.stamp
    echo '#include <linux/modules/'$l'>' >> modversions.h
done
echo '#endif' >> modversions.h
sed 's,$,autoconf.h,' ../../savedheaders/list | awk -f %{SOURCE16} >> autoconf.h
install -m 644 %{SOURCE15} rhconfig.h
echo "#include <linux/rhconfig.h>" >> version.h
keyword=if
for i in smp BOOT BOOTsmp bigmem  up ; do
# When we build in an i386, we don't have an bigmem header directory
# in savedheaders/i386/bigmem.  We also don't have a BOOT directory
# anywhere except in savedheaders/i386.  So, we need to use this method
# of determining if a kernel version string needs to be included in the
# version.h file
    verh=`echo ../../savedheaders/*/$i/version.h | awk ' { print $1 } '`
    if [ -n "$verh" -a -f "$verh" ]; then
	if [ "$i" = up ]; then
	    if [ "$keyword" = if ]; then
		echo "#if 0" >> version.h
	    fi
  	    echo "#else" >> version.h
	else
	    echo "#$keyword defined(__module__$i)" >> version.h
	    keyword=elif
	fi
	grep UTS_RELEASE $verh >> version.h
    fi
done
echo "#endif" >> version.h
if [ -f ../../savedheaders/%{_target_cpu}/up/version.h ] ; then
    # keep to a standard normally
    HEADER_FILE=../../savedheaders/%{_target_cpu}/up/version.h
else
    # test build not including uniprocessor, must get info from somewhere
    HEADER_FILE=$(ls ../../savedheaders/%{_target_cpu}/*/version.h | head -1)
fi
grep -v UTS_RELEASE $HEADER_FILE >> version.h
rm -rf ../../savedheaders
} ; popd
touch $RPM_BUILD_ROOT/boot/kernel.h-%{kversion}

rm -f $RPM_BUILD_ROOT/usr/include/linux

for i in $RPM_BUILD_ROOT/lib/modules/*; do
  rm -f $i/modules.*
done

rm -rf $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/savedheaders

# fix up the tmp_include_depends file wrt the buildroot
perl -p -i -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/tmp_include_depends

###
### clean
###

%clean
rm -rf $RPM_BUILD_ROOT

###
### scripts
###

# do this for upgrades...in case the old modules get removed we have
# loopback in the kernel so that mkinitrd will work.
%pre 
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
exit 0

%pre smp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
exit 0

%pre bigmem
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
exit 0

%post 
cd /boot
%ifnarch ia64 
ln -sf vmlinuz-%{KVERREL} vmlinuz
%endif
ln -sf System.map-%{KVERREL} System.map
ln -sf module-info-%{KVERREL} module-info
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/mkkerneldoth ] && /sbin/mkkerneldoth
if [ -x /sbin/new-kernel-pkg ] ; then
        /sbin/new-kernel-pkg --mkinitrd --depmod --install %{KVERREL}
fi


%post smp
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/mkkerneldoth ] && /sbin/mkkerneldoth
if [ -x /sbin/new-kernel-pkg ] ; then
        /sbin/new-kernel-pkg --mkinitrd --depmod --install %{KVERREL}smp
fi

%post bigmem
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/mkkerneldoth ] && /sbin/mkkerneldoth
if [ -x /sbin/new-kernel-pkg ] ; then
        /sbin/new-kernel-pkg --mkinitrd --depmod --install %{KVERREL}bigmem
fi

%post jensen
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/mkkerneldoth ] && /sbin/mkkerneldoth
if [ -x /sbin/new-kernel-pkg ] ; then
        /sbin/new-kernel-pkg --mkinitrd --depmod --install %{KVERREL}jensen
fi

%ifnarch ia64
%post BOOT
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/mkkerneldoth ] && /sbin/mkkerneldoth
if [ -x /sbin/new-kernel-pkg ] ; then
        /sbin/new-kernel-pkg --mkinitrd --depmod --install %{KVERREL}BOOT
fi

%endif

# Allow clean removal of modules directory
%preun 
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
#rm -f /lib/modules/%{KVERREL}/modules.*
if [ -x /sbin/new-kernel-pkg ] ; then
 /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}
fi


%preun smp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
rm -f /lib/modules/%{KVERREL}smp/modules.*
if [ -x /sbin/new-kernel-pkg ] ; then
 /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}smp
fi


%preun bigmem
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
rm -f /lib/modules/%{KVERREL}bigmem/modules.*
if [ -x /sbin/new-kernel-pkg ] ; then
 /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}bigmem
fi


%preun BOOT
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
#rm -f /lib/modules/%{KVERREL}BOOT/modules.*
if [ -x /sbin/new-kernel-pkg ] ; then
 /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}BOOT
fi


%preun jensen
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
#rm -f /lib/modules/%{KVERREL}jensen/modules.*


# We need this here because we don't prereq kudzu; it could be
# installed after the kernel
%triggerin -- kudzu
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade || :

%triggerin smp -- kudzu
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade || :

%triggerin bigmem -- kudzu
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade || :

%triggerin BOOT -- kudzu
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade || :

%triggerin jensen -- kudzu
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade || :


# Old kernel-headers packages owned include symlinks; new
# ones just make them so that we can have multiple kernel-headers
# packages installed.

%triggerpostun source -- kernel-headers < 2.2.16
cd /usr/src
rm -f %{kslnk}
ln -snf linux-%{KVERREL} %{kslnk}
exit 0

%post source
cd /usr/src
rm -f %{kslnk}
ln -snf linux-%{KVERREL} %{kslnk}

%postun source
if [ -L /usr/src/%{kslnk} ]; then 
    if [ -L /usr/src/%{kslnk} -a `ls -ld /usr/src/%{kslnk} 2>/dev/null| awk '{ print $11 }'` = "linux-%{KVERREL}" ]; then
	[ $1 = 0 ] && rm -f /usr/src/%{kslnk}
    fi
fi
exit 0

###
### file lists
###

%if %{buildup}
%files 
%defattr(-,root,root)
/boot/%{kernel_glob}
%ifarch ia64
/boot/efi/redhat/%{kernel_glob}
%endif
/boot/module-info-%{KVERREL}
/boot/System.map-%{KVERREL}
/boot/config-%{KVERREL}
%dir /lib/modules
%dir /dev/shm
/lib/modules/%{KVERREL}
%endif

%if %{buildsmp}
%ifnarch i386
%files smp
%defattr(-,root,root)
/boot/%{kernel_glob}smp
%ifarch ia64
/boot/efi/redhat/%{kernel_glob}smp
%endif
/boot/module-info-%{KVERREL}smp
/boot/System.map-%{KVERREL}smp
/boot/config-%{KVERREL}smp
%dir /lib/modules
%dir /dev/shm
/lib/modules/%{KVERREL}smp

%endif
%endif

%if %{buildbigmem}
%files bigmem
%defattr(-,root,root)
/boot/%{kernel_glob}bigmem
/boot/module-info-%{KVERREL}bigmem
/boot/System.map-%{KVERREL}bigmem
/boot/config-%{KVERREL}bigmem
%dir /lib/modules
%dir /dev/shm
/lib/modules/%{KVERREL}bigmem
%endif

%if %{buildBOOT}
%files BOOT
%defattr(-,root,root)
/boot/%{kernel_glob}BOOT
/boot/System.map-%{KVERREL}BOOT
/boot/config-%{KVERREL}BOOT
%dir /lib/modules
%dir /dev/shm
/lib/modules/%{KVERREL}BOOT
%endif

%ifnarch i586 i686 sparc64 athlon
# START BASE ARCHES ONLY
%ifarch i386 alpha sparc ia64 x86_64

%files source
%defattr(-,root,root)
%dir /usr/src/linux-%{KVERREL}
/usr/src/linux-%{KVERREL}/COPYING*
/usr/src/linux-%{KVERREL}/CREDITS
/usr/src/linux-%{KVERREL}/Documentation
/usr/src/linux-%{KVERREL}/MAINTAINERS
/usr/src/linux-%{KVERREL}/Makefile
/usr/src/linux-%{KVERREL}/README
/usr/src/linux-%{KVERREL}/REPORTING-BUGS
/usr/src/linux-%{KVERREL}/Rules.make
/usr/src/linux-%{KVERREL}/arch
%ifarch sparc
/usr/src/linux-%{KVERREL}/arch/sparc64
%endif
/usr/src/linux-%{KVERREL}/drivers
/usr/src/linux-%{KVERREL}/crypto
/usr/src/linux-%{KVERREL}/fs
/usr/src/linux-%{KVERREL}/init
/usr/src/linux-%{KVERREL}/ipc
/usr/src/linux-%{KVERREL}/kernel
/usr/src/linux-%{KVERREL}/lib
/usr/src/linux-%{KVERREL}/mm
/usr/src/linux-%{KVERREL}/net
/usr/src/linux-%{KVERREL}/scripts
%ifarch %{all_x86}
%{?ibcs_1:/usr/src/linux-%{KVERREL}/abi}
%endif
/usr/src/linux-%{KVERREL}/configs
/usr/src/linux-%{KVERREL}/include
/usr/src/linux-%{KVERREL}/include/asm
%ifarch %{all_x86}
%{?ibcs_1:/usr/src/linux-%{KVERREL}/include/abi}
%endif
/usr/src/linux-%{KVERREL}/include/linux
/usr/src/linux-%{KVERREL}/include/rxrpc
/usr/src/linux-%{KVERREL}/include/net
/usr/src/linux-%{KVERREL}/include/pcmcia
/usr/src/linux-%{KVERREL}/include/scsi
/usr/src/linux-%{KVERREL}/include/video
/usr/src/linux-%{KVERREL}/tmp_include_depends
%dir /usr/src/linux-%{KVERREL}/include
%dir /usr/src/linux-%{KVERREL}/arch
%ifarch alpha sparc
/usr/src/linux-%{KVERREL}/include/math-emu
%endif  

%files doc
%defattr(-,root,root)
%doc linux-%{version}/Documentation/*


%endif
# END BASE ARCHES ONLY
%endif


#
# Dear Mr. or Mrs. Journalist,
#
# The changelog below is a list of modifications that have been made
# to the kernel at one time. By no means does this text reflect any
# official position of Red Hat, Inc. nor does any text reflect what
# is in the actual current kernel, due to the fact that we actually log 
# tests and one-off builds as well.
#
# Sincerely yours,
#     Arjan van de Ven
#     Red Hat Linux kernel maintainer. 
#

%changelog
* Thu Mar  2 2006 Marc Deslauriers <marcdeslauriers@videotron.ca> 2.4.20-46.9.legacy
- Fixed the broken CVE-2005-0749 patch that was causing unstability

* Thu Mar 16 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- 2.3.99pre2-3
- replace iBCS with abi, remove patches
- port abi to 2.3.99pre2-3
- fix packaging bug (ksymoops.8* was included in kernel-utils AND
  kernel-pcmcia-cs)
- add devfsd
- fix compilation on alpha (fix various kernel bugs and work
  around a compiler bug)
