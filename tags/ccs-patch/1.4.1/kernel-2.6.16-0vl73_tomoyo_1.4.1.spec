%define _noVersionedDependencies 1
%define _minimum_patches 0

Summary: The Linux kernel (the core of the Linux operating system)
Summary(ja): Linux カーネル (Linux オペレーティングシステムの心臓部分)

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.

%define buildup 1
%define buildsmp 0
%define builddoc 0
%define buildsource 0

# Versions of various parts

#
# Polite request for people who spin their own kernel rpms:
# please modify the "release" field in a way that identifies
# that the kernel isn't the stock distribution kernel, for example by
# adding some text to the end of the version number.
#
%define sublevel 16
%define kversion 2.6.%{sublevel}
%define rpmversion 2.6.%{sublevel}
%define release 0vl73_tomoyo_1.4.1

%define make_target bzImage

%define KVERREL %{rpmversion}-%{release}

# groups of related archs
%define all_x86 i386 i586 i686 athlon
%define all_ppc ppciseries ppcpseries ppc ppc64

# Override generic defaults with per-arch defaults 

%ifarch noarch
%define builddoc 1
%define buildsource 1
%define buildup 0
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-*.config
%endif

# Second, per-architecture exclusions (ifarch)
%ifarch i686 i586 athlon
%define buildsource 0
%define builddoc 0
%endif

%ifarch %{all_x86}
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-i?86*.config
%define image_install_path boot
%endif

%ifarch x86_64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-x86_64*.config
%define image_install_path boot
%endif

%ifarch ppc64
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc64*.config
%define image_install_path boot
%define make_target bzImage zImage.stub
%endif

%ifarch ppc64iseries
%define buildsmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc64*.config
%define image_install_path boot
%define make_target bzImage
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
%define buildsmp 0
%define image_install_path boot
%define make_target %{nil}
%endif

%ifarch ia64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ia64.config
%define buildsmp 0
%define image_install_path boot/efi/EFI/redhat
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
%define package_conflicts  cipe < 1.4.5, kudzu <= 0.92, initscripts < 6.51, dev < 3.2-7, iptables < 1.2.5-3, bcm5820 < 1.81, nvidia-rh72 <= 1.0 ipw2200-firmware < 2.3 selinux-policy-targeted < 1.23.16-1

#
# Several packages had bugs in them that became obvious when the NPTL
# threading code got integrated. 
#
%define nptl_conflicts SysVinit < 2.84-13, pam < 0.75-48, vixie-cron < 3.0.1-73, privoxy < 3.0.0-8, spamassassin < 2.44-4.8.x,  cups < 1.1.17-13

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
%define kernel_prereq  fileutils, modutils >= 3.2.2 , initscripts >= 5.83, mkinitrd >= 3.5.23

Name: kernel
Group: System Environment/Kernel
License: GPLv2
Version: %{rpmversion}
Release: %{release}
ExclusiveArch: noarch %{all_x86} x86_64 %{all_ppc} sparc sparc64 ia64
ExclusiveOS: Linux
Provides: kernel = %{rpmversion}
Provides: kernel26 = %{rpmversion}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: alsa-driver = 1.0.12
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
BuildPreReq: modutils >= 3.2.2, patch >= 2.5.4, bash >= 2.03, sh-utils, tar
BuildPreReq: bzip2, findutils, gzip, m4, perl, make >= 3.78, gnupg, diffutils
BuildRequires: gcc >= 3.3.5, binutils >= 2.15

Vendor:		Project Vine
Distribution:	Vine Linux

Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-%{kversion}.tar.bz2

Source10: COPYING.modules
Source11: genkey

Source20: kernel-%{kversion}-i586.config
Source21: kernel-%{kversion}-i686.config
#Source22: kernel-%{kversion}-i686-smp.config
Source23: kernel-%{kversion}-x86_64.config
#Source24: kernel-%{kversion}-x86_64-smp.config
Source25: kernel-%{kversion}-ppc64.config
#Source29: kernel-%{kversion}-sparc.config
#Source30: kernel-%{kversion}-sparc64.config
#Source31: kernel-%{kversion}-sparc64-smp.config
Source32: kernel-%{kversion}-ppc.config
#Source33: kernel-%{kversion}-ppc-smp.config
#Source34: kernel-%{kversion}-ia64.config


# Source 100 - 500 for Vine Linux
# fb boot logo
Source100: logo_vine_clut224.ppm
# software suspend 2.2.5
%define swsusp2_version 2.2.5-for-2.6.16.9
Source200: suspend2-%{swsusp2_version}.tar.bz2

#
# Patches 0 through 100 are meant for core subsystem upgrades
#
Patch1: patch-2.6.16.36.bz2

# Patches 100 through 500 are meant for architecture patches

# 200 - 299   x86(-64)

#Patch200: linux-2.6-x86-tune-p4.patch
Patch201: linux-2.6-x86-apic-off-by-default.patch
Patch202: linux-2.6-x86-vga-vidfail.patch

# add no_timer_check for i386 kernel (thanks to NAKAMURA Kenta)
Patch290: linux-2.6.12-io_apic-i386-no_timer_check.patch

# 300 - 399   ppc(64)
Patch301: linux-2.6.15-cell-numa-init.patch
Patch305: linux-2.6-cell-mambo-drivers.patch
Patch306: linux-2.6-hvc-console.patch
Patch310: linux-2.6-cell-spiderpic-no-devtree.patch
Patch313: linux-2.6-hvc-rtas-console.patch
Patch314: linux-2.6-ppc-rtas-check.patch
Patch317: linux-2.6-ppc-iseries-input-layer.patch

Patch350: linux-2.6.12-windtunnel-printk.patch
Patch351: linux-2.6.16-offb.patch
Patch352: offb-bootx-fix1.patch
Patch353: offb-bootx-fix2.patch
Patch354: bootx-with-ramdisk.patch
Patch355: eMac-lockup-fix.patch

# 400 - 499   ia64
# 500 - 599   s390(x)
# 600 - 699   sparc(64)

#
# Patches 800 through 899 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#
Patch800: linux-2.6-build-nonintconfig.patch
Patch801: linux-2.6-build-userspace-headers-warning.patch

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#

# Restrict /dev/mem usage.
Patch1050: linux-2.6-devmem.patch

# Provide read only /dev/crash driver.
Patch1060: linux-2.6-crash-driver.patch
Patch1070: linux-2.6-sleepon.patch

# NFS bits.
Patch1201: linux-2.6-NFSD-ctlbits.patch
Patch1203: linux-2.6-NFSD-badness.patch

# NIC driver updates
Patch1301: linux-2.6-net-sundance-ip100A.patch
Patch1302: linux-2.6-net-wireless-features.patch
Patch1340: linux-2.6-sky2-1.4.patch
Patch1341: linux-2.6-sky2-jumbo-packets.patch
Patch1342: linux-2.6.16.34-sky2-1.4-1.7.patch
Patch1343: linux-2.6-sky2-phy-read-timeout.patch
Patch1344: linux-2.6-sky2-1.7-88E803X-transmit-lockup.patch
Patch1350: linux-2.6-skge-1.5.patch
Patch1360: linux-2.6.16.28-e1000-7.2.7.patch
Patch1361: linux-2.6.16-net-e1000-suspend.patch
Patch1370: linux-2.6.16-r8169-update.patch
Patch1371: linux-2.6.16-r1000-1.0.4.patch
Patch1390: linux-2.6.16-tg3-3.66d.patch

Patch1400: linux-2.6-pcmcia-disable-warning.patch

# Misc bits.
Patch1610: linux-2.6-atkbd-dell-multimedia.patch
Patch1630: linux-2.6-module_version.patch
Patch1650: linux-2.6-input-kill-stupid-messages.patch
Patch1660: linux-2.6-input-usblegacy.patch
Patch1670: linux-2.6-serial-tickle-nmi.patch
Patch1690: linux-2.6-radeon-backlight.patch
Patch1700: linux-2.6-ide-tune-locking.patch
Patch1710: linux-2.6-autofs-pathlookup.patch
Patch1720: linux-2.6-selinux-hush.patch
Patch1730: linux-2.6-ide-cd-shutup.patch
Patch1740: linux-2.6-block-reduce-stack.patch
Patch1750: linux-2.6-ub.patch
Patch1760: linux-2.6-sata-enable-atapi-by-default.patch
Patch1770: linux-2.6-valid-ether-addr.patch
Patch1780: linux-2.6-firmware-loader-timeout.patch
Patch1790: linux-2.6-softcursor-persistent-alloc.patch
Patch1800: linux-2.6-pwc-powerup-by-default.patch
Patch1810: linux-2.6-smsc-ircc2-pnp.patch
Patch1820: linux-2.6-audit-new-msg-types.patch
Patch1830: linux-2.6-w1-hush-debug.patch
Patch1840: linux-2.6-x86-hp-reboot.patch
Patch1850: linux-2.6-mv643xx-compile-fix.patch
Patch1860: linux-2.6-softlockup-disable.patch
Patch1870: linux-2.6-revert-sched.patch
Patch1880: linux-2.6.16-mmconfig-new-intel-motherboards.patch

# Warn about usage of various obsolete functionality that may go away.
Patch1900: linux-2.6-obsolete-idescsi-warning.patch
Patch1901: linux-2.6-obsolete-oss-warning.patch

# no external module should use these symbols.
Patch1910: linux-2.6-unexport-symbols.patch

# VM bits
Patch2001: linux-2.6-vm-silence-atomic-alloc-failures.patch
Patch2002: linux-2.6-vm-clear-unreclaimable.patch

# SATA
Patch2100: linux-2.6-promise-pdc2037x.patch
Patch2110: linux-2.6.16.28-ahci-newids.patch
Patch2120: linux-2.6.16-sata_via-vt8237a.patch
Patch2130: linux-2.6.16.29-libata-acpi.patch

# IDE
Patch2200: linux-2.6.16-ide-driver-jmicron.patch
Patch2210: linux-2.6.16-ide-generic-marvell-pata.patch

# alsa-driver 1.0.12
# Patch3000: linux-2.6.16.34-alsa-1.0.12.patch
Patch3000: linux-2.6.16.36-alsa-1.0.12.patch

# fix firmware_class to use mutexes
Patch3100: linux-2.6.16-firmware_class-mutexes.patch

#
# External drivers that are about to get accepted upstream
#

# bcm43xx driver
Patch4000: linux-2.6.16-bcm43xx.patch

# sdhci driver
Patch4010: linux-2.6.16-sdhci-0.12.patch

#
# 6000 to 10000 is for Vine Linux
#

# unicon
Patch6000: linux-2.6.16.29-unicon.patch

# supermount-ng 2.0.8
# http://supermount-ng.sf.net/
Patch6010: linux-2.6.16-rc6-supermount-ng-2.0.8.patch
Patch6011: linux-2.6.16-supermount-ng-2.0.8-fix.patch

# bootsplash
# http://www.bootsplash.de/
Patch6020: linux-2.6.16.29-unicon-bootsplash-3.1.6.patch

# unicon ad-hoc revert patch for ppc (does not affect other archs)
Patch6025: linux-2.6.16.29-unicon-ppc.patch

# unionfs 1.2
# http://www.fsl.cs.sunysb.edu/project-unionfs.html
Patch6030: linux-2.6.16-unionfs-1.2.patch
Patch6031: linux-2.6.16-unionfs-1.2-fix.patch

# squashfs 3.0
# http://squashfs.sourceforge.net/
Patch6040: linux-2.6.16-squashfs-3.0.patch

# saa7133gyc/ivtv driver update
# Thanks for T.Adachi
# http://www.paken.org/linuxwiki/index.php?CX23416GYC-STVLP%A4%CE%B2%F2%C0%CF
Patch7000: linux-2.6.16.34-saa7133gyc-stvlp_ivtv.patch
Patch7010: ivtv_061003patch.patch.gz

#
# 10000 to 20000 is for stuff that has to come last due to the
# amount of drivers they touch. But only these should go here. 
# Not patches you're too lazy for to put in the proper place.
#
Patch10000: linux-2.6-LINUX_COMPILER-LANG_C.patch

# Security fix patches
Patch20050: linux-2.6.16-fs-grow_buffers-limit.patch
Patch20060: linux-2.6.16_CVE-2006-6106.patch
Patch20070: linux-2.6.16_CVE-2006-5173.patch
Patch20080: linux-2.6.16_CVE-2006-5823.patch
Patch20090: linux-2.6.16_CVE-2006-6053.patch
Patch20100: linux-2.6.16_CVE-2006-6054.patch
Patch20110: linux-2.6.16_CVE-2006-6056.patch
Patch20120: linux-2.6.16_CVE-2006-4814.patch
Patch20130: linux-2.6.16_CVE-2006-5749.patch
Patch20140: linux-2.6.16_CVE-2006-5753.patch
Patch20150: linux-2.6.16_CVE-2007-0006.patch
Patch20160: linux-2.6.16_CVE-2007-0772.patch
Patch20170: linux-2.6.16_CVE-2007-0005.patch
Patch20180: linux-2.6.16_CVE-2007-1000.patch
Patch20190: linux-2.6.16_CVE-2007-0958.patch

# mol-0.9.71_pre8 for ppc
%define molver 0.9.71
%define molpre _pre8
Source50000: http://dev.gentoo.org/~josejx/mol-%{molver}%{molpre}.tar.bz2
Source50001: mol-0.9.71-config
Patch50000:  mol-0.9.71_pre8-Makefile.patch


# END OF PATCH DEFINITIONS

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

%description 
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

%description -l ja
kernel パッケージには、Linux オペレーティングシステムの心臓部分とも
いえる Linux カーネル (vmlinuz) が含まれています。
カーネルは，メモリ管理，プロセス管理，デバイスの入出力等，オペレーティング
システムの基本的な部分を司ります。

%package devel
Summary: Development package for building kernel modules to match the kernel.
Summary(ja): 特定のバージョンのカーネル用のモジュールを構築するための開発パッケージ
Group: System Environment/Kernel
AutoReqProv: no
Provides: kernel26-devel-%{_target_cpu} = %{rpmversion}-%{release}

%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.

### kernel-source
%package source
Summary: The source code for the Linux kernel.
Summary(ja): Linux カーネルのソースコード
Group: Development/Libraries
Prereq: fileutils
Requires: make >= 3.78
Requires: gcc >= 3.2
Requires: binutils
# documentations
Requires: kernel-doc = %{rpmversion}-%{release}
# for menuconfig
Requires: ncurses-devel readline-devel
# for gconfig
#Requires: gtk2-devel
# for xconfig
#Requires: qt-devel

%description source
The kernel-source package contains the source code files for the Linux
kernel. The source files can be used to build a custom kernel that is
smaller due only including drivers for your particular hardware, if you are
so inclined (and you know what you're doing). The customisation guide in the
documentation describes in detail how to do this. This package is neither
needed nor usable for building external kernel modules for linking into the
default kernel.

If you use "gconfig" to configure the kernel, install gtk2-devel package.
If you use "xconfig" to configure the kernel, install qt-devel package.

%description source -l ja
kernel-source パッケージには Linux カーネルのソースコードが含まれて
います．カーネルのソースコードは多くの C プログラムの作成に必要です．
カーネルのソースコードに定義されている制限に依存することがあるからです．
このソースコードを使って，あなたのシステム向けにチューンアップした
カスタムカーネルを作成することもできます．

"gconfig" をつかってカーネルのコンフィグレーションを行う場合は、gtk2-devel
パッケージをインストールしてください。
"xconfig" をつかってカーネルのコンフィグレーションを行う場合は、qt-devel
パッケージをインストールしてください。

### kernel-doc
%package doc
Summary: Various documentation bits found in the kernel source.
Summary(ja): カーネルソース内のさまざまなドキュメント群
Group: Applications/Documentation

%description doc
This package contains documentation files from the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files. 

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.

%description doc -l ja
このパッケージにはカーネルソースに含まれているドキュメントが
収められています．Linux カーネルやデバイスドライバに関する様々な
情報がこのドキュメントには記されています．

Linux カーネルモジュールを読み込む際の引数を調べたい場合等，
このパッケージをインストールすると良いでしょう．


%package smp
Summary: The Linux kernel compiled for SMP machines.
Summary(ja): SMP マシン用にコンパイルされた Linux カーネル

Group: System Environment/Kernel
Provides: kernel = %{rpmversion}
Provides: kernel26 = %{rpmversion}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}smp
Provides: alsa-driver = 1.0.12
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

%description smp -l ja
このパッケージには SMP 版の Linux カーネルが収められています．
このカーネルは 2個以上の CPU を搭載したマシンにのみ必要となりますが，
1CPU のマシンでも問題なく動作します．

あなたのマシンが 2個以上の CPU を搭載している場合は
kernel-smp パッケージをインストールしてください．

%package smp-devel
Summary: Development package for building kernel modules to match the SMP kernel.
Summary(ja): 特定のバージョンのSMPカーネル用のモジュールを構築するための開発パッケージ
Group: System Environment/Kernel
Provides: kernel-smp-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}smp
Provides: kernel-devel = %{rpmversion}-%{release}smp
Provides: kernel26-devel = %{rpmversion}-%{release}smp
AutoReqProv: no

%description smp-devel
This package provides kernel headers and makefiles sufficient to build modules
against the SMP kernel package.


%ifarch ppc
%package -n mol-kmods
Summary:     Mac-on-Linux kernel modules
Summary(ja): Mac-on-Linux カーネルモジュール
Group:       System Environment/Kernel
Version:     %{molver}_%{rpmversion}
Release:     %{release}
Requires:    kernel = %{rpmversion}-%{release}

%description -n mol-kmods
This package contains the Mac-on-Linux kernel module
needed by MOL. It also contains the sheep_net kernel
module (for networking).

This package is built for kernel-%{rpmversion}-%{release}.

%description -n mol-kmods -l ja
このパッケージには Mac-on-Linux (MOL) で必要とされる
カーネルモジュールが収録されています。

このパッケージは kernel-%{rpmversion}-%{release} 向けにビルドされたものです。
%endif


%prep

%setup -q -n %{name}-%{kversion} -c -a 200
cd linux-%{kversion}

#
# Patches 0 through 100 are meant for core subsystem upgrades
# 
%patch1 -p1

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
#%patch200 -p1
# Keep UP APIC off by default.
%patch201 -p1
# add vidfail capability;
# without this patch specifying a framebuffer on the kernel prompt would
# make the boot stop if there's no supported framebuffer device; this is bad
# for the installer cd that wants to automatically fall back to textmode
# in that case
%patch202 -p1

%patch290 -p1

# 
# ppc64
#

# Arnd says don't call cell_spumem_init() till he fixes it.
%patch301 -p1
# Fix the MV643xx Gigabit Ethernet driver
#%patch304 -p1
# Support the IBM Mambo simulator; core as well as disk and network drivers.
%patch305 -p1
# Make HVC console generic; support simulator console device using it.
%patch306 -p1
# Hardcode PIC addresses for Cell spiderpic
%patch310 -p1
# RTAS console support
%patch313 -p1
# Check properly for successful RTAS instantiation
%patch314 -p1
# No input layer on iseries
%patch317 -p1

%patch350 -p1
#%patch351 -p1
%patch352 -p1
%patch353 -p1
%patch354 -p1
%patch355 -p1

#
# ia64
#

#
# sparc/sparc64
#


#
# Patches 500 through 1000 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#


# This patch adds a "make nonint_oldconfig" which is non-interactive and
# also gives a list of missing options at the end. Useful for automated
# builds (as used in the buildsystem).
%patch800 -p1
# Warn if someone tries to build userspace using kernel headers
%patch801 -p1

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#


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

#
# Various upstream NFS/NFSD fixes.
#
# kNFSD: fixed '-p port' arg to rpc.nfsd and enables the defining proto versions and transports
%patch1201 -p1
# Fix badness.
%patch1203 -p1

# NIC driver fixes.
# New PCI ID for sundance driver.
%patch1301 -p1
# Goodies for wireless drivers to make NetworkManager work
%patch1302 -p1
# sky2 update (1.4)
%patch1340 -p1
# sky2 jumbo paket fix
%patch1341 -p1
# sky2 update (1.7)
%patch1342 -p1
# fix "phy read timeout" message flood
%patch1343 -p1
# fix 88E803X trasnmit lokup
%patch1344 -p1
# skge update
%patch1350 -p1
# e1000 update
%patch1360 -p1
%patch1361 -p1
# r8169 update
%patch1370 -p1
# r1000 driver
%patch1371 -p1
# tg3 update (3.66d)
%patch1390 -p1

# disable pcmcia warnings
%patch1400 -p1

# Misc fixes
# Make multimedia buttons on Dell Inspiron 8200 work.
%patch1610 -p1
# Add missing MODULE_VERSION tags to some modules.
%patch1630 -p1
# The input layer spews crap no-one cares about.
%patch1650 -p1
# usb legacy workaround.
%patch1660 -p1
# Tickle the NMI whilst doing serial writes.
%patch1670 -p1
# Radeon on thinkpad backlight power-management goodness.
%patch1690 -p1
# Fix IDE locking bug.
%patch1700 -p1
# autofs4 looks up wrong path element when ghosting is enabled
%patch1710 -p1
# Silence some selinux messages.
%patch1720 -p1
# Silence noisy CD drive spew
%patch1730 -p1
# Reduce stack usage in block layer
#%patch1740 -p1
# Enable USB storage,UB & libusual magick.
#%patch1750 -p1
# Enable SATA ATAPI by default.
%patch1760 -p1
# 
%patch1770 -p1
# Increase timeout on firmware loader.
%patch1780 -p1
# Use persistent allocation in softcursor
%patch1790 -p1
# Power up PWC driver by default.
%patch1800 -p1
# PNP support for smsc-ircc2
%patch1810 -p1
%patch1820 -p1
# Silence debug messages in w1
%patch1830 -p1
# Reboot through BIOS on HP laptops.
%patch1840 -p1
# Fix compilation for MV643xx Ethernet
%patch1850 -p1
# Add a safety net to softlockup so that it doesn't prevent installs.
%patch1860 -p1
# revert some sched.c change to fix lockups
%patch1870 -p1
# Patch inserts PCI memory mapped config region(s) into the resource map. This
# will allow for the MMCCONFIG regions to be marked as busy in the iomem
# address space as well as the regions(s) showing up in /proc/iomem.
# backported from 2.6.19-rc
%patch1880 -p1

# Warn about obsolete functionality usage.
%patch1900 -p1
%patch1901 -p1
# Remove kernel-internal functionality that nothing external should use.
%patch1910 -p1

#
# VM related fixes.
#
# Silence GFP_ATOMIC failures.
%patch2001 -p1
# VM oom killer tweaks.
%patch2002 -p1

# SATA update
# Add support Promise 2037x SATA controllers with PATA ports
%patch2100 -p1
# Add newer chipset support for AHCI (JMicron, VIA, ATI, NVIDIA, SiS)
%patch2110 -p1
# Add newer chipset support for sata_via (VT8237A)
%patch2120 -p1
# use ACPI on libata suspend/resume function.
%patch2130 -p1

# JMicron legacy IDE driver
%patch2200 -p1
# support Marvell PATA controller by generic ide driver.
%patch2210 -p1

# Alsa update
%patch3000 -p1

# firmware_class
%patch3100 -p1

#
# External drivers that are about to get accepted upstream
#

# bcm43xx driver
%patch4000 -p1

# sdhci driver
%patch4010 -p1

#
# Patches 5000 to 6000 are reserved for new drivers that are about to
# be merged upstream
#


#
# Patches 6000 to 10000 are for Vine Linux
#

# unicon
%patch6000 -p1

# supermount-ng
%patch6010 -p1
%patch6011 -p1

# bootsplash-3.1.6
%patch6020 -p1

# unicon ad-hoc revert patch for ppc
%patch6025 -p1

# unionfs
%if !%{_minimum_patches}
%patch6030 -p1
%patch6031 -p1
%endif

# squashfs
%patch6040 -p1

# saa7133gyc/ivtv
%patch7000 -p1
%patch7010 -p1

#
# final stuff
#
# do not include localized version string in /proc/version
%patch10000 -p1

# security fix
%patch20050 -p1 -b .CVE-2006-5757
%patch20060 -p1 -b .CVE-2006-6106
%patch20070 -p1 -b .CVE-2006-5173
%patch20080 -p1 -b .CVE-2006-5823
%patch20090 -p1 -b .CVE-2006-6053
%patch20100 -p1 -b .CVE-2006-6054
%patch20110 -p1 -b .CVE-2006-6056
%patch20120 -p1 -b .CVE-2006-4814
%patch20130 -p1 -b .CVE-2006-5749
%patch20140 -p1 -b .CVE-2006-5753
%patch20150 -p1 -b .CVE-2007-0006
%patch20160 -p1 -b .CVE-2007-0772
%patch20170 -p1 -b .CVE-2007-0005
%patch20180 -p1 -b .CVE-2007-1000
%patch20190 -p1 -b .CVE-2007-0958

#
# misc small stuff to make things compile or otherwise improve performance
#

#
# apply software suspend patches
#
sh ../suspend2-%{swsusp2_version}/apply

# TOMOYO Linux
tar -zxf %_sourcedir/ccs-patch-1.4.1-20070605.tar.gz
sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -0vl73custom/" -- Makefile
patch -sp1 < ccs-patch-2.6.16-0vl73.txt

# END OF PATCH APPLICATIONS

cp %{SOURCE10} Documentation/

# put Vine logo
cp -f %{SOURCE100} drivers/video/logo/logo_linux_clut224.ppm

#
# install extra documentations
#


#
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

# copy missing header files from asm-ppc to asm-powerpc
cp -a include/asm-ppc/highmem.h include/asm-powerpc/highmem.h


###
### build
###
%build
sync

cd linux-%{kversion}


BuildKernel() {

    # Pick the right config file for the kernel we're building
    if [ -n "$1" ] ; then
	Config=kernel-%{kversion}-%{_target_cpu}-$1.config
	DevelDir=/usr/src/kernels/%{KVERREL}-$1-%{_target_cpu}
	DevelLink=/usr/src/kernels/%{KVERREL}$1-%{_target_cpu}
    else
	Config=kernel-%{kversion}-%{_target_cpu}.config
	DevelDir=/usr/src/kernels/%{KVERREL}-%{_target_cpu}
	DevelLink=
    fi

    KernelVer=%{rpmversion}-%{release}$1
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
%ifarch ppc
    cp vmlinux $RPM_BUILD_ROOT/%{image_install_path}/vmlinux-$KernelVer
%else
    cp arch/$Arch/boot/bzImage $RPM_BUILD_ROOT/%{image_install_path}/vmlinuz-$KernelVer
%endif
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
    cp --parents `find  -type f -name "Makefile*" -o -name "Kconfig*"` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build 
    cp Module.symvers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    # then drop all but the needed Makefiles/Kconfig files
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Documentation
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cp arch/%{_arch}/kernel/asm-offsets.s $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch}/kernel || :
    cp .config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp .kernelrelease $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
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

# build documentation package
%if %{builddoc}
mkdir -p $RPM_BUILD_ROOT%{_docdir}/kernel-doc-%{kversion}/Documentation

# sometimes non-world-readable files sneak into the kernel source tree
chmod -R a+r *
# copy the source over
tar cf - Documentation | tar xf - -C $RPM_BUILD_ROOT%{_docdir}/kernel-doc-%{kversion}
%endif

# build source package
%if %{buildsource}
mkdir -p $RPM_BUILD_ROOT%{_prefix}/src/linux-%{kversion}
sync
make -s mrproper
sync
tar cf - . | tar xf - -C $RPM_BUILD_ROOT%{_prefix}/src/linux-%{kversion}
rm -rf $RPM_BUILD_ROOT%{_prefix}/src/linux-%{kversion}/Documentation
ln -sf %{_docdir}/kernel-doc-%{kversion}/Documentation $RPM_BUILD_ROOT%{_prefix}/src/linux-%{kversion}/
sync

# set the EXTRAVERSION to <version>custom, so that people who follow a kernel building howto
# don't accidentally overwrite their currently working moduleset and hose their system
perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}custom/" $RPM_BUILD_ROOT/usr/src/linux-%{kversion}/Makefile
install -m 644 %{SOURCE10}  $RPM_BUILD_ROOT/usr/src/linux-%{kversion}
%endif

sync


# build MOL kernel modules
%ifarch ppc
rm -rf ${RPM_BUILD_DIR}/mol-%{molver}%{molpre}
cd ${RPM_BUILD_DIR}; tar -zxf %{SOURCE50000}

cd ${RPM_BUILD_DIR}/mol-%{molver}%{molpre}
patch -p1 < %{PATCH50000}

make defconfig
cp -f %{SOURCE50001} .config-ppc
make clean
make KERNEL_TREES=${RPM_BUILD_DIR}/%{name}-%{rpmversion}/linux-%{kversion} \
     modules
make KERNEL_TREES=${RPM_BUILD_DIR}/%{name}-%{rpmversion}/linux-%{kversion} \
     install-modules DESTDIR=${RPM_BUILD_ROOT} prefix=/usr
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
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --mkinitrd --depmod --install %{KVERREL}
KNAME=vmlinuz

%ifarch ppc
touch /etc/modprobe.d/modprobe.conf.dist
AUDIO=`grep "audio" /etc/modprobe.d/modprobe.conf.dist`
if [ "$AUDIO" = "" ]; then
  for MODCONFFILE in /etc/modprobe.d/modprobe.conf.dist
  do
    TEMPFILE=`/bin/mktemp -q /tmp/modprobe.conf.dist.XXXXXX`
    sed -e 's/ dmasound$//' $MODCONFFILE > $TEMPFILE
    grep -q "alias sound snd-powermac" $TEMPFILE || \
      echo alias sound snd-powermac >> $TEMPFILE
    mv -f $TEMPFILE $MODCONFFILE
  done
fi
KNAME=vmlinux
%endif

cd /boot
if [ ! -f $KNAME ]; then
  ln -sf $KNAME-%{KVERREL} $KNAME.old
  ln -sf System.map-%{KVERREL} System.map.old
  ln -sf initrd-%{KVERREL}.img initrd.old.img
else
  mv -f $KNAME $KNAME.old
  mv -f System.map System.map.old
  if [ -f initrd.img ]; then
    mv -f initrd.img initrd.old.img
  else
    ln -sf initrd-%{KVERREL}.img initrd.old.img
  fi
fi
ln -sf $KNAME-%{KVERREL} $KNAME
ln -sf System.map-%{KVERREL} System.map
ln -sf initrd-%{KVERREL}.img initrd.img

[ -x /sbin/mkkerneldoth ] && /sbin/mkkerneldoth
depmod -a -F /boot/System.map-%{KVERREL} %{KVERREL}

# if preffered bootloader is LILO, execute lilo.
%ifarch i386 i586 i686 athlon
if [ -f /etc/sysconfig/bootloader ]; then
  source /etc/sysconfig/bootloader
  if [ "$BOOTLOADER" = "lilo" ]; then
    if [ -x /sbin/lilo -a -f /etc/lilo.conf ]; then
      /sbin/lilo > /dev/null
      exit 0
    fi
  fi
fi
%endif
			      
%post smp
[ ! -x /usr/sbin/module_upgrade ] || /usr/sbin/module_upgrade
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --mkinitrd --depmod --install %{KVERREL}smp
%ifarch i386 i586 i686 athlon x86_64
cd /boot
if [ ! -f vmlinuz ]; then
  ln -sf vmlinuz-%{KVERREL}smp vmlinuz.old
  ln -sf System.map-%{KVERREL}smp System.map.old
  ln -sf initrd-%{KVERREL}smp.img initrd.old.img
else
  mv -f vmlinuz vmlinuz.old
  mv -f System.map System.map.old
  if [ -f initrd.img ]; then
    mv -f initrd.img initrd.old.img
  else
    ln -sf initrd-%{KVERREL}smp.img initrd.old.img
  fi
fi
ln -sf vmlinuz-%{KVERREL}smp vmlinuz
ln -sf System.map-%{KVERREL}smp System.map
ln -sf initrd-%{KVERREL}smp.img initrd.img
%endif
[ -x /sbin/mkkerneldoth ] && /sbin/mkkerneldoth
depmod -a -F /boot/System.map-%{KVERREL}smp %{KVERREL}smp

# if preffered bootloader is LILO, execute lilo.
%ifarch i386 i586 i686 athlon x86_64
if [ -f /etc/sysconfig/bootloader ]; then
  source /etc/sysconfig/bootloader
  if [ "$BOOTLOADER" = "lilo" ]; then
    if [ -x /sbin/lilo -a -f /etc/lilo.conf ]; then
      /sbin/lilo > /dev/null
      exit 0
    fi
  fi
fi
%endif

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
/lib/modules/%{KVERREL}/build
/lib/modules/%{KVERREL}/source

%files devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-%{_target_cpu}
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

%files smp-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu}
/usr/src/kernels/%{KVERREL}smp-%{_target_cpu}
%endif



# only some architecture builds need kernel-source
%if %{buildsource}
%files source
%defattr(-,root,root)
%{_prefix}/src/linux-%{kversion}
%dir %{_prefix}/src/linux-%{kversion}
%endif

# only some architecture builds need kernel-doc
%if %{builddoc}
%files doc
%defattr(-,root,root)
%{_datadir}/doc/kernel-doc-%{kversion}/Documentation/*
%dir %{_datadir}/doc/kernel-doc-%{kversion}/Documentation
%dir %{_datadir}/doc/kernel-doc-%{kversion}
%endif


%ifarch ppc
%files -n mol-kmods
%{_libdir}/mol/%{molver}/modules/
%endif


%changelog
* Wed Mar 14 2007 Satoshi IWAMOTO <satoshi.iwamoto@nifty.ne.jp> 2.6.16-0vl73
- add patch20190 for fix CVE-2007-0958 (PT_INTERP)

* Thu Jul 03 2003 Arjan van de Ven <arjanv@redhat.com>
- 2.6 start

