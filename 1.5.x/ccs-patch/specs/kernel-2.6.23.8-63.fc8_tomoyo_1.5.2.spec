Summary: The Linux kernel (the core of the Linux operating system)

# For a stable, released kernel, released_kernel should be 1. For rawhide
# and/or a kernel built from an rc or git snapshot, released_kernel should
# be 0.
%define released_kernel 1

# Versions of various parts

# Polite request for people who spin their own kernel rpms:
# please modify the "buildid" define in a way that identifies
# that the kernel isn't the stock distribution kernel, for example,
# by setting the define to ".local" or ".bz123456"
#
#% define buildid .local

# fedora_build defines which build revision of this kernel version we're
# building. Rather than incrementing forever, as with the prior versioning
# setup, we set fedora_cvs_origin to the current cvs revision s/1.// of the
# kernel spec when the kernel is rebased, so fedora_build automatically
# works out to the offset from the rebase, so it doesn't get too ginormous.
#
# Bah. Have to set this to a negative for the moment to fix rpm ordering after
# moving the spec file. cvs sucks. Should be sure to fix this once 2.6.23 is out.
%define fedora_cvs_origin 209
%define fedora_build %(R="$Revision: 1.272 $"; R="${R%% \$}"; R="${R##: 1.}"; expr $R - %{fedora_cvs_origin})

# base_sublevel is the kernel version we're starting with and patching
# on top of -- for example, 2.6.22-rc7-git1 starts with a 2.6.21 base,
# which yields a base_sublevel of 21.
%define base_sublevel 23

## If this is a released kernel ##
%if 0%{?released_kernel}
# Do we have a 2.6.21.y update to apply?
%define stable_update 8
# Set rpm version accordingly
%if 0%{?stable_update}
%define stablerev .%{stable_update}
%endif
%define rpmversion 2.6.%{base_sublevel}%{?stablerev}

## The not-released-kernel case ##
%else
# The next upstream release sublevel (base_sublevel+1)
%define upstream_sublevel %(expr %{base_sublevel} + 1)
# The rc snapshot level
%define rcrev 0
# The git snapshot level
%define gitrev 0
# Set rpm version accordingly
%define rpmversion 2.6.%{upstream_sublevel}
%endif
# Nb: The above rcrev and gitrev values automagically define Patch00 and Patch01 below.

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.
# All should default to 1 (enabled) and be flipped to 0 (disabled)
# by later arch-specific checks.

# The following build options are enabled by default.
# Use either --without <opt> in your rpmbuild command or force values
# to 0 in here to disable them.
#
# standard kernel
%define with_up        %{?_without_up:        0} %{?!_without_up:        1}
# kernel-smp (only valid for ppc 32-bit, sparc64)
%define with_smp       %{?_without_smp:       0} %{?!_without_smp:       1}
# kernel-PAE (only valid for i686)
%define with_pae       %{?_without_pae:       0} %{?!_without_pae:       1}
# kernel-xen
%define with_xen       %{?_without_xen:       0} %{?!_without_xen:       1}
# kernel-kdump
%define with_kdump     %{?_without_kdump:     0} %{?!_without_kdump:     1}
# kernel-debug
%define with_debug     %{?_without_debug:     0} %{!?_without_debug:     1}
# kernel-doc
%define with_doc       %{?_without_doc:       0} %{?!_without_doc:       1}
# kernel-headers
%define with_headers   %{?_without_headers:   0} %{?!_without_headers:   1}
# kernel-debuginfo
%define with_debuginfo %{?_without_debuginfo: 0} %{!?_without_debuginfo: 1}

# Additional options for user-friendly one-off kernel building:
#
# Only build the base kernel (--with baseonly):
%define with_baseonly  %{?_with_baseonly:     1} %{?!_with_baseonly:     0}
# Only build the smp kernel (--with smponly):
%define with_smponly   %{?_with_smponly:      1} %{?!_with_smponly:      0}
# Only build the pae kernel (--with paeonly):
%define with_paeonly   %{?_with_paeonly:      1} %{?!_with_paeonly:      0}
# Only build the xen kernel (--with xenonly):
%define with_xenonly   %{?_with_xenonly:      1} %{?!_with_xenonly:      0}

# Whether or not to gpg sign modules
%define with_modsign   %{?_without_modsign:   0} %{?!_without_modsign:   1}

# Whether or not to do C=1 builds with sparse
%define usesparse 0
%if "%fedora" > "8"
%define usesparse 1
%endif

# Whether or not to apply the Xen patches -- leave this enabled
%define includexen 0
# Xen doesn't work with current upstream kernel, shut it off
%define with_xen 0

# Set debugbuildsenabled to 1 for production (build separate debug kernels)
#  and 0 for rawhide (all kernels are debug kernels).
# See also 'make debug' and 'make release'.
%define debugbuildsenabled 1

# Want to build a vanilla kernel build without any non-upstream patches?
# (well, almost none, we need nonintconfig for build purposes). Default to 0 (off).
%define with_vanilla %{?_with_vanilla: 1} %{?!_with_vanilla: 0}

# pkg_release is what we'll fill in for the rpm Release: field
%if 0%{?released_kernel}
%define pkg_release %{fedora_build}%{?buildid}%{?dist}
%else
%if 0%{?rcrev}
%define rctag .rc%rcrev
%endif
%if 0%{?gitrev}
%define gittag .git%gitrev
%if !0%{?rcrev}
%define rctag .rc0
%endif
%endif
%define pkg_release 0.%{fedora_build}%{?rctag}%{?gittag}%{?buildid}%{?dist}
%endif

# The kernel tarball/base version
%define kversion 2.6.%{base_sublevel}

%define make_target bzImage
%define kernel_image x86

%define xen_hv_cset 11633
%define xen_flags verbose=y crash_debug=y
%define xen_target vmlinuz
%define xen_image vmlinuz

%define KVERREL %{PACKAGE_VERSION}-%{PACKAGE_RELEASE}
%define hdrarch %_target_cpu

%if 0%{!?nopatches:1}
%define nopatches 0
%endif

%if %{with_vanilla}
%define nopatches 1
%endif

%if %{nopatches}
%define includexen 0
%define with_xen 0
%define variant -vanilla
%else
%define variant_fedora -fedora
%endif

%define using_upstream_branch 0
%if 0%{?upstream_branch:1}
%define using_upstream_branch 1
%define variant -%{upstream_branch}%{?variant_fedora}
%define pkg_release %{upstream_branch_release}.%{pkg_release}
%endif

%if !%{debugbuildsenabled}
%define with_debug 0
%endif

%if !%{with_debuginfo}
%define _enable_debug_packages 0
%endif
%define debuginfodir /usr/lib/debug

# if requested, only build base kernel
%if %{with_baseonly}
%define with_smp 0
%define with_pae 0
%define with_xen 0
%define with_kdump 0
%define with_debug 0
%endif

# if requested, only build smp kernel
%if %{with_smponly}
%define with_up 0
%define with_pae 0
%define with_xen 0
%define with_kdump 0
%define with_debug 0
%endif

# if requested, only build pae kernel
%if %{with_paeonly}
%define with_up 0
%define with_smp 0
%define with_xen 0
%define with_kdump 0
%define with_debug 0
%endif

# if requested, only build xen kernel
%if %{with_xenonly}
%define with_up 0
%define with_smp 0
%define with_pae 0
%define with_kdump 0
%define with_debug 0
%endif

%define all_x86 i386 i586 i686

# These arches install vdso/ directories.
%define vdso_arches %{all_x86} x86_64 ppc ppc64

# Overrides for generic default options

# only ppc and sparc64 need separate smp kernels
%ifnarch ppc sparc64 alphaev56
%define with_smp 0
%endif

# pae is only valid on i686
%ifnarch i686
%define with_pae 0
%endif

# xen only builds on i686, x86_64 and ia64
%ifnarch i686 x86_64 ia64
%define with_xen 0
%endif

# only build kernel-kdump on ppc64
# (no relocatable kernel support upstream yet)
%ifnarch ppc64
%define with_kdump 0
%endif

# don't do debug builds on anything but i686 and x86_64
%ifnarch i686 x86_64
%define with_debug 0
%endif

# only package docs noarch
%ifnarch noarch
%define with_doc 0
%endif

# no need to build headers again for these arches,
# they can just use i386 and ppc64 and sparc headers
%ifarch i586 i686 ppc64iseries sparc64
%define with_headers 0
%endif

# don't build noarch kernels or headers (duh)
%ifarch noarch
%define with_up 0
%define with_headers 0
%define all_arch_configs kernel-%{version}-*.config
%endif

# don't sign modules on these platforms
%ifarch s390x sparc64 ppc alpha
%define with_modsign 0
%endif

# sparse blows up on ppc64
%ifarch ppc64 ppc alpha sparc64
%define usesparse 0
%endif

# Per-arch tweaks

%ifarch %{all_x86}
%define all_arch_configs kernel-%{version}-i?86*.config
%define image_install_path boot
%define hdrarch i386
# we build always xen i686 HV with pae
%define xen_flags verbose=y crash_debug=y pae=y
%endif

%ifarch x86_64
%define all_arch_configs kernel-%{version}-x86_64*.config
%define image_install_path boot
%endif

%ifarch ppc64
%define all_arch_configs kernel-%{version}-ppc64*.config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%define kernel_image_elf 1
%define hdrarch powerpc
%endif

%ifarch s390x
%define all_arch_configs kernel-%{version}-s390x.config
%define image_install_path boot
%define make_target image
%define kernel_image arch/s390/boot/image
%define hdrarch s390
%endif

%ifarch sparc
# Yes, this is a hack. We want both sets of headers in the sparc.rpm
%define hdrarch sparc64
%endif

%ifarch sparc64
%define all_arch_configs kernel-%{version}-sparc64*.config
%define make_target image
%define kernel_image arch/sparc64/boot/image
%define image_install_path boot
%endif

%ifarch ppc
%define all_arch_configs kernel-%{version}-ppc{-,.}*config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%define kernel_image_elf 1
%define hdrarch powerpc
%endif

%ifarch ia64
%define all_arch_configs kernel-%{version}-ia64*.config
%define image_install_path boot/efi/EFI/redhat
%define make_target compressed
%define kernel_image vmlinux.gz
# ia64 xen HV doesn't building with debug=y at the moment
%define xen_flags verbose=y crash_debug=y
%define xen_target compressed
%define xen_image vmlinux.gz
%endif

%ifarch alpha alphaev56
%define all_arch_configs kernel-%{version}-alpha*.config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%endif

%if %{nopatches}
%define with_modsign 0
# XXX temporary until last vdso patches are upstream
%define vdso_arches %{nil}
%endif

%if %{nopatches}%{using_upstream_branch}
# Ignore unknown options in our config-* files.
# Some options go with patches we're not applying.
%define oldconfig_target loose_nonint_oldconfig
%else
%define oldconfig_target nonint_oldconfig
%endif

# To temporarily exclude an architecture from being built, add it to
# %nobuildarches. Do _NOT_ use the ExclusiveArch: line, because if we
# don't build kernel-headers then the new build system will no longer let
# us use the previous build of that package -- it'll just be completely AWOL.
# Which is a BadThing(tm).

# We don't build a kernel on i386; we only do kernel-headers there,
# and we no longer build for 31bit S390. Same for 32bit sparc.
%define nobuildarches i386 s390 sparc

%ifarch %nobuildarches
%define with_up 0
%define with_smp 0
%define with_pae 0
%define with_xen 0
%define with_kdump 0
%define with_debuginfo 0
%define _enable_debug_packages 0
%endif

%define with_pae_debug 0
%if %with_pae
%define with_pae_debug %{with_debug}
%endif

# TOMOYO Linux
%define with_modsign 0
%define _enable_debug_packages 0
%define with_debuginfo 0

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
%define package_conflicts initscripts < 7.23, udev < 063-6, iptables < 1.3.2-1, ipw2200-firmware < 2.4, selinux-policy-targeted < 1.25.3-14

#
# The ld.so.conf.d file we install uses syntax older ldconfig's don't grok.
#
%define kernel_xen_conflicts glibc < 2.3.5-1, xen < 3.0.1

# upto and including kernel 2.4.9 rpms, the 4Gb+ kernel was called kernel-enterprise
# now that the smp kernel offers this capability, obsolete the old kernel
%define kernel_smp_obsoletes kernel-enterprise < 2.4.10
%define kernel_PAE_obsoletes kernel-smp < 2.6.17

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 6.0.9-7

#
# This macro does requires, provides, conflicts, obsoletes for a kernel package.
#	%%kernel_reqprovconf <subpackage>
# It uses any kernel_<subpackage>_conflicts and kernel_<subpackage>_obsoletes
# macros defined above.
#
%define kernel_reqprovconf \
Provides: kernel = %{rpmversion}-%{pkg_release}\
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{pkg_release}%{?1}\
Provides: kernel-drm = 4.3.0\
Provides: kernel-drm-nouveau = 10\
Requires(pre): %{kernel_prereq}\
Conflicts: %{kernel_dot_org_conflicts}\
Conflicts: %{package_conflicts}\
%{?1:%{expand:%%{?kernel_%{1}_conflicts:Conflicts: %%{kernel_%{1}_conflicts}}}}\
%{?1:%{expand:%%{?kernel_%{1}_obsoletes:Obsoletes: %%{kernel_%{1}_obsoletes}}}}\
# We can't let RPM do the dependencies automatic because it'll then pick up\
# a correct but undesirable perl dependency from the module headers which\
# isn't required for the kernel proper to function\
AutoReq: no\
AutoProv: yes\
%{nil}

Name: ccs-kernel%{?variant}
Group: System Environment/Kernel
License: GPLv2
URL: http://www.kernel.org/
Version: %{rpmversion}
Release: %{pkg_release}_tomoyo_1.5.2
# DO NOT CHANGE THE 'ExclusiveArch' LINE TO TEMPORARILY EXCLUDE AN ARCHITECTURE BUILD.
# SET %%nobuildarches (ABOVE) INSTEAD
ExclusiveArch: noarch %{all_x86} x86_64 ppc ppc64 ia64 sparc sparc64 s390x alpha alphaev56
ExclusiveOS: Linux

%kernel_reqprovconf
%ifarch x86_64
Obsoletes: kernel-smp
%endif


#
# List the packages used during the kernel build
#
BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, sh-utils, tar
BuildRequires: bzip2, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
%if %{with_modsign}
BuildRequires: gnupg
%endif
BuildRequires: gcc >= 3.4.2, binutils >= 2.12, redhat-rpm-config
%if %{usesparse}
BuildRequires: sparse >= 0.3
%endif
BuildConflicts: rhbuildsys(DiskFree) < 500Mb

%define fancy_debuginfo 0
%if %{with_debuginfo}
%if "%fedora" > "7"
%define fancy_debuginfo 1
%endif
%endif

%if %{fancy_debuginfo}
# Fancy new debuginfo generation introduced in Fedora 8.
BuildRequires: rpm-build >= 4.4.2.1-4
%define debuginfo_args --strict-build-id
%endif

Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-%{kversion}.tar.bz2
#Source1: xen-%{xen_hv_cset}.tar.bz2
Source2: Config.mk

Source10: COPYING.modules
Source11: genkey
Source14: find-provides
Source15: merge.pl

Source20: Makefile.config
Source21: config-debug
Source22: config-nodebug
Source23: config-generic
Source24: config-xen-generic
Source25: config-rhel-generic
Source26: config-rhel-x86-generic

Source30: config-x86-generic
Source31: config-i586
Source32: config-i686
Source33: config-i686-PAE
Source34: config-xen-x86

Source40: config-x86_64-generic
Source41: config-xen-x86_64

Source50: config-powerpc-generic
Source51: config-powerpc32-generic
Source52: config-powerpc32-smp
Source53: config-powerpc64
Source54: config-powerpc64-kdump

Source60: config-ia64-generic
Source61: config-ia64
Source62: config-xen-ia64

Source70: config-s390x

Source90: config-sparc64-generic
Source91: config-sparc64
Source92: config-sparc64-smp

%if %{using_upstream_branch}
### BRANCH PATCH ###
%else
# Here should be only the patches up to the upstream canonical Linus tree.

# For a stable release kernel
%if 0%{?stable_update}
Patch00: patch-2.6.%{base_sublevel}.%{stable_update}.bz2

# non-released_kernel case
# These are automagically defined by the rcrev and gitrev values set up
# near the top of this spec file.
%else
%if 0%{?rcrev}
Patch00: patch-2.6.%{upstream_sublevel}-rc%{rcrev}.bz2
%if 0%{?gitrev}
Patch01: patch-2.6.%{upstream_sublevel}-rc%{rcrev}-git%{gitrev}.bz2
%endif
%else
# pre-{base_sublevel+1}-rc1 case
%if 0%{?gitrev}
Patch00: patch-2.6.%{base_sublevel}-git%{gitrev}.bz2
%endif
%endif
%endif

%endif

# -stable RC
Patch02: patch-2.6.23.9-rc1.bz2

%if !%{nopatches}

# revert upstream changes we get from elsewhere
Patch05: linux-2.6-upstream-reverts.patch

Patch19: linux-2.6-highres-timers.patch

Patch21: linux-2.6-utrace-tracehook.patch
Patch22: linux-2.6-utrace-tracehook-ia64.patch
Patch23: linux-2.6-utrace-tracehook-sparc64.patch
Patch24: linux-2.6-utrace-tracehook-s390.patch
Patch25: linux-2.6-utrace-tracehook-um.patch
Patch26: linux-2.6-utrace-tracehook-avr32.patch
Patch27: linux-2.6-utrace-regset.patch
Patch28: linux-2.6-utrace-regset-ia64.patch
Patch29: linux-2.6-utrace-regset-sparc64.patch
Patch30: linux-2.6-utrace-regset-s390.patch
Patch31: linux-2.6-utrace-regset-avr32.patch
Patch32: linux-2.6-utrace-core.patch
Patch33: linux-2.6-utrace-ptrace-compat.patch
Patch34: linux-2.6-utrace-ptrace-compat-ia64.patch
Patch35: linux-2.6-utrace-ptrace-compat-sparc64.patch
Patch36: linux-2.6-utrace-ptrace-compat-s390.patch
Patch37: linux-2.6-utrace-ptrace-compat-avr32.patch

Patch41: linux-2.6-sysrq-c.patch
Patch50: linux-2.6-ia64-build-id-linker-script-fix.patch
Patch60: linux-2.6-x86-tune-generic.patch
Patch61: linux-2.6-x86-setup-add-near-jump.patch
Patch70: linux-2.6-x86_64-silence-up-apic-errors.patch
Patch72: linux-2.6-x86-tsc-calibration-2.patch
Patch75: linux-2.6-x86-debug-boot.patch
Patch76: linux-2.6-x86-clean-up-oops-bug-reports.patch

Patch80: linux-2.6-alsa-1.0.15-merge-1.patch
Patch81: linux-2.6-alsa-1.0.15-merge-2.patch
Patch82: linux-2.6-alsa.git-000-771af442.patch
Patch83: linux-2.6-alsa.git-004-ba76a374.patch
Patch84: linux-2.6-alsa-hda-stac-dmic.patch
Patch85: linux-2.6-alsa-revert-hda-stac-volume.patch

Patch100: linux-2.6-g5-therm-shutdown.patch
Patch120: linux-2.6-ppc32-ucmpdi2.patch
Patch130: linux-2.6-ibmvscsi-schizo.patch
Patch131: linux-2.6-pmac-zilog.patch
Patch135: linux-2.6-powerpc-generic-suspend-2-remove-adb-sleep-notifier.patch
Patch136: linux-2.6-powerpc-generic-suspend-3-remove-dmasound.patch
Patch137: linux-2.6-powerpc-generic-suspend-4-kill-pmu-sleep-notifier.patch
Patch138: linux-2.6-powerpc-generic-suspend-5-pmu-pm_ops.patch
Patch140: linux-2.6-ppc-pegasos-via-ata-legacy-irq.patch
Patch141: linux-2.6-ppc-fix-dso-unwind.patch

Patch150: linux-2.6-build-nonintconfig.patch
Patch160: linux-2.6-execshield.patch
Patch170: linux-2.6-modsign-mpilib.patch
Patch180: linux-2.6-modsign-crypto.patch
Patch190: linux-2.6-modsign-include.patch
Patch200: linux-2.6-modsign-verify.patch
Patch210: linux-2.6-modsign-ksign.patch
Patch220: linux-2.6-modsign-core.patch
Patch230: linux-2.6-modsign-script.patch
Patch240: linux-2.6-modules-modalias-platform.patch
Patch250: linux-2.6-debug-sizeof-structs.patch
Patch260: linux-2.6-debug-nmi-timeout.patch
Patch270: linux-2.6-debug-taint-vm.patch
Patch280: linux-2.6-debug-spinlock-taint.patch
Patch330: linux-2.6-debug-no-quiet.patch
Patch340: linux-2.6-debug-boot-delay.patch
Patch345: linux-2.6-debug-acpi-os-write-port.patch
Patch350: linux-2.6-devmem.patch
Patch370: linux-2.6-crash-driver.patch

Patch380: linux-2.6-irq-synchronization.patch

Patch400: linux-2.6-scsi-cpqarray-set-master.patch
Patch401: linux-2.6-scsi-async-double-add.patch
Patch402: linux-2.6-scsi-mpt-vmware-fix.patch

Patch420: linux-2.6-squashfs.patch
Patch423: linux-2.6-gfs-locking-exports.patch
Patch424: linux-2.6-cifs-fix-incomplete-rcv.patch
Patch425: linux-2.6-cifs-typo-in-cifs_reconnect-fix.patch
Patch426: linux-2.6-cifs-fix-bad-handling-of-EAGAIN.patch

Patch430: linux-2.6-net-silence-noisy-printks.patch
Patch431: linux-2.6-netfilter-fix-null-deref-nf_nat_move_storage.patch
Patch440: linux-2.6-sha_alignment.patch
Patch450: linux-2.6-input-kill-stupid-messages.patch
Patch451: linux-2.6-input-alps-add-dell-vostro-1400.patch
Patch452: linux-2.6-input-alps-add-thinkpad-r61.patch
Patch460: linux-2.6-serial-460800.patch
Patch461: linux-2.6-serial_pnp-add-new-wacom-ids.patch
Patch480: linux-2.6-proc-self-maps-fix.patch
Patch510: linux-2.6-silence-noise.patch
Patch570: linux-2.6-selinux-mprotect-checks.patch
Patch590: linux-2.6-unexport-symbols.patch
Patch600: linux-2.6-vm-silence-atomic-alloc-failures.patch
Patch602: linux-2.6-mm-fix-ptrace-access-beyond-vma.patch
Patch603: linux-2.6-dio-fix-cache-invalidation-after-sync-writes.patch

Patch610: linux-2.6-defaults-fat-utf8.patch
Patch620: linux-2.6-defaults-unicode-vt.patch
Patch630: linux-2.6-defaults-nonmi.patch
Patch640: linux-2.6-defaults-nommconf.patch
Patch660: linux-2.6-libata-ali-atapi-dma.patch
Patch661: linux-2.6-libata-acpi-enable.patch
Patch662: linux-2.6-libata-add-dma-disable-option.patch
Patch665: linux-2.6-libata-dont-fail-revalidation-for-bad-gtf-methods.patch
Patch666: linux-2.6-libata-pata_serverworks-fix-drive-combinations.patch
Patch670: linux-2.6-ata-quirk.patch
Patch680: linux-2.6-wireless.patch
Patch681: linux-2.6-wireless-pending.patch
Patch690: linux-2.6-at76.patch
Patch691: linux-2.6-ath5k.patch
Patch692: linux-2.6-zd1211rw-mac80211.patch
Patch693: linux-2.6-rtl8180.patch
Patch694: linux-2.6-b43-rev-d.patch
Patch700: linux-2.6-cfg80211-extras.patch
Patch710: linux-2.6-netdev-e1000e-01.patch
Patch711: linux-2.6-netdev-e1000e-02.patch
Patch712: linux-2.6-netdev-e1000e-03.patch
Patch713: linux-2.6-netdev-e1000e-04.patch
Patch714: linux-2.6-netdev-e1000e-05.patch
Patch715: linux-2.6-netdev-e1000e-06.patch
Patch716: linux-2.6-netdev-e1000e-07.patch
Patch717: linux-2.6-netdev-e1000e-08.patch
Patch718: linux-2.6-netdev-e1000e-09.patch
Patch719: linux-2.6-netdev-e1000e-10.patch
Patch720: linux-2.6-e1000-bad-csum-allow.patch
Patch730: linux-2.6-netdev-spidernet-fix-interrupt-handling.patch
#Patch780: linux-2.6-clockevents-fix-resume-logic.patch
Patch750: linux-2.6-acpi-git-ec-init-fixes.patch
Patch770: linux-2.6-pmtrace-time-fix.patch
Patch800: linux-2.6-wakeups-hdaps.patch
Patch801: linux-2.6-wakeups.patch
Patch820: linux-2.6-compile-fixes.patch
Patch1100: linux-2.6-add-mmf_dump_elf_headers.patch
Patch1101: linux-2.6-default-mmf_dump_elf_headers.patch
Patch1102: linux-2.6-add-sys-module-name-notes.patch
Patch1103: linux-2.6-i386-vdso-install-unstripped-copies-on-disk.patch
Patch1105: linux-2.6-powerpc-vdso-install-unstripped-copies-on-disk.patch
Patch1106: linux-2.6-x86_64-ia32-vdso-install-unstripped-copies-on-disk.patch
Patch1107: linux-2.6-x86_64-vdso-install-unstripped-copies-on-disk.patch
Patch1108: linux-2.6-pass-g-to-assembler-under-config_debug_info.patch
Patch1109: linux-2.6-powerpc-lparmap-g.patch
Patch1200: linux-2.6-ps3-ehci-iso.patch
Patch1210: linux-2.6-ps3-storage-alias.patch
Patch1220: linux-2.6-ps3-legacy-bootloader-hack.patch
Patch1230: linux-2.6-powerpc-spu-vicinity.patch

Patch1300: linux-2.6-usb-suspend-classes.patch
Patch1305: linux-2.6-usb-storage-initialize-huawei-e220-properly.patch
Patch1400: linux-2.6-smarter-relatime.patch
Patch1503: linux-2.6-xfs-optimize-away-dmapi-tests.patch
Patch1504: linux-2.6-xfs-optimize-away-realtime-tests.patch
Patch1505: linux-2.6-xfs-refactor-xfs_mountfs.patch
Patch1509: linux-2.6-xfs-setfattr-32bit-compat.patch
Patch1512: linux-2.6-firewire-multi-lun.patch
Patch1515: linux-2.6-lirc.patch
Patch1520: linux-2.6-dcdbas-autoload.patch

Patch1610: linux-2.6-pci-dont-size-transparent-bridges.patch

#nouveau + drm fixes
Patch1800: drm-mm-git.patch
Patch1801: nouveau-drm.patch

# Fix lockdep bug in firewire.
Patch1900: linux-2.6-firewire-lockdep.patch
# OHCI 1.0 isochronous receive support
Patch1910: linux-2.6-firewire-ohci-1.0-iso-receive.patch
# Work around E100 NAPI bug
Patch2000: linux-2.6-net-e100-disable-polling.patch
# fix thinkpad key events for volume/brightness
Patch2100: linux-2.6-thinkpad-key-events.patch
# SELinux performance patches
Patch2200: linux-2.6-selinux-no-revalidate-read-write.patch
Patch2201: linux-2.6-selinux-ebitmap-for-avc-miss.patch
Patch2202: linux-2.6-selinux-ebitmap-for-avc-miss-cleanup.patch
Patch2203: linux-2.6-selinux-sigchld-wait.patch
Patch2204: linux-2.6-selinux-ebitmap-loop-bug.patch

%endif

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root-%{_target_cpu}

%description
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.


%package doc
Summary: Various documentation bits found in the kernel source
Group: Documentation
%description doc
This package contains documentation files from the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files.

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.


%package headers
Summary: Header files for the Linux kernel for use by glibc
Group: Development/System
Obsoletes: glibc-kernheaders
Provides: glibc-kernheaders = 3.0-46
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.


%package debuginfo-common
Summary: Kernel source files used by %{name}-debuginfo packages
Group: Development/Debug
Provides: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
%description debuginfo-common
This package is required by %{name}-debuginfo subpackages.
It provides the kernel source files common to all builds.


#
# This macro creates a kernel-<subpackage>-debuginfo package.
#	%%kernel_debuginfo_package <subpackage>
#
%define kernel_debuginfo_package() \
%package %{?1:%{1}-}debuginfo\
Summary: Debug information for package %{name}%{?1:-%{1}}\
Group: Development/Debug\
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}\
Provides: %{name}%{?1:-%{1}}-debuginfo-%{_target_cpu} = %{KVERREL}\
AutoReqProv: no\
%description -n %{name}%{?1:-%{1}}-debuginfo\
This package provides debug information for package %{name}%{?1:-%{1}}.\
This is required to use SystemTap with %{name}%{?1:-%{1}}-%{KVERREL}.\
%{expand:%%global debuginfo_args %{?debuginfo_args} -p '/.*/%%{KVERREL}%{?1:-?%{1}}(-%%{_target_cpu})?/.*|/.*%%{KVERREL}%{?1}' -o debuginfo%{?1}.list}\
%{nil}

#
# This macro creates a kernel-<subpackage>-devel package.
#	%%kernel_devel_package <subpackage> <pretty-name>
#
%define kernel_devel_package() \
%package %{?1:%{1}-}devel\
Summary: Development package for building kernel modules to match the %{?2:%{2} }kernel\
Group: System Environment/Kernel\
Provides: kernel%{?1:-%{1}}-devel-%{_target_cpu} = %{rpmversion}-%{release}\
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}%{?1}\
Provides: kernel-devel = %{rpmversion}-%{release}%{?1}\
AutoReqProv: no\
Requires(pre): /usr/bin/find\
%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
This package provides kernel headers and makefiles sufficient to build modules\
against the %{?2:%{2} }kernel package.\
%{nil}

#
# This macro creates a kernel-<subpackage> and its -devel and -debuginfo too.
#	%%define variant_summary The Linux kernel compiled for <configuration>
#	%%kernel_variant_package [-n <pretty-name>] <subpackage>
#
%define kernel_variant_package(n:) \
%package %1\
Summary: %{variant_summary}\
Group: System Environment/Kernel\
%kernel_reqprovconf\
%{expand:%%kernel_devel_package %1 %{!?-n:%1}%{?-n:%{-n*}}}\
%{expand:%%kernel_debuginfo_package %1}\
%{nil}


# First the auxiliary packages of the main kernel package.
%kernel_devel_package
%kernel_debuginfo_package


# Now, each variant package.

%define variant_summary The Linux kernel compiled for SMP machines
%kernel_variant_package -n SMP smp
%description smp
This package includes a SMP version of the Linux kernel. It is
required only on machines with two or more CPUs as well as machines with
hyperthreading technology.

Install the kernel-smp package if your machine uses two or more CPUs.


%define variant_summary The Linux kernel compiled for PAE capable machines
%kernel_variant_package PAE
%description PAE
This package includes a version of the Linux kernel with support for up to
64GB of high memory. It requires a CPU with Physical Address Extensions (PAE).
The non-PAE kernel can only address up to 4GB of memory.
Install the kernel-PAE package if your machine has more than 4GB of memory.


%define variant_summary The Linux kernel compiled with extra debugging enabled for PAE capable machines
%kernel_variant_package PAE-debug
%description PAE-debug
This package includes a version of the Linux kernel with support for up to
64GB of high memory. It requires a CPU with Physical Address Extensions (PAE).
The non-PAE kernel can only address up to 4GB of memory.
Install the kernel-PAE package if your machine has more than 4GB of memory.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.


%define variant_summary The Linux kernel compiled with extra debugging enabled
%kernel_variant_package debug
%description debug
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.


%define variant_summary The Linux kernel compiled for Xen VM operations
%kernel_variant_package -n Xen xen
%description xen
This package includes a version of the Linux kernel which
runs in a Xen VM. It works for both privileged and unprivileged guests.


%define variant_summary A minimal Linux kernel compiled for crash dumps
%kernel_variant_package kdump
%description kdump
This package includes a kdump version of the Linux kernel. It is
required only on machines which will use the kexec-based kernel crash dump
mechanism.


%prep
# do a few sanity-checks for --with *only builds
%if %{with_baseonly}
%if !%{with_up}
echo "Cannot build --with baseonly, up build is disabled"
exit 1
%endif
%endif

%if %{with_smponly}
%if !%{with_smp}
echo "Cannot build --with smponly, smp build is disabled"
exit 1
%endif
%endif

%if %{with_paeonly}
%if !%{with_pae}
echo "Cannot build --with paeonly, pae build is disabled"
exit 1
%endif
%endif

%if %{with_xenonly}
%if !%{with_xen}
echo "Cannot build --with xenonly, xen build is disabled"
exit 1
%endif
%endif

# First we unpack the kernel tarball.
# If this isn't the first make prep, we use links to the existing clean tarball
# which speeds things up quite a bit.
if [ ! -d kernel-%{kversion}/vanilla ]; then
  # Ok, first time we do a make prep.
  rm -f pax_global_header
%setup -q -n kernel-%{kversion} -c
  mv linux-%{kversion} vanilla
else
  # We already have a vanilla dir.
  cd kernel-%{kversion}
  if [ -d linux-%{kversion}.%{_target_cpu} ]; then
     # Just in case we ctrl-c'd a prep already
     rm -rf deleteme.%{_target_cpu}
     # Move away the stale away, and delete in background.
     mv linux-%{kversion}.%{_target_cpu} deleteme.%{_target_cpu}
     rm -rf deleteme.%{_target_cpu} &
  fi
fi

cp -rl vanilla linux-%{kversion}.%{_target_cpu}

cd linux-%{kversion}.%{_target_cpu}

# Drop some necessary files from the source dir into the buildroot
cp $RPM_SOURCE_DIR/config-* .
cp %{SOURCE15} .

# Dynamically generate kernel .config files from config-* files
make -f %{SOURCE20} VERSION=%{version} configs

#if a rhel kernel, apply the rhel config options
%if 0%{?rhel}
  for i in %{all_arch_configs}
  do
    mv $i $i.tmp
    ./merge.pl config-rhel-generic $i.tmp > $i
    rm $i.tmp
  done
  for i in kernel-%{version}-{i586,i686,i686-PAE,x86_64}*.config
  do
    echo i is this file  $i
    mv $i $i.tmp
    ./merge.pl config-rhel-x86-generic $i.tmp > $i
    rm $i.tmp
  done
%endif

patch_command='patch -p1 -F1 -s'
ApplyPatch()
{
  local patch=$1
  shift
  if [ ! -f $RPM_SOURCE_DIR/$patch ]; then
    exit 1;
  fi
  case "$patch" in
  *.bz2) bunzip2 < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *.gz) gunzip < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *) $patch_command ${1+"$@"} < "$RPM_SOURCE_DIR/$patch" ;;
  esac
}

%if %{using_upstream_branch}
### BRANCH APPLY ###
%else

# Update to latest upstream.
# released_kernel with stable_update available case
%if 0%{?stable_update}
ApplyPatch patch-2.6.%{base_sublevel}.%{stable_update}.bz2

# non-released_kernel case
%else
%if 0%{?rcrev}
ApplyPatch patch-2.6.%{upstream_sublevel}-rc%{rcrev}.bz2
%if 0%{?gitrev}
ApplyPatch patch-2.6.%{upstream_sublevel}-rc%{rcrev}-git%{gitrev}.bz2
%endif
%else
# pre-{base_sublevel+1}-rc1 case
%if 0%{?gitrev}
ApplyPatch patch-2.6.%{base_sublevel}-git%{gitrev}.bz2
%endif
%endif
%endif

%endif

# -stable RC
ApplyPatch patch-2.6.23.9-rc1.bz2

# This patch adds a "make nonint_oldconfig" which is non-interactive and
# also gives a list of missing options at the end. Useful for automated
# builds (as used in the buildsystem).
ApplyPatch linux-2.6-build-nonintconfig.patch

%if !%{nopatches}

# Revert -stable pieces we get from elsewhere here
ApplyPatch linux-2.6-upstream-reverts.patch -R

# patch-2.6.23-hrt3.patch
ApplyPatch linux-2.6-highres-timers.patch

# Roland's utrace ptrace replacement.
# Main patch includes i386, x86_64, powerpc.
ApplyPatch linux-2.6-utrace-tracehook.patch
# Additional arch work by other contributors.
ApplyPatch linux-2.6-utrace-tracehook-ia64.patch
ApplyPatch linux-2.6-utrace-tracehook-sparc64.patch
ApplyPatch linux-2.6-utrace-tracehook-s390.patch
ApplyPatch linux-2.6-utrace-tracehook-um.patch
ApplyPatch linux-2.6-utrace-tracehook-avr32.patch
# Main patch includes i386, x86_64, powerpc.
ApplyPatch linux-2.6-utrace-regset.patch
# Additional arch work by other contributors.
ApplyPatch linux-2.6-utrace-regset-ia64.patch
ApplyPatch linux-2.6-utrace-regset-sparc64.patch
ApplyPatch linux-2.6-utrace-regset-s390.patch
ApplyPatch linux-2.6-utrace-regset-avr32.patch
# Core patch has no machine dependencies.
ApplyPatch linux-2.6-utrace-core.patch
# Main patch includes i386, x86_64, powerpc.
ApplyPatch linux-2.6-utrace-ptrace-compat.patch
# Additional arch work by other contributors.
ApplyPatch linux-2.6-utrace-ptrace-compat-ia64.patch
ApplyPatch linux-2.6-utrace-ptrace-compat-sparc64.patch
ApplyPatch linux-2.6-utrace-ptrace-compat-s390.patch
ApplyPatch linux-2.6-utrace-ptrace-compat-avr32.patch

# setuid /proc/self/maps fix. (dependent on utrace)
ApplyPatch linux-2.6-proc-self-maps-fix.patch

# ALSA 1.0.15
ApplyPatch linux-2.6-alsa-1.0.15-merge-1.patch
ApplyPatch linux-2.6-alsa-1.0.15-merge-2.patch
# ALSA updates headed upstream for 2.6.24
ApplyPatch linux-2.6-alsa.git-000-771af442.patch
ApplyPatch linux-2.6-alsa.git-004-ba76a374.patch
# undo the STAC volume control update
ApplyPatch linux-2.6-alsa-revert-hda-stac-volume.patch
# ALSA enhancments for 2.6.25
ApplyPatch linux-2.6-alsa-hda-stac-dmic.patch

# Nouveau DRM + drm fixes
ApplyPatch drm-mm-git.patch
ApplyPatch nouveau-drm.patch

# enable sysrq-c on all kernels, not only kexec
ApplyPatch linux-2.6-sysrq-c.patch

# Architecture patches
# IA64
ApplyPatch linux-2.6-ia64-build-id-linker-script-fix.patch
# x86(-64)
# Compile 686 kernels tuned for Pentium4.
ApplyPatch linux-2.6-x86-tune-generic.patch
# x86: fix boot on 486
ApplyPatch linux-2.6-x86-setup-add-near-jump.patch
# Suppress APIC errors on UP x86-64.
#ApplyPatch linux-2.6-x86_64-silence-up-apic-errors.patch
# fix x86 tsc clock calibration
ApplyPatch linux-2.6-x86-tsc-calibration-2.patch
# debug early boot
#ApplyPatch linux-2.6-x86-debug-boot.patch
# shorter i386 oops reports (scheduled for 2.6.24)
ApplyPatch linux-2.6-x86-clean-up-oops-bug-reports.patch

#
# PowerPC
#
# Alleviate G5 thermal shutdown problems
ApplyPatch linux-2.6-g5-therm-shutdown.patch
# Temporary hack to work around GCC PR #25724 / #21237
ApplyPatch linux-2.6-ppc32-ucmpdi2.patch
# Fix up ibmvscsi for combined pSeries/iSeries build
ApplyPatch linux-2.6-ibmvscsi-schizo.patch
# Move pmac_zilog to its newly-registered device number
ApplyPatch linux-2.6-pmac-zilog.patch
# PlayStation support
ApplyPatch linux-2.6-ps3-ehci-iso.patch
ApplyPatch linux-2.6-ps3-storage-alias.patch
ApplyPatch linux-2.6-ps3-legacy-bootloader-hack.patch
#ApplyPatch linux-2.6-powerpc-spu-vicinity.patch
# Suspend through /sys/power/state
ApplyPatch linux-2.6-powerpc-generic-suspend-2-remove-adb-sleep-notifier.patch
ApplyPatch linux-2.6-powerpc-generic-suspend-3-remove-dmasound.patch
ApplyPatch linux-2.6-powerpc-generic-suspend-4-kill-pmu-sleep-notifier.patch
ApplyPatch linux-2.6-powerpc-generic-suspend-5-pmu-pm_ops.patch
# pegasos IDE
ApplyPatch linux-2.6-ppc-pegasos-via-ata-legacy-irq.patch
# fix unwind
ApplyPatch linux-2.6-ppc-fix-dso-unwind.patch

# Exec shield
ApplyPatch linux-2.6-execshield.patch

#
# GPG signed kernel modules
#
ApplyPatch linux-2.6-modsign-mpilib.patch
ApplyPatch linux-2.6-modsign-crypto.patch
ApplyPatch linux-2.6-modsign-include.patch
ApplyPatch linux-2.6-modsign-verify.patch
ApplyPatch linux-2.6-modsign-ksign.patch
ApplyPatch linux-2.6-modsign-core.patch
ApplyPatch linux-2.6-modsign-script.patch

#
# bugfixes to drivers and filesystems
#
# pc speaker autoload
ApplyPatch linux-2.6-modules-modalias-platform.patch

# Various low-impact patches to aid debugging.
ApplyPatch linux-2.6-debug-sizeof-structs.patch
ApplyPatch linux-2.6-debug-nmi-timeout.patch
ApplyPatch linux-2.6-debug-taint-vm.patch
ApplyPatch linux-2.6-debug-spinlock-taint.patch
%if !%{debugbuildsenabled}
ApplyPatch linux-2.6-debug-no-quiet.patch
%endif
ApplyPatch linux-2.6-debug-boot-delay.patch
# try to find out what is breaking acpi-cpufreq
ApplyPatch linux-2.6-debug-acpi-os-write-port.patch

#
# Make /dev/mem a need-to-know function
#
ApplyPatch linux-2.6-devmem.patch

#
# /dev/crash driver for the crashdump analysis tool
#
ApplyPatch linux-2.6-crash-driver.patch

#
# driver core
#
# synchronize irqs poperly
ApplyPatch linux-2.6-irq-synchronization.patch
# don't resize transparent bridges
ApplyPatch linux-2.6-pci-dont-size-transparent-bridges.patch

#
# SCSI Bits.
#
# fix cpqarray pci enable
ApplyPatch linux-2.6-scsi-cpqarray-set-master.patch
# Fix async scanning double-add problems
ApplyPatch linux-2.6-scsi-async-double-add.patch
# fix vmware emulated scsi controller
ApplyPatch linux-2.6-scsi-mpt-vmware-fix.patch

# Filesystem patches.
# Squashfs
ApplyPatch linux-2.6-squashfs.patch
# export symbols for gfs2 locking modules
ApplyPatch linux-2.6-gfs-locking-exports.patch
# cifs kernel memory corruption fixes
ApplyPatch linux-2.6-cifs-fix-incomplete-rcv.patch
ApplyPatch linux-2.6-cifs-typo-in-cifs_reconnect-fix.patch
ApplyPatch linux-2.6-cifs-fix-bad-handling-of-EAGAIN.patch

# Networking
# Disable easy to trigger printk's.
ApplyPatch linux-2.6-net-silence-noisy-printks.patch
# fix oops in netfilter
ApplyPatch linux-2.6-netfilter-fix-null-deref-nf_nat_move_storage.patch

# Misc fixes
# Fix SHA1 alignment problem on ia64
ApplyPatch linux-2.6-sha_alignment.patch
# The input layer spews crap no-one cares about.
ApplyPatch linux-2.6-input-kill-stupid-messages.patch
# Add support for some new mouse configurations
ApplyPatch linux-2.6-input-alps-add-dell-vostro-1400.patch
ApplyPatch linux-2.6-input-alps-add-thinkpad-r61.patch
# Allow to use 480600 baud on 16C950 UARTs
ApplyPatch linux-2.6-serial-460800.patch
# add ids for new wacom tablets
ApplyPatch linux-2.6-serial_pnp-add-new-wacom-ids.patch

# Silence some useless messages that still get printed with 'quiet'
ApplyPatch linux-2.6-silence-noise.patch

# Fix the SELinux mprotect checks on executable mappings
ApplyPatch linux-2.6-selinux-mprotect-checks.patch

# Remove kernel-internal functionality that nothing external should use.
ApplyPatch linux-2.6-unexport-symbols.patch

#
# VM related fixes.
#
# Silence GFP_ATOMIC failures.
ApplyPatch linux-2.6-vm-silence-atomic-alloc-failures.patch
# fix ptrace hang trying to access invalid memory location
ApplyPatch linux-2.6-mm-fix-ptrace-access-beyond-vma.patch
# fix read after direct IO write returning stale data
ApplyPatch linux-2.6-dio-fix-cache-invalidation-after-sync-writes.patch

# Changes to upstream defaults.
# Use UTF-8 by default on VFAT.
ApplyPatch linux-2.6-defaults-fat-utf8.patch
# Use unicode VT's by default.
ApplyPatch linux-2.6-defaults-unicode-vt.patch
# Disable NMI watchdog by default.
ApplyPatch linux-2.6-defaults-nonmi.patch
# Disable PCI MMCONFIG by default.
ApplyPatch linux-2.6-defaults-nommconf.patch

# Disable ATAPI DMA on ALI chipsets.
ApplyPatch linux-2.6-libata-ali-atapi-dma.patch
# ia64 ata quirk
ApplyPatch linux-2.6-ata-quirk.patch
# Enable ACPI ATA objects
ApplyPatch linux-2.6-libata-acpi-enable.patch
# add option to disable PATA DMA
ApplyPatch linux-2.6-libata-add-dma-disable-option.patch
# fix resume failure on some systems
ApplyPatch linux-2.6-libata-dont-fail-revalidation-for-bad-gtf-methods.patch
# serverworks is broken with some drive combinations
ApplyPatch linux-2.6-libata-pata_serverworks-fix-drive-combinations.patch

# wireless patches headed for 2.6.24
ApplyPatch linux-2.6-wireless.patch
# wireless patches staged for 2.6.25
ApplyPatch linux-2.6-wireless-pending.patch

# Add misc wireless bits from upstream wireless tree
ApplyPatch linux-2.6-at76.patch
ApplyPatch linux-2.6-ath5k.patch
ApplyPatch linux-2.6-zd1211rw-mac80211.patch
ApplyPatch linux-2.6-rtl8180.patch
ApplyPatch linux-2.6-b43-rev-d.patch

# Restore ability to add/remove virtual i/fs to mac80211 devices
ApplyPatch linux-2.6-cfg80211-extras.patch

# latest Intel driver for ich9
ApplyPatch linux-2.6-netdev-e1000e-01.patch
ApplyPatch linux-2.6-netdev-e1000e-02.patch
ApplyPatch linux-2.6-netdev-e1000e-03.patch
ApplyPatch linux-2.6-netdev-e1000e-04.patch
ApplyPatch linux-2.6-netdev-e1000e-05.patch
ApplyPatch linux-2.6-netdev-e1000e-06.patch
ApplyPatch linux-2.6-netdev-e1000e-07.patch
ApplyPatch linux-2.6-netdev-e1000e-08.patch
ApplyPatch linux-2.6-netdev-e1000e-09.patch
ApplyPatch linux-2.6-netdev-e1000e-10.patch

# Workaround for flaky e1000 EEPROMs
ApplyPatch linux-2.6-e1000-bad-csum-allow.patch
# spidernet: fix interrupt handling
ApplyPatch linux-2.6-netdev-spidernet-fix-interrupt-handling.patch

# ACPI/PM patches
# fix EC init
ApplyPatch linux-2.6-acpi-git-ec-init-fixes.patch
# fix date/time display when using PM_TRACE
ApplyPatch linux-2.6-pmtrace-time-fix.patch

# Fix excessive wakeups
# Make hdaps timer only tick when in use.
ApplyPatch linux-2.6-wakeups-hdaps.patch
ApplyPatch linux-2.6-wakeups.patch

# dm / md

# ACPI

# USB
# Do USB suspend only on certain classes of device.
ApplyPatch linux-2.6-usb-suspend-classes.patch
# initialize strange modem/storage device properly (from F7 kernel)
ApplyPatch linux-2.6-usb-storage-initialize-huawei-e220-properly.patch

# implement smarter atime updates support.
ApplyPatch linux-2.6-smarter-relatime.patch

# xfs bugfixes & stack reduction
ApplyPatch linux-2.6-xfs-optimize-away-dmapi-tests.patch
ApplyPatch linux-2.6-xfs-optimize-away-realtime-tests.patch
ApplyPatch linux-2.6-xfs-refactor-xfs_mountfs.patch
ApplyPatch linux-2.6-xfs-setfattr-32bit-compat.patch

#
# misc small stuff to make things compile
#

C=$(wc -l $RPM_SOURCE_DIR/linux-2.6-compile-fixes.patch | awk '{print $1}')
if [ "$C" -gt 10 ]; then
ApplyPatch linux-2.6-compile-fixes.patch
fi

# build id related enhancements
ApplyPatch linux-2.6-add-mmf_dump_elf_headers.patch
ApplyPatch linux-2.6-default-mmf_dump_elf_headers.patch
ApplyPatch linux-2.6-add-sys-module-name-notes.patch
ApplyPatch linux-2.6-i386-vdso-install-unstripped-copies-on-disk.patch
ApplyPatch linux-2.6-powerpc-vdso-install-unstripped-copies-on-disk.patch
ApplyPatch linux-2.6-x86_64-ia32-vdso-install-unstripped-copies-on-disk.patch
ApplyPatch linux-2.6-x86_64-vdso-install-unstripped-copies-on-disk.patch
ApplyPatch linux-2.6-pass-g-to-assembler-under-config_debug_info.patch
ApplyPatch linux-2.6-powerpc-lparmap-g.patch

#
# The multi-lun patch fixes #242254, but won't be in 2.6.23.
#
ApplyPatch linux-2.6-firewire-multi-lun.patch

# http://www.lirc.org/
ApplyPatch linux-2.6-lirc.patch

# DMI autoloading for dcdbas driver
ApplyPatch linux-2.6-dcdbas-autoload.patch

ApplyPatch linux-2.6-firewire-lockdep.patch
ApplyPatch linux-2.6-firewire-ohci-1.0-iso-receive.patch
ApplyPatch linux-2.6-net-e100-disable-polling.patch
ApplyPatch linux-2.6-thinkpad-key-events.patch

# ---------- below all scheduled for 2.6.24 -----------------

# SELinux perf patches
ApplyPatch linux-2.6-selinux-no-revalidate-read-write.patch
ApplyPatch linux-2.6-selinux-ebitmap-for-avc-miss.patch
ApplyPatch linux-2.6-selinux-ebitmap-for-avc-miss-cleanup.patch
ApplyPatch linux-2.6-selinux-sigchld-wait.patch
ApplyPatch linux-2.6-selinux-ebitmap-loop-bug.patch

# TOMOYO Linux
# wget -qO - 'http://svn.sourceforge.jp/cgi-bin/viewcvs.cgi/trunk/1.5.x/ccs-patch.tar.gz?root=tomoyo&view=tar' | tar -zxf -; tar -cf - -C ccs-patch/ . | tar -xf -; rm -fR ccs-patch/
tar -zxf %_sourcedir/ccs-patch-1.5.2-20071205.tar.gz
sed -i -e 's:EXTRAVERSION =.*:EXTRAVERSION = .8-63.fc8:' -- Makefile
patch -sp1 < patches/ccs-patch-2.6.23.8-63.fc8.diff

# END OF PATCH APPLICATIONS

%endif

# Any further pre-build tree manipulations happen here.

chmod +x scripts/checkpatch.pl

cp %{SOURCE10} Documentation/

mkdir configs

# Remove configs not for the buildarch
for cfg in kernel-%{version}-*.config; do
  if [ `echo %{all_arch_configs} | grep -c $cfg` -eq 0 ]; then
    rm -f $cfg
  fi
done

%if !%{with_debug}
rm -f kernel-%{version}-*-debug.config
%endif

# now run oldconfig over all the config files
for i in *.config
do
  mv $i .config
  # TOMOYO Linux
  cat config.ccs >> .config
  sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- .config
  Arch=`head -1 .config | cut -b 3-`
  make ARCH=$Arch %{oldconfig_target} > /dev/null
  echo "# $Arch" > configs/$i
  cat .config >> configs/$i
done

# get rid of unwanted files resulting from patch fuzz
find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null

cd ..

# Unpack the Xen tarball.
%if %{includexen}
cp %{SOURCE2} .
if [ -d xen ]; then
  rm -rf xen
fi
%setup -D -T -q -n kernel-%{version} -a1
cd xen
# Any necessary hypervisor patches go here

%endif


###
### build
###
%build

%if %{usesparse}
%define sparse_mflags	C=1
%endif

#
# Create gpg keys for signing the modules
#
%if %{with_modsign}
gpg --homedir . --batch --gen-key %{SOURCE11}
gpg --homedir . --export --keyring ./kernel.pub Red > extract.pub
make linux-%{kversion}.%{_target_cpu}/scripts/bin2c
linux-%{kversion}.%{_target_cpu}/scripts/bin2c ksign_def_public_key __initdata < extract.pub > linux-%{kversion}.%{_target_cpu}/crypto/signature/key.h
%endif

%if %{fancy_debuginfo}
# This override tweaks the kernel makefiles so that we run debugedit on an
# object before embedding it.  When we later run find-debuginfo.sh, it will
# run debugedit again.  The edits it does change the build ID bits embedded
# in the stripped object, but repeating debugedit is a no-op.  We do it
# beforehand to get the proper final build ID bits into the embedded image.
# This affects the vDSO images in vmlinux, and the vmlinux image in bzImage.
idhack='cmd_objcopy=$(if $(filter -S,$(OBJCOPYFLAGS)),'\
'sh -xc "/usr/lib/rpm/debugedit -b $$RPM_BUILD_DIR -d /usr/src/debug -i $<";)'\
'$(OBJCOPY) $(OBJCOPYFLAGS) $(OBJCOPYFLAGS_$(@F)) $< $@'
%endif

BuildKernel() {
    MakeTarget=$1
    KernelImage=$2
    Flavour=$3

    # Pick the right config file for the kernel we're building
    if [ -n "$Flavour" ] ; then
      Config=kernel-%{version}-%{_target_cpu}-$Flavour.config
      DevelDir=/usr/src/kernels/%{KVERREL}-$Flavour-%{_target_cpu}
      DevelLink=/usr/src/kernels/%{KVERREL}$Flavour-%{_target_cpu}
    else
      Config=kernel-%{version}-%{_target_cpu}.config
      DevelDir=/usr/src/kernels/%{KVERREL}-%{_target_cpu}
      DevelLink=
    fi

    KernelVer=%{version}-%{release}$Flavour
    echo BUILDING A KERNEL FOR $Flavour %{_target_cpu}...

    # make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = %{?stablerev}-%{release}$Flavour/" Makefile

    # if pre-rc1 devel kernel, must fix up SUBLEVEL for our versioning scheme
    %if !0%{?rcrev}
    %if 0%{?gitrev}
    perl -p -i -e 's/^SUBLEVEL.*/SUBLEVEL = %{upstream_sublevel}/' Makefile
    %endif
    %endif

    # and now to start the build process

    make -s mrproper
    cp configs/$Config .config

    %if !%{with_debuginfo}
    perl -p -i -e 's/^CONFIG_DEBUG_INFO=y$/# CONFIG_DEBUG_INFO is not set/' .config
    %endif

    Arch=`head -1 .config | cut -b 3-`
    echo USING ARCH=$Arch

    if [ "$KernelImage" == "x86" ]; then
       KernelImage=arch/$Arch/boot/bzImage
    fi

    make -s ARCH=$Arch %{oldconfig_target} > /dev/null
    make -s ARCH=$Arch %{?_smp_mflags} $MakeTarget %{?sparse_mflags} \
    	 ${idhack+"$idhack"}
    make -s ARCH=$Arch %{?_smp_mflags} modules %{?sparse_mflags} || exit 1

    # Start installing the results
%if %{with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/boot
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/%{image_install_path}
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
%ifarch %{vdso_arches}
    make -s ARCH=$Arch INSTALL_MOD_PATH=$RPM_BUILD_ROOT vdso_install KERNELRELEASE=$KernelVer
%endif

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
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/weak-updates
    # first copy everything
    cp --parents `find  -type f -name "Makefile*" -o -name "Kconfig*"` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp Module.symvers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp System.map $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    # then drop all but the needed Makefiles/Kconfig files
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Documentation
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
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
%if %{with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
%endif

    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f >modnames

    # mark modules executable so that strip-to-file can strip them
    xargs --no-run-if-empty chmod u+x < modnames

    # Generate a list of modules for block and networking.

    fgrep /drivers/ modnames | xargs --no-run-if-empty nm -upA |
    sed -n 's,^.*/\([^/]*\.ko\):  *U \(.*\)$,\1 \2,p' > drivers.undef

    collect_modules_list()
    {
      sed -r -n -e "s/^([^ ]+) \\.?($2)\$/\\1/p" drivers.undef |
      LC_ALL=C sort -u > $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$1
    }

    collect_modules_list networking \
    			 'register_netdev|ieee80211_register_hw|usbnet_probe'
    collect_modules_list block \
    			 'ata_scsi_ioctl|scsi_add_host|blk_init_queue'

    # detect missing or incorrect license tags
    rm -f modinfo
    while read i
    do
      echo -n "${i#$RPM_BUILD_ROOT/lib/modules/$KernelVer/} " >> modinfo
      /sbin/modinfo -l $i >> modinfo
    done < modnames

    egrep -v \
    	  'GPL( v2)?$|Dual BSD/GPL$|Dual MPL/GPL$|GPL and additional rights$' \
	  modinfo && exit 1

    rm -f modinfo modnames

    # remove files that will be auto generated by depmod at rpm -i time
    for i in alias ccwmap dep ieee1394map inputmap isapnpmap ofmap pcimap seriomap symbols usbmap
    do
      rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$i
    done

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
%if %{with_xen}
  cd xen
  mkdir -p $RPM_BUILD_ROOT/%{image_install_path} $RPM_BUILD_ROOT/boot
  make %{?_smp_mflags} %{xen_flags}
  install -m 644 xen.gz $RPM_BUILD_ROOT/%{image_install_path}/xen.gz-%{KVERREL}
  install -m 755 xen-syms $RPM_BUILD_ROOT/boot/xen-syms-%{KVERREL}
  cd ..
%endif
%endif

cd linux-%{kversion}.%{_target_cpu}

%if %{with_debug}
BuildKernel %make_target %kernel_image debug
%if %{with_pae}
BuildKernel %make_target %kernel_image PAE-debug
%endif
%endif

%if %{with_pae}
BuildKernel %make_target %kernel_image PAE
%endif

%if %{with_up}
BuildKernel %make_target %kernel_image
%endif

%if %{with_smp}
BuildKernel %make_target %kernel_image smp
%endif

%if %{includexen}
%if %{with_xen}
BuildKernel %xen_target %xen_image xen
%endif
%endif

%if %{with_kdump}
BuildKernel %make_target %kernel_image kdump
%endif

%if %{with_modsign}
# gpg sign the modules
gcc $RPM_OPT_FLAGS -o scripts/modsign/mod-extract scripts/modsign/mod-extract.c

# We do this on the installed, stripped .ko files in $RPM_BUILD_ROOT
# rather than as we are building them.  The __arch_install_post macro
# comes after __debug_install_post, which is what runs find-debuginfo.sh.
# This is necessary because the debugedit changes to the build ID bits
# change the contents of the .ko that go into the signature.  A signature
# made before debugedit is no longer correct for the .ko contents we'll
# have in the end.
%define __arch_install_post \
find $RPM_BUILD_ROOT/lib/modules -name '*.ko' |\
(cd %{_builddir}/%{buildsubdir}/linux-%{kversion}.%{_target_cpu}\
while read i\
do\
  GNUPGHOME=.. sh ./scripts/modsign/modsign.sh $i Red\
  mv -f $i.signed $i\
done)\
%{nil}
%endif

###
### Special hacks for debuginfo subpackages.
###

# This macro is used by %%install, so we must redefine it before that.
%define debug_package %{nil}

%if %{fancy_debuginfo}
%define __debug_install_post \
  /usr/lib/rpm/find-debuginfo.sh %{debuginfo_args} %{_builddir}/%{?buildsubdir}\
%{nil}
%endif

%if %{with_debuginfo}
%ifnarch noarch
%global __debug_package 1
%files -f debugfiles.list debuginfo-common
%defattr(-,root,root)
%endif
%endif

###
### install
###

%install

cd linux-%{kversion}.%{_target_cpu}

%if %{includexen}
%if %{with_xen}
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

%if %{with_doc}
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}/Documentation

# sometimes non-world-readable files sneak into the kernel source tree
chmod -R a+r *
# copy the source over
tar cf - Documentation | tar xf - -C $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}
%endif

%if %{with_headers}
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

#
# This macro defines a %%post script for a kernel*-devel package.
#	%%kernel_devel_post <subpackage>
#
%define kernel_devel_post() \
%{expand:%%post %{?1:%{1}-}devel}\
if [ -f /etc/sysconfig/kernel ]\
then\
    . /etc/sysconfig/kernel || exit $?\
fi\
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ]\
then\
    (cd /usr/src/kernels/%{KVERREL}-%{?1:%{1}-}%{_target_cpu} &&\
     /usr/bin/find . -type f | while read f; do\
       hardlink -c /usr/src/kernels/*.fc*-*/$f $f\
     done)\
fi\
%{nil}

#
# This macro defines a %%post script for a kernel package and its devel package.
#	%%kernel_variant_post [-v <subpackage>] [-s <s> -r <r>] <mkinitrd-args>
# More text can follow to go at the end of this variant's %%post.
#
%define kernel_variant_post(s:r:v:) \
%{expand:%%kernel_devel_post %{?-v*}}\
%{expand:%%post %{?-v*}}\
%{-s:\
if [ `uname -i` == "x86_64" -o `uname -i` == "i386" ] &&\
   [ -f /etc/sysconfig/kernel ]; then\
  /bin/sed -i -e 's/^DEFAULTKERNEL=%{-s*}$/DEFAULTKERNEL=%{-r*}/' /etc/sysconfig/kernel || exit $?\
fi}\
/sbin/new-kernel-pkg --package kernel%{?-v:-%{-v*}} --mkinitrd --depmod --install %{?1} %{KVERREL}%{?-v*} || exit $?\
#if [ -x /sbin/weak-modules ]\
#then\
#    /sbin/weak-modules --add-kernel %{KVERREL}%{?-v*} || exit $?\
#fi\
%{nil}

#
# This macro defines a %%preun script for a kernel package.
#	%%kernel_variant_preun <subpackage>
#
%define kernel_variant_preun() \
%{expand:%%preun %{?1}}\
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}%{?1} || exit $?\
#if [ -x /sbin/weak-modules ]\
#then\
#    /sbin/weak-modules --remove-kernel %{KVERREL}%{?1} || exit $?\
#fi\
%{nil}

%kernel_variant_preun
%kernel_variant_post -s kernel-smp -r kernel

%kernel_variant_preun smp
%kernel_variant_post -v smp

%kernel_variant_preun PAE
%kernel_variant_post -v PAE -s kernel-smp -r kernel-PAE

%kernel_variant_preun debug
%kernel_variant_post -v debug

%kernel_variant_post -v PAE-debug -s kernel-smp -r kernel-PAE-debug
%kernel_variant_preun PAE-debug

%kernel_variant_preun xen
%kernel_variant_post xen -v xen -s kernel-xen[0U] -r kernel-xen -- `[ -d /proc/xen -a ! -e /proc/xen/xsd_kva ] || echo --multiboot=/%{image_install_path}/xen.gz-%{KVERREL}`
if [ -x /sbin/ldconfig ]
then
    /sbin/ldconfig -X || exit $?
fi

###
### file lists
###

%if %{with_headers}
%files headers
%defattr(-,root,root)
/usr/include/*
%endif

# only some architecture builds need kernel-doc
%if %{with_doc}
%files doc
%defattr(-,root,root)
%{_datadir}/doc/kernel-doc-%{kversion}/Documentation/*
%dir %{_datadir}/doc/kernel-doc-%{kversion}/Documentation
%dir %{_datadir}/doc/kernel-doc-%{kversion}
%endif

# This is %{image_install_path} on an arch where that includes ELF files,
# or empty otherwise.
%define elf_image_install_path %{?kernel_image_elf:%{image_install_path}}

#
# This macro defines the %%files sections for a kernel package
# and its devel and debuginfo packages.
#	%%kernel_variant_files [-k vmlinux] [-a <extra-files-glob>] [-e <extra-nonbinary>] <condition> <subpackage>
#
%define kernel_variant_files(a:e:k:) \
%if %{1}\
%{expand:%%files %{?2}}\
%defattr(-,root,root)\
/%{image_install_path}/%{?-k:%{-k*}}%{!?-k:vmlinuz}-%{KVERREL}%{?2}\
/boot/System.map-%{KVERREL}%{?2}\
#/boot/symvers-%{KVERREL}%{?2}.gz\
/boot/config-%{KVERREL}%{?2}\
%{?-a:%{-a*}}\
%dir /lib/modules/%{KVERREL}%{?2}\
/lib/modules/%{KVERREL}%{?2}/kernel\
/lib/modules/%{KVERREL}%{?2}/build\
/lib/modules/%{KVERREL}%{?2}/source\
/lib/modules/%{KVERREL}%{?2}/extra\
/lib/modules/%{KVERREL}%{?2}/updates\
/lib/modules/%{KVERREL}%{?2}/weak-updates\
%ifarch %{vdso_arches}\
/lib/modules/%{KVERREL}%{?2}/vdso\
%endif\
/lib/modules/%{KVERREL}%{?2}/modules.block\
/lib/modules/%{KVERREL}%{?2}/modules.networking\
%ghost /boot/initrd-%{KVERREL}%{?2}.img\
%{?-e:%{-e*}}\
%{expand:%%files %{?2:%{2}-}devel}\
%defattr(-,root,root)\
%verify(not mtime) /usr/src/kernels/%{KVERREL}%{?2:-%{2}}-%{_target_cpu}\
/usr/src/kernels/%{KVERREL}%{?2}-%{_target_cpu}\
%if %{with_debuginfo}\
%ifnarch noarch\
%if %{fancy_debuginfo}\
%{expand:%%files -f debuginfo%{?2}.list %{?2:%{2}-}debuginfo}\
%else\
%{expand:%%files %{?2:%{2}-}debuginfo}\
%endif\
%defattr(-,root,root)\
%if !%{fancy_debuginfo}\
%if "%{elf_image_install_path}" != ""\
%{debuginfodir}/%{elf_image_install_path}/*-%{KVERREL}%{?2}.debug\
%endif\
%{debuginfodir}/lib/modules/%{KVERREL}%{?2}\
%{debuginfodir}/usr/src/kernels/%{KVERREL}%{?2:-%{2}}-%{_target_cpu}\
%endif\
%endif\
%endif\
%endif\
%{nil}


%kernel_variant_files %{with_up}
%kernel_variant_files %{with_smp} smp
%kernel_variant_files %{with_debug} debug
%kernel_variant_files %{with_pae} PAE
%kernel_variant_files %{with_pae_debug} PAE-debug
%kernel_variant_files -k vmlinux %{with_kdump} kdump
%kernel_variant_files -a /%{image_install_path}/xen*-%{KVERREL} -e /etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf %{with_xen} xen


%changelog
* Wed Nov 21 2007 John W. Linville <linville@redhat.com>
- Revise b43 rev D support (new upstream patch)
- Restore ability to add/remove virtual i/fs to mac80211 devices

* Sun May 27 2007 Dave Jones <davej@redhat.com>
- Start F8 branch. Rebase to 2.6.22rc3
