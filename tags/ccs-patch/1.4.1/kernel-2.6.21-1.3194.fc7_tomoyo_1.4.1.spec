Summary: The Linux kernel (the core of the Linux operating system)


# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.
# All should default to 1 (enabled) and be flipped to 0 (disabled)
# by later arch-specific checks.

# The following build options are enabled by default.
# Use either --without <opt> in your rpmbuild command or force values
# to 0 in here to disable them.
#
# standard kernel
%define with_up      %{?_without_up:      0} %{?!_without_up:      1}
# kernel-smp (only valid for ppc 32-bit, sparc64)
%define with_smp     %{?_without_smp:     0} %{?!_without_smp:     1}
# kernel-PAE (only valid for i686)
%define with_pae     %{?_without_pae:     0} %{?!_without_pae:     1}
# kernel-xen
%define with_xen     %{?_without_xen:     0} %{?!_without_xen:     1}
# kernel-kdump
%define with_kdump   %{?_without_kdump:   0} %{?!_without_kdump:   1}
# kernel-debug
%define with_debug   %{?_without_debug:   0} %{!?_without_debug:   1}
# kernel-doc
%define with_doc     %{?_without_doc:     0} %{?!_without_doc:     1}
# kernel-headers
%define with_headers %{?_without_headers: 0} %{?!_without_headers: 1}

# Additional options for user-friendly one-off kernel building:
#
# Only build the base kernel (--with baseonly):
%define with_baseonly %{?_with_baseonly: 1} %{?!_with_baseonly: 0}
# Only build the smp kernel (--with smponly):
%define with_smponly  %{?_with_smponly:  1} %{?!_with_smponly:  0}
# Only build the xen kernel (--with xenonly):
%define with_xenonly  %{?_with_xenonly:  1} %{?!_with_xenonly:  0}

# Whether or not to gpg sign modules
%define with_modsign 1

# Whether or not to do C=1 builds with sparse
%define usesparse 0

# Whether or not to apply the Xen patches -- leave this enabled
%define includexen 0
# Xen doesn't work with current upstream kernel, shut it off
%define with_xen 0

# Set debugbuildsenabled to 1 for production (build separate debug kernels)
#  and 0 for rawhide (all kernels are debug kernels).
# See also 'make debug' and 'make release'.
%define debugbuildsenabled 1

# Versions of various parts

# Polite request for people who spin their own kernel rpms:
# please modify the "buildid" define in a way that identifies
# that the kernel isn't the stock distribution kernel, for example,
# by setting the define to ".local" or ".bz123456"
#
#% define buildid .local
%define sublevel 21
%define kversion 2.6.%{sublevel}
%define rpmversion 2.6.%{sublevel}
%define release %(R="$Revision: 1.3194 $"; RR="${R##: }"; echo ${RR%%?})%{?dist}%{?buildid}_tomoyo_1.4.1

%define make_target bzImage
%define kernel_image x86

%define xen_hv_cset 11633
%define xen_flags verbose=y crash_debug=y
%define xen_target vmlinuz
%define xen_image vmlinuz

%define KVERREL %{PACKAGE_VERSION}-%{PACKAGE_RELEASE}
%define hdrarch %_target_cpu

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

# if requested, only build xen kernel
%if %{with_xenonly}
%define with_up 0
%define with_smp 0
%define with_pae 0
%define with_kdump 0
%define with_debug 0
%endif

# don't build xen or kdump kernels for OLPC
%if 0%{?olpc}
%define with_xen 0
%define with_kdump 0
%endif

# if building for RHEL
%if 0%{?rhel}
# don't build i586 RHEL kernels
%define all_x86 i386 i686
# RHEL has not-yet-upstream relocatable x86_64
%ifarch x86_64
%define with_kdump 0
%endif
# if building for Fedora
%else
%define all_x86 i386 i586 i686
%endif

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

# only build kernel-kdump on x86_64 and ppc64
# (no relocatable kernel support upstream yet)
%ifnarch x86_64 ppc64 ppc64iseries
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
# they can just use i386 and ppc64 headers
%ifarch i586 i686 ppc64iseries
%define with_headers 0
%endif

# don't build noarch kernels or headers (duh)
%ifarch noarch
%define with_up 0
%define with_headers 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-*.config
%endif

# don't sign modules on these platforms
%ifarch s390 s390x sparc sparc64 ppc alpha
%define with_modsign 0
%endif

# sparse blows up on ppc64
%ifarch ppc64 ppc alpha
%define usesparse 0
%endif

# Per-arch tweaks

%ifarch %{all_x86}
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-i?86*.config
%define image_install_path boot
%define hdrarch i386
# we build always xen i686 HV with pae
%define xen_flags verbose=y crash_debug=y pae=y
%endif

%ifarch x86_64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-x86_64*.config
%define image_install_path boot
%endif

%ifarch ppc64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc64*.config
%define image_install_path boot
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
%define hdrarch powerpc
%endif

%ifarch ia64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ia64*.config
%define image_install_path boot/efi/EFI/redhat
%define make_target compressed
%define kernel_image vmlinux.gz
# ia64 xen HV doesn't building with debug=y at the moment
%define xen_flags verbose=y crash_debug=y
%define xen_target compressed
%define xen_image vmlinux.gz
%endif

%ifarch alpha alphaev56
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-alpha*.config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%endif

# To temporarily exclude an architecture from being built, add it to
# %nobuildarches. Do _NOT_ use the ExclusiveArch: line, because if we
# don't build kernel-headers then the new build system will no longer let
# us use the previous build of that package -- it'll just be completely AWOL.
# Which is a BadThing(tm).

# We don't build a kernel on i386 or s390x -- we only do kernel-headers there.
%define nobuildarches i386 s390

%ifarch %nobuildarches
%define with_up 0
%define with_smp 0
%define with_pae 0
%define with_xen 0
%define with_kdump 0
%define _enable_debug_packages 0
%endif

# TOMOYO Linux
%define with_modsign 0
%define _enable_debug_packages 0

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
%define xen_conflicts glibc < 2.3.5-1, xen < 3.0.1

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 6.0.9-1

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
ExclusiveArch: noarch %{all_x86} x86_64 ppc ppc64 ia64 sparc sparc64 s390 s390x alpha alphaev56
%endif
ExclusiveOS: Linux
Provides: kernel-drm = 4.3.0
Provides: kernel-drm-nouveau = 6
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReq: no
AutoProv: yes


#
# List the packages used during the kernel build
#
BuildPreReq: module-init-tools, patch >= 2.5.4, bash >= 2.03, sh-utils, tar
BuildPreReq: bzip2, findutils, gzip, m4, perl, make >= 3.78, diffutils
%if %{with_modsign}
BuildPreReq: gnupg
%endif
BuildRequires: gcc >= 3.4.2, binutils >= 2.12, redhat-rpm-config
BuildRequires: sparse >= 0.3
BuildConflicts: rhbuildsys(DiskFree) < 500Mb


Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-%{kversion}.tar.bz2
#Source1: xen-%{xen_hv_cset}.tar.bz2
Source2: Config.mk

Source10: COPYING.modules
Source11: genkey
Source12: kabitool
Source14: find-provides
Source15: merge.pl

Source20: kernel-%{kversion}-i586.config
Source21: kernel-%{kversion}-i686.config
Source22: kernel-%{kversion}-i686-debug.config
Source23: kernel-%{kversion}-i686-PAE.config
Source24: kernel-%{kversion}-i686-PAE-debug.config

Source25: kernel-%{kversion}-x86_64.config
Source26: kernel-%{kversion}-x86_64-debug.config
Source27: kernel-%{kversion}-x86_64-kdump.config

Source28: kernel-%{kversion}-ppc.config
Source29: kernel-%{kversion}-ppc-smp.config
Source30: kernel-%{kversion}-ppc64.config
Source31: kernel-%{kversion}-ppc64-kdump.config

Source34: kernel-%{kversion}-s390.config
Source35: kernel-%{kversion}-s390x.config

Source36: kernel-%{kversion}-ia64.config

Source37: kernel-%{kversion}-i686-xen.config
Source38: kernel-%{kversion}-x86_64-xen.config
Source39: kernel-%{kversion}-ia64-xen.config

#Source50: kernel-%{kversion}-sparc.config
#Source51: kernel-%{kversion}-sparc64.config
#Source52: kernel-%{kversion}-sparc64-smp.config

#Source60: kernel-%{kversion}-alpha.config
#Source61: kernel-%{kversion}-alphaev56.config
#Source62: kernel-%{kversion}-alphaev56-smp.config

Source80: config-rhel-generic
Source81: config-rhel-x86-generic
Source82: config-olpc-generic

#
# Patches 0 through 100 are meant for core subsystem upgrades
#
Patch1: patch-2.6.21.2.bz2

# Patches 10 through 99 are for things that are going upstream really soon.
Patch10: linux-2.6-utrace.patch
Patch11: nouveau-drm.patch

Patch12: linux-2.6-fix-pmops-1.patch
Patch13: linux-2.6-fix-pmops-2.patch
Patch14: linux-2.6-fix-pmops-3.patch
Patch15: linux-2.6-fix-pmops-4.patch

# enable sysrq-c on all kernels, not only kexec
# FIXME: upstream soon? When? It's been here for ages.
Patch16: linux-2.6-sysrq-c.patch

# DRM bits for 965
Patch17: linux-2.6-i965gm-support.patch

# Patches 100 through 500 are meant for architecture patches

# 200 - 299   x86(-64)

Patch200: linux-2.6-x86-tune-generic.patch
Patch201: linux-2.6-x86-vga-vidfail.patch
Patch202: linux-2.6-x86-64-edac-support.patch
Patch203: linux-2.6-x86_64-silence-up-apic-errors.patch
Patch204: linux-2.6-x86-dont-delete-cpu_devs-data.patch
Patch205: linux-2.6-x86-fix-oprofile.patch
Patch206: linux-2.6-x86-fsc-interrupt-controller-quirk.patch
Patch207: linux-2.6-x86-dell-hpet.patch

# 300 - 399   ppc(64)
Patch300: linux-2.6-g5-therm-shutdown.patch
Patch301: linux-2.6-powerpc-slabalign.patch
Patch303: linux-2.6-ppc32-ucmpdi2.patch
Patch304: linux-2.6-ibmvscsi-schizo.patch
Patch305: linux-2.6-pmac-zilog.patch
Patch306: linux-2.6-powerpc-reserve-initrd-1.patch
Patch307: linux-2.6-powerpc-reserve-initrd-2.patch
Patch308: linux-2.6-cell-spu-device-tree.patch
Patch309: linux-2.6-cell-spufs-fixes.patch

Patch310: linux-2.6-common-uevent.patch
Patch311: linux-2.6-uevent-macio.patch
Patch312: linux-2.6-uevent-of_platform.patch
Patch313: linux-2.6-uevent-ebus.patch

Patch330: linux-2.6-powermac-generic-suspend-1.patch
Patch331: linux-2.6-powermac-generic-suspend-2.patch
Patch332: linux-2.6-powermac-generic-suspend-3.patch
Patch333: linux-2.6-powermac-generic-suspend-4.patch

Patch340: linux-2.6-mpc52xx-sdma.patch
Patch341: linux-2.6-mpc52xx-fec.patch

# Patches from ps3-linux-patches.git (2007-05-04)
Patch350: linux-2.6-ps3-stable-patches.patch
Patch351: linux-2.6-ps3-smp-boot.patch
Patch352: linux-2.6-ps3-system-bus-rework.patch
Patch353: linux-2.6-ps3-kexec.patch
Patch354: linux-2.6-ps3-gelic.patch
Patch355: linux-2.6-ps3-gelic-wireless.patch
Patch356: linux-2.6-ps3-ehci-iso.patch
Patch357: linux-2.6-ps3-clear-spu-irq.patch
Patch358: linux-2.6-ps3-wrap-spu-runctl.patch
# Ignore the SPE logo bits. Cute, but not exactly necessary
Patch359: linux-2.6-ps3-storage.patch
Patch360: linux-2.6-ps3-sound.patch
Patch361: linux-2.6-ps3-device-init.patch
Patch362: linux-2.6-ps3-system-bus-rework-2.patch

# And then some minor tweaks...
Patch370: linux-2.6-ps3-memory-probe.patch
Patch371: linux-2.6-ps3-legacy-ioport.patch
Patch372: linux-2.6-ps3fb-panic.patch
Patch373: linux-2.6-ps3-ethernet-modular.patch
Patch374: linux-2.6-ps3-sound-autoload.patch
Patch375: linux-2.6-ps3-ethernet-autoload.patch
Patch376: linux-2.6-ps3av-export-header.patch
Patch377: linux-2.6-ps3-usb-autoload.patch

# 500 - 599   s390(x)

# 600 - 699   sparc(64)

# 700 - 799   alpha

#
# Patches 800 through 899 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#
Patch800: linux-2.6-build-nonintconfig.patch

# Exec-shield.
Patch810: linux-2.6-execshield.patch

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
Patch951: linux-2.6-xen-utrace.patch
Patch952: linux-2.6-xen-x86_64-silence-up-apic-errors.patch
Patch953: linux-2.6-xen-x86_64-add-ppoll-pselect.patch
Patch954: linux-2.6-xen-execshield.patch
Patch955: linux-2.6-xen-tux.patch
Patch956: linux-2.6-xen-execshield-lazy-exec-limit.patch
Patch958: linux-2.6-ia64-kexec-kdump-xen-conflict.patch
Patch960: linux-2.6-xen-blktap-fixes.patch
Patch961: linux-2.6-xen-blktap-cleanup.patch
Patch962: linux-2.6-xen-blktap-dynamic-major.patch
Patch963: linux-2.6-xen-blktap-sysfs.patch
Patch990: linux-2.6-xen-pvfb.patch

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#

Patch1010: linux-2.6-debug-sizeof-structs.patch
Patch1011: linux-2.6-debug-slab-backtrace.patch
Patch1012: linux-2.6-debug-nmi-timeout.patch
Patch1013: linux-2.6-debug-taint-vm.patch
Patch1015: linux-2.6-debug-spinlock-taint.patch
Patch1016: linux-2.6-debug-extra-warnings.patch
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
Patch1100: linux-2.6-scsi-bounce-isa.patch
Patch1101: linux-2.6-scsi-cpqarray-set-master.patch

# NFS bits.
Patch1201: linux-2.6-NFSD-badness.patch

# NIC driver fixes
Patch1300: linux-2.6-net-e1000-no-msi-warning.patch
Patch1301: linux-2.6-net-e1000-debug-shirq.patch
Patch1302: linux-2.6-net-e1000-no-polling-in-open.patch

# Filesystem stuff.
# Squashfs
Patch1400: linux-2.6-squashfs.patch
# GFS2
Patch1410: linux-2.6-gfs2-update.patch

# Networking core.
Patch1500: linux-2.6-net-silence-noisy-printks.patch

# Misc bits.
Patch1600: linux-2.6-module_version.patch
Patch1601: linux-2.6-sha_alignment.patch
Patch1610: linux-2.6-input-kill-stupid-messages.patch
Patch1620: linux-2.6-ondemand-timer.patch
Patch1630: linux-2.6-kvm-19.patch
Patch1640: linux-2.6-module-override-modparam-cmdline.patch
Patch1650: linux-2.6-serial-460800.patch
Patch1660: linux-2.6-mm-udf-fixes.patch
Patch1670: linux-2.6-sysfs-inode-allocator-oops.patch
Patch1681: linux-2.6-xfs-umount-fix.patch
Patch1690: linux-2.6-PT_LOAD-align.patch
Patch1700: linux-2.6-dvb-spinlock.patch
Patch1710: linux-2.6-nfs-noreaddirplus.patch
Patch1711: linux-2.6-nfs-missing-braces.patch
Patch1720: linux-2.6-proc-self-maps-fix.patch
Patch1730: linux-2.6-suspend-ordering.patch
Patch1740: linux-2.6-softlockup-disable.patch
Patch1750: linux-2.6-singlethread-freezable-workqueues.patch
Patch1770: linux-2.6-optimise-spinlock-debug.patch
Patch1771: linux-2.6-silence-noise.patch
Patch1780: linux-2.6-prevent-idle-softirq.patch
Patch1791: linux-2.6-libertas.diff
Patch1792: linux-2.6-olpc-touchpad.diff
Patch1793: linux-2.6-raid-autorun.patch
Patch1794: linux-2.6-i82875-edac-pci-setup.patch
Patch1795: linux-2.6-crap-sysfs-workaround.patch

# SELinux/audit patches.
Patch1801: linux-2.6-selinux-mprotect-checks.patch

# Warn about usage of various obsolete functionality that may go away.
Patch1900: linux-2.6-obsolete-oss-warning.patch

# no external module should use these symbols.
Patch1910: linux-2.6-unexport-symbols.patch

# VM bits.
Patch2000: linux-2.6-vm-invalidate_mapping_pages-cond-resched.patch
Patch2001: linux-2.6-vm-silence-atomic-alloc-failures.patch

# Tweak some defaults.
Patch2100: linux-2.6-defaults-fat-utf8.patch
Patch2103: linux-2.6-defaults-unicode-vt.patch
Patch2105: linux-2.6-defaults-nonmi.patch
Patch2106: linux-2.6-defaults-pci_no_msi_mmconf.patch

# ATA Bits
Patch2200: linux-2.6-sata-promise-pata-ports.patch
Patch2201: linux-2.6-libata-hpa.patch
Patch2202: linux-2.6-libata-sata_nv-adma.patch
Patch2203: linux-2.6-libata-ali-atapi-dma.patch
Patch2204: linux-2.6-ata-quirk.patch
Patch2206: linux-2.6-libata-sata_nv-wildcard-removal.patch
Patch2207: linux-2.6-libata-pata-pcmcia-new-ident.patch
Patch2208: linux-2.6-libata-atiixp-ids.patch
Patch2209: linux-2.6-libata-pata-hpt3x2n-correct-revision-boundary.patch
Patch2210: linux-2.6-libata-pata-sis-fix-timing.patch

# Wireless bits
Patch2300: linux-2.6-wireless.patch
Patch2301: git-wireless-dev.patch
Patch2302: git-iwlwifi.patch
Patch2303: linux-2.6-bcm43xx-pci-neuter.patch
Patch2304: linux-2.6-mac80211-fixes.patch
Patch2305: linux-2.6-bcm43xx-mac80211-fixes.patch

# Assorted dyntick/clock/timer fixes.
Patch2402: linux-2.6-acpi-keep-tsc-stable-when-lapic-timer-c2-ok-is-set.patch
Patch2403: linux-2.6-clockevents-fix-resume-logic.patch

# ACPI bits
Patch2501: linux-2.6-acpi-dock-oops.patch

# Excessive wakeups.
Patch2600: linux-2.6-wakeups-hdaps.patch

# Add the new firewire stack. Diff between the v2.6.20 tag and commit
# a0ab4547b23c09541bc47a294a1397b3b0415bfe in the linux1394 git tree.
Patch5000: linux-2.6-firewire.patch
Patch5001: linux-2.6-firewire-be32-fix.patch

#
# 10000 to 20000 is for stuff that has to come last due to the
# amount of drivers they touch. But only these should go here.
# Not patches you're too lazy for to put in the proper place.
#

Patch10000: linux-2.6-compile-fixes.patch
Patch10001: linux-2.6-warnings-inline.patch
Patch10002: linux-2.6-warnings-emptymacros.patch
Patch10003: linux-2.6-warnings-register.patch

# Xen hypervisor patches (20000+)
Patch20000: xen-printf-rate-limit.patch
Patch20001: xen-11668-hvm_disable_fix.patch
Patch20002: xen-dom0-reboot.patch

# END OF PATCH DEFINITIONS

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root-%{_target_cpu}

# Override find_provides to use a script that provides "kernel(symbol) = hash".
# Pass path of the RPM temp dir containing kabideps to find-provides script.
#global _use_internal_dependency_generator 0
#define __find_provides %_sourcedir/find-provides %{_tmppath}
#define __find_requires /usr/lib/rpm/redhat/find-requires kernel

%ifarch x86_64
Obsoletes: kernel-smp
%endif

%description
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

%package debuginfo
Summary: Debug information for package %{name}
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
Provides: %{name}-debuginfo-%{_target_cpu} = %{KVERREL}
%description debuginfo
This package provides debug information for package %{name}
This is required to use SystemTap with %{name}-%{KVERREL}.

%package debuginfo-common
Summary: Kernel source files used by %{name}-debuginfo packages
Group: Development/Debug
Provides: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
%description debuginfo-common
This package is required by %{name}-debuginfo subpackages.
It provides the kernel source files common to all builds.

%package devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}
Prereq: /usr/bin/find
%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.

%package smp
Summary: The Linux kernel compiled for SMP machines.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-drm-nouveau = 6
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
AutoReq: no
AutoProv: yes
%description smp
This package includes a SMP version of the Linux kernel. It is
required only on machines with two or more CPUs as well as machines with
hyperthreading technology.

Install the kernel-smp package if your machine uses two or more CPUs.

%package smp-debuginfo
Summary: Debug information for package %{name}-smp
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
Provides: %{name}-%smp-debuginfo-%{_target_cpu} = %{KVERREL}
%description smp-debuginfo
This package provides debug information for package %{name}-smp
This is required to use SystemTap with %{name}-smp-%{KVERREL}.

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


%package PAE
Summary: The Linux kernel compiled for PAE capable machines.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-drm-nouveau = 6
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}PAE
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Obsoletes: kernel-smp < 2.6.17
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReq: no
AutoProv: yes
%description PAE
This package includes a version of the Linux kernel with support for up to
64GB of high memory. It requires a CPU with Physical Address Extensions (PAE).
The non-PAE kernel can only address up to 4GB of memory.
Install the kernel-PAE package if your machine has more than 4GB of memory.

%package PAE-debuginfo
Summary: Debug information for package %{name}-PAE
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
Provides: %{name}-%PAE-debuginfo-%{_target_cpu} = %{KVERREL}
%description PAE-debuginfo
This package provides debug information for package %{name}-PAE
This is required to use SystemTap with %{name}-PAE-%{KVERREL}.

%package PAE-devel
Summary: Development package for building kernel modules to match the PAE kernel.
Group: System Environment/Kernel
Provides: kernel-PAE-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}PAE
Provides: kernel-devel = %{rpmversion}-%{release}PAE
AutoReqProv: no
Prereq: /usr/bin/find
%description PAE-devel
This package provides kernel headers and makefiles sufficient to build modules
against the PAE kernel package.

%if %{debugbuildsenabled}
%package PAE-debug
Summary: The Linux kernel compiled with extra debugging enabled for PAE capable machines.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-drm-nouveau = 6
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}PAE-debug
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
AutoReq: no
AutoProv: yes
%description PAE-debug
This package includes a version of the Linux kernel with support for up to
64GB of high memory. It requires a CPU with Physical Address Extensions (PAE).
The non-PAE kernel can only address up to 4GB of memory.
Install the kernel-PAE package if your machine has more than 4GB of memory.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.

%package PAE-debug-debuginfo
Summary: Debug information for package %{name}-PAE-debug
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
Provides: %{name}-debug-debuginfo-%{_target_cpu} = %{KVERREL}
%description PAE-debug-debuginfo
This package provides debug information for package %{name}-PAE-debug

%package PAE-debug-devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Prereq: /usr/bin/find
Provides: kernel-PAE-debug-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}PAE-debug
Provides: kernel-devel = %{rpmversion}-%{release}PAE-debug
%description PAE-debug-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.
%endif


%package doc
Summary: Various documentation bits found in the kernel source.
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


%if %{?debugbuildsenabled}
%package debug
Summary: The Linux kernel compiled with extra debugging enabled.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-drm-nouveau = 6
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

%package debug-debuginfo
Summary: Debug information for package %{name}-debug
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
Provides: %{name}-debug-debuginfo-%{_target_cpu} = %{KVERREL}
%description debug-debuginfo
This package provides debug information for package %{name}-debug

%package debug-devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Prereq: /usr/bin/find
Provides: kernel-debug-devel-%{_target_cpu} = %{rpmversion}-%{release}
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}debug
Provides: kernel-devel = %{rpmversion}-%{release}debug
%description debug-devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.
%endif


%package xen
Summary: The Linux kernel compiled for Xen VM operations
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}xen
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{xen_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReq: no
AutoProv: yes
%description xen
This package includes a version of the Linux kernel which
runs in Xen VM. It works for both priviledged and unpriviledged guests.

%package xen-debuginfo
Summary: Debug information for package %{name}-xen
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
Provides: %{name}-xen-debuginfo-%{_target_cpu} = %{KVERREL}
%description xen-debuginfo
This package provides debug information for package %{name}-xen
This is required to use SystemTap with %{name}-xen-%{KVERREL}.

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

%package kdump
Summary: A minimal Linux kernel compiled for kernel crash dumps.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-drm-nouveau = 6
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}kdump
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReq: no
AutoProv: yes
%description kdump
This package includes a kdump version of the Linux kernel. It is
required only on machines which will use the kexec-based kernel crash dump
mechanism.

%package kdump-debuginfo
Summary: Debug information for package %{name}-kdump
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{KVERREL}
Provides: %{name}-kdump-debuginfo-%{_target_cpu} = %{KVERREL}
%description kdump-debuginfo
This package provides debug information for package %{name}-kdump
This is required to use SystemTap with %{name}-kdump-%{KVERREL}.

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
     rm -rf deleteme.%{_target_cpu}
     # Move away the stale away, and delete in background.
     mv linux-%{kversion}.%{_target_cpu} deleteme.%{_target_cpu}
     rm -rf deleteme.%{_target_cpu} &
  fi
fi

cp -rl vanilla linux-%{kversion}.%{_target_cpu}

cd linux-%{kversion}.%{_target_cpu}

# Update to latest upstream.
%patch1 -p1

# Patches 10 through 100 are meant for core subsystem upgrades

# Roland's utrace ptrace replacement.
%patch10 -p1
%patch11 -p1

# Power management fixes
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1

# sysrq works always
%patch16 -p1

# DRM support for 965GM
%patch17 -p1

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
# Don't delete cpu_devs data to identify different x86 types in late_initcall
%patch204 -p1
# Fix oprofile.
%patch205 -p1
# quirk for Siemens Nixdorf AG FSC Multiprocessor Interrupt Controller
%patch206 -p1
# Blacklist Dell Optiplex 320 from using the HPET
%patch207 -p1

#
# PowerPC
#
# Alleviate G5 thermal shutdown problems
%patch300 -p1
# Ensure slab objects are aligned enough for a uint64_t (#235392)
%patch301 -p1
#%patch302 -p1
# Temporary hack to work around GCC PR #25724 / #21237
%patch303 -p1
# Fix up ibmvscsi for combined pSeries/iSeries build
%patch304 -p1
# Move pmac_zilog to its newly-registered device number
%patch305 -p1
# Ensure initrd memory is reserved at boot
%patch306 -p1
%patch307 -p1
%patch308 -p1
%patch309 -p1

# uevent support for of_platform device
%patch310 -p1
%patch311 -p1
%patch312 -p1
%patch313 -p1

%patch330 -p1
%patch331 -p1
%patch332 -p1
%patch333 -p1
# Efika Ethernet
%patch340 -p1
%patch341 -p1

# PlayStation 3 support
%patch350 -p1
%patch351 -p1
%patch352 -p1
%patch353 -p1
%patch354 -p1
%patch355 -p1
%patch356 -p1
%patch357 -p1
%patch358 -p1
%patch359 -p1
%patch360 -p1
%patch361 -p1
%patch362 -p1

%patch370 -p1
%patch371 -p1
%patch372 -p1
%patch373 -p1
%patch374 -p1
%patch375 -p1
%patch376 -p1
%patch377 -p1

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

# Xen utrace
%patch951 -p1
%patch952 -p1
%patch953 -p1
# Xen exec-shield bits
%patch954 -p1
%patch955 -p1
%patch956 -p1
# ia64 xen cleanups for kexec/kdump
%patch958 -p1

# xen blktap fixes
%patch960 -p1
# The blktap patch needs to rename a file.  For now, that is far more easily
# done in the spec file than in the patch itself.
mv drivers/xen/blktap/blktap.c drivers/xen/blktap/blktapmain.c
%patch961 -p1
%patch962 -p1
%patch963 -p1

# xen framebuffer patches
%patch990 -p1

%endif

#
# Patches 1000 to 5000 are reserved for bugfixes to drivers and filesystems
#


# Various low-impact patches to aid debugging.
%patch1010 -p1
%patch1011 -p1
%patch1012 -p1
%patch1013 -p1
%patch1015 -p1
# Only spew extra warnings on rawhide builds.
%if ! %{debugbuildsenabled}
%patch1016 -p1
%endif
%patch1018 -p1
%patch1019 -p1
%patch1020 -p1
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
# Fix old SCSI adapter crashes with CD-ROM
%patch1100 -p1
# fix cpqarray pci enable
%patch1101 -p1

#
# Various NFS/NFSD fixes.
#
# Fix badness.
%patch1201 -p1

# NIC driver fixes
# Don't print warnings about MSI failures on e1000
%patch1300 -p1
# Fix up e1000 oops (#240339)
%patch1301 -p1
%patch1302 -p1

# Filesystem patches.
# Squashfs
%patch1400 -p1
# GFS2 update
%patch1410 -p1

# Networking
# Disable easy to trigger printk's.
%patch1500 -p1

# Misc fixes
# Add missing MODULE_VERSION tags to some modules.
%patch1600 -p1
# Fix SHA1 alignment problem on ia64
%patch1601 -p1
# The input layer spews crap no-one cares about.
%patch1610 -p1
# don't wakeup ondemand timer whilst idle.
%patch1620 -p1
# Update KVM.
%patch1630 -p1
# Allow overriding module parameters from kernel command_line
#%patch1640 -p1
# Allow to use 480600 baud on 16C950 UARTs
%patch1650 -p1
# Allow large files on UDF
%patch1660 -p1
# fix oops in sysfs_readdir
%patch1670 -p1
# Fix XFS umount bug.
%patch1681 -p1
# Align kernel data segment to page boundary.
%patch1690 -p1
# DVB spinlock bug
%patch1700 -p1
# NFS: Added support to turn off the NFSv3 READDIRPLUS RPC.
%patch1710 -p1
# Missing braces
%patch1711 -p1
# setuid /proc/self/maps fix.
%patch1720 -p1
# Fix ACPI suspend / device suspend ordering problem
%patch1730 -p1
# Add a safety net to softlockup so that it doesn't prevent installs.
%patch1740 -p1
# Make freezable workqueues single threaded.
%patch1750 -p1
# Speed up spinlock debug.
%patch1770 -p1
# Silence some useless messages that still get printed with 'quiet'
%patch1771 -p1
# Prevent going idle with softirq pending
%patch1780 -p1

# OLPC specific patches
%if 0%{?olpc}
# Marvell Libertas wireless driver
%patch1791 -p1
# OLPC touchpad
%patch1792 -p1
%endif

# temporarily restore START_ARRAY ioctl
%patch1793 -p1
# Fix i82875 EDAC driver setup so X will start
%patch1794 -p1
# Work around sysfs/uevent use-after-free problems with Bluetooth HID
%patch1795 -p1

# Fix the SELinux mprotect checks on executable mappings
%patch1801 -p1

# Warn about obsolete functionality usage.
%patch1900 -p1
# Remove kernel-internal functionality that nothing external should use.
%patch1910 -p1

#
# VM related fixes.
#
# Re-add cond_resched to invalidate_mapping_pages()
%patch2000 -p1
# Silence GFP_ATOMIC failures.
%patch2001 -p1

# Changes to upstream defaults.
# Use UTF-8 by default on VFAT.
%patch2100 -p1
# Use unicode VT's by default.
%patch2103 -p1
# Disable NMI watchdog by default.
%patch2105 -p1
# Disable MMCONFIG & MSI by default.
%patch2106 -p1

# Enable PATA ports on Promise SATA.
#%patch2200 -p1
# HPA support for libata.
%patch2201 -p1
# sata_nv: Don't attempt using ADMA for (READ|SET)_MAX commands
%patch2202 -p1
# Disable ATAPI DMA on ALI chipsets.
%patch2203 -p1
# libata: don't initialize sg in ata_exec_internal() if DMA_NONE
# ia64 ata quirk
%patch2204 -p1
# remove the wildcard from sata_nv driver
%patch2206 -p1
# pata_pcmcia.c: add card ident for jvc cdrom
%patch2207 -p1
# Add libata ID's for ATI SB700
%patch2208 -p1
# hpt3x2n: Correct revision boundary
%patch2209 -p1
# pata_sis: Fix and clean up some timing setups
%patch2210 -p1

# Add critical wireless updates from 2.6.22
%patch2300 -p1
# Add the new wireless stack and drivers from wireless-dev
%patch2301 -p1
# ...and the iwlwifi driver from Intel
%patch2302 -p1
# avoid bcm43xx vs bcm43xx-mac80211 PCI ID conflicts
%patch2303 -p1
# some mac80211 bug fixes (defrag mem leak, reassoc failure handling)
%patch2304 -p1
# bcm43xx-mac80211: important phy and ssb bus fixes
%patch2305 -p1

# Assorted dyntick/clock/timer fixes.
%patch2402 -p1
%patch2403 -p1

# ACPI patches
# Fix ACPI dock oops (#238054)
%patch2501 -p1

# Fix excessive wakeups
# Make hdaps timer only tick when in use.
%patch2600 -p1

#
# Patches 5000 to 6000 are reserved for new drivers that are about to
# be merged upstream
#

# Pull in the new firewire stack
%patch5000 -p1
%patch5001 -p1

#
# final stuff
#

#
# misc small stuff to make things compile or otherwise improve performance
#
#%patch10000 -p1
%patch10001 -p1
%patch10002 -p1
%patch10003 -p1

# TOMOYO Linux
tar -zxf %_sourcedir/ccs-patch-1.4.1-20070605.tar.gz
sed -i -e 's:EXTRAVERSION =.*:EXTRAVERSION = -1.3194.fc7:' -- Makefile
patch -sp1 < ccs-patch-2.6.21-1.3194.fc7.txt

# END OF PATCH APPLICATIONS

cp %{SOURCE10} Documentation/

mkdir configs

cp -f %{all_arch_configs} .


%if 0%{?rhel}
# don't need these for relocatable kernels
rm -f kernel-%{kversion}-{i686,x86_64}-kdump.config
%endif

%if 0%{?olpc}
# don't need these for OLPC
rm -f kernel-%{kversion}-*PAE*.config
rm -f kernel-%{kversion}-*xen*.config
rm -f kernel-%{kversion}-*kdump*.config
%endif

%if 0%{?debugbuildsenabled}
%else
rm -f kernel-%{kversion}-*-debug.config
%endif

# now run oldconfig over all the config files
for i in *.config
do
  mv $i .config
  # TOMOYO Linux
  cat config.ccs >> .config
  sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- .config
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
find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null

cd ..

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
%patch20001 -p2
%patch20002 -p2
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
    make -s ARCH=$Arch %{?_smp_mflags} $MakeTarget %{?sparse_mflags}
    make -s ARCH=$Arch %{?_smp_mflags} modules %{?sparse_mflags} || exit 1

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

    # Create the kABI metadata for use in packaging
#   echo "**** GENERATING kernel ABI metadata ****"
#   gzip -c9 < Module.symvers > $RPM_BUILD_ROOT/boot/symvers-$KernelVer.gz
#   chmod 0755 %_sourcedir/kabitool
#   if [ ! -e $RPM_SOURCE_DIR/kabi_whitelist ]; then
#       %_sourcedir/kabitool -b $RPM_BUILD_ROOT/$DevelDir -k $KernelVer -l $RPM_BUILD_ROOT/kabi_whitelist
#   else
#       cp $RPM_SOURCE_DIR/kabi_whitelist $RPM_BUILD_ROOT/kabi_whitelist
#   fi
#   rm -f %{_tmppath}/kernel-$KernelVer-kabideps
#    %_sourcedir/kabitool -b . -d %{_tmppath}/kernel-$KernelVer-kabideps -k $KernelVer -w $RPM_BUILD_ROOT/kabi_whitelist

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
#    mv $RPM_BUILD_ROOT/kabi_whitelist $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
#    cp symsets-$KernelVer.tar.gz $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
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
%if "%{_enable_debug_packages}" == "1"
    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer
%endif

    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f >modnames

    # gpg sign the modules
%if %{with_modsign}
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

    # Generate a list of modules for SCSI, sata/pata, and networking.
    touch $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.scsi
    touch $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.libata
    touch $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.networking
    for i in `cat modnames | grep drivers | grep -v drivers\/ata`
    do
      if [ $(nm $i |grep --count scsi_add_host) -ne 0 ];
      then
        basename `echo $i` >> $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.scsi
      fi
    done

    for i in `cat modnames | grep drivers\/ata`
    do
      if [ $(nm $i |grep --count ata_device_add) -ne 0 -o $(nm $i |grep --count ata_pci_init_one) -ne 0 ];
      then
        basename `echo $i` >> $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.libata
      fi
    done

    for i in `cat modnames |grep drivers`
    do
      if [ $(nm $i |grep --count register_netdev) -ne 0 ];
      then
        basename `echo $i` >> $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.networking
      fi
    done

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

%if %{debugbuildsenabled}
%if %{with_debug}
BuildKernel %make_target %kernel_image debug
%endif
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

###
### Special hacks for debuginfo subpackages.
###

# This macro is used by %%install, so we must redefine it before that.
%define debug_package %{nil}

%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%global __debug_package 1
%files debuginfo-common
%defattr(-,root,root)
/usr/src/debug/%{name}-%{version}/linux-%{kversion}.%{_target_cpu}
%if %{includexen}
%if %{with_xen}
/usr/src/debug/%{name}-%{version}/xen
%endif
%endif
%dir /usr/src/debug
%dir /usr/lib/debug
%dir /usr/lib/debug/%{image_install_path}
%dir /usr/lib/debug/lib
%dir /usr/lib/debug/lib/modules
%dir /usr/lib/debug/usr/src/kernels
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

%post
if [ `uname -i` == "x86_64" -o `uname -i` == "i386" ]; then
  if [ -f /etc/sysconfig/kernel ]; then
    /bin/sed -i -e 's/^DEFAULTKERNEL=kernel-smp$/DEFAULTKERNEL=kernel/' /etc/sysconfig/kernel || exit $?
  fi
fi
/sbin/new-kernel-pkg --package kernel --mkinitrd --depmod --install %{KVERREL} || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --add-kernel %{KVERREL} || exit $?
#fi

%post devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post smp
/sbin/new-kernel-pkg --package kernel-smp --mkinitrd --depmod --install %{KVERREL}smp || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --add-kernel %{KVERREL}smp || exit $?
#fi

%post smp-devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post PAE
if [ -f /etc/sysconfig/kernel ]; then
    /bin/sed -i -e 's/^DEFAULTKERNEL=kernel-smp$/DEFAULTKERNEL=kernel-PAE/' /etc/sysconfig/kernel
fi
/sbin/new-kernel-pkg --package kernel-PAE --mkinitrd --depmod --install %{KVERREL}PAE || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --add-kernel %{KVERREL}PAE || exit $?
#fi

%post PAE-devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-PAE-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi


%if %{debugbuildsenabled}
%post debug
/sbin/new-kernel-pkg --package kernel-debug --mkinitrd --depmod --install %{KVERREL}debug || exit $?
if [ -x /sbin/weak-modules ]
then
    /sbin/weak-modules --add-kernel %{KVERREL}debug || exit $?
fi

%post debug-devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-debug-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post PAE-debug
if [ -f /etc/sysconfig/kernel ]; then
    /bin/sed -i -e 's/^DEFAULTKERNEL=kernel-smp$/DEFAULTKERNEL=kernel-PAE/' /etc/sysconfig/kernel
fi
/sbin/new-kernel-pkg --package kernel-PAE --mkinitrd --depmod --install %{KVERREL}PAE-debug || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --add-kernel %{KVERREL}PAE || exit $?
#fi

%post PAE-debug-devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-PAE-debug-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi
%endif

%post xen
if [ `uname -i` == "x86_64" -o `uname -i` == "i386" ]; then
  if [ -f /etc/sysconfig/kernel ]; then
    /bin/sed -i -e 's/^DEFAULTKERNEL=kernel-xen[0U]/DEFAULTKERNEL=kernel-xen/' /etc/sysconfig/kernel || exit $?
  fi
fi
if [ -e /proc/xen/xsd_kva -o ! -d /proc/xen ]; then
	/sbin/new-kernel-pkg --package kernel-xen --mkinitrd --depmod --install --multiboot=/%{image_install_path}/xen.gz-%{KVERREL} %{KVERREL}xen || exit $?
else
	/sbin/new-kernel-pkg --package kernel-xen --mkinitrd --depmod --install %{KVERREL}xen || exit $?
fi
if [ -x /sbin/ldconfig ]
then
    /sbin/ldconfig -X || exit $?
fi
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --add-kernel %{KVERREL}xen || exit $?
#fi

%post xen-devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-xen-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi

%post kdump
/sbin/new-kernel-pkg --package kernel-kdump --mkinitrd --depmod --install %{KVERREL}kdump || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --add-kernel %{KVERREL}kdump || exit $?
#fi

%post kdump-devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ] ; then
  pushd /usr/src/kernels/%{KVERREL}-kdump-%{_target_cpu} > /dev/null
  /usr/bin/find . -type f | while read f; do hardlink -c /usr/src/kernels/*FC*/$f $f ; done
  popd > /dev/null
fi


%preun
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL} || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --remove-kernel %{KVERREL} || exit $?
#fi

%preun smp
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}smp || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --remove-kernel %{KVERREL}smp || exit $?
#fi

%preun PAE
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}PAE || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --remove-kernel %{KVERREL}PAE || exit $?
#fi

%preun kdump
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}kdump || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --remove-kernel %{KVERREL}kdump || exit $?
#fi

%if %{debugbuildsenabled}
%preun debug
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}debug || exit $?
if [ -x /sbin/weak-modules ]
then
    /sbin/weak-modules --remove-kernel %{KVERREL}debug || exit $?
fi

%preun PAE-debug
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}PAE-debug || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --remove-kernel %{KVERREL}PAE || exit $?
#fi
%endif

%preun xen
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}xen || exit $?
#if [ -x /sbin/weak-modules ]
#then
#    /sbin/weak-modules --remove-kernel %{KVERREL}xen || exit $?
#fi

###
### file lists
###

# This is %{image_install_path} on an arch where that includes ELF files,
# or empty otherwise.
%define elf_image_install_path %{?kernel_image_elf:%{image_install_path}}

%if %{with_up}
%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%files debuginfo
%defattr(-,root,root)
%if "%{elf_image_install_path}" != ""
/usr/lib/debug/%{elf_image_install_path}/*-%{KVERREL}.debug
%endif
/usr/lib/debug/lib/modules/%{KVERREL}
/usr/lib/debug/usr/src/kernels/%{KVERREL}-%{_target_cpu}
%endif
%endif

%files
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}
/boot/System.map-%{KVERREL}
#/boot/symvers-%{KVERREL}.gz
/boot/config-%{KVERREL}
%dir /lib/modules/%{KVERREL}
/lib/modules/%{KVERREL}/kernel
/lib/modules/%{KVERREL}/build
/lib/modules/%{KVERREL}/source
/lib/modules/%{KVERREL}/extra
/lib/modules/%{KVERREL}/updates
/lib/modules/%{KVERREL}/weak-updates
/lib/modules/%{KVERREL}/modules.scsi
/lib/modules/%{KVERREL}/modules.libata
/lib/modules/%{KVERREL}/modules.networking
%ghost /boot/initrd-%{KVERREL}.img

%files devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-%{_target_cpu}
%endif


%if %{with_headers}
%files headers
%defattr(-,root,root)
/usr/include/*
%endif


%if %{debugbuildsenabled}
%if %{with_debug}
%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%files debug-debuginfo
%defattr(-,root,root)
%if "%{elf_image_install_path}" != ""
/usr/lib/debug/%{elf_image_install_path}/*-%{KVERREL}debug.debug
%endif
/usr/lib/debug/lib/modules/%{KVERREL}debug
/usr/lib/debug/usr/src/kernels/%{KVERREL}-debug-%{_target_cpu}
%endif
%endif

%files debug
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}debug
/boot/System.map-%{KVERREL}debug
#/boot/symvers-%{KVERREL}debug.gz
/boot/config-%{KVERREL}debug
%dir /lib/modules/%{KVERREL}debug
/lib/modules/%{KVERREL}debug/kernel
/lib/modules/%{KVERREL}debug/build
/lib/modules/%{KVERREL}debug/source
/lib/modules/%{KVERREL}debug/extra
/lib/modules/%{KVERREL}debug/updates
/lib/modules/%{KVERREL}debug/weak-updates
/lib/modules/%{KVERREL}debug/modules.scsi
/lib/modules/%{KVERREL}debug/modules.libata
/lib/modules/%{KVERREL}debug/modules.networking
%ghost /boot/initrd-%{KVERREL}debug.img

%files debug-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-debug-%{_target_cpu}
/usr/src/kernels/%{KVERREL}debug-%{_target_cpu}
%endif
%endif



%if %{with_pae}
%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%files PAE-debuginfo
%defattr(-,root,root)
%if "%{elf_image_install_path}" != ""
/usr/lib/debug/%{elf_image_install_path}/*-%{KVERREL}PAE.debug
%endif
/usr/lib/debug/lib/modules/%{KVERREL}PAE
/usr/lib/debug/usr/src/kernels/%{KVERREL}-PAE-%{_target_cpu}
%endif
%endif

%files PAE
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}PAE
/boot/System.map-%{KVERREL}PAE
#/boot/symvers-%{KVERREL}PAE.gz
/boot/config-%{KVERREL}PAE
%dir /lib/modules/%{KVERREL}PAE
/lib/modules/%{KVERREL}PAE/kernel
/lib/modules/%{KVERREL}PAE/build
/lib/modules/%{KVERREL}PAE/source
/lib/modules/%{KVERREL}PAE/extra
/lib/modules/%{KVERREL}PAE/updates
/lib/modules/%{KVERREL}PAE/weak-updates
/lib/modules/%{KVERREL}PAE/modules.scsi
/lib/modules/%{KVERREL}PAE/modules.libata
/lib/modules/%{KVERREL}PAE/modules.networking
%ghost /boot/initrd-%{KVERREL}PAE.img

%files PAE-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-PAE-%{_target_cpu}
/usr/src/kernels/%{KVERREL}PAE-%{_target_cpu}

%if %{debugbuildsenabled}
%if %{with_debug}
%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%files PAE-debug-debuginfo
%defattr(-,root,root)
%if "%{elf_image_install_path}" != ""
/usr/lib/debug/%{elf_image_install_path}/*-%{KVERREL}PAE-debug.debug
%endif
/usr/lib/debug/lib/modules/%{KVERREL}PAE-debug
/usr/lib/debug/usr/src/kernels/%{KVERREL}-PAE-debug-%{_target_cpu}
%endif
%endif

%files PAE-debug
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}PAE-debug
/boot/System.map-%{KVERREL}PAE-debug
#/boot/symvers-%{KVERREL}PAE-debug.gz
/boot/config-%{KVERREL}PAE-debug
%dir /lib/modules/%{KVERREL}PAE-debug
/lib/modules/%{KVERREL}PAE-debug/kernel
/lib/modules/%{KVERREL}PAE-debug/build
/lib/modules/%{KVERREL}PAE-debug/source
/lib/modules/%{KVERREL}PAE-debug/extra
/lib/modules/%{KVERREL}PAE-debug/updates
/lib/modules/%{KVERREL}PAE-debug/weak-updates
/lib/modules/%{KVERREL}PAE-debug/modules.scsi
/lib/modules/%{KVERREL}PAE-debug/modules.libata
/lib/modules/%{KVERREL}PAE-debug/modules.networking
%ghost /boot/initrd-%{KVERREL}PAE-debug.img

%files PAE-debug-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-PAE-debug-%{_target_cpu}
/usr/src/kernels/%{KVERREL}PAE-debug-%{_target_cpu}
%endif
%endif
# PAE
%endif


%if %{with_smp}
%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%files smp-debuginfo
%defattr(-,root,root)
%if "%{elf_image_install_path}" != ""
/usr/lib/debug/%{elf_image_install_path}/*-%{KVERREL}smp.debug
%endif
/usr/lib/debug/lib/modules/%{KVERREL}smp
/usr/lib/debug/usr/src/kernels/%{KVERREL}-smp-%{_target_cpu}
%endif
%endif

%files smp
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}smp
/boot/System.map-%{KVERREL}smp
#/boot/symvers-%{KVERREL}smp.gz
/boot/config-%{KVERREL}smp
%dir /lib/modules/%{KVERREL}smp
/lib/modules/%{KVERREL}smp/kernel
/lib/modules/%{KVERREL}smp/build
/lib/modules/%{KVERREL}smp/source
/lib/modules/%{KVERREL}smp/extra
/lib/modules/%{KVERREL}smp/updates
/lib/modules/%{KVERREL}smp/weak-updates
/lib/modules/%{KVERREL}smp/modules.scsi
/lib/modules/%{KVERREL}smp/modules.libata
/lib/modules/%{KVERREL}smp/modules.networking
%ghost /boot/initrd-%{KVERREL}smp.img

%files smp-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu}
/usr/src/kernels/%{KVERREL}smp-%{_target_cpu}
%endif


%if %{includexen}
%if %{with_xen}
%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%files xen-debuginfo
%defattr(-,root,root)
%if "%{elf_image_install_path}" != ""
/usr/lib/debug/%{elf_image_install_path}/*-%{KVERREL}xen.debug
%endif
/usr/lib/debug/lib/modules/%{KVERREL}xen
/usr/lib/debug/usr/src/kernels/%{KVERREL}-xen-%{_target_cpu}
/usr/lib/debug/boot/xen*-%{KVERREL}.debug
%endif
%endif

%files xen
%defattr(-,root,root)
/%{image_install_path}/vmlinuz-%{KVERREL}xen
/boot/System.map-%{KVERREL}xen
#/boot/symvers-%{KVERREL}xen.gz
/boot/config-%{KVERREL}xen
/%{image_install_path}/xen.gz-%{KVERREL}
/boot/xen-syms-%{KVERREL}
%dir /lib/modules/%{KVERREL}xen
/lib/modules/%{KVERREL}xen/kernel
%verify(not mtime) /lib/modules/%{KVERREL}xen/build
/lib/modules/%{KVERREL}xen/source
/etc/ld.so.conf.d/kernelcap-%{KVERREL}.conf
/lib/modules/%{KVERREL}xen/extra
/lib/modules/%{KVERREL}xen/updates
/lib/modules/%{KVERREL}xen/weak-updates
/lib/modules/%{KVERREL}xen/modules.scsi
/lib/modules/%{KVERREL}xen/modules.libata
/lib/modules/%{KVERREL}xen/modules.networking
%ghost /boot/initrd-%{KVERREL}xen.img

%files xen-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-xen-%{_target_cpu}
/usr/src/kernels/%{KVERREL}xen-%{_target_cpu}
%endif
%endif

%if %{with_kdump}
%if "%{_enable_debug_packages}" == "1"
%ifnarch noarch
%files kdump-debuginfo
%defattr(-,root,root)
%if "%{image_install_path}" != ""
/usr/lib/debug/%{image_install_path}/*-%{KVERREL}kdump.debug
%endif
/usr/lib/debug/lib/modules/%{KVERREL}kdump
/usr/lib/debug/usr/src/kernels/%{KVERREL}-kdump-%{_target_cpu}
%endif
%endif

%files kdump
%defattr(-,root,root)
/%{image_install_path}/vmlinux-%{KVERREL}kdump
/boot/System.map-%{KVERREL}kdump
#/boot/symvers-%{KVERREL}kdump.gz
/boot/config-%{KVERREL}kdump
%dir /lib/modules/%{KVERREL}kdump
/lib/modules/%{KVERREL}kdump/kernel
/lib/modules/%{KVERREL}kdump/build
/lib/modules/%{KVERREL}kdump/source
/lib/modules/%{KVERREL}kdump/extra
/lib/modules/%{KVERREL}kdump/updates
/lib/modules/%{KVERREL}kdump/weak-updates
/lib/modules/%{KVERREL}kdump/modules.scsi
/lib/modules/%{KVERREL}kdump/modules.libata
/lib/modules/%{KVERREL}kdump/modules.networking
%ghost /boot/initrd-%{KVERREL}kdump.img

%files kdump-devel
%defattr(-,root,root)
%verify(not mtime) /usr/src/kernels/%{KVERREL}-kdump-%{_target_cpu}
/usr/src/kernels/%{KVERREL}kdump-%{_target_cpu}
%endif

# only some architecture builds need kernel-doc

%if %{with_doc}
%files doc
%defattr(-,root,root)
%{_datadir}/doc/kernel-doc-%{kversion}/Documentation/*
%dir %{_datadir}/doc/kernel-doc-%{kversion}/Documentation
%dir %{_datadir}/doc/kernel-doc-%{kversion}
%endif

%changelog
* Wed May 23 2007 Dave Jones <davej@redhat.com>
- Disable more debug options in the non-debug builds.

* Fri Oct 13 2006 Dave Jones <davej@redhat.com>
- 2.6.19rc2
