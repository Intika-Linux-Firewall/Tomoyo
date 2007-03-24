summary: the linux kernel (the core of the linux operating system)

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.

%define buildup 1
%define buildsmp 1
%define buildsource 0
%define buildhugemem 1
%define buildlargesmp 1
%define builddoc 0
%define kabi 1

%define FC2 0
%define FC3 0

#added to allow build with unpackaged or missing docs (CentOS-4)
%define _unpackaged_files_terminate_build 0
%define _missing_doc_files_terminate_build 0

# Versions of various parts

#
# Polite request for people who spin their own kernel rpms:
# please modify the "release" field in a way that identifies
# that the kernel isn't the stock distribution kernel, for example by
# adding some text to the end of the version number.
#
%define release 42.0.10.EL_tomoyo_1.4
%define sublevel 9
%define kversion 2.6.%{sublevel}
%define rpmversion 2.6.%{sublevel}
%define signmodules 0
%define make_target bzImage

%if %{kabi}
# kABI_major needs to change whenever we make changes that would break
# existing modules.  kABI_minor needs to be bumped whenever we add exports
# (but otherwise maintain the ABI).  When kABI_major gets bumped, reset 
# kABI_minor to 0.
%define kabi_major 4.0
%define kabi_minor 0
%endif

%define KVERREL %{PACKAGE_VERSION}-%{PACKAGE_RELEASE}

# groups of related archs
# Added i586 kernel support (CentOS-4)
#%define all_x86 i686
%define all_x86 i586 i686

# Override generic defaults with per-arch defaults 

%ifarch noarch
%define builddoc 1
%define buildsource 0
%define buildup 0
%define buildsmp 0
%define buildlargesmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}*.config
%endif

%ifnarch i686
%define buildhugemem 0
%endif

# Second, per-architecture exclusions (ifarch)

%ifarch %{all_x86}
%define buildlargesmp 0
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
%define buildlargesmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc64*.config
%define image_install_path boot
%define signmodules 1
%define make_target bzImage
%endif

%ifarch s390
%define buildsmp 0
%define buildlargesmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-s390*.config
%define image_install_path boot
%endif

%ifarch s390x
%define buildsmp 0
%define buildlargesmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-s390x.config
%define image_install_path boot
%endif

%ifarch ppc
%define buildlargesmp 0
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ppc*.config
%define buildsmp 0
%define image_install_path boot
%endif

%ifarch ia64
%define all_arch_configs $RPM_SOURCE_DIR/kernel-%{kversion}-ia64*.config
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
%define package_conflicts  cipe < 1.4.5, tux < 2.1.0, kudzu <= 0.92, initscripts < 7.23, dev < 3.2-7, iptables < 1.2.5-3, bcm5820 < 1.81, nvidia-rh72 <= 1.0, ipw2200-firmware < 2.2

#
# Several packages had bugs in them that became obvious when the NPTL
# threading code got integrated. 
#
%define nptl_conflicts SysVinit < 2.84-13, pam < 0.75-48, vixie-cron < 3.0.1-73, privoxy < 3.0.0-8, spamassassin < 2.44-4.8.x,  cups < 1.1.17-13

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
%define kernel_prereq  fileutils, module-init-tools, initscripts >= 5.83, mkinitrd >= 4.2.1.6-1

#
# don't use RPM's internal dependency generator, instead
# just use our magic one that finds the versions of kernel modules for
# provides and don't do any requires
# (we used to just turn off AutoReqProv on all packages)
#
%define _use_internal_dependency_generator 0
%define __find_provides /usr/lib/rpm/redhat/find-kmod-provides.sh
%define __find_requires %{nil}

Name: kernel
Group: System Environment/Kernel
License: GPLv2
Version: %{rpmversion}
Release: %{release}
ExclusiveArch: noarch %{all_x86} x86_64 ppc64 ppc64iseries s390 s390x ia64
ExclusiveOS: Linux
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{release}

%if %{kabi}
Provides: kABI(%{kabi_major}.%{_target_cpu}) = %{kabi_minor}
%endif

Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{nptl_conflicts}
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function


#
# List the packages used during the kernel build
#
BuildPreReq: module-init-tools, patch >= 2.5.4, bash >= 2.03, sh-utils, tar
BuildPreReq: bzip2, findutils, gzip, m4, perl, make >= 3.78, gnupg, kernel-utils 
BuildRequires: gcc >= 2.96-98, binutils >= 2.12, redhat-rpm-config >= 8.0.32.1
BuildConflicts: rhbuildsys(DiskFree) < 500Mb



Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-%{kversion}.tar.bz2

Source10: COPYING.modules
Source11: genkey.centos
Source12: modsign_exclude

#Added sources for the i586 Kernel (CentOS-4)
Source20: kernel-%{kversion}-i586.config
Source21: kernel-%{kversion}-i586-smp.config

Source22: kernel-%{kversion}-i686.config
Source23: kernel-%{kversion}-i686-smp.config
Source24: kernel-%{kversion}-i686-hugemem.config
Source25: kernel-%{kversion}-x86_64.config
Source26: kernel-%{kversion}-x86_64-smp.config
Source27: kernel-%{kversion}-x86_64-largesmp.config
Source28: kernel-%{kversion}-ppc64.config
Source29: kernel-%{kversion}-ppc64iseries.config
Source30: kernel-%{kversion}-s390.config
Source31: kernel-%{kversion}-s390x.config
Source32: kernel-%{kversion}-ppc.config
Source33: kernel-%{kversion}-ia64.config
Source34: kernel-%{kversion}-ia64-largesmp.config
Source35: kernel-%{kversion}-ppc64-largesmp.config
Source15000: ccs-patch-1.4-20070401.tar.gz

#
# Patches 0 through 100 are meant for core subsystem upgrades
#
Patch3: patch-2.6.9-ac11.bz2
Patch4: linux-2.6.9-selected-ac-bits.patch

#
# Patches 10 to 100 are upstream patches we want to back out 
#
Patch10: linux-2.6.9-ac-backouts.patch
Patch11: linux-2.6.7-iobitmap.patch

# Patches 100 through 500 are meant for architecture patches

# 200 - 299   x86(-64)
Patch201: linux-2.6.9-x86_64-copy_user_generic-exception.patch
Patch202: linux-2.6.9-x86-share-cachedescriptors.patch
Patch203: linux-2.6.9-x86_64-configure-oops-stackdump.patch
Patch204: linux-2.6.9-x86_64-phys_proc_id-only-when-initialised.patch
Patch205: linux-2.6.9-x86_64-missing-compat-ioctls.patch
Patch206: linux-2.6.9-x86-show_trace-irq-context.patch
Patch207: linux-2.6.9-x86_64-lost-edge-triggered-irqs.patch
Patch208: linux-2.6.9-x86_64-mga-dri.patch
Patch209: linux-2.6.9-x86_64-ni_syscall-overrun.patch
Patch210: linux-2.6.9-x86_64-flexmmap.patch
Patch211: linux-2.6.9-x86_64-task_size-32bit.patch
Patch212: linux-2.6.9-x86-sysenter-ebp.patch
Patch213: linux-2.6.10-x86-dma_declare_coherent_memory-kmalloc-args.patch
Patch214: linux-2.6.9-x86-intel-ich7-ids.patch
Patch215: linux-2.6.9-x86_64-hit-hpet-twice.patch
Patch216: linux-2.6.9-x86-vsyscall-sysenter-unwind-info.patch
Patch217: linux-2.6.9-x86_64-switch_to-missinglock.patch
Patch218: linux-2.6.9-x86-enhanced-speedstep.patch
Patch219: linux-2.6.9-x86_64-nmi-switch.patch
Patch220: linux-2.6.9-x86_64-panic_timeout.patch
Patch221: linux-2.6.9-x86_64-srat-numa.patch
Patch222: linux-2.6.9-x86_64-hugetlb.patch
Patch223: linux-2.6.9-x86_64-change_page_attr-flush-fix.patch
Patch224: linux-2.6.9-x86_64-syscall_signal-restart.patch
Patch225: linux-2.6.9-x86_64-clustered-apic.patch
Patch226: linux-2.6.9-x86_64-amd-dualcore.patch
Patch227: linux-2.6.9-x86-irq-stack-apic-context.patch
Patch228: linux-2.6.9-ioremap-fixes.patch
Patch229: linux-2.6.9-x86-cpuid4.patch
Patch230: linux-2.6.9-hpet-legacy.patch
Patch231: linux-2.6.9-dualcore.patch
Patch232: linux-2.6.9-x8664-acpi-off.patch
Patch233: linux-2.6.9-powernow-k8.patch
Patch234: linux-2.6.9-x8664-reboot.patch
Patch235: linux-2.6.9-x8664-hotplug.patch
Patch236: linux-2.6.9-x8664-enable-numa.patch
Patch237: linux-2.6.9-x8664-csum-copy.patch
Patch238: linux-2.6.9-x8664-morrison-numa.patch
Patch239: linux-2.6.9-x86-irq-boot-disable-dualcore.patch
Patch240: linux-2.6.9-x8664-pfn-valid.patch
Patch241: linux-2.6.9-x86-thread-leak.patch
Patch242: linux-2.6.9-x8664-largesmp.patch
Patch243: linux-2.6.9-x86-cpu-relax.patch
Patch244: linux-2.6.9-x86-disable-ht.patch
Patch245: linux-2.6.9-x86-correct-cpufreq.patch
Patch246: linux-2.6.9-x8664-dma-snyc-cpu-device.patch
Patch247: linux-2.6.9-x8664-unisys.patch
Patch248: linux-2.6.9-x8664-noiommu.patch
Patch249: linux-2.6.9-x8664-32-bit-hang.patch
Patch250: linux-2.6.9-x8664-pci-iomap.patch
Patch251: linux-2.6.9-x8664-set-bit.patch
Patch252: linux-2.6.9-x86-auto-bigsmp.patch
Patch253: linux-2.6.9-x8664-agp.patch
Patch254: linux-2.6.9-x8664-core.patch
Patch255: linux-2.6.9-x8664-mce.patch
Patch256: linux-2.6.9-x86-pci-ioapic.patch
Patch257: linux-2.6.9-x86-nmi-oprofile.patch
Patch258: linux-2.6.9-x86-enable-apic-up.patch
Patch259: linux-2.6.9-x86-irq-compression.patch
Patch260: linux-2.6.9-x8664-srat-parser.patch
Patch261: linux-2.6.9-x8664-pgtable-alloc.patch
Patch262: linux-2.6.9-x86-mem-limit.patch
Patch263: linux-2.6.9-x86-setup-gap.patch
Patch264: linux-2.6.9-x86-dmi-scan.patch
Patch265: linux-2.6.9-x86-vdso-signal-tramp.patch
Patch266: linux-2.6.9-x8664-cmd-line.patch
Patch267: linux-2.6.9-x8664-tlb-flush.patch
Patch268: linux-2.6.9-x86-modern-apic.patch
Patch269: linux-2.6.9-x86-sci-override.patch
Patch270: linux-2.6.9-x86-timer-over-8254.patch
Patch271: linux-2.6.9-x8664-lapic-status.patch
Patch272: linux-2.6.9-x8664-ebda-alloc.patch

# 300 - 399   ppc(64)
Patch300: linux-2.6.2-ppc64-build.patch
Patch301: linux-2.6.8-ppc64-netboot.patch
Patch302: linux-2.6.9-ppc64-singlestep.patch
Patch303: linux-2.6.9-ppc64-hvsi-udbg.patch
Patch304: linux-2.6.9-ppc64-hvsi-reset.patch
Patch305: linux-2.6.9-ppc64-pci-hostbridge-hotplug.patch
Patch306: linux-2.6.9-ppc64-vscsi.patch
Patch307: linux-2.6.9-ppc64-signal-backtrace.patch
Patch308: linux-2.6.9-ppc64-hvsi-hangup.patch
Patch309: linux-2.6.9-ppc64-cpu-hotplug-map-cpu-node.patch
Patch310: linux-2.6.9-ppc64-cpu-hotplug-sched-domains.patch
Patch311: linux-2.6.9-ppc64-cpu-hotplug-notifier.patch
Patch312: linux-2.6.9-ppc64-cpu-hotplug-reinit-scheddomains.patch
Patch313: linux-2.6.9-ppc64-cpu-hotplug-destroy_sched_domains.patch
Patch314: linux-2.6.9-ppc64-cpu-hotplug-use-notifier.patch
Patch315: linux-2.6.9-ppc64-sigsuspend-regstomping.patch
Patch316: linux-2.6.9-ppc64-icom-driver.patch
Patch317: linux-2.6.9-ppc64-ibmvscsi-race-fix.patch
Patch318: linux-2.6.9-ppc64-ensure-irqs-not-hard-disabled.patch
Patch319: linux-2.6.9-ppc64-purr.patch
Patch320: linux-2.6.9-ppc64-eeh-reset-state2.patch
Patch321: linux-2.6.9-ppc64-tce-table-space.patch
Patch322: linux-2.6.9-ppc64-viocd.patch
Patch323: linux-2.6.9-ppc64-lparcfg-paca-align.patch
Patch324: linux-2.6.9-ppc64-ibmveth-getlink.patch
Patch325: linux-2.6.9-ppc64-rpaclose.patch
Patch326: linux-2.6.9-ppc64-alloc-consistent-order.patch
Patch327: linux-2.6.9-ppc64-sighandler-stackalign.patch
Patch328: linux-2.6.9-ppc64-eeh-recover.patch
Patch329: linux-2.6.9-ppc64-idle-setup.patch
Patch330: linux-2.6.9-ppc64-tiocgicount32.patch
Patch331: linux-2.6.9-ppc64-vpa-init.patch
Patch332: linux-2.6.9-ppc64-prom-init.patch
Patch333: linux-2.6.9-ppc64-getpurr.patch
Patch334: linux-2.6.9-ppc64-xmon-early.patch
Patch335: linux-2.6.9-ppc64-iseries-veth-mod-race.patch
Patch336: linux-2.6.9-ppc64-viocd-2.patch
Patch337: linux-2.6.9-ppc64-ibmveth-starve.patch
Patch338: linux-2.6.9-ppc64-numa-memhole.patch
Patch339: linux-2.6.9-ppc64-numa-setup.patch
Patch340: linux-2.6.9-ppc64-clear-ri-after-restore-stack.patch
Patch341: linux-2.6.9-ppc64-ibmvscsi-dangling-ptr.patch
Patch342: linux-2.6.9-ppc64-rpadebug.patch
Patch343: linux-2.6.9-ppc64-rpacc.patch
Patch344: linux-2.6.9-ppc64-noprobe-failed-pci.patch
Patch345: linux-2.6.9-ppc64-io-base.patch
Patch346: linux-2.6.9-ppc64-isa-ioports.patch
Patch347: linux-2.6.9-ppc64-eeh-dynamic.patch
Patch348: linux-2.6.9-ppc-eeh-error-doc.patch
Patch349: linux-2.6.9-vscsi-update-155.patch
Patch350: linux-2.6.9-ppc64-signal-frame.patch
Patch351: linux-2.6.9-ppc64-ext-pci-config.patch
Patch352: linux-2.6.9-ppc64-sigreturn-audit.patch
Patch353: linux-2.6.9-ppc64-iommu-merge.patch
Patch354: linux-2.6.9-veth-updates.patch
Patch355: linux-2.6.13-jasmine.patch
Patch356: linux-2.6.13-xmon-locking.patch
Patch357: linux-2.6.13-evade-hypervisor-bug.patch
Patch358: linux-2.6.9-power5-cpu.patch
Patch359: linux-2.6.9-js20-cpu-enablement.patch
Patch360: linux-2.6.9-ati-radeon.patch
Patch361: linux-2.6.9-offb.patch
Patch362: linux-2.6.9-ppc64-oprofile.patch
Patch363: linux-2.6.9-ppc64-time.patch
Patch364: linux-2.6.9-ppc64-lpar.patch
Patch365: linux-2.6.9-ppc64-early-serial.patch
Patch366: linux-2.6.9-ppc64-vmx.patch
Patch367: linux-2.6.9-ppc64-eeh.patch
Patch368: linux-2.6.9-ppc64-ptrace.patch
Patch369: linux-2.6.9-ppc64-user-access.patch

# 400 - 499   ia64
Patch400: linux-2.6.3-ia64-build.patch
Patch401: linux-2.6.9-ia64-sn2-update.patch
Patch402: linux-2.6.9-ia64-pci-sn2-fix.patch
Patch403: linux-2.6.9-ia64-mmtimer-sn2-fix.patch
Patch404: linux-2.6.9-ia64-qla1280-sn2-fix.patch
Patch405: linux-2.6.9-ia64-sgiioc4-sn2-fix.patch
Patch406: linux-2.6.9-ia64-sn-console-sn2-fix.patch
Patch407: linux-2.6.9-ia64-snsc-sn2-fix.patch
Patch408: linux-2.6.9-ia64-cyclone-timer-fix.patch
Patch409: linux-2.6.9-ia64-irq-routing-maxcpus.patch
Patch410: linux-2.6.9-ia64-sba_iommu-size.patch
Patch411: linux-2.6.9-ia64-tr_info-hang.patch
Patch412: linux-2.6.9-ia64-cpu-relax.patch
Patch413: linux-2.6.9-ia64-init-trigger-switch4.patch
Patch414: linux-2.6.9-ia64-sgiioc-ide-workaround.patch
Patch415: linux-2.6.9-ia64-rx1600-pdh-console-fix.patch
Patch416: linux-2.6.9-ia64-sys_waitid.patch
Patch417: linux-2.6.9-ia64-zx2-idents.patch
Patch418: linux-2.6.9-ia64-ia32_signal-memset-correctness.patch
Patch419: linux-2.6.9-ia64-tollhouse-error.patch
Patch420: linux-2.6.9-ia64-tollhouse-pci-toplogy.patch
Patch421: linux-2.6.9-ia64-tollhouse-inf-loop.patch
Patch422: linux-2.6.9-ia64-tollhouse-add-geoid.patch
Patch423: linux-2.6.9-ia64-tollhouse-header.patch
Patch424: linux-2.6.9-ia64-map-gate-page.patch
Patch425: linux-2.6.12-sn-update.patch
Patch426: linux-2.6.9-ia64-perfmon-update.patch
Patch427: linux-2.6.9-ia64-zx2-console.patch
Patch428: linux-2.6.9-ia64-sx2000.patch
Patch429: linux-2.6.9-ia64-sigprocmask-race.patch
Patch430: linux-2.6.9-ia64-handle-page-not-present.patch
Patch431: linux-2.6.13-ia64-memcpy.patch
Patch432: linux-2.6.13-ia64-multi-core.patch
Patch433: linux-2.6.9-ia64-nat-coredump.patch
Patch434: linux-2.6.9-ia64-dma-get-cache.patch
Patch435: linux-2.6.9-ia64-swiotlb-updates.patch
Patch436: linux-2.6.9-ia64-pci-ext.patch
Patch437: linux-2.6.9-ia64-nested-dtlb-miss-hugetlb.patch
Patch438: linux-2.6.9-ia64-unaligned.patch
Patch439: linux-2.6.9-ia64-irq-share.patch
Patch440: linux-2.6.9-ia64-mmu-context.patch
Patch441: linux-2.6.9-ia64-osinit-dump.patch

# 500 - 599   s390(x)
Patch500: linux-2.6.1-s390-compile.patch
Patch501: linux-2.6.9-s390-autoraid.patch
Patch502: linux-2.6.9-s390-qeth-fake_ll-fix.patch
Patch503: linux-2.6.9-s390-zfcp_port-fix.patch
Patch504: linux-2.6.9-s390-zfcp-stackframe.patch
Patch506: linux-2.6.9-s390-dasd-fixed-buffer.patch
Patch507: linux-2.6.9-s390-core_dump-fix.patch
Patch508: linux-2.6.9-s390-lcs_startup-fix.patch
Patch509: linux-2.6.9-s390-qeth_addr-fix.patch
Patch510: linux-2.6.9-s390-qeth_hipersocket-fix.patch
Patch511: linux-2.6.9-s390-no_hz_timer-fix.patch
Patch512: linux-2.6.9-s390-config_watchdog.patch
Patch513: linux-2.6.9-s390-lcs_seq_numbers.patch
Patch514: linux-2.6.11-s390-qeth_fake_ll-fix.patch
Patch515: linux-2.6.10-s390-dasd_io_error-fix.patch
Patch516: linux-2.6.10-s390-qdio_packet_loss-fix.patch
Patch517: linux-2.6.10-s390-cio-fix.patch
Patch518: linux-2.6.11-s390-cio-vary_off-fix.patch
Patch519: linux-2.6.10-s390-qdio_time_delay-fix.patch
Patch520: linux-2.6.9-s390-pagefault-deadlock.patch
Patch521: linux-2.6.9-s390-qeth-netstall-update.patch
Patch522: linux-2.6.9-s390-zfcp-update.patch
Patch523: linux-2.6.9-s390-memory-read.patch
Patch524: linux-2.6.9-s390-fadvise.patch
Patch525: linux-2.6.9-s390-dasd-cio-update.patch
Patch526: linux-2.6.9-s390-crypto-driver-update-116.patch
Patch527: linux-2.6.9-s390-pfault-interrupt-race.patch
Patch528: linux-2.6.9-s390-ptrace-peek-poke.patch
Patch529: linux-2.6.9-s390-swap-offset.patch
Patch530: linux-2.6.9-s390-internal-return.patch
Patch531: linux-2.6.9-s390-cio-patch-retry.patch
Patch532: linux-2.6.9-s390-vmcp.patch
Patch533: linux-2.6.9-s390-debug_feature.patch
Patch534: linux-2.6.9-s390-vm_logreader.patch
Patch535: linux-2.6.9-s390-vmwatchdog.patch
Patch536: linux-2.6.9-s390-qeth-ipv6-ui64.patch
Patch537: linux-2.6.9-s390-semaphore.patch
Patch538: linux-2.6.9-s390-ctc-mpc.patch
Patch539: linux-2.6.9-s390-signal-quiesce-fixes.patch
Patch540: linux-2.6.9-s390-diag10.patch
Patch541: linux-2.6.9-s390-strnlen.patch
Patch542: linux-2.6.9-s390-qeth-update.patch
Patch543: linux-2.6.9-s390-test-bit.patch
Patch544: linux-2.6.9-s390-dcssblk-driver.patch
Patch545: linux-2.6.9-s390-stack-corruption.patch
Patch546: linux-2.6.9-s390-sysrq.patch
Patch547: linux-2.6.9-s390-crypto-overwrite.patch
Patch548: linux-2.6.9-s390-lcs-update.patch
Patch549: linux-2.6.9-s390-hypfs.patch
Patch550: linux-2.6.9-s390-copy-from-user.patch

#
# Patches 900 through 1000 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#
Patch900: linux-2.4.0-nonintconfig.patch

Patch910: linux-2.6.0-exec-shield.patch
Patch911: linux-2.6.8-print-fatal-signals.patch
Patch912: linux-2.6.8-execshield-vaspace.patch
Patch913: linux-2.6.9-nx-large-page.patch
Patch914: linux-2.6.9-ht-active-load-balancing.patch

Patch920: linux-2.6.8-4g4g-backout.patch
Patch921: linux-2.6.0-4g4g.patch
Patch922: linux-2.6.9-4g4g-noncachable.patch
Patch923: linux-2.6.9-4g4g-hugemem-warning.patch
Patch924: linux-2.6.9-4g4g-maxtasksize.patch
Patch930: linux-2.6.0-must_check.patch
Patch940: linux-2.6.2-tux.patch
Patch945: linux-2.6.11-rwsem-intr-safe.patch
Patch946: linux-2.6.11-bio-bounce-error.patch
Patch947: linux-2.6.9-mmiowb.patch

# Module signing infrastructure.
Patch950: linux-2.6.7-modsign-core.patch
Patch951: linux-2.6.7-modsign-crypto.patch
Patch952: linux-2.6.7-modsign-ksign.patch
Patch953: linux-2.6.7-modsign-mpilib.patch
Patch954: linux-2.6.7-modsign-script.patch
Patch955: linux-2.6.7-modsign-include.patch
Patch956: linux-2.6.9-sha1.patch
Patch957: linux-2.6.9-key-unavailable-key-oops.patch

#
# Patches 1000 to 4999 are reserved for bugfixes to drivers and filesystems
#
Patch1000: linux-2.4.0-test11-vidfail.patch
Patch1020: linux-2.6.4-stackusage.patch
Patch1021: linux-2.6.9-smbfs-uid-gid.patch
Patch1022: linux-2.6.9-pci-sysfs.patch
Patch1023: linux-2.6.9-openipmi-update.patch
Patch1024: linux-2.6.9-cifs-update.patch
Patch1025: linux-2.6.9-hfs.patch
# Ext2/Ext3 bits.
Patch1030: linux-2.6.5-ext3-reservations.patch
Patch1031: linux-2.6.8-ext3-reservations-update.patch
Patch1032: linux-2.6.9-ext3-cleanup-abort.patch
Patch1033: linux-2.6.5-ext3-online-resize.patch
Patch1034: linux-2.6.9-ext3-handle-bitmapdel.patch
Patch1035: linux-2.6.9-ext3-handle-double-revoke.patch
Patch1036: linux-2.6.9-ext2-mbcache.patch
Patch1037: linux-2.6.9-ext3-mbcache.patch
Patch1038: linux-2.6.9-ext3-umount-leak.patch
Patch1039: linux-2.6.9-ext3-file-limit.patch
Patch1040: linux-2.6.9-ext3-release-race.patch
Patch1041: linux-2.6.9-ext3-memleak.patch
Patch1042: linux-2.6.9-jbd-umount-race.patch
Patch1043: linux-2.6.9-ext3-nfs-enoent.patch
Patch1044: linux-2.6.9-ext3-xattr-share.patch
Patch1045: linux-2.6.9-ext3-sub-second-timestamp.patch
Patch1046: linux-2.6.9-ext3-acl-extend.patch
Patch1047: linux-2.6.9-ext3-log-do-checkpoint-assertion.patch
Patch1048: linux-2.6.9-ext2-loop-symlink.patch
Patch1049: linux-2.6.9-ext3-jbd-race.patch

Patch1050: linux-2.6.7-devmem.patch
Patch1051: linux-2.6.0-devmem.patch
Patch1060: linux-2.6.3-crash-driver.patch
Patch1070: linux-2.6.0-sleepon.patch
Patch1080: linux-2.6.7-voluntary-preemption.patch
Patch1081: linux-2.6.7-early-schedule.patch
Patch1082: linux-2.6.9-ramfs.patch

Patch1084: linux-2.6.9-ext2-readdir-fpos.patch

Patch1087: linux-2.6.9-ext3-robustness.patch
Patch1088: linux-2.6.9-ext3-dir-hole.patch

# SATA bits.
Patch1100: linux-2.6.9-sata.patch
Patch1101: linux-2.6.9-sata-nth-page.patch
Patch1102: linux-2.6.9-sata-ahci-update.patch
Patch1103: linux-2.6.9-sata-updates.patch
Patch1104: linux-2.6.10-sata-updates.patch
Patch1105: linux-2.6.9-sata-lba48-max-sectors.patch
Patch1106: linux-2.6.12-sata-updates.patch
Patch1107: linux-2.6.9-diskdump-sata.patch
Patch1108: linux-2.6.14-sata-updates.patch

# SCSI bits.
Patch1120: linux-2.6.7-scsi-whitelist.patch
Patch1121: linux-2.6.9-scsi-bounce-limit.patch
Patch1122: linux-2.6.9-scsi-aic-hostraid.patch
Patch1123: linux-2.6.10-scsi-midlayer-updates.patch
Patch1124: linux-2.6.9-scsi-aic-oops-nohardware.patch
Patch1125: linux-2.6.9-scsi-reset-ULDs.patch
Patch1126: linux-2.6.9-scsi-ips-update.patch
Patch1127: linux-2.6.9-scsi-NULL-iterate-devices.patch
Patch1128: linux-2.6.10-scsi-qla2xxx-update.patch
Patch1129: linux-2.6.10-scsi-cciss-clustering-fix.patch
Patch1130: linux-2.6.9-scsi-usb-forced-remove-oops.patch
Patch1131: linux-2.6.9-scsi-test_unit_ready-cdrom.patch
Patch1132: linux-2.6.9-scsi-aic-leakplug.patch
Patch1133: linux-2.6.9-scsi-refcount-cmd-allocation.patch
Patch1134: linux-2.6.9-scsi-full-status-sg_io.patch
Patch1135: linux-2.6.9-scsi-sg_cmd_done-sg_release-race.patch
Patch1136: linux-2.6.9-scsi-aac-remove-handle-aif.patch
Patch1137: linux-2.6.9-scsi-megaraid-kioc.patch
Patch1138: linux-2.6.9-scsi-inverted-refcounting.patch
Patch1139: linux-2.6.9-scsi-ioctl-overflow.patch

Patch1140: linux-2.6.9-blockfixes.patch
Patch1141: linux-2.6.9-block-segment-coalesce.patch
Patch1142: linux-2.6.9-cciss-getluninfo-fix.patch
Patch1143: linux-2.6.9-sx8-sysfs.patch
Patch1144: linux-2.6.9-block-blkdev_get_blocks-EOF.patch
Patch1145: linux-2.6.9-block-cciss-ioctl-returncode.patch
Patch1146: linux-2.6.9-block-cciss-id-updates.patch
Patch1147: linux-2.6.9-block-__getblk_slow-hang.patch

Patch1150: linux-2.6.9-md-resync-bugs.patch
Patch1151: linux-2.6.9-md-nr_pending.patch
Patch1152: linux-2.6.9-dm-dm_target_msg-ioctl.patch
Patch1153: linux-2.6.9-dm-multipath-ioctl-ref-by-devno.patch
Patch1154: linux-2.6.9-dm-fix-mirror-log-refcount.patch
Patch1155: linux-2.6.9-dm-suspendhook.patch
Patch1156: linux-2.6.9-dm-raid1-deadlock-fix.patch
Patch1157: linux-2.6.9-dm-kprintf-tidy.patch
Patch1158: linux-2.6.9-dm-add-dm_dev-name.patch
Patch1159: linux-2.6.9-dm-details-recordrestore.patch
Patch1160: linux-2.6.9-dm-export-mapinfo.patch
Patch1161: linux-2.6.9-dm-multipath.patch
Patch1162: linux-2.6.9-dm-64bit-fixes.patch
Patch1163: linux-2.6.9-dm-multipath-suspend-requeueing.patch
Patch1164: linux-2.6.9-dm-avoid-bdget.patch
Patch1165: linux-2.6.9-md-bi_max_vecs-fix.patch
Patch1166: linux-2.6.9-md-multipath-assemly.patch
Patch1167: linux-2.6.9-md-bogus-level-check.patch
Patch1168: linux-2.6.9-md-thinkos.patch
Patch1169: linux-2.6.9-dm-mirroring.patch
Patch1170: linux-2.6.9-dm-event-dev-removal.patch
Patch1171: linux-2.6.9-dm-raid1-race.patch
Patch1172: linux-2.6.9-dm-barrier.patch
Patch1173: linux-2.6.9-md-linear.patch


# NFS bits.
Patch1200: linux-2.6.9-NFS-mounthangfix.patch
Patch1201: linux-2.6.9-NFSD-non-null-getxattr.patch
Patch1202: linux-2.6.9-NFSD-locallock-oopsfix.patch
Patch1203: linux-2.6.9-NFSD-putrootfh-return.patch
Patch1204: linux-2.6.9-NFSD-portwarning-dottedquads.patch
Patch1205: linux-2.6.9-NFS-cthon-rename.patch
Patch1206: linux-2.6.8-lockd-racewarn2.patch
Patch1207: linux-2.6.9-lockd-NLM-length.patch
Patch1208: linux-2.6.9-lockd-block-nosleep.patch
Patch1209: linux-2.6.9-lockd-reclaims.patch
Patch1210: linux-2.6.9-lockd-svc-reclaims.patch
Patch1211: linux-2.6.9-NFS-nlmcreds.patch
Patch1212: linux-2.6.9-rpc-autherr-retry.patch
Patch1213: linux-2.6.9-NFS-stackoverflow.patch
Patch1214: linux-2.6.9-NFSD-add_set_client.patch
Patch1215: linux-2.6.9-NFSD-use_set_client4.patch
Patch1216: linux-2.6.9-lockd-callbacks.patch
Patch1217: linux-2.6.9-NFS-auth-oops.patch
Patch1218: linux-2.6.9-NFS-mmap-corruption.patch
Patch1219: linux-2.6.9-NFS-locking-oops.patch
Patch1220: linux-2.6.9-NFS-callback.patch
Patch1221: linux-2.6.9-NFS4-compat-mount.patch
Patch1222: linux-2.6.9-nfs-bindreserve.patch
Patch1223: linux-2.6.9-nfs-procfs-lockd.patch
Patch1224: linux-2.6.9-nfs-intr-flap-prevents.patch
Patch1225: linux-2.6.9-nfsv3-kerberos.patch
Patch1226: linux-2.6.9-knfsd-port.patch
Patch1227: linux-2.6.9-nfs-estale.patch
Patch1228: linux-2.6.9-nfsd-umount-failure.patch
Patch1229: linux-2.6.9-rpc.patch
Patch1230: linux-2.6.9-nfs-acl.patch
Patch1231: linux-2.6.9-nfs-rename-dir.patch
Patch1232: linux-2.6.9-nfs-krb5-mountd.patch
Patch1233: linux-2.6.9-nfs-debug.patch
Patch1234: linux-2.6.9-nfs-gss-pipe-release-oops.patch
Patch1235: linux-2.6.9-nfsv3-locking.patch
Patch1236: linux-2.6.9-nfs-not-syncing-panic.patch
Patch1237: linux-2.6.9-nfsv3-cache-invalidation.patch
Patch1238: linux-2.6.9-nfs-aio.patch
Patch1239: linux-2.6.9-lockd-recovery.patch
Patch1240: linux-2.6.9-nfs-hash.patch
Patch1241: linux-2.6.9-nfs-interrupt.patch
Patch1242: linux-2.6.9-nfs-updates.patch

# Core networking fixes.
Patch1300: linux-2.6.9-net-ipv6-fix-mtu-calculation.patch
Patch1301: linux-2.6.9-net-vlan-change_mtu-success.patch
Patch1302: linux-2.6.9-net-SIOCGIFHWADDR-NULL-dev_addr.patch
Patch1303: linux-2.6.9-net-compat-missing-security.patch
Patch1304: linux-2.6.9-net-xfrm-fixes.patch
Patch1305: linux-2.6.9-net-cmsg_signedness.patch
Patch1306: linux-2.6.9-net-ftp_conntrack_leak.patch
Patch1307: linux-2.6.9-net-ip_options_leak.patch
Patch1308: linux-2.6.9-net-procroute-stale-pointer.patch
Patch1309: linux-2.6.9-net-bonding-panic.patch
Patch1310: linux-2.6.9-net-sk_forward_alloc-BUG.patch
Patch1311: linux-2.6.9-net-tcp-bic-fix.patch
Patch1312: linux-2.6.9-net-fragment-corruption.patch
Patch1313: linux-2.6.9-net-sctp-recv-accounting.patch
Patch1314: linux-2.6.9-net-ipsec-sa-sequence-collision.patch
Patch1315: linux-2.6.9-net-sctp-sendbuffer-accounting.patch
Patch1316: linux-2.6.9-net-snmp6-fix-crash-on-shutdown.patch
Patch1317: linux-2.6.9-net-igmp-avoid-tx-balance.patch
Patch1318: linux-2.6.9-net-ipsec-spinlock-deadlock.patch
Patch1319: linux-2.6.9-net-conntrack-procfiles-remove.patch
Patch1320: linux-2.6.9-net-bonding-arp-failover-fix.patch
Patch1321: linux-2.6.9-net-ipv6-exthdrs-bug.patch
Patch1322: linux-2.6.11-net-sctp-bind.patch
Patch1323: linux-2.6.9-update-bonding-doc.patch
Patch1324: linux-2.6.9-net-ipv6-ui64.patch
Patch1325: linux-2.6.9-ipv6-leak-route.patch
Patch1326: linux-2.6.12-netlink-hang.patch
Patch1327: linux-2.6.12-net-sctp-bind-to-device.patch
Patch1328: linux-2.6.12-sysctl-route-perms.patch
Patch1329: linux-2.6.12-ipvs-conn-flush.patch
Patch1330: linux-2.6.12-tcp-output.patch
Patch1331: linux-2.6.12-network.patch
Patch1332: linux-2.6.9-bonding.patch
Patch1333: linux-2.6.9-net-sctp-shutdown.patch
Patch1334: linux-2.6.9-net-sctp-receive-buffer.patch
Patch1335: linux-2.6.9-net-sctp.patch

# NIC driver updates
Patch1350: linux-2.6.9-net-b44-4g4g.patch
Patch1351: linux-2.6.9-net-tr-irqlock-fix.patch
Patch1352: linux-2.6.9-net-tulip-waitdmastop.patch
Patch1353: linux-2.6.10-net-3c59x-reload-EEPROM.patch
Patch1354: linux-2.6.9-net-tg3-fiber-autoneg-bounces.patch
Patch1355: linux-2.6.9-net-e100-xmit-timeout-enable-interrupts.patch
Patch1356: linux-2.6.9-net-forcedeth-rx-csum.patch
Patch1357: linux-2.6.9-net-via-rhine-devinit.patch
Patch1358: linux-2.6.9-net-e1000-erratum23.patch
Patch1359: linux-2.6.9-net-e1000-post-mature-writeback.patch
Patch1360: linux-2.6.9-net-e1000-rx-mini-jumbo-inval.patch
Patch1361: linux-2.6.9-net-e1000-64k-align-check-dma.patch
Patch1362: linux-2.6.9-net-s2io-update.patch
Patch1364: linux-2.6.10-net-e1000-update.patch
Patch1365: linux-2.6.10-net-e100-update.patch
Patch1366: linux-2.6.9-net-e100-e100_tx_timeout-workqueue.patch
Patch1367: linux-2.6.9-net-sk98lin-module_device_table.patch
Patch1368: linux-2.6.10-net-tg3-update.patch
Patch1369: linux-2.6.9-net-e100-fix-NAPI-state-machine.patch
Patch1370: linux-2.6.9-net-e100-ich7.patch
Patch1371: linux-2.6.9-net-e1000-avoid-sleep-in-timer-context.patch
Patch1372: linux-2.6.9-net-e1000-flush-rmmod.patch
Patch1373: linux-2.6.9-net-forcedeth-class-quirk.patch
Patch1374: linux-2.6.11-net-ixgb-update.patch
Patch1375: linux-2.6.11-net-e1000-update.patch
Patch1376: linux-2.6.9-net-b44-bounce-buffer-fix.patch
Patch1377: linux-2.6.12rc2-net-3c59x-update.patch
Patch1378: linux-2.6.9-net-tg3-update.patch
Patch1379: linux-2.6.9-net-e100-update.patch
Patch1380: linux-2.6.9-net-dl2k-drvname.patch
Patch1381: linux-2.6.9-net-b44-link-status-check.patch
Patch1382: linux-2.6.9-net-typhoon-update.patch
Patch1383: linux-2.6.9-pcnet32-update.patch
Patch1384: linux-2.6.9-forcedeth-update.patch
Patch1385: linux-2.6.9-net-tg3-ethtool.patch
Patch1386: linux-2.6.9-net-bnx2-driver.patch
Patch1387: linux-2.6.9-net-mii-update.patch
Patch1388: linux-2.6.9-net-sky2.patch
patch1389: linux-2.6.9-net-add-skge.patch

# ACPI Horrors.
Patch1400: linux-2.6.9-acpi-breakpoint-nop.patch
Patch1401: linux-2.6.9-acpi-lequal-less-strict.patch
Patch1402: linux-2.6.9-acpi-debug-level.patch
Patch1403: linux-2.6.9-acpi-reset-mechanism.patch
Patch1404: linux-2.6.9-acpi-panic-pci_root_add.patch
Patch1405: linux-2.6.9-acpi-xsdt.patch

# Kprobes
Patch1450: linux-2.6.12-kprobes-base.patch
Patch1451: linux-2.6.12-kprobes-jprobe.patch
Patch1452: linux-2.6.12-kprobes-reentrant.patch
Patch1453: linux-2.6.12-kprobes-return-address.patch
Patch1454: linux-2.6.13-relayfs.patch
Patch1455: linux-2.6.12-kprobes-ia64.patch
Patch1456: linux-2.6.12-kprobes-isr-task.patch
Patch1457: linux-2.6.12-kprobes-smp-miss.patch
Patch1458: linux-2.6.12-kprobes-scalability.patch

# storage driver updates
Patch1470: linux-2.6.9-qlogic-update-80100b5-rh2.patch
Patch1471: linux-2.6.9-cciss-update-266.patch
Patch1472: linux-2.6.9-i2o-updates.patch
Patch1473: linux-2.6.9-cciss-update-268.patch
Patch1474: linux-2.6.9-qlogic-update-8.01.02-d2.patch
Patch1475: linux-2.6.9-sym53c8xx-update.patch
Patch1476: linux-2.6.9-qlogic-update.patch
Patch1477: linux-2.6.9-cciss-update.patch

# Netdump bits.
Patch1500: linux-2.6.8-crashdump-common.patch
Patch1501: linux-2.6.9-crashdump-fix-reboot-failure.patch
Patch1510: linux-2.6.7-netdump.patch
Patch1520: linux-2.6.8-netconsole.patch
Patch1521: linux-2.6.9-netconsole-tg3-oops.patch
Patch1530: linux-2.6.9-netpoll-oops.patch

# Diskdump goodies.
Patch1540: linux-2.6.8-diskdump-3.patch
Patch1541: linux-2.6.8-diskdump-scsi-3.patch
Patch1542: linux-2.6.8-mptfusion-diskdump.patch
Patch1543: linux-2.6.7-aic7xxx-diskdump.patch
Patch1544: linux-2.6.8-sym53c8xx-diskdump.patch
Patch1545: linux-2.6.8-ipr-diskdump.patch
Patch1546: linux-2.6.9-diskdump-dienmi.patch
Patch1547: linux-2.6.9-diskdump-export_state.patch
Patch1548: linux-2.6.9-diskdump-mdelay.patch
Patch1549: linux-2.6.9-diskdump-mem.patch
Patch1550: linux-2.6.9-diskdump-system_state.patch
Patch1551: linux-2.6.9-diskdump-condition.patch
Patch1552: linux-2.6.9-diskdump-gendisk.patch
Patch1554: linux-2.6.9-diskdump-megaraid.patch
Patch1555: linux-2.6.9-diskdump-wce.patch
Patch1556: linux-2.6.9-diskdump-badmsg.patch
Patch1557: linux-2.6.9-dump_smp_call-ia64.patch
Patch1558: linux-2.6.9-dump_smp_call-i386.patch
Patch1559: linux-2.6.9-dump_smp_call-ppc64.patch
Patch1560: linux-2.6.9-dump_smp_call-x86_64.patch
Patch1561: linux-2.6.9-dump_smp_call_function-3.patch
Patch1562: linux-2.6.9-diskdump-maxblocks.patch
Patch1563: linux-2.6.9-diskdump-queuebusy.patch
Patch1564: linux-2.6.9-diskdump-partial.patch
Patch1565: linux-2.6.9-diskdump-swap.patch
Patch1566: linux-2.6.9-diskdump-osinit.patch
Patch1567: linux-2.6.9-diskdump-detail-partial.patch
Patch1568: linux-2.6.9-diskdump-compress.patch
Patch1569: linux-2.6.9-diskdump-ide.patch
Patch1570: linux-2.6.9-diskdump-fixes.patch

# SELinux bits
Patch1600: linux-2.6.9-selinux-netif-fixes.patch
Patch1601: linux-2.6.9-selinux-setxattr-daccheck.patch
Patch1602: linux-2.6.9-selinux-sidtab-locking-fix.patch
Patch1603: linux-2.6.9-selinux-mediate-send_sigurg.patch
Patch1604: linux-2.6.9-selinux-setscheduler-deadlock.patch
Patch1605: linux-2.6.9-selinux-avc-rcu.patch
Patch1606: linux-2.6.9-selinux-xattr-rework-tmpfs-mm.patch
Patch1608: linux-2.6.9-selinux-destroy-avtab-node-cache.patch
Patch1609: linux-2.6.9-selinux-avc_update_node-spinlock-oops.patch
Patch1610: linux-2.6.9-selinux-avc-deadlock.patch
Patch1611: linux-2.6.9-selinux-invalid-policy-fix.patch
Patch1612: linux-2.6.9-selinux-kmalloc-fail-null-deref.patch
Patch1613: linux-2.6.9-selinux-bad-root-context.patch
Patch1614: linux-2.6.9-selinux-invalid-policy-memleak.patch
Patch1615: linux-2.6.9-selinux-attr_force.patch
Patch1616: linux-2.6.9-selinux-unknown-netlink.patch
Patch1617: linux-2.6.12-selinux-free-page.patch
Patch1618: linux-2.6.12-selinux-strcpy-overflow.patch
Patch1619: linux-2.6.12-selinux-mls-compat.patch

# Misc bits.
Patch1700: linux-2.6.9-procfs-getpid-fix.patch
Patch1701: linux-2.6.9-procfs-deadtask-dereference.patch
Patch1702: linux-2.6.9-procfs-self-attr-clear.patch
Patch1710: linux-2.6.9-edd-config.patch
Patch1720: linux-2.6.10-sysfs-update.patch
Patch1730: linux-2.6.9-signal-handling-dr7.patch
Patch1740: linux-2.6.9-timer-barrier.patch
Patch1750: linux-2.6.9-nonpower2sectorsize.patch
Patch1760: linux-2.6.9-module_version.patch
Patch1780: linux-2.6.9-irqaffinity-disable-E7xxx.patch
Patch1781: linux-2.6.9-ASPM-workaround-PCIE.patch
Patch1782: linux-2.6.9-hotplug-msi-update.patch
Patch1783: linux-2.6.9-80332-IOP-hotplug.patch
Patch1784: linux-2.6.9-ExpressCard-hotplug-ICH6M.patch
Patch1785: linux-2.6.9-pcix-hotplug-fixes.patch
Patch1790: linux-2.6.9-hugetlb_get_unmapped_area-fix.patch 
Patch1800: linux-2.6.9-statm-combined.patch
Patch1810: linux-2.6.9-idefloppy-suppress-noise.patch
Patch1820: linux-2.6.9-do_wait-hang-fix.patch
Patch1830: linux-2.6.9-pci_mmcfg_write-flush_error.patch
Patch1840: linux-2.6.9-via-apic-quirk-devinit.patch
Patch1850: linux-2.6.9-autofs-recognise-map-update.patch
Patch1860: linux-2.6.9-taint-mce.patch
Patch1861: linux-2.6.9-taint-force-rmmod.patch
Patch1862: linux-2.6.9-taint-badpage.patch
Patch1870: linux-2.6.9-xtime-correctness.patch
Patch1880: linux-2.6.9-pagevec-alignment.patch
Patch1890: linux-2.6.9-overlapping-vma.patch
Patch1900: linux-2.6.9-futex-disable-warning.patch
Patch1901: linux-2.6.9-futex-mmap_sem-deadlock.patch
Patch1910: linux-2.6.9-spinlock-debug-panic.patch
Patch1920: linux-2.6.9-compat-F_GETLK.patch
Patch1930: linux-2.6.9-waitid-bogus-ECHILD.patch
Patch1950: linux-2.6.9-agp-missing-cacheflushes.patch
Patch1951: linux-2.6.9-agp-posting-bugs.patch
Patch1960: linux-2.6.9-vc-resizing-overflow.patch
Patch1970: linux-2.6.9-kern_exit-race.patch
Patch1971: linux-2.6.9-exit-deadtask-nodentry-cache.patch
Patch1990: linux-2.6.9-random-sysctl-overflow.patch
Patch1991: linux-2.6.9-i8042-release.patch
Patch1992: linux-2.6.9-ixchxrom-flash.patch
Patch1993: linux-2.6.9-nr-keys.patch
Patch1994: linux-2.6.9-active-pci-support.patch
Patch1995: linux-2.6.9-pci-scan-device-master-abort.patch
Patch1996: linux-2.6.9-pci-bar-size.patch
Patch1997: linux-2.6.9-sched-pin-inline.patch

# VM bits.
Patch2000: linux-2.6.9-vm-tame-oomkiller.patch
Patch2001: linux-2.6.9-vm-dirty_ratio-initialisation-fix.patch
Patch2002: linux-2.6.9-vm-pageout-throttling.patch
Patch2003: linux-2.6.9-vm-page-writeback.patch
Patch2004: linux-2.6.9-vm-sc-congested.patch
Patch2005: linux-2.6.9-vm-total-scanned.patch
Patch2007: linux-2.6.9-rlimit_memlock-bypass.patch
Patch2009: linux-2.6.9-vm-oomkiller-tweak.patch
Patch2010: linux-2.6.9-vm-oomkiller-debugging.patch
Patch2011: linux-2.6.9-invalidate-page-race-fix.patch
Patch2012: linux-2.6.9-vm-mincore.patch
Patch2013: linux-2.6.9-vm-dma-zone-exhaustion.patch
Patch2014: linux-2.6.9-vm-improve-scanning.patch
Patch2015: linux-2.6.9-vm-swaptoken-null-mm.patch
Patch2016: linux-2.6.9-vm-unmap-pte-increment.patch
Patch2018: linux-2.6.9-bouncepages-accounting.patch
Patch2019: linux-2.6.9-topdown-mmap.patch
Patch2020: linux-2.6.9-mm-track.patch
Patch2021: linux-2.6.9-prune-icache-vs-iput.patch
Patch2022: linux-2.6.9-proc-disable-oom.patch
Patch2023: linux-2.6.9-ia64-update-mmu-cache.patch
Patch2024: linux-2.6.13-buffer.patch
Patch2025: linux-2.6.13-prio-tree.patch
Patch2026: linux-2.6.9-readahead.patch
Patch2027: linux-2.6.9-vm-committed-space.patch
Patch2028: linux-2.6.9-vmalloc.patch
Patch2029: linux-2.6.9-dirty-ratio.patch
Patch2030: linux-2.6.9-hugetlb.patch
Patch2031: linux-2.6.9-fork-optimization.patch
Patch2032: linux-2.6.9-swap-lock-page.patch
Patch2033: linux-2.6.9-bootmem.patch
Patch2034: linux-2.6.9-busy-inodes.patch

# IDE bits.
Patch2100: linux-2.6.9-ide-csb6-raid.patch
Patch2101: linux-2.6.9-ide-cd-early-EOF.patch
Patch2102: linux-2.6.9-ide-cd-panic.patch
Patch2103: linux-2.6.9-ide-supress-error-msg.patch
Patch2104: linux-2.6.9-ide-blacklist-update.patch
Patch2105: linux-2.6.12-ide-serverworks-hotplug.patch
Patch2106: linux-2.6.12-ide-serverworks-csb6.patch
Patch2107: linux-2.6.9-ide-updates.patch

# USB bits
Patch2200: linux-2.6.9-usb-edgeport-overflows.patch
Patch2201: linux-2.6.9-usb-storage-reload.patch
Patch2202: linux-2.6.9-usb-input-chicony-noget.patch
Patch2203: linux-2.6.13-usb-acm-wb.patch
Patch2204: linux-2.6.9-usb-memory-sticks.patch
Patch2205: linux-2.6.9-usb-toggles.patch
Patch2206: linux-2.6.9-usb-handoff.patch
Patch2207: linux-2.6.9-usb-khubd-deadlock.patch
Patch2208: linux-2.6.9-usb-hid-disconnect.patch
Patch2209: linux-2.6.9-usb-compat-ioctl.patch
Patch2210: linux-2.6.9-usb-ehci-nvidia.patch
Patch2211: linux-2.6.9-usb-cd-size.patch
Patch2212: linux-2.6.9-usb-error-handling.patch
Patch2213: linux-2.6.9-pizzaro-reboot.patch

# More SCSI bits.
Patch2300: linux-2.6.9-scsi-silence-sg_io-warning.patch
Patch2301: linux-2.6.9-scsi-qla-fix-hw-segment-counting.patch
Patch2302: linux-2.6.9-scsi-aacraid-dead-param.patch
Patch2303: linux-2.6.9-scsi-megaraid-update.patch
Patch2304: linux-2.6.9-scsi-megaraid-warning-fixes.patch
Patch2305: linux-2.6.9-scsi-mptfusion-update.patch
Patch2306: linux-2.6.9-i2o-increase-lct-get-timeout.patch
Patch2307: linux-2.6.9-scsi-oops-faulty-dvd.patch
Patch2308: linux-2.6.9-scsi-blacklist-false-echo-buffer.patch
Patch2309: linux-2.6.9-scsi-done-fail.patch
Patch2310: linux-2.6.9-iscsi-sfnet.patch
Patch2311: linux-2.6.12-qla1280-hotplug.patch
Patch2312: linux-2.6.9-ipr-update.patch
Patch2313: linux-2.6.9-ide-scsi-transform.patch
Patch2314: linux-2.6.9-mt-tell.patch
Patch2315: linux-2.6.9-st-sgio.patch
Patch2316: linux-2.6.9-sg-oops.patch
Patch2317: linux-2.6.9-ide-scsi-highmem.patch
Patch2318: linux-2.6.9-megaraid-update.patch
Patch2319: linux-2.6.9-sr-cd-rom-size.patch
Patch2320: linux-2.6.9-megaraid-sas.patch
Patch2321: linux-2.6.9-aacraid-update.patch
Patch2322: linux-2.6.9-sas-aic94xx.patch
Patch2323: linux-2.6.9-scsi-delete-timer-race.patch
Patch2324: linux-2.6.9-scsi-eh-tur.patch
Patch2325: linux-2.6.9-scsi-proc.patch
Patch2326: linux-2.6.9-scsi-qla2xxx-update.patch
Patch2327: linux-2.6.9-scsi-aic7xxx.patch
Patch2328: linux-2.6.9-scsi-adp94xx.patch
Patch2329: linux-2.6.9-scsi-3ware-update.patch

# Audit patches
Patch2400: linux-2.6.9-audit-retcode.patch
Patch2401: linux-2.6.9-audit-caps.patch
Patch2402: linux-2.6.9-auditcongestion.patch
Patch2403: linux-2.6.9-auditlost.patch
Patch2404: linux-2.6.9-audit-loginuid-proc.patch
Patch2405: linux-2.6.9-ppc64-auditsyscall.patch
Patch2406: linux-2.6.9-auditinonum.patch
Patch2407: linux-2.6.9-audit-netlinkfix.patch
Patch2408: linux-2.6.9-auditdev.patch
Patch2409: linux-2.6.9-auditipc.patch
Patch2410: linux-2.6.9-auditstr.patch
Patch2411: linux-2.6.9-auditaltroot.patch
Patch2412: linux-2.6.9-auditarch.patch
Patch2413: linux-2.6.11-rc3.stamp.patch
Patch2414: linux-2.6.9-auditoneliners.patch
Patch2415: linux-2.6.9-ia64-audit-syscall.patch
Patch2416: linux-2.6.9-audit-comm-exe.patch
Patch2417: linux-2.6.9-audit-netlink-loginuid.patch
Patch2418: linux-2.6.9-audit-netlink-perms.patch
Patch2419: linux-2.6.9-auditrequeue.patch
Patch2420: linux-2.6.9-audit-fix-setluid.patch
Patch2421: linux-2.6.9-audit-reuse-skb.patch
Patch2422: linux-2.6.9-audit-x86_64-compat.patch
Patch2423: linux-2.6.9-audit-sel-setscheduler.patch
Patch2424: linux-2.6.9-audit-unknownperm.patch
Patch2425: linux-2.6.9-audit-signal.patch
Patch2426: linux-2.6.9-audit-to-skb-1.patch
Patch2427: linux-2.6.9-audit-to-skb-2.patch
Patch2428: linux-2.6.9-audit-to-skb-3.patch
Patch2429: linux-2.6.9-audit-va-abuse.patch
Patch2430: linux-2.6.9-avc-deadlock.patch
Patch2431: linux-2.6.9-audit-types.patch
Patch2432: linux-2.6.9-audit-spelling.patch
Patch2433: linux-2.6.9-audit-socketcalls.patch
Patch2434: linux-2.6.9-audit-untrusted.patch
Patch2435: linux-2.6.9-audit-kthread.patch
Patch2436: linux-2.6.9-audit-not-auditd.patch
Patch2437: linux-2.6.9-avc-path.patch
Patch2438: linux-2.6.9-auid.patch
Patch2439: linux-2.6.9-audit-serial.patch
Patch2440: linux-2.6.9-audit-arch-first.patch
Patch2441: linux-2.6.9-audit-untrusted-2.patch
Patch2442: linux-2.6.9-audit-aux-defer-free.patch
Patch2443: linux-2.6.9-audit-pwd.patch
Patch2444: linux-2.6.9-audit-filters.patch
Patch2445: linux-2.6.9-audit-inode-flags.patch
Patch2446: linux-2.6.9-audit-reply-thread.patch
Patch2447: linux-2.6.9-audit-backlog-wait.patch
Patch2448: linux-2.6.9-auditd-oom.patch
Patch2449: linux-2.6.9-audit-printk-loglevel.patch
Patch2450: linux-2.6.9-audit-pid.patch
Patch2451: linux-2.6.9-audit-livelock.patch
Patch2452: linux-2.6.9-audit-idle-thread.patch
Patch2453: linux-2.6.9-audit-speedup.patch
Patch2454: linux-2.6.9-audit-task-refcnt.patch
Patch2455: linux-2.6.9-audit-dup-rules.patch
Patch2456: linux-2.6.9-audit-ppc64-syscallresult.patch
Patch2457: linux-2.6.9-audit-syscall-fail.patch
Patch2458: linux-2.6.9-audit-msg2.patch

# Key management patches
Patch2500: linux-2.6.13-taskaux.patch
Patch2501: linux-2.6.13-keys.patch
Patch2502: linux-2.6.13-key-syscall.patch
Patch2503: linux-2.6.13-key-reiserfs.patch
Patch2504: linux-2.6.13-key-calculate-keyring-size.patch
Patch2505: linux-2.6.13-key-updates.patch


# Core FS patches
Patch2550: linux-2.6.12-free-secdata.patch
Patch2551: linux-2.6.12-osync-bdev.patch
Patch2552: linux-2.6.9-blkgetsize-compat-ioctl.patch
Patch2553: linux-2.6.9-dio-vs-truncate.patch
Patch2554: linux-2.6.9-olargefile.patch
Patch2555: linux-2.6.9-osync-error.patch
Patch2556: linux-2.6.9-generic-aio-retval.patch
Patch2557: linux-2.6.9-auditfs.patch
Patch2558: linux-2.6.9-auditfs-lock-contention.patch
Patch2559: linux-2.6.9-audit-panic.patch
Patch2560: linux-2.6.9-audit-cleanup.patch
Patch2561: linux-2.6.9-odirect-2G.patch
Patch2562: linux-2.6.9-register-disk.patch
Patch2563: linux-2.6.9-iosched.patch
Patch2565: linux-2.6.9-readpage-invalidate.patch
Patch2566: linux-2.6.9-fd-limit.patch
Patch2567: linux-2.6.9-dio-gfs-locking.patch
Patch2568: linux-2.6.9-poll.patch
Patch2569: linux-2.6.9-fs-lsm-hooks.patch

# Device Mapper patches
Patch2600: linux-2.6.13-dm-swap-error.patch
Patch2601: linux-2.6.13-dm-private-workqueue.patch
Patch2602: linux-2.6.13-dm-emc-memset.patch
Patch2603: linux-2.6.13-dm-flush-workqueue.patch
Patch2604: linux-2.6.13-dm-raid1-limit-bios-size.patch
Patch2605: linux-2.6.13-dm-email.patch
Patch2606: linux-2.6.13-dm-snapshot-origin.patch
Patch2607: linux-2.6.13-dmc-locking.patch
Patch2608: linux-2.6.13-dm-mpath-suspend.patch
Patch2609: linux-2.6.13-dm-mpath-eio.patch
Patch2610: linux-2.6.13-dm-mpath-pg-init.patch
Patch2611: linux-2.6.13-dm-mpath-scsi-error.patch
Patch2612: linux-2.6.14-dm-updates.patch
Patch2613: linux-2.6.9-dm-mirror-update.patch

# OpenIB Infiniband patches
Patch2700: linux-2.6.9-OFED-1.0-rc6.patch
Patch2701: linux-2.6.9-spinlock-define.patch
Patch2702: linux-2.6.9-if_infiniband.patch
Patch2703: linux-2.6.9-gfp_t-typedef.patch
Patch2704: linux-2.6.9-empty-debugfs.patch
Patch2705: linux-2.6.9-mutex-backport.patch
Patch2706: linux-2.6.9-pci_find_next_cap.patch
Patch2707: linux-2.6.9-scsi_scan_target-export.patch
Patch2708: linux-2.6.9-wait_for_completion_timeout.patch
Patch2709: linux-2.6.9-OpenIB-build.patch
Patch2710: linux-2.6.9-OpenIB-core.patch
Patch2711: linux-2.6.9-OpenIB-idr.patch
Patch2712: linux-2.6.9-OpenIB-mthca-dev.patch
Patch2713: linux-2.6.9-OpenIB-mthca-provider.patch
Patch2714: linux-2.6.9-OpenIB-sdp-orphan.patch
Patch2715: linux-2.6.9-OpenIB-srp-locking.patch
Patch2716: linux-2.6.9-OpenIB-umad.patch
Patch2717: linux-2.6.9-OpenIB-uverbs.patch
Patch2718: linux-2.6.9-OpenIB-srp-header.patch
Patch2719: linux-2.6.9-OpenIB-addr-arp.patch
Patch2720: linux-2.6.9-OpenIB-addr-include.patch
Patch2721: linux-2.6.9-OpenIB-ucm-devt.patch
Patch2722: linux-2.6.9-OpenIB-ucma.patch
Patch2723: linux-2.6.9-OpenIB-device-backport.patch
Patch2724: linux-2.6.9-OpenIB-read_mostly.patch
Patch2725: linux-2.6.9-OpenIB-scatterlist.patch
Patch2726: linux-2.6.9-OpenIB-ipoib-neighbour.patch
Patch2727: linux-2.6.9-OpenIB-skb_header_release.patch
Patch2728: linux-2.6.9-OpenIB-ia64-bitop.patch
Patch2729: linux-2.6.9-OpenIB-net-includes.patch
Patch2730: linux-2.6.9-OpenIB-workqueue.patch
Patch2731: linux-2.6.9-OpenIB-add_lmc_cache.patch
Patch2732: linux-2.6.9-OpenIB-flush_core_git.patch
Patch2733: linux-2.6.9-OpenIB-flush_users.patch
Patch2734: linux-2.6.9-OpenIB-git_ucm_ib_listen.patch
Patch2735: linux-2.6.9-OpenIB-ipath_rollup.patch
Patch2736: linux-2.6.9-OpenIB-ipoib_misaligned.patch
Patch2737: linux-2.6.9-OpenIB-ipoib_netif_wake_fix.patch
Patch2738: linux-2.6.9-OpenIB-local_sa.patch
Patch2739: linux-2.6.9-OpenIB-mad_rmpp_requester_retry.patch
Patch2740: linux-2.6.9-OpenIB-rdma_misc.patch
Patch2741: linux-2.6.9-OpenIB-request_check_GID_LID.patch
Patch2742: linux-2.6.9-OpenIB-sa_pack_unpack.patch
Patch2743: linux-2.6.9-OpenIB-srp_avoid_null_deref.patch
Patch2744: linux-2.6.9-OpenIB-srp_saquery.patch
Patch2745: linux-2.6.9-OpenIB-ipath-backport.patch
Patch2746: linux-2.6.9-OpenIB-srp-host.patch
Patch2747: linux-2.6.9-OFED-rc6-to-final.patch
Patch2748: linux-2.6.9-OpenIB-mthca_cq_error.patch
Patch2749: linux-2.6.9-OpenIB-sdp_fix.patch

# EDAC Support
Patch2800: linux-2.6.9-edac.patch


Patch2999: linux-2.6.3-printopen.patch

#
# External drivers that are about to get accepted upstream
#

# Emulex FC driver
Patch3000: linux-2.6.9-emulex-lpfc.patch
Patch3001: linux-2.6.9-emulex-lpfc-80163.patch
Patch3002: linux-2.6.9-emulex-lpfc-80166.patch
Patch3003: linux-2.6.9-emulex-lpfc-80166x2.patch
Patch3004: linux-2.6.9-emulex-lpfc-801611.patch
Patch3005: linux-2.6.9-emulex-lpfc-801617.patch
Patch3006: linux-2.6.9-emulex-lpfc-801618.patch
Patch3007: linux-2.6.9-emulex-lpfc-801626.patch
Patch3008: linux-2.6.9-emulex-lpfc-shutdown.patch
Patch3009: linux-2.6.9-emulex-lpfcdfc-20014.patch

# Speedtouch USB DSL modem driver.
Patch3010: linux-2.6.9-speedtouch.patch

# Intel Centrino wireless drivers.
Patch3020: linux-2.6.9-ipw2100.patch
Patch3021: linux-2.6.9-ipw2200.patch
Patch3022: linux-2.6.9-ieee80211.patch
Patch3023: linux-2.6.9-80211-update.patch
Patch3024: linux-2.6.9-ipw2100-update.patch
Patch3025: linux-2.6.9-ipw2200-update.patch

# Misc bits.
Patch4001: linux-2.6.10-ac-selected-bits.patch
Patch4002: linux-2.6.9-pty-smp-race.patch
Patch4003: linux-2.6.9-intel8x0-sound-ids.patch
Patch4004: linux-2.6.9-x86-sysrq-b-oops.patch
Patch4005: linux-2.6.9-sys_io_setup-unwritable-addr.patch
Patch4006: linux-2.6.9-ptrace-fixes.patch
Patch4007: linux-2.6.9-panic_on_oops-default.patch
Patch4008: linux-2.6.11-sys_ipc-fix.patch
Patch4009: linux-2.6.9-gpt-partition-noprobe.patch
Patch4010: linux-2.6.9-tmpfs-truncate-BUG.patch
Patch4011: linux-2.6.9-cpufreq-silence-warnings.patch
Patch4012: linux-2.6.9-vesafb-probe-error.patch
Patch4013: linux-2.6.9-dellserial.patch
Patch4014: linux-2.6.9-autofs-leak.patch
Patch4015: linux-2.6.9-tty-locking-fix.patch
Patch4016: linux-2.6.9-execshield-iret.patch
Patch4017: linux-2.6.9-sysrq-enhancements.patch
Patch4018: linux-2.6.9-do_task_stat-accounting-fixes.patch
Patch4019: linux-2.6.11-serial-ns16550a-baud-rate-adjust.patch
Patch4020: linux-2.6.9-quirks.patch
Patch4021: linux-2.6.9-tmpfs-symbolic-oops.patch
Patch4022: linux-2.6.9-esb2-support.patch
Patch4023: linux-2.6.9-sigkill.patch
Patch4024: linux-2.6.9-bio-clone.patch
Patch4025: linux-2.6.9-acpi-powernow-fix.patch
Patch4026: linux-2.6.9-hangcheck-timer.patch
Patch4027: linux-2.6.9-aio.patch
Patch4028: linux-2.6.9-kallsyms-insmod.patch
Patch4029: linux-2.6.9-locks-after-close.patch
Patch4030: linux-2.6.9-autofs.patch
Patch4031: linux-2.6.9-isdn.patch
Patch4032: linux-2.6.9-sound-i810.patch
Patch4033: linux-2.6.9-get-set-priority.patch
Patch4034: linux-2.6.9-disassociate-ctty.patch
Patch4035: linux-2.6.9-signal-coredump.patch
Patch4036: linux-2.6.9-mq.patch
Patch4037: linux-2.6.9-wacom-driver-update.patch
Patch4038: linux-2.6.9-rbu-firmware-driver.patch
Patch4039: linux-2.6.9-docs.patch
Patch4040: linux-2.6.9-blank-screen-console.patch
Patch4041: linux-2.6.9-softrepeat-off.patch
Patch4042: linux-2.6.9-sound-updates.patch
Patch4043: linux-2.6.9-procfs-removal.patch
Patch4044: linux-2.6.9-dcdbas.patch
Patch4045: linux-2.6.9-serial-hang.patch
Patch4046: linux-2.6.9-pci-bist.patch
Patch4047: linux-2.6.9-proc-devices.patch
Patch4048: linux-2.6.9-tunable-per-cpu-pages.patch
Patch4049: linux-2.6.9-tunable-wake-balance.patch
Patch4050: linux-2.6.9-proc-meminfo.patch
Patch4051: linux-2.6.9-i2c.patch
Patch4052: linux-2.6.9-audit-execve.patch
Patch4053: linux-2.6.9-rsa-driver-fixes.patch
Patch4054: linux-2.6.9-boot-cpu-id.patch

# ALSA fixes.
Patch4100: linux-2.6.9-alsa-vx222-newid.patch
Patch4101: linux-2.6.9-alsa-intel-hd-driver.patch
Patch4102: linux-2.6.9-alsa-realtek-alc260.patch
Patch4103: linux-2.6.9-alsa-intel-hd-driver-update.patch

# Security fixes.
Patch5000: linux-2.6.9-CAN-2004-1056-drm-insufficient-locking.patch
Patch5001: linux-2.6.9-CAN-2004-1137-igmp-flaws.patch
Patch5002: linux-2.6.9-CAN-2004-1235-do_brk.patch
Patch5003: linux-2.6.9-CAN-2005-0001-expand-stack-race.patch
Patch5004: linux-2.6.9-CAN-2005-0135-ia64-unwind.patch
Patch5005: linux-2.6.9-CAN-2005-0136-ia64-ptrace.patch
Patch5006: linux-2.6.9-CAN-2005-0176-shmlockperms.patch
Patch5007: linux-2.6.9-CAN-2005-0204-outs-iobitmap.patch
Patch5009: linux-2.6.9-CAN-2005-0209-dst-leak.patch
Patch5010: linux-2.6.9-CAN-2005-0384-ppp-dos.patch
Patch5011: linux-2.6.9-CAN-2005-0400-ext2-infoleak.patch
Patch5012: linux-2.6.9-CAN-2005-0449-ip_defrag.patch
Patch5013: linux-2.6.9-CAN-2005-0531-size_t.patch
Patch5014: linux-2.6.9-CAN-2005-0736-epoll-overflow.patch
Patch5015: linux-2.6.9-CAN-2005-0749-elfloader-kfree.patch
Patch5016: linux-2.6.9-CAN-2005-0750-bluetooth-rangecheck.patch
Patch5017: linux-2.6.9-CAN-2005-1762-x86_64-ptrace-canonical-addr.patch
Patch5018: linux-2.6.9-CAN-2005-0767-drm-radeon-race.patch
Patch5019: linux-2.6.9-CAN-2005-0815-isofs.patch
Patch5020: linux-2.6.9-CAN-2005-0839-N_MOUSE.patch
Patch5021: linux-2.6.10-CAN-2005-0867-sysfs-signedness.patch
Patch5022: linux-2.6.9-CAN-2005-1263-binfmt_elf.patch
Patch5023: linux-2.6.9-CAN-2005-1264-raw-blkdev_ioctl.patch
Patch5024: linux-2.6.12-CAN-2005-1761-ia64-ptrace.patch
Patch5025: linux-2.6.9-CAN-2005-0756-x8664-ptrace-check-segment.patch
Patch5026: linux-2.6.9-CAN-2005-1765-x8664-ptrace-overflow.patch
Patch5027: linux-2.6.9-CAN-2005-2555-cap-net-admin.patch
Patch5028: linux-2.6.9-CAN-2005-2100-44split.patch
Patch5029: linux-2.6.9-CAN-2005-2490-sendmsg-compat.patch
Patch5030: linux-2.6.9-CAN-2005-2492-sendmsg.patch
Patch5031: linux-2.6.9-CAN-2005-2872-ipt-recent.patch
Patch5032: linux-2.6.9-CAN-2005-3053-set-mempolicy.patch
Patch5033: linux-2.6.9-CAN-2005-3110-ebtables-race.patch
Patch5034: linux-2.6.9-CAN-2005-3119-key-leak.patch
Patch5035: linux-2.6.9-CAN-2005-3180-orinoco-etherleak.patch
Patch5036: linux-2.6.9-CAN-2005-3181-getname-leak.patch
Patch5037: linux-2.6.9-CAN-2005-2458-gzip-zlib.patch
Patch5038: linux-2.6.9-CAN-2005-3106-exec-mmap.patch
Patch5039: linux-2.6.9-CAN-2005-2709-sysctl-unregister.patch
Patch5040: linux-2.6.9-CAN-2005-2800-proc-scsi.patch
Patch5041: linux-2.6.9-CVE-2005-3857-printk-dos.patch
Patch5042: linux-2.6.9-CVE-2005-3848-dst-entry-leak.patch
Patch5043: linux-2.6.9-CVE-2005-3858-ip6-input-finish-dos.patch
Patch5044: linux-2.6.9-CVE-2005-3806-ip6-flowlabel-dos.patch
Patch5045: linux-2.6.9-CVE-2005-2185-igmp-dos.patch
Patch5046: linux-2.6.9-CVE-2005-3358-mempolicy.patch
Patch5047: linux-2.6.9-CVE-2005-3784-auto-reap.patch
Patch5048: linux-2.6.9-CVE-2005-4605-proc-info-leak.patch
Patch5049: linux-2.6.9-CVE-2005-2973-ipv6-infinite-loop.patch
Patch5050: linux-2.6.9-CVE-2005-3359-atm-mod-count.patch
Patch5051: linux-2.6.9-CVE-2005-3623-nfs-acl-read.patch
Patch5052: linux-2.6.9-CVE-2006-1052-selinux-ptrace.patch
Patch5053: linux-2.6.9-CVE-2005-3055-usb-perms.patch
Patch5054: linux-2.6.9-CVE-2006-0741-elf.patch
Patch5055: linux-2.6.9-CVE-2006-1056-fpu.patch
Patch5056: linux-2.6.9-CVE-2006-2451-dumpable.patch
Patch5057: linux-2.6.9-CVE-2004-2660-odirect-mem.patch
Patch5058: linux-2.6.9-CVE-2006-1858-sctp-overflow.patch
Patch5059: linux-2.6.9-CVE-2006-2936-ftdi-sio-dos.patch
Patch5060: linux-2.6.9-CVE-2006-2935-cdrom-typo.patch
Patch5061: linux-2.6.9-CVE-2006-3468-nfs-fh.patch
Patch5062: linux-2.6.9-CVE-2006-3626-proc-setuid.patch
Patch5063: linux-2.6.9-CVE-2006-2444-snmp-nat-mem.patch
Patch5064: linux-2.6.9-CVE-2006-2932-ds-es-dos.patch
Patch5065: linux-2.6.9-CVE-2006-2071-mprotect-perms.patch
Patch5066: linux-2.6.9-CVE-2006-4623-dvb.patch
Patch5067: linux-2.6.9-CVE-2006-0039-netfilter.patch
Patch5068: linux-2.6.9-CVE-2006-4093-ppc-clear-en-attn.patch
Patch5069: linux-2.6.9-CVE-2006-4538-ia64-corrupt-elf.patch
Patch5070: linux-2.6.9-CVE-2006-5823-cramfs-zlib-inflate.patch
Patch5071: linux-2.6.9-CVE-2006-6106-capi-size-check.patch

# Security fixes that don't have CANs assigned (yet?)
# These get renamed if one is later assigned.
Patch5100: linux-2.6.9-ptrace-sched-race.patch

#
# 10000 to 20000 is for stuff that has to come last due to the
# amount of drivers they touch. But only these should go here. 
# Not patches you're too lazy for to put in the proper place.
#

Patch10000: linux-2.6.0-compile.patch
Patch10001: linux-2.6.9-exports.patch
Patch10002: linux-2.6.9-slab-update.patch
Patch10003: linux-2.6.9-pci-ids.patch

# empty final patch file to facilitate testing of kernel patches
Patch20000: linux-kernel-test.patch

# END OF PATCH DEFINITIONS

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

%description 
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

%package devel
Summary: Development package for building kernel modules to match the kernel.
Group: System Environment/Kernel
AutoReqProv: no
Provides: kernel-devel-%{_target_cpu} = %{rpmversion}-%{release}

%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the kernel package.

%package sourcecode
Summary: The source code for the Linux kernel.
Group: Development/System
Prereq: fileutils
Requires: make >= 3.78
Requires: gcc >= 3.2
Requires: /usr/bin/strip
# for xconfig and gconfig
Requires: qt-devel, gtk2-devel readline-devel ncurses-devel
Provides: kernel-source
Obsoletes: kernel-source <= 2.6.6

%description sourcecode
The kernel-sourcecode package contains the source code files for the Linux
kernel. The source files can be used to build a custom kernel that is
smaller by virtue of only including drivers for your particular hardware, if
you are so inclined (and you know what you're doing). The customisation
guide in the documentation describes in detail how to do this. This package
is neither needed nor usable for building external kernel modules for
linking such modules into the default operating system kernels.

%package doc
Summary: Various documentation bits found in the kernel source.
Group: Documentation
%if !%{buildsource}
Obsoletes: kernel-source <= 2.6.6
Obsoletes: kernel-sourcecode <= 2.6.6
%endif

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

Provides: kernel-smp-%{_target_cpu} = %{rpmversion}-%{release}
%if %{kabi}
Provides: kABI(%{kabi_major}smp.%{_target_cpu}) = %{kabi_minor}
%endif

%description smp
This package includes a SMP version of the Linux kernel. It is
required only on machines with two or more CPUs as well as machines with
hyperthreading technology.

Install the kernel-smp package if your machine uses two or more CPUs.

%package smp-devel
Summary: Development package for building kernel modules to match the SMP kernel.
Group: System Environment/Kernel
Provides: kernel-smp-devel-%{_target_cpu} = %{rpmversion}-%{release}
AutoReqProv: no

%description smp-devel
This package provides kernel headers and makefiles sufficient to build modules
against the SMP kernel package.

%package hugemem
Summary: The Linux kernel compiled for machines with 16 Gigabytes of memory or more.
Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{nptl_conflicts}
Obsoletes: kernel-enterprise < 2.4.10
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function

Provides: kernel-hugemem-%{_target_cpu} = %{rpmversion}-%{release}
%if %{kabi}
Provides: kABI(%{kabi_major}hugemem.%{_target_cpu}) = %{kabi_minor}
%endif

%description hugemem
This package includes an SMP version of the Linux kernel which
supports systems with 16 Gigabytes of memory or more.

%package hugemem-devel
Summary: Development package for building kernel modules to match the hugemem kernel.
Group: System Environment/Kernel
Provides: kernel-hugemem-devel-%{_target_cpu} = %{rpmversion}-%{release}
AutoReqProv: no

%description hugemem-devel
This package provides kernel headers and makefiles sufficient to build modules
against the hugemem kernel package.

%package largesmp
Summary: The Linux kernel compiled for machines with more than 64 CPUs.

Group: System Environment/Kernel
Provides: kernel = %{version}
Provides: kernel-drm = 4.3.0
Prereq: %{kernel_prereq}
Conflicts: %{kernel_dot_org_conflicts}
Conflicts: %{package_conflicts}
Conflicts: %{nptl_conflicts}
# upto and including kernel 2.4.9 rpms, the 4Gb+ kernel was called kernel-enterprise
# now that the largesmp kernel offers this capability, obsolete the old kernel
Obsoletes: kernel-enterprise < 2.4.10
# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function

Provides: kernel-largesmp-%{_target_cpu} = %{rpmversion}-%{release}
%if %{kabi}
Provides: kABI(%{kabi_major}largesmp.%{_target_cpu}) = %{kabi_minor}
%endif

%description largesmp

This package includes a version of the Linux kernel configured to handle up to
64 CPUs on X86-64, 128 CPUs on PPC64 and 512 CPUs on IA-64.

Install the kernel-largesmp package if your machine has more than 8 CPUs on 
x86-64, more than 64 CPUs on PPC64, or more than 64 CPUs on IA-64.

%package largesmp-devel
Summary: Development package for building modules for the many-CPUs kernel.
Group: System Environment/Kernel
Provides: kernel-largesmp-devel-%{_target_cpu} = %{rpmversion}-%{release}
AutoReqProv: no

%description largesmp-devel
This package provides kernel headers and makefiles sufficient to build modules
against the many CPUs kernel package.

%prep

%setup -q -n %{name}-%{version} -c
cd linux-%{kversion}

#
# Patches 0 through 100 are meant for core subsystem upgrades
# 

# Various fixes from Alan's -ac tree.
%patch3 -p1
%patch4 -p1

#
# Patches to back out
#

# -AC bits we don't want.
%patch10 -p1 -R
# iobitmap increase that breaks booting
%patch11 -p1 -R

#
# Architecture patches
#

#
# x86(-64)
#
# fix x86_64 copy_user_generic
%patch201 -p1
# Share cache descriptors between x86/x86-64
%patch202 -p1
# x86_64: add an option to configure oops stack dump
%patch203 -p1
# x86[64]: display phys_proc_id only when it is initialized
%patch204 -p1
# x86_64: no TIOCSBRK/TIOCCBRK in ia32 emulation
%patch205 -p1
# Fix show_trace() in irq context with CONFIG_4KSTACKS
%patch206 -p1
# x86_64: Fix lost edge triggered irqs on UP kernel
%patch207 -p1
# x86_64: Reenable MGA DRI
%patch208 -p1
# Fix Buffer overrun in arch/x86_64/sys_ia32.c:sys32_ni_syscall()
%patch209 -p1
# Flexible mmap patch for x86-64 
%patch210 -p1
# Fix wrong TASK_SIZE on x86_64 for 32bit processes
%patch211 -p1
# Clear ebp on sysenter return.
%patch212 -p1
# Fix up wrong argument order in dma_declare_coherent_memory()
%patch213 -p1
# ICH7 ID additions
%patch214 -p1
# HPET init needs register to be whacked twice.
%patch215 -p1
# fix i386 vsyscall-sysenter unwind info
%patch216 -p1
# missing lock in switch_to()
%patch217 -p1
# Intel enhanced speedstep fixes.
%patch218 -p1
# NMI switch support for x86_64
%patch219 -p1
# Fix panic() w/panic_timeout hangs instead of rebooting
%patch220 -p1
# SRAT NUMA support.
%patch221 -p1
# Fix hugepages for x86_64
%patch222 -p1
# Fix flush of multiple pages in change_page_attr
%patch223 -p1
# fix syscall/signal restart bug
%patch224 -p1
# Clustered APIC support for x86-64.
%patch225 -p1
# Dual core support for AMD64.
%patch226 -p1
# x86: use the IRQ stack in APIC contexts too
%patch227 -p1
# Numerous ioremap fixes.
%patch228 -p1
# make newer intel cpus recognize cpuid4
%patch229 -p1
# HPET legacy
%patch230 -p1
# intel dual core support
%patch231 -p1
# x8664 acpi off
%patch232 -p1
# powernow k8 support
%patch233 -p1
# x8664 reboot fix
%patch234 -p1
# x8664 hotplug fix
%patch235 -p1
# x8664 enable numa
%patch236 -p1
# x8664 csum partial copy
%patch237 -p1
# x8664 morrison numa fixes
%patch238 -p1
# x86 disable irqs during bogomips calcuation
%patch239 -p1
# x8664 correct pfn_valid
%patch240 -p1
# fix x86 thread info leak
%patch241 -p1
# largesmp patches for x86664
%patch242 -p1
# add cpu_relax() calls
%patch243 -p1
# add noht option for x86 and x86-64
%patch244 -p1
# fix cpufrequency
%patch245 -p1
# implement dma_sync_single_range_for_{cpu,device}
%patch246 -p1
# support for unisys boxes
%patch247 -p1
# eliminate noiommu panic
%patch248 -p1
# fix 32-bit hang
%patch249 -p1
# include iomap.h
%patch250 -p1
# avoid calling node_to_cpumask too early
%patch251 -p1
# autodetect and setup bigsmp mode
%patch252 -p1
# make i810, i830, and i915 build on x86_64
%patch253 -p1
# x8664: add core map support
%patch254 -p1
# x8664: mce updates
%patch255 -p1
# make sure we don't re-assign ioapic addresses
%patch256 -p1
# make oprofile work on p4 systems
%patch257 -p1
# let the BIOS tell us how to set lapic/ioapic for up kernels
%patch258 -p1
# irq compression
%patch259 -p1
# srat paring fix
%patch260 -p1
# find space for pagetables
%patch261 -p1
# mem limit
%patch262 -p1
# setup gap
%patch263 -p1
# dmi scan update
%patch264 -p1
# Mark vDSO signal trampoline EH with the new S flag
%patch265 -p1
# support longer x86_64 cmd line
%patch266 -p1
# disable tlb flush filter
%patch267 -p1
# modern_apic()
%patch268 -p1
# proper sci overridate
%patch269 -p1
# automatically set timer_over_8254
%patch270 -p1
# lapic status for installer
%patch271 -p1
# avoid EBDA for early memory map allocation
%patch272 -p1

# 
# ppc64
#

# Patch for Kconfig and Makefile build issues
%patch300 -p1
%patch301 -p1
# Fix single stepping on PPC64
%patch302 -p1
# HVSI udbg support
%patch303 -p1
# Make HVSI console survive FSP reset
%patch304 -p1
# Make PCI hostbridge hotplugging work
%patch305 -p1
# Fix IBM VSCSI problems
%patch306 -p1
# Store correct backtracking info in ppc64 signal frames
%patch307 -p1
# Prevent HVSI from oopsing on hangup
%patch308 -p1
# Make ppc64 NUMA map CPU->node before bringing up the CPU
%patch309 -p1
# sched domains / cpu hotplug cleanup
%patch310 -p1
# Add a CPU_DOWN_PREPARE hotplug CPU notifier
%patch311 -p1
# Register a cpu hotplug notifier to reinitialize the scheduler domains hierarchy
%patch312 -p1
# Make arch_destroy_sched_domains() conditional
%patch313 -p1
# Use CPU_DOWN_FAILED notifier in the sched-domains hotplug code
%patch314 -p1
# PPC64 sigsuspend stomping on r4 and r5
%patch315 -p1
# Enable ICOM serial driver
%patch316 -p1
# IBM VSCSI driver race fix
%patch317 -p1
# Ensure PPC64 interrupts don't end up hard-disabled
%patch318 -p1
# Add PURR and version data to /proc/ppc64/lparcfg
%patch319 -p1
# Convert to using ibm,read-slot-reset-state2 RTAS call
%patch320 -p1
# Fix inability to find space for TCE table on ppc64
%patch321 -p1
# Prevent block device queues from being shared in viocd
%patch322 -p1
# Align PACA buffer for ppc64 hypervisor's use
%patch323 -p1
# Indicate that the veth link is always up
%patch324 -p1
# Quiesce OpenFirmware stdin device at boot.
%patch325 -p1
# Make ppc64's pci_alloc_consistent() conform to documentation
%patch326 -p1
# fix stack alignment for signal handlers on ppc64
%patch327 -p1
# Provide working PCI EEH error recovery on ppc64 (#135115)
%patch328 -p1
# Move idle loop setup to after main ppc64 arch setup init. (#142634)
%patch329 -p1
# Provide 64-bit translations for 32-bit TIOCMIWAIT/TIOCGICOUNT ioctls
%patch330 -p1
# Fix PPC64 pSeries VPA registration
%patch331 -p1
# Fix communication to PROM to close stdin on PPC64
%patch332 -p1
# Implement h/w PPC64 CPU utilisation data gathering
%patch333 -p1
# Stop xmon=on from jumping immediately into xmon on ppc64
%patch334 -p1
# Fix race and memory leak in iSeries veth module unloading
%patch335 -p1
# Prevent an iSeries partition oopsing with no CDROM drive.
%patch336 -p1
# IBM veth driver buffer starvation fix
%patch337 -p1
# Don't map objects to non-existent PPC64 NUMA nodes
%patch338 -p1
# Fix PPC64 NUMA's handling of memory nodes with holes in them
%patch339 -p1
# move clearing of RI bit to after stack restoration
%patch340 -p1
# Fix a dangling pointer in the IBM vscsi driver
%patch341 -p1
# Implement correct logic for determining hotplug capabilities
%patch342 -p1
# Tell the firmware what the kernels capabilities are
%patch343 -p1
# avoid probing pci devices marked as failed.
%patch344 -p1
# set pci I/O base dynamically
%patch345 -p1
# don't request legacy I/O regions if no ISA bus
%patch346 -p1
# allow hotplug of eeh devices
%patch347 -p1
# add pci eeh error recovery documentation
%patch348 -p1
# update vscsi to v. 1.5.5
%patch349 -p1
# ppc64 signal frame
%patch350 -p1
# Only access extended PCI config regs if available
%patch351 -p1
# make sure sys_sigreturn calls audit
%patch352 -p1
# fix iommu_map_sg to terminate scatter gather list correctly
%patch353 -p1
# veth driver updates
%patch354 -p1
# add jasmine serial driver
%patch355 -p1
# fix xmon locking
%patch356 -p1
# evade hypervisor bug
%patch357 -p1
# add power5+ cpu support
%patch358 -p1
# js20++ cpu enablement
%patch359 -p1 
#add chip id for ATI RN50
%patch360 -p1
#fix offb crash
%patch361 -p1
# fix oprofile for
%patch362 -p1
# fix time going backwards
%patch363 -p1
# fix cpu hotplug
%patch364 -p1
# support early serial console
%patch365 -p1
# fix incorrect get_uswer usage
%patch366 -p1
# eeh dynamic
%patch367 -p1
# ptrace fixes
%patch368 -p1
# fix userspace access checks
%patch369 -p1

#
# ia64
#

# Basic build fixes
%patch400 -p1
%patch401 -p1
%patch402 -p1
%patch403 -p1
%patch404 -p1
%patch405 -p1
%patch406 -p1
%patch407 -p1
%patch408 -p1
%patch409 -p1
%patch410 -p1
%patch411 -p1
%patch412 -p1
%patch413 -p1
%patch414 -p1
%patch415 -p1
%patch416 -p1
%patch417 -p1
%patch418 -p1
# tollhouse support
%patch419 -p1
%patch420 -p1
%patch421 -p1
%patch422 -p1
%patch423 -p1
# make sure gate page is mapped
%patch424 -p1
# sn update
%patch425 -p1
%patch426 -p1
%patch427 -p1
%patch428 -p1
%patch429 -p1
%patch430 -p1
%patch431 -p1
%patch432 -p1
%patch433 -p1
%patch434 -p1
%patch435 -p1
%patch436 -p1
%patch437 -p1
%patch438 -p1
%patch439 -p1
%patch440 -p1
%patch441 -p1

#
# s390
#

# Basic build fixes
%patch500 -p1
# Auto raidstart for S390
%patch501 -p1
# Fix fake_ll for QETH device  (#136175)
%patch502 -p1
# Recover after aborted nameserver request.
%patch503 -p1
# zfcp: Kernel stack frame for zfcp_cfdc_dev_ioctl() is too big
%patch504 -p1
# Fixed buffers for DASD devices.
%patch506 -p1
# Fix coredumps on S390
%patch507 -p1
# lcs device will not start anymore after first detection.
%patch508 -p1
# Fix possible failure of IP addr registration
%patch509 -p1
# Support broadcast on z800/z900 HiperSockets
%patch510 -p1
# fix race condition on s390 when going idle
%patch511 -p1
# include watchdog config on s390
%patch512 -p1
# introduce sequence numbers for lcs packets.
%patch513 -p1
# qeth fake_ll fixes
%patch514 -p1
# delay dasd retries to prevent i/o error
%patch515 -p1
# s390 qdio packet loss
%patch516 -p1
# Fix various problems in s390 common I/O layer.
%patch517 -p1
# s390 common i/o layer vary on/off
%patch518 -p1
# s390 qdio time delay missing interrupt problem
%patch519 -p1
# s390 fix pagefault handler deadlock
%patch520 -p1
# s390 fix qeth stalls and update
%patch521 -p1
# s390 zfcp driver update
%patch522 -p1
# s390 correct memory size read
%patch523 -p1
# s390 fix fadvise for s390x and compat
%patch524 -p1
# s390 dasd + cio driver updates
%patch525 -p1
# s390 crypto driver update to 1.16
%patch526 -p1
# s390 pfault interrupt race fix
%patch527 -p1
# s390 ptrace peek poke fixes
%patch528 -p1
# s390 swap offset fixes
%patch529 -p1
# s390 internal return
%patch530 -p1
# s390 cio patch retry
%patch531 -p1
# s390: add vmcp device driver
%patch532 -p1
# s390: stop debug feature on oops
%patch533 -p1
# s390: add vm logreader driver
%patch534 -p1
# s390: add vm watchdog driver
%patch535 -p1
# qeth driver updates
%patch536 -p1
# s390: semaphore performance fixes
%patch537 -p1
# s390: add ctc mpc driver
%patch538 -p1
# fix signal quiesce
%patch539 -p1
# s390: add fixup exception for diag10 instruction
%patch540 -p1
# s390: make strnlen_user correct
%patch541 -p1
# s390: qeth ui64 fixes
%patch542 -p1
# s390: test_bit fixes
%patch543 -p1
# s390: fix and enable dcssblk driver
%patch544 -p1
# s390: fix possible kernel stack corruption
%patch545 -p1
# s390: sysrq backtrace oops
%patch546 -p1
# s390: fix crypto driver memory overwrite
%patch547 -p1
# s390: lcs driver fixes
%patch548 -p1
# s390: add hypfs filesystem
%patch549 -p1
# s390: add padding to copy-from_user
%patch550 -p1


#
# Patches 500 through 1000 are reserved for bugfixes to the core system
# and patches related to how RPMs are build
#


# This patch adds a "make nonint_oldconfig" which is non-interactive and
# also gives a list of missing options at the end. Useful for automated
# builds (as used in the buildsystem).
%patch900 -p1


#
# The execshield patch series, broken into smaller pieces
#
# 1) Exec shield core
%patch910 -p1
# 2) Option to printk fatal signals, useful for debugging
%patch911 -p1
# 3) The Execshield VA rearrangements
%patch912 -p1
# fix nx for large pages
%patch913 -p1
# ht active load balancing bugfix
%patch914 -p1

#
# 4G/4G split
#
%patch920 -p1 -R
%patch921 -p1
%patch922 -p1
%patch923 -p1
%patch924 -p1

#
# Patch that adds a __must_check attribute for functions for which checking
# the return value is mantadory (eg copy_from_user)
#
%patch930 -p1

#
# TUX
#
%patch940 -p1

# rwsem update
%patch945 -p1

# propogate bounce errors up
%patch946 -p1
# mmiowb support, no-op except for ia64
%patch947 -p1

#
# GPG signed kernel modules
#
%patch950 -p1
%patch951 -p1
%patch952 -p1
%patch953 -p1
%patch954 -p1
%patch955 -p1
%patch956 -p1
%patch957 -p1


#
# Patches 1000 to 4999 are reserved for bugfixes to drivers and filesystems
#


# add vidfail capability; 
# without this patch specifying a framebuffer on the kernel prompt would
# make the boot stop if there's no supported framebuffer device; this is bad
# for the installer cd that wants to automatically fall back to textmode
# in that case
%patch1000 -p1

#
# Fix the extreme stack usage in some kernel functions
#
%patch1020 -p1
# make smbfs honor uid and gid mount options
%patch1021 -p1
# make pci-sysfs do 2-byte accesses 
%patch1022 -p1
# selected ipmi updates
%patch1023 -p1
# update CIFS
%patch1024 -p1
# hfs fixes
%patch1025 -p1

# EXT3 bits.
# Ext3 reservations. reduces fragmentation bigtime
%patch1030 -p1
%patch1031 -p1
# improves ext3's error logging when we encounter an on-disk corruption.
%patch1032 -p1
# ext3 online resize
%patch1033 -p1
# improves ext3's ability to deal with corruption on-disk
%patch1034 -p1
# Handle double-delete of indirect blocks
%patch1035 -p1
# Fix xattr/mbcache race
%patch1036 -p1
%patch1037 -p1
# Fix percpu data leak on umount of ext2/ext3
%patch1038 -p1
# Fix ext2/3 maximum size limits
%patch1039 -p1
# Fix ext3 release race.
%patch1040 -p1
# Fix buffer leak in ext3
%patch1041 -p1
# fix kjournad vs umount race
%patch1042 -p1
# nfs enoent
%patch1043 -p1
# xattr share
%patch1044 -p1
# sub-second timestamp
%patch1045 -p1
# extend ACL limit on ext3 to EA limit
%patch1046 -p1
# fix log_do_checkpoint assertion failure
%patch1047 -p1
# ext2: fix hang on symlink removal for loop devices
%patch1048 -p1
# ext3: fix ext3/jbd race releasing journal heads
%patch1049 -p1


#
# Make /dev/mem a need-to-know function 
#
%patch1050 -p1
%patch1051 -p1


#
# /dev/crash driver for the crashdump analysis tool
#
%patch1060 -p1

#
# Most^WAll users of sleep_on are broken; fix a bunch
#
%patch1070 -p1

#
# Ingo's patch for voluntary preemption
#
%patch1080 -p1
%patch1081 -p1

#ramfs fixes
%patch1082 -p1

# fix ext2 readdir f_pos revalidation logic
%patch1084 -p1

# ext3: make the fs robust when it has already been corrupted
%patch1087 -p1
# ext3: make sure readdir doesn't fail
%patch1088 -p1


#
# Sata update
# 
%patch1100 -p1
%patch1101 -p1
%patch1102 -p1
%patch1103 -p1
%patch1104 -p1
%patch1105 -p1
%patch1106 -p1
%patch1107 -p1
%patch1108 -p1

#
# SCSI Bits.
#
# Additions to the SCSI whitelist to make card readers work.
%patch1120 -p1
# fix SCSI bounce limit
%patch1121 -p1
# AIC host raid support.
%patch1122 -p1
# SCSI midlayer updates from 2.6.10rc
%patch1123 -p1
# Avoid oops when insmod'ing aic79xx on machine without hardware
%patch1124 -p1
# scsi: Add reset ioctl capability to ULDs
%patch1125 -p1
# scsi: Update ips driver to 2.6.10rc version.
%patch1126 -p1
# avoid extra 'put' on devices in __scsi_iterate_device()
# http://marc.theaimsgroup.com/?l=linux-scsi&m=109886580930570&w=2
%patch1127 -p1
# Update Qlogic driver to 2.6.10-rc2
%patch1128 -p1
# cciss: fixes for clustering
%patch1129 -p1
# Fix USB forced remove oops
%patch1130 -p1
# Fix up scsi_test_unit_ready() to work correctly with CD-ROMs
%patch1131 -p1
# Plug leaks in error paths in aic driver
%patch1132 -p1
# Add refcounting to scsi command allocation
%patch1133 -p1
# return full SCSI status byte in SG_IO
%patch1134 -p1
# sg: Fix oops of sg_cmd_done and sg_release race
%patch1135 -p1
# aacraid: remove aac_handle_aif
%patch1136 -p1
# Prevent kernel panic if an application issues an ioctl with an unrecognized subopcode.
%patch1137 -p1
# Fix refcounting order in sd/sr, fixing cable pulls on USB storage.
%patch1138 -p1
# IOCTL integer overflow and information leak.
%patch1139 -p1


# Block / MD layer fixes.
# Fix blocklayer races
%patch1140 -p1
# fix bad segment coalescing in blk_recalc_rq_segments()
%patch1141 -p1
# cciss: Off-by-one error causing oops in CCISS_GETLUNIFO ioctl
%patch1142 -p1
# Fix sx8 device naming in sysfs
%patch1143 -p1
# blkdev_get_blocks(): handle eof
%patch1144 -p1
# Fix CCISS ioctl return code
%patch1145 -p1
# CCISS ID updates
%patch1146 -p1
# __getblk_slow can loop forever when pages are partially mapped
%patch1147 -p1
# md: fix two little bugs in raid10
%patch1150 -p1
# md: make sure md always uses rdev_dec_pending properly
%patch1151 -p1
# dm multipath: Add target message ioctl
%patch1152 -p1
# dm multipath: ioctl ref by device no
%patch1153 -p1
# dm: fix mirror log ref count
%patch1154 -p1
# dm multipath: Split suspend hook
%patch1155 -p1
# dm raid1: deadlock fix
%patch1156 -p1
# device-mapper: tidy error kprintfs
%patch1157 -p1
# linux-2.6.9-dm-add-dm_dev-name.patch
%patch1158 -p1
# dm multipath: bio details record/restore
%patch1159 -p1
# dm multipath: export mapinfo
%patch1160 -p1
# dm multipath.
%patch1161 -p1
# Fix 64 bit issues in device mapper.
%patch1162 -p1
# dm multipath: fix infinite suspend requeueing
%patch1163 -p1
# Avoid a bdget in device mapper.
%patch1164 -p1
# raid5/raid6 bi_max_vec fixes.
%patch1165 -p1
# fix multipath assembly bug
%patch1166 -p1
# Fix bogus level check in resync code
%patch1167 -p1
# Fix various thinkos in md.
%patch1168 -p1
# Device Mapper mirroring
%patch1169 -p1
# device mapper refcount fix
%patch1170 -p1
# device mapper raid1 race fix
%patch1171 -p1
# make clear that md does not support i/o barriers
%patch1172 -p1
# make sure md linear doesn't wrap 
%patch1173 -p1

#
# Various upstream NFS/NFSD fixes.
#
%patch1200 -p1
%patch1201 -p1
%patch1202 -p1
%patch1203 -p1
%patch1204 -p1
%patch1205 -p1
%patch1206 -p1
%patch1207 -p1
%patch1208 -p1
%patch1209 -p1
%patch1210 -p1
%patch1211 -p1
%patch1212 -p1
%patch1213 -p1
%patch1214 -p1
%patch1215 -p1
%patch1216 -p1
%patch1217 -p1
%patch1218 -p1
%patch1219 -p1
%patch1220 -p1
%patch1221 -p1
%patch1222 -p1
%patch1223 -p1
%patch1224 -p1
%patch1225 -p1
%patch1226 -p1
%patch1227 -p1
%patch1228 -p1
%patch1229 -p1
%patch1230 -p1
%patch1231 -p1
%patch1232 -p1
%patch1233 -p1
%patch1234 -p1
%patch1235 -p1
%patch1236 -p1
%patch1237 -p1
%patch1238 -p1
%patch1239 -p1
%patch1240 -p1
%patch1241 -p1
%patch1242 -p1

# Networking fixes.
# Fix IPV6 MTU calculation
%patch1300 -p1
# vlan_dev: return 0 on vlan_dev_change_mtu success
%patch1301 -p1
# Handle SIOCGIFHWADDR NULL dev->dev_addr
%patch1302 -p1
# fix missing security_*() check in net/compat.c
%patch1303 -p1
# XFRM layer bug fixes
%patch1304 -p1
# Fix CMSG validation checks wrt. signedness.
%patch1305 -p1
# Fix memory leak in ip_conntrack_ftp
%patch1306 -p1
# [IPV4]: Do not leak IP options.
%patch1307 -p1
# /proc/net/route stale pointer OOPS fix
%patch1308 -p1
# bonding: avoid kernel panic when 802.3ad link brought down.
%patch1309 -p1
# sk_forward_alloc() BUG assertion fix
%patch1310 -p1
# TCP BIC bug fix
%patch1311 -p1
# Fix fragment corruption
%patch1312 -p1
# sctp: add receive buffer accounting to protocol
%patch1313 -p1
# Fix IPSEC SA sequence collision
%patch1314 -p1
# Fix sctp sendbuffer accounting
%patch1315 -p1
# snmp6: avoid crash on dev shutdown
%patch1316 -p1
# bonding: Send IGMP traffic out only "active" link of bond+in ALB or TLB mode
%patch1317 -p1
# Fix IPSEC output spinlock deadlock.
%patch1318 -p1
# Remove ip_conntrack proc files on module removal.
%patch1319 -p1
# bonding with arp_ip_target failover sometime does not work
%patch1320 -p1
# Fix call to ipv6_skip_exthdr with an incorrect length argument.
%patch1321 -p1
# enable sctp to honour IP_FREEBIND option/ip_nonlocal_bind sysctl
%patch1322 -p1
# update bonding docs
%patch1323 -p1
# esure qeth driver gets proper eui64 values
%patch1324 -p1
#make sure ipv6 doesn't leak routes
%patch1325 -p1
# fix netlink hangs
%patch1326 -p1
# make sctp honor SO_BINDTODEVICE
%patch1327 -p1
# make net.ipv[4,6].route.flush file write only
%patch1328 -p1
# prevent list corruption in ip_vs_conn_flush
%patch1329 -p1
# fix tcp assertions
%patch1330 -p1
# network updates from 2.6.12
%patch1331 -p1
# bonding fixes
%patch1332 -p1
# make sctp properly call shutdown
%patch1333 -p1
#fix sctp receive buffer accounting
%patch1334 -p1
# various sctp fixes
%patch1335 -p1

# NIC driver fixes.
# Fix problems with b44 & 4g/4g
%patch1350 -p1
# Use correct spinlock functions in token ring net code
%patch1351 -p1
# make tulip_stop_rxtx() wait for DMA to fully stop
%patch1352 -p1
# reload EEPROM values at rmmod for needy cards
%patch1353 -p1
# [TG3]: Fix fiber hw autoneg bounces
%patch1354 -p1
# e100: fix improper enabling of interrupts
%patch1355 -p1
# rx checksum support for gige nForce ethernet
%patch1356 -p1
# via-rhine: references __init code during resume
%patch1357 -p1
# Workaround for the E1000 erratum 23
%patch1358 -p1
# Workaround E1000 post-maturely writing back to TX descriptors
%patch1359 -p1
# e100/e1000: return -EINVAL when setting rx-mini or rx-jumbo
%patch1360 -p1
# E1000 64k-alignment fix
%patch1361 -p1
# s2io update
%patch1362 -p1
# E1000 update from 2.6.10
%patch1364 -p1
# e100 update to 3.3.6-k2
%patch1365 -p1
# avoid panic in e100_tx_timeout on ppc64
%patch1366 -p1
# sk98lin: add MODULE_DEVICE_TABLE entry
%patch1367 -p1
# tg3: update + support BCM5752
%patch1368 -p1
# E100: fix state machine handling w/ NAPI
%patch1369 -p1
# ICH7 IDs for E100
%patch1370 -p1
# e1000: avoid sleep in timer context
%patch1371 -p1
# e1000: flush workqueues on remove
%patch1372 -p1
# Some nVidia network controllers show up as bridges.
%patch1373 -p1
# update ixgb to upstream 2.6.11
%patch1374 -p1
# E1000 update to upstream 2.6.11
%patch1375 -p1
# b44: fix bounce buffer allocation
%patch1376 -p1
# 3c59x: backport from 2.6.12-rc2 (enhanced ethtool support)
%patch1377 -p1
# tg3: update to 3.27 (support xw4300)
%patch1378 -p1
# e100: update to version 3.4.8
%patch1379 -p1
# fix driver name in dl2k as returned by ETHTOOL_GDRVINFO
%patch1380 -p1
# make sure b44 driver displays proper state on open
%patch1381 -p1
# update typhoon drvier
%patch1382 -p1
# update pcnet32
%patch1383 -p1
# update forcedeth
%patch1384 -p1
# tg3 update
%patch1385 -p1
# add bnx2
%patch1386 -p1
# update mii
%patch1387 -p1
# add sky2 driver
%patch1388 -p1
# add skge net driver
%patch1389 -p1

# ACPI bits
# Eliminate spurious ACPI breakpoint msgs
%patch1400 -p1
# Make LEqual less strict about operand types matching.
%patch1401 -p1
# Fix ACPI debug level
%patch1402 -p1
# Implement ACPI reset mechanism.
%patch1403 -p1
# Fix panic in acpi_pci_root_add()
%patch1404 -p1
# Support ACPI 2.0 systems with no XSDT
%patch1405 -p1

#kprobes
%patch1450 -p1
%patch1451 -p1
%patch1452 -p1
%patch1453 -p1
#relayfs
%patch1454 -p1
#ia64 kprobes support
%patch1455 -p1
%patch1456 -p1
%patch1457 -p1
#kprobes scalability
%patch1458 -p1

# storage driver updates
%patch1470 -p1
%patch1471 -p1
%patch1472 -p1
%patch1473 -p1
%patch1474 -p1
%patch1475 -p1
%patch1476 -p1
%patch1477 -p1

#
# Various crash dumping patches
#
%patch1500 -p1
%patch1501 -p1
%patch1510 -p1
%patch1520 -p1
%patch1521 -p1

%patch1530 -p1
%patch1540 -p1
%patch1541 -p1
%patch1542 -p1
%patch1543 -p1
%patch1544 -p1
%patch1545 -p1
%patch1546 -p1
%patch1547 -p1
%patch1548 -p1
%patch1549 -p1
%patch1550 -p1
%patch1551 -p1
%patch1552 -p1
%patch1554 -p1
%patch1555 -p1
%patch1556 -p1
%patch1557 -p1
%patch1558 -p1
%patch1559 -p1
%patch1560 -p1
%patch1561 -p1
%patch1562 -p1
%patch1563 -p1
%patch1564 -p1
%patch1565 -p1
%patch1566 -p1
%patch1567 -p1
%patch1568 -p1
%patch1569 -p1
%patch1570 -p1

#
# Various SELinux fixes from 2.6.10rc
#
%patch1600 -p1
%patch1601 -p1
%patch1602 -p1
%patch1603 -p1
%patch1604 -p1
%patch1605 -p1
# SELinux xattr for tmpfs (from 2.6.9-mm)
%patch1606 -p1
%patch1608 -p1
%patch1609 -p1
%patch1610 -p1
%patch1611 -p1
%patch1612 -p1
%patch1613 -p1
%patch1614 -p1
%patch1615 -p1
%patch1616 -p1
%patch1617 -p1
%patch1618 -p1
%patch1619 -p1

# Misc fixes
# Fix ps showing wrong ppid. (#132030)
%patch1700 -p1
# Make proc_pid_status not dereference dead task structs.
%patch1701 -p1
# Add ability to clear setting in /proc/self/attr
%patch1702 -p1
# Make EDD runtime configurable.
%patch1710 -p1
# Backport sysfs changes from 2.6.10 (#140372)
%patch1720 -p1
# Optimize away the unconditional write to debug registers on signal delivery path
%patch1730 -p1
# Add barriers to generic timer code to prevent race
%patch1740 -p1
# Fix problems with non-power-of-two sector size discs
%patch1750 -p1
# Add missing MODULE_VERSION tags to some modules.
%patch1760 -p1
# disable sw irqbalance/irqaffinity for e7520-e7320-e7525
%patch1780 -p1
# ASPM workaround for PCIe
%patch1781 -p1
# Hot-plug driver updates due to MSI change
%patch1782 -p1
# Workaround for 80332 IOP hot-plug problem
%patch1783 -p1
# ExpressCard hot-plug support for ICH6M
%patch1784 -p1
# Various PCI-X hotplug fixes
%patch1785 -p1
# hugetlb_get_unmapped_area fix
%patch1790 -p1
# Various statm accounting fixes
%patch1800 -p1
# Suppress ide-floppy 'medium not present' noise
%patch1810 -p1
# Fix possible hang in do_wait()
%patch1820 -p1
# flush error in pci_mmcfg_write
%patch1830 -p1
# Fix boot crash on VIA systems
%patch1840 -p1
# autofs4 - allow map update recognition
%patch1850 -p1
# Add additional tainting mechanisms.
%patch1860 -p1
%patch1861 -p1
%patch1862 -p1
# xtime correctness.
%patch1870 -p1
# pagevec alignment
%patch1880 -p1
# ia64/x86_64/s390 overlapping vma fix
%patch1890 -p1
# Remove Futex Warning
%patch1900 -p1
# Futex mmap_sem deadlock
%patch1901 -p1
# Make spinlock debugging panic instead of continue.
%patch1910 -p1
# Fix compat fcntl F_GETLK{,64}
%patch1920 -p1
# fix uninitialized variable in waitid(2)
%patch1930 -p1
# Missing Cache flushes in AGPGART code.
%patch1950 -p1
# Workaround broken pci posting in AGPGART.
%patch1951 -p1
# Bounds checking for vc resize
%patch1960 -p1
# fix & clean up zombie/dead task handling & preemption
%patch1970 -p1
# Don't cache /proc/pid dentry for dead process
%patch1971 -p1
# Random poolsize sysctl handler integer overflow.
%patch1990 -p1
#make sure i8042 properly release resources
%patch1991 -p1
#allow rom flashes on intel motherboads 
%patch1992 -p1
# NR_KEYS
%patch1993 -p1
# Active pci support
%patch1994 -p1
# fix master abort in pci_scan_device
%patch1995 -p1
# fix pci bar size
%patch1996 -p1
# schedule updates
%patch1997 -p1

#
# VM related fixes.
#
# Make the OOM killer less aggressive.
%patch2000 -p1
# vm_dirty_ratio initialisation fix.
%patch2001 -p1
# VM pageout throttling.
%patch2002 -p1
# Lower dirty limit for mappings which can't be cached in highmem
%patch2003 -p1
# Don't oomkill when congested
%patch2004 -p1
# Increment total_scanned var to throttle kswapd
%patch2005 -p1
# RLIMIT_MEMLOCK bypass and unpriveledged user DoS.
%patch2007 -p1
# tweak for the oomkiller.
%patch2009 -p1
# Print some extra debugging info on oom_kill.
%patch2010 -p1
# fix invalidate page race
%patch2011 -p1
# Fix the mincore syscall's error handling
%patch2012 -p1
# Fix DMA zone exhaustion problem
%patch2013 -p1
# Improve try_to_free_pages scanning
%patch2014 -p1
# swap token NULL mm check
%patch2015 -p1
# Prevent incrementing pte off end of kmap'd virtual page
%patch2016 -p1
# bounce page accounting
%patch2018 -p1
# ensure topdown allocator doesn't map page at 0
%patch2019 -p1
# mm tracker
%patch2020 -p1
# fix prune_icache vs iput race
%patch2021 -p1
# ability to disable oom kills via /proc/sys/oom-kill
%patch2022 -p1
# cache coherency fixes for ia64
%patch2023 -p1
# patch for buffer.c oops
%patch2024 -p1
# prio-tree fixes
%patch2025 -p1
# readahead fixes
%patch2026 -p1
# fix vm committed sign error
%patch2027 -p1
# allow vmalloc to allocate larger regions
%patch2028 -p1
# get watermarks correct on numa; allow fine grained dirty ratio setting
%patch2029 -p1
# properly update hugetlb number of pages
%patch2030 -p1
# optimize pte copying in fork()
%patch2031 -p1
# fix do_swap_page vs. shrink_list race
%patch2032 -p1
# make bootmem_low work 
%patch2033 -p1
# fix busy inodes after unmount
%patch2034 -p1

# IDE bits.
# Make CSB6 driver support configurations.
%patch2100 -p1
# Handle early EOF on CD's.
%patch2101 -p1
# Prevent panic with CD error
%patch2102 -p1
# Suppress Error Message on IDE probe
%patch2103 -p1
# Update IDE blacklist.
%patch2104 -p1
# convert __init to __devinit in serverworks for hotplug
%patch2105 -p1
# Do not load IDE driver on ServerWorks CSB6 chipsets
%patch2106 -p1
# IDE updates pci ids
%patch2107 -p1

# USB bits
# IO edgeport overflows.
%patch2200 -p1
# Allow usb-storage to be reloaded
%patch2201 -p1
# Add NOGET quirk for Chicony keyboards.
%patch2202 -p1
# fix usb acm modem interactions with line discipline
%patch2203 -p1
# fix usb memory sticks
%patch2204 -p1
# fix usb keys
%patch2205 -p1
# usb handoff
%patch2206 -p1
# khubd deadlock fixes
%patch2207 -p1
# fix endless loops in HID on disconnect
%patch2208 -p1
# properly implement usb compat ioctls
%patch2209 -p1
# Workaround for EHCI on some nVidia silicon
%patch2210 -p1
# get correct cd size
%patch2211 -p1
# usb error handling
%patch2212 -p1
# pizzaro reboot fix
%patch2213 -p1

# SCSI bits.
# Drop the 'deprecated SG_IO warning'.
%patch2300 -p1
# fix incorrect hw segment counting in qla2x00 drivers
%patch2301 -p1
# aacraid: remove unused module parameter "commit"
%patch2302 -p1
# Update megaraid.
%patch2303 -p1
# Megaraid diskdump warnings.
%patch2304 -p1
# Update mpt fusion driver, include SAS support.
%patch2305 -p1
# Increase i2o_block timeout, fixing installs with Adaptec 2400A
%patch2306 -p1
# SCSI Fix oops with faulty DVD
%patch2307 -p1
# Blacklist devices that falsely claim an echo buffer
%patch2308 -p1
# call __scsi_done in SDEV_DEL state
%patch2309 -p1
# add iscsi-sfnet driver - iscsi support
%patch2310 -p1
# qla1280: remove __inidata from driver_setup for hotplug
%patch2311 -p1
# update ipr driver to 2.0.11.1
%patch2312 -p1
# ide-scsi transform
%patch2313 -p1
# fix mt tell
%patch2314 -p1
# sg_io handling
%patch2315 -p1
# fix sg oops
%patch2316 -p1
# properly handle highmem in ide-scsi
%patch2317 -p1
# megaraid update
%patch2318 -p1
# fix cdrom sizing
%patch2319 -p1
# add megaraid_sas driver
%patch2320 -p1
# aacraid update
%patch2321 -p1
# add serial attached scsi, aic94xx
%patch2322 -p1
# fix scsi delete timer race
%patch2323 -p1
# fix scsi_eh_tur retry logic
%patch2324 -p1
# fix /proc/scsi/scsi overflows
%patch2325 -p1
# update qla2xxx to version 8.01.04-d7
%patch2326 -p1
# support 16-byte cdbs
%patch2327 -p1
# add adp94xx driver
%patch2328 -p1
# 3ware updates
%patch2329 -p1

# Audit layer
%patch2400 -p1
%patch2401 -p1
%patch2402 -p1
%patch2403 -p1
%patch2404 -p1
%patch2405 -p1
%patch2406 -p1
%patch2407 -p1
%patch2408 -p1
%patch2409 -p1
%patch2410 -p1
%patch2411 -p1
%patch2412 -p1
%patch2413 -p1
%patch2414 -p1
%patch2415 -p1
%patch2416 -p1
%patch2417 -p1
%patch2418 -p1
%patch2419 -p1
%patch2420 -p1
%patch2421 -p1
%patch2422 -p1
%patch2423 -p1
%patch2424 -p1
%patch2425 -p1
%patch2426 -p1
%patch2427 -p1
%patch2428 -p1
%patch2429 -p1
%patch2430 -p1
%patch2431 -p1
%patch2432 -p1
%patch2433 -p1
%patch2434 -p1
%patch2435 -p1
%patch2436 -p1
%patch2437 -p1
%patch2438 -p1
%patch2439 -p1
%patch2440 -p1
%patch2441 -p1
%patch2442 -p1
%patch2443 -p1
%patch2444 -p1
%patch2445 -p1
%patch2446 -p1
%patch2447 -p1
%patch2448 -p1
%patch2449 -p1
%patch2450 -p1
%patch2451 -p1
%patch2452 -p1
%patch2453 -p1
%patch2454 -p1
%patch2455 -p1
%patch2456 -p1
%patch2457 -p1
%patch2458 -p1

# Key management patches
%patch2500 -p1
%patch2501 -p1
%patch2502 -p1
%patch2503 -p1
%patch2504 -p1
%patch2505 -p1

# Core FS patches
# free_secdata on mount
%patch2550 -p1
# properly osync block devices
%patch2551 -p1
# add blkgetsize compat ioctl
%patch2552 -p1
# fix direct IO vs truncate for out of tree filesystems
%patch2553 -p1
# fix olarge file semantics for 32-bit apps on ia64
%patch2554 -p1
# fix error reporting on o_sync
%patch2555 -p1
# fix aio hang
%patch2556 -p1
# auditfs
%patch2557 -p1
# auditfs fixes
%patch2558 -p1
# audit_panic when out of memory
%patch2559 -p1
# avoid unnecessary audit records
%patch2560 -p1
# break up o_direct iovecs that are too large
%patch2561 -p1
# remove partition check in register_disk
%patch2562 -p1
# ioscheduler updates
%patch2563 -p1
# fix readpage vs. truncate race
%patch2565 -p1
# dont' create a new file on -ENFILE
%patch2566 -p1
# GFS dio locking
%patch2567 -p1
# make poll timeout correct large values on  64-bit platforms
%patch2568 -p1
# make readv/writev go through lsm
%patch2569 -p1

# Device Mapper fixes
%patch2600 -p1
%patch2601 -p1
%patch2602 -p1
%patch2603 -p1
%patch2604 -p1
%patch2605 -p1
%patch2606 -p1
%patch2607 -p1
%patch2608 -p1
%patch2609 -p1
%patch2610 -p1
%patch2611 -p1
%patch2612 -p1
%patch2613 -p1

# OpenIB Infiniband support
%patch2700 -p1
%patch2701 -p1
%patch2702 -p1
%patch2703 -p1
%patch2704 -p1
%patch2705 -p1
%patch2706 -p1
%patch2707 -p1
%patch2708 -p1
%patch2709 -p1
%patch2710 -p1
%patch2711 -p1
%patch2712 -p1
%patch2713 -p1
%patch2714 -p1
%patch2715 -p1
%patch2716 -p1
%patch2717 -p1
%patch2718 -p1
%patch2719 -p1
%patch2720 -p1
%patch2721 -p1
%patch2722 -p1
%patch2723 -p1
%patch2724 -p1
%patch2725 -p1
%patch2726 -p1
%patch2727 -p1
%patch2728 -p1
%patch2729 -p1
%patch2730 -p1
%patch2731 -p1
%patch2732 -p1
%patch2733 -p1
%patch2734 -p1
%patch2735 -p1
%patch2736 -p1
%patch2737 -p1
%patch2738 -p1
%patch2739 -p1
%patch2740 -p1
%patch2741 -p1
%patch2742 -p1
%patch2743 -p1
%patch2744 -p1
%patch2745 -p1
%patch2746 -p1
%patch2747 -p1
%patch2748 -p1
%patch2749 -p1

# Intial EDAC support
%patch2800 -p1

#
# Local hack (off for any shipped kernels) to printk all files opened 
# the first 180 seconds after boot for debugging userspace startup 
# speeds
#
# %patch2999 -p1

#
# External drivers that are about to get accepted upstream
#

# Emulex FC
%patch3000 -p1
%patch3001 -p1
%patch3002 -p1
%patch3003 -p1
%patch3004 -p1
%patch3005 -p1
%patch3006 -p1
%patch3007 -p1
%patch3008 -p1
%patch3009 -p1

# Speedtouch
%patch3010 -p1

# Intel wireless
%patch3020 -p1
%patch3021 -p1
%patch3022 -p1
%patch3023 -p1
%patch3024 -p1
%patch3025 -p1

# Misc bits
# Various fixes from 2.6.10-ac
%patch4001 -p1
# Fix pty race condition on SMP machine
%patch4002 -p1
# AC97 ID additions.
%patch4003 -p1
# Fix Alt-Sysrq-B panics x86/x86_64
%patch4004 -p1
# Fix oops when io_setup is called with unwritable addr
%patch4005 -p1
# Various ptrace fixes.
%patch4006 -p1
# set panic_on_oops=1 by default
%patch4007 -p1
# Fix shmget for ppc64, s390-64 & sparc64.
%patch4008 -p1
# gpt partition noprobe
%patch4009 -p1
# tmpfs caused truncate BUG()
%patch4010 -p1
# Silence some cpufreq warnings.
%patch4011 -p1
# Fix Vesafb probe error.
%patch4012 -p1
# Add support for a brace of Dell PCI serial cards
%patch4013 -p1
# Fix leak in autofs
%patch4014 -p1
# Fix tty locking.
%patch4015 -p1
# cope with faults in iret
%patch4016 -p1
# sysrq key enhancements
%patch4017 -p1
# Fix accounting in do_task_stat()
%patch4018 -p1
# adjust baud rate for serial ns16550a
%patch4019 -p1
# quirks patch
%patch4020 -p1
# fix oops with symbolic links on tmpfs
%patch4021 -p1
# esb2 support
%patch4022 -p1
# sigkill
%patch4023 -p1
# bio clone copy idx
%patch4024 -p1
# acpi fix for powernow
%patch4025 -p1
# update hangcheck timer
%patch4026 -p1
# aio fixes
%patch4027 -p1
# fix kallsyms race against insmod
%patch4028 -p1
# fix locks vs. close race
%patch4029 -p1
# fix autofs possibe infinite recursion on bind mounts
%patch4030 -p1
# isdn fixes
%patch4031 -p1
# fix release_region order in i810
%patch4032 -p1
# fix get/set_priority semantics
%patch4033 -p1
# fix disassociate ctty semantics
%patch4034 -p1
# remove bogus BUG_ON calls while dumping core
%patch4035 -p1
# fix mqueue refcounting
%patch4036 -p1
# Wacom driver update
%patch4037 -p1
# add firmware update driver
%patch4038 -p1
# updates to kernel documentation
%patch4039 -p1
# fix boot BUG call when blank_console_t is called before keventd is up
%patch4040 -p1
# default softreapeat to off for atkbd.c
%patch4041 -p1
# sound driver updates
%patch4042 -p1
# procfs removal races fix
%patch4043 -p1
# add Dell dcbas driver
%patch4044 -p1
# fix hanging serial console
%patch4045 -p1
# pci bist
%patch4046 -p1
# /proc/devices overflow protection
%patch4047 -p1
# tunable per cpu pages
%patch4048 -p1
# tunable wake balance
%patch4049 -p1
# updated /proc/meminfo
%patch4050 -p1
# add i2 drivers
%patch4051 -p1
# audit execve 
%patch4052 -p1
# rsa driver fixes
%patch4053 -p1
# recognize boot cpu apic id properly
%patch4054 -p1

# ALSA fixes
# New ID for vx222 driver.
%patch4100 -p1
# Intel HD audio driver.
%patch4101 -p1
# improve support for alc260 codec
%patch4102 -p1
# intel hd audio driver update, remove empty files
%patch4103 -p1 -E

# Security issues.
%patch5000 -p1
%patch5001 -p1
%patch5002 -p1
%patch5003 -p1
%patch5004 -p1
%patch5005 -p1
%patch5006 -p1
%patch5007 -p1
%patch5009 -p1
%patch5010 -p1
%patch5011 -p1
%patch5012 -p1
%patch5013 -p1
%patch5014 -p1
%patch5015 -p1
%patch5016 -p1
%patch5017 -p1
%patch5018 -p1
%patch5019 -p1
%patch5020 -p1
%patch5021 -p1
%patch5022 -p1
%patch5023 -p1
%patch5024 -p1
%patch5025 -p1
%patch5026 -p1
%patch5027 -p1
%patch5028 -p1
%patch5029 -p1
%patch5030 -p1
%patch5031 -p1
%patch5032 -p1
%patch5033 -p1
%patch5034 -p1
%patch5035 -p1
%patch5036 -p1
%patch5037 -p1
%patch5038 -p1
%patch5039 -p1
%patch5040 -p1
%patch5041 -p1
%patch5042 -p1
%patch5043 -p1
%patch5044 -p1
%patch5045 -p1
%patch5046 -p1
%patch5047 -p1
%patch5048 -p1
%patch5049 -p1
%patch5050 -p1
%patch5051 -p1
%patch5052 -p1
%patch5053 -p1
%patch5054 -p1
%patch5055 -p1
%patch5056 -p1
%patch5057 -p1
%patch5058 -p1
%patch5059 -p1
%patch5060 -p1
%patch5061 -p1
%patch5062 -p1
%patch5063 -p1
%patch5064 -p1
%patch5065 -p1
%patch5066 -p1
%patch5067 -p1
%patch5068 -p1
%patch5069 -p1
%patch5070 -p1
%patch5071 -p1

# Security fixes without CAN-CVE's yet.
%patch5100 -p1

#
# final stuff
#

#
# misc small stuff to make things compile or otherwise improve performance
#
%patch10000 -p1

# Remove a bunch of exports that went away in 2.6.10rc1
%patch10001 -p1

# Add kzalloc and kstrdup, removes duplicate kstrdup definitions in various
# code as well
%patch10002 -p1
# patch for pci ids
%patch10003 -p1

# make sure the kernel has the sublevel we know it has. This looks weird
# but for -pre and -rc versions we need it since we only want to use
# the higher version when the final kernel is released.
perl -p -i -e "s/^SUBLEVEL.*/SUBLEVEL = %{sublevel}/" Makefile
perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -prep/" Makefile

# conditionally applied test patch for debugging convenience
%if %([ -s %{PATCH20000} ] && echo 1 || echo 0)
%patch20000 -p1
%endif

# TOMOYO Linux
tar -zxf %{SOURCE15000}
sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -42.0.10.EL/" -- Makefile
patch -sp1 < ccs-patch-2.6.9-42.0.10.EL.txt

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
	make ARCH=`echo $i | cut -d"-" -f3 | cut -d"." -f1 | sed -e s/i.86/i386/ -e s/s390x/s390/ -e s/ppc64.series/ppc64/  ` nonint_oldconfig > /dev/null 
	cp .config configs/$i 
done

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
gpg --homedir . --export --keyring ./kernel.pub CentOS > extract.pub
make linux-%{kversion}/scripts/bin2c
linux-%{kversion}/scripts/bin2c ksign_def_public_key __initdata < extract.pub > linux-%{kversion}/crypto/signature/key.h

cd linux-%{kversion}



BuildKernel() {

    # Pick the right config file for the kernel we're building
    if [ -n "$1" ] ; then
	Config=kernel-%{kversion}-%{_target_cpu}-$1.config
	DevelDir=/usr/src/kernels/%{KVERREL}-$1-%{_target_cpu}
    else
	Config=kernel-%{kversion}-%{_target_cpu}.config
	DevelDir=/usr/src/kernels/%{KVERREL}-%{_target_cpu}
    fi

    KernelVer=%{version}-%{release}$1
    echo BUILDING A KERNEL FOR $1 %{_target_cpu}...

    # make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}$1/" Makefile

    # and now to start the build process

    make -s mrproper
    cp configs/$Config .config

    make -s nonint_oldconfig > /dev/null
    make -s include/linux/version.h 

    make -s %{?_smp_mflags} %{make_target}
    make -s %{?_smp_mflags} modules || exit 1
    make buildcheck
    
    # Start installing the results

    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/boot
    mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
    install -m 644 .config $RPM_BUILD_ROOT/boot/config-$KernelVer
    install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-$KernelVer
    cp arch/*/boot/bzImage $RPM_BUILD_ROOT/%{image_install_path}/vmlinuz-$KernelVer
    cp arch/*/boot/zImage.stub $RPM_BUILD_ROOT/%{image_install_path}/zImage.stub-$KernelVer || :

    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
    make -s INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=$KernelVer
%if %{kabi}
    mkdir -p $RPM_BUILD_ROOT/lib/modules/kabi-%{kabi_major}-%{kabi_minor}$1
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
    cp -a arch/%{_arch}/scripts $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch} || :
    cp -a arch/%{_arch}/*lds $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch}/ || :
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*.o
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*/*.o
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cd include
    cp -a acpi config linux math-emu media net pcmcia rxrpc scsi sound video asm asm-generic $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cp -a `readlink asm` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
%ifarch x86_64
    mkdir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/asm-i386
    cp -a asm-i386/ide.h asm-i386/node.h asm-i386/cpu.h $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/asm-i386
%endif
    # Make sure the Makefile and version.h have a matching timestamp so that
    # external modules can be built
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/version.h
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/autoconf.h
    cd .. 

    #
    # save the vmlinux file for kernel debugging into the kernel-debuginfo rpm
    #
    mkdir -p $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT/usr/lib/debug/lib/modules/$KernelVer

    # gpg sign the modules
%if %{signmodules}
    gcc -o scripts/modsign/mod-extract scripts/modsign/mod-extract.c -Wall
	KEYFLAGS="--no-default-keyring --homedir .." 
	KEYFLAGS="$KEYFLAGS --secret-keyring ../kernel.sec" 
	KEYFLAGS="$KEYFLAGS --keyring ../kernel.pub" 
	export KEYFLAGS 
    for i in ` find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f` ; do
	if [ x`echo \`basename $i \` | join - $RPM_SOURCE_DIR/modsign_exclude | wc -l` = x0 ]
	then
		sh ./scripts/modsign/modsign.sh $i CentOS 
		mv -f $i.signed $i
	fi
    done
	unset KEYFLAGS
%endif

    # mark modules executable so that strip-to-file can strip them
    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f  | xargs chmod u+x

    # detect missing or incorrect license tags
    for i in `find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" ` ; do echo -n "$i " ; /sbin/modinfo -l $i >> modinfo ; done
    cat modinfo | grep -v "^GPL" | grep -v "^Dual BSD/GPL" | grep -v "^Dual MPL/GPL" | grep -v "^GPL and additional rights" | grep -v "^GPL v2" && exit 1 
    rm -f modinfo
    # remove files that will be auto generated by depmod at rpm -i time
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.*

    # Move the devel headers out of the root file system
    mkdir -p $RPM_BUILD_ROOT/usr/src/kernels
    mv $RPM_BUILD_ROOT/lib/modules/$KernelVer/build $RPM_BUILD_ROOT/$DevelDir
    ln -sf $DevelDir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
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

%if %{buildhugemem}
BuildKernel hugemem
%endif

%if %{buildlargesmp}
BuildKernel largesmp
%endif

###
### install
###

%install

cd linux-%{kversion}

# architectures that don't get kernel-source (i586/i686/athlon) dont need
# much of an install because the build phase already copied the needed files

%if %{builddoc}
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}/Documentation

# sometimes non-world-readable files sneak into the kernel source tree
chmod -R a+r *
# copy the source over
tar cf - Documentation | tar xf - -C $RPM_BUILD_ROOT/usr/share/doc/kernel-doc-%{kversion}
%endif

%if %{buildsource}

mkdir -p $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
chmod -R a+r *

# clean up the source tree so that it is ready for users to build their own
# kernel
make -s mrproper
# copy the source over
tar cf - . | tar xf - -C $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}

# set the EXTRAVERSION to <version>custom, so that people who follow a kernel building howto
# don't accidentally overwrite their currently working moduleset and hose
# their system
perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}custom/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/Makefile

# some config options may be appropriate for an rpm kernel build but are less so for custom user builds,
# change those to values that are more appropriate as default for people who build their own kernel.
perl -p -i -e "s/^CONFIG_DEBUG_INFO.*/# CONFIG_DEBUG_INFO is not set/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/configs/*
perl -p -i -e "s/^.*CONFIG_DEBUG_PAGEALLOC.*/# CONFIG_DEBUG_PAGEALLOC is not set/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/configs/*
perl -p -i -e "s/^.*CONFIG_DEBUG_SLAB.*/# CONFIG_DEBUG_SLAB is not set/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/configs/*
perl -p -i -e "s/^.*CONFIG_DEBUG_SPINLOCK.*/# CONFIG_DEBUG_SPINLOCK is not set/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/configs/*
perl -p -i -e "s/^.*CONFIG_DEBUG_HIGHMEM.*/# CONFIG_DEBUG_HIGHMEM is not set/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/configs/*
perl -p -i -e "s/^.*CONFIG_MODULE_SIG.*/# CONFIG_MODULE_SIG is not set/" $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}/configs/*

install -m 644 %{SOURCE10}  $RPM_BUILD_ROOT/usr/src/linux-%{KVERREL}
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

%pre hugemem
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
exit 0

%pre largesmp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
exit 0

%post 
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --package kernel --mkinitrd --depmod --install %{KVERREL}

%post devel
if [ -x /usr/sbin/hardlink ] ; then
pushd /usr/src/kernels/%{KVERREL}-%{_target_cpu} > /dev/null ; {
	cd /usr/src/kernels/%{KVERREL}-%{_target_cpu}
	find . -type f | while read f; do hardlink -c /usr/src/kernels/*/$f $f ; done
}
popd > /dev/null
fi

%post smp
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --package kernel-smp --mkinitrd --depmod --install %{KVERREL}smp

%post smp-devel
if [ -x /usr/sbin/hardlink ] ; then
pushd /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu} > /dev/null ; {
	cd /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu}
	find . -type f | while read f; do hardlink -c /usr/src/kernels/*/$f $f ; done
}
popd > /dev/null
fi

%post hugemem
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --package kernel-hugemem --mkinitrd --depmod --install %{KVERREL}hugemem

%post hugemem-devel
if [ -x /usr/sbin/hardlink ] ; then
pushd /usr/src/kernels/%{KVERREL}-hugemem-%{_target_cpu} > /dev/null ; {
	cd /usr/src/kernels/%{KVERREL}-hugemem-%{_target_cpu}
	find . -type f | while read f; do hardlink -c /usr/src/kernels/*/$f $f ; done
}
popd > /dev/null
fi

%post largesmp
[ -x /usr/sbin/module_upgrade ] && /usr/sbin/module_upgrade
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --package kernel-largesmp --mkinitrd --depmod --install %{KVERREL}largesmp

%post largesmp-devel
if [ -x /usr/sbin/hardlink ] ; then
pushd /usr/src/kernels/%{KVERREL}-largesmp-%{_target_cpu} > /dev/null ; {
	cd /usr/src/kernels/%{KVERREL}-largesmp-%{_target_cpu}
	find . -type f | while read f; do hardlink -c /usr/src/kernels/*/$f $f ; done
}
popd > /dev/null
fi

%preun 
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}

%preun smp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}smp

%preun hugemem
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}hugemem

%preun largesmp
/sbin/modprobe loop 2> /dev/null > /dev/null  || :
[ -x /sbin/new-kernel-pkg ] && /sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}largesmp


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
%if %{kabi}
%dir /lib/modules/kabi-%{kabi_major}-%{kabi_minor}
%endif

%files devel
%defattr(-,root,root)
/lib/modules/%{KVERREL}/build
/lib/modules/%{KVERREL}/source
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
%if %{kabi}
%dir /lib/modules/kabi-%{kabi_major}-%{kabi_minor}smp
%endif

%files smp-devel
%defattr(-,root,root)
/lib/modules/%{KVERREL}smp/build
/lib/modules/%{KVERREL}smp/source
%verify(not mtime) /usr/src/kernels/%{KVERREL}-smp-%{_target_cpu}
%endif

%if %{buildhugemem}
%files hugemem
%defattr(-,root,root)
/%{image_install_path}/*-%{KVERREL}hugemem
/boot/System.map-%{KVERREL}hugemem
/boot/config-%{KVERREL}hugemem
%dir /lib/modules/%{KVERREL}hugemem
/lib/modules/%{KVERREL}hugemem/kernel
%if %{kabi}
%dir /lib/modules/kabi-%{kabi_major}-%{kabi_minor}hugemem
%endif

%files hugemem-devel
%defattr(-,root,root)
/lib/modules/%{KVERREL}hugemem/build
/lib/modules/%{KVERREL}hugemem/source
%verify(not mtime) /usr/src/kernels/%{KVERREL}-hugemem-%{_target_cpu}
%endif

%if %{buildlargesmp}
%files largesmp
%defattr(-,root,root)
/%{image_install_path}/*-%{KVERREL}largesmp
/boot/System.map-%{KVERREL}largesmp
/boot/config-%{KVERREL}largesmp
%dir /lib/modules/%{KVERREL}largesmp
/lib/modules/%{KVERREL}largesmp/kernel
%if %{kabi}
%dir /lib/modules/kabi-%{kabi_major}-%{kabi_minor}largesmp
%endif

%files largesmp-devel
%defattr(-,root,root)
/lib/modules/%{KVERREL}largesmp/build
/lib/modules/%{KVERREL}largesmp/source
%verify(not mtime) /usr/src/kernels/%{KVERREL}-largesmp-%{_target_cpu}
%endif

# only some architecture builds need kernel-source and kernel-doc

%if %{buildsource}
%files sourcecode
%defattr(-,root,root)
/usr/src/linux-%{KVERREL}/
%endif


%if %{builddoc}
%files doc
%defattr(-,root,root)
/usr/share/doc/kernel-doc-%{kversion}/Documentation/*
%endif

%changelog
* Tue Feb 27 2007 Johnny Hughes <johnny@centos.org> [2.6.9-42.0.10]
- rolled in standard centos changes (build for i586, change genkey to
  genkey.centos, do not terminate build on extra files).

* Thu Jul 03 2003 Arjan van de Ven <arjanv@redhat.com>
- 2.6 start 
