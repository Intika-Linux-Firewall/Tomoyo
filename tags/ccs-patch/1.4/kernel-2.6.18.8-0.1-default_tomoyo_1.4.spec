#
# spec file for package kernel-default (Version 2.6.18.8)
#
# Copyright (c) 2007 SUSE LINUX Products GmbH, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# norootforbuild

Name:           kernel-default
URL:            http://www.kernel.org/
%if 0%{?opensuse_bs}
# Strip off the build number ("y") from the "x.y" release number
%define source_rel %(release=%release; echo ${release%.*})
%else
# We don't have build numbers internally
%define source_rel %release
%endif
%define build_kdump %([ default != kdump ] ; echo $?)
%define build_xen %(case default in (xen*) echo 1;; (*) echo 0;; esac)
%define build_um  %([ default != um ] ; echo $?)
%define build_vanilla  %([ default != vanilla ] ; echo $?)
%ifarch ia64
# arch/ia64/scripts/unwcheck.py
BuildRequires:  python
%endif
Version:        2.6.18.8
Release: 0.1_tomoyo_1.4
Summary:        The Standard Kernel for both Uniprocessor and Multiprocessor Systems
License:        GNU General Public License (GPL)
Group:          System/Kernel
%if %build_um
#Conflicts:    kernel
%else
%if !%build_xen
Provides:       kernel = 2.6.18.8-%source_rel
%endif
%endif
Provides:       kernel-default-nongpl
Obsoletes:      kernel-default-nongpl
%ifarch alpha
%else
%ifarch %ix86
Provides:       k_athlon k_debug k_deflt k_deflt_22 k_deflt_24 k_eide k_laptop k_orig k_pentiu k_pos_ibm k_psmp k_smp k_smp_22 k_smp_24 smp kernel-smp
Obsoletes:      k_athlon k_debug k_deflt k_deflt_22 k_deflt_24 k_eide k_laptop k_orig k_pentiu k_pos_ibm k_psmp k_smp k_smp_22 k_smp_24 smp kernel-smp
%else
%ifarch ia64
Provides:       k_debug k_deflt k_itanium2 k_itanium2-smp k_smp kernel-sn2
Obsoletes:      k_debug k_deflt k_itanium2 k_itanium2-smp k_smp kernel-sn2
%else
%ifarch ppc
Provides:       k_chrp k_chrps k_deflt k_pmac k_pmacs k_prep k_preps
Obsoletes:      k_chrp k_chrps k_deflt k_pmac k_pmacs k_prep k_preps
%else
%ifarch ppc64
%else
%ifarch s390x
Provides:       kernel-64bit k_deflt
Obsoletes:      kernel-64bit k_deflt
%else
%ifarch x86_64
Provides:       k_deflt k_numa k_smp smp kernel-smp
Obsoletes:      k_deflt k_numa k_smp smp kernel-smp
%endif
%endif
%endif
%endif
%endif
%endif
%endif
%ifarch %ix86 x86_64
Requires:       irqbalance
%endif
%if %build_xen
Requires:       xen >= xen-3.0.2_09697
%endif
Conflicts:      apparmor-profiles <= 2.0-34
Conflicts:      apparmor-parser <= 2.0-21.1
Autoreqprov:    on
%define my_builddir %_builddir/%{name}-%{version}
Source0:        http://www.kernel.org/pub/linux/kernel/v2.6/linux-2.6.18.tar.bz2
Source1:        functions.sh
Source11:       postun.sh
Source12:       post.sh
Source20:       series.conf
Source21:       config.conf
Source22:       supported.conf
Source30:       arch-symbols
Source31:       guards
Source32:       config-subst
Source33:       check-for-config-changes
Source34:       check-supported-list
Source35:       install-configs
Source38:       kabi-checks
Source40:       build-source-timestamp
Source41:       built-in-where
Source42:       make-symsets
Source43:       find-provides
Source45:       module-renames
Source46:       find-types
Source100:      config.tar.bz2
Source101:      patches.arch.tar.bz2
Source102:      patches.drivers.tar.bz2
Source103:      patches.fixes.tar.bz2
Source104:      patches.rpmify.tar.bz2
Source105:      patches.suse.tar.bz2
Source106:      patches.uml.tar.bz2
Source107:      patches.xen.tar.bz2
Source108:      patches.addon.tar.bz2
Source109:      patches.kernel.org.tar.bz2
Source120:      kabi.tar.bz2
PreReq:         mkinitrd >= 1.2
PreReq:         coreutils
PreReq:         perl-Bootloader >= 0.4.1
PreReq:         rpm
PreReq:         /sbin/update-bootloader
#!BuildIgnore: irqbalance xen
#!BuildIgnore: perl-Bootloader mkinitrd
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
ExclusiveArch: alpha %ix86 ia64 ppc ppc64 s390x x86_64
# These files are found in the kernel-source package:
NoSource:       0
NoSource:       100
NoSource:       101
NoSource:       102
NoSource:       103
NoSource:       104
NoSource:       105
NoSource:       106
NoSource:       107
NoSource:       108
NoSource:       109
NoSource:       120
# Provide the exported symbols as "ksym(symbol) = hash"
%define __find_provides %_sourcedir/find-provides %name
# Will modules not listed in supported.conf abort the kernel build (0/1)?
%define supported_modules_check 0
%define tolerate_unknown_new_config_options 0
# kABI change tolerance (default in maintenance should be 4, 6, 8 or 15,
# 31 is the maximum; see scripts/kabi-checks)
%define tolerate_kabi_changes 31

%(chmod +x %_sourcedir/{arch-symbols,guards,config-subst,check-for-config-changes,check-supported-list,built-in-where,find-provides,make-symsets,find-types,kabi-checks,install-configs})

%description
The standard kernel for both uniprocessor and multiprocessor systems.



Source Timestamp: 2007/03/02 13:51:59 UTC
CVS Branch: SL102_BRANCH

%prep
if ! [ -e %_sourcedir/linux-2.6.18.tar.bz2 ]; then
    echo "The kernel-default-2.6.18.8.nosrc.rpm package does not contain the" \
	 "complete sources. Please install kernel-source-2.6.18.8.src.rpm."
    exit 1
fi
symbols=$(
    echo kernel-default
    cd %_sourcedir
    PATCH_ARCH=%_target_cpu ./arch-symbols
    ! [ -e extra-symbols ] || cat extra-symbols
)
echo "Architecture symbol(s):" $symbols
# Unpack all sources and patches
%setup -q -c -T -a 0 -a 100 -a 101 -a 102 -a 103 -a 104 -a 105 -a 106 -a 107 -a 108 -a 109 -a 120
# Generate the list of supported modules
(   %_sourcedir/guards $symbols < %_sourcedir/supported.conf
    for how in external; do
	(   %_sourcedir/guards $symbols < %_sourcedir/supported.conf
	    %_sourcedir/guards $symbols < %_sourcedir/supported.conf
	    %_sourcedir/guards $symbols $how < %_sourcedir/supported.conf \
	) | sort | uniq -u | sed -e 's:$: '"$how"':'
    done
) | sed -e 's,.*/,,' | sort > linux-2.6.18/Module.supported
cd linux-2.6.18
# Find out for which architecture to build. We do this here, and use the
# result in the %build and %install sections.
#
# On architectures with a bi-arch or cross compiler, we can compile for
# an architecture different from %arch. The location of the config file
# tells us for which architecture to compile.
set -- $(
    for config in $(%_sourcedir/guards $symbols < %_sourcedir/config.conf) ; do
	[ ${config#*/} = default ] && echo $config
    done)
if [ $# -ne 1 ]; then
    echo "$# config files found for this spec file (but one needed)" >&2
    exit 1
fi
subarch=${1%/*}
# Apply the patches needed for this architecture.
%if !%build_vanilla
for patch in $(%_sourcedir/guards $symbols < %_sourcedir/series.conf); do
    if ! patch -s -E -p1 --no-backup-if-mismatch -i ../$patch; then
	echo "*** Patch $patch failed ***"
	exit 1
    fi
done
%else
for patch in $(%_sourcedir/guards $symbols < %_sourcedir/series.conf | egrep kernel.org\|rpmify); do
    if ! patch -s -E -p1 --no-backup-if-mismatch -i ../$patch; then
	echo "*** Patch $patch failed ***"
	exit 1
    fi
done
%endif

%_sourcedir/install-configs %_sourcedir %my_builddir %source_rel
config=arch/$subarch/defconfig.default

%_sourcedir/config-subst CONFIG_DEBUG_INFO < $config > .config
# We compile for this sub-architecture (i.e., machine architecture):
%if %build_um
cat > ../.rpm-defs <<EOF
ARCH=default
SUBARCH=$subarch
MAKE_ARGS="ARCH=default SUBARCH=$subarch"
EOF
%else
cat > ../.rpm-defs <<EOF
ARCH=$subarch
SUBARCH=$subarch
MAKE_ARGS="ARCH=$subarch"
EOF
%endif
%if 0%{?__debug_package:1}
cat >> ../.rpm-defs <<EOF
MAKE_ARGS="\$MAKE_ARGS CONFIG_DEBUG_INFO=y"
EOF
%endif

%build
source .rpm-defs
cd linux-2.6.18
# TOMOYO Linux
tar -zxf  %_sourcedir/ccs-patch-1.4-20070401.tar.gz
patch -sp1 < ccs-patch-2.6.18.8-0.1_SUSE.txt
cat config.ccs >> .config
cp .config .config.orig
%if %{tolerate_unknown_new_config_options}
MAKE_ARGS="$MAKE_ARGS -k"
yes '' | make oldconfig $MAKE_ARGS
%else
make silentoldconfig $MAKE_ARGS < /dev/null

%_sourcedir/check-for-config-changes .config.orig .config
rm .config.orig
%endif
make prepare $MAKE_ARGS
KERNELRELEASE=$(make -s kernelrelease)
echo "KERNELRELEASE=$KERNELRELEASE" >> ../.rpm-defs
cat > .kernel-binary.spec.buildenv <<EOF
# Override the timestamp 'uname -v' reports with the build
# timestamp.
export BUILD_TIMESTAMP="$(head -n 1 %_sourcedir/build-source-timestamp)"
# The following branch/timestamp will end up in Oopses.
export OOPS_TIMESTAMP="$(
    echo -n $(sed -ne 's/^CVS Branch: \(.*\)/\1-/p' \
		  %_sourcedir/build-source-timestamp)
    head -n 1 %_sourcedir/build-source-timestamp \
	| tr -dc 0-9)"
export KBUILD_VERBOSE=0
export KBUILD_SYMTYPES=1
EOF
source .kernel-binary.spec.buildenv
make %{?jobs:-j%jobs} all $MAKE_ARGS

%install
source .rpm-defs
# get rid of /usr/lib/rpm/brp-strip-debug
# strip removes too much from the vmlinux ELF binary
export NO_BRP_STRIP_DEBUG=true
# /lib/modules/$KERNELRELEASE/build will be a stale symlink until the
# kernel-source package is installed. Don't check for stale symlinks
# in the brp-symlink check:
export NO_BRP_STALE_LINK_ERROR=yes
# skip long-running sanity checks
export NO_BRP_NOEXECSTACK=yes
cd linux-2.6.18
rm -rf %buildroot
mkdir -p %buildroot/boot
# (Could strip out non-public symbols.)
cp -p System.map %buildroot/boot/System.map-$KERNELRELEASE
add_vmlinux()
{
    local vmlinux=boot/vmlinux-$KERNELRELEASE
%if 0%{?__debug_package:1}
    local vmlinux_debug=usr/lib/debug/$vmlinux.debug
    mkdir -p $(dirname %buildroot/$vmlinux_debug)
    cp vmlinux %buildroot/$vmlinux
    /usr/lib/rpm/debugedit -b %my_builddir -d /usr/src/debug \
			   -l vmlinux.sourcefiles %buildroot/$vmlinux
    objcopy --only-keep-debug \
	    %buildroot/$vmlinux \
	    %buildroot/$vmlinux_debug || :
    objcopy --add-gnu-debuglink=%buildroot/$vmlinux_debug \
	    --strip-debug \
	    %buildroot/$vmlinux || :
    mkdir -p %buildroot/usr/src/debug
    LANG=C sort -z -u vmlinux.sourcefiles \
    | (	cd %my_builddir
	cpio -pd0m %buildroot/usr/src/debug
    )
    chmod -R a+rX,go-w %buildroot/usr/src/debug
%else
    cp vmlinux %buildroot/$vmlinux
%endif
    if [ "$1" = --compressed ]; then
	gzip -9 %buildroot/$vmlinux
    fi
}
%if %build_kdump
    add_vmlinux
    chmod 644 %buildroot/boot/vmlinux-$KERNELRELEASE
    image=vmlinux
%else
%if %build_um
    add_vmlinux
    chmod 755 %buildroot/boot/vmlinux-$KERNELRELEASE
    image=linux
%else
%if %build_xen
    add_vmlinux --compressed
    cp -p vmlinuz %buildroot/boot/vmlinuz-$KERNELRELEASE
    image=vmlinuz
%else
# architecture specifics
%ifarch %ix86 x86_64
    add_vmlinux --compressed
    cp -p arch/*/boot/bzImage %buildroot/boot/vmlinuz-$KERNELRELEASE
    image=vmlinuz
%endif
%ifarch alpha
    add_vmlinux --compressed
    cp -p arch/alpha/boot/vmlinux.gz %buildroot/boot/vmlinuz-$KERNELRELEASE
    image=vmlinuz
%endif
%ifarch ppc ppc64
    add_vmlinux
    chmod 644 %buildroot/boot/vmlinux-$KERNELRELEASE
    image=vmlinux
%endif
%ifarch ia64
    add_vmlinux --compressed
    mv %buildroot/boot/vmlinux-$KERNELRELEASE.gz \
       %buildroot/boot/vmlinuz-$KERNELRELEASE
    image=vmlinuz
%endif
%ifarch s390 s390x
    add_vmlinux --compressed
    cp -p arch/s390/boot/image %buildroot/boot/image-$KERNELRELEASE
    image=image
%endif
    if [ -e init/kerntypes.o ]; then
	cp init/kerntypes.o %buildroot/boot/Kerntypes-$KERNELRELEASE
    fi
# end of build_xen
%endif
# end of build_um
%endif
# end of build_kdump
%endif
(   cat %_sourcedir/functions.sh
    sed -e "s:@KERNELRELEASE@:$KERNELRELEASE:g" \
	-e "s:@IMAGE@:$image:g" \
	-e "s:@FLAVOR""@:default:g" \
        %_sourcedir/post.sh
) > ../post.sh
(   cat %_sourcedir/functions.sh
    sed -e "s:@KERNELRELEASE@:$KERNELRELEASE:g" \
	-e "s:@IMAGE@:$image:g" \
	-e "s:@FLAVOR""@:default:g" \
        %_sourcedir/postun.sh
) > ../postun.sh
%if %build_kdump || %build_um || %build_xen || %build_vanilla
suffix=-default
%endif
ln -s $image$suffix %buildroot/boot/$image$suffix
ln -s initrd$suffix %buildroot/boot/initrd$suffix
cp .config %buildroot/boot/config-$KERNELRELEASE
make modules_install $MAKE_ARGS INSTALL_MOD_PATH=%buildroot
if ! %_sourcedir/check-supported-list \
	%_sourcedir %buildroot/lib/modules/$KERNELRELEASE; then
%if %supported_modules_check
    exit 1
%endif
    echo "Consistency check error: please update supported.conf."
fi
gzip -c9 < Module.symvers > %buildroot/boot/symvers-$KERNELRELEASE.gz
# Group the exported symbols listed in symvers.gz by directory, and
# create a database of sets. Preserve exports from previous kernels
# (stored in old-symsets.tar.gz) when possible.
old_symsets=%my_builddir/kabi/$SUBARCH/symsets-default.tar.gz
[ -e $old_symsets ] || old_symsets=
(   grep -v $'\tvmlinux$' Module.symvers
    # Find out in which built-in.o files the exported symbols that ended
    # up in vmlinux were defined.
    grep $'\tvmlinux$' Module.symvers | %_sourcedir/built-in-where
) | %_sourcedir/make-symsets \
    %buildroot/boot/symsets-$KERNELRELEASE.tar.gz \
    $old_symsets
# Also put the resulting file in $obj_dir/$SUBARCH/default
# so that kernel-source + kernel-default is sufficient for building
# modules that have modversions as well.
obj_dir=usr/src/linux-${KERNELRELEASE%%-default}-obj
mkdir -p %buildroot/$obj_dir/$SUBARCH/default
cp Module.symvers %buildroot/$obj_dir/$SUBARCH/default
# Table of types used in exported symbols (for modversion debugging).

%_sourcedir/find-types > %buildroot/boot/symtypes-$KERNELRELEASE
if [ -s %buildroot/boot/symtypes-$KERNELRELEASE ]; then
    gzip -9 %buildroot/boot/symtypes-$KERNELRELEASE
else
    rm -f %buildroot/boot/symtypes-$KERNELRELEASE
fi
# Some architecture's $(uname -m) output is different from the ARCH
# parameter that needs to be passed to kbuild. Create symlinks from
# $(uname -m) to the ARCH directory.
[ -e %buildroot/$obj_dir/%_target_cpu ] \
    || ln -sf $SUBARCH %buildroot/$obj_dir/%_target_cpu
%ifarch ppc ppc64
[ -e %buildroot/$obj_dir/ppc ] \
    || ln -s $SUBARCH %buildroot/$obj_dir/ppc
[ -e %buildroot/$obj_dir/ppc64 ] \
    || ln -s $SUBARCH %buildroot/$obj_dir/ppc64
%endif
# Check for kABI changes
KABI=0
if [ -e %my_builddir/kabi/$SUBARCH/symvers-default ]; then
    %_sourcedir/kabi-checks \
	%my_builddir/kabi/$SUBARCH/symvers-default \
	Module.symvers \
	%my_builddir/kabi/commonsyms \
	%my_builddir/kabi/usedsyms \
    || KABI=$?
fi
if [ $KABI -gt %tolerate_kabi_changes ]; then
    echo "kABI changes of badness $KABI exceed the maximum allowed badness" \
	 "of %tolerate_kabi_changes. Please try to avoid the kABI changes."
    if [ ! -e %my_builddir/kabi/$SUBARCH/ignore-default -a \
	 ! -e %_sourcedir/IGNORE-KABI-BADNESS ]; then
	echo "Create a file IGNORE-KABI-BADNESS in the kernel-source" \
	     "directory to build this kernel even though its badness is" \
	     "higher than allowed for an official kernel."
       exit 1
    fi
    # Indicate the ABI badness in build result emails.
    echo "KABI BADNESS $KABI" > %_rpmdir/%_arch/mbuild_subject.tag
fi
# We were building in %my_builddir/linux-2.6.18, but the sources will
# later be installed in /usr/src/linux-2.6.18-%source_rel. Fix up the
# build symlink.
rm -f %buildroot/lib/modules/$KERNELRELEASE/{source,build}
ln -s /usr/src/linux-${KERNELRELEASE%%-default} \
    %buildroot/lib/modules/$KERNELRELEASE/source
ln -s /$obj_dir/$SUBARCH/default \
    %buildroot/lib/modules/$KERNELRELEASE/build
# Abort if there are any undefined symbols
msg="$(/sbin/depmod -F %buildroot/boot/System.map-$KERNELRELEASE \
		    -b %buildroot -ae $KERNELRELEASE 2>&1)"
if [ $? -ne 0 ] || echo "$msg" | grep  'needs unknown symbol'; then
    exit 1
fi
# Create a dummy initrd with roughly the size the real one will have.
# That way, YaST will know that this package requires some additional
# space in /boot.
dd if=/dev/zero of=%buildroot/boot/initrd-$KERNELRELEASE \
    bs=1024 seek=2047 count=1
# Collect the file list.
(   cd %buildroot
    echo "%%defattr(-, root, root)"
    find boot \
	\( -type l -o -name 'initrd-*' \) -printf '%%%%ghost /%%p\n' -o \
	-type f -printf '/%%p\n'
    find lib/modules/$KERNELRELEASE \
	-type d -printf '%%%%dir /%%p\n' -o \
	-path '*/modules.*' -printf '%%%%ghost /%%p\n' -o \
	-printf '/%%p\n'
    find $obj_dir \
	-type d -printf '%%%%dir /%%p\n' -o \
	-printf '/%%p\n'
    echo '%%dir /etc/modprobe.d/'
    echo '%%config /etc/modprobe.d/module-renames'
    if [ -e .%_docdir/%name ]; then
	echo "%%doc %_docdir/%name"
    fi
) > %my_builddir/kernel.files
# Set up some module aliases
install -d -m 755 %buildroot/etc/modprobe.d/
install -m 644 %_sourcedir/module-renames %buildroot/etc/modprobe.d/

%post -f post.sh

%postun -f postun.sh

%files -f kernel.files

%changelog
* Fri Mar 02 2007 - lmb@suse.de
- patches.suse/revert-netfilter-source-routing: Revert parts of
  the netfilter patch from 2.6.18.5 due to kABI changes.
* Thu May 08 2003 - kraxel@suse.de
- initial release
