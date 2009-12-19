#! /bin/sh
#
# This is a kernel build script for openSUSE 11.1's 2.6.27 kernel.
#

die () {
    echo $1
    exit 1
}

cd /usr/lib/rpm/ || die "Can't chdir to /usr/lib/rpm/ ."

if ! grep -q ccs-kernel find-supplements.ksyms
then
	patch << "EOF" || die "Can't patch find-supplements.ksyms ."
--- find-supplements.ksyms	2008-05-22 10:02:00.000000000 +0900
+++ find-supplements.ksyms	2008-06-11 11:04:06.000000000 +0900
@@ -7,6 +7,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel*)      is_kernel_package=1 ;;
 kernel*)	   is_kernel_package=1 ;;
 esac
 
EOF
fi

if ! grep -q ccs-kernel find-requires.ksyms
then
	patch << "EOF" || die "Can't patch find-requires.ksyms ."
--- find-requires.ksyms	2008-04-16 14:20:34.000000000 +0900
+++ find-requires.ksyms	2008-04-16 14:21:06.000000000 +0900
@@ -5,6 +5,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel*)       is_kernel_package=1 ;;
 kernel*)	    is_kernel_package=1 ;;
 esac
 
EOF
fi

if ! grep -q ccs-kernel find-provides.ksyms
then
	patch << "EOF" || die "Can't patch find-provides.ksyms ."
--- find-provides.ksyms	2008-04-16 14:22:34.000000000 +0900
+++ find-provides.ksyms	2008-04-16 14:23:04.000000000 +0900
@@ -5,6 +5,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel-*)      is_kernel_package=1 ;;
 kernel*)	    is_kernel_package=1 ;;
 esac
 
EOF
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-source-2.6.27.39-0.2.1.src.rpm ]
then
    wget http://download.opensuse.org/update/11.1/rpm/src/kernel-source-2.6.27.39-0.2.1.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-source-2.6.27.39-0.2.1.src.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.7.1-20091111.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/43375/ccs-patch-1.7.1-20091111.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-1.7.1-20091219.tar.gz ]
then
    mkdir -p ccs-patch.tmp || die "Can't create directory."
    cd ccs-patch.tmp/ || die "Can't change directory."
    wget -O hotfix.patch 'http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.7.x/ccs-patch/patches/hotfix.patch?revision=3273&root=tomoyo' || die "Can't download hotfix."
    tar -zxf ../ccs-patch-1.7.1-20091111.tar.gz || die "Can't extract tar ball."
    patch -p1 < hotfix.patch || die "Can't apply hotfix."
    rm -f hotfix.patch || die "Can't delete hotfix."
    tar -zcf ../ccs-patch-1.7.1-20091219.tar.gz -- * || die "Can't create tar ball."
    cd ../ || die "Can't change directory."
    rm -fR ccs-patch.tmp  || die "Can't delete directory."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SOURCES/kernel-default.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-default.spec	2009-11-24 01:26:41.000000000 +0900
+++ kernel-default.spec	2009-12-01 14:11:52.000000000 +0900
@@ -57,13 +57,13 @@
 %if %build_vanilla || %build_kdump || %CONFIG_MODULES != "y"
 %define split_packages 0
 %else
-%define split_packages 1
+%define split_packages 0
 %endif
 
-Name:           kernel-default
+Name:           ccs-kernel-default
 Summary:        The Standard Kernel
 Version:        2.6.27.39
-Release:        0.2.1
+Release:        0.2.1_tomoyo_1.7.1
 License:        GPL v2 only
 Group:          System/Kernel
 Url:            http://www.kernel.org/
@@ -225,7 +225,7 @@
 %define tolerate_unknown_new_config_options 0
 # kABI change tolerance (default in maintenance should be 4, 6, 8 or 15,
 # 31 is the maximum; see scripts/kabi-checks)
-%define tolerate_kabi_changes 6
+%define tolerate_kabi_changes 31
 
 %description
 The standard kernel for both uniprocessor and multiprocessor systems.
@@ -310,6 +310,10 @@
 %build
 source .rpm-defs
 cd linux-2.6.27
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.1-20091219.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.27-suse-11.1.diff
+cat config.ccs >> .config
 cp .config .config.orig
 %if %{tolerate_unknown_new_config_options}
 MAKE_ARGS="$MAKE_ARGS -k"
EOF
sed -e 's:^Provides:#Provides:' -e 's:^Obsoletes:#Obsoletes:' -e 's:-n kernel:-n ccs-kernel:' kernel-default.spec > ccs-kernel.spec || die "Can't edit spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
exit 0
