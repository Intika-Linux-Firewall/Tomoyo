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

if [ ! -r kernel-source-2.6.27.19-3.2.1.src.rpm ]
then
    wget http://download.opensuse.org/source/distribution/11.1/repo/oss/suse/src/kernel-source-2.6.27.19-3.2.1.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-source-2.6.27.19-3.2.1.src.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.6.6-20090314.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.6-20090314.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SOURCES/kernel-default.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-default.spec	2009-02-26 00:17:33.000000000 +0900
+++ kernel-default.spec	2009-02-27 14:20:07.000000000 +0900
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
 Version:        2.6.27.19
-Release:        3.<RELEASE1>
+Release:        3.2.1_tomoyo_1.6.6
 License:        GPL v2 only
 Group:          System/Kernel
 Url:            http://www.kernel.org/
@@ -221,7 +221,7 @@
 %define tolerate_unknown_new_config_options 0
 # kABI change tolerance (default in maintenance should be 4, 6, 8 or 15,
 # 31 is the maximum; see scripts/kabi-checks)
-%define tolerate_kabi_changes 6
+%define tolerate_kabi_changes 31
 
 %description
 The standard kernel for both uniprocessor and multiprocessor systems.
@@ -306,6 +306,10 @@
 %build
 source .rpm-defs
 cd linux-2.6.27
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.6-20090314.tar.gz
+patch -sp1 < %_sourcedir/ccs-patch-2.6.27-suse-11.1.diff
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
