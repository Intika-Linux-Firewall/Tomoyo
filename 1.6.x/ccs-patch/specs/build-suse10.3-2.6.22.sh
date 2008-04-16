#! /bin/sh
#
# This is a kernel build script for openSUSE 10.3's 2.6.22 kernel.
#

die () {
    echo $1
    exit 1
}

cd /usr/lib/rpm/ || die "Can't chdir to /usr/lib/rpm/ ."

if ! grep -q ccs-kernel find-supplements.ksyms
then
	patch << "EOF" || die "Can't patch find-supplements.ksyms ."
--- find-supplements.ksyms	2008-04-16 14:18:13.000000000 +0900
+++ find-supplements.ksyms	2008-04-16 14:19:06.000000000 +0900
@@ -6,6 +6,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel*)
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
+ccs-kernel*)
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
+ccs-kernel-*)
 kernel*)	    is_kernel_package=1 ;;
 esac
 
EOF
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-source-2.6.22.17-0.1.src.rpm ]
then
    wget http://download.opensuse.org/update/10.3/rpm/src/kernel-source-2.6.22.17-0.1.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-source-2.6.22.17-0.1.src.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.6.0-20080401.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.0-20080401.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SOURCES/kernel-default.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-default.spec	2008-02-11 11:04:16.000000000 +0900
+++ kernel-default_tomoyo_1.6.0.spec	2008-04-01 11:31:06.000000000 +0900
@@ -10,7 +10,7 @@
 
 # norootforbuild
 
-Name:           kernel-default
+Name:           ccs-kernel-default
 Url:            http://www.kernel.org/
 %if 0%{?opensuse_bs}
 # Strip off the build number ("y") from the "x.y" release number
@@ -39,7 +39,7 @@
 %endif
 Summary:        The Standard Kernel for both Uniprocessor and Multiprocessor Systems
 Version:        2.6.22.17
-Release: 0.1
+Release: 0.1_tomoyo_1.6.0
 License:        GPL v2 or later
 Group:          System/Kernel
 AutoReqProv:    on
@@ -187,7 +187,7 @@
 %define tolerate_unknown_new_config_options 0
 # kABI change tolerance (default in maintenance should be 4, 6, 8 or 15,
 # 31 is the maximum; see scripts/kabi-checks)
-%define tolerate_kabi_changes 6
+%define tolerate_kabi_changes 31
 
 %description
 The standard kernel for both uniprocessor and multiprocessor systems.
@@ -277,6 +277,11 @@
 %build
 source .rpm-defs
 cd linux-2.6.22
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.0-20080401.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.22.17-0.1_SUSE.diff
+sed -i -e 's:-ccs::' -- Makefile
+cat config.ccs >> .config
 cp .config .config.orig
 %if %{tolerate_unknown_new_config_options}
 MAKE_ARGS="$MAKE_ARGS -k"
EOF
mv kernel-default.spec kernel-2.6.22.17-0.1-default_tomoyo_1.6.0.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.22.17-0.1-default_tomoyo_1.6.0.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.22.17-0.1-default_tomoyo_1.6.0.spec"
echo "to build kernel rpm packages."
exit 0
