#! /bin/sh
#
# This is a kernel build script for openSUSE 10.2's 2.6.18 kernel.
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

if [ ! -r kernel-source-2.6.18.8-0.10.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/suse/suse/update/10.2/rpm/src/kernel-source-2.6.18.8-0.10.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-source-2.6.18.8-0.10.src.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.6.2-20080625.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.2-20080625.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SOURCES/kernel-default.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-default.spec	2008-06-09 08:29:42.000000000 +0900
+++ kernel-default.spec	2008-06-20 09:23:49.000000000 +0900
@@ -23,13 +23,13 @@
 %define build_um  %([ default != um ] ; echo $?)
 %define build_vanilla  %([ default != vanilla ] ; echo $?)
 
-Name:           kernel-default
+Name:           ccs-kernel-default
 %ifarch ia64
 # arch/ia64/scripts/unwcheck.py
 BuildRequires:  python
 %endif
 Version:        2.6.18.8
-Release: 0.10
+Release: 0.10_tomoyo_1.6.2
 Summary:        The Standard Kernel for both Uniprocessor and Multiprocessor Systems
 License:        GPL v2 or later
 Group:          System/Kernel
@@ -235,6 +235,10 @@
 %build
 source .rpm-defs
 cd linux-2.6.18
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.2-20080625.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.18.8-0.10_SUSE.diff
+cat config.ccs >> .config
 cp .config .config.orig
 %if %{tolerate_unknown_new_config_options}
 MAKE_ARGS="$MAKE_ARGS -k"
EOF
mv kernel-default.spec kernel-2.6.18.8-0.10-default_tomoyo_1.6.2.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.18.8-0.10-default_tomoyo_1.6.2.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.18.8-0.10-default_tomoyo_1.6.2.spec"
echo "to build kernel rpm packages."
exit 0
