#! /bin/sh
#
# This is a kernel build script for openSUSE 11.0's 2.6.25 kernel.
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

if [ ! -r kernel-source-2.6.25.9-0.2.src.rpm ]
then
    wget http://download.opensuse.org/distribution/11.0/repo/src-oss/suse/src/kernel-source-2.6.25.9-0.2.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-source-2.6.25.9-0.2.src.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.6.2-20080625.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.2-20080625.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-2.6.25.9-0.2_SUSE.diff ]
then
    wget -O ccs-patch-2.6.25.9-0.2_SUSE.diff 'http://svn.sourceforge.jp/cgi-bin/viewcvs.cgi/*checkout*/trunk/1.6.x/ccs-patch/patches/ccs-patch-2.6.25.9-0.2_SUSE.diff?root=tomoyo' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SOURCES/kernel-default.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-default.spec	2008-06-30 19:13:25.000000000 +0900
+++ kernel-default.spec	2008-07-10 15:22:11.000000000 +0900
@@ -40,10 +40,10 @@
 %define build_nomodules 1
 %endif
 
-Name:           kernel-default
+Name:           ccs-kernel-default
 Summary:        The Standard Kernel for both Uniprocessor and Multiprocessor Systems
 Version:        2.6.25.9
-Release: 0.2
+Release: 0.2_tomoyo_1.6.2
 License:        GPL v2 or later
 Group:          System/Kernel
 Url:            http://www.kernel.org/
@@ -307,6 +307,11 @@
 %build
 source .rpm-defs
 cd linux-2.6.25
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.2-20080625.tar.gz
+patch -sp1 < %_sourcedir/ccs-patch-2.6.25.9-0.2_SUSE.diff
+sed -i -e 's:-ccs::' -- Makefile
+cat config.ccs >> .config
 cp .config .config.orig
 %if %{tolerate_unknown_new_config_options}
 MAKE_ARGS="$MAKE_ARGS -k"
EOF
mv kernel-default.spec kernel-2.6.25.9-0.2-default_tomoyo_1.6.2.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.25.9-0.2-default_tomoyo_1.6.2.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.25.9-0.2-default_tomoyo_1.6.2.spec"
echo "to build kernel rpm packages."
exit 0
