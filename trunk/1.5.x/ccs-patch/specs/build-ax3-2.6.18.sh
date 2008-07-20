#! /bin/sh
#
# This is a kernel build script for Asianux 3's 2.6.18 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.18-8.16AX.src.rpm ]
then
    wget http://ftp.miraclelinux.com/pub/Asianux/Server/3.0/updates/src/kernel-2.6.18-8.16AX.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.18-8.16AX.src.rpm || die "Can't install source package."

cd /usr/src/asianux/SOURCES/ || die "Can't chdir to /usr/src/asianux/SOURCES/ ."
if [ ! -r ccs-patch-1.5.4-20080510.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/27219/ccs-patch-1.5.4-20080510.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/asianux/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2008-03-17 09:18:26.000000000 +0900
+++ kernel-2.6.spec	2008-04-16 12:40:24.000000000 +0900
@@ -33,7 +33,7 @@
 %define sublevel 18
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
-%define release 8.16%{?dist}
+%define release 8.16%{?dist}_tomoyo_1.5.4
 %define signmodules 0
 %define xen_hv_cset 11772
 %define make_target bzImage
@@ -191,6 +191,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -216,7 +219,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 4.2.21-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -2766,6 +2769,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.5.4-20080510.tar.gz
+sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -8.16AX/" -- Makefile
+patch -sp1 < patches/ccs-patch-2.6.18-8.16AX.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -2791,6 +2799,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config 
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch nonint_oldconfig > /dev/null
   echo "# $Arch" > configs/$i
EOF
mv kernel-2.6.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
exit 0
