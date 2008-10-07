#! /bin/sh
#
# This is a kernel build script for Asianux 3's 2.6.18 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.18-53.11AXS3.src.rpm ]
then
    wget http://ftp.miraclelinux.com/pub/Asianux/Server/3.0/updates/src/kernel-2.6.18-53.11AXS3.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.18-53.11AXS3.src.rpm || die "Can't install source package."

cd /usr/src/asianux/SOURCES/ || die "Can't chdir to /usr/src/asianux/SOURCES/ ."
if [ ! -r ccs-patch-1.6.4-20080903.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.4-20080903.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/asianux/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2008-08-20 09:49:28.000000000 +0900
+++ kernel-2.6.spec	2008-10-07 18:45:20.000000000 +0900
@@ -64,7 +64,7 @@
 %define sublevel 18
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
-%define release 53.11%{?dist}
+%define release 53.11%{?dist}_tomoyo_1.6.4
 %define signmodules 0
 %define xen_hv_cset 15042
 %define xen_abi_ver 3.1
@@ -257,6 +257,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -282,7 +285,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 4.2.21-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -3748,6 +3751,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.4-20080903.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.18-asianux-3.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -3778,6 +3785,9 @@
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
