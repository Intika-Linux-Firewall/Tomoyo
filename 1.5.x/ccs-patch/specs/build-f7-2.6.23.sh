#! /bin/sh
#
# This is a kernel build script for Fedora 7's 2.6.23 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.23.15-80.fc7.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/fedora/updates/7/SRPMS/kernel-2.6.23.15-80.fc7.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.23.15-80.fc7.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.5.4-20080510.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/27220/ccs-patch-1.5.4-20080510.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2008-02-11 06:12:23.000000000 +0900
+++ kernel-2.6.spec	2008-04-16 11:35:00.000000000 +0900
@@ -12,7 +12,7 @@
 # that the kernel isn't the stock distribution kernel, for example,
 # by setting the define to ".local" or ".bz123456"
 #
-#% define buildid .local
+%define buildid _tomoyo_1.5.4
 
 # fedora_build defines which build revision of this kernel version we're
 # building. Rather than incrementing forever, as with the prior versioning
@@ -364,6 +364,11 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define with_modsign 0
+%define _enable_debug_packages 0
+%define with_debuginfo 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -389,7 +394,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 6.0.9-7.1
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -1421,6 +1426,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.5.4-20080510.tar.gz
+sed -i -e 's:EXTRAVERSION =.*:EXTRAVERSION = .15-80.fc7:' -- Makefile
+patch -sp1 < patches/ccs-patch-2.6.23.15-80.fc7.diff
+
 # Any further pre-build tree manipulations happen here.
 
 chmod +x scripts/checkpatch.pl
@@ -1441,6 +1451,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch %{oldconfig_target} > /dev/null
   echo "# $Arch" > configs/$i
EOF
mv kernel-2.6.spec kernel-2.6.23.15-80.fc7_tomoyo_1.5.4.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.23.15-80.fc7_tomoyo_1.5.4.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.23.15-80.fc7_tomoyo_1.5.4.spec"
echo "to build kernel rpm packages."
exit 0
