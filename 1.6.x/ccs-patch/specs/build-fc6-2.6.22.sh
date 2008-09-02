#! /bin/sh
#
# This is a kernel build script for Fedora Core 6's 2.6.22 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.22.14-72.fc6.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/fedora/core/updates/6/SRPMS/kernel-2.6.22.14-72.fc6.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.22.14-72.fc6.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.6.4-20080903.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.4-20080903.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2007-11-22 03:35:14.000000000 +0900
+++ kernel-2.6.spec	2008-04-16 12:00:45.000000000 +0900
@@ -12,7 +12,7 @@
 # that the kernel isn't the stock distribution kernel, for example,
 # by setting the define to ".local" or ".bz123456"
 #
-#% define buildid .local
+%define buildid _tomoyo_1.6.4
 
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
@@ -389,11 +394,11 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 5.1.19.0.3-1
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
-Release: %{pkg_release}
+Release: %{pkg_release}.fc6
 # DO NOT CHANGE THE 'ExclusiveArch' LINE TO TEMPORARILY EXCLUDE AN ARCHITECTURE BUILD.
 # SET %nobuildarches (ABOVE) INSTEAD
 ExclusiveArch: noarch %{all_x86} x86_64 ppc ppc64 ia64 sparc sparc64 s390x alpha alphaev56
@@ -1359,6 +1364,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.4-20080903.tar.gz
+# sed -i -e 's:EXTRAVERSION =.*:EXTRAVERSION = .14-72.fc6:' -- Makefile
+patch -sp1 < patches/ccs-patch-2.6.22-fedora-core-6.diff
+
 # Any further pre-build tree manipulations happen here.
 
 chmod +x scripts/checkpatch.pl
@@ -1379,6 +1389,9 @@
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
mv kernel-2.6.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
exit 0
