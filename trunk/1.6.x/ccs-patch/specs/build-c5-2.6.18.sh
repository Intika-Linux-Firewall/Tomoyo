#! /bin/sh
#
# This is a kernel build script for CentOS 5.2's 2.6.18 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.18-92.1.22.el5.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/centos/5.2/updates/SRPMS/kernel-2.6.18-92.1.22.el5.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.18-92.1.22.el5.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.6.7-20090401.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.7-20090401.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2008-12-17 01:17:06.000000000 +0900
+++ kernel-2.6.spec	2008-12-17 14:58:33.000000000 +0900
@@ -66,7 +66,7 @@
 # that the kernel isn't the stock distribution kernel, for example,
 # by setting the define to ".local" or ".bz123456"
 #
-#% define buildid
+%define buildid _tomoyo_1.6.7
 #
 %define sublevel 18
 %define kversion 2.6.%{sublevel}
@@ -281,6 +281,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -306,7 +309,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 4.2.21-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -4854,6 +4857,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.7-20090401.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.18-centos-5.2.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -4913,6 +4920,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e "s/CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch nonint_oldconfig > /dev/null
   echo "# $Arch" > configs/$i
EOF
mv kernel-2.6.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb --without kabichk /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
exit 0
