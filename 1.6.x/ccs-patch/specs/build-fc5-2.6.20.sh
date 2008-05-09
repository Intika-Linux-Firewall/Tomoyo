#! /bin/sh
#
# This is a kernel build script for Fedora Core 5's 2.6.20 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.20-1.2320.fc5.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/fedora/core/updates/5/SRPMS/kernel-2.6.20-1.2320.fc5.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.20-1.2320.fc5.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.6.1-20080510.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.1-20080510.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2007-06-13 05:34:55.000000000 +0900
+++ kernel-2.6.spec	2008-04-16 12:09:56.000000000 +0900
@@ -33,7 +33,7 @@
 %define sublevel 20
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
-%define release %(R="$Revision: 1.2320 $"; RR="${R##: }"; echo ${RR%%?})%{?dist}
+%define release %(R="$Revision: 1.2320 $"; RR="${R##: }"; echo ${RR%%?})%{?dist}.fc5_tomoyo_1.6.1
 %define signmodules 0
 %define xen_hv_cset 11774
 %define make_target bzImage
@@ -196,6 +196,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -221,7 +224,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 4.2.21-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -1208,6 +1211,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf $RPM_SOURCE_DIR/ccs-patch-1.6.1-20080510.tar.gz
+sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -1.2320.fc5/" -- Makefile
+patch -sp1 < patches/ccs-patch-2.6.20-1.2320.fc5.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -1226,6 +1234,9 @@
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
mv kernel-2.6.spec kernel-2.6.20-1.2320.fc5_tomoyo_1.6.1.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.20-1.2320.fc5_tomoyo_1.6.1.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.20-1.2320.fc5_tomoyo_1.6.1.spec"
echo "to build kernel rpm packages."
exit 0
