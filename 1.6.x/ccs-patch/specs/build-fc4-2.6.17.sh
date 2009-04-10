#! /bin/sh
#
# This is a kernel build script for Fedora Core 4's 2.6.17 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.17-1.2142_FC4.src.rpm ]
then
    wget http://ftp.riken.go.jp/Linux/fedoralegacy/fedora/4/updates/SRPMS/kernel-2.6.17-1.2142_FC4.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.17-1.2142_FC4.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.6.7-20090410.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.7-20090410.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2006-07-12 11:30:41.000000000 +0900
+++ kernel-2.6.spec	2008-04-16 12:23:17.000000000 +0900
@@ -18,7 +18,7 @@
 %define sublevel 17
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
-%define release %(R="$Revision: 1.2142 $"; RR="${R##: }"; echo ${RR%%?})_FC4
+%define release %(R="$Revision: 1.2142 $"; RR="${R##: }"; echo ${RR%%?})_FC4_tomoyo_1.6.7p1
 %define signmodules 0
 %define make_target bzImage
 %define kernel_image x86
@@ -119,6 +119,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -145,7 +148,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 5.83, mkinitrd >= 4.2.15-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -729,6 +732,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.7-20090410.tar.gz
+# sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -1.2142_FC4/" -- Makefile
+patch -sp1 < patches/ccs-patch-2.6.17-fedora-core-4.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -740,6 +748,9 @@
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
