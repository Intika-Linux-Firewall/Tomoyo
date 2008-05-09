#! /bin/sh
#
# This is a kernel build script for Fedora Core 3's 2.6.12 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.12-2.3.legacy_FC3.src.rpm ]
then
    wget http://ftp.riken.go.jp/Linux/fedoralegacy/fedora/3/updates/SRPMS/kernel-2.6.12-2.3.legacy_FC3.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.12-2.3.legacy_FC3.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.5.4-20080510.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/27219/ccs-patch-1.5.4-20080510.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2006-02-18 23:05:50.000000000 +0900
+++ kernel-2.6.spec	2008-04-16 12:15:41.000000000 +0900
@@ -21,7 +21,7 @@
 %define rpmversion 2.6.%{sublevel}
 #define rhbsys  %([ -r /etc/beehive-root -o -n "%{?__beehive_build}" ] && echo || echo .`whoami`)
 #define release %(R="$Revision: 1.1381 $"; RR="${R##: }"; echo ${RR%%?})_FC3%{rhbsys}
-%define release 2.3.legacy_FC3
+%define release 2.3.legacy_FC3_tomoyo_1.5.4
 %define signmodules 0
 %define make_target bzImage
 
@@ -108,6 +108,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -134,7 +137,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools, initscripts >= 5.83, mkinitrd >= 4.1.18.1-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -778,6 +781,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.5.4-20080510.tar.gz
+sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -2.3.legacy_FC3/" -- Makefile
+patch -sp1 < patches/ccs-patch-2.6.12-2.3.legacy_FC3.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -789,6 +797,9 @@
 for i in *.config
 do 
 	mv $i .config 
+	# TOMOYO Linux
+	cat config.ccs >> .config
+	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
 	Arch=`head -1 .config | cut -b 3-`
 	make ARCH=$Arch nonint_oldconfig > /dev/null
 	echo "# $Arch" > configs/$i
EOF
mv kernel-2.6.spec kernel-2.6.12-2.3.legacy_FC3_tomoyo_1.5.4.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.12-2.3.legacy_FC3_tomoyo_1.5.4.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.12-2.3.legacy_FC3_tomoyo_1.5.4.spec"
echo "to build kernel rpm packages."
exit 0
