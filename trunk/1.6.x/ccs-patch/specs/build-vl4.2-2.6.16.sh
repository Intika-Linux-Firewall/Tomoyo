#! /bin/sh
#
# This is a kernel build script for VineLinux 4.2's 2.6.16 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.16-76.37vl4.src.rpm ]
then
    wget http://updates.vinelinux.org/Vine-4.2/updates/SRPMS/kernel-2.6.16-76.37vl4.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.16-76.37vl4.src.rpm || die "Can't install source package."

cd /usr/src/vine/SOURCES/ || die "Can't chdir to /usr/src/vine/SOURCES/ ."
if [ ! -r ccs-patch-1.6.2-20080625.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.2-20080625.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-2.6.16-76.37vl4.diff ]
then
    wget -O ccs-patch-2.6.16-76.37vl4.diff 'http://svn.sourceforge.jp/cgi-bin/viewcvs.cgi/*checkout*/trunk/1.6.x/ccs-patch/patches/ccs-patch-2.6.16-76.37vl4.diff?root=tomoyo' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/vine/SPECS/kernel-2.6-vl.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6-vl.spec	2008-06-11 17:38:52.000000000 +0900
+++ kernel-2.6-vl.spec	2008-06-26 13:16:35.000000000 +0900
@@ -23,7 +23,7 @@
 %define sublevel 16
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
-%define release 76.37%{_dist_release}
+%define release 76.37%{_dist_release}_tomoyo_1.6.2
 
 %define make_target bzImage
 
@@ -100,6 +100,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -126,7 +129,7 @@
 #
 %define kernel_prereq  fileutils, modutils >= 3.2.2 , initscripts >= 5.83, mkinitrd >= 4.2.1.8-0vl2.1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -1072,6 +1075,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.2-20080625.tar.gz
+sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -76.37vl4custom/" -- Makefile
+patch -sp1 < %_sourcedir/ccs-patch-2.6.16-76.37vl4.diff
+
 cp %{SOURCE10} Documentation/
 
 # put Vine logo
@@ -1092,6 +1100,9 @@
 for i in *.config
 do 
 	mv $i .config 
+	# TOMOYO Linux
+	cat config.ccs >> .config
+	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
 	Arch=`head -1 .config | cut -b 3-`
 	echo "# $Arch" > configs/$i
 	cat .config >> configs/$i 
EOF
mv kernel-2.6-vl.spec kernel-2.6.16-76.37vl4_tomoyo_1.6.2.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.16-76.37vl4_tomoyo_1.6.2.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.16-76.37vl4_tomoyo_1.6.2.spec"
echo "to build kernel rpm packages."
exit 0
