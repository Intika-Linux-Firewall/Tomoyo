#! /bin/sh
#
# This is a kernel build script for VineLinux 6.1's 3.0 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-3.0.71-1vl6.src.rpm ]
then
    wget http://updates.vinelinux.org/Vine-6.1/updates/SRPMS/kernel-3.0.71-1vl6.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-3.0.71-1vl6.src.rpm || die "Can't verify signature."
rpm -ivh kernel-3.0.71-1vl6.src.rpm || die "Can't install source package."

cd /root/rpm/SOURCES/ || die "Can't chdir to /root/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.8.3-20130512.tar.gz ]
then
    wget -O ccs-patch-1.8.3-20130512.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.3-20130512.tar.gz' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /root/rpm/SPECS/kernel-vl.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-vl.spec
+++ kernel-vl.spec
@@ -28,7 +28,7 @@
 %define patchlevel 71
 %define kversion 3.%{sublevel}
 %define rpmversion 3.%{sublevel}.%{patchlevel}
-%define release 1%{?_dist_release}
+%define release 1%{?_dist_release}_tomoyo_1.8.3p7
 
 %define make_target bzImage
 %define hdrarch %_target_cpu
@@ -120,6 +120,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -152,7 +155,7 @@
 #
 %define kernel_prereq  fileutils, module-init-tools >= 3.6, initscripts >= 8.80, mkinitrd >= 6.0.93, linux-firmware >= 20110601-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -705,6 +708,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.8.3-20130512.tar.gz
+patch -sp1 < patches/ccs-patch-3.0-vine-linux-6.diff
+
 cp %{SOURCE10} Documentation/
 
 # put Vine logo
@@ -723,6 +730,9 @@
 for i in *.config
 do 
 	mv $i .config 
+	# TOMOYO Linux
+	cat config.ccs >> .config
+	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
 	Arch=`head -1 .config | cut -b 3-`
 	make ARCH=$Arch oldnoconfig
 	echo "# $Arch" > configs/$i
EOF
mv kernel-vl.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
ARCH=`uname -m`
echo "I'll start 'rpmbuild -bb --target $ARCH /tmp/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target $ARCH /tmp/ccs-kernel.spec
exit 0
