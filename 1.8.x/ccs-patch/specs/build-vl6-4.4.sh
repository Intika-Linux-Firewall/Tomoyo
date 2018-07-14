#! /bin/sh
#
# This is a kernel build script for VineLinux 6's 4.4 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-4.4.110-2vl6.src.rpm ]
then
    wget http://updates.vinelinux.org/Vine-6.5/updates/SRPMS/kernel-4.4.110-2vl6.src.rpm || die "Can't download source package."
fi
LANG=C rpm --checksig kernel-4.4.110-2vl6.src.rpm | grep -F ': (sha1) dsa sha1 md5 gpg OK' || die "Can't verify signature."
rpm -ivh kernel-4.4.110-2vl6.src.rpm || die "Can't install source package."

cd ~/rpm/SOURCES/ || die "Can't chdir to ~/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.8.5-20180714.tar.gz ]
then
    wget -O ccs-patch-1.8.5-20180714.tar.gz 'http://osdn.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.5-20180714.tar.gz' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p ~/rpm/SPECS/kernel44-vl.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel44-vl.spec
+++ kernel44-vl.spec
@@ -34,7 +34,7 @@
 %define patchlevel 110
 %define kversion 4.%{sublevel}
 %define rpmversion 4.%{sublevel}.%{patchlevel}
-%define release 2%{?_dist_release}
+%define release 2%{?_dist_release}_tomoyo_1.8.5p2
 
 %define make_target bzImage
 %define hdrarch %_target_cpu
@@ -126,6 +126,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -158,7 +161,7 @@
 #
 %define kernel_prereq  fileutils, %{kmod}, initscripts >= 8.80, mkinitrd >= 6.0.93, linux-firmware >= 20110601-1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -670,6 +673,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.8.5-20180714.tar.gz
+patch -sp1 < patches/ccs-patch-4.4-vine-linux-6.diff
+
 cp %{SOURCE10} Documentation/
 
 # put Vine logo
@@ -688,6 +695,9 @@
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
mv kernel44-vl.spec ccs-kernel.spec || die "Can't rename spec file."
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
