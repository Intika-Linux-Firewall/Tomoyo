#! /bin/sh
#
# This is a kernel build script for Asianux 2's 2.6.9 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.9-89.16.AXS2.src.rpm ]
then
    wget http://ftp.miraclelinux.com/pub/Miracle/ia32/standard/4.0/updates/SRPMS/kernel-2.6.9-89.16.AXS2.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.9-89.16.AXS2.src.rpm || die "Can't install source package."

cd /usr/src/asianux/SOURCES/ || die "Can't chdir to /usr/src/asianux/SOURCES/ ."
if [ ! -r ccs-patch-1.6.8-20100923.tar.gz ]
then
    wget -O ccs-patch-1.6.8-20100923.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/30297/ccs-patch-1.6.8-20100923.tar.gz' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/asianux/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec
+++ kernel-2.6.spec
@@ -26,7 +26,7 @@
 # that the kernel isn't the stock distribution kernel, for example by
 # adding some text to the end of the version number.
 #
-%define release 89.16%{?dist}
+%define release 89.16%{?dist}_tomoyo_1.6.8p3
 %define sublevel 9
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
@@ -139,6 +139,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -177,7 +180,7 @@
 %define __find_provides /usr/lib/rpm/asianux/find-kmod-provides.sh
 %define __find_requires %{nil}
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -6248,6 +6251,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.8-20100923.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.9-asianux-2.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -6293,6 +6300,9 @@
 for i in *.config 
 do 
 	mv $i .config 
+	# TOMOYO Linux
+	cat config.ccs >> .config
+	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
 	make ARCH=`echo $i | cut -d"-" -f3 | cut -d"." -f1 | sed -e s/i.86/i386/ -e s/s390x/s390/ -e s/ppc64.series/ppc64/  ` nonint_oldconfig > /dev/null 
 	cp .config configs/$i 
 done
EOF
mv kernel-2.6.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
exit 0
