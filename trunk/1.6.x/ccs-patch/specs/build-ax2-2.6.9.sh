#! /bin/sh
#
# This is a kernel build script for Asianux 2's 2.6.9 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.9-42.21AX.src.rpm ]
then
    wget http://ftp.miraclelinux.com/pub/Miracle/ia32/standard/4.0/updates/SRPMS/kernel-2.6.9-42.21AX.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.9-42.21AX.src.rpm || die "Can't install source package."

cd /usr/src/asianux/SOURCES/ || die "Can't chdir to /usr/src/asianux/SOURCES/ ."
if [ ! -r ccs-patch-1.6.0-20080401.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.0-20080401.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-2.6.9-42.21AX.diff ]
then
    wget -O ccs-patch-2.6.9-42.21AX.diff 'http://svn.sourceforge.jp/cgi-bin/viewcvs.cgi/*checkout*/trunk/1.6.x/ccs-patch/patches/ccs-patch-2.6.9-42.21AX.diff?root=tomoyo' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/asianux/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2008-03-24 13:32:17.000000000 +0900
+++ kernel-2.6.spec	2008-04-16 12:48:54.000000000 +0900
@@ -29,7 +29,7 @@
 # adding some text to the end of the version number.
 #
 %define axbsys %([ "%{?WITH_LKST}" -eq 0 ] && echo || echo .lkst)
-%define release 42.21AX%{axbsys}
+%define release 42.21AX%{axbsys}_tomoyo_1.6.0
 %define sublevel 9
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
@@ -131,6 +131,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -167,7 +170,7 @@
 %define __find_provides /usr/lib/rpm/asianux/find-kmod-provides.sh
 %define __find_requires %{nil}
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -4060,6 +4063,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.0-20080401.tar.gz
+sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -42.21AX/" -- Makefile
+patch -sp1 < %_sourcedir/ccs-patch-2.6.9-42.21AX.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -4071,6 +4079,9 @@
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
mv kernel-2.6.spec kernel-2.6.9-42.21AX_tomoyo_1.6.0.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.9-42.21AX_tomoyo_1.6.0.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.9-42.21AX_tomoyo_1.6.0.spec"
echo "to build kernel rpm packages."
exit 0
