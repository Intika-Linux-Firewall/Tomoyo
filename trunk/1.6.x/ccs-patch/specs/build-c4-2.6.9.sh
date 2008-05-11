#! /bin/sh
#
# This is a kernel build script for CentOS 4.6's 2.6.9 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.9-67.0.15.EL.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/centos/4.6/updates/SRPMS/kernel-2.6.9-67.0.15.EL.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.9-67.0.15.EL.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.6.1-20080510.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.1-20080510.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-2.6.9-67.0.15.EL.diff ]
then
    wget -O ccs-patch-2.6.9-67.0.15.EL.diff 'http://svn.sourceforge.jp/cgi-bin/viewcvs.cgi/*checkout*/trunk/1.6.x/ccs-patch/patches/ccs-patch-2.6.9-67.0.15.EL.diff?root=tomoyo' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec	2008-05-08 23:11:38.000000000 +0900
+++ kernel-2.6.spec	2008-05-11 13:16:28.000000000 +0900
@@ -30,7 +30,7 @@
 # that the kernel isn't the stock distribution kernel, for example by
 # adding some text to the end of the version number.
 #
-%define release 67.0.15.EL
+%define release 67.0.15.EL_tomoyo_1.6.1
 %define sublevel 9
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
@@ -136,6 +136,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -172,7 +175,7 @@
 %define __find_provides /usr/lib/rpm/redhat/find-kmod-provides.sh
 %define __find_requires %{nil}
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -3785,6 +3788,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.1-20080510.tar.gz
+sed -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -67.0.15.EL/" -- Makefile
+patch -sp1 < %_sourcedir/ccs-patch-2.6.9-67.0.15.EL.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -3796,6 +3804,9 @@
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
mv kernel-2.6.spec kernel-2.6.9-67.0.15.EL_tomoyo_1.6.1.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.9-67.0.15.EL_tomoyo_1.6.1.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.9-67.0.15.EL_tomoyo_1.6.1.spec"
echo "to build kernel rpm packages."
exit 0
