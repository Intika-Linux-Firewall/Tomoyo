#! /bin/sh
#
# This is a kernel build script for CentOS 3.9's 2.4.21 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.4.21-63.EL.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/centos/3.9/updates/SRPMS/kernel-2.4.21-63.EL.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-2.4.21-63.EL.src.rpm || die "Can't verify signature."
rpm -ivh kernel-2.4.21-63.EL.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20100412.tar.gz ]
then
    wget http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20100412.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.4.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.4.spec	2009-11-04 07:31:03.000000000 +0900
+++ kernel-2.4.spec	2009-11-04 16:48:08.000000000 +0900
@@ -20,7 +20,7 @@
 # that the kernel isn't the stock RHL kernel, for example by
 # adding some text to the end of the version number.
 #
-%define release 63.EL
+%define release 63.EL_tomoyo_1.7.2
 %define sublevel 21
 %define kversion 2.4.%{sublevel}
 # /usr/src/%{kslnk} -> /usr/src/linux-%{KVERREL}
@@ -133,7 +133,7 @@
 %define kernel_prereq  fileutils, modutils >=  2.4.18, initscripts >= 5.83, mkinitrd >= 3.2.6
 
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{kversion}
@@ -1921,6 +1921,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.2-20100412.tar.gz
+patch -sp1 < patches/ccs-patch-2.4.21-centos-3.9.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -1976,6 +1980,8 @@
 # since make mrproper wants to wipe out .config files, we move our mrproper
 # up before we copy the config files around.
     cp configs/kernel-%{kversion}-$Config.config .config
+    # TOMOYO Linux
+    cat config.ccs >> .config
     # make sure EXTRAVERSION says what we want it to say
     perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}$2/" Makefile
 
EOF
mv kernel-2.4.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
echo "I'll start 'rpmbuild -bb --target i686 /tmp/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target i686 /tmp/ccs-kernel.spec
exit 0
