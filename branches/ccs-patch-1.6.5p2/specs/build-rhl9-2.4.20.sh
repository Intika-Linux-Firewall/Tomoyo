#! /bin/sh
#
# This is a kernel build script for RedHat Linux 9's 2.4.20 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.4.20-46.9.legacy.src.rpm ]
then
    wget http://ftp.riken.go.jp/Linux/fedoralegacy/redhat/9/updates/SRPMS/kernel-2.4.20-46.9.legacy.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.4.20-46.9.legacy.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.6.5-20081225.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.5-20081225.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.4.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.4.spec	2006-03-03 02:01:06.000000000 +0900
+++ kernel-2.4.spec	2008-04-16 09:31:57.000000000 +0900
@@ -21,7 +21,7 @@
 # that the kernel isn't the stock RHL kernel, for example by
 # adding some text to the end of the version number.
 #
-%define release 46.9.legacy
+%define release 46.9.legacy_tomoyo_1.6.5
 %define sublevel 20
 %define kversion 2.4.%{sublevel}
 # /usr/src/%{kslnk} -> /usr/src/linux-%{KVERREL}
@@ -119,7 +119,7 @@
 %define kernel_glob vmlinu?-%{KVERREL}
 %endif
 
-Name: kernel
+Name: ccs-kernel
 Version: %{kversion}
 Release: %{release}%{?targetboard:%{targetboard}}%{?debuglevel_1:.dbg}
 %define KVERREL %{PACKAGE_VERSION}-%{PACKAGE_RELEASE}
@@ -1418,6 +1418,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.5-20081225.tar.gz
+# sed -i -e "s/^SUBLEVEL.*/SUBLEVEL = 20/" -e "s/^EXTRAVERSION.*/EXTRAVERSION = -46.9.legacycustom/" -- Makefile
+patch -sp1 < patches/ccs-patch-2.4.20-redhat-linux-9.diff
+
 cp %{SOURCE10} Documentation/
 chmod +x arch/sparc*/kernel/check_asm.sh
 
@@ -1522,6 +1527,8 @@
 # since make mrproper wants to wipe out .config files, we move our mrproper
 # up before we copy the config files around.
     cp configs/kernel-%{kversion}-$Config.config .config
+    # TOMOYO Linux
+    cat config.ccs >> .config
     # make sure EXTRAVERSION says what we want it to say
     perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}$2/" Makefile
 %ifarch sparc sparc64     
EOF
mv kernel-2.4.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
exit 0
