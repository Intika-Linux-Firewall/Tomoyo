#! /bin/sh
#
# This is a kernel build script for Fedora 12's 2.6.32 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.32.9-67.fc12.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/fedora/updates/12/SRPMS/kernel-2.6.32.9-67.fc12.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.32.9-67.fc12.src.rpm || die "Can't install source package."

cd /root/rpmbuild/SOURCES/ || die "Can't chdir to /root/rpmbuild/SOURCES/ ."
if [ ! -r ccs-patch-1.7.1-20100214.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/43375/ccs-patch-1.7.1-20100214.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-1.7.1-20100306.diff ]
then
    wget -O ccs-patch-1.7.1-20100306.diff 'http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.7.x/ccs-patch/patches/ccs-patch-2.6.32-fedora-12.diff?revision=3498&root=tomoyo' || die "Can't download patch."
fi

cd /root/rpmbuild/SPECS/ || die "Can't chdir to /root/rpmbuild/SPECS/ ."
cp -p kernel.spec ccs-kernel.spec || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- ccs-kernel.spec	2010-02-27 17:59:39.000000000 +0900
+++ ccs-kernel.spec	2010-03-06 16:39:25.208418907 +0900
@@ -15,7 +15,7 @@
 # that the kernel isn't the stock distribution kernel, for example,
 # by setting the define to ".local" or ".bz123456"
 #
-# % define buildid .local
+%define buildid _tomoyo_1.7.1p2
 
 # fedora_build defines which build revision of this kernel version we're
 # building. Rather than incrementing forever, as with the prior versioning
@@ -410,6 +410,11 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define with_modsign 0
+%define _enable_debug_packages 0
+%define with_debuginfo 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -445,7 +450,7 @@
 # Packages that need to be installed before the kernel is, because the %post
 # scripts use them.
 #
-%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, kernel-firmware >= %{rpmversion}-%{pkg_release}, grubby >= 7.0.4-1
+%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, grubby >= 7.0.4-1
 %if %{with_dracut}
 %define initrd_prereq  dracut >= 002 xorg-x11-drv-ati-firmware
 %else
@@ -481,7 +486,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -876,7 +881,7 @@
 Provides: kernel-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -1422,6 +1427,10 @@
 
 # END OF PATCH APPLICATIONS ====================================================
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.1-20100214.tar.gz
+patch -sp1 < %_sourcedir/ccs-patch-1.7.1-20100306.diff
+
 %endif
 
 # Any further pre-build tree manipulations happen here.
@@ -1448,6 +1457,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch %{oldconfig_target} > /dev/null
   echo "# $Arch" > configs/$i
EOF
echo ""
echo ""
echo ""
echo "Edit /root/rpmbuild/SPECS/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /root/rpmbuild/SPECS/ccs-kernel.spec"
echo "to build kernel rpm packages."
exit 0
