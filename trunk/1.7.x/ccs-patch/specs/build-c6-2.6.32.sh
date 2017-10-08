#! /bin/sh
#
# This is a kernel build script for CentOS 6's 2.6.32 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.32-696.13.2.el6.src.rpm ]
then
    wget http://vault.centos.org/6.9/updates/Source/SPackages/kernel-2.6.32-696.13.2.el6.src.rpm || die "Can't download source package."
fi
LANG=C rpm --checksig kernel-2.6.32-696.13.2.el6.src.rpm | grep -F ': rsa sha1 (md5) pgp md5 OK' || die "Can't verify signature."
rpm -ivh kernel-2.6.32-696.13.2.el6.src.rpm || die "Can't install source package."

cd ~/rpmbuild/SOURCES/ || die "Can't chdir to ~/rpmbuild/SOURCES/ ."
if [ ! -r ccs-patch-1.7.3-20161111.tar.gz ]
then
    wget -O ccs-patch-1.7.3-20161111.tar.gz 'http://osdn.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.3-20161111.tar.gz' || die "Can't download patch."
fi

cd ~/rpmbuild/SPECS/ || die "Can't chdir to ~/rpmbuild/SPECS/ ."
cp -p kernel.spec ccs-kernel.spec || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- ccs-kernel.spec
+++ ccs-kernel.spec
@@ -15,7 +15,7 @@
 # that the kernel isn't the stock distribution kernel, for example,
 # by setting the define to ".local" or ".bz123456"
 #
-# % define buildid .local
+%define buildid _tomoyo_1.7.3p5
 
 %define distro_build 696.13.2
 %define signmodules 1
@@ -437,7 +437,7 @@
 # Packages that need to be installed before the kernel is, because the %post
 # scripts use them.
 #
-%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, kernel-firmware >= %{rpmversion}-%{pkg_release}, grubby >= 7.0.4-1
+%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, grubby >= 7.0.4-1
 %if %{with_dracut}
 %define initrd_prereq  dracut-kernel >= 004-408.el6
 %else
@@ -473,7 +473,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -771,7 +771,7 @@
 Provides: kernel-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -937,6 +937,10 @@
 
 ApplyOptionalPatch linux-kernel-test.patch
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.3-20161111.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.32-centos-6.diff
+
 # Any further pre-build tree manipulations happen here.
 
 chmod +x scripts/checkpatch.pl
@@ -961,6 +965,8 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch %{oldconfig_target} > /dev/null
   echo "# $Arch" > configs/$i
EOF
echo ""
echo ""
echo ""
echo "Edit ~/rpmbuild/SPECS/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb --without kabichk ~/rpmbuild/SPECS/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
echo "I'll start 'rpmbuild -bb --target i686 --without kabichk --with baseonly --without debug --without debuginfo ~/rpmbuild/SPECS/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target i686 --without kabichk --with baseonly --without debug --without debuginfo ~/rpmbuild/SPECS/ccs-kernel.spec
exit 0
