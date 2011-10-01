#! /bin/sh
#
# This is a kernel build script for Fedora 13's 2.6.33 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.33.3-85.fc13.src.rpm ]
then
    wget ftp://ftp.isu.edu.tw/pub/Linux/Fedora/linux/releases/13/Fedora/source/SRPMS/kernel-2.6.33.3-85.fc13.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-2.6.33.3-85.fc13.src.rpm || die "Can't verify signature."
rpm -ivh kernel-2.6.33.3-85.fc13.src.rpm || die "Can't install source package."

cd /root/rpmbuild/SOURCES/ || die "Can't chdir to /root/rpmbuild/SOURCES/ ."
if [ ! -r ccs-patch-1.8.3-20110929.tar.gz ]
then
    wget -O ccs-patch-1.8.3-20110929.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.3-20110929.tar.gz' || die "Can't download patch."
fi

if [ ! -r ccs-patch-2.6.33-fedora-13-20110614.diff ]
then
    wget -O ccs-patch-2.6.33-fedora-13-20110614.diff 'http://sourceforge.jp/projects/tomoyo/svn/view/branches/ccs-patch-2.6.33-fedora-13.diff?revision=5185&root=tomoyo' || die "Can't download patch."
fi

cd /root/rpmbuild/SPECS/ || die "Can't chdir to /root/rpmbuild/SPECS/ ."
cp -p kernel.spec ccs-kernel.spec || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- ccs-kernel.spec
+++ ccs-kernel.spec
@@ -23,7 +23,7 @@
 #
 # (Uncomment the '#' and both spaces below to set the buildid.)
 #
-# % define buildid .local
+%define buildid _tomoyo_1.8.3
 ###################################################################
 
 # buildid can also be specified on the rpmbuild command line
@@ -431,6 +431,11 @@
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
@@ -507,7 +512,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -949,7 +954,7 @@
 Provides: kernel-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -1544,6 +1549,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.8.3-20110929.tar.gz
+patch -sp1 < %_sourcedir/ccs-patch-2.6.33-fedora-13-20110614.diff
+
 %endif
 
 # Any further pre-build tree manipulations happen here.
@@ -1570,6 +1579,9 @@
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
echo ""
ARCH=`uname -m`
echo "I'll start 'rpmbuild -bb --target $ARCH --with baseonly --without debug --without debuginfo /root/rpmbuild/SPECS/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
if /bin/false
then
patch << "EOF" || die "Can't patch spec file."
--- /root/rpmbuild/SPECS/ccs-kernel.spec
+++ /root/rpmbuild/SPECS/ccs-kernel.spec
@@ -221,7 +221,7 @@
 
 # kernel-PAE is only built on i686.
 %ifarch i686
-%define with_pae 1
+%define with_pae 0
 %else
 %define with_pae 0
 %endif
EOF
fi
exec rpmbuild -bb --target $ARCH --with baseonly --without debug --without debuginfo /root/rpmbuild/SPECS/ccs-kernel.spec
exit 0
