#! /bin/sh
#
# This is a kernel build script for Fedora 8's 2.6.25 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.25.4-10.fc8.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/fedora/updates/8/SRPMS/kernel-2.6.25.4-10.fc8.src.rpm || die "Can't download source package."
fi
rpm -ivh kernel-2.6.25.4-10.fc8.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.6.1-20080510.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.1-20080510.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-2.6.25.4-10.fc8.diff ]
then
    wget -O ccs-patch-2.6.25.4-10.fc8.diff 'http://svn.sourceforge.jp/cgi-bin/viewcvs.cgi/*checkout*/trunk/1.6.x/ccs-patch/patches/ccs-patch-2.6.25.4-10.fc8.diff?root=tomoyo' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel.spec	2008-05-23 11:21:37.000000000 +0900
+++ kernel.spec	2008-06-07 17:21:38.000000000 +0900
@@ -12,7 +12,7 @@
 # that the kernel isn't the stock distribution kernel, for example,
 # by setting the define to ".local" or ".bz123456"
 #
-#% define buildid .local
+%define buildid _tomoyo_1.6.1
 
 # fedora_build defines which build revision of this kernel version we're
 # building. Rather than incrementing forever, as with the prior versioning
@@ -389,6 +389,11 @@
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
@@ -442,7 +447,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -751,7 +756,7 @@
 Provides: kernel-devel = %{rpmversion}-%{release}%{?1}\
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -1228,6 +1233,11 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.6.1-20080510.tar.gz
+sed -i -e 's:EXTRAVERSION =.*:EXTRAVERSION = .7-92.fc8:' -- Makefile
+patch -sp1 < %_sourcedir/ccs-patch-2.6.25.4-10.fc8.diff
+
 %endif
 
 # Any further pre-build tree manipulations happen here.
@@ -1253,6 +1263,9 @@
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
mv kernel.spec kernel-2.6.25.4-10.fc8_tomoyo_1.6.1.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/kernel-2.6.25.4-10.fc8_tomoyo_1.6.1.spec if needed, and run"
echo "rpmbuild -bb /tmp/kernel-2.6.25.4-10.fc8_tomoyo_1.6.1.spec"
echo "to build kernel rpm packages."
exit 0
