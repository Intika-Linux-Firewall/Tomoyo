#! /bin/sh
#
# This is a kernel build script for Fedora 20's 3.19 kernel.
#

die () {
    echo $1
    exit 1
}

yum -y install tar wget rpm-build make gcc patch redhat-rpm-config xmlto asciidoc gnupg elfutils-devel zlib-devel binutils-devel newt-devel python-devel perl-ExtUtils-Embed pciutils-devel hmaccalc bison net-tools audit-libs-devel pesign bc ncurses-devel

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-3.19.8-100.fc20.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/fedora/updates/20/SRPMS/kernel-3.19.8-100.fc20.src.rpm || die "Can't download source package."
fi
LANG=C rpm --checksig kernel-3.19.8-100.fc20.src.rpm | grep -F ': rsa sha1 (md5) pgp md5 OK' || die "Can't verify signature."
rpm -ivh kernel-3.19.8-100.fc20.src.rpm || die "Can't install source package."

cd /root/rpmbuild/SOURCES/ || die "Can't chdir to /root/rpmbuild/SOURCES/ ."
if [ ! -r ccs-patch-1.8.4-20150505.tar.gz ]
then
    wget -O ccs-patch-1.8.4-20150505.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.4-20150505.tar.gz' || die "Can't download patch."
fi

cd /root/rpmbuild/SPECS/ || die "Can't chdir to /root/rpmbuild/SPECS/ ."
cp -p kernel.spec ccs-kernel.spec || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- ccs-kernel.spec
+++ ccs-kernel.spec
@@ -31,7 +31,7 @@
 #
 # (Uncomment the '#' and both spaces below to set the buildid.)
 #
-# % define buildid .local
+%define buildid _tomoyo_1.8.4
 ###################################################################
 
 # The buildid can also be specified on the rpmbuild command line
@@ -477,7 +477,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2 and Redistributable, no modification permitted
 URL: http://www.kernel.org/
@@ -964,7 +964,7 @@
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
 Requires: perl\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -984,7 +984,7 @@
 Provides: kernel%{?1:-%{1}}-modules-extra-uname-r = %{KVERREL}%{?1:+%{1}}\
 Requires: kernel-uname-r = %{KVERREL}%{?1:+%{1}}\
 AutoReqProv: no\
-%description -n kernel%{?variant}%{?1:-%{1}}-modules-extra\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-modules-extra\
 This package provides less commonly used kernel modules for the %{?2:%{2} }kernel package.\
 %{nil}
 
@@ -1527,6 +1527,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.8.4-20150505.tar.gz
+patch -sp1 < patches/ccs-patch-3.19-fedora-20.diff
+
 %endif
 
 # Any further pre-build tree manipulations happen here.
@@ -1551,6 +1555,17 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux 2.5
+  sed -i -e 's/# CONFIG_SECURITY_PATH is not set/CONFIG_SECURITY_PATH=y/' -- .config
+  sed -i -e 's/# CONFIG_SECURITY_TOMOYO is not set/CONFIG_SECURITY_TOMOYO=y/' -- .config
+  echo 'CONFIG_SECURITY_TOMOYO_MAX_ACCEPT_ENTRY=2048' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_MAX_AUDIT_LOG=1024' >> .config
+  echo '# CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER is not set' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_POLICY_LOADER="/sbin/tomoyo-init"' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_ACTIVATION_TRIGGER="/sbin/init"' >> .config
+  echo '# CONFIG_DEFAULT_SECURITY_TOMOYO is not set' >> .config
+  # TOMOYO Linux 1.8
+  cat config.ccs >> .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch listnewconfig | grep -E '^CONFIG_' >.newoptions || true
 %if %{listnewconfig_fail}
EOF
echo ""
echo ""
echo ""
echo "Edit /root/rpmbuild/SPECS/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /root/rpmbuild/SPECS/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
ARCH=`uname -m`
echo "I'll start 'rpmbuild -bb --target $ARCH --without debug --without debuginfo /root/rpmbuild/SPECS/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target $ARCH --without debug --without debuginfo /root/rpmbuild/SPECS/ccs-kernel.spec
exit 0
