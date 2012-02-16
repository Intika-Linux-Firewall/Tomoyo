set -e

DOWNLOAD_DIR="${HOME}/sources"

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49693"
URL_SERVICE_FILES="http://repo.tomoyolinux.co.uk/pub/other/services/tpel/6"

ARCH="$(uname -m)"
CCS_TOOLS_VER="1.8.3-20111025"

rm -rf "${HOME}/rpmbuild"
rpmdev-setuptree
rm -rf "${HOME}/rpmbuild/SOURCES"
ln -sf "${DOWNLOAD_DIR}/ccs-tools-${CCS_TOOLS_VER}" \
	"${HOME}/rpmbuild/SOURCES"

if [[ ! -d "${DOWNLOAD_DIR}/ccs-tools-${CCS_TOOLS_VER}" ]]; then
	mkdir "${DOWNLOAD_DIR}/ccs-tools-${CCS_TOOLS_VER}"
fi
cd "${DOWNLOAD_DIR}/ccs-tools-${CCS_TOOLS_VER}"

if [[ ! -e "ccs-tools-${CCS_TOOLS_VER}.tar.gz" ]]; then
	wget "${URL_CCS}/ccs-tools-${CCS_TOOLS_VER}.tar.gz" \
		-O "ccs-tools-${CCS_TOOLS_VER}.tar.gz"
fi

if [[ ! -e "ccs-auditd" ]]; then
	wget "${URL_SERVICE_FILES}/ccs-auditd" -O "ccs-auditd"
fi

if [[ ! -e "ccs-notifyd" ]]; then
	wget "${URL_SERVICE_FILES}/ccs-notifyd" -O "ccs-notifyd"
fi

tar -zxvf "ccs-tools-${CCS_TOOLS_VER}.tar.gz" ccstools/ccs-tools.spec -O \
	> "${HOME}/rpmbuild/SPECS/ccs-tools.spec"

cd "${HOME}/rpmbuild/SPECS"

apply_patch() {
	cat << 'EOF' | patch
--- ccs-tools.spec
+++ ccs-tools.spec
@@ -8,16 +8,13 @@
 ExclusiveOS: Linux
 Autoreqprov: no
 Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
-##
-## This spec file is intended for distribution independent.
-## I don't enable "BuildRequires:" line because rpmbuild will fail on
-## environments where packages are managed by (e.g.) apt.
-##
-# BuildRequires: ncurses-devel
+BuildRequires: ncurses-devel
 Requires: ncurses
 Conflicts: ccs-tools < 1.8.3-2
 
 Source0: http://osdn.dl.sourceforge.jp/tomoyo/49693/ccs-tools-1.8.3-20111025.tar.gz
+Source1: http://repo.tomoyolinux.co.uk/pub/other/services/tpel/6/ccs-auditd
+Source2: http://repo.tomoyolinux.co.uk/pub/other/services/tpel/6/ccs-notifyd
 
 %description
 This package contains userspace tools for administrating TOMOYO Linux 1.8.x.
@@ -36,6 +33,14 @@
 rm -rf $RPM_BUILD_ROOT
 make INSTALLDIR=$RPM_BUILD_ROOT USRLIBDIR=%_libdir install
 
+mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
+
+install -m 755 $RPM_SOURCE_DIR/ccs-auditd \
+    $RPM_BUILD_ROOT/etc/rc.d/init.d/ccs-auditd
+
+install -m 755 $RPM_SOURCE_DIR/ccs-notifyd \
+    $RPM_BUILD_ROOT/etc/rc.d/init.d/ccs-notifyd
+
 %clean
 
 rm -rf $RPM_BUILD_ROOT
@@ -43,6 +48,17 @@
 %post
 ldconfig || true
 
+/sbin/chkconfig --add ccs-auditd
+/sbin/chkconfig --add ccs-notifyd
+
+%preun
+if [ $1 = 0 ]; then
+    /sbin/service ccs-auditd stop > /dev/null 2>&1
+    /sbin/service ccs-notify stop > /dev/null 2>&1
+    /sbin/chkconfig --del ccs-auditd
+    /sbin/chkconfig --del ccs-notifyd
+fi
+
 %files
 %defattr(-,root,root)
 /sbin/
@@ -51,6 +67,9 @@
 /usr/sbin/
 /usr/share/man/man8/
 
+%{_sysconfdir}/rc.d/init.d/ccs-auditd
+%{_sysconfdir}/rc.d/init.d/ccs-notifyd
+
 %changelog
 * Tue Oct 25 2011 1.8.3-2
 - Let ccs-queryd use query id rather than global PID when reaching target
EOF
}

rpmbuild -bs "${HOME}/rpmbuild/SPECS/ccs-tools.spec"
