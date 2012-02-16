#!/bin/bash -x
set -e

DOWNLOAD_DIR="${HOME}/sources"

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49693"
URL_SERVICE_FILES="http://repo.tomoyolinux.co.uk/pub/other/services/fedora/16"

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

if [[ ! -e "ccs-auditd.service" ]]; then
	wget "${URL_SERVICE_FILES}/ccs-auditd.service" -O "ccs-auditd.service"
fi

if [[ ! -e "ccs-notifyd.service" ]]; then
	wget "${URL_SERVICE_FILES}/ccs-notifyd.service" -O "ccs-notifyd.service"
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
+Source1: http://repo.tomoyolinux.co.uk/pub/other/services/fedora/16/ccs-auditd.service
+Source2: http://repo.tomoyolinux.co.uk/pub/other/services/fedora/16/ccs-notifyd.service
 
 %description
 This package contains userspace tools for administrating TOMOYO Linux 1.8.x.
@@ -36,6 +33,14 @@
 rm -rf $RPM_BUILD_ROOT
 make INSTALLDIR=$RPM_BUILD_ROOT USRLIBDIR=%_libdir install
 
+mkdir -p $RPM_BUILD_ROOT/lib/systemd/system
+
+install -m 644 $RPM_SOURCE_DIR/ccs-auditd.service \
+    $RPM_BUILD_ROOT/lib/systemd/system/ccs-auditd.service
+
+install -m 644 $RPM_SOURCE_DIR/ccs-notifyd.service \
+    $RPM_BUILD_ROOT/lib/systemd/system/ccs-notifyd.service
+
 %clean
 
 rm -rf $RPM_BUILD_ROOT
@@ -43,6 +48,19 @@
 %post
 ldconfig || true
 
+%preun
+if [ $1 -eq 0 ] ; then
+    # On uninstall (not upgrade), disable and stop the units
+    /bin/systemctl --no-reload disable ccs-auditd.service >/dev/null 2>&1 || :
+    /bin/systemctl --no-reload disable ccs-notifyd.service >/dev/null 2>&1 || :
+    /bin/systemctl stop ccs-auditd.service >/dev/null 2>&1 || :
+    /bin/systemctl stop ccs-notifyd.service >/dev/null 2>&1 || :
+fi
+
+%postun
+/bin/systemctl daemon-reload >/dev/null 2>&1 || :
+
+
 %files
 %defattr(-,root,root)
 /sbin/
@@ -51,6 +69,8 @@
 /usr/sbin/
 /usr/share/man/man8/
 
+/lib/systemd/system/*.service
+
 %changelog
 * Tue Oct 25 2011 1.8.3-2
 - Let ccs-queryd use query id rather than global PID when reaching target
EOF
}

rpmbuild -bs "${HOME}/rpmbuild/SPECS/ccs-tools.spec"
