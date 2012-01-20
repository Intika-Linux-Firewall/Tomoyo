Summary: Userspace tools for TOMOYO Linux 2.4.x

Name: tomoyo-tools
Version: 2.4.0
Release: 4
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
##
## This spec file is intended to be distribution independent.
## I don't enable "BuildRequires:" line because rpmbuild will fail on
## environments where packages are managed by (e.g.) apt.
##
# BuildRequires: ncurses-devel
Requires: ncurses
Conflicts: tomoyo-tools < 2.4.0-4

Source0: http://osdn.dl.sourceforge.jp/tomoyo/52848/tomoyo-tools-2.4.0-20111025.tar.gz

%description
This package contains userspace tools for administrating TOMOYO Linux 2.4.
Please see http://tomoyo.sourceforge.jp/2.4/ for documentation.

%prep

%setup -q -n tomoyo-tools

%build

make USRLIBDIR=%_libdir CFLAGS="-Wall $RPM_OPT_FLAGS"

%install

rm -rf $RPM_BUILD_ROOT
make INSTALLDIR=$RPM_BUILD_ROOT USRLIBDIR=%_libdir install

%clean

rm -rf $RPM_BUILD_ROOT

%post
ldconfig || true

%files
%defattr(-,root,root)
/sbin/
%_libdir/tomoyo/
%_libdir/libtomoyo*
/usr/sbin/
/usr/share/man/man8/

%changelog
* Tue Oct 25 2011 2.4.0-4
- Add "socket:[family=\\$:type=\\$:protocol=\\$]" to ANY_PATHNAME group.

* Thu Sep 29 2011 2.4.0-3
- Fix build failure with --as-needed option.
- Remove redundant/unused code.
- Revert include/sched.h inclusion and bring "#define _GNU_SOURCE" to the top.

* Sat Aug 20 2011 2.4.0-2
- Add /proc/self/exe as aggregator entry.
- Fix policy unpacking when multiple namespaces exist.
- Include linux/sched.h if sched.h does not provide CLONE_NEWNS.

* Sat Aug 06 2011 2.4.0-1
- Major update release.
