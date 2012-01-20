Summary: Userspace tools for TOMOYO Linux 2.4.x

##
## Change to /usr/lib64 if needed.
##
%define usrlibdir /usr/lib

Name: tomoyo-tools
Version: 2.4.0
Release: 3
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
Conflicts: tomoyo-tools < 2.4.0-3

Source0: http://osdn.dl.sourceforge.jp/tomoyo/52848/tomoyo-tools-2.4.0-20110929.tar.gz

%description
This package contains userspace tools for administrating TOMOYO Linux 2.4.
Please see http://tomoyo.sourceforge.jp/2.4/ for documentation.

%prep

%setup -q -n tomoyo-tools

%build

make USRLIBDIR=%{usrlibdir} CFLAGS="-Wall $RPM_OPT_FLAGS"

%install

rm -rf $RPM_BUILD_ROOT
make INSTALLDIR=$RPM_BUILD_ROOT USRLIBDIR=%{usrlibdir} \
    CFLAGS="-Wall $RPM_OPT_FLAGS" install

%clean

rm -rf $RPM_BUILD_ROOT

%post
ldconfig || true

%files
%defattr(-,root,root)
/sbin/
%{usrlibdir}/tomoyo/
%{usrlibdir}/libtomoyo*
/usr/sbin/
/usr/share/man/man8/

%changelog
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
