Summary: Userspace tools for TOMOYO Linux 2.5.x

Name: tomoyo-tools
Version: 2.5.0
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
Conflicts: tomoyo-tools < 2.5.0-3

Source0: http://osdn.dl.sourceforge.jp/tomoyo/53357/tomoyo-tools-2.5.0-20120414.tar.gz

%description
This package contains userspace tools for administrating TOMOYO Linux 2.5.x.
Please see http://tomoyo.sourceforge.jp/2.5/ for documentation.

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
* Sat Apr 14 2012 2.5.0-3
- Let tomoyo-editpolicy print number of selected entries if any.
- Fix IP address parsing in ccs_parse_ip().

* Tue Oct 25 2011 2.5.0-2
- Let tomoyo-queryd use query id rather than global PID when reaching target
  process's domain policy.
- Add "socket:[family=\\$:type=\\$:protocol=\\$]" to ANY_PATHNAME group.

* Thu Sep 29 2011 2.5.0-1
- Major update release.
