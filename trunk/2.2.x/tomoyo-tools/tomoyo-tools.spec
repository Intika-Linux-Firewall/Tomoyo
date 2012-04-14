Summary: Userspace tools for TOMOYO Linux 2.2.x

Name: tomoyo-tools
Version: 2.2.0
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
Conflicts: tomoyo-tools < 2.2.0-4

Source0: http://osdn.dl.sourceforge.jp/tomoyo/41908/tomoyo-tools-2.2.0-20120414.tar.gz

%description
This package contains userspace tools for administrating TOMOYO Linux 2.2.x.
Please see http://tomoyo.sourceforge.jp/2.2/ for documentation.

%prep

%setup -q -n tomoyo-tools

%build

make USRLIBDIR=%_libdir CFLAGS="-Wall $RPM_OPT_FLAGS"

%install

rm -rf $RPM_BUILD_ROOT
make INSTALLDIR=$RPM_BUILD_ROOT USRLIBDIR=%_libdir install

%clean

rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/sbin/
%_libdir/tomoyo/
/usr/sbin/
/usr/share/man/man8/
%config(noreplace) %_libdir/tomoyo/tomoyotools.conf

%changelog
* Sat Apr 14 2012 2.2.0-4
- Let tomoyo-editpolicy parse statistics lines correctly.
- Update manpages.
- Update Makefile to include variables.

* Fri Feb 11 2011 2.2.0-3
- Mount sysfs when /sys/kernel/security/ does not exist rather than when /sys/kernel/ does not exist, for some distributions have /sys/kernel/debug/ on root device.

* Thu Feb 25 2010 2.2.0-2
- Recursive directory matching operator support was added to kernel 2.6.33.
- Restriction for ioctl/chmod/chown/chgrp/mount/unmount/chroot/pivot_root was added to kernel 2.6.34.

* Mon Jul 27 2009 2.2.0-1
- Separated from ccs-tools package.
