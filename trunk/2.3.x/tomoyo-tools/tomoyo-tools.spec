Summary: Userspace tools for TOMOYO Linux 2.3.x

Name: tomoyo-tools
Version: 2.3.0
Release: 5
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
Conflicts: tomoyo-tools < 2.3.0-5

Source0: http://osdn.dl.sourceforge.jp/tomoyo/48663/tomoyo-tools-2.3.0-20120414.tar.gz

%description
This package contains userspace tools for administrating TOMOYO Linux 2.3.x.
Please see http://tomoyo.sourceforge.jp/2.3/ for documentation.

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
/usr/sbin/
/usr/share/man/man8/
%config(noreplace) %_libdir/tomoyo/tomoyotools.conf

%changelog
* Sat Apr 14 2012 2.3.0-5
- Update manpages.
- Update Makefile to include variables.

* Thu Sep 29 2011 2.3.0-4
- Fix build failure with --as-needed option.
- Bring "#define _GNU_SOURCE" to the top in order to make sure that CLONE_NEWNS is defined.
- Remove redundant/unused code.
- init_policy: Print library file's pathnames using wildcard patterns.
- tomoyo-editpolicy: Allow use of 'O' key from to exception policy editor screen.
- tomoyo-editpolicy: Fix segmentation fault error when '@' key is pressed from process viewer screen.
- tomoyo-checkpolicy: Fix validation with "number_group" lines.
- tomoyo-queryd: Ignore patterned "allow_read" lines in exception policy.

* Wed May 11 2011 2.3.0-3
- Fix build error on parallel build.
- Fix wrong domainname validation.
- Allow configuring tomoyo-editpolicy's background color.

* Fri Feb 11 2011 2.3.0-2
- Mount sysfs when /sys/kernel/security/ does not exist rather than when /sys/kernel/ does not exist, for some distributions have /sys/kernel/debug/ on root device.
- Wait for /etc/tomoyo/tomoyo-post-init in a more reliable way.
- Fix regression introduced when fixing old/new inversion bug.

* Fri Aug 20 2010 2.3.0-1
- Rebased using ccs-tools package.
- Various enhancements were added to kernel 2.6.36.

* Thu Feb 25 2010 2.2.0-2
- Recursive directory matching operator support was added to kernel 2.6.33.
- Restriction for ioctl/chmod/chown/chgrp/mount/unmount/chroot/pivot_root was added to kernel 2.6.34.

* Mon Jul 27 2009 2.2.0-1
- Separated from ccs-tools package.
