Summary: TOMOYO Linux tools

Name: tomoyo-tools
Version: 1.7.0
Release: 1
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: tomoyo-tools < 1.7.0-1

Source0: http://osdn.dl.sourceforge.jp/tomoyo/43376/tomoyo-tools-1.7.0-20090903.tar.gz

%description
This is TOMOYO Linux tools.

%prep

%setup -q -n tomoyotools

%build

make -s all

%install

make -s install INSTALLDIR=%{buildroot}

%clean

rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/sbin/tomoyo-init
/usr/lib/tomoyo/
/usr/sbin/
/usr/share/man/
%attr(4755,root,root) /usr/lib/tomoyo/force-logout
%config(noreplace) /usr/lib/tomoyo/tomoyotools.conf

%changelog
* Thu Sep 03 2009 1.7.0-1
- Removed programs for TOMOYO 2.2.0 from this package.
  Please use tomoyo-tools-2.2.0 package for TOMOYO 2.2.0 .
- Converted /sbin/tomoyo-init and /usr/lib/tomoyo/init_policy to binary programs.
- Removed "realpath", "make_alias", "makesyaoranconf".
- Added "--with-domainname" option to tomoyo-findtemp program.
- Changed installation directory from /usr/lib/tomoyo/ to /usr/sbin/ .
- Changed installation directory from /usr/lib/tomoyo/misc/ to /usr/lib/tomoyo/ .

* Tue Jun 23 2009 1.6.8-2
- tomoyo-auditd: Print error message if auditing interface is not available.

* Thu May 28 2009 1.6.8-1
- Minor update release.

* Wed Apr 01 2009 1.6.7-1
- Feature enhancement release.

* Mon Feb 02 2009 1.6.6-1
- Fix is_alphabet_char() bug.

* Tue Nov 11 2008 1.6.5-1
- Third anniversary release.
- Updated coding style and fixed some bugs.

* Wed Sep 03 2008 1.6.4-1
- Minor update release.

* Tue Jul 15 2008 1.6.3-1
- Bug fix release.
- Dropped suid-root from /usr/lib/tomoyo/misc/proxy because /usr/lib/tomoyo/ is 0755.

* Wed Jun 25 2008 1.6.2-1
- Minor update release.
- Change permission of /usr/lib/tomoyo/ to 0755

* Sat May 10 2008 1.6.1-1
- Minor update release.

* Tue Apr 01 2008 1.6.0-1
- Feature enhancement release.

* Thu Jan 31 2008 1.5.3-1
- Minor update release.

* Wed Dec 05 2007 1.5.2-1
- Minor update release.
- Added manpage.

* Thu Oct 19 2007 1.5.1-1
- Minor update release.

* Thu Sep 20 2007 1.5.0-1
- First-release.
