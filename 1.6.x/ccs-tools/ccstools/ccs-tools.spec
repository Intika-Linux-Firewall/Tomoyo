Summary: TOMOYO Linux tools

Name: ccs-tools
Version: 1.6.9
Release: 2
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: ccs-tools < 1.6.9-2

Source0: https://osdn.dl.osdn.jp/tomoyo/30298/ccs-tools-1.6.9-20120301.tar.gz

%description
This is TOMOYO Linux tools.

%prep

%setup -q -n ccstools

%build

make -s all

%install

make -s install INSTALLDIR=%{buildroot}

%clean

rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/sbin/ccs-init
/sbin/tomoyo-init
/usr/lib/ccs/
/usr/sbin/
/usr/share/man/
%attr(4755,root,root) /usr/lib/ccs/misc/force-logout
%config(noreplace) /usr/lib/ccs/ccstools.conf

%changelog
* Thu Mar 01 2012 1.6.9-2
- Version bump for synchronizing with kernel patch.

* Fri Apr 01 2011 1.6.9-1
- Version bump for synchronizing with kernel patch.

* Mon Nov 22 2010 1.6.8-5
- ccs-checkpolicy: Do not check trailing '/' for deny_unmount keyword.

* Fri Jan 15 2010 1.6.8-4
- Convert /sbin/ccs-init and /sbin/tomoyo-init as C program in case awk and seq
  are not available by the time /sbin/init starts.

* Wed Nov 11 2009 1.6.8-3
- Fix typo.

* Tue Jun 23 2009 1.6.8-2
- ccs-auditd: Print error message if auditing interface is not available.

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
- Dropped suid-root from /usr/lib/ccs/misc/proxy because /usr/lib/ccs/ is 0755.

* Wed Jun 25 2008 1.6.2-1
- Minor update release.
- Change permission of /usr/lib/ccs/ to 0755

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
