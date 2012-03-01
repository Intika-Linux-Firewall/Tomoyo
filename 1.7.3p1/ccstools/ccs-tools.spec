Summary: TOMOYO Linux tools

Name: ccs-tools
Version: 1.7.3
Release: 2
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: ccs-tools < 1.7.3-2

Source0: http://osdn.dl.sourceforge.jp/tomoyo/43376/ccs-tools-1.7.3-20120301.tar.gz

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
/usr/lib/ccs/
/usr/sbin/
/usr/share/man/
%attr(4755,root,root) /usr/lib/ccs/force-logout
%config(noreplace) /usr/lib/ccs/ccstools.conf

%changelog
* Thu Mar 01 2012 1.7.3-2
- Fix ccs-checkpolicy number_group validation failure.
- Let ccs-editpolicy allow optimization command to exception policy.
- Fix ccs-editpolicy wrong copy to buffer command from Process State Viewer mode.
- Let init_policy generate wildcarded allow_read entries.

* Fri Apr 01 2011 1.7.3-1
- Fix convert-audit-log bad exec.envp[] handling.

* Fri Dec 31 2010 1.7.2-3
- Fix regression introduced when fixing old/new inversion bug.

* Mon Nov 22 2010 1.7.2-2
- ccs-init should ignore EINTR when waiting for child programs to finish.
- Fix ccs-diffpolicy old/new inversion bug.
- Fix init_policy's error message.
- ccs-load-module should search /sbin and /bin in addition to $PATH.
- Use \e for representing \ in manpage of ccs-pathmatch.

* Thu Apr 01 2010 1.7.2-1
- ccs-sortpolicy should not remove use_profile lines.
- ccs-init calls /etc/ccs/ccs-load-module for loading TOMOYO which was built as a loadable kernel module.
- Updated to handle TOMOYO 1.7.2's syntax.

* Sun Jan 10 2010 1.7.1-2
- ccs-auditd should call fflush() immediately after fprintf().
- ccs-queryd was not able to handle /etc/ld.so.cache updates.
- ccs-checkpolicy was not able to handle some of TOMOYO 1.7.1's syntax.
- Use dynamic buffer allocation for supporting longer lines.
- Ignore /proc/0 which is an invalid proc entry.

* Wed Nov 11 2009 1.7.1-1
- Fourth anniversary release.
- Added network mode support to ccs-queryd and ccs-auditd.
- Removed policy diff support from ccs-savepolicy, ccs-loadpolicy, ccs-init .
- Added ccs-diffpolicy for generating policy diff file.
- Updated to handle TOMOYO 1.7.x's syntax.
- Added ccs-selectpolicy for picking up specific domain's policy.
- Added convert-audit-log for generating policy from audit logs.
- Added "--file" option to ccs-patternize.

* Thu Sep 03 2009 1.7.0-1
- Removed programs for TOMOYO 2.2.0 from this package.
  Please use tomoyo-tools-2.2.0 package for TOMOYO 2.2.0 .
- Converted /sbin/ccs-init and /usr/lib/ccs/init_policy to binary programs.
- Removed "realpath", "make_alias", "makesyaoranconf".
- Added "--with-domainname" option to ccs-findtemp program.
- Changed installation directory from /usr/lib/ccs/ to /usr/sbin/ .
- Changed installation directory from /usr/lib/ccs/misc/ to /usr/lib/ccs/ .

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
