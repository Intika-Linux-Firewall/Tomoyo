Summary: Userspace tools for TOMOYO Linux 1.8.x

##
## Change to /usr/lib64 if needed.
##
%define usrlibdir /usr/lib

Name: ccs-tools
Version: 1.8.2
Release: 5
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
##
## This spec file is intended for distribution independent.
## I don't enable "BuildRequires:" line because rpmbuild will fail on
## environments where packages are managed by (e.g.) apt.
##
# BuildRequires: ncurses-devel
Requires: ncurses
Conflicts: ccs-tools < 1.8.2-5

Source0: http://osdn.dl.sourceforge.jp/tomoyo/49693/ccs-tools-1.8.2-20110820.tar.gz

%description
This package contains userspace tools for administrating TOMOYO Linux 1.8.x.
Please see http://tomoyo.sourceforge.jp/1.8/ for documentation.

%prep

%setup -q -n ccstools

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
%{usrlibdir}/ccs/
%{usrlibdir}/libccs*
/usr/sbin/
/usr/share/man/man8/

%changelog
* Sat Aug 20 2011 1.8.2-5
- Add /proc/self/exe as aggregator entry.
- Fix policy unpacking when multiple namespaces exist.
- Include linux/sched.h if sched.h does not provide CLONE_NEWNS.

* Wed Jul 13 2011 1.8.2-4
- Let ccs-init handle profiles in all namespaces.
- Let ccs-editpolicy print domain's name rather than shortcut's name.
- Let ccs-editpolicy parse and print IPv6 address in RFC5952 format.
- Let ccs-checkpolicy parse and check IPv6 address in RFC5952 format.
- Let libccstools.so.2 parse IPv6 address in RFC5952 format.

* Thu Jul 07 2011 1.8.2-3
- Fix bugs in ccs-editpolicy's domain transition jump information.
- Let ccs-setprofile use /proc/ccs/domain_policy rather than /proc/ccs/.domain_status .

* Sun Jun 26 2011 1.8.2-2
- Improve ccs-editpolicy's domain transition jump information.
- Fix several bugs in ccs-editpolicy.

* Mon Jun 20 2011 1.8.2-1
- Updated to handle TOMOYO 1.8.2's syntax.
- Support policy namespace.
- Let ccs-editpolicy validate policy when editing on-disk policy files.
- Let ccs-auditd reload configuration file upon SIGHUP.
- Let ccs-notifyd reload configuration file upon SIGHUP.

* Wed May 11 2011 1.8.1-2
- Fix wrong domainname validation.
- Fix wrong ACL lines counting.
- Allow configuring ccs-editpolicy's background color.

* Fri Apr 01 2011 1.8.1-1
- Updated to handle TOMOYO 1.8.1's syntax.
- Support packed policy format.
- Fix build error on parallel build.
- Make ccs-editpolicy handle all domain transition related directives.

* Mon Feb 14 2011 1.8.0-4
- Use readymade manpages in order to remove help2man and gzip from build dependency.
- Removed examples from build target in order to remove readline-devel from build dependency.
- Use Include.make for passing variables.
- Use install command rather than cp/chmod/chown commands.
- Add comments on and reconstruct some of files.
- Stop if failed to build ccs-editpolicy (probably due to lack of ncurses-devel).

* Fri Dec 31 2010 1.8.0-3
- Usability enhancement release.
- Not compatible with 1.8.0-2 and earlier.
- Needs ccs-patch 1.8.0-20101231 due to pathname changes in audit interface.
- Various bugs were fixed and configuration files are introduced.

* Mon Nov 22 2010 1.8.0-2
- ccs-patternize must print "network " keyword.

* Thu Nov 11 2010 1.8.0-1
- Fifth anniversary release.

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
