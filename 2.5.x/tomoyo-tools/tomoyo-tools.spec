Summary: Userspace tools for TOMOYO Linux 2.5.x

Name: tomoyo-tools
Version: 2.5.0
Release: 9
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
Conflicts: tomoyo-tools < 2.5.0-9

Source0: http://osdn.dl.osdn.jp/tomoyo/53357/tomoyo-tools-2.5.0-20170102.tar.gz

%description
This package contains userspace tools for administrating TOMOYO Linux 2.5.x.
Please see http://tomoyo.osdn.jp/2.5/ for documentation.

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
/sbin/*
%_libdir/tomoyo/*
%_libdir/libtomoyo*
/usr/sbin/*
/usr/share/man/man8/*

%changelog
* Mon Jan 02 2017 2.5.0-9
- Rebase to ccs-tools 1.8.5-2.

* Sun Jun 01 2014 2.5.0-8
- Let tomoyo-editpolicy print "acl_group $N" correctly when using offline mode.

* Sun Jan 05 2014 2.5.0-7
- Let init_policy add path to systemd , as suggested by Shawn Landden.
- Let tomoyo-queryd use poll() rather than select().

* Sat Apr 06 2013 2.5.0-6
- Fix compile warning from clang.

* Thu Feb 14 2013 2.5.0-5
- Change Makefile's build flags, as suggested by Simon Ruderich and Hideki
  Yamane. (Debian bug 674723)
- Change / to /* in rpm's %files section because Fedora 18 complains conflicts.

* Sun Aug 05 2012 2.5.0-4
- Let tomoyo-checkpolicy handle namespace prefix in exception policy.
- Rename manpage for init_policy to tomoyo_init_policy
  (to allow parallel installation of ccs-tools package).

* Sat Apr 14 2012 2.5.0-3
- Let tomoyo-init parse statistics lines correctly.
- Let tomoyo-editpolicy print number of selected entries if any.
- Fix IP address parsing in ccs_parse_ip().

* Tue Oct 25 2011 2.5.0-2
- Let tomoyo-queryd use query id rather than global PID when reaching target
  process's domain policy.
- Add "socket:[family=\\$:type=\\$:protocol=\\$]" to ANY_PATHNAME group.

* Thu Sep 29 2011 2.5.0-1
- Major update release.
