Summary: TOMOYO Linux tools

Name: tomoyo-tools
Version: 2.2.0
Release: 1
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: ccs-tools < 2.2.0-1

Source0: http://osdn.dl.sourceforge.jp/tomoyo/?????/ccs-tools-2.2.0-20090???.tar.gz

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
/sbin/tomoyo-init
/usr/lib/tomoyo/
/usr/sbin/
/usr/share/man/
%attr(4755,root,root) /usr/lib/tomoyo/force-logout
%config(noreplace) /usr/lib/tomoyo/tomoyotools.conf

%changelog
* ??? ??? ?? 2009 2.2.0-1
- Separated from ccs-tools package.
