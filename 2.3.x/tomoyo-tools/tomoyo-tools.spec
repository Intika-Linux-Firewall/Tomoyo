Summary: TOMOYO Linux tools

Name: tomoyo-tools
Version: 2.3.0
Release: 1
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: tomoyo-tools < 2.3.0-1

Source0: tomoyo-tools.tar.gz

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
/usr/lib/
/usr/sbin/
/usr/share/man/
%attr(4755,root,root) /usr/lib/tomoyo/force-logout
%config(noreplace) /usr/lib/tomoyo/tomoyotools.conf

%changelog
* Fri Jun 04 2010 2.3.0-0
- This is a private release for testing.
