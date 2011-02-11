Summary: TOMOYO Linux tools

Name: tomoyo-tools
Version: 2.3.0
Release: 2
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: tomoyo-tools < 2.3.0-2

Source0: http://osdn.dl.sourceforge.jp/tomoyo/48663/tomoyo-tools-2.3.0-20110211.tar.gz

%description
This is TOMOYO Linux tools.

%prep

%setup -q -n tomoyo-tools

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
%config(noreplace) /usr/lib/tomoyo/tomoyotools.conf

%changelog
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
