#!/bin/sh

export LANG=C

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t selinuxfs none /selinux/

# rpmdb of CentOS 5.8 LiveCD seems to be damaged...
rm -f /var/lib/rpm/__db*
rpm --rebuilddb
rpm -ivh /*.rpm
rpm -e kernel
# Due to CD-R's capacity limit (700MB), remove openoffice.org packages.
yum -y remove 'openoffice.org-*'
# Install Japanese fonts needed for TOMOYO tutorial.
yum -y install fonts-japanese
yum -y update
yum clean all
rpm --rebuilddb
rm -f /var/log/yum.log

/usr/lib/ccs/init_policy

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
