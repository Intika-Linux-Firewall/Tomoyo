#!/bin/sh

export LANG=C

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t selinuxfs none /selinux/

# rpmdb of CentOS 5.7 LiveCD seems to be damaged...
rm -f /var/lib/rpm/__db*
rpm --rebuilddb
rpm -ivh /*.rpm
rpm -e kernel
tar -zcf /locale.tar.gz /usr/lib/locale/ /usr/share/locale/
yum -y update
rm -fR /usr/lib/locale/ /usr/share/locale/
tar -zxf /locale.tar.gz
rm -f /locale.tar.gz
yum clean all
rpm --rebuilddb
rm -f /var/log/yum.log

/usr/lib/ccs/init_policy

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
