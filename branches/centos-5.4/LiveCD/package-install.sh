#!/bin/sh

export LANG=C

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t selinuxfs none /selinux/

# rpmdb of CentOS 5.4 LiveCD seems to be damaged...
rm -f /var/lib/rpm/__db*
rpm --rebuilddb
rpm -ivh /*.rpm
rpm -e kernel
yum -y update
yum clean all
rpm --rebuilddb

/usr/lib/ccs/init_policy

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
