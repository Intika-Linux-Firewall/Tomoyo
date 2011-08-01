#!/bin/sh

# set -v

export LANG=C

die () {
    echo '********** ' $1 ' **********'
    umount /selinux/
    umount /sys/
    umount /proc/
    exit 1
}

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t selinuxfs none /selinux/

yum -y update
yum clean all
rpm --rebuilddb

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
