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

wget -O /kumaneko-key http://I-love.SAKURA.ne.jp/kumaneko-key || die "Can't install key."
rpm --import /kumaneko-key || die "Can't install key."
rm -f /kumaneko-key
wget -O /etc/yum.repos.d/ccs.repo http://tomoyo.sourceforge.jp/repos-1.8/CentOS6/ccs.repo || die "Can't install repository." 
yum -y install ccs-kernel ccs-tools || die "Can't install packages."
rpm -e kernel
yum -y update
yum clean all
rpmbuild --rebuilddb

/usr/lib/ccs/init_policy --use_profile=1 --use_group=0

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
