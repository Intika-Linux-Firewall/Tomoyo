#!/bin/sh

export LANG=C

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t selinuxfs none /selinux/

# rpmdb of CentOS 5.9 LiveCD seems to be damaged...
rm -f /var/lib/rpm/__db*
rpm --rebuilddb
rpm -ivh /*.rpm
rpm -e kernel
# Due to CD-R's capacity limit (700MB), remove openoffice.org and thunderbird packages.
yum -y remove 'openoffice.org-*' thunderbird
# Install Japanese fonts needed for TOMOYO tutorial.
yum -y install fonts-japanese
yum -y update
yum clean all
rpm --rebuilddb
rm -f /var/log/yum.log
# Install Flash Player plugin needed for TOMOYO website.
rpm -ivh `wget -O - 'http://get.adobe.com/jp/flashplayer/completion/?installer=Flash_Player_11.2_for_other_Linux_(.rpm)_32-bit' | awk ' { if ($1 == "location.href") print substr($3, 2, length($3) - 3); } '`
# Create symbolic link needed for Mozilla.
ln -s /usr/lib/flash-plugin/libflashplayer.so /usr/lib/mozilla/plugins-wrapped/

# Initialize TOMOYO Linux
/usr/lib/ccs/init_policy

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
