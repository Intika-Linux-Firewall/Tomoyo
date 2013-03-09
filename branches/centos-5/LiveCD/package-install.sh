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
# Due to CD-R's capacity limit (700MB), remove openoffice.org packages.
yum -y remove 'openoffice.org-*'
# Install Japanese fonts needed for TOMOYO tutorial.
yum -y install fonts-japanese
yum -y update
yum clean all
rpm --rebuilddb
rm -f /var/log/yum.log
# Install Flash Player plugin needed for TOMOYO website.
FILENAME=`wget -O - 'http://get.adobe.com/jp/flashplayer/completion/?installer=Flash_Player_11_for_other_Linux_(.rpm)_32-bit' | awk ' { if ($1 == "location.href") print $3; } ' | awk -F\' ' { if ( substr($2, 0, 33) == "http://fpdownload.macromedia.com/" && index($2, ".rpm") > 0) print $2 } '`
rpm -ivh $FILENAME
# Create symbolic link needed for Mozilla.
ln -s /usr/lib/flash-plugin/libflashplayer.so /usr/lib/mozilla/plugins-wrapped/

# Initialize TOMOYO Linux
/usr/lib/ccs/init_policy

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
