#!/bin/sh

export LANG=C

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t selinuxfs none /selinux/

# rpmdb of CentOS 5.11 LiveCD seems to be damaged...
rm -f /var/lib/rpm/__db*
rpm --rebuilddb
rpm -ivh /*.rpm
rpm -e kernel
# Due to CD-R's capacity limit (700MB), remove openoffice.org and thunderbird and java packages.
yum -y remove 'openoffice.org-*' thunderbird java-1.6.0-openjdk
# Install Japanese fonts needed for TOMOYO tutorial.
yum -y install fonts-japanese
yum -y update
yum clean all
rpm --rebuilddb
rm -f /var/log/yum.log
# Install Flash Player plugin needed for TOMOYO website.
wget --no-check-certificate `wget --no-check-certificate -O - 'https://get.adobe.com/flashplayer/download/?installer=FP_11.2_for_other_Linux_32-bit_%28.rpm%29&stype=2734&standalone=1' | awk ' { if ($1 == "setTimeout(\"location.href") print substr($3, 2, length($3) - 5); } '`
rpm -ivh flash-plugin-*.rpm
rm -f flash-plugin-*.rpm
# Create symbolic link needed for Mozilla.
ln -s /usr/lib/flash-plugin/libflashplayer.so /usr/lib/mozilla/plugins-wrapped/

# Initialize TOMOYO Linux
/usr/lib/ccs/init_policy

: > /etc/resolv.conf
umount -l /selinux/
umount -l /sys/
umount -l /proc/
