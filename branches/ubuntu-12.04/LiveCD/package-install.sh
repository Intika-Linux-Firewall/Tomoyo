#!/bin/sh

# set -v

export LANG=C

die () {
    echo '********** ' $1 ' **********'
    umount -l /dev/pts/
    umount -l /sys/
    umount -l /proc/
    exit 1
}

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t devpts none /dev/pts/

wget http://osdn.dl.sourceforge.jp/tomoyo/55680/tomoyo-tools_2.5.0-3_i386.deb
echo 'd94b61bedd65857fc71a51e5440256f0  tomoyo-tools_2.5.0-3_i386.deb' | md5sum -c - || rm -f tomoyo-tools_2.5.0-3_i386.deb
dpkg-deb -x tomoyo-tools_2.5.0-3_i386.deb /
rm -f tomoyo-tools_2.5.0-3_i386.deb

wget -O - http://I-love.SAKURA.ne.jp/kumaneko-key | apt-key add - || die "Can't install key."
grep -qF tomoyo.sourceforge.jp /sources.list || echo 'deb http://tomoyo.sourceforge.jp/repos-1.8/Ubuntu12.04/ ./' >> /sources.list
apt-get -y -o Dir::Etc::SourceList=/sources.list update || die "apt-get update failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list install linux-generic-pae-ccs linux-headers-generic-pae-ccs ccs-tools || die "Can't install packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list purge linux-image-3.2.0-23-generic-pae linux-image-generic-pae linux-headers-generic-pae linux-generic-pae || die "Can't uninstall packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list upgrade || die "apt-get upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list dist-upgrade || die "apt-get dist-upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list autoremove
dpkg --purge linux-headers-3.2.0-23 linux-headers-3.2.0-23-generic-pae
find / -name '*.pyc' -print0 | xargs -0 rm --
apt-get -y -o Dir::Etc::SourceList=/sources.list clean

/usr/lib/ccs/init_policy --use_profile=1
awk ' { print "squashfs:"$0 } ' /etc/ccs/policy/current/manager.conf > /etc/ccs/policy/current/manager.conf.tmp
cat /etc/ccs/policy/current/manager.conf.tmp >> /etc/ccs/policy/current/manager.conf
rm -f /etc/ccs/policy/current/manager.conf.tmp

/usr/lib/tomoyo/init_policy --use_profile=1
# Workaround for squashfs:/path/to/manager which the TOMOYO 2.5 kernel cannot acccept.
(
echo '<kernel> /usr/sbin/tomoyo-loadpolicy'
echo '<kernel> /usr/sbin/tomoyo-editpolicy'
echo '<kernel> /usr/sbin/tomoyo-setlevel'
echo '<kernel> /usr/sbin/tomoyo-setprofile'
echo '<kernel> /usr/sbin/tomoyo-queryd'
) > /etc/tomoyo/policy/current/manager.conf
(
echo 'initialize_domain /usr/sbin/tomoyo-loadpolicy from any'
echo 'initialize_domain /usr/sbin/tomoyo-editpolicy from any'
echo 'initialize_domain /usr/sbin/tomoyo-setlevel from any'
echo 'initialize_domain /usr/sbin/tomoyo-setprofile from any'
echo 'initialize_domain /usr/sbin/tomoyo-queryd from any'
) >> /etc/tomoyo/policy/current/exception_policy.conf

umount -l /dev/pts/
umount -l /sys/
umount -l /proc/

echo "********** Done. **********"
exit 0
