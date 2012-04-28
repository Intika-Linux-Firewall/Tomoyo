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

wget -O - http://I-love.SAKURA.ne.jp/kumaneko-key | apt-key add - || die "Can't install key."
grep -qF tomoyo.sourceforge.jp /sources.list || echo 'deb http://tomoyo.sourceforge.jp/repos-1.8/Ubuntu12.04/ ./' >> /sources.list
apt-get -y -o Dir::Etc::SourceList=/sources.list update || die "apt-get update failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list install linux-generic-pae-ccs linux-headers-generic-pae-ccs ccs-tools || die "Can't install packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list purge linux-image-3.2.0-23-generic-pae linux-image-generic-pae linux-headers-generic-pae linux-generic-pae || die "Can't uninstall packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list upgrade || die "apt-get upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list dist-upgrade || die "apt-get dist-upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list autoremove
apt-get -y -o Dir::Etc::SourceList=/sources.list clean

/usr/lib/ccs/init_policy

wget http://osdn.dl.sourceforge.jp/tomoyo/55680/tomoyo-tools_2.5.0-3_i386.deb
echo 'd94b61bedd65857fc71a51e5440256f0  tomoyo-tools_2.5.0-3_i386.deb' | md5sum -c - || rm -f tomoyo-tools_2.5.0-3_i386.deb
dpkg -i tomoyo-tools_2.5.0-3_i386.deb
rm -f tomoyo-tools_2.5.0-3_i386.deb
/usr/lib/tomoyo/init_policy

umount -l /dev/pts/
umount -l /sys/
umount -l /proc/

echo "********** Done. **********"
exit 0
