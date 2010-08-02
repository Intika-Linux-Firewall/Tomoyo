#!/bin/sh

# set -v

export LANG=C

die () {
    echo '********** ' $1 ' **********'
    umount -l /lib/init/rw/
    umount -l /var/lock/
    umount -l /var/run/
    umount -l /dev/shm/
    umount -l /dev/pts/
    umount /sys/
    umount /proc/
    exit 1
}

mount -t proc none /proc/
mount -t sysfs none /sys/
mount -t devpts none /dev/pts/
mount -t tmpfs none /dev/shm/
mount -t tmpfs none /var/run/
mount -t tmpfs none /var/lock/
mount -t tmpfs none /lib/init/rw/

wget -O - http://I-love.SAKURA.ne.jp/kumaneko-key | apt-key add - || die "Can't install key."
echo 'deb http://osdn.dl.sourceforge.jp/tomoyo/47128/ ./' >> /etc/apt/sources.list
echo 'deb http://osdn.dl.sourceforge.jp/tomoyo/47128/ ./' >> /sources.list
apt-get -y -o Dir::Etc::SourceList=/sources.list update || die "apt-get update failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list install linux-ccs linux-headers-ccs ccs-tools || die "Can't install packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list purge linux-image-2.6.32-21-generic linux-headers-2.6.32-21 linux-image-generic linux-headers-generic linux-generic || die "Can't uninstall packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list upgrade || die "apt-get upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list dist-upgrade || die "apt-get dist-upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list autoremove
apt-get -y -o Dir::Etc::SourceList=/sources.list clean

/usr/lib/ccs/init_policy

wget http://osdn.dl.sourceforge.jp/tomoyo/47128/tomoyo-tools_2.2.0-2_i386.deb
dpkg -i tomoyo-tools_2.2.0-2_i386.deb
rm -f tomoyo-tools_2.2.0-2_i386.deb
/usr/lib/tomoyo/tomoyo_init_policy

umount -l /lib/init/rw/
umount -l /var/lock/
umount -l /var/run/
umount -l /dev/shm/
umount -l /dev/pts/
umount -l /sys/
umount -l /proc/

echo "********** Done. **********"
exit 0
