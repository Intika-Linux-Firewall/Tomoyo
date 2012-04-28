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
grep -qF tomoyo.sourceforge.jp /sources.list || echo 'deb http://tomoyo.sourceforge.jp/repos-1.8/Ubuntu12.04/ ./' >> /sources.list
apt-get -y -o Dir::Etc::SourceList=/sources.list update || die "apt-get update failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list install linux-generic-pae-ccs linux-headers-generic-pae-ccs ccs-tools || die "Can't install packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list purge linux-image-3.2.0-23-generic linux-image-generic linux-headers-generic linux-generic || die "Can't uninstall packages."
apt-get -y -o Dir::Etc::SourceList=/sources.list upgrade || die "apt-get upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list dist-upgrade || die "apt-get dist-upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list autoremove
apt-get -y -o Dir::Etc::SourceList=/sources.list clean

/usr/lib/ccs/init_policy

wget http://osdn.dl.sourceforge.jp/tomoyo/55680/tomoyo-tools_2.5.0-3_i386.deb
echo '063aa57e372bfa78ac7c83594bdfc77c  tomoyo-tools_2.5.0-3_i386.deb' | md5sum -c - || rm -f tomoyo-tools_2.5.0-3_i386.deb
dpkg -i tomoyo-tools_2.5.0-3_i386.deb
rm -f tomoyo-tools_2.5.0-3_i386.deb
/usr/lib/tomoyo/init_policy

umount -l /lib/init/rw/
umount -l /var/lock/
umount -l /var/run/
umount -l /dev/shm/
umount -l /dev/pts/
umount -l /sys/
umount -l /proc/

echo "********** Done. **********"
exit 0
