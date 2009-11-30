#!/bin/sh

REMOVED_VERSIONS="2.6.31-14 2.6.31-15"
INSTALL_VERSION="2.6.31-15"

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

apt-get -y -o Dir::Etc::SourceList=/sources.list.riken update || die "apt-get update failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list.riken upgrade || die "apt-get upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list.riken dist-upgrade || die "apt-get dist-upgrade failed. Try again later."

apt-get -y -o Dir::Etc::SourceList=/sources.list.riken install linux-headers-${INSTALL_VERSION}

dpkg -i /*.deb

for VER in ${REMOVED_VERSIONS}; do
    apt-get -y purge linux-image-${VER}-generic linux-headers-${VER}
done
apt-get -y purge linux-image-generic linux-headers-generic linux-generic

apt-get -y -o Dir::Etc::SourceList=/sources.list.riken autoremove
apt-get -y -o Dir::Etc::SourceList=/sources.list.riken clean

depmod ${INSTALL_VERSION}-ccs

/usr/lib/ccs/init_policy

umount -l /lib/init/rw/
umount -l /var/lock/
umount -l /var/run/
umount -l /dev/shm/
umount -l /dev/pts/
umount /sys/
umount /proc/

echo "********** Done. **********"
exit 0
