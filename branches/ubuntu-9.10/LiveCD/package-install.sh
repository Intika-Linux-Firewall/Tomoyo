#!/bin/sh

REMOVED_VERSIONS="2.6.31-14 2.6.31-16"
INSTALL_VERSION="2.6.31-16"

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

apt-get -y -o Dir::Etc::SourceList=/sources.list update || die "apt-get update failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list upgrade || die "apt-get upgrade failed. Try again later."
apt-get -y -o Dir::Etc::SourceList=/sources.list dist-upgrade || die "apt-get dist-upgrade failed. Try again later."

apt-get -y -o Dir::Etc::SourceList=/sources.list install linux-headers-${INSTALL_VERSION}

dpkg -i /*.deb

for VER in ${REMOVED_VERSIONS}; do
    apt-get -y purge linux-image-${VER}-generic linux-headers-${VER}
done
apt-get -y purge linux-image-generic linux-headers-generic linux-generic

apt-get -y -o Dir::Etc::SourceList=/sources.list autoremove
apt-get -y -o Dir::Etc::SourceList=/sources.list clean

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
