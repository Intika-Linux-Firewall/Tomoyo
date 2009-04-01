#! /bin/sh
#
# This is kernel build script for debian lenny's 2.6.26 kernel.
#

die () {
    echo $1
    exit 1
}

export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget
for key in 19A42D19 9B441EA8
do
  gpg --list-keys $key 2> /dev/null > /dev/null || wget -O - 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x'$key | gpg --import || die "Can't import PGP key."
done

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.7-20090401.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.7-20090401.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-2.6.26-1-686 || die "Can't install packages."
apt-get source linux-image-2.6.26-1-686 || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-2.6-2.6.26 || die "Can't chdir to linux-2.6-2.6.26/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.7-20090401.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.26-debian-lenny.diff || die "Can't apply patch."
cat /boot/config-2.6.26-1-686 config.ccs > .config || die "Can't create config."
yes | make -s oldconfig > /dev/null

# Start compilation.
REVISION=`head -n 1 debian/changelog | awk ' { print $2 } ' | awk -F'(' ' { print $2 } ' |  awk -F')' ' { print $1 } '`
make-kpkg --append-to-version -1-686-ccs --arch i386 --subarch i686 --arch-in-name --initrd --revision $REVISION linux-image || die "Failed to build kernel package."

exit 0
