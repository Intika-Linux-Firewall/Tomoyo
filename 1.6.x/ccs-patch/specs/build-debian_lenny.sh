#! /bin/sh
#
# This is kernel build script for debian lenny's 2.6.25 kernel.
#

die () {
    echo $1
    exit 1
}

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.3-20080715.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.3-20080715.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x19A42D19 ' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x9B441EA8 '| gpg --import || die "Can't import PGP key."
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-2.6.25-2-686 || die "Can't install packages."
apt-get source linux-image-2.6.25-2-686 || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-2.6-2.6.25 || die "Can't chdir to linux-2.6-2.6.25/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.3-20080715.tar.gz || die "Can't extract patch."
cp -p Makefile Makefile.tmp || die "Can't create backup."
patch -p1 < patches/ccs-patch-2.6.25.diff || die "Can't apply patch."
mv -f Makefile.tmp Makefile || die "Can't restore."
cat /boot/config-2.6.25-2-686 config.ccs > .config || die "Can't create config."
sed -i -e 's:CONFIG_XEN=y:# CONFIG_XEN is not set:' -- .config
yes | make -s oldconfig > /dev/null

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."
make-kpkg --append-to-version -2-686-ccs --arch i386 --subarch i686 --arch-in-name --initrd linux-image || die "Failed to build kernel package."

exit 0
