#! /bin/sh
#
# This is kernel build script for debian lenny's 2.6.24 kernel.
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

# Get workaround patch for gcc-4.3's compilation error.
if [ ! -r linux-2.6-compile-fix-gcc-43.patch ]
then
    wget -O linux-2.6-compile-fix-gcc-43.patch 'http://cvs.fedora.redhat.com/viewcvs/*checkout*/devel/kernel/linux-2.6-compile-fix-gcc-43.patch?rev=1.3'
fi

# Install kernel source packages.
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x19A42D19 ' | gpg --import || die "Can't import PGP key."
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-2.6.24-1-686 || die "Can't install packages."
apt-get source linux-image-2.6.24-1-686 || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-2.6-2.6.24 || die "Can't chdir to linux-2.6-2.6.24/ ."
patch -p1 < /usr/src/rpm/SOURCES/linux-2.6-compile-fix-gcc-43.patch || die "Can't apply patch."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.3-20080715.tar.gz || die "Can't extract patch."
cp -p Makefile Makefile.tmp || die "Can't create backup."
patch -p1 < patches/ccs-patch-2.6.24-4lenny.diff || die "Can't apply patch."
mv -f Makefile.tmp Makefile || die "Can't restore."
cat /boot/config-2.6.24-1-686 config.ccs > .config || die "Can't create config."
yes | make -s oldconfig > /dev/null

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."
make-kpkg --append-to-version -1-686-ccs --subarch i686 --arch-in-name --initrd linux-image || die "Failed to build kernel package."

exit 0
