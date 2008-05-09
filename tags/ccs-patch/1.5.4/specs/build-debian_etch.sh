#! /bin/sh
#
# This is kernel build script for debian etch's 2.6.18 kernel.
#

die () {
    echo $1
    exit 1
}

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-2.6.18-6-686 || die "Can't install packages."
apt-get source linux-image-2.6.18-6-686 || die "Can't install kernel source."

# Download TOMOYO Linux patches.
cd linux-2.6-2.6.18.dfsg.1 || die "Can't chdir to linux-2.6-2.6.18.dfsg.1/ ."
# wget http://osdn.dl.sourceforge.jp/tomoyo/27220/ccs-patch-1.5.4-20080510.tar.gz || die "Can't download patch."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.5.4-20080510.tar.gz || die "Can't extract patch."
cp -p Makefile Makefile.tmp || die "Can't create backup."
patch -p1 < patches/ccs-patch-2.6.18-18etch3.diff || die "Can't apply patch."
mv -f Makefile.tmp Makefile || die "Can't restore."
cat /boot/config-2.6.18-6-686 config.ccs > .config || die "Can't create config."
yes | make -s oldconfig > /dev/null

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."
make-kpkg --append-to-version -6-686-ccs --subarch i686 --arch-in-name --initrd linux-image || die "Failed to build kernel package."

exit 0
