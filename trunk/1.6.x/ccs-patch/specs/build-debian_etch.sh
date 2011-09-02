#! /bin/sh
#
# This is kernel build script for debian etch's 2.6.18 kernel.
#

die () {
    echo $1
    exit 1
}

generate_meta_package() {
    [ -r $1 ] || die "Can't find $1 ."
    dpkg-deb -x $1 tmp
    dpkg-deb -e $1 tmp/DEBIAN
    dir=`echo -n tmp/usr/share/doc/*`
    mv ${dir} ${dir}-ccs
    sed -i -e 's:-686:-686-ccs:' -- tmp/DEBIAN/md5sums tmp/DEBIAN/control
    dpkg-deb -b tmp && mv tmp.deb $2
    rm -fR tmp
}

export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.9-20110903.tar.gz ]
then
    wget -O ccs-patch-1.6.9-20110903.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/30297/ccs-patch-1.6.9-20110903.tar.gz' || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install build-essential kernel-package || die "Can't install packages."
apt-get install linux-source-2.6.18 || die "Can't install kernel source."
rm -fR linux-source-2.6.18
tar -jxf linux-source-2.6.18.tar.bz2

# Apply patches and create kernel config.
cd linux-source-2.6.18 || die "Can't chdir to linux-source-2.6.18/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.9-20110903.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.18-debian-etch.diff || die "Can't apply patch."
cat /boot/config-2.6.18-6-686 config.ccs > .config || die "Can't create config."

# Start compilation.
make-kpkg --append-to-version -6-686-ccs --revision `cat version.Debian` --initrd binary-arch || die "Failed to build kernel package."

# Generate meta packages.
wget http://archive.debian.org/debian/pool/main/l/linux-latest-2.6/linux-image-2.6-686_2.6.18+6etch3_i386.deb
generate_meta_package linux-image-2.6-686_2.6.18+6etch3_i386.deb linux-image-2.6-686-ccs_2.6.18+6etch3_i386.deb

exit 0
