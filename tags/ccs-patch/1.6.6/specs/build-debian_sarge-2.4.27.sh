#! /bin/sh
#
# This is kernel build script for debian sarge's 2.4.27 kernel.
#

die () {
    echo $1
    exit 1
}

export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.6-20090202.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.6-20090202.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get install kernel-source-2.4.27 || die "Can't install packages."
apt-get install kernel-patch-debian-2.4.27 || die "Can't install packages."
apt-get build-dep kernel-image-2.4.27-4-686-smp || die "Can't install packages."
apt-get source kernel-image-2.4.27-4-686-smp || die "Can't install kernel source."

# Apply patches and create kernel config.
cd kernel-image-2.4.27-i386-2.4.27/ || die "Can't chdir to kernel-image-2.4.27-i386-2.4.27/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.6-20090202.tar.gz config.ccs || die "Can't extract patch."
cat config/686-smp config.ccs > config/686-smp-ccs || die "Can't create config."
debian/rules flavours=686-smp-ccs || die "Can't run rules."
cd build-686-smp-ccs/ || die "Can't chdir to build-686-smp-ccs/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.6-20090202.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.4.27-debian-sarge.diff || die "Can't apply patch."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686-smp") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control | sed -e 's:-686-smp:-686-smp-ccs:g' > debian/control.tmp || die "Can't create file."
cat debian/control.tmp >> debian/control || die "Can't edit file."
cd .. || die "Can't chdir to ../ ."

# Start compilation.
debian/rules binary-arch flavours=686-smp-ccs || die "Failed to build kernel package."

exit 0
