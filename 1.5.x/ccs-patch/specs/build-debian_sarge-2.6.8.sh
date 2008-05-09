#! /bin/sh
#
# This is kernel build script for debian sarge's 2.6.8 kernel.
#

die () {
    echo $1
    exit 1
}

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get install kernel-source-2.6.8 || die "Can't install packages."
apt-get install kernel-patch-debian-2.6.8 || die "Can't install packages."
apt-get build-dep kernel-image-2.6.8-4-686-smp || die "Can't install packages."
apt-get source kernel-image-2.6.8-4-686-smp || die "Can't install kernel source."

# Download TOMOYO Linux patches.
cd kernel-image-2.6.8-i386-2.6.8/ || die "Can't chdir to kernel-image-2.6.8-i386-2.6.8/ ."
wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.1-20080510.tar.gz || die "Can't download patch."

# Apply patches and create kernel config.
tar -zxf ccs-patch-1.6.1-20080510.tar.gz ./config.ccs || die "Can't extract patch."
cat config/686-smp config.ccs > config/686-smp-ccs || die "Can't create config."
debian/rules flavours=686-smp-ccs || die "Can't run rules."
cd build-686-smp-ccs/ || die "Can't chdir to build-686-smp-ccs/ ."
tar -zxf ../ccs-patch-1.6.1-20080510.tar.gz || die "Can't extract patch."
cp -p Makefile Makefile.tmp || die "Can't create backup."
patch -p1 < patches/ccs-patch-2.6.8-17sarge1.diff || die "Can't apply patch."
mv -f Makefile.tmp Makefile || die "Can't restore."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686-smp") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control | sed -e 's:-686-smp:-686-smp-ccs:g' > debian/control.tmp || die "Can't create file."
cat debian/control.tmp >> debian/control || die "Can't edit file."
cd .. || die "Can't chdir to ../ ."

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."
debian/rules binary-arch flavours=686-smp-ccs || die "Failed to build kernel package."

exit 0
