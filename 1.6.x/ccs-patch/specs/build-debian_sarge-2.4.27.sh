#! /bin/sh
#
# This is kernel build script for debian sarge's 2.4.27 kernel.
#

# Install kernel source packages.
cd /usr/src/
apt-get install fakeroot build-essential
apt-get install kernel-source-2.4.27
apt-get install kernel-patch-debian-2.4.27
apt-get build-dep kernel-image-2.4.27-4-686-smp
apt-get source kernel-image-2.4.27-4-686-smp

# Download TOMOYO Linux patches.
cd kernel-image-2.4.27-i386-2.4.27/
wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.0-20080401.tar.gz

# Apply patches and create kernel config.
tar -zxf ccs-patch-1.6.0-20080401.tar.gz ./config.ccs
cat config/686-smp config.ccs > config/686-smp-ccs
debian/rules flavours=686-smp-ccs
cd build-686-smp-ccs/
tar -zxf ../ccs-patch-1.6.0-20080401.tar.gz
cp -p Makefile Makefile.tmp
patch -p1 < patches/ccs-patch-2.4.27-10sarge7.diff
mv -f Makefile.tmp Makefile
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686-smp") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control | sed -e 's:-686-smp:-686-smp-ccs:g' > debian/control.tmp
cat debian/control.tmp >> debian/control
cd ..

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo`
debian/rules binary-arch flavours=686-smp-ccs
