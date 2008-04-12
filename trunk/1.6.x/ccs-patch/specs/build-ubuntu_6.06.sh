#! /bin/sh
#
# This is kernel build script for ubuntu 6.06's 2.6.15 kernel.
#

# Install kernel source packages.
cd /usr/src/
apt-get install linux-kernel-devel fakeroot build-essential
apt-get build-dep linux-image-2.6.15-51-686
apt-get source linux-image-2.6.15-51-686
apt-get build-dep linux-restricted-modules-2.6.15-51-686
apt-get source linux-restricted-modules-2.6.15-51-686

# Download TOMOYO Linux patches.
cd linux-source-2.6.15-2.6.15/
wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.0-20080401.tar.gz

# Apply patches and create kernel config.
tar -zxf ccs-patch-1.6.0-20080401.tar.gz
patch -p1 < patches/ccs-patch-2.6.15.7-ubuntu1.diff
cat debian/config/i386/config.686 config.ccs > debian/config/i386/config.686-ccs
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686") > 0) { flag = 1; $2 = $2 "-ccs"; } else flag = 0; }; if (flag) print $0; } ' debian/control.stub > debian/control.stub.tmp
cat debian/control.stub.tmp >> debian/control.stub
cat debian/control.stub.tmp >> debian/control
chmod +x debian/post-install
chmod -R +x debian/bin/

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo`
debian/rules binary-debs flavours=686-ccs

# Install header package for compiling additional modules.
dpkg -i debian/build/linux-headers-2.6.15-51*.deb
ln -sf asm-i386 /usr/src/linux-headers-2.6.15-51-686-ccs/include/asm
cd /usr/src/linux-restricted-modules-2.6.15-2.6.15.12/
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-686:-686-ccs:g' > debian/control.stub.in.tmp
cat debian/control.stub.in.tmp >> debian/control.stub.in
debian/rules debian/control
debian/rules binary
