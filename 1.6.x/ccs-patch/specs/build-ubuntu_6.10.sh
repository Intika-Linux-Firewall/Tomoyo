#! /bin/sh
#
# This is kernel build script for ubuntu 6.10's 2.6.17 kernel.
#

# Install kernel source packages.
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x17063E6D ' | gpg --import
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x63549F8E ' | gpg --import
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x174BF01A ' | gpg --import
cd /usr/src/
apt-get install linux-kernel-devel fakeroot build-essential
apt-get build-dep linux-image-2.6.17-12-generic
apt-get source linux-image-2.6.17-12-generic
apt-get build-dep linux-restricted-modules-2.6.17-12-generic
apt-get source linux-restricted-modules-2.6.17-12-generic

# Download TOMOYO Linux patches.
cd linux-source-2.6.17-2.6.17.1/
wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.0-20080401.tar.gz

# Apply patches and create kernel config.
tar -zxf ccs-patch-1.6.0-20080401.tar.gz
patch -p1 < patches/ccs-patch-2.6.17.14-ubuntu1.diff
cat debian/config/i386/config.generic config.ccs > debian/config/i386/config.generic-ccs
cat debian/config/vars.generic > debian/config/i386/vars.generic-ccs
chmod +x debian/post-install
chmod -R +x debian/bin/

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo`
debian/rules binary-debs flavours=generic-ccs

# Install header package for compiling additional modules.
dpkg -i debian/build/linux-headers-2.6.17-12*.deb
cd /usr/src/linux-restricted-modules-2.6.17-2.6.17.9/
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-generic:-generic-ccs:g' > debian/control.stub.in.tmp
cat debian/control.stub.in.tmp >> debian/control.stub.in
sed -i -e 's/,generic/,generic-ccs generic/' debian/rules
debian/rules debian/control
debian/rules binary
