#! /bin/sh
#
# This is kernel build script for ubuntu 7.10's 2.6.22 kernel.
#

# Install kernel source packages.
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x191FCD8A ' | gpg --import
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x60E80B5B ' | gpg --import
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x174BF01A ' | gpg --import
cd /usr/src/
apt-get install linux-kernel-devel fakeroot build-essential
apt-get build-dep linux-image-2.6.22-14-generic
apt-get source linux-image-2.6.22-14-generic
apt-get install linux-headers-2.6.22-14
apt-get build-dep linux-ubuntu-modules-2.6.22-14-generic
apt-get source linux-ubuntu-modules-2.6.22-14-generic

# Download TOMOYO Linux patches.
cd linux-source-2.6.22-2.6.22/
wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.0-20080401.tar.gz
tar -zxf ccs-patch-1.6.0-20080401.tar.gz

# Copy patches and create kernel config.
mkdir -p debian/binary-custom.d/ccs/patchset
cp -p patches/ccs-patch-2.6.22.9-ubuntu1.diff debian/binary-custom.d/ccs/patchset/ubuntu-7.10.patch
cd debian/binary-custom.d/ccs/
cat ../../config/i386/config ../../config/i386/config.generic ../../../config.ccs > config.i386
sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- config.i386
touch rules
cd ../../../
awk ' BEGIN { flag = 0; print ""; } { if ($1 == "Package:" ) { if (index($0, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub | sed -e 's:-generic:-ccs:' > debian/control.stub.ccs
cat debian/control.stub.ccs >> debian/control.stub
debian/rules debian/control

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo`
debian/rules custom-binary-ccs
cd ..

# Install header package for compiling additional modules.
dpkg -i linux-headers-2.6.22-14-ccs_2.6.22-14.*_i386.deb
cd linux-ubuntu-modules-2.6.22-2.6.22
awk ' BEGIN { flag = 0; print ""; } { if ($1 == "Package:" ) { if (index($0, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub | sed -e 's:-generic:-ccs:' > debian/control.stub.ccs
cat debian/control.stub.ccs >> debian/control.stub
debian/rules debian/control
sed -i -e 's:virtual:virtual ccs:' debian/rules.d/i386.mk
debian/rules binary-indep binary-arch
