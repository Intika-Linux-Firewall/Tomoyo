#! /bin/sh
#
# This is kernel build script for ubuntu 8.04's 2.6.24 kernel.
#

die () {
    echo $1
    exit 1
}

VERSION=`uname -r | cut -d - -f 1,2`

apt-get -y install wget
wget -O - 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x0A0AC927' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x17063E6D' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x174BF01A' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x191FCD8A' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x60E80B5B' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x63549F8E' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x76682A37' 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x8BF9EFE6' | gpg --import || die "Can't import PGP key."

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.3-20080715.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.3-20080715.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install linux-kernel-devel fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-generic || die "Can't install packages."
apt-get source linux-image-${VERSION}-generic || die "Can't install kernel source."
apt-get install linux-headers-${VERSION} || die "Can't install packages."
apt-get build-dep linux-ubuntu-modules-${VERSION}-generic || die "Can't install packages."
apt-get source linux-ubuntu-modules-${VERSION}-generic || die "Can't install kernel source."
apt-get build-dep linux-restricted-modules-${VERSION}-generic || die "Can't install packages."
apt-get source linux-restricted-modules-${VERSION}-generic || die "Can't install kernel source."

# Copy patches and create kernel config.
cd linux-2.6.24/ || die "Can't chdir to linux-2.6.24/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.3-20080715.tar.gz || die "Can't extract patch."
mkdir -p debian/binary-custom.d/ccs/patchset || die "Can't create debian/binary-custom.d/ccs/patchset ."
cp -p patches/ccs-patch-2.6.24.3-ubuntu1.diff debian/binary-custom.d/ccs/patchset/ubuntu-8.04.patch || die "Can't copy patch."
cd debian/binary-custom.d/ccs/ || die "Can't chdir to debian/binary-custom.d/ccs/ ."
cat ../../config/i386/config ../../config/i386/config.generic ../../../config.ccs > config.i386 || die "Can't create config."
sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- config.i386 || die "Can't edit config."
touch rules || die "Can't create file."
cd ../../../ || die "Can't chdir to ../../../ ."
awk ' BEGIN { flag = 0; print ""; } { if ($1 == "Package:" ) { if (index($0, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub | sed -e 's:-generic:-ccs:' > debian/control.stub.ccs || die "Can't create file."
cat debian/control.stub.ccs >> debian/control.stub || die "Can't edit file."
debian/rules debian/control || die "Can't run control."

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."
debian/rules custom-binary-ccs || die "Failed to build kernel package."
cd .. || die "Can't chdir to ../ ."

# Install header package for compiling additional modules.
dpkg -i linux-headers-${VERSION}-ccs_${VERSION}.*_i386.deb || die "Can't install packages."
cd linux-ubuntu-modules-2.6.24-2.6.24 || die "Can't chdir to linux-ubuntu-modules-2.6.24-2.6.24 ."
awk ' BEGIN { flag = 0; print ""; } { if ($1 == "Package:" ) { if (index($0, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub | sed -e 's:-generic:-ccs:' > debian/control.stub.ccs || die "Can't create file."
cat debian/control.stub.ccs >> debian/control.stub || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
sed -i -e 's:virtual:virtual ccs:' debian/rules.d/i386.mk || die "Can't edit file."
debian/rules binary-indep binary-arch || die "Failed to build kernel package."
cd .. || die "Can't chdir to ../ ."

cd linux-restricted-modules-2.6.24-2.6.24.13/ || die "Can't chdir to linux-restricted-modules-2.6.24-2.6.24.13/ ."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-generic:-ccs:g' > debian/control.stub.in.tmp || die "Can't create file."
cat debian/control.stub.in.tmp >> debian/control.stub.in || die "Can't edit file."
sed -i -e 's/,generic/,ccs generic/' debian/rules || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
debian/rules binary || die "Failed to build kernel package."

exit 0