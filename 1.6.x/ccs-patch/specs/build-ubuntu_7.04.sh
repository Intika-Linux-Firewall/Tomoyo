#! /bin/sh
#
# This is kernel build script for ubuntu 7.04's 2.6.20 kernel.
#

die () {
    echo $1
    exit 1
}

VERSION=`uname -r | cut -d - -f 1,2`
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget
for key in 0A0AC927 17063E6D 174BF01A 191FCD8A 60E80B5B 63549F8E 76682A37 8BF9EFE6
do
  gpg --list-keys $key 2> /dev/null > /dev/null || wget -O - 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x'$key | gpg --import || die "Can't import PGP key."
done

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.4-20080903.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.4-20080903.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install linux-kernel-devel fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-generic || die "Can't install packages."
apt-get source linux-image-${VERSION}-generic || die "Can't install packages."
apt-get build-dep linux-restricted-modules-${VERSION}-generic || die "Can't install packages."
apt-get source linux-restricted-modules-${VERSION}-generic || die "Can't install packages."

# Apply patches and create kernel config.
cd linux-source-2.6.20-2.6.20/ || die "Can't chdir to linux-2.6.20-2.6.20/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.4-20080903.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.20-ubuntu-7.04.diff || die "Can't apply patch."
for i in `find debian/ -type f -name '*generic*'`; do cp -p $i `echo $i | sed -e 's/generic/ccs/g'`; done
for i in debian/config/*/config.ccs; do cat config.ccs >> $i; done
touch debian/control.stub.in || die "Can't touch control."
debian/rules debian/control || die "Can't update control."
touch debian/abi/i386.ignore || die "Can't create file."

# Start compilation.
debian/rules binary-debs flavours=ccs || die "Failed to build kernel package."

# Install header package for compiling additional modules.
dpkg -i debian/build/linux-headers-${VERSION}*.deb || die "Can't install packages."
cd /usr/src/linux-restricted-modules-2.6.20-2.6.20.6/ || die "Can't chdir to /usr/src/linux-restricted-modules-2.6.20-2.6.20.6/ ."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-generic:-ccs:g' > debian/control.stub.in.tmp || die "Can't create file."
cat debian/control.stub.in.tmp >> debian/control.stub.in || die "Can't edit file."
sed -i -e 's/,generic/,ccs generic/' debian/rules || die "Can't edit file."
grep generic debian/d-i/kernel-versions.in | sed -e 's/generic/ccs/g' >> debian/d-i/kernel-versions.in.tmp || die "Can't create file."
cat debian/d-i/kernel-versions.in.tmp >> debian/d-i/kernel-versions.in || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
debian/rules binary || die "Failed to build kernel package."

exit 0
