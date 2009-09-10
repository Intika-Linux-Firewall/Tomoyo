#! /bin/sh
#
# This is kernel build script for ubuntu 6.10's 2.6.17 kernel.
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
if [ ! -r ccs-patch-1.6.8-20090911.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.8-20090911.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install linux-kernel-devel fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-generic || die "Can't install packages."
apt-get source linux-image-${VERSION}-generic || die "Can't install kernel source."
apt-get build-dep linux-restricted-modules-${VERSION}-generic || die "Can't install packages."
apt-get source linux-restricted-modules-${VERSION}-generic || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-source-2.6.17-2.6.17.1/ || die "Can't chdir to linux-2.6.17-2.6.17.1/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.8-20090911.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.17-ubuntu-6.10.diff || die "Can't apply patch."
cat debian/config/i386/config.generic config.ccs > debian/config/i386/config.generic-ccs || die "Can't create config."
cat debian/config/vars.generic > debian/config/i386/vars.generic-ccs || die "Can't create file."
chmod +x debian/post-install || die "Can't chmod post-install ."
chmod -R +x debian/bin/ || die "Can't chmod debian/bin/ ."

# Start compilation.
debian/rules binary-debs flavours=generic-ccs || die "Failed to build kernel package."

# Install header package for compiling additional modules.
dpkg -i debian/build/linux-headers-${VERSION}*.deb || die "Can't install packages."
cd /usr/src/linux-restricted-modules-2.6.17-2.6.17.9/ || die "Can't chdir to /usr/src/linux-restricted-modules-2.6.17-2.6.17.9/ ."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-generic:-generic-ccs:g' > debian/control.stub.in.tmp || die "Can't create file."
cat debian/control.stub.in.tmp >> debian/control.stub.in || die "Can't edit file."
sed -i -e 's/,generic/,generic-ccs generic/' debian/rules || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
debian/rules binary || die "Failed to build kernel package."

exit 0
