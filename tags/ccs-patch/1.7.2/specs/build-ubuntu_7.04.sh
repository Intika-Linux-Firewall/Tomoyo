#! /bin/sh
#
# This is kernel build script for ubuntu 7.04's 2.6.20 kernel.
#

die () {
    echo $1
    exit 1
}

update_linux_26_header_package() {
    [ -r $1 ] || die "Can't find $1 ."
    [ -r $2 ] || die "Can't find $2 ."
    dpkg-deb -x $1 old
    dpkg-deb -x $2 new
    dpkg-deb -e $2 new/DEBIAN
    for i in sched.h init_task.h ccsecurity.h ccsecurity_vfs.h
      do
      rm -f new/usr/src/*/include/linux/$i
      cp -p old/usr/src/*/include/linux/$i new/usr/src/*/include/linux/
    done
    rm -f new/usr/src/*/security
    (cd old/usr/src/*/ ; tar -cf - security/ ) | ( cd new/usr/src/*/ ; tar -xf - )
    dpkg-deb -b new
    rm -fR new old
    mv new.deb $2
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
if [ ! -r ccs-patch-1.7.2-20100401.tar.gz ]
then
    wget http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20100401.tar.gz || die "Can't download patch."
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
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.7.2-20100401.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.20-ubuntu-7.04.diff || die "Can't apply patch."
for i in `find debian/ -type f -name '*generic*'`; do cp -p $i `echo $i | sed -e 's/generic/ccs/g'`; done
for i in debian/config/*/config; do cat config.ccs >> $i; done
touch debian/control.stub.in || die "Can't touch control."
debian/rules debian/control || die "Can't update control."
touch debian/abi/i386.ignore || die "Can't create file."

# Start compilation.
debian/rules binary-debs flavours=ccs || die "Failed to build kernel package."
cd debian/build/
update_linux_26_header_package linux-headers-${VERSION}_*.deb linux-headers-*-ccs*.deb  || die "Can't update package."
cd ../../

# Install header package for compiling additional modules.
dpkg -i debian/build/linux-headers-*-ccs*.deb || die "Can't install packages."
cd /usr/src/linux-restricted-modules-2.6.20-2.6.20.6/ || die "Can't chdir to /usr/src/linux-restricted-modules-2.6.20-2.6.20.6/ ."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-generic:-ccs:g' > debian/control.stub.in.tmp || die "Can't create file."
cat debian/control.stub.in.tmp >> debian/control.stub.in || die "Can't edit file."
sed -i -e 's/,generic/,ccs generic/' debian/rules || die "Can't edit file."
grep generic debian/d-i/kernel-versions.in | sed -e 's/generic/ccs/g' >> debian/d-i/kernel-versions.in.tmp || die "Can't create file."
cat debian/d-i/kernel-versions.in.tmp >> debian/d-i/kernel-versions.in || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
debian/rules binary flavours="${VERSION}-386 ${VERSION}-generic ${VERSION}-ccs" || die "Failed to build kernel package."

# Generate meta packages.
cd /usr/src/
rm -fR linux-meta-2.6.20.17.30/
apt-get source linux-meta
cd linux-meta-2.6.20.17.30/
sed -i -e 's/generic/ccs/g' -- debian/control
sed -i -e 's/ccs-depends/generic-depends/g' -- debian/control
debian/rules binary-arch
cd ../
rm -fR linux-meta-2.6.20.17.30/

exit 0
