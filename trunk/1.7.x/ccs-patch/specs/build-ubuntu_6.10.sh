#! /bin/sh
#
# This is kernel build script for ubuntu 6.10's 2.6.17 kernel.
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
if [ ! -r ccs-patch-1.7.1-20091111.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/43375/ccs-patch-1.7.1-20091111.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-1.7.1-20091219.tar.gz ]
then
    mkdir -p ccs-patch.tmp || die "Can't create directory."
    cd ccs-patch.tmp/ || die "Can't change directory."
    wget -O hotfix.patch 'http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.7.x/ccs-patch/patches/hotfix.patch?revision=3273&root=tomoyo' || die "Can't download hotfix."
    tar -zxf ../ccs-patch-1.7.1-20091111.tar.gz || die "Can't extract tar ball."
    patch -p1 < hotfix.patch || die "Can't apply hotfix."
    rm -f hotfix.patch || die "Can't delete hotfix."
    tar -zcf ../ccs-patch-1.7.1-20091219.tar.gz -- * || die "Can't create tar ball."
    cd ../ || die "Can't change directory."
    rm -fR ccs-patch.tmp  || die "Can't delete directory."
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
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.7.1-20091219.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.17-ubuntu-6.10.diff || die "Can't apply patch."
cat debian/config/i386/config.generic config.ccs > debian/config/i386/config.generic-ccs || die "Can't create config."
cat debian/config/vars.generic > debian/config/i386/vars.generic-ccs || die "Can't create file."
chmod +x debian/post-install || die "Can't chmod post-install ."
chmod -R +x debian/bin/ || die "Can't chmod debian/bin/ ."

# Start compilation.
debian/rules binary-debs flavours=generic-ccs || die "Failed to build kernel package."
cd debian/build/
update_linux_26_header_package linux-headers-${VERSION}_*.deb linux-headers-*-ccs*.deb  || die "Can't update package."
cd ../../

# Install header package for compiling additional modules.
dpkg -i debian/build/linux-headers-*-ccs*.deb || die "Can't install packages."
cd /usr/src/linux-restricted-modules-2.6.17-2.6.17.9/ || die "Can't chdir to /usr/src/linux-restricted-modules-2.6.17-2.6.17.9/ ."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-generic:-generic-ccs:g' > debian/control.stub.in.tmp || die "Can't create file."
cat debian/control.stub.in.tmp >> debian/control.stub.in || die "Can't edit file."
sed -i -e 's/,generic/,generic-ccs generic/' debian/rules || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
debian/rules binary flavours="${VERSION}-386 ${VERSION}-generic-ccs" || die "Failed to build kernel package."

exit 0
