#! /bin/sh
#
# This is kernel build script for ubuntu 6.06's 2.6.15 kernel.
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
    for i in sched.h init_task.h ccs_common.h ccs_compat.h ccs_proc.h realpath.h sakura.h syaoran.h tomoyo.h tomoyo_socket.h tomoyo_vfs.h
      do
      rm -f new/usr/src/*/include/linux/$i
      cp -p old/usr/src/*/include/linux/$i new/usr/src/*/include/linux/
    done
    rm -f new/usr/src/*/fs
    (cd old/usr/src/*/ ; tar -cf - fs/ ) | ( cd new/usr/src/*/ ; tar -xf - )
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
if [ ! -r ccs-patch-1.6.8-20100804.tar.gz ]
then
    wget http://sourceforge.jp/frs/redir.php?f=/tomoyo/30297/ccs-patch-1.6.8-20100804.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install linux-kernel-devel fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-686 || die "Can't install packages."
apt-get source linux-image-${VERSION}-686 || die "Can't install kernel source."
apt-get build-dep linux-restricted-modules-${VERSION}-686 || die "Can't install packages."
apt-get source linux-restricted-modules-${VERSION}-686 || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-source-2.6.15-2.6.15/ || die "Can't chdir to linux-source-2.6.15-2.6.15/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.8-20100804.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.15-ubuntu-6.06.diff || die "Can't apply patch."
cat debian/config/i386/config.686 config.ccs > debian/config/i386/config.686-ccs || die "Can't create config."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686") > 0) { flag = 1; $2 = $2 "-ccs"; } else flag = 0; }; if (flag) print $0; } ' debian/control.stub > debian/control.stub.tmp || die "Can't create file."
cat debian/control.stub.tmp >> debian/control.stub || die "Can't edit file."
cat debian/control.stub.tmp >> debian/control || die "Can't edit file."
chmod +x debian/post-install || die "Can't chmod post-install ."
chmod -R +x debian/bin/ || die "Can't chmod debian/bin/ ."

# Start compilation.
debian/rules binary-debs flavours=686-ccs || die "Failed to build kernel package."
cd debian/build/
update_linux_26_header_package linux-headers-${VERSION}_*.deb linux-headers-*-ccs*.deb  || die "Can't update package."
cd ../../

# Install header package for compiling additional modules.
dpkg -i debian/build/linux-headers-*-ccs*.deb || die "Can't install packages."
ln -sf asm-i386 /usr/src/linux-headers-${VERSION}-686-ccs/include/asm || die "Can't create symlink."
cd /usr/src/linux-restricted-modules-2.6.15-2.6.15.12/ || die "Can't chdir to /usr/src/linux-restricted-modules-2.6.15-2.6.15.12/ ."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-686:-686-ccs:g' > debian/control.stub.in.tmp || die "Can't create file."
cat debian/control.stub.in.tmp >> debian/control.stub.in || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
debian/rules binary flavours="${VERSION}-386 ${VERSION}-686-ccs" || die "Failed to build kernel package."

exit 0
