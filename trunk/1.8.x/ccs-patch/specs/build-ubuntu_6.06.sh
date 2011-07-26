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
    for i in sched.h init_task.h security.h ccsecurity.h
      do
      rm -f new/usr/src/*/include/linux/$i
      cp -p old/usr/src/*/include/linux/$i new/usr/src/*/include/linux/
    done
    rm -f new/usr/src/*/security
    tar -cf - -C old/usr/src/*/ security/ | tar -xf - -C new/usr/src/*/
    dpkg-deb -b new && mv new.deb $2
    rm -fR new old
}

#VERSION=`uname -r | cut -d - -f 1,2`
VERSION=`apt-cache search ^linux-image-2.6.15-..- | cut -b 13-21 | awk ' { print $1 }' | sort -r | uniq | head -n 1`
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.8.2-20110726.tar.gz ]
then
    wget -O ccs-patch-1.8.2-20110726.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.2-20110726.tar.gz' || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get -y install linux-kernel-devel fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-686 || die "Can't install packages."
apt-get source linux-image-${VERSION}-686 || die "Can't install kernel source."
apt-get build-dep linux-restricted-modules-${VERSION}-686 || die "Can't install packages."
apt-get source linux-restricted-modules-${VERSION}-686 || die "Can't install kernel source."
for i in `awk ' { if ( $1 != "Build-Depends:") next; $1 = ""; n = split($0, a, ","); for (i = 1; i <= n; i++) { split(a[i], b, " "); print b[1]; } } ' linux-source-2.6.15-2.6.15/debian/control`; do apt-get -y install $i; done

# Apply patches and create kernel config.
cd linux-source-2.6.15-2.6.15/ || die "Can't chdir to linux-source-2.6.15-2.6.15/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.8.2-20110726.tar.gz || die "Can't extract patch."
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

# Generate meta packages.
cd /usr/src/
rm -fR linux-meta-*/
apt-get source linux-meta
cd linux-meta-*/
sed -i -e 's/686/686-ccs/g' -- debian/control
debian/rules binary-arch
cd ../
rm -fR linux-meta-*/

exit 0
