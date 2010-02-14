#! /bin/sh
#
# This is kernel build script for debian sarge's 2.6.8 kernel.
#

die () {
    echo $1
    exit 1
}

generate_meta_package() {
    [ -r $1 ] || die "Can't find $1 ."
    dpkg-deb -x $1 tmp
    dpkg-deb -e $1 tmp/DEBIAN
    dir=`echo -n tmp/usr/share/doc/*`
    mv ${dir} ${dir}-ccs
    sed -i -e 's:-686-smp:-686-smp-ccs:' -- tmp/DEBIAN/md5sums
    sed -i -e 's:-686-smp:-686-smp-ccs:' -- tmp/DEBIAN/control
    dpkg-deb -b tmp
    rm -fR tmp
    mv tmp.deb $2
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

export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.7.1-20100214.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/43375/ccs-patch-1.7.1-20100214.tar.gz || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get install kernel-source-2.6.8 || die "Can't install packages."
apt-get install kernel-patch-debian-2.6.8 || die "Can't install packages."
apt-get build-dep kernel-image-2.6.8-4-686-smp || die "Can't install packages."
apt-get source kernel-image-2.6.8-4-686-smp || die "Can't install kernel source."

# Apply patches and create kernel config.
cd kernel-image-2.6.8-i386-2.6.8/ || die "Can't chdir to kernel-image-2.6.8-i386-2.6.8/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.7.1-20100214.tar.gz config.ccs || die "Can't extract patch."
cat config/686-smp config.ccs > config/686-smp-ccs || die "Can't create config."
cat config.ccs >> config/default || die "Can't create config."
rm -f config.ccs
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686-smp") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control | sed -e 's:-686-smp:-686-smp-ccs:g' > debian/control.tmp || die "Can't create file."
cat debian/control.tmp >> debian/control || die "Can't edit file."
debian/rules flavours=686-smp-ccs || die "Can't run rules."
for i in build-686-smp-ccs kernel-source-2.6.8
  do
  cd $i/ || die "Can't chdir to $i/ ."
  tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.7.1-20100214.tar.gz || die "Can't extract patch."
  patch -p1 < patches/ccs-patch-2.6.8-debian-sarge.diff || die "Can't apply patch."
  rm -fR patches/ specs/
  cd .. || die "Can't chdir to ../ ."
done

# Start compilation.
debian/rules binary-arch flavours=686-smp-ccs || die "Failed to build kernel package."

cd .. || die "Can't chdir to ../ ."
update_linux_26_header_package kernel-headers-2.6.8-4_2.6.8-17sarge1_i386.deb kernel-headers-2.6.8-4-686-smp-ccs_2.6.8-17sarge1_i386.deb

# Generate meta packages.
wget http://archive.debian.org/debian-security/pool/updates/main/k/kernel-latest-2.6-i386/kernel-image-2.6-686-smp_101sarge2_i386.deb
generate_meta_package kernel-image-2.6-686-smp_101sarge2_i386.deb kernel-image-2.6-686-smp-ccs_101sarge2_i386.deb
wget http://archive.debian.org/debian-security/pool/updates/main/k/kernel-latest-2.6-i386/kernel-headers-2.6-686-smp_101sarge2_i386.deb
generate_meta_package kernel-headers-2.6-686-smp_101sarge2_i386.deb kernel-headers-2.6-686-smp-ccs_101sarge2_i386.deb

exit 0
