#! /bin/sh
#
# This is kernel build script for debian sarge's 2.6.8 kernel.
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

export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.8-20100120.tar.gz ]
then
    wget http://sourceforge.jp/frs/redir.php?f=/tomoyo/30297/ccs-patch-1.6.8-20100120.tar.gz || die "Can't download patch."
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
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.8-20100120.tar.gz config.ccs || die "Can't extract patch."
cat config/686-smp config.ccs > config/686-smp-ccs || die "Can't create config."
cat config.ccs >> config/default || die "Can't create config."
rm -f config.ccs
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-686-smp") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control | sed -e 's:-686-smp:-686-smp-ccs:g' > debian/control.tmp || die "Can't create file."
cat debian/control.tmp >> debian/control || die "Can't edit file."
debian/rules flavours=686-smp-ccs || die "Can't run rules."
for i in build-686-smp-ccs kernel-source-2.6.8
  do
  cd $i/ || die "Can't chdir to $i/ ."
  tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.8-20100120.tar.gz || die "Can't extract patch."
  patch -p1 < patches/ccs-patch-2.6.8-debian-sarge.diff || die "Can't apply patch."
  rm -fR patches/ specs/
  cd .. || die "Can't chdir to ../ ."
done

# Start compilation.
debian/rules binary-arch flavours=686-smp-ccs || die "Failed to build kernel package."

cd .. || die "Can't chdir to ../ ."
update_linux_26_header_package kernel-headers-2.6.8-4_2.6.8-17sarge1_i386.deb kernel-headers-2.6.8-4-686-smp-ccs_2.6.8-17sarge1_i386.deb

exit 0
