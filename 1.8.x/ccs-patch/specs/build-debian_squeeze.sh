#! /bin/sh
#
# This is kernel build script for debian squeeze's 2.6.32 kernel.
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
    sed -i -e 's:-686:-686-ccs:' -- tmp/DEBIAN/md5sums tmp/DEBIAN/control
    dpkg-deb -b tmp && mv tmp.deb $2
    rm -fR tmp
}

export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget zlib1g-dev debian-keyring

# Download TOMOYO Linux patches.
mkdir -p /root/rpmbuild/SOURCES/
cd /root/rpmbuild/SOURCES/ || die "Can't chdir to /root/rpmbuild/SOURCES/ ."
if [ ! -r ccs-patch-1.8.1-20110401.tar.gz ]
then
    wget -O ccs-patch-1.8.1-20110401.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.1-20110401.tar.gz' || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-2.6.32-5-686 || die "Can't install packages."
apt-get source linux-image-2.6.32-5-686 || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-2.6-2.6.32 || die "Can't chdir to linux-2.6-2.6.32/ ."
debian/rules
cd debian/build/source_i386_none/ || die "Can't change directory"
tar -zxf /root/rpmbuild/SOURCES/ccs-patch-1.8.1-20110401.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.32-debian-squeeze.diff || die "Can't apply patch."
cd ../../../ || die "Can't change directory"
patch -p1 << EOF || die "Can't apply patch."
--- linux-2.6-2.6.32.orig/debian/config/i386/defines
+++ linux-2.6-2.6.32/debian/config/i386/defines
@@ -4,14 +4,8 @@
 
 [base]
 featuresets:
- openvz
- vserver
- xen
 flavours:
- 486
- 686
- 686-bigmem
- amd64
+ 686-ccs
 kernel-arch: x86
 
 [image]
@@ -27,11 +21,11 @@
 configs:
  kernelarch-x86/config-arch-32
 
-[686_description]
+[686-ccs_description]
 hardware: modern PCs
 hardware-long: PCs with Intel Pentium Pro/II/III/4/4M/D/M, Xeon, Celeron, Core or Atom; AMD Geode LX/NX, Athlon (K7), Duron, Opteron, Sempron, Turion or Phenom; Transmeta Efficeon; VIA C3 "Nehemiah" or C7 processors
 
-[686_image]
+[686-ccs_image]
 configs:
  kernelarch-x86/config-arch-32
 recommends: libc6-i686
EOF
debian/rules debian/control || /bin/true
debian/rules binary-arch || die "Can't build packages."

# Generate meta packages.
wget http://ftp.jp.debian.org/debian/pool/main/l/linux-latest-2.6/linux-image-2.6-686_2.6.32+29_i386.deb
generate_meta_package linux-image-2.6-686_2.6.32+29_i386.deb linux-image-2.6-686-ccs_2.6.32+29_i386.deb

exit 0
