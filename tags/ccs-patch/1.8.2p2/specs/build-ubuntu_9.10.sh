#! /bin/sh
#
# This is kernel build script for ubuntu 9.10's 2.6.31 kernel.
#

die () {
    echo $1
    exit 1
}

#VERSION=`uname -r | cut -d - -f 1,2`
VERSION=`apt-cache search ^linux-image-2.6.31-..- | cut -b 13-21 | awk ' { print $1 }' | sort -r | uniq | head -n 1`
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.8.2-20110713.tar.gz ]
then
    wget -O ccs-patch-1.8.2-20110713.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.2-20110713.tar.gz' || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get -y install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-generic || die "Can't install packages."
apt-get source linux-image-${VERSION}-generic || die "Can't install kernel source."
apt-get -y install linux-headers-${VERSION} || die "Can't install packages."
for i in `awk ' { if ( $1 != "Build-Depends:") next; $1 = ""; n = split($0, a, ","); for (i = 1; i <= n; i++) { split(a[i], b, " "); print b[1]; } } ' linux-2.6.31/debian/control`; do apt-get -y install $i; done

# Apply patches and create kernel config.
cd linux-2.6.31/ || die "Can't chdir to linux-2.6.31/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.8.2-20110713.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.31-ubuntu-9.10.diff || die "Can't apply patch."
rm -fR patches/ specs/ || die "Can't delete patch."
for i in `find debian.master/ -type f -name '*generic*'`; do cp -p $i `echo $i | sed -e 's/generic/ccs/g'`; done
for i in debian.master/config/*/config.common.*; do cat config.ccs >> $i; done
rm debian.master/control.stub || die "Can't delete control.stub."
make -f debian.master/rules debian.master/control.stub || die "Can't update control.stub."
rm debian/control || die "Can't delete control."
debian/rules debian/control || die "Can't update control."

# Make modified header files go into local header package.
patch -p0 << "EOF" || die "Can't patch link-headers."
--- debian.master/scripts/link-headers
+++ debian.master/scripts/link-headers
@@ -39,4 +39,17 @@
 done
 )
 
+if [ $flavour == "ccs" ]
+then
+    cd $hdrdir/../../../../$symdir/usr/src/$symdir/include/linux/
+    for i in sched.h init_task.h security.h ccsecurity.h
+    do
+	rm -f $hdrdir/include/linux/$i
+	cp -p $i $hdrdir/include/linux/
+    done
+    rm -f $hdrdir/security
+    cd ../../
+    tar -cf - security | tar -xf - -C $hdrdir
+fi
+
 exit
EOF

# Start compilation.
debian/rules binary-headers || die "Failed to build kernel package."
debian/rules binary-debs flavours=ccs || die "Failed to build kernel package."

# Generate meta packages.
cd /usr/src/
rm -fR linux-meta-*/
apt-get source linux-meta
cd linux-meta-*/
sed -e 's/generic/ccs/g' -- debian/control.d/generic > debian/ccs
rm -f debian/control.d/*
mv debian/ccs debian/control.d/ccs
debian/rules binary-arch
cd ../
rm -fR linux-meta-*/

exit 0
