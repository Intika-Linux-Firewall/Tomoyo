#! /bin/sh
#
# This is kernel build script for ubuntu 8.10's 2.6.27 kernel.
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
  gpg --list-keys $key 2> /dev/null > /dev/null || wget -O - 'http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x'$key | gpg --import || die "Can't import PGP key."
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
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-generic || die "Can't install packages."
apt-get source linux-image-${VERSION}-generic || die "Can't install kernel source."
apt-get install linux-headers-${VERSION} || die "Can't install packages."
apt-get build-dep linux-restricted-modules-${VERSION}-generic || die "Can't install packages."
apt-get source linux-restricted-modules-${VERSION}-generic || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-2.6.27/ || die "Can't chdir to linux-2.6.27/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.6.4-20080903.tar.gz || die "Can't extract patch."
patch -p1 <<EOF || die "Can't apply patch."
diff -urp 1.6.4/fs/tomoyo_cond.c 1.6.4-hotfix/fs/tomoyo_cond.c
--- 1.6.4/fs/tomoyo_cond.c	2008-09-03 00:00:00.000000000 +0900
+++ 1.6.4-hotfix/fs/tomoyo_cond.c	2008-10-14 16:38:51.000000000 +0900
@@ -1031,8 +1031,8 @@ bool ccs_check_condition(const struct ac
 		const u8 left = header >> 8;
 		const u8 right = header;
 		ptr++;
-		if ((left >= PATH1_UID && left < MAX_KEYWORD) ||
-		    (right >= PATH1_UID && right < MAX_KEYWORD)) {
+		if ((left >= PATH1_UID && left < EXEC_ARGC) ||
+		    (right >= PATH1_UID && right < EXEC_ARGC)) {
 			if (!obj)
 				goto out;
 			if (!obj->validate_done) {
EOF
patch -p1 < patches/ccs-patch-2.6.27-ubuntu-8.10.diff || die "Can't apply patch."
for i in `find debian/ -type f -name '*generic*'`; do cp -p $i `echo $i | sed -e 's/generic/ccs/g'`; done
for i in debian/config/*/config.ccs; do cat config.ccs >> $i; done
touch debian/control.stub.in || die "Can't touch control."
debian/rules debian/control || die "Can't update control."
for i in debian/abi/2.6.27-*/*/ ; do touch $i/ccs.ignore; done

# Start compilation.
debian/rules binary-headers || die "Failed to build kernel package."
debian/rules binary-debs flavours=ccs || die "Failed to build kernel package."

# Install header package for compiling additional modules.
dpkg -i /usr/src/linux-headers-${VERSION}*.deb || die "Can't install packages."
cd /usr/src/linux-restricted-modules-2.6.27/ || die "Can't chdir to /usr/src/linux-restricted-modules-2.6.27/ ."
for i in `find debian/ -type f -name '*generic*'`; do cp -p $i `echo $i | sed -e 's/generic/ccs/g'`; done
touch debian/control.stub.in || die "Can't touch control."
debian/rules debian/control || die "Can't run control."
debian/rules binary-arch arch=i386 flavours=ccs || die "Failed to build kernel package."

exit 0
