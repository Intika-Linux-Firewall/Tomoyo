#! /bin/sh
#
# This is kernel build script for debian lenny's 2.6.26 kernel.
#

die () {
    echo $1
    exit 1
}

export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget
for key in 19A42D19 9B441EA8
do
  gpg --list-keys $key 2> /dev/null > /dev/null || wget -O - 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x'$key | gpg --import || die "Can't import PGP key."
done

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.6.4-20080903.tar.gz ]
then
    wget http://osdn.dl.sourceforge.jp/tomoyo/30297/ccs-patch-1.6.4-20080903.tar.gz || die "Can't download patch."
fi

if [ ! -r ccs-patch-2.6.26-debian-lenny.diff ]
then
    wget -O ccs-patch-2.6.26-debian-lenny.diff 'http://svn.sourceforge.jp/cgi-bin/viewcvs.cgi/*checkout*/trunk/1.6.x/ccs-patch/patches/ccs-patch-2.6.26-debian-lenny.diff?root=tomoyo' || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-2.6.26-1-686 || die "Can't install packages."
apt-get source linux-image-2.6.26-1-686 || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-2.6-2.6.26 || die "Can't chdir to linux-2.6-2.6.26/ ."
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
patch -p1 < /usr/src/rpm/SOURCES/ccs-patch-2.6.26-debian-lenny.diff || die "Can't apply patch."
cat /boot/config-2.6.26-1-686 config.ccs > .config || die "Can't create config."
yes | make -s oldconfig > /dev/null

# Start compilation.
make-kpkg --append-to-version -1-686-ccs --arch i386 --subarch i686 --arch-in-name --initrd linux-image || die "Failed to build kernel package."

exit 0
