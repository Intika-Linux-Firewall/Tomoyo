#! /bin/sh
#
# This is kernel build script for debian wheezy's 3.2 kernel.
#

die () {
    echo $1
    exit 1
}

ABI_VERSION=4
ORIGINAL_FLAVOUR=686-pae
NEW_FLAVOUR=${ORIGINAL_FLAVOUR}-ccs
REVISION=`apt-cache show --no-all-versions linux-source-3.2 | awk ' { if ($1 == "Version:") print $2; } '`

echo "Building "${NEW_FLAVOUR}" from "${ORIGINAL_FLAVOUR}"."
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

# Install base packages.
apt-get install build-essential kernel-package || die "Can't install packages."
sed -i -e 's/maintainer := .*/maintainer := Tetsuo Handa/' -e 's/email := .*/email := penguin-kernel@I-love.SAKURA.ne.jp/' -- /etc/kernel-pkg.conf || die "Can't edit /etc/kernel-pkg.conf ."

# Download TOMOYO Linux patches.
mkdir -p /root/rpmbuild/SOURCES/
cd /root/rpmbuild/SOURCES/ || die "Can't chdir to /root/rpmbuild/SOURCES/ ."
if [ ! -r ccs-patch-1.8.5-20151111.tar.gz ]
then
    apt-get -y install wget
    wget -O ccs-patch-1.8.5-20151111.tar.gz 'http://osdn.jp/frs/redir.php?f=/tomoyo/49684/ccs-patch-1.8.5-20151111.tar.gz' || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install linux-source-3.2 || die "Can't install kernel source."

rm -fR linux-source-3.2
tar -jxf linux-source-3.2.tar.bz2

# Apply patches and create kernel config.
cd linux-source-3.2 || die "Can't chdir to linux-source-3.2/ ."
tar -zxf /root/rpmbuild/SOURCES/ccs-patch-1.8.5-20151111.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-3.2-debian-wheezy.diff || die "Can't apply patch."
cat /boot/config-3.2.0-$ABI_VERSION-$ORIGINAL_FLAVOUR config.ccs > .config || die "Can't create config."
sed -i -e 's/SUBLEVEL = .*/SUBLEVEL = 0/' Makefile || die "Can't edit Makefile"

# Start compilation.
make-kpkg --append-to-version -$ABI_VERSION-$NEW_FLAVOUR --initrd --revision $REVISION binary-arch || die "Failed to build kernel package."

exit 0
