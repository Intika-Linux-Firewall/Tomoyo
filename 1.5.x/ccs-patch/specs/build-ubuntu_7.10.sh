#! /bin/sh
#
# This is kernel build script for ubuntu 7.10's 2.6.22 kernel.
#

die () {
    echo $1
    exit 1
}

# Install kernel source packages.
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x191FCD8A ' | gpg --import || die "Can't import PGP key."
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x60E80B5B ' | gpg --import || die "Can't import PGP key."
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x174BF01A ' | gpg --import || die "Can't import PGP key."
curl 'http://pgp.nic.ad.jp/pks/lookup?op=get&search=0x0A0AC927 ' | gpg --import || die "Can't import PGP key."
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install linux-kernel-devel fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-2.6.22-14-generic || die "Can't install packages."
apt-get source linux-image-2.6.22-14-generic || die "Can't install kernel source."
apt-get install linux-headers-2.6.22-14 || die "Can't install packages."
apt-get build-dep linux-ubuntu-modules-2.6.22-14-generic || die "Can't install packages."
apt-get source linux-ubuntu-modules-2.6.22-14-generic || die "Can't install kernel source."
apt-get build-dep linux-restricted-modules-2.6.22-14-generic || die "Can't install packages."
apt-get source linux-restricted-modules-2.6.22-14-generic || die "Can't install kernel source."

# Download TOMOYO Linux patches.
cd linux-source-2.6.22-2.6.22/ || die "Can't chdir to linux-2.6.22-2.6.22/ ."
wget http://osdn.dl.sourceforge.jp/tomoyo/27219/ccs-patch-1.5.4-20080510.tar.gz || die "Can't download patch."
tar -zxf ccs-patch-1.5.4-20080510.tar.gz || die "Can't extract patch."

# Copy patches and create kernel config.
mkdir -p debian/binary-custom.d/ccs/patchset || die "Can't create debian/binary-custom.d/ccs/patchset ."
cp -p patches/ccs-patch-2.6.22.9-ubuntu1.diff debian/binary-custom.d/ccs/patchset/ubuntu-7.10.patch || die "Can't copy patch."
cd debian/binary-custom.d/ccs/ || die "Can't chdir to debian/binary-custom.d/ccs/ ."
cat ../../config/i386/config ../../config/i386/config.generic ../../../config.ccs > config.i386 || die "Can't create config."
sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- config.i386 || die "Can't edit config."
touch rules || die "Can't create file."
cd ../../../ || die "Can't chdir to ../../../ ."
awk ' BEGIN { flag = 0; print ""; } { if ($1 == "Package:" ) { if (index($0, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub | sed -e 's:-generic:-ccs:' > debian/control.stub.ccs || die "Can't create file."
cat debian/control.stub.ccs >> debian/control.stub || die "Can't edit file."
debian/rules debian/control || die "Can't run control."

# Start compilation.
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."
debian/rules custom-binary-ccs || die "Failed to build kernel package."
cd .. || die "Can't chdir to ../ ."

# Install header package for compiling additional modules.
dpkg -i linux-headers-2.6.22-14-ccs_2.6.22-14.*_i386.deb || die "Can't install packages."
cd linux-ubuntu-modules-2.6.22-2.6.22 || die "Can't chdir to linux-ubuntu-modules-2.6.22-2.6.22 ."
awk ' BEGIN { flag = 0; print ""; } { if ($1 == "Package:" ) { if (index($0, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub | sed -e 's:-generic:-ccs:' > debian/control.stub.ccs || die "Can't create file."
cat debian/control.stub.ccs >> debian/control.stub || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
sed -i -e 's:virtual:virtual ccs:' debian/rules.d/i386.mk || die "Can't edit file."
debian/rules binary-indep binary-arch || die "Failed to build kernel package."
cd .. || die "Can't chdir to ../ ."

cd linux-restricted-modules-2.6.22-2.6.22.4/ || die "Can't chdir to linux-restricted-modules-2.6.22-2.6.22.4/ ."
awk ' BEGIN { flag = 0; print ""; } { if ( $1 == "Package:") { if ( index($2, "-generic") > 0) flag = 1; else flag = 0; }; if (flag) print $0; } ' debian/control.stub.in | sed -e 's:-generic:-ccs:g' > debian/control.stub.in.tmp || die "Can't create file."
cat debian/control.stub.in.tmp >> debian/control.stub.in || die "Can't edit file."
sed -i -e 's/,generic/,ccs generic/' debian/rules || die "Can't edit file."
debian/rules debian/control || die "Can't run control."
debian/rules binary || die "Failed to build kernel package."

exit 0
