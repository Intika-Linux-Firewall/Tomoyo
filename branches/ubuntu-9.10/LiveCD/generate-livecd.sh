#!/bin/sh

LIVECD_HOME=~/LiveCD/
CD_LABEL="Ubuntu 9.10 i386 TOMOYO 1.7.1"
ISOIMAGE_NAME=../ubuntu-9.10-desktop-i386-tomoyo-1.7.1.iso
KERNEL_VERSION=2.6.31-16-ccs

# set -v

die () {
    echo '********** ' $1 ' **********'
    exit 1
}

cd ${LIVECD_HOME}
echo "********** Updating root filesystem for LiveCD. **********"

echo '<kernel>' > squash/etc/ccs/domain_policy.conf
echo 'use_profile 1' >> squash/etc/ccs/domain_policy.conf

mkdir -p -m 700 squash/var/log/tomoyo
if  ! grep -q ccs-auditd squash/etc/init.d/rc.local
then
    (
	echo 'if [ `stat -f --printf=%t /` -eq 61756673 ]'
	echo 'then'
	echo 'ccs-loadpolicy -e << EOF
file_pattern /target/\{\*\}/\*
file_pattern /target/\{\*\}/
file_pattern /rofs/\{\*\}/\*
initialize_domain /usr/share/ubiquity/install.py
keep_domain <kernel> /usr/share/ubiquity/install.py
EOF'
	echo 'mount -t tmpfs -o size=64m none /var/log/tomoyo/'
	echo 'fi'
	echo '/usr/sbin/ccs-auditd /dev/null /var/log/tomoyo/reject.log'
	) >> squash/etc/init.d/rc.local
fi

cd squash/usr/share/doc/ || die "Can't change directory."
rm -fR tomoyo/ || die "Can't delete directory."
wget -O - 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.7/1st-step/ubuntu9.10-live.tar.gz?root=tomoyo&view=tar' | tar -zxf - || die "Can't copy document."
mv ubuntu9.10-live/ tomoyo || die "Can't create directory."
sed -i -e 's@http://tomoyo\.sourceforge\.jp/tomoyo\.css@tomoyo.css@' -- tomoyo/index.html.* || die "Can't copy document."
cd ../../../../ || die "Can't change directory."
cp -p resources/tomoyo.css squash/usr/share/doc/tomoyo/ || die "Can't copy document."
cp -p resources/tomoyo-*.desktop squash/etc/skel/ || die "Can't copy shortcut."

rm -f squash/var/cache/apt/*.bin
rm -f squash/boot/*.bak
rm -f squash/*.deb
rm -f squash/root/.bash_history
rm -f squash/etc/resolv.conf
rm -f squash/sources.list
rm -f squash/package-install.sh
rm -f squash/var/lib/apt/lists/*_*
rm -f squash/var/cache/debconf/*-old
rm -f squash/boot/initrd.img-*-ccs

cd ${LIVECD_HOME}
echo "********** Copying kernel. **********"
cp -af squash/boot/vmlinuz-*-ccs cdrom/casper/vmlinuz || die "Can't copy kernel."

cd ${LIVECD_HOME}
echo "********** Updating initramfs. **********"
[ -e cdrom/casper/initrd.lz ] || die "Copy original initramfs image file to cdrom/casper/initrd.lz ."
rm -fR initrd/
mkdir initrd
lzcat -S .lz cdrom/casper/initrd.lz | ( cd initrd/ ; cpio -id ) || die "Can't extract initramfs."

for KERNEL_DIR in modules firmware
do
    if [ ! -d initrd/lib/${KERNEL_DIR}/${KERNEL_VERSION}/ ]
    then
	mkdir initrd/lib/${KERNEL_DIR}/${KERNEL_VERSION} || die "Can't create kernel modules directory."
	( cd initrd/lib/${KERNEL_DIR}/*-generic/ ; find ! -type d -print0 ) | ( cd squash/lib/${KERNEL_DIR}/${KERNEL_VERSION} ; xargs -0 tar -cf - ) | ( cd initrd/lib/${KERNEL_DIR}/${KERNEL_VERSION} ; tar -xf - ) || die "Can't copy kernel modules."
	rm -fR initrd/lib/${KERNEL_DIR}/*-generic || die "Can't delete kernel modules directory."
    fi
done

SETUP_SCRIPT=initrd/scripts/casper-bottom/10adduser

if ! grep -q TOMOYO ${SETUP_SCRIPT}
then
(
    echo '# --- TOMOYO Linux Project (begin) ---'
    echo 'mv /root/home/$USERNAME/tomoyo-*.desktop /root/home/$USERNAME/Desktop/'
    echo '# --- TOMOYO Linux Project (end) ---'
) >> ${SETUP_SCRIPT}
fi

(cd initrd/ ; find -print0 | cpio -o0 -H newc | lzma -9 ) > cdrom/casper/initrd.lz || die "Can't update initramfs."

cd ${LIVECD_HOME}
echo "********** Generating squashfs image file. **********"
mksquashfs squash cdrom/casper/filesystem.squashfs -noappend || die "Can't generate squashfs image file."

cd ${LIVECD_HOME}
echo "********** Updating MD5 information. **********"
cd cdrom/
mv md5sum.txt md5sum.txt.old
cat md5sum.txt.old | awk '{ print $2 }' | xargs md5sum > md5sum.txt
rm -f md5sum.txt.old
[ -r .disk/casper-uuid-ccs ] || mv .disk/casper-uuid-generic .disk/casper-uuid-ccs
sed -i -e 's/casper-uuid-generic/casper-uuid-ccs/' -- md5sum.txt

cd ${LIVECD_HOME}
echo "********** Generating iso image file. **********"
cd cdrom/
mkisofs -r -V "${CD_LABEL}" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ${ISOIMAGE_NAME} . || die "Can't generate iso image file."

echo "********** Done. **********"
exit 0
