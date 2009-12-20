#!/bin/sh

LIVECD_HOME=~/LiveCD/
CD_LABEL="CentOS-5.4-i386-TOMOYO-LiveCD"
ISOIMAGE_NAME=../CentOS-5.4-i386-TOMOYO-LiveCD.iso
ORIGINAL_VERSION=2.6.18-164.el5
ORIGINAL_VERSION_REGEXP=2\.6\.18-164\.el5
KERNEL_VERSION=2.6.18-164.9.1.el5_ccs # tomoyo_1.7.1p1

set -v

die () {
    echo '********** ' $1 ' **********'
    exit 1
}

cd ${LIVECD_HOME}
echo "********** Updating root filesystem for LiveCD. **********"

[ -d ext3/home/ ] || mount -o loop,noatime,nodiratime squash/LiveOS/ext3fs.img ext3/ || die "Mount squash/LiveOS/ext3fs.img on ext3/ ."

echo '<kernel>' > ext3/etc/ccs/domain_policy.conf
echo 'use_profile 1' >> ext3/etc/ccs/domain_policy.conf

mkdir -p -m 700 ext3/var/log/tomoyo
grep -q mount ext3/etc/rc.d/rc.local || echo 'mount -t tmpfs -o size=64m none /var/log/tomoyo/' >> ext3/etc/rc.d/rc.local
grep -q ccs-auditd ext3/etc/rc.d/rc.local || echo '/usr/sbin/ccs-auditd /dev/null /var/log/tomoyo/reject.log' >> ext3/etc/rc.d/rc.local

cd ext3/usr/share/doc/ || die "Can't change directory."
rm -fR tomoyo/ || die "Can't delete directory."
wget -O - 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.7/1st-step/centos5-live.tar.gz?root=tomoyo&view=tar' | tar -zxf - || die "Can't copy document."
mv centos5-live/ tomoyo || die "Can't create directory."
sed -i -e 's@http://tomoyo\.sourceforge\.jp/tomoyo\.css@tomoyo.css@' -- tomoyo/index.html.* || die "Can't copy document."
cd ../../../../ || die "Can't change directory."
cp -p resources/tomoyo.css ext3/usr/share/doc/tomoyo/ || die "Can't copy document."
cp -p resources/tomoyo-*.desktop resources/install-japanese-font.desktop ext3/etc/skel/ || die "Can't copy shortcut."

rm -f ext3/*.rpm
rm -f ext3/package-install.sh
rm -f ext3/root/.bash_history
rm -f ext3/boot/initrd-*

SETUP_SCRIPT=ext3/etc/rc.d/init.d/centos-live

if ! grep -q TOMOYO ${SETUP_SCRIPT}
    then
    (
	echo '# --- TOMOYO Linux Project (begin) ---'
	echo 'mv /home/centos/tomoyo-*.desktop /home/centos/install-japanese-font.desktop /home/centos/Desktop/'
	echo '# --- TOMOYO Linux Project (end) ---'
    ) >> ${SETUP_SCRIPT}
fi

cd ${LIVECD_HOME}
echo "********** Copying kernel. **********"
cp -af ext3/boot/vmlinuz-${KERNEL_VERSION} cdrom/isolinux/vmlinuz0 || die "Can't copy kernel."

cd ${LIVECD_HOME}
echo "********** Updating initramfs. **********"
[ -e cdrom/isolinux/initrd0.img ] || die "Copy original initramfs image file to cdrom/isolinux/initrd0.img ."
rm -fR initrd/
mkdir initrd
zcat cdrom/isolinux/initrd0.img | (cd initrd/ ; cpio -id ) || die "Can't extract initramfs."

if [ ! -d initrd/lib/modules/${KERNEL_VERSION}/ ]
    then
    mkdir initrd/lib/modules/${KERNEL_VERSION} || die "Can't create kernel modules directory."
    for i in `( cd initrd/lib/modules/${ORIGINAL_VERSION}/ ; echo *.ko )`
      do
      find ext3/lib/modules/${KERNEL_VERSION}/ -type f -name $i -exec cp -p \{\} initrd/lib/modules/${KERNEL_VERSION}/ \; || die "Can't copy kernel modules."
    done
    cp -p initrd/lib/modules/${ORIGINAL_VERSION}/modules.* initrd/lib/modules/${KERNEL_VERSION}/ || "Can't copy modules information."
    sed -i -e "s/${ORIGINAL_VERSION_REGEXP}/${KERNEL_VERSION}/g" initrd/lib/modules/${KERNEL_VERSION}/modules.* || die "Can't update modules information."
    rm -fR initrd/lib/modules/${ORIGINAL_VERSION}/ || die "Can't delete kernel modules directory."
fi

( cd initrd ; find -print0 | cpio -o0 -H newc | gzip -9 ) > cdrom/isolinux/initrd0.img || die "Can't update initramfs."

cd ${LIVECD_HOME}
echo "********** Updating root filesystem for LiveCD. **********"

rm squash/LiveOS/ext3fs.img || die "Can't delete old image file."
dd if=/dev/zero of=squash/LiveOS/ext3fs.img bs=1048576 count=4096 || "die Can't create image file."
mke2fs -j -m 0 -L "CentOS-5.4-i386-" -F squash/LiveOS/ext3fs.img || die "Can't create filesystem."
tune2fs -c -1 -i 0 -o user_xattr,acl squash/LiveOS/ext3fs.img || die "Can't tune filesystem."
mount -o loop,noatime,nodiratime squash/LiveOS/ext3fs.img mnt/ || die "Can't mount filesystem."
cp -a ext3/* ext3/.rnd mnt/ || die "Can't copy image file."
umount -d ext3/ || die "Can't unmount old filesystem." 

chroot mnt/ mount -t proc none /proc/
chroot mnt/ mount -t sysfs none /sys/
chroot mnt/ mount -t selinuxfs none /selinux/
chroot mnt/ restorecon -R /
chroot mnt/ umount -l /selinux/
chroot mnt/ umount -l /proc/
chroot mnt/ umount -l /sys/
umount -d mnt/ || die "Can't unmount new filesystem."

cd ${LIVECD_HOME}
echo "********** Generating squashfs image file. **********"
mksquashfs squash cdrom/LiveOS/squashfs.img -noappend || die "Can't generate squashfs image file."

cd ${LIVECD_HOME}
echo "********** Generating iso image file. **********"
cd cdrom/
grep -q TOMOYO -- isolinux/isolinux.cfg || sed -i -e 's/i386/i386-TOMOYO/' -- isolinux/isolinux.cfg
mkisofs -r -V "${CD_LABEL}" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ${ISOIMAGE_NAME} . || die "Can't generate iso image file."

echo "********** Done. **********"
exit 0
