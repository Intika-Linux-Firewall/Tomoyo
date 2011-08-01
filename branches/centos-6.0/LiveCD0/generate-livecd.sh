#!/bin/sh

LIVECD_HOME=~/LiveCD/
CD_LABEL="CentOS-6.0-i386-LiveCD"
ISOIMAGE_NAME=../CentOS-6.0-i386-TOMOYO-LiveCD.iso

set -v

die () {
    echo '********** ' $1 ' **********'
    exit 1
}

cd ${LIVECD_HOME}
echo "********** Updating root filesystem for LiveCD. **********"

[ -d ext3/home/ ] || mount -o loop,noatime squash/LiveOS/ext3fs.img ext3/ || die "Mount squash/LiveOS/ext3fs.img on ext3/ ."

cd ${LIVECD_HOME}
echo "********** Updating root filesystem for LiveCD. **********"

rm squash/LiveOS/ext3fs.img || die "Can't delete old image file."
dd if=/dev/zero of=squash/LiveOS/ext3fs.img bs=1048576 count=4096 || die "Can't create image file."
mkfs.ext4 -m 0 -L "CentOS-6.0-i386-" -F squash/LiveOS/ext3fs.img || die "Can't create filesystem."
tune2fs -c -1 -i 0 -o user_xattr,acl squash/LiveOS/ext3fs.img || die "Can't tune filesystem."
mount -o loop,noatime squash/LiveOS/ext3fs.img mnt/ || die "Can't mount filesystem."
cp -a ext3/* mnt/ || die "Can't copy image file."
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
mksquashfs squash cdrom/LiveOS/squashfs.img -noappend -b 131072 -no-sparse -no-exports -no-recovery || die "Can't generate squashfs image file."

cd ${LIVECD_HOME}
echo "********** Generating iso image file. **********"
cd cdrom/
mkisofs -r -V "${CD_LABEL}" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ${ISOIMAGE_NAME} . || die "Can't generate iso image file."

echo "********** Done. **********"
exit 0
