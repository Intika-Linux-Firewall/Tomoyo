#!/bin/sh

LIVECD_HOME=~/LiveCD/
CD_LABEL="CentOS-6.0-i386-TOMOYO-LiveCD"
ISOIMAGE_NAME=../CentOS-6.0-i386-TOMOYO-LiveCD.iso
ORIGINAL_VERSION=2.6.32-71.el6.i686
KERNEL_VERSION=2.6.32-71.29.1.el6_tomoyo_1.8.2p2.i686

set -v

die () {
    echo '********** ' $1 ' **********'
    exit 1
}

cd ${LIVECD_HOME}
echo "********** Updating root filesystem for LiveCD. **********"

[ -d ext3/home/ ] || mount -o loop,noatime squash/LiveOS/ext3fs.img ext3/ || die "Mount squash/LiveOS/ext3fs.img on ext3/ ."

mkdir -p -m 700 ext3/var/log/tomoyo
grep -q mount ext3/etc/rc.d/rc.local || echo 'mount -t tmpfs -o size=64m none /var/log/tomoyo/' >> ext3/etc/rc.d/rc.local
grep -q ccs-auditd ext3/etc/rc.d/rc.local || echo /usr/sbin/ccs-auditd >> ext3/etc/rc.d/rc.local

cd ext3/usr/share/doc/ || die "Can't change directory."
rm -fR tomoyo/ || die "Can't delete directory."
mkdir tomoyo/ || die "Can't create directory."
cd tomoyo/ || die "Can't change directory."
wget -O centos5-live.html.en 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/centos5-live.html.en?revision=HEAD&root=tomoyo' || die "Can't copy document."
wget -O centos5-live.html.ja 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/centos5-live.html.ja?revision=HEAD&root=tomoyo' || die "Can't copy document."
wget -O - 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/media.centos5.tar.gz?root=tomoyo&view=tar' | tar -zxf - || die "Can't copy document."
ln -s centos5-live.html.en index.html.en
ln -s centos5-live.html.ja index.html.ja
cd ../../../../../ || die "Can't change directory."
cp -p resources/*.desktop ext3/usr/share/doc/tomoyo/ || die "Can't copy document."
grep -q desktop ext3/etc/rc.d/rc.local || echo 'cp -af --remove-destination /usr/share/doc/tomoyo/*.desktop /home/centos/Desktop/' >> ext3/etc/rc.d/rc.local
grep -q centos:centos ext3/etc/rc.d/rc.local || echo 'chown centos:centos /home/centos/Desktop/*.desktop' >> ext3/etc/rc.d/rc.local

rm -f ext3/var/log/yum.log
rm -fR ext3/var/lib/yum/*/
rm -fR ext3/var/tmp/*/
rm -f ext3/var/lib/rpm/__db.00*
rm -f ext3/package-install.sh
rm -f ext3/root/.bash_history
rm -f ext3/boot/initramfs-*

cd ${LIVECD_HOME}
echo "********** Copying kernel. **********"
cp -af ext3/boot/vmlinuz-${KERNEL_VERSION} cdrom/isolinux/vmlinuz0 || die "Can't copy kernel."
ln -f cdrom/isolinux/vmlinuz0 cdrom/EFI/boot/ || die "Can't copy kernel."

cd ${LIVECD_HOME}
echo "********** Updating initramfs. **********"
[ -e cdrom/isolinux/initrd0.img ] || die "Copy original initramfs image file to cdrom/isolinux/initrd0.img ."
rm -fR initrd/
mkdir initrd
zcat cdrom/isolinux/initrd0.img | (cd initrd/ ; cpio -id ) || die "Can't extract initramfs."

if [ ! -d initrd/lib/modules/${KERNEL_VERSION}/ ]
then
    mkdir initrd/lib/modules/${KERNEL_VERSION} || die "Can't create kernel modules directory."
    ( cd initrd/lib/modules/${ORIGINAL_VERSION}/ ; find . -type f -print0 ) | xargs -0 tar -cf - -C ext3/lib/modules/${KERNEL_VERSION}/ | tar -xf - -C initrd/lib/modules/${KERNEL_VERSION}/ || die "Can't copy kernel modules."
    cp -p initrd/lib/modules/${ORIGINAL_VERSION}/modules.* initrd/lib/modules/${KERNEL_VERSION}/ || "Can't copy modules information."
    rm -fR initrd/lib/modules/${ORIGINAL_VERSION}/ || die "Can't delete kernel modules directory."
fi

( cd initrd ; find -print0 | cpio -o0 -H newc | gzip -9 ) > cdrom/isolinux/initrd0.img || die "Can't update initramfs."
ln -f cdrom/isolinux/initrd0.img cdrom/EFI/boot/ || die "Can't update initramfs."

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
grep -q TOMOYO -- isolinux/isolinux.cfg || sed -i -e 's/i386/i386-TOMOYO/' -- isolinux/isolinux.cfg
mkisofs -r -V "${CD_LABEL}" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ${ISOIMAGE_NAME} . || die "Can't generate iso image file."

echo "********** Done. **********"
exit 0
