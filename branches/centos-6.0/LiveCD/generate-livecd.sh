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
wget -O centos6-live.html.en 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/centos6-live.html.en?revision=HEAD&root=tomoyo' || die "Can't copy document."
wget -O centos6-live.html.ja 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/centos6-live.html.ja?revision=HEAD&root=tomoyo' || die "Can't copy document."
wget -O - 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/media.centos6.tar.gz?root=tomoyo&view=tar' | tar -zxf - || die "Can't copy document."
ln -s centos6-live.html.en index.html.en
ln -s centos6-live.html.ja index.html.ja
cd ../../../../../ || die "Can't change directory."
cp -p resources/*.desktop ext3/usr/share/doc/tomoyo/ || die "Can't copy document."
grep -q desktop ext3/etc/rc.d/rc.local || echo 'cp -af --remove-destination /usr/share/doc/tomoyo/*.desktop /home/centoslive/Desktop/' >> ext3/etc/rc.d/rc.local
grep -q centoslive:centoslive ext3/etc/rc.d/rc.local || echo 'chown centoslive:centoslive /home/centoslive/Desktop/*.desktop' >> ext3/etc/rc.d/rc.local

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

chroot ext3/ mount -t proc none /proc/
chroot ext3/ mount -t sysfs none /sys/
chroot ext3/ mount -t selinuxfs none /selinux/
chroot ext3/ restorecon -R /
chroot ext3/ umount -l /selinux/
chroot ext3/ umount -l /proc/
chroot ext3/ umount -l /sys/
cat /dev/zero > ext3/zero
sync
rm -f ext3/zero
umount -d ext3/ || die "Can't unmount filesystem."

e2fsck -f squash/LiveOS/ext3fs.img || die "Errors in filesystem."

cd ${LIVECD_HOME}
echo "********** Generating squashfs image file. **********"
mksquashfs squash cdrom/LiveOS/squashfs.img -noappend -b 131072 -no-sparse -no-exports -no-recovery || die "Can't generate squashfs image file."

#TODO: How to update cdrom/LiveOS/osmin.img ?
rm -f cdrom/LiveOS/osmin.img

cd ${LIVECD_HOME}
echo "********** Generating iso image file. **********"
cd cdrom/
grep -q TOMOYO -- isolinux/isolinux.cfg || sed -i -e 's/i386/i386-TOMOYO/' -- isolinux/isolinux.cfg
mkisofs -r -V "${CD_LABEL}" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ${ISOIMAGE_NAME} . || die "Can't generate iso image file."

echo "********** Done. **********"
exit 0
