#!/bin/sh

LIVECD_HOME=~/LiveCD/
CD_LABEL="Ubuntu 12.04 i386 TOMOYO 1.8.5"
ISOIMAGE_NAME=../ubuntu-12.04-desktop-i386-tomoyo-1.8.5.iso
KERNEL_VERSION=3.2.0-113-generic-pae-ccs

# set -v

die () {
    echo '********** ' $1 ' **********'
    exit 1
}

cd ${LIVECD_HOME}
echo "********** Updating root filesystem for LiveCD. **********"

mkdir -p -m 700 squash/var/log/tomoyo
if  ! grep -q tomoyo squash/etc/init.d/rc.local
then
    (
	echo 'if [ `stat -f --printf=%t /` -eq 1021994 ]'
	echo 'then'
	echo '[ -d /proc/ccs/ ] && ccs-loadpolicy -e << EOF
initialize_domain /usr/share/ubiquity/install.py
keep_domain <kernel> /usr/share/ubiquity/install.py
EOF'
	echo '[ -d /sys/kernel/security/tomoyo/ ] && tomoyo-loadpolicy -e << EOF
initialize_domain /usr/share/ubiquity/install.py
keep_domain <kernel> /usr/share/ubiquity/install.py
EOF'
	echo 'mount -t tmpfs -o size=64m none /var/log/tomoyo/'
	echo 'fi'
	echo '[ -d /proc/ccs/ ] && /usr/sbin/ccs-auditd'
	echo '[ -d /sys/kernel/security/tomoyo/ ] && /usr/sbin/tomoyo-auditd'
	) >> squash/etc/init.d/rc.local
fi

if ! grep -qF tomoyo.osdn.jp squash/etc/init.d/rc.local
then
    (
	echo 'if ! grep -qF tomoyo.osdn.jp /etc/apt/sources.list'
	echo 'then'
	echo 'echo "" >> /etc/apt/sources.list'
	echo 'echo "# TOMOYO Linux 1.8 kernel and tools" >> /etc/apt/sources.list'
	echo 'echo "deb https://tomoyo.osdn.jp/repos-1.8/Ubuntu12.04/ ./" >> /etc/apt/sources.list'
	echo 'fi'
    ) >> squash/etc/init.d/rc.local
fi

cd squash/usr/share/doc/ || die "Can't change directory."
rm -fR tomoyo/ || die "Can't delete directory."
mkdir tomoyo/ || die "Can't create directory."
cd tomoyo/ || die "Can't change directory."
wget -O ubuntu12.04-live.html.en 'https://osdn.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/ubuntu12.04-live.html.en?revision=HEAD&root=tomoyo' || die "Can't copy document."
wget -O ubuntu12.04-live.html.ja 'https://osdn.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/ubuntu12.04-live.html.ja?revision=HEAD&root=tomoyo' || die "Can't copy document."
wget -O - 'https://osdn.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/media.ubuntu12.04.tar.gz?root=tomoyo&view=tar' | tar -zxf - || die "Can't copy document."
ln -s ubuntu12.04-live.html.en index.html.en
ln -s ubuntu12.04-live.html.ja index.html.ja
cd ../../../../../ || die "Can't change directory."
cp -p resources/tomoyo*.desktop squash/etc/skel/ || die "Can't copy shortcut."

rm -f squash/var/cache/apt/*.bin
rm -f squash/boot/*.bak
rm -f squash/*.deb
rm -f squash/root/.bash_history
rm -f squash/etc/resolv.conf
rm -f squash/etc/resolv.conf2
rm -f squash/sources.list
rm -f squash/package-install.sh
rm -f squash/var/lib/apt/lists/*_*
rm -f squash/var/cache/debconf/*-old
rm -f squash/boot/initrd.img-*-ccs
rm -f squashetc/apt/trusted.gpg~

cd ${LIVECD_HOME}
echo "********** Copying kernel. **********"
cp -af squash/boot/vmlinuz-*-ccs cdrom/casper/vmlinuz
rm -f squash/boot/vmlinuz-*-ccs

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
	( cd initrd/lib/${KERNEL_DIR}/*-generic-pae/ ; find ! -type d -print0 ) | ( cd squash/lib/${KERNEL_DIR}/${KERNEL_VERSION} ; xargs -0 tar -cf - ) | ( cd initrd/lib/${KERNEL_DIR}/${KERNEL_VERSION} ; tar -xf - ) || die "Can't copy kernel modules."
	rm -fR initrd/lib/${KERNEL_DIR}/*-generic-pae || die "Can't delete kernel modules directory."
    fi
done

SETUP_SCRIPT=initrd/scripts/casper-bottom/25adduser

if ! grep -q TOMOYO ${SETUP_SCRIPT}
then
(
    echo '# --- TOMOYO Linux Project (begin) ---'
    echo 'mv /root/home/$USERNAME/tomoyo*.desktop /root/home/$USERNAME/Desktop/'
    echo '[ -d /proc/ccs/ ] || rm /root/home/$USERNAME/Desktop/tomoyo-editpolicy.desktop'
    echo 'mount -t securityfs none /sys/kernel/security/'
    echo '[ -d /sys/kernel/security/tomoyo/ ] || rm /root/home/$USERNAME/Desktop/tomoyo2-editpolicy.desktop'
    echo 'umount /sys/kernel/security/'
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
[ -r .disk/casper-uuid-ccs ] || mv .disk/casper-uuid-generic-pae .disk/casper-uuid-ccs
sed -i -e 's/casper-uuid-generic-pae/casper-uuid-ccs/' -- md5sum.txt

cd ${LIVECD_HOME}
echo "********** Generating iso image file. **********"
cd cdrom/
mkisofs -r -V "${CD_LABEL}" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ${ISOIMAGE_NAME} . || die "Can't generate iso image file."

echo "********** Done. **********"
exit 0
