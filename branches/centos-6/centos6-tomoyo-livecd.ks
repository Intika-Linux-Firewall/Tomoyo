# Kickstart file for CentOS 6 + TOMOYO LiveCD.
# based on http://people.centos.org/arrfab/CentOS6/SRPMS/livecd-tools-0.3.6-1.el6.src.rpm
# and http://people.centos.org/arrfab/CentOS6/LiveCD-DVD/centos6-liveCD-desktop.cfg
#
# Usage: livecd-creator -f "CentOS-6.6-i386-TOMOYO-LiveCD" --cache=/var/cache/livecd -c this_file
lang en_US.UTF-8
keyboard us
timezone US/Eastern
auth --useshadow --enablemd5
selinux --enforcing
firewall --enabled --service=mdns
repo --name=base    --baseurl=http://ftp.riken.jp/Linux/centos/6.6/os/i386/
repo --name=updates --baseurl=http://ftp.riken.jp/Linux/centos/6.6/updates/i386/
repo --name=ccs     --baseurl=http://tomoyo.sourceforge.jp/repos-1.8/CentOS6/
repo --name=adobe   --baseurl=http://linuxdownload.adobe.com/linux/i386/

xconfig --startxonboot
part / --size 4096 --fstype ext4
services --enabled=NetworkManager --disabled=network,sshd

%packages
ConsoleKit
ConsoleKit-libs
ConsoleKit-x11
DeviceKit-power
GConf2
GConf2-gtk
MAKEDEV
ModemManager
NetworkManager
NetworkManager-glib
NetworkManager-gnome
ORBit2
PackageKit
PackageKit-device-rebind
PackageKit-glib
PackageKit-gtk-module
PackageKit-yum
PackageKit-yum-plugin
acl
acpid
aic94xx-firmware
alsa-lib
alsa-plugins-pulseaudio
alsa-utils
anaconda
anaconda-yum-plugins
at
at-spi
at-spi-python
atk
atmel-firmware
attr
audit
audit-libs
authconfig
authconfig-gtk
avahi-autoipd
avahi-glib
avahi-libs
avahi-ui
b43-fwcutter
b43-openfwwf
basesystem
bash
bc
bfa-firmware
bind-libs
bind-utils
binutils
biosdevname
blktrace
bluez
bluez-libs
bridge-utils
btparser
busybox
bzip2
bzip2-libs
ca-certificates
cairo
ccs-kernel
ccs-tools
cdparanoia-libs
centos-indexhtml
centos-release
checkpolicy
cheese
chkconfig
comps-extras
control-center
control-center-extra
control-center-filesystem
coreutils
coreutils-libs
cpio
cpuspeed
cracklib
cracklib-dicts
cracklib-python
crda
createrepo
cronie
cronie-anacron
crontabs
cryptsetup-luks
cryptsetup-luks-libs
ctapi-common
cups-libs
curl
cyrus-sasl
cyrus-sasl-lib
cyrus-sasl-plain
dash
db4
db4-utils
dbus
dbus-glib
dbus-libs
dbus-python
dbus-x11
deltarpm
desktop-file-utils
device-mapper
device-mapper-event
device-mapper-event-libs
device-mapper-libs
device-mapper-multipath
device-mapper-multipath-libs
device-mapper-persistent-data
dhclient
dhcp-common
diffutils
dmidecode
dmraid
dmraid-events
dmz-cursor-themes
dnsmasq
docbook-dtds
dosfstools
dracut
dracut-kernel
e2fsprogs
e2fsprogs-libs
ed
efibootmgr
eggdbus
eject
elfutils-libelf
elfutils-libs
enchant
ethtool
evince
evince-libs
evolution-data-server
exempi
expat
fcoe-utils
festival
festival-lib
festival-speechtools-libs
festvox-slt-arctic-hts
file
file-libs
filesystem
findutils
fipscheck
fipscheck-lib
firefox
firstboot
flac
flash-plugin
fontconfig
fontpackages-filesystem
fprintd
fprintd-pam
freetype
fuse
fuse-libs
gamin
gawk
gdbm
gdk-pixbuf2
gdm
gdm-libs
gdm-user-switch-applet
gedit
genisoimage
ghostscript
ghostscript-fonts
glib-networking
glib2
glibc
glibc-common
glx-utils
gmp
gnome-applets
gnome-bluetooth
gnome-bluetooth-libs
gnome-desktop
gnome-disk-utility
gnome-disk-utility-libs
gnome-disk-utility-ui-libs
gnome-doc-utils-stylesheets
gnome-icon-theme
gnome-keyring
gnome-keyring-pam
gnome-mag
gnome-media
gnome-media-libs
gnome-menus
gnome-packagekit
gnome-panel
gnome-panel-libs
gnome-power-manager
gnome-python2
gnome-python2-applet
gnome-python2-bonobo
gnome-python2-canvas
gnome-python2-desktop
gnome-python2-extras
gnome-python2-gconf
gnome-python2-gnome
gnome-python2-gnomevfs
gnome-python2-libegg
gnome-python2-libwnck
gnome-screensaver
gnome-session
gnome-session-xsession
gnome-settings-daemon
gnome-speech
gnome-terminal
gnome-themes
gnome-user-docs
gnome-vfs2
gnome-vfs2-smb
gnupg2
gnutls
gpgme
gpm-libs
grep
groff
grub
grubby
gstreamer
gstreamer-plugins-base
gstreamer-plugins-good
gstreamer-tools
gthumb
gtk2
gtk2-engines
gtksourceview2
gucharmap
gvfs
gvfs-archive
gvfs-fuse
gvfs-obexftp
gvfs-smb
gzip
hal
hal-info
hal-libs
hdparm
hicolor-icon-theme
hunspell
hunspell-en
hwdata
info
initscripts
iproute
iptables
iptables-ipv6
iputils
ipw2100-firmware
ipw2200-firmware
irqbalance
iscsi-initiator-utils
iso-codes
isomd5sum
ivtv-firmware
iw
iwl100-firmware
iwl1000-firmware
iwl3945-firmware
iwl4965-firmware
iwl5000-firmware
iwl5150-firmware
iwl6000-firmware
iwl6000g2a-firmware
iwl6050-firmware
jasper-libs
kbd
kbd-misc
kernel-firmware
kexec-tools
keyutils-libs
kpartx
krb5-libs
lcms-libs
ledmon
less
libICE
libIDL
libSM
libX11
libX11-common
libXScrnSaver
libXau
libXcomposite
libXcursor
libXdamage
libXdmcp
libXext
libXfixes
libXfont
libXft
libXi
libXinerama
libXmu
libXrandr
libXrender
libXres
libXt
libXtst
libXv
libXvMC
libXxf86dga
libXxf86misc
libXxf86vm
libacl
libaio
libao
libarchive
libart_lgpl
libasyncns
libatasmart
libattr
libavc1394
libblkid
libbonobo
libbonoboui
libcanberra
libcanberra-gtk2
libcap
libcap-ng
libcdio
libcom_err
libconfig
libcroco
libcurl
libdaemon
libdmx
libdrm
libdv
libedit
liberation-fonts-common
liberation-sans-fonts
libertas-usb8388-firmware
libexif
libffi
libfontenc
libfprint
libgail-gnome
libgcc
libgcrypt
libgdata
libglade2
libgnome
libgnomecanvas
libgnomekbd
libgnomeui
libgpg-error
libgphoto2
libgsf
libgtop2
libgudev1
libgweather
libhbaapi
libhbalinux
libical
libidn
libiec61883
libiptcdata
libjpeg-turbo
libmcpp
libnih
libnl
libnotify
libogg
liboil
libopenraw
libopenraw-gnome
libpcap
libpciaccess
libpng
libproxy
libproxy-bin
libproxy-python
libraw1394
libreport
libreport-compat
libreport-gtk
libreport-newt
libreport-plugin-reportuploader
libreport-plugin-rhtsupport
libreport-python
librsvg2
libsamplerate
libselinux
libselinux-python
libselinux-utils
libsemanage
libsepol
libshout
libsmbclient
libsndfile
libsoup
libspectre
libss
libssh2
libstdc++
libtalloc
libtar
libtasn1
libtdb
libtevent
libthai
libtheora
libtiff
libtool-ltdl
libudev
libusb
libusb1
libuser
libuser-python
libutempter
libuuid
libv4l
libvisual
libvorbis
libvpx
libwacom
libwacom-data
libwnck
libxcb
libxkbfile
libxklavier
libxml2
libxml2-python
libxslt
lldpad
lldpad-libs
lockdev
logrotate
lsof
lua
lvm2
lvm2-libs
lzo
m4
mailx
make
makebootfat
man
man-pages
man-pages-overrides
mcpp
mdadm
memtest86+
mesa-dri-drivers
mesa-dri-filesystem
mesa-dri1-drivers
mesa-libEGL
mesa-libGL
mesa-libGLU
mesa-libgbm
mesa-private-llvm
metacity
microcode_ctl
mingetty
mlocate
mobile-broadband-provider-info
module-init-tools
mozilla-filesystem
mtdev
mtools
mtr
mysql-libs
nautilus
nautilus-extensions
ncurses
ncurses-base
ncurses-libs
net-tools
newt
newt-python
notification-daemon
nspluginwrapper
nspr
nss
nss-softokn
nss-softokn-freebl
nss-sysinit
nss-tools
nss-util
ntp
ntpdate
ntsysv
numactl
obex-data-server
obexd
openct
openjpeg-libs
openldap
openobex
openssh
openssh-askpass
openssh-clients
openssh-server
openssl
orca
p11-kit
p11-kit-trust
pam
pam_passwdqc
pango
parted
passwd
pciutils
pciutils-libs
pcmciautils
pcre
pcsc-lite
pcsc-lite-libs
pcsc-lite-openct
perl
perl-Module-Pluggable
perl-Pod-Escapes
perl-Pod-Simple
perl-libs
perl-version
pinentry
pinfo
pixman
pkgconfig
plymouth
plymouth-core-libs
plymouth-gdm-hooks
plymouth-graphics-libs
plymouth-plugin-label
plymouth-plugin-two-step
plymouth-scripts
plymouth-system-theme
plymouth-theme-rings
plymouth-utils
pm-utils
policycoreutils
polkit
polkit-desktop-policy
polkit-gnome
poppler
poppler-data
poppler-glib
popt
postfix
ppp
prelink
procps
psacct
psmisc
pth
pulseaudio
pulseaudio-gdm-hooks
pulseaudio-libs
pulseaudio-libs-glib2
pulseaudio-module-bluetooth
pulseaudio-module-gconf
pulseaudio-module-x11
pulseaudio-utils
pycairo
pygobject2
pygpgme
pygtk2
pygtk2-libglade
pygtksourceview
pykickstart
pyorbit
pyparted
python
python-cryptsetup
python-decorator
python-deltarpm
python-dmidecode
python-ethtool
python-iniparse
python-iwlib
python-libs
python-meh
python-nss
python-pyblock
python-pycurl
python-slip
python-urlgrabber
pyxf86config
ql2100-firmware
ql2200-firmware
ql23xx-firmware
ql2400-firmware
ql2500-firmware
quota
rarian
rarian-compat
rdate
rdesktop
readahead
readline
redhat-bookmarks
redhat-logos
redhat-menus
rfkill
rng-tools
rootfiles
rpm
rpm-libs
rpm-python
rsync
rsyslog
rt61pci-firmware
rt73usb-firmware
rtkit
samba-common
samba-winbind
samba-winbind-clients
scl-utils
sed
selinux-policy
selinux-policy-targeted
setserial
setup
setuptool
sg3_utils-libs
sgml-common
sgpio
shadow-utils
shared-mime-info
slang
smartmontools
smp_utils
snappy
sos
sound-theme-freedesktop
speex
spice-vdagent
sqlite
squashfs-tools
startup-notification
strace
sudo
syslinux
syslinux-nonlinux
sysstat
system-config-date
system-config-date-docs
system-config-firewall-base
system-config-firewall-tui
system-config-keyboard
system-config-keyboard-base
system-config-network-tui
system-config-users
system-config-users-docs
system-gnome-theme
system-icon-theme
system-setup-keyboard
systemtap-runtime
sysvinit-tools
taglib
tar
tcp_wrappers
tcp_wrappers-libs
tcpdump
tcsh
thunderbird
tigervnc
tigervnc-server
time
tmpwatch
traceroute
tsclient
ttmkfdir
tzdata
udev
udisks
unique
unzip
upstart
urw-fonts
usbutils
usermode
usermode-gtk
ustr
util-linux-ng
vconfig
vim-common
vim-enhanced
vim-minimal
virt-what
vlgothic-fonts
vlgothic-fonts-common
vte
wavpack
wget
which
wireless-tools
wodim
words
wpa_supplicant
xcb-util
xdg-user-dirs
xdg-user-dirs-gtk
xdg-utils
xkeyboard-config
xml-common
xmlrpc-c
xmlrpc-c-client
xorg-x11-drivers
xorg-x11-drv-acecad
xorg-x11-drv-aiptek
xorg-x11-drv-apm
xorg-x11-drv-ast
xorg-x11-drv-ati
xorg-x11-drv-ati-firmware
xorg-x11-drv-cirrus
xorg-x11-drv-dummy
xorg-x11-drv-elographics
xorg-x11-drv-evdev
xorg-x11-drv-fbdev
xorg-x11-drv-fpit
xorg-x11-drv-geode
xorg-x11-drv-glint
xorg-x11-drv-hyperpen
xorg-x11-drv-i128
xorg-x11-drv-i740
xorg-x11-drv-intel
xorg-x11-drv-keyboard
xorg-x11-drv-mach64
xorg-x11-drv-mga
xorg-x11-drv-modesetting
xorg-x11-drv-mouse
xorg-x11-drv-mutouch
xorg-x11-drv-neomagic
xorg-x11-drv-nouveau
xorg-x11-drv-nv
xorg-x11-drv-openchrome
xorg-x11-drv-penmount
xorg-x11-drv-qxl
xorg-x11-drv-r128
xorg-x11-drv-rendition
xorg-x11-drv-s3virge
xorg-x11-drv-savage
xorg-x11-drv-siliconmotion
xorg-x11-drv-sis
xorg-x11-drv-sisusb
xorg-x11-drv-synaptics
xorg-x11-drv-tdfx
xorg-x11-drv-trident
xorg-x11-drv-v4l
xorg-x11-drv-vesa
xorg-x11-drv-vmmouse
xorg-x11-drv-vmware
xorg-x11-drv-void
xorg-x11-drv-voodoo
xorg-x11-drv-wacom
xorg-x11-drv-xgi
xorg-x11-font-utils
xorg-x11-fonts-misc
xorg-x11-glamor
xorg-x11-server-Xorg
xorg-x11-server-common
xorg-x11-server-utils
xorg-x11-utils
xorg-x11-xauth
xorg-x11-xinit
xorg-x11-xkb-utils
xulrunner
xvattr
xz
xz-libs
xz-lzma-compat
yelp
yum
yum-metadata-parser
yum-plugin-fastestmirror
yum-plugin-security
yum-utils
zd1211-firmware
zenity
zip
zlib

%end

%post

## default LiveCD user
LIVECD_USER="centoslive"

########################################################################
# Create a sub-script so the output can be captured
# Must change "$" to "\$" and "`" to "\`" to avoid shell quoting
########################################################################
cat > /root/post-install << EOF_post
#!/bin/bash

echo ###################################################################
echo ## Creating the livesys init script
echo ###################################################################

cat > /etc/rc.d/init.d/livesys << EOF_initscript
#!/bin/bash
#
# live: Init script for live image
#
# chkconfig: 345 00 99
# description: Init script for live image.

. /etc/init.d/functions

if ! strstr "\\\`cat /proc/cmdline\\\`" liveimg || [ "\\\$1" != "start" ]; then
    exit 0
fi

if [ -e /.liveimg-configured ] ; then
    configdone=1
fi


exists() {
    which \\\$1 >/dev/null 2>&1 || return
    \\\$*
}

touch /.liveimg-configured

# mount live image
if [ -b \\\`readlink -f /dev/live\\\` ]; then
   mkdir -p /mnt/live
   mount -o ro /dev/live /mnt/live 2>/dev/null || mount /dev/live /mnt/live
fi

livedir="LiveOS"
for arg in \\\`cat /proc/cmdline\\\` ; do
  if [ "\\\${arg##live_dir=}" != "\\\${arg}" ]; then
    livedir=\\\${arg##live_dir=}
    return
  fi
done

# enable swaps unless requested otherwise
swaps=\\\`blkid -t TYPE=swap -o device\\\`
if ! strstr "\\\`cat /proc/cmdline\\\`" noswap && [ -n "\\\$swaps" ] ; then
  for s in \\\$swaps ; do
    action "Enabling swap partition \\\$s" swapon \\\$s
  done
fi
if ! strstr "\\\`cat /proc/cmdline\\\`" noswap && [ -f /mnt/live/\\\${livedir}/swap.img ] ; then
  action "Enabling swap file" swapon /mnt/live/\\\${livedir}/swap.img
fi

mountPersistentHome() {
  # support label/uuid
  if [ "\\\${homedev##LABEL=}" != "\\\${homedev}" -o "\\\${homedev##UUID=}" != "\\\${homedev}" ]; then
    homedev=\\\`/sbin/blkid -o device -t "\\\$homedev"\\\`
  fi

  # if we're given a file rather than a blockdev, loopback it
  if [ "\\\${homedev##mtd}" != "\\\${homedev}" ]; then
    # mtd devs don't have a block device but get magic-mounted with -t jffs2
    mountopts="-t jffs2"
  elif [ ! -b "\\\$homedev" ]; then
    loopdev=\\\`losetup -f\\\`
    if [ "\\\${homedev##/mnt/live}" != "\\\${homedev}" ]; then
      action "Remounting live store r/w" mount -o remount,rw /mnt/live
    fi
    losetup \\\$loopdev \\\$homedev
    homedev=\\\$loopdev
  fi

  # if it's encrypted, we need to unlock it
  if [ "\\\$(/sbin/blkid -s TYPE -o value \\\$homedev 2>/dev/null)" = "crypto_LUKS" ]; then
    echo
    echo "Setting up encrypted /home device"
    plymouth ask-for-password --command="cryptsetup luksOpen \\\$homedev EncHome"
    homedev=/dev/mapper/EncHome
  fi

  # and finally do the mount
  mount \\\$mountopts \\\$homedev /home
  # if we have /home under what's passed for persistent home, then
  # we should make that the real /home.  useful for mtd device on olpc
  if [ -d /home/home ]; then mount --bind /home/home /home ; fi
  [ -x /sbin/restorecon ] && /sbin/restorecon /home
  if [ -d /home/\\\$LIVECD_USER ]; then USERADDARGS="-M" ; fi
}

findPersistentHome() {
  for arg in \\\`cat /proc/cmdline\\\` ; do
    if [ "\\\${arg##persistenthome=}" != "\\\${arg}" ]; then
      homedev=\\\${arg##persistenthome=}
      return
    fi
  done
}

if strstr "\\\`cat /proc/cmdline\\\`" persistenthome= ; then
  findPersistentHome
elif [ -e /mnt/live/\\\${livedir}/home.img ]; then
  homedev=/mnt/live/\\\${livedir}/home.img
fi

# if we have a persistent /home, then we want to go ahead and mount it
if ! strstr "\\\`cat /proc/cmdline\\\`" nopersistenthome && [ -n "\\\$homedev" ] ; then
  action "Mounting persistent /home" mountPersistentHome
fi

# make it so that we don't do writing to the overlay for things which
# are just tmpdirs/caches
mount -t tmpfs -o mode=0755 varcacheyum /var/cache/yum
mount -t tmpfs tmp /tmp
mount -t tmpfs vartmp /var/tmp
[ -x /sbin/restorecon ] && /sbin/restorecon /var/cache/yum /tmp /var/tmp >/dev/null 2>&1

if [ -n "\\\$configdone" ]; then
  exit 0
fi


## fix various bugs and issues
# unmute sound card
exists alsaunmute 0 2> /dev/null

# turn off firstboot for livecd boots
echo "RUN_FIRSTBOOT=NO" > /etc/sysconfig/firstboot

# turn off mdmonitor by default
chkconfig --level 345 mdmonitor       off 2>/dev/null

# turn off setroubleshoot on the live image to preserve resources
chkconfig --level 345 setroubleshoot  off 2>/dev/null

# don't start cron/at as they tend to spawn things which are
# disk intensive that are painful on a live image
chkconfig --level 345 auditd          off 2>/dev/null
chkconfig --level 345 crond           off 2>/dev/null
chkconfig --level 345 atd             off 2>/dev/null
chkconfig --level 345 readahead_early off 2>/dev/null
chkconfig --level 345 readahead_later off 2>/dev/null

# disable kdump service
chkconfig --level 345 kdump           off 2>/dev/null

# disable microcode_ctl service
chkconfig --level 345 microcode_ctl   off 2>/dev/null

# disable smart card services
chkconfig --level 345 openct          off 2>/dev/null
chkconfig --level 345 pcscd           off 2>/dev/null

# disable postfix service
chkconfig --level 345 postfix         off 2>/dev/null

# Stopgap fix for RH #217966; should be fixed in HAL instead
touch /media/.hal-mtab

# workaround clock syncing on shutdown that we don't want (#297421)
sed -i -e 's/hwclock/no-such-hwclock/g' /etc/rc.d/init.d/halt

# set the LiveCD hostname
sed -i -e 's/HOSTNAME=localhost.localdomain/HOSTNAME=livecd.centos/g' /etc/sysconfig/network
/bin/hostname livecd.centos

## create the LiveCD default user
# add default user with no password
/usr/sbin/useradd -c "LiveCD default user" $LIVECD_USER
/usr/bin/passwd -d $LIVECD_USER > /dev/null
# give default user sudo privileges
echo "$LIVECD_USER     ALL=(ALL)     NOPASSWD: ALL" >> /etc/sudoers

## configure default user's desktop
# set up timed auto-login at 10 seconds
cat >> /etc/gdm/custom.conf << FOE
[daemon]
TimedLoginEnable=true
TimedLogin=$LIVECD_USER
TimedLoginDelay=10
FOE

# add keyboard and display configuration utilities to the desktop
mkdir -p /home/$LIVECD_USER/Desktop >/dev/null
cp /usr/share/applications/gnome-keyboard.desktop           /home/$LIVECD_USER/Desktop/
cp /usr/share/applications/gnome-display-properties.desktop /home/$LIVECD_USER/Desktop/
cp /usr/share/applications/liveinst.desktop                 /home/$LIVECD_USER/Desktop/

### TOMOYO Linux start ###
mount -t tmpfs -o size=64m none /var/log/tomoyo/
chown centoslive:centoslive /usr/share/doc/tomoyo/media.centos6/*.desktop
mv /usr/share/doc/tomoyo/media.centos6/*.desktop /home/$LIVECD_USER/Desktop/
sed -i -e 's/"kernel"/"ccs-kernel"/' -- /usr/lib/anaconda/packages.py
### TOMOYO Linux end ###
# disable screensaver locking
gconftool-2 --direct --config-source=xml:readwrite:/etc/gconf/gconf.xml.defaults -s -t bool   /apps/gnome-screensaver/lock_enabled "false" >/dev/null

# disable PackageKit update checking by default
gconftool-2 --direct --config-source=xml:readwrite:/etc/gconf/gconf.xml.defaults -s -t int /apps/gnome-packagekit/update-icon/frequency_get_updates "0" >/dev/null

# Switching to Thunderbird as the default MUA
gconftool-2 --direct --config-source=xml:readwrite:/etc/gconf/gconf.xml.defaults --type string --set /desktop/gnome/url-handlers/mailto/command "thunderbird %" >/dev/null


# detecting disk partitions and logical volumes 
CreateDesktopIconHD()
{
cat > /home/$LIVECD_USER/Desktop/Local\ hard\ drives.desktop << EOF_HDicon
[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Link
Name=Local hard drives
Name[en_US]=Local hard drives
Name[fr_CA]=Disques durs locaux
URL=/mnt/disc
Icon=/usr/share/icons/gnome/32x32/devices/gnome-dev-harddisk.png
EOF_HDicon

chmod 755 /home/$LIVECD_USER/Desktop/Local\ hard\ drives.desktop
}

CreateDesktopIconLVM()
{
mkdir -p /home/$LIVECD_USER/Desktop >/dev/null

cat > /home/$LIVECD_USER/Desktop/Local\ logical\ volumes.desktop << EOF_LVMicon
[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Link
Name=Local logical volumes
Name[en_US]=Local logical volumes
Name[fr_CA]=Volumes logiques locaux
URL=/mnt/lvm
Icon=/usr/share/icons/gnome/32x32/devices/gnome-dev-harddisk.png
EOF_LVMicon

chmod 755 /home/$LIVECD_USER/Desktop/Local\ logical\ volumes.desktop
}

# don't mount disk partitions if 'nodiskmount' is given as a boot option
if ! strstr "\\\`cat /proc/cmdline\\\`" nodiskmount ; then
	MOUNTOPTION="ro"
	HARD_DISKS=\\\`egrep "[sh]d.\\\$" /proc/partitions | tr -s ' ' | sed 's/^  *//' | cut -d' ' -f4\\\`

	echo "Mounting hard disk partitions... "
	for DISK in \\\$HARD_DISKS; do
	    # Get the device and system info from fdisk (but only for fat and linux partitions).
	    FDISK_INFO=\\\`fdisk -l /dev/\\\$DISK | tr [A-Z] [a-z] | egrep "fat|linux" | egrep -v "swap|extended|lvm" | sed 's/*//' | tr -s ' ' | tr ' ' ':' | cut -d':' -f1,6-\\\`
	    for FDISK_ENTRY in \\\$FDISK_INFO; do
		PARTITION=\\\`echo \\\$FDISK_ENTRY | cut -d':' -f1\\\`
		MOUNTPOINT="/mnt/disc/\\\${PARTITION##/dev/}"
		mkdir -p \\\$MOUNTPOINT
		MOUNTED=FALSE

		# get the partition type
		case \\\`echo \\\$FDISK_ENTRY | cut -d':' -f2-\\\` in
		*fat*) 
		    FSTYPES="vfat"
		    EXTRAOPTIONS=",uid=500";;
		*)
		    FSTYPES="ext4 ext3 ext2"
		    EXTRAOPTIONS="";;
		esac

		# try to mount the partition
		for FSTYPE in \\\$FSTYPES; do
		    if mount -o "\\\${MOUNTOPTION}\\\${EXTRAOPTIONS}" -t \\\$FSTYPE \\\$PARTITION \\\$MOUNTPOINT &>/dev/null; then
			echo "\\\$PARTITION \\\$MOUNTPOINT \\\$FSTYPE noauto,\\\${MOUNTOPTION}\\\${EXTRAOPTIONS} 0 0" >> /etc/fstab
			echo -n "\\\$PARTITION "
			MOUNTED=TRUE
			CreateDesktopIconHD
		    fi
		done
		[ \\\$MOUNTED = "FALSE" ] && rmdir \\\$MOUNTPOINT
	    done
	done
	echo
fi

# don't mount logical volumes if 'nolvmmount' is given as a boot option
if ! strstr "\\\`cat /proc/cmdline\\\`" nolvmmount ; then
        MOUNTOPTION="ro"
	FSTYPES="ext4 ext3 ext2"
	echo "Scanning for logical volumes..."
	if ! lvm vgscan 2>&1 | grep "No volume groups"; then
	    echo "Activating logical volumes ..."
	    modprobe dm_mod >/dev/null
	    lvm vgchange -ay
	    LOGICAL_VOLUMES=\\\`lvm lvdisplay -c | sed "s/^  *//" | cut -d: -f1\\\`
	    if [ ! -z "\\\$LOGICAL_VOLUMES" ]; then
		echo "Making device nodes ..."
		lvm vgmknodes
		echo -n "Mounting logical volumes ... "
		for VOLUME_NAME in \\\$LOGICAL_VOLUMES; do
		    VG_NAME=\\\`echo \\\$VOLUME_NAME | cut -d/ -f3\\\`
		    LV_NAME=\\\`echo \\\$VOLUME_NAME | cut -d/ -f4\\\`
		    MOUNTPOINT="/mnt/lvm/\\\${VG_NAME}-\\\${LV_NAME}"
		    mkdir -p \\\$MOUNTPOINT

		    MOUNTED=FALSE
		    for FSTYPE in \\\$FSTYPES; do
			if mount -o \\\$MOUNTOPTION -t \\\$FSTYPE \\\$VOLUME_NAME \\\$MOUNTPOINT &>/dev/null; then
			    echo "\\\$VOLUME_NAME \\\$MOUNTPOINT \\\$FSTYPE defaults,\\\${MOUNTOPTION} 0 0" >> /etc/fstab
			    echo -n "\\\$VOLUME_NAME "
			    MOUNTED=TRUE
			    CreateDesktopIconLVM
			    break
			fi
		    done
		    [ \\\$MOUNTED = FALSE ] && rmdir \\\$MOUNTPOINT
		done
		echo

	    else
		echo "No logical volumes found"
	    fi
	fi
fi


# give back ownership to the default user
chown -R $LIVECD_USER:$LIVECD_USER /home/$LIVECD_USER
EOF_initscript


# bah, hal starts way too late
cat > /etc/rc.d/init.d/livesys-late << EOF_lateinitscript
#!/bin/bash
#
# live: Late init script for live image
#
# chkconfig: 345 99 01
# description: Late init script for live image.

. /etc/init.d/functions

if ! strstr "\\\`cat /proc/cmdline\\\`" liveimg || [ "\\\$1" != "start" ] || [ -e /.liveimg-late-configured ] ; then
    exit 0
fi

exists() {
    which \\\$1 >/dev/null 2>&1 || return
    \\\$*
}

touch /.liveimg-late-configured

# read some variables out of /proc/cmdline
for o in \\\`cat /proc/cmdline\\\` ; do
    case \\\$o in
    ks=*)
        ks="\\\${o#ks=}"
        ;;
    xdriver=*)
        xdriver="--set-driver=\\\${o#xdriver=}"
        ;;
    esac
done

# if liveinst or textinst is given, start anaconda
if strstr "\\\`cat /proc/cmdline\\\`" liveinst ; then
   plymouth --quit
   /usr/sbin/liveinst \\\$ks
fi
if strstr "\\\`cat /proc/cmdline\\\`" textinst ; then
   plymouth --quit
   /usr/sbin/liveinst --text \\\$ks
fi

# configure X, allowing user to override xdriver
if [ -n "\$xdriver" ]; then
    exists system-config-display --noui --reconfig --set-depth=24 \\\$xdriver
fi

# Fix the "liveinst doesn't start in gui mode when not enough memory available" - switching to terminal mode
sed -i "s/Terminal=false/Terminal=true/" /home/$LIVECD_USER/Desktop/liveinst.desktop

EOF_lateinitscript

# workaround avahi segfault (#279301)
touch /etc/resolv.conf
/sbin/restorecon /etc/resolv.conf

chmod 755 /etc/rc.d/init.d/livesys
/sbin/restorecon /etc/rc.d/init.d/livesys
/sbin/chkconfig --add livesys

chmod 755 /etc/rc.d/init.d/livesys-late
/sbin/restorecon /etc/rc.d/init.d/livesys-late
/sbin/chkconfig --add livesys-late

# go ahead and pre-make the man -k cache (#455968)
/usr/sbin/makewhatis -w

# save a little bit of space at least...
rm -f /var/lib/rpm/__db*
rm -f /boot/initrd*
rm -f /boot/initramfs*
# make sure there aren't core files lying around
rm -f /core*

# convince readahead not to collect
rm -f /.readahead_collect
touch /var/lib/readahead/early.sorted


### TOMOYO Linux start ###
# Initialize policy configuration.
export PATH=/sbin:/bin:$PATH
/usr/lib/ccs/init_policy --use_profile=1 --use_group=0
# Install tutorial documents.
cd /usr/share/doc/
mkdir tomoyo/
cd tomoyo/
mv /etc/hosts /etc/hosts.tmp
#export http_proxy=http://proxy:port/
echo '202.221.179.21 sourceforge.jp' > /etc/hosts
echo '202.221.179.25 svn.sourceforge.jp' >> /etc/hosts
wget -O centos6-live.html.en 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/centos6-live.html.en?revision=HEAD&root=tomoyo'
wget -O centos6-live.html.ja 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/centos6-live.html.ja?revision=HEAD&root=tomoyo'
wget -O - 'http://sourceforge.jp/projects/tomoyo/svn/view/tags/htdocs/1.8/media.centos6.tar.gz?root=tomoyo&view=tar' | tar -zxf -
mv /etc/hosts.tmp /etc/hosts
ln -s centos6-live.html.en index.html.en
ln -s centos6-live.html.ja index.html.ja
# Create directory for audit logs.
mkdir -p -m 700 /var/log/tomoyo
echo /usr/sbin/ccs-auditd >> /etc/rc.d/rc.local
# Import PGP key for ccs-kernel and ccs-tools packages.
cat > kumaneko-key << EOF_kumaneko_key
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

mQGiBFHikAQRBAC6MyO7E4kf9CAvaeu1oMB6WlTmI47smeDGeoFFnCmfYaodQKoE
IioOgiKDZg18GiT+3IHVzeX37v/e0IeVhrAfX7ksnN740NwJNNiaSJu6UueQ3ngw
v/oHaSJdIgEBvTA+dgZuj0AQL4acb27AQSv+x3MPmvxdQX7W3UJO9fiYMwCgmtmO
a4/qOym3JZrbBbEveuuIVncD/AhNn/Nl2hr92vX9WzS+asgUOlNqGuaNVAuc5418
UpDfe0w03756UkLxhPCnGoCCZbOUq531FvoFZSElV1HG0/lP2OGEdH3X2oxorVGd
SG08l1MofRKenZOSnaKBKCSNoQr55b5okwr+eShuEmd3K/0uxHurfuw8aoeNwKQT
ifFIBACrY+LYXR08vMUYdYZlsFtPdHl9nu9ri46U/s1m1iX0ytUnZTf4P8S7pu70
hG9Scc8+cKCx3rLQEsSCeAs+gMwaRwHxLoiKr7Wg1LAfHeOde4tB11R/5YYvP/c4
4Ff7QSDdetS5Fy8Lq/lHwOiqlbcTlMCrD5/g1fXepoj+CZ1UwbRxVGV0c3VvIEhh
bmRhIChmb3Igb2xkZXIgdmVyc2lvbnMgb2YgUlBNIHdoaWNoIGNhbm5vdCBoYW5k
bGUgNDA5NmJpdCBSU0Ega2V5KSA8cGVuZ3Vpbi1rZXJuZWxASS1sb3ZlLlNBS1VS
QS5uZS5qcD6IaAQTEQIAKAUCUeKQBAIbAwUJCV4YgAYLCQgHAwIGFQgCCQoLBBYC
AwECHgECF4AACgkQs3859v15c0eWbwCggVloUNaHxkrF02VYmzp/LN3dJ3sAoJJo
DpMyNB4G441x+Tdgvi0+/brF
=fT9Z
-----END PGP PUBLIC KEY BLOCK-----
EOF_kumaneko_key
rpm --import kumaneko-key
rm -f kumaneko-key
# Enable YUM repository for ccs-kernel and ccs-tools packages.
cat > /etc/yum.repos.d/ccs.repo << EOF_ccs_repo 
[ccs]
name=TOMOYO Linux kernels and tools
baseurl=http://tomoyo.sourceforge.jp/repos-1.8/CentOS6/
enabled=1
gpgcheck=1
EOF_ccs_repo
# Import PGP key for flash-plugin package.
cat > adobe-key << EOF_adobe_key
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.2.6 (GNU/Linux)

mQGiBEXlsbkRBACdGA0PaNHSYxn9K5SPo5e7mEsVpl37Xm7F2m1nTIMLq2v/IT8Z
bhLhVXTCR9amFRR4qV+AN6SJeXEYeMrZW/7TiMkULfkoThrtTF/spUK5/HvTGgqh
iGVbBQfqx65mboeXNQwLGXSBCtA7zA2PM/E0oLwpEuJidAodsQLKNQIKWwCgxDq8
wz0/jcqyIULCYasHmz56dFsD/2Ye27k52I1TRT3EvBIjOkmNfic8rkkoJfuTFRFM
Ivb+jot1Y6JltCHjqgwGmBi3hPJjOxti0yO1s82m9RKBKzKNGl4/yp4QI6mftK0x
F0U8RW5kD7oKD5jYGU6ZZuivZ9SpBg7PdEFXzTTYXwrBD3/W0AkXB/mGSlO4cA9f
GsUuA/97tCsspIJKTuKLrt82heu9BUk7Uq56fB2HGjrwAlPgKAR9ajuXjdNwfEOS
928kKP544YE5U3pL1J4INEjgzeAiKjtK7npxOVj7clXvO8bi1D3IjJe1NtF2gGbt
+gmi38fDqj8iox43ihNbiib3od8GFu30wmr0uJCQC2cEF+paw7RFQWRvYmUgU3lz
dGVtcyBJbmNvcnBvcmF0ZWQgKExpbnV4IFJQTSBTaWduaW5nIEtleSkgPHNlY3Vy
ZUBhZG9iZS5jb20+iF4EExECAB4FAkXlsbkCGwMGCwkIBwMCAxUCAwMWAgECHgEC
F4AACgkQOmm9JPZ3fGe6bgCfRyDO0U8iQM5kHs6kesgio556JPUAoJw5ta+DACp2
SbHaG7wwEVOZQBdeuQINBEXlsb4QCACPQRsfdoPMxwACfGh9hc6toEctrLNbzmz0
W6tDKBWmbUm5c0RMKSBOHWBQtVhtS6XI2eIPB8XPKoz0uXaeqSYoZaG/vol1mUVz
ovVQa16yOHjzwK9VaQ1OxwF2UQ77amI1mT06FBuvu9xw/qyzCQiEqv6mXHp3yw8p
yU4n99Jc+B5M3Qs2Ppx8DRu31uM+jW6WIxP5uFWwFty1zftqTFrfbU6DXsJsAdto
FnzcbUaweK7Ibd03jdLzibkztrXKb4VasW92RlkCucJU2CaYXpW8CCBJnZ+hzvJp
RMp1YKBCcgWCm743pjpRtY5aPMl+5hBAuBsAJ+odLNM2LlWeWbzjAAMFB/44U5sJ
WDveeN1drH+WCCMNO83Ixv3i8YAxJgtArQZ36MHauRrAQQLjzjC78YHzeydixoeM
iBPvCpqz+kggxl2Nk2YyLIzzuP4BkZuusb46QvEO3FVHGeMNJnF7phbyg5/wE8gS
/KjlbiAQ8sDQ/ddDQbJfpgxQT5dBou3lcjrD7L5xJokDFJUoQ3w9N0Wnk96YgtFY
rdw0qXm/s5bnes4udSmwheGsKyvaP0r+ahfznQGJlNOxsqNWLGESyA79lnf3Hs79
8Tr3n4rqBkecRVdHzLFtzI+mRmwRtQETMr7SL6vRD4c1Vq7aZMuRQ0kgeDP38v7z
D+Er8IEvnKgfHdMIiEkEGBECAAkFAkXlsb4CGwwACgkQOmm9JPZ3fGcL8QCgwyz3
RWeAGeteAaS6ksAkKtLti/IAoKU5fzzgfcGUfIuyWqPIUAu906XA
=QO07
-----END PGP PUBLIC KEY BLOCK-----
EOF_adobe_key
rpm --import adobe-key
rm -f adobe-key
# Enable YUM repository for flash-plugin package.
cat > /etc/yum.repos.d/adobe-linux-i386.repo << EOF_adobe_repo
[adobe-linux-i386]
name=Adobe Systems Incorporated
baseurl=http://linuxdownload.adobe.com/linux/i386/
enabled=1
gpgcheck=1
EOF_adobe_repo
# Create symbolic link needed for Mozilla.
ln -s /usr/lib/flash-plugin/libflashplayer.so /usr/lib/mozilla/plugins-wrapped/
# Clean up.
rm -f /var/log/yum.log
rm -fR /var/lib/yum/*/
rm -fR /var/tmp/*/
rm -f /var/lib/rpm/__db.00*
rm -f /boot/initramfs-*
rm -f /root/.bash_history
cat /dev/zero > /file || rm -f /file
### TOMOYO Linux end ###
EOF_post

/bin/bash -x /root/post-install 2>&1 | tee /root/post-install.log

%end

%post --nochroot

########################################################################
# Create a sub-script so the output can be captured
# Must change "$" to "\$" and "`" to "\`" to avoid shell quoting
########################################################################
cat > /root/postnochroot-install << EOF_postnochroot
#!/bin/bash

# Copy licensing information
cp $INSTALL_ROOT/usr/share/doc/*-release-*/GPL $LIVE_ROOT/GPL

# add livecd-iso-to-disk utility on the LiveCD
# only works on x86, x86_64
if [ "\$(uname -i)" = "i386" -o "\$(uname -i)" = "x86_64" ]; then
  if [ ! -d \$LIVE_ROOT/LiveOS ]; then mkdir -p \$LIVE_ROOT/LiveOS ; fi
  cp /usr/bin/livecd-iso-to-disk \$LIVE_ROOT/LiveOS
fi

# customize boot menu entries
grep -B4 'menu default'  \$LIVE_ROOT/isolinux/isolinux.cfg > \$LIVE_ROOT/isolinux/default.txt
grep -B3 'xdriver=vesa'  \$LIVE_ROOT/isolinux/isolinux.cfg > \$LIVE_ROOT/isolinux/basicvideo.txt
grep -A3 'label check0'  \$LIVE_ROOT/isolinux/isolinux.cfg > \$LIVE_ROOT/isolinux/check.txt
grep -A2 'label memtest' \$LIVE_ROOT/isolinux/isolinux.cfg > \$LIVE_ROOT/isolinux/memtest.txt
grep -A2 'label local'   \$LIVE_ROOT/isolinux/isolinux.cfg > \$LIVE_ROOT/isolinux/localboot.txt

sed "s/label linux0/label linuxtext0/"   \$LIVE_ROOT/isolinux/default.txt > \$LIVE_ROOT/isolinux/textboot.txt
sed -i "s/Boot/Boot (Text Mode)/"                                           \$LIVE_ROOT/isolinux/textboot.txt
sed -i "s/liveimg/liveimg 3/"                                               \$LIVE_ROOT/isolinux/textboot.txt
sed -i "/menu default/d"                                                    \$LIVE_ROOT/isolinux/textboot.txt

sed "s/label linux0/label install0/"     \$LIVE_ROOT/isolinux/default.txt > \$LIVE_ROOT/isolinux/install.txt
sed -i "s/Boot/Install/"                                                    \$LIVE_ROOT/isolinux/install.txt
sed -i "s/liveimg/liveimg liveinst noswap nolvmmount/"                      \$LIVE_ROOT/isolinux/install.txt
sed -i "s/ quiet / /"                                                       \$LIVE_ROOT/isolinux/install.txt
sed -i "s/ rhgb / /"                                                        \$LIVE_ROOT/isolinux/install.txt
sed -i "/menu default/d"                                                    \$LIVE_ROOT/isolinux/install.txt

sed "s/label linux0/label textinstall0/" \$LIVE_ROOT/isolinux/default.txt > \$LIVE_ROOT/isolinux/textinstall.txt
sed -i "s/Boot/Install (Text Mode)/"                                        \$LIVE_ROOT/isolinux/textinstall.txt
sed -i "s/liveimg/liveimg textinst noswap nolvmmount/"                      \$LIVE_ROOT/isolinux/textinstall.txt
sed -i "s/ quiet / /"                                                       \$LIVE_ROOT/isolinux/textinstall.txt
sed -i "s/ rhgb / /"                                                        \$LIVE_ROOT/isolinux/textinstall.txt
sed -i "/menu default/d"                                                    \$LIVE_ROOT/isolinux/textinstall.txt

cat \$LIVE_ROOT/isolinux/default.txt \$LIVE_ROOT/isolinux/basicvideo.txt \$LIVE_ROOT/isolinux/check.txt \$LIVE_ROOT/isolinux/memtest.txt \$LIVE_ROOT/isolinux/localboot.txt > \$LIVE_ROOT/isolinux/current.txt
diff \$LIVE_ROOT/isolinux/isolinux.cfg \$LIVE_ROOT/isolinux/current.txt | sed '/^[0-9][0-9]*/d; s/^. //; /^---$/d' > \$LIVE_ROOT/isolinux/cleaned.txt
cat \$LIVE_ROOT/isolinux/cleaned.txt \$LIVE_ROOT/isolinux/default.txt \$LIVE_ROOT/isolinux/textboot.txt \$LIVE_ROOT/isolinux/basicvideo.txt \$LIVE_ROOT/isolinux/install.txt \$LIVE_ROOT/isolinux/textinstall.txt \$LIVE_ROOT/isolinux/memtest.txt \$LIVE_ROOT/isolinux/localboot.txt > \$LIVE_ROOT/isolinux/isolinux.cfg
rm -f \$LIVE_ROOT/isolinux/*.txt

# Forcing plymouth to show the logo in vesafb 
sed -i "s/rhgb/rhgb vga=791/g"	\$LIVE_ROOT/isolinux/isolinux.cfg

# Disabling auto lvm/disk mount (that will crash the "Install to Hard Drive feature")
sed -i "s/quiet/quiet nodiskmount nolvmmount/g"	\$LIVE_ROOT/isolinux/isolinux.cfg

# Forcing tsc_init_debug to be enabled
sed -i "s/rhgb/rhgb tsc_init_debug/g"	\$LIVE_ROOT/isolinux/isolinux.cfg

EOF_postnochroot

/bin/bash -x /root/postnochroot-install 2>&1 | tee /root/postnochroot-install.log

%end
