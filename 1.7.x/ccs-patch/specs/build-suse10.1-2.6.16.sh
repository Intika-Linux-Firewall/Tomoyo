#! /bin/sh
#
# This is a kernel build script for openSUSE 10.1's 2.6.16 kernel.
#

die () {
    echo $1
    exit 1
}

cd /usr/lib/rpm/ || die "Can't chdir to /usr/lib/rpm/ ."

if ! grep -q ccs-kernel find-supplements.ksyms
then
	patch << "EOF" || die "Can't patch find-supplements.ksyms ."
--- find-supplements.ksyms
+++ find-supplements.ksyms
@@ -5,6 +5,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel-*)     is_kernel_package=1 ;;
 kernel-*)	   is_kernel_package=1 ;;
 esac
 
EOF
fi

if ! grep -q ccs-kernel find-requires.ksyms
then
	patch << "EOF" || die "Can't patch find-requires.ksyms ."
--- find-requires.ksyms
+++ find-requires.ksyms
@@ -5,11 +5,12 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel-*)      is_kernel_package=1 ;;
 kernel-*)	    is_kernel_package=1 ;;
 esac
 
 all_provides() {
-    nm "$@" \
+    for module in "$@"; do nm -- $module; done \
     | sed -r -ne 's:^0*([0-9a-f]+) A __crc_(.+):\1\t\2:p' \
     | sort -k2 -u
 }
EOF
fi

if ! grep -q ccs-kernel find-provides.ksyms
then
	patch << "EOF" || die "Can't patch find-provides.ksyms ."
--- find-provides.ksyms
+++ find-provides.ksyms
@@ -5,6 +5,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel-*)      is_kernel_package=1 ;;
 kernel-*)	    is_kernel_package=1 ;;
 esac
 
EOF
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-source-2.6.16.54-0.2.5.src.rpm ]
then
    wget http://suse.inode.at/pub/update/10.1/rpm/src/kernel-source-2.6.16.54-0.2.5.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-source-2.6.16.54-0.2.5.src.rpm || die "Can't verify signature."
rpm -ivh kernel-source-2.6.16.54-0.2.5.src.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20100412.tar.gz ]
then
    wget http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20100412.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SOURCES/kernel-smp.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-smp.spec
+++ kernel-smp.spec
@@ -10,7 +10,7 @@
 
 # norootforbuild
 
-Name:           kernel-smp
+Name:           ccs-kernel-smp
 Url:            http://www.kernel.org/
 %define build_kdump %([ smp != kdump ] ; echo $?)
 %define build_xen %(case smp in (xen*) echo 1;; (*) echo 0;; esac)
@@ -20,7 +20,7 @@
 BuildRequires:  python
 %endif
 Version:        2.6.16.54
-Release: 0.2.5
+Release: 0.2.5_tomoyo_1.7.2
 Summary:        Kernel with Multiprocessor Support
 License:        GPL v2 or later
 Group:          System/Kernel
@@ -136,7 +136,7 @@
 %define tolerate_unknown_new_config_options 0
 # kABI change tolerance (default in maintenance should be 4, 6, 8 or 15;
 # see scripts/kabi-checks)
-%define tolerate_kabi_changes 6
+%define tolerate_kabi_changes 31
 %(chmod +x %_sourcedir/{arch-symbols,guards,config-subst,check-for-config-changes,check-supported-list,built-in-where,find-provides,make-symsets,find-types,kabi-checks,install-configs})
 
 %description
@@ -225,6 +225,10 @@
 %build
 source .rpm-defs
 cd linux-2.6.16
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.2-20100412.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.16-suse-10.1.diff
+cat config.ccs >> .config
 cp .config .config.orig
 %if %{tolerate_unknown_new_config_options}
 MAKE_ARGS="$MAKE_ARGS -k"
EOF
sed -e 's:^Provides:#Provides:' -e 's:^Obsoletes:#Obsoletes:' kernel-smp.spec > ccs-kernel.spec || die "Can't edit spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
echo "I'll start 'rpmbuild -bb --target i586 /tmp/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target i586 /tmp/ccs-kernel.spec
exit 0
