#!/bin/bash -x
set -e

DOWNLOAD_DIR="${HOME}/sources"

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684"
URL_CCS_SVN="http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.8.x/ccs-patch/patches"
#URL_KERNEL="http://www.mirrorservice.org/sites/ftp.scientificlinux.org/linux/scientific/6.1/SRPMS/vendor"
URL_KERNEL="ftp://ftp.redhat.com/pub/redhat/linux/enterprise/6Server/en/os/SRPMS/"

ARCH="$(uname -m)"
CCS_VER="1.8.3p4"
CCS_PATCH_VER="1.8.3-20111213"
KERNEL_VER="2.6.32-220.2.1.el6"

CCS_DIFF_NAME="ccs-patch-2.6.32-centos-6.2.diff"

UPDATED_DIFF=0
#CCS_DIFF_REVISION="ccs-patch-2.6.32-centos-6.1.diff?view=co&revision=5710&root=tomoyo&pathrev=5710"

rm -rf "${HOME}/rpmbuild"
rpmdev-setuptree
rm -rf "${HOME}/rpmbuild/SOURCES"
ln -sf "${DOWNLOAD_DIR}/ccs-kernel-${KERNEL_VER}" ${HOME}/rpmbuild/SOURCES

if [[ ! -d "${DOWNLOAD_DIR}/ccs-kernel-${KERNEL_VER}" ]]; then
	mkdir "${DOWNLOAD_DIR}/ccs-kernel-${KERNEL_VER}"
fi
cd "${DOWNLOAD_DIR}/ccs-kernel-${KERNEL_VER}"

if [[ ! -e "ccs-patch-${CCS_PATCH_VER}.tar.gz" ]]; then
	wget "${URL_CCS}/ccs-patch-${CCS_PATCH_VER}.tar.gz" \
		-O "ccs-patch-${CCS_PATCH_VER}.tar.gz"
fi

if [[ "${UPDATED_DIFF}" = 1 ]]; then
	if [[ ! -e "${CCS_DIFF_NAME}" ]]; then
		wget "${URL_CCS_SVN}/${CCS_DIFF_REVISION}" -O "${CCS_DIFF_NAME}"
	fi
fi

if [[ ! -e "kernel-${KERNEL_VER}.src.rpm" ]]; then
	if [[ ! -e "kernel-${KERNEL_VER}.src.rpm" ]]; then
		wget "${URL_KERNEL}/kernel-${KERNEL_VER}.src.rpm" \
			-O "kernel-${KERNEL_VER}.src.rpm"
	fi
fi

rpm -ivh "kernel-${KERNEL_VER}.src.rpm"

cd "${HOME}/rpmbuild/SPECS"
cp -v "kernel.spec" "ccs-kernel.spec"

cat_patch() {
	cat << 'EOF'
--- ccs-kernel.spec
+++ ccs-kernel.spec
@@ -15,7 +15,7 @@
 # that the kernel isn't the stock distribution kernel, for example,
 # by setting the define to ".local" or ".bz123456"
 #
-# % define buildid .local
+%define buildid _tomoyo_${CCS_VER}
 
 %define rhel 1
 %if %{rhel}
@@ -94,7 +94,7 @@
 # kernel-kdump
 %define with_kdump     %{?_without_kdump:     0} %{?!_without_kdump:     1}
 # kernel-debug
-%define with_debug     %{?_without_debug:     0} %{?!_without_debug:     1}
+%define with_debug     %{?_without_debug:     1} %{?!_without_debug:     0}
 # kernel-doc
 %define with_doc       %{?_without_doc:       0} %{?!_without_doc:       1}
 # kernel-headers
@@ -102,7 +102,7 @@
 # kernel-firmware
 %define with_firmware  %{?_with_firmware:     1} %{?!_with_firmware:     0}
 # perf noarch subpkg
-%define with_perf      %{?_without_perf:      0} %{?!_without_perf:      1}
+%define with_perf      %{?_without_perf:      1} %{?!_without_perf:      0}
 # kernel-debuginfo
 %define with_debuginfo %{?_without_debuginfo: 0} %{?!_without_debuginfo: 1}
 # kernel-bootwrapper (for creating zImages from kernel + initrd)
@@ -451,7 +451,7 @@
 # Packages that need to be installed before the kernel is, because the %post
 # scripts use them.
 #
-%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, kernel-firmware >= %{rpmversion}-%{pkg_release}, grubby >= 7.0.4-1
+%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, grubby >= 7.0.4-1
 %if %{with_dracut}
 %define initrd_prereq  dracut-kernel >= 002-18.git413bcf78
 %else
@@ -487,7 +487,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -601,6 +601,9 @@
 Source82: config-generic
 Source83: config-x86_64-debug-rhel
 
+Source99998: ${CCS_DIFF_NAME}
+Source99999: ccs-patch-${CCS_PATCH_VER}.tar.gz
+
 # empty final patch file to facilitate testing of kernel patches
 Patch999999: linux-kernel-test.patch
 
@@ -727,7 +729,7 @@
 Provides: kernel-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -893,6 +895,10 @@
 
 ApplyOptionalPatch linux-kernel-test.patch
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-${CCS_PATCH_VER}.tar.gz
+patch -sp1 < patches/${CCS_DIFF_NAME}
+
 # Any further pre-build tree manipulations happen here.
 
 chmod +x scripts/checkpatch.pl
@@ -917,6 +923,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e "s/CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch %{oldconfig_target} > /dev/null
   echo "# $Arch" > configs/$i
EOF
}

# Before applying the patch, replace the placeholder variables with the real values.
if [[ "${UPDATED_DIFF}" = 0 ]]; then
	cat_patch | sed \
		-e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#Source99998.*##g" \
		-e "s#\${CCS_PATCH_VER}#${CCS_PATCH_VER}#g" \
		-e "s#patches/\${CCS_DIFF_NAME}#patches/${CCS_DIFF_NAME}#g" \
		| patch -Np0
elif [[ "${UPDATED_DIFF}" = 1 ]]; then
	cat_patch | sed \
		-e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#Source99998: \${CCS_DIFF_NAME}#Source99998: ${CCS_DIFF_NAME}#g" \
		-e "s#\${CCS_PATCH_VER}#${CCS_PATCH_VER}#g" \
		-e "s#patches/\${CCS_DIFF_NAME}#%_sourcedir/${CCS_DIFF_NAME}#g" \
		| patch -Np0
fi

rpmbuild -bs "${HOME}/rpmbuild/SPECS/ccs-kernel.spec"
