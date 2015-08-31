#!/bin/bash -x
set -e

DOWNLOAD_DIR="${HOME}/sources"

URL_CCS="http://osdn.jp/frs/redir.php?f=/tomoyo/49684"
URL_CCS_SVN="http://osdn.jp/projects/tomoyo/svn/view/trunk/1.8.x/ccs-patch/patches"
URL_KERNEL="http://mirror.bytemark.co.uk/fedora/linux/updates/17/SRPMS"

ARCH="$(uname -m)"
CCS_VER="1.8.3p7"
CCS_PATCH_VER="1.8.3-20120915"
KERNEL_VER="3.6.1-1.fc17"

CCS_DIFF_NAME="ccs-patch-3.6.diff"

UPDATED_DIFF=0
#CCS_DIFF_REVISION="ccs-patch-2.6.40-fedora-15.diff?revision=5320&root=tomoyo"

rm -rf "${HOME}/rpmbuild"
rpmdev-setuptree
rm -rf "${HOME}/rpmbuild/SOURCES"
ln -sf "${DOWNLOAD_DIR}/ccs-kernel-${KERNEL_VER}" ${HOME}/rpmbuild/SOURCES

if [[ ! -d "${DOWNLOAD_DIR}/ccs-kernel-${KERNEL_VER}" ]]; then
	mkdir -p "${DOWNLOAD_DIR}/ccs-kernel-${KERNEL_VER}"
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
@@ -23,7 +23,7 @@ Summary: The Linux kernel
 #
 # (Uncomment the '#' and both spaces below to set the buildid.)
 #
-# % define buildid .local
+%define buildid _tomoyo_${CCS_VER}
 ###################################################################
 
 # The buildid can also be specified on the rpmbuild command line
@@ -109,7 +109,7 @@ Summary: The Linux kernel
 # kernel-PAE (only valid for i686)
 %define with_pae       %{?_without_pae:       0} %{?!_without_pae:       1}
 # kernel-debug
-%define with_debug     %{?_without_debug:     0} %{?!_without_debug:     1}
+%define with_debug     %{?_without_debug:     1} %{?!_without_debug:     0}
 # kernel-doc
 %define with_doc       %{?_without_doc:       0} %{?!_without_doc:       1}
 # kernel-headers
@@ -117,7 +117,7 @@ Summary: The Linux kernel
 # perf
-%define with_perf      %{?_without_perf:      0} %{?!_without_perf:      1}
+%define with_perf      %{?_without_perf:      1} %{?!_without_perf:      0}
 # tools
-%define with_tools     %{?_without_tools:     0} %{?!_without_tools:     1}
+%define with_tools     %{?_without_tools:     1} %{?!_without_tools:     0}
 # kernel-debuginfo
 %define with_debuginfo %{?_without_debuginfo: 0} %{?!_without_debuginfo: 1}
 # kernel-bootwrapper (for creating zImages from kernel + initrd)
@@ -511,7 +511,7 @@ AutoReq: no\
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -592,6 +592,10 @@ Source1000: config-local
 Source2000: cpupower.service
 Source2001: cpupower.config
 
+
+Source99998: ${CCS_DIFF_NAME}
+Source99999: ccs-patch-${CCS_PATCH_VER}.tar.gz
+
 # Here should be only the patches up to the upstream canonical Linus tree.
 
 # For a stable release kernel
@@ -985,7 +988,7 @@ Provides: kernel-devel-uname-r = %{KVERR
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
 Requires: perl\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -1004,7 +1007,7 @@ Provides: kernel-modules-extra = %{versi
 Provides: kernel-modules-extra-uname-r = %{KVERREL}%{?1:.%{1}}\
 Requires: kernel-uname-r = %{KVERREL}%{?1:.%{1}}\
 AutoReqProv: no\
-%description -n kernel%{?variant}%{?1:-%{1}}-modules-extra\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-modules-extra\
 This package provides less commonly used kernel modules for the %{?2:%{2} }kernel package.\
 %{nil}
 
@@ -1571,6 +1574,10 @@ ApplyPatch rtlwifi-fix-for-race-conditio
 
 %endif
 
+# TOMOYO Linux
+tar -zxf  %_sourcedir/ccs-patch-${CCS_PATCH_VER}.tar.gz
+patch -sp1 < patches/${CCS_DIFF_NAME}
+
 # Any further pre-build tree manipulations happen here.
 
 chmod +x scripts/checkpatch.pl
@@ -1598,6 +1605,18 @@ rm -f kernel-%{version}-*debug.config
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux 2.5
+  sed -i -e 's/# CONFIG_SECURITY_PATH is not set/CONFIG_SECURITY_PATH=y/' -- .config
+  sed -i -e 's/# CONFIG_SECURITY_TOMOYO is not set/CONFIG_SECURITY_TOMOYO=y/' -- .config
+  echo 'CONFIG_SECURITY_TOMOYO_MAX_ACCEPT_ENTRY=2048' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_MAX_AUDIT_LOG=1024' >> .config
+  echo '# CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER is not set' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_POLICY_LOADER="/sbin/tomoyo-init"' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_ACTIVATION_TRIGGER="/sbin/init"' >> .config
+  echo '# CONFIG_DEFAULT_SECURITY_TOMOYO is not set' >> .config
+  # TOMOYO Linux 1.8  
+  cat config.ccs >> .config
+  sed -i -e "s/CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch listnewconfig | grep -E '^CONFIG_' >.newoptions || true
 %if %{listnewconfig_fail}
EOF
}
 
# Before applying the patch, replace the placeholder variables with the real values.
if [[ "${UPDATED_DIFF}" = 0 ]]; then
	cat_patch | sed \
		-e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#Source99998.*##g" \
		-e "s#\${CCS_PATCH_VER}#${CCS_PATCH_VER}#g" \
		-e "s#patches/\${CCS_DIFF_NAME}#patches/${CCS_DIFF_NAME}#g" \
		| patch
elif [[ "${UPDATED_DIFF}" = 1 ]]; then
	cat_patch | sed \
		-e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#Source99998: \${CCS_DIFF_NAME}#Source99998: ${CCS_DIFF_NAME}#g" \
		-e "s#\${CCS_PATCH_VER}#${CCS_PATCH_VER}#g" \
		-e "s#patches/\${CCS_DIFF_NAME}#%_sourcedir/${CCS_DIFF_NAME}#g" \
		| patch
fi

rpmbuild -bs "${HOME}/rpmbuild/SPECS/ccs-kernel.spec"
