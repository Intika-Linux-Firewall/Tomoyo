#!/bin/bash

. ./global_functions

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684"
URL_CCS_SVN="http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.8.x/ccs-patch/patches"

ARCH="$(uname -m)"
CCS_VER="1.8.2p3"
CCSPATCH_VER="1.8.2-20110903"
KERNEL_VER="2.6.40.3-0.fc15"

UPDATED_DIFF=0
CCSDIFF_NAME="ccs-patch-3.0.diff"

# only required if using updated revision
#UPDATED_DIFF=1
#CCSDIFF_NAME="ccs-patch-2.6.40-fedora-15-20110802.diff"
#CCSDIFF_REVISION="ccs-patch-2.6.40-fedora-15.diff?revision=5320&root=tomoyo"

setup_rpmbuild_tree
enter_dir "${SOURCE_DIR}"

download_file "${URL_CCS}/ccs-patch-${CCSPATCH_VER}.tar.gz" \
	"ccs-patch-${CCSPATCH_VER}.tar.gz"
if [[ "${UPDATED_DIFF}" = 1 ]]; then
	download_file "${URL_CCS_SVN}/${CCSDIFF_REVISION}" "${CCSDIFF_NAME}"
fi
download_srpm "kernel"

install_dependencies "kernel-${KERNEL_VER}.src.rpm"
verify_signature "kernel-${KERNEL_VER}.src.rpm"
install_srpm "kernel-${KERNEL_VER}.src.rpm"

enter_dir "${RPM_BUILD_DIR}/SPECS"
copy_file "kernel.spec" "ccs-kernel.spec"

patch_spec() {
	cat << "EOF"
--- ccs-kernel.spec
+++ ccs-kernel.spec
@@ -23,7 +23,7 @@
 #
 # (Uncomment the '#' and both spaces below to set the buildid.)
 #
-# % define buildid .local
+%define buildid _tomoyo_${CCS_VER}
 ###################################################################
 
 # The buildid can also be specified on the rpmbuild command line
@@ -427,6 +427,11 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define with_modsign 0
+%define _enable_debug_packages 0
+%define with_debuginfo 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -486,7 +491,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -870,7 +875,7 @@
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
 Requires: perl\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -1397,6 +1402,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -xzf %_sourcedir/ccs-patch-${CCSPATCH_VER}.tar.gz
+patch -sp1 < patches/${CCSDIFF_NAME}
+
 %endif
 
 # Any further pre-build tree manipulations happen here.
@@ -1425,6 +1434,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch listnewconfig | grep -E '^CONFIG_' >.newoptions || true
 %if %{listnewconfig_fail}
EOF
}

# before applying the patch, replace the placeholder variables with the real values
msg "Patching ccs-kernel.spec ..."
if [[ "${UPDATED_DIFF}" = 0 ]]; then
	patch_spec | sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#patches/${CCSDIFF_NAME}#g" | patch
elif [[ "${UPDATED_DIFF}" = 1 ]]; then
	patch_spec | sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#%_sourcedir/${CCSDIFF_NAME}#g" | patch
fi
[[ $? != 0 ]] && error "ERROR: patching ccs-kernel.spec failed"

run_build --target ${ARCH} --with baseonly --without debug \
	--without debuginfo "${RPM_BUILD_DIR}/SPECS/ccs-kernel.spec"

exit 0
