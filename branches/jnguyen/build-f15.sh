#!/bin/bash

. "${RPM_SCRIPT_DIR}/global_functions"

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684"
URL_CCS_SVN="http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.8.x/ccs-patch/patches"
URL_KERNEL="http://mirror.bytemark.co.uk/fedora/linux/updates/15/SRPMS"

ARCH="$(uname -m)"
CCS_VER="1.8.3p1"
CCSPATCH_VER="1.8.3-20111025"
KERNEL_VER="2.6.40.6-0.fc15"

UPDATED_DIFF=0
CCSDIFF_NAME="ccs-patch-3.0.diff"
#CCSDIFF_NAME="ccs-patch-2.6.40-fedora-15-20110802.diff"
#CCSDIFF_REVISION="ccs-patch-2.6.40-fedora-15.diff?revision=5320&root=tomoyo"

setup_rpmbuild_tree
setup_source_dir "${RPM_SOURCE_DIR}/ccs-kernel-${KERNEL_VER}"
cd "${RPM_SOURCE_DIR}/ccs-kernel-${KERNEL_VER}"

download_file "${URL_CCS}/ccs-patch-${CCSPATCH_VER}.tar.gz" \
	"ccs-patch-${CCSPATCH_VER}.tar.gz"
if [[ "${UPDATED_DIFF}" = 1 ]]; then
	download_file "${URL_CCS_SVN}/${CCSDIFF_REVISION}" "${CCSDIFF_NAME}"
fi
download_file "${URL_KERNEL}/kernel-${KERNEL_VER}.src.rpm" \
	"kernel-${KERNEL_VER}.src.rpm"

verify_signature "kernel-${KERNEL_VER}.src.rpm"
install_srpm "kernel-${KERNEL_VER}.src.rpm"

cd "${RPM_BUILD_DIR}/SPECS"
cp -v "kernel.spec" "ccs-kernel.spec"

# Before applying the patch, replace the placeholder variables with the real values.
msg "Patching ccs-kernel.spec ..."
if [[ "${UPDATED_DIFF}" = 0 ]]; then
	sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#patches/${CCSDIFF_NAME}#g" \
		"${RPM_SCRIPT_DIR}/${0%.*}.patch" | patch
elif [[ "${UPDATED_DIFF}" = 1 ]]; then
	sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#%_sourcedir/${CCSDIFF_NAME}#g" \
		"${RPM_SCRIPT_DIR}/${0%.*}.patch" | patch
fi
[[ $? != 0 ]] && error "ERROR: patching ccs-kernel.spec failed"

rpmbuild -bs "${RPM_BUILD_ROOT}/SPECS/ccs-kernel.spec"
