#!/bin/bash

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684"
URL_CCS_SVN="http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.8.x/ccs-patch/patches"
URL_KERNEL="http://www.mirrorservice.org/sites/ftp.scientificlinux.org/linux/scientific/6.1/SRPMS/vendor"

ARCH="$(uname -m)"
CCS_VER="1.8.3p3"
CCSPATCH_VER="1.8.3-20111118"
KERNEL_VER="2.6.32-131.21.1.el6"

UPDATED_DIFF=0
CCSDIFF_NAME="ccs-patch-2.6.32-centos-6.1.diff"
#CCSDIFF_REVISION=""

if [[ "x${CCS_SCRIPT_DIR}" = "x" ]]; then
	printf '%s\n' 'Variable $CCS_SCRIPT_DIR not defined.'; exit 1
fi

. "${CCS_SCRIPT_DIR}/global_functions" || exit 1

check_variables
setup_rpmbuild_tree
setup_source_dir "${CCS_SOURCE_DIR}/ccs-kernel-${KERNEL_VER}"
cd "${CCS_SOURCE_DIR}/ccs-kernel-${KERNEL_VER}"

download_file "${URL_CCS}/ccs-patch-${CCSPATCH_VER}.tar.gz" \
	"ccs-patch-${CCSPATCH_VER}.tar.gz"
if [[ "${UPDATED_DIFF}" = 1 ]]; then
	download_file "${URL_CCS_SVN}/${CCSDIFF_REVISION}" "${CCSDIFF_NAME}"
fi
download_file "${URL_KERNEL}/kernel-${KERNEL_VER}.src.rpm" \
	"kernel-${KERNEL_VER}.src.rpm"

install_srpm "kernel-${KERNEL_VER}.src.rpm"

cd "${CCS_BUILD_DIR}/SPECS"
cp -v "kernel.spec" "ccs-kernel.spec"

# Before applying the patch, replace the placeholder variables with the real values.
msg "Patching ccs-kernel.spec ..."
PATCH_NAME="$(basename ${0%.*}).patch"
if [[ "${UPDATED_DIFF}" = 0 ]]; then
	sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#patches/${CCSDIFF_NAME}#g" \
		"${CCS_SCRIPT_DIR}/${PATCH_NAME}" | patch
elif [[ "${UPDATED_DIFF}" = 1 ]]; then
	sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#%_sourcedir/${CCSDIFF_NAME}#g" \
		"${CCS_SCRIPT_DIR}/${PATCH_NAME}" | patch
fi
[[ $? != 0 ]] && error "ERROR: patching ccs-kernel.spec failed"

rpmbuild -bs "${CCS_BUILD_DIR}/SPECS/ccs-kernel.spec"
