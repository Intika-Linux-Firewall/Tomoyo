#!/bin/bash

. "${RPM_SCRIPT_DIR}/global_functions"

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49693"

ARCH="$(uname -m)"
CCSTOOLS_VER="1.8.3-20111025"

setup_rpmbuild_tree
setup_source_dir "${RPM_SOURCE_DIR}/ccs-tools-${CCSTOOLS_VER}"
cd "${RPM_SOURCE_DIR}/ccs-tools-${CCSTOOLS_VER}"

download_file "${URL_CCS}/ccs-tools-${CCSTOOLS_VER}.tar.gz" \
	"ccs-tools-${CCSTOOLS_VER}.tar.gz"

msg "Extracting ccs-tools.spec ..."
tar -zxvf "ccs-tools-${CCSTOOLS_VER}.tar.gz" ccstools/ccs-tools.spec -O \
	> "${RPM_BUILD_DIR}/SPECS/ccs-tools.spec"

cd "${RPM_BUILD_DIR}/SPECS"

patch < "${RPM_SCRIPT_DIR}/${0%.*}.patch"

rpmbuild -bs "${RPM_BUILD_DIR}/SPECS/ccs-tools.spec"
