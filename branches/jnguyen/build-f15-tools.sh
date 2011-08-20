#!/bin/bash

. ./global_functions

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49693"

ARCH="$(uname -m)"
CCSTOOLS_VER="1.8.2-20110820"

setup_rpmbuild_tree
enter_dir "${SOURCE_DIR}"

download_file "${URL_CCS}/ccs-tools-${CCSTOOLS_VER}.tar.gz" \
	"ccs-tools-${CCSTOOLS_VER}.tar.gz"

msg "Extracting ccs-tools.spec ..."
tar -zxvf "ccs-tools-${CCSTOOLS_VER}.tar.gz" ccstools/ccs-tools.spec -O \
	> "${RPM_BUILD_DIR}/SPECS/ccs-tools.spec"

run_build --target ${ARCH} --with baseonly --without debug \
	--without debuginfo "${RPM_BUILD_DIR}/SPECS/ccs-tools.spec"

exit 0
