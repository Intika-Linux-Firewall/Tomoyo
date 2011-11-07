#!/bin/bash

URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49693"
URL_SERVICE_FILES="http://repo.tomoyolinux.co.uk/pub/other/services/tpel/6"

ARCH="$(uname -m)"
CCSTOOLS_VER="1.8.3-20111025"

if [[ "x${CCS_SCRIPT_DIR}" = "x" ]]; then
	printf '%s\n' 'Variable $CCS_SCRIPT_DIR not defined.'; exit 1
fi

. "${CCS_SCRIPT_DIR}/global_functions" || exit 1

check_variables
setup_rpmbuild_tree
setup_source_dir "${CCS_SOURCE_DIR}/ccs-tools-${CCSTOOLS_VER}"
cd "${CCS_SOURCE_DIR}/ccs-tools-${CCSTOOLS_VER}"

download_file "${URL_CCS}/ccs-tools-${CCSTOOLS_VER}.tar.gz" \
	"ccs-tools-${CCSTOOLS_VER}.tar.gz"

download_file "${URL_SERVICE_FILES}/ccs-auditd" "ccs-auditd"

download_file "${URL_SERVICE_FILES}/ccs-notifyd" "ccs-notifyd"

msg "Extracting ccs-tools.spec ..."
tar -zxvf "ccs-tools-${CCSTOOLS_VER}.tar.gz" ccstools/ccs-tools.spec -O \
	> "${CCS_BUILD_DIR}/SPECS/ccs-tools.spec"

cd "${CCS_BUILD_DIR}/SPECS"

patch < "${CCS_SCRIPT_DIR}/$(basename ${0%.*}).patch"

rpmbuild -bs "${CCS_BUILD_DIR}/SPECS/ccs-tools.spec"
