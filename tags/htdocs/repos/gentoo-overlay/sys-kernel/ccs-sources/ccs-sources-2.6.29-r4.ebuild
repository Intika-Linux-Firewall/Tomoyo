# Copyright 2009 Naohiro Aota
# Distributed under the terms of the GNU General Public License v2
# $Header: $

ETYPE="sources"
K_WANT_GENPATCHES="base extras"
K_GENPATCHES_VER="5"
K_SECURITY_UNSUPPORTED="1"

inherit eutils kernel-2
detect_version
detect_arch

CCS_TGP="ccs-patch-1.6.7-20090410"
CCS_TGP_SRC="mirror://sourceforge.jp/tomoyo/30297/${CCS_TGP}.tar.gz"
CCS_PATCH_VER="2.6.29"

DESCRIPTION="TOMOYO Linux sources for the ${KV_MAJOR}.${KV_MINOR} kernel tree"
SRC_URI="${KERNEL_URI} ${GENPATCHES_URI} ${ARCH_URI} ${CCS_TGP_SRC}"
KEYWORDS="~alpha ~amd64 ~arm ~hppa ~ia64 ~ppc ~ppc64 ~sh ~sparc ~x86"
RDEPEND="sys-apps/ccs-tools"

K_EXTRAEINFO="Before booting with TOMOYO enabled kernel, you need to
run this command to initialize TOMOYO policies:
# /usr/lib/ccs/init_policy.sh"

src_unpack() {
	kernel-2_src_unpack

	cd "${WORKDIR}"
	unpack ${CCS_TGP}.tar.gz
	cp -ax fs include "${S}" || die

	cd "${S}"
	epatch "${WORKDIR}"/patches/ccs-patch-${CCS_PATCH_VER}.diff || die
}
