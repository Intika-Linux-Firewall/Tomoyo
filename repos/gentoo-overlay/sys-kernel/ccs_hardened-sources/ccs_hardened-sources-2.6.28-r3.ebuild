# Copyright 2009 Naohiro Aota
# Distributed under the terms of the GNU General Public License v2
# $Header: $

ETYPE="sources"
K_WANT_GENPATCHES="base extras"
K_GENPATCHES_VER="7"
K_SECURITY_UNSUPPORTED="1"

inherit eutils kernel-2
detect_version

CCS_TGP="ccs-patch-1.6.7-20090401"
CCS_TGP_SRC="mirror://osdn.jp/tomoyo/30297/${CCS_TGP}.tar.gz"
CCS_PATCH_VER="2.6.28-hardened-gentoo"

HGPV="${KV_MAJOR}.${KV_MINOR}.${KV_PATCH}-8"
HGPV_URI="http://dev.gentoo.org/~gengor/distfiles/${CATEGORY}/${PN}/hardened-patches-${HGPV}.extras.tar.bz2
	mirror://gentoo/hardened-patches-${HGPV}.extras.tar.bz2"

DESCRIPTION="TOMOYO Linux sources for the hardened kernel ${KV_MAJOR}.${KV_MINOR}"
SRC_URI="${KERNEL_URI} ${GENPATCHES_URI} ${ARCH_URI} ${HGPV_URI} ${CCS_TGP_SRC}"
KEYWORDS="~alpha amd64 ~hppa ~ia64 ~ppc ~ppc64 ~sparc x86"
RDEPEND="sys-apps/ccs-tools"

UNIPATCH_LIST="${DISTDIR}/hardened-patches-${HGPV}.extras.tar.bz2"
UNIPATCH_EXCLUDE="2705_i915-no-vblank-on-disabled-pipe.patch 2710_i915-set-vblank-flag-correctly.patch
	4200_fbcondecor-0.9.5.patch"


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
