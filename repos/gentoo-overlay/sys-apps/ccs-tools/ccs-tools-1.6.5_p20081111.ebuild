# Copyright 2008 Naohiro Aota
# Distributed under the terms of the GNU General Public License v2
# $Header: $

inherit flag-o-matic

MY_P="${P/_p/-}"
DESCRIPTION="TOMOYO Linux tools"
HOMEPAGE="http://www.sourcefoge.jp/projects/tomoyo/"
SRC_URI="mirror://sourceforge.jp/tomoyo/30298/${MY_P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="x86 arm sh ppc ia64 hppa amd64"
IUSE=""

DEPEND="virtual/libc
	sys-libs/ncurses
	sys-libs/readline"

S="${WORKDIR}/ccstools/"

alias_list="ccs-auditd ccs-queryd ccstree checkpolicy editpolicy editpolicy_offline findtemp ld-watch loadpolicy pathmatch patternize savepolicy setlevel setprofile sortpolicy domainmatch"

src_unpack() {
	unpack ${A}

	cd "${S}"
	sed -i \
		-e "/^INSTALLDIR /cINSTALLDIR = ${D}" \
		-e "/^CFLAGS=/D" \
		Makefile || die
}

src_compile() {
	CFLAGS="${CFLAGS} -Wall -Wno-pointer-sign"
	strip-unsupported-flags
	emake || die
}

src_install() {
	diropts -m 755 -o root -g root
	dodir /usr/lib/ccs /usr/lib/ccs/misc /usr/lib/ccs/conf

	exeinto /usr/lib/ccs/
	exeopts -o root -g root
	doexe ccstools realpath
	exeopts -m 755 -o root -g root
	doexe domainmatch init_policy.sh tomoyo_init_policy.sh
	for i in ${alias_list}; do dohard /usr/lib/ccs/ccstools /usr/lib/ccs/$i; done
	for i in ${alias_list}; do dosym  /usr/lib/ccs/$i /usr/sbin/ccs-`echo $i | sed 's:^ccs-::'`; done

	exeinto /usr/lib/ccs/misc/
	exeopts -m 0755 -o root -g root
	doexe makesyaoranconf candy chaplet checktoken gettoken groovy honey mailauth proxy timeauth falsh ccs-notifyd audit-exec-param convert-exec-param
	exeopts -m 4755 -o root -g root
	doexe force-logout

	insinto /usr/lib/ccs/
	insopts -m 644 -o root -g root
	doins README.ccs COPYING.ccs

	insinto /usr/lib/ccs/conf
	doins ccstools.conf
	dosym /usr/lib/ccs/conf/ccstools.conf /usr/lib/ccs/ccstools.conf

	into /
	insopts -m 700 -o root -g root
	dosbin ccs-init tomoyo-init

	doman man/man8/*

	insopts -m 644 -o root -g root
	doenvd "${FILESDIR}/50ccs-tools"
}
