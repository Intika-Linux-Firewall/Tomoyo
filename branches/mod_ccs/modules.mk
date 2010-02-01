mod_ccs.la: mod_ccs.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version mod_ccs.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_ccs.la
