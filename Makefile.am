bin_PROGRAMS = pe-exec
sbin_SCRIPTS = pe-format2-conf.sh
noinst_SCRIPTS = pe-format.init
noinst_DATA = pe-format.conf

EXTRA_DIST = pe-format.conf.in pe-format.init.in pe-format2-conf.sh.in

pkgstatefile = @localstatedir@/pe-format2

pe_exec_SOURCES = pe-exec.c pe-recog.c pe-recog.h pe-config.c pe-config.h cil-coff.h
pe_exec_CPPFLAGS = -DSTATEFILE=\"$(pkgstatefile)\"

$(noinst_SCRIPTS) $(dist_sbin_SCRIPTS): Makefile
	rm -f $@ $@.tmp
	@SED@ \
		-e "s|[@]sbindir@|${sbindir}|" \
		-e "s|[@]pkgstatefile@|${pkgstatefile}|" \
		${srcdir}/$@.in > $@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

$(noinst_DATA): Makefile
	rm -f $@ $@.tmp
	@SED@ \
		-e "s|[@]sysconfdir@|${sysconfdir}|" \
		${srcdir}/$@.in > $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@
