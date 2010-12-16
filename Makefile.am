bin_PROGRAMS = pe-exec
dist_sbin_SCRIPTS = pe-format2-conf.sh
noinst_SCRIPTS = pe-format.init

EXTRA_DIST = pe-format.conf pe-format.init.in pe-format2-conf.sh.in

pkgstatefile = @localstatedir@/lib/pe-format2

pe_exec_SOURCES = pe-exec.c cil-coff.h
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
