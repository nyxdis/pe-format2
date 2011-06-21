bin_PROGRAMS = pe-exec
sbin_SCRIPTS = pe-format2-conf.sh
noinst_SCRIPTS = pe-format.init
noinst_DATA = pe-format.conf

pkgstatefile = @localstatedir@/pe-format2

pe_exec_SOURCES = pe-exec.c pe-recog.c pe-recog.h pe-config.c pe-config.h cil-coff.h
pe_exec_CPPFLAGS = -DSTATEFILE=\"$(pkgstatefile)\"
