#!/bin/sh
# Regenerate the configuration for pe-exec
# (this is supposed to be sourced by the init.d script)

export UNKNOWN MSDOS WIN32 CLR

(
if [ -n "${RC_SVCNAME}" ]; then
	ewarn=ewarn
	eerror=eerror
else
	ewarn=echo
	eerror=echo
	exec >&2
fi

foundone=0
[ -z "${UNKNOWN}" ] && ${ewarn} '${UNKNOWN} is not set!' || foundone=1
[ -z "${MSDOS}" ] && ${ewarn} '${MSDOS} is not set!' || foundone=1
[ -z "${WIN32}" ] && ${ewarn} '${WIN32} is not set!' || foundone=1
[ -z "${CLR}" ] && ${ewarn} '${CLR} is not set!' || foundone=1

if [ ${foundone} -ne 1 ]; then
	${eerror} 'None of the expected interpreters were set, aborting.'
	exit 1
else
	printf '%s\0%s\0%s\0%s\0' "${UNKNOWN}" "${MSDOS}" "${WIN32}" "${CLR}" > /var/lib/pe-format2
	exit $?
fi
)
