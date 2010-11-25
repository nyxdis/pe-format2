#!/bin/sh
# Regenerate the configuration for pe-exec
# (this is supposed to be sourced by the init.d script)

export UNKNOWN MSDOS WIN32 CLR WIN64

(
if [ -n "${RC_SVCNAME}" ]; then
	ewarn=ewarn
	eerror=eerror
else
	ewarn=echo
	eerror=echo
	exec >&2
fi

firstworking() {
	while [ ${#} -gt 1 ]; do
		if "${1}" --version >/dev/null 2>&1; then
			echo "${1}"
			return
		fi
		shift
	done

	ewarn "\${${1}} is not set and none of the default applications were found!"
}

: ${UNKNOWN:=$(firstworking wine mono ilrun dosbox dosemu UNKNOWN)}
: ${MSDOS:=$(firstworking dosbox dosemu MSDOS)}
: ${WIN32:=$(firstworking wine WIN32)}
: ${CLR:=$(firstworking mono ilrun CLR)}
: ${WIN64:=$(firstworking wine64 WIN64)}

if [ -z "${UNKNOWN}" -a -z "${MSDOS}" -a -z "${WIN32}" -a -z "${CLR}" -a -z "${WIN64}" ]; then
	${eerror} 'None of the expected interpreters were set, aborting.'
	exit 1
else
	printf '%s\0' "${UNKNOWN}" "${MSDOS}" "${WIN32}" "${CLR}" "${WIN64}" > /var/lib/pe-format2
	exit ${?}
fi
)
