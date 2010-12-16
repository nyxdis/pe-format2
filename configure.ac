AC_PREREQ([2.60])
AC_INIT([pe-format], [2.0.4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.6 foreign dist-bzip2 no-dependencies])

# Define only include macros we're going to use.
AC_DEFUN([AC_INCLUDES_DEFAULT], [
m4_ifval([$1], [$1
], [dnl
#ifdef HAVE_STDINT_H
#	include <stdint.h>
#endif
])])

AC_PROG_CC
AC_PROG_SED
AC_CHECK_HEADERS([stdint.h])
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug], [Enable stderr debug]))

AS_IF([test "x$enable_debug" = "xyes"], [
	AC_DEFINE([ENABLE_DEBUG], [1])
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
