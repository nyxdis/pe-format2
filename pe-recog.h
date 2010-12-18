/*
 *	pe-exec by Michał Górny <gentoo@mgorny.alt.pl>
 *	Based on winexe-detector by Per Wigren <per@wigren.nu>
 *	Based on binfmt-detector-cil by Ilya Konstantinov <future@shiny.co.il>
 *	Based on PE headers structures courtesy of Mono .NET runtime project
 *	(http://www.go-mono.com).
 *
 *	Licensed under the GNU GPL v2 or higher. See COPYING for details.
 */

#ifndef PE_RECOG_H
#define PE_RECOG_H

#include <stdio.h>

enum exe_type {
	EXE_UNKNOWN = 0,
	EXE_MSDOS,
	EXE_WIN32,
	EXE_CLR,
	EXE_WIN64,
	EXE_ERROR
};

enum exe_type detect_format(FILE* const image);

#endif
