/*
 *	pe-exec by Michał Górny <gentoo@mgorny.alt.pl>
 *	Based on winexe-detector by Per Wigren <per@wigren.nu>
 *	Based on binfmt-detector-cil by Ilya Konstantinov <future@shiny.co.il>
 *	Based on PE headers structures courtesy of Mono .NET runtime project
 *	(http://www.go-mono.com).
 *
 *	Licensed under the GNU GPL v2 or higher. See COPYING for details.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_DEBUG
int pretending = 0;
#endif

#include "pe-config.h"
#include "pe-recog.h"

/* Execute the program supplied on 'argv' using the handler supplied as
 * 'exe', modifying the 'argv' as necessary. */
void doexec(char* const exe, char* argv[]) {
	argv[0] = exe;

#ifdef ENABLE_DEBUG
	fprintf(stderr, "doexec(%s, [%s, ...])", exe, argv[1]);
	if (pretending)
		return;
#endif

	execvp(exe, argv);
	perror("execv() failed");
}

int main(const int argc, char* argv[]) {
	FILE *image;
	enum exe_type et;

	if (argc < 2) {
		fprintf(stderr, "Synopsis: %s file.exe [...]\n", argv[0]);
		return 0;
	}

#ifdef ENABLE_DEBUG
	if (!strcmp(argv[1], "--pretend") && argc >= 3) {
		pretending = 1;
		argv[1] = argv[2]; /* we won't be using argv[2+] anyway */
	}
#endif

	image = fopen(argv[1], "r");
	et = detect_format(image); /* image can be NULL here */

	if (et == EXE_ERROR)
		perror("I/O error while reading executable");
	if (image)
		fclose(image);

	if (et < EXE_ERROR) {
		char* const handler = read_conf(et);
		if (handler)
			doexec(handler, argv);
	}

	return 127;
}
