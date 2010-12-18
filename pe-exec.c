/*
 *	pe-exec by Michał Górny <gentoo@mgorny.alt.pl>
 *	Based on winexe-detector by Per Wigren <per@wigren.nu>
 *	Based on binfmt-detector-cil by Ilya Konstantinov <future@shiny.co.il>
 *	Based on PE headers structures courtesy of Mono .NET runtime project
 *	(http://www.go-mono.com).
 *
 *	Licensed under the GNU GPL v2 or higher. See COPYING for details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef ENABLE_DEBUG
int pretending = 0;
#endif

#include "pe-recog.h"

const char* const handlers_path = STATEFILE;

/* Read the handlers configuration file and find a handler for specified
 * executable type 'et'. Returns the pointer to an internal buffer
 * or NULL. */
char* read_conf(const enum exe_type et) {
	FILE* const f = fopen(handlers_path, "r");
	static char buf[2049];
	int numread = 0;
	int slen;
	enum exe_type i = 0;

	if (!f) {
		perror("Unable to open handlers configuration file");
		return NULL;
	}

	buf[sizeof(buf)-1] = 0; /* make sure strlen() doesn't segfault */

	while (1) {
		const int ret = fread(&buf[numread], sizeof(char), (sizeof(buf) / sizeof(char)) - numread - 1, f);
		numread += ret;

		slen = strlen(buf);
		if (slen < numread) { /* string found */
			if (i == et) { /* found it! */
				fclose(f);
				return buf[0] ? buf : NULL;
			} else { /* scroll the buffer */
				slen++; /* NUL terminator */
				memmove(buf, &buf[slen], numread - slen);
				numread -= slen;
				i++;
			}
		} else if (numread == (sizeof(buf) / sizeof(char)) - 1) { /* buffer overflow */
			if (i == et) { /* if we need it, we fail */
				fputs("Buffer overflow while reading handler\n", stderr);
				fclose(f);
				return NULL;
			} else { /* if we don't, just keep skipping */
				numread = 0;
			}
		} else if (ret == 0) { /* read() failed and no useful data */
			if (ferror(f))
				perror("I/O error while reading handlers config");
			else if (feof(f))
				fputs("EOF while reading handlers config\n", stderr);
			fclose(f);
			return NULL;
		}
	}

	fclose(f);
	return NULL;
}

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
