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

#include "cil-coff.h"

#ifdef ENABLE_DEBUG
#	define DEBUG(fstr, ...) fprintf(stderr, fstr "\n", __VA_ARGS__)

int pretending = 0;

#else
#	define DEBUG(...)
#endif

enum exe_type {
	EXE_UNKNOWN = 0,
	EXE_MSDOS,
	EXE_WIN32,
	EXE_CLR,
	EXE_WIN64,
	EXE_ERROR
};

const char* const handlers_path = "/var/lib/pe-format2";

/* Return the fileformat of executable pointed by 'image' or EXE_ERROR
 * if an error occures (or 'image' is NULL, which means the error
 * happened before. */
enum exe_type detect_format(FILE* const image) {
	if (!image)
		return EXE_ERROR;
	
	/* Parse the MSDOS header */
	{
		MSDOSHeader msdos_header;
		unsigned long pe_offset;

		if (fread(&msdos_header, sizeof(msdos_header), 1, image) < 1)
			return feof(image) ? EXE_UNKNOWN : EXE_ERROR;

		DEBUG("msdos_sig: %02x%02x (%c%c)", msdos_header.msdos_sig[0],
				msdos_header.msdos_sig[1], msdos_header.msdos_sig[0],
				msdos_header.msdos_sig[1]);
		if (!(msdos_header.msdos_sig[0] == 'M' && msdos_header.msdos_sig[1] == 'Z'))
			return EXE_UNKNOWN;

		pe_offset = msdos_header.pe_offset[0]
			| msdos_header.pe_offset[1] << 8
			| msdos_header.pe_offset[2] << 16
			| msdos_header.pe_offset[3] << 24;

		DEBUG("pe_offset: %08lx", pe_offset);
		if (pe_offset == 0)
			return EXE_MSDOS;
		if (fseek(image, pe_offset, SEEK_SET) != 0)
			return feof(image) ? EXE_MSDOS : EXE_ERROR;
	}
	
	/* Parse the PE header */
	{
		DotNetHeader dotnet_header;
		unsigned short pe_magic;

		if (fread(&dotnet_header, sizeof(dotnet_header), 1, image) < 1)
			return feof(image) ? EXE_MSDOS : EXE_ERROR;

		DEBUG("coff_machine: %04x", dotnet_header.coff.coff_machine);
		/* 014c is for x86, 8664 for amd64 */
		if (dotnet_header.coff.coff_machine == 0x8664)
			return EXE_WIN64;

		pe_magic = dotnet_header.pe.pe_magic[0]
			 | dotnet_header.pe.pe_magic[1] << 8;

		DEBUG("pesig: %02x%02x (%c%c), pe_magic: %04x", dotnet_header.pesig[0],
				dotnet_header.pesig[1], dotnet_header.pesig[0],
				dotnet_header.pesig[1], pe_magic);
		/* 0x10b is PE32, 0x20b is PE32+ */
		if (dotnet_header.pesig[0] == 'P' && dotnet_header.pesig[1] == 'E'
				&& (pe_magic == 0x10B || pe_magic == 0x20B)) {
			unsigned long rva = dotnet_header.datadir.pe_cli_header.rva[0]
				| dotnet_header.datadir.pe_cli_header.rva[1] << 8
				| dotnet_header.datadir.pe_cli_header.rva[2] << 16
				| dotnet_header.datadir.pe_cli_header.rva[3] << 24;

			DEBUG("cli_header.size: %08lx, rva: %08lx",
					dotnet_header.datadir.pe_cli_header.size, rva);
			if ((dotnet_header.datadir.pe_cli_header.size != 0)
					&& (rva != 0)) {
				if (fseek(image, rva, SEEK_SET) == 0)
					return EXE_CLR;
				else
					return feof(image) ? EXE_WIN32 : EXE_ERROR;
			} else
				return EXE_WIN32;
		} else /* LE, LX, NE, ... */
			return EXE_MSDOS;
	}

	return EXE_UNKNOWN; /* shouldn't be reached */
}

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
	DEBUG("doexec(%s, [%s, ...])", exe, argv[1]);
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
