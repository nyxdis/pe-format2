/*
 *	pe-exec by Michał Górny <gentoo@mgorny.alt.pl>
 *	Based on winexe-detector by Per Wigren <per@wigren.nu>
 *	Based on binfmt-detector-cil by Ilya Konstantinov <future@shiny.co.il>
 *	Based on PE headers structures courtesy of Mono .NET runtime project
 *	(http://www.go-mono.com).
 *
 *	Licensed under the GNU GPL v2 or higher. See COPYING for details.
 */

#include "config.h"

#include <stdio.h>

#include "cil-coff.h"
#include "pe-recog.h"

#ifdef HAVE_STDINT_H
#	include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#	include <inttypes.h>
#endif

#ifndef PRIx32
#	define PRIx32 "lx"
#endif
#ifndef PRIx16
#	define PRIx16 "x"
#endif

#ifdef ENABLE_DEBUG
#	define DEBUG(fstr, a, b, c, d, e) fprintf(stderr, fstr "\n", a, b, c, d, e)
#else
#	define DEBUG(fstr, a, b, c, d, e)
#endif

/* Return the fileformat of executable pointed by 'image' or EXE_ERROR
 * if an error occures (or 'image' is NULL, which means the error
 * happened before. */
enum exe_type detect_format(FILE* const image) {
	if (!image)
		return EXE_ERROR;
	
	/* Parse the MSDOS header */
	{
		MSDOSHeader msdos_header;
		uint32_t pe_offset;

		if (fread(&msdos_header, sizeof(msdos_header), 1, image) < 1)
			return feof(image) ? EXE_UNKNOWN : EXE_ERROR;

		DEBUG("msdos_sig: %02hhx%02hhx (%c%c)", msdos_header.msdos_sig[0],
				msdos_header.msdos_sig[1], msdos_header.msdos_sig[0],
				msdos_header.msdos_sig[1], 0);
		if (!(msdos_header.msdos_sig[0] == 'M' && msdos_header.msdos_sig[1] == 'Z'))
			return EXE_UNKNOWN;

		pe_offset = msdos_header.pe_offset[0]
			| msdos_header.pe_offset[1] << 8
			| msdos_header.pe_offset[2] << 16
			| msdos_header.pe_offset[3] << 24;

		DEBUG("pe_offset: %08" PRIx32, pe_offset, 0, 0, 0, 0);
		if (pe_offset == 0)
			return EXE_MSDOS;
		if (fseek(image, pe_offset, SEEK_SET) != 0)
			return feof(image) ? EXE_MSDOS : EXE_ERROR;
	}
	
	/* Parse the PE header */
	{
		DotNetHeader dotnet_header;
		uint16_t pe_magic;

		if (fread(&dotnet_header, sizeof(dotnet_header), 1, image) < 1)
			return feof(image) ? EXE_MSDOS : EXE_ERROR;

		pe_magic = dotnet_header.pe.pe_magic[0]
			 | dotnet_header.pe.pe_magic[1] << 8;

		DEBUG("pesig: %02hhx%02hhx (%c%c), pe_magic: %04" PRIx16, dotnet_header.pesig[0],
				dotnet_header.pesig[1], dotnet_header.pesig[0],
				dotnet_header.pesig[1], pe_magic);
		/* 0x10b is PE32, 0x20b is PE32+ */
		if (dotnet_header.pesig[0] == 'P' && dotnet_header.pesig[1] == 'E'
				&& (pe_magic == 0x10B || pe_magic == 0x20B)) {
			uint32_t rva = dotnet_header.datadir.pe_cli_header.rva[0]
				| dotnet_header.datadir.pe_cli_header.rva[1] << 8
				| dotnet_header.datadir.pe_cli_header.rva[2] << 16
				| dotnet_header.datadir.pe_cli_header.rva[3] << 24;

			DEBUG("coff_machine: %04" PRIx16 ", cli_header.size: %08" PRIx32
					", rva: %08" PRIx32,
					dotnet_header.coff.coff_machine,
					dotnet_header.datadir.pe_cli_header.size, rva, 0, 0);
			/* 014c is for x86, 8664 for amd64 */
			if (dotnet_header.coff.coff_machine == 0x8664)
				return EXE_WIN64;
			else if ((dotnet_header.datadir.pe_cli_header.size != 0)
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
