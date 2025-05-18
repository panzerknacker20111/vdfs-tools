/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2012 by Samsung Electronics, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 * */
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include "vdfs_tools.h"

#include <elf.h>
#include <endian.h>
#ifndef ElfW
# if ELFCLASSM == ELFCLASS32
#  define ElfW(x)  Elf32_ ## x
#  define ELFW(x)  ELF32_ ## x
# else
#  define ElfW(x)  Elf64_ ## x
#  define ELFW(x)  ELF64_ ## x
# endif
#endif

#define CHECK_BYTES_COUNT (sizeof(ElfW(Ehdr)))

UNUSED static int is_pfm_file(char *buffer, int length)
{
	if (length < 4)
		return 0;

	if (((*((__u32 *)buffer) & 0xff00ffff) == 0x12000100) ||
			((*(__u32 *)buffer & 0xff00ffff) == 0x02000100))
		return 1;

	return 0;
}

 UNUSED static int is_pdp_11_file(char *buffer, int length)
{
	if (length < 3)
		return 0;

	if (((*((__u16 *)buffer) & 0xffff) == 0x109))
		return 1;

	return 0;
}

static int is_elf_file(char *buffer, int length)
{
	if (length < 4)
		return 0;

	if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' &&
			buffer[3] == 'F')
		return 1;

	return 0;
}

UNUSED static int is_ascii_file(char *buffer, int length)
{
	int count;
	int c;

	if (length == 0)
		return 0;
	for (count = 0; count < length; count++) {
		c = (int)buffer[count];
		if (!isascii(c))
			return 0;
	}

	return 1;
}


int is_need_sign(int src_fd)
{
	char buffer[CHECK_BYTES_COUNT];
	int ret, check_bytes_count;

	memset(buffer, 0, CHECK_BYTES_COUNT);
	ret = read(src_fd, buffer, CHECK_BYTES_COUNT);
	if (ret == -1) {
		ret = errno;
		perror("cannot read data from a file");
		return ret;
	}
	check_bytes_count = ret;
	ret = lseek(src_fd, 0, SEEK_SET);
	if (ret == -1) {
		ret = errno;
		perror("cannot set file position");
		return ret;
	}

	if (is_elf_file(buffer, check_bytes_count))
		return 1;

	return 0;
}
