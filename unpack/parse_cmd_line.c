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
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/errors.h"
#include "../include/vdfs_tools.h"

/**
 * @brief   Print unpack.vdfs4 usage options. Shown in case of wrong parameters.
 * @return  void
 */
void usage(void)
{
	printf("Utility for unpacking VDFS4 volumes\n"\
	"Usage: unpack.vdfs4 [options] image_name\n"\
	"Possible options are:\n"\
	"-o dir_name or --out_dir name\n"\
	"\tOutput directory name\n"\
	"-v or --verbose\n"\
	"\tVerbose mode of execution\n"\
	"-d dump_filename or --dump dump_filename\n"\
	"\tDump runtime information into file dump_file\n"\
	"-N or --no-decode\n"\
	"\tnot decompress tuned files inside of volume\n"\
	"-c or --config file\n"\
	"\tprint list of files inside of volume with type to file\n"\
	"\n");
}

/**
 * @brief	Parse parameters from unpack.vdfs4 run command line.
 * @param [in]	argc	Number of command line parameters.
 * @param [in]	argv[]	An array with command line parameters strings.
 * @param [in]	sbi	A pointer to the structure containing runtime
 *			parameters of vdfs4 superblock.
 * @return  0 if parced successfully, or error
 */
int parse_cmd(int argc, char *argv[], struct vdfs4_sb_info *sbi)
{
	const char *short_options = "vd:o:F:K:Nc:";
	const struct option long_options[] = {
		{"verbose",	no_argument,		NULL, 'v'},
		{"dump",	required_argument,	NULL, 'd'},
		{"out_dir",	required_argument,	NULL, 'o'},
		{"no-decode",	no_argument,	NULL, 'N'},
		{"config",	required_argument,	NULL, 'c'},
		{NULL, 0, NULL,	0}
	};
	int opt = 0;
	int long_index = 0;
	int ret = 0;

	while ((opt = getopt_long(argc, argv,
		short_options, long_options, &long_index)) != EOF) {
		switch (opt) {
		case 'v':
			SET_FLAG(sbi->service_flags, VERBOSE);
			set_logger_verbosity(LOG_ALL);
			break;
		case 'd':
			if (sbi->dump_file != NULL) {
				log_warning("Many -d parameters. "
						"First is used\n");
				break;
			}

			sbi->dump_file = fopen(optarg, "w");
			if (sbi->dump_file == NULL)
				log_warning("Can't open %s. "
					"Dump will not be written", optarg);
			break;
		case 'o':
			sbi->root_path = optarg;
			break;
		case 'N':
			SET_FLAG(sbi->service_flags, NO_DECODE);
			break;
		case 'c':
			if (sbi->squash_list_file != NULL) {
				log_warning("Many -c parameters. "
						"First is used\n");
				break;
			}

			sbi->squash_list_file = fopen(optarg, "w");
			if (sbi->squash_list_file == NULL)
				log_warning("Can't open %s. "
					"Config file will not be written ",
					optarg);
			break;
		default:
			log_error("Unrecognized option");
			ret = -EWRONGOPTS;
		}
	};

	if ((argc - 1) < optind) {
		log_error("No device or image name given");
		ret = -EWRONGOPTS;
	}
	sbi->file_name = argv[optind];

	if ((argc - 1) > optind) {
		log_error("Too many options");
		ret = -EWRONGOPTS;
	}

	if (ret)
		usage();

	return ret;
}

