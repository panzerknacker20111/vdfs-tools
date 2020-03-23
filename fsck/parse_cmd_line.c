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

#include "../include/errors.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/vdfs_tools.h"
#include <time.h>

#include "fsck.h"

/**
 * @brief	Print fsck.vdfs4 usage options. Shown in case of wrong parameters.
 * @return  void
 */

void usage(void)
{
	printf("Usage: fsck.vdfs4 [options] device_name or image_name\n"\
	"Possible options are:\n"\
	"-v for verbose mode\n"\
	"-c for color mode (don't working yet)\n"\
	"-d node_id for dumping bnodes from cattree\n"\
	"-e node_id for dumping bnodes from exttree\n"\
	"-p for showing debug area messages\n"\
	"-i inject trash to volume\n"
	"-C update crc for bitmaps, bnodes and extended superblock\n"
	"possible option are:\n"
	"	file=file_name - file for storing backup information\n"
	"	seed=seed_num - injection seed\n"
	"	tlen=trash_length - length of the trash to be injected\n"
	"	tofs=trash_offset - offset from the beginning of the block\n"\
	"-r file=file_name restore corrupted volume from backup file "
	" (used only with -i), file_name is a file with backup data\n"\
	"-n print a file block numbers or print a file\n"
	" which holds a specified block number\n"
	"possible option are:\n"
	"	file=filename - search for a filename\n"
	"	blck=block_number - search for a block\n"
	"-q restore mkfs squash images config\n"
	);
}

/**
 * @brief       Parse parameters from fsck.vdfs4 run command line.
 * @param [in]  argc	Number of command line parameters.
 * @param [in]	argv[]	An array with command line parameters strings.
 * @param [in]	sbi		A pointer to the structure containing runtime
			parameters of vdfs4 superblock.
 * @return  0 if parced successfully, or error
 */
int parse_cmd(int argc, char *argv[], struct vdfs4_fsck_superblock_info
	*fsck_info)

{
	const char *short_options = "vcd:e:pn:i:r:qC";

	const struct option long_options[] = {
			{"verbose", no_argument, NULL, 'v'},
			{"color", no_argument, NULL, 'c'},
			{"cattree_dump_bnode", required_argument, NULL, 'd'},
			{"exttree_dump_bnode", required_argument, NULL, 'e'},
			{"parse", no_argument, NULL, 'p'},
			{"find_by_name", required_argument, NULL, 'n'},
			{"inject", required_argument, NULL, 'i'},
			{"restore", required_argument, NULL, 'r'},
			{"config", no_argument, NULL, 'q'},
			{"crc-update", no_argument, NULL, 'C'},
			{NULL, 0, NULL, 0}
	};
	int opt = 0;
	int long_index = 0;
	int ret_code = 0;

	while ((opt = getopt_long(argc, argv,
			short_options, long_options, &long_index)) != EOF) {
			switch (opt) {
			case 'v':
				SET_FLAG(fsck_info->sbi.service_flags, VERBOSE);
				set_logger_verbosity(LOG_ALL);
				break;
			case 'c':
				SET_FLAG(fsck_info->sbi.service_flags, COLOR);
				break;
			case 'd':
				SET_FLAG(fsck_info->sbi.service_flags,
						CATTREE_BNODE_DUMP);
				fsck_info->cmd_info.dump_node = atoi(optarg);
				break;
			case 'e':
				SET_FLAG(fsck_info->sbi.service_flags,
						EXTTREE_BNODE_DUMP);
				fsck_info->cmd_info.dump_node = atoi(optarg);
				break;
			case 'p':
				SET_FLAG(fsck_info->sbi.service_flags,
					PARSE_DEBUG_AREA);
				break;
			case 'n':
				SET_FLAG(fsck_info->sbi.service_flags,
					FIND_BY_NAME);
				if (!strncmp(optarg, "blck", 4)) {
					fsck_info->cmd_info.block_to_find =
						atoi(optarg + strlen("blck="));
				} else if (!strncmp(optarg, "file", 4)) {
					strncpy(fsck_info->cmd_info.
						file_name_to_find,
						optarg + strlen("file="),
						strlen(optarg) -
						strlen("file=") + 1);
					fsck_info->cmd_info.block_to_find = 0;
				} else {
					log_error("Bad command argument\n");
					ret_code = -EWRONGOPTS;
				}
				break;
			case 'i':
				SET_FLAG(fsck_info->sbi.service_flags,
					PERFORM_INJECTION);

				if (!strncmp(optarg, "seed", 4)) {
					fsck_info->cmd_info.injection_seed =
						atoi(optarg + strlen("seed="));
				} else if (!strncmp(optarg, "file", 4)) {
					if (strlen(optarg + strlen("file=")) >
						VDFS4_FILE_NAME_LEN) {
						log_error("Inval file path\n");
						return -EINVAL;
					}
					strncpy(fsck_info->cmd_info.
							restore_file_path,
							optarg +
							strlen("file="),
							strlen(optarg) -
							strlen("file=") + 1);
				} else if (!strncmp(optarg, "tofs", 4)) {
					fsck_info->cmd_info.trash_offset =
						atoi(optarg + strlen("tofs="));
				} else if (!strncmp(optarg, "tlen", 4)) {
					fsck_info->cmd_info.trash_size =
						atoi(optarg + strlen("tlen="));
				} else {
					log_error("Bad command argument\n");
					ret_code = -EWRONGOPTS;
				}
				break;
			case 'r':
				SET_FLAG(fsck_info->sbi.service_flags,
					RESTORE);

				if (!strncmp(optarg, "file", 4))
					strncpy(fsck_info->cmd_info.
						restore_file_path,
						optarg + strlen("file="),
						strlen(optarg) -
						strlen("file=") + 1);
				else {
					log_error("Bad command argument\n");
					ret_code = -EWRONGOPTS;
				}

				break;
			case 'q':
				SET_FLAG(fsck_info->sbi.service_flags,
					SQUASH_CONF_RESTORE);
				break;
			case 'C':
				SET_FLAG(fsck_info->sbi.service_flags,
					UPDATE_CRC);
				break;
			default:
				log_error("Unrecognized option");
				ret_code = -EWRONGOPTS;
			};
	}

	/* If no arguments left after parsing options, we assume
	 *  no disk name was given */
	if ((argc - 1) < optind) {
		log_info("No device or image name given");
		ret_code = -EWRONGOPTS;
	}

	if ((argc - 1) > optind) {
		log_error("Too many options");
		ret_code = -EWRONGOPTS;
	}

	fsck_info->sbi.file_name = argv[optind];

	if (ret_code)
		usage();

	return ret_code;
}
