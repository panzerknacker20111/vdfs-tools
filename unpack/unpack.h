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

#ifndef __UNPACK_H__
#define __UNPACK_H__

#include "../include/vdfs_tools.h"
#include "../include/vdfs4.h"
#define SIGNED_DLINK 5 // Use the correct value for your project
/** @brief	A structure used as a base for list of full directories paths
 */
struct dir_list_item {
	/** object id of catalog */
	__le64 object_id;
	__le64 parent_id;
	/** directory name with full path */
	char *name;
	int name_len;
	/** a pointer to the next list item */
	struct dir_list_item *next;
};

struct packtree_point_value_array {
	struct vdfs4_pack_insert_point_value **val;
	int count;
};
/**
 * @brief	Parse parameters from vdfs4 unpack run command line.
 * @param [in]	argc	Number of command line parameters.
 * @param [in]	argv[]	An array with command line parameters strings.
 * @param [in]	sbi	A pointer to the structure containing runtime
 *			parameters of vdfs4 superblock.
 * @return	0 if parced successfully, or error
 */
int parse_cmd(int argc, char *argv[], struct vdfs4_sb_info *sbi);

#endif /* __UNPACK_H__ */
