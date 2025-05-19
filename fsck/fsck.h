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

#ifndef FSCK_H_INCLUDED
#define FSCK_H_INCLUDED

#define NUM_OF_METADATA_FORKS_IN_ESB 8
#define NUM_OF_SB_ON_VOLUME 6

#define FSCK_DIFFERENCE_ERROR 1
#define FSCK_UNALIGNED_METADATA (1 << 1)
#define FSCK_CORRUPTED_RECORD (1 << 2)
#define FSCK_CORRUPTED_BNODE_ID (1 << 3)
#define FSCK_CORRUPTED_BNODE_MAGIC (1 << 4)
#define FSCK_INVALID_BTREE_HEIGHT (1 << 5)
#define FSCK_CORRUPTED_BTREE_STRUCTURE (1 << 6)
#define FSCK_RECORDS_OFFSETS_DOSENT_MATCH (1 << 7)
#define FSCK_INVALID_BNODE_FREESPACE (1 << 8)
#define FSCK_INVALID_RECS_CNT (1 << 9)
#define FSCK_INVALID_GEN_KEY (1 << 10)
#define FSCK_INVALID_TOTAL_ITEMS_COUNT (1 << 11)
#define FSCK_INVALID_LINKS_COUNT (1 << 12)
#define FSCK_INTERSECTED_EXTENTS (1 << 13)
#define FSCK_INVALID_TOTAL_BLOCKS_COUNT (1 << 14)
#define FSCK_CORRUPTED_OFFSET (1 << 15)
#define FSCK_BNODE_CRC_MISMATCH (1 << 16)

#define LEAKAGE_TYPE_1 0
#define LEAKAGE_TYPE_2 1

/* Corruption type */

#define CORRUPTED_EXTENT 1
#define NOT_A_SMALL_ORPHANE_EXTENT ULLONG_MAX

#include <errno.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <limits.h>
#include <stdio.h>
#include <math.h>
#include "../include/vdfs_tools.h"
#include "string.h"
#include <sys/time.h>
#include "../include/btree.h"
#include "../include/cattree.h"
#include "../include/vdfs4.h"
#include "../include/bitmap.h"
#include "../include/exttree.h"
#include "../include/compress.h"

#define CRC_BYTES_TO_SIGNIFICANT_BYTES(x) (x - ((x / 4096) * 16))

/* VDFS4_SPACE_BITMAP_INO, VDFS4_FREE_INODE_BITMAP_INO, */
#define FSCK_NUM_OF_CHECKED_BMAPS 2

/* VDFS4_CAT_TREE_INO, VDFS4_EXTENTS_TREE_INO, VDFS4_XATTR_TREE_INO */
#define FSCK_NUM_OF_CHECKED_TREES 3

#define FSCK_CHECKED_METADATA_ELS (FSCK_NUM_OF_CHECKED_BMAPS + \
					FSCK_NUM_OF_CHECKED_TREES)

#define SPACE_BM_INDEX 0
#define INODE_BM_INDEX 1
#define CATTREE_BM_INDEX 2
#define EXTTREE_BM_INDEX 3
#define XATTRTREE_BM_INDEX 4

#define FSCK_FIRST_TREE_INDEX CATTREE_BM_INDEX

#define VOLUME_UID_SIZE 16

extern struct vdfs4_btree *fsck_checked_trees[FSCK_NUM_OF_CHECKED_TREES];
extern char *fsck_checked_magics[FSCK_CHECKED_METADATA_ELS];
extern int fsck_checked_magics_len[FSCK_CHECKED_METADATA_ELS];
extern int fsck_checked_inos[FSCK_CHECKED_METADATA_ELS];
extern int fsck_checked_crc_size[FSCK_CHECKED_METADATA_ELS];

/**
 * @brief	The struct bm_difference_result is used to keep the result of
 *		calculate_difference function for inode and space bitmaps both.
 *		Struct contain info about number of extents, total difference
 *		and pointer to extents array
 */
struct bm_difference_result {
	struct vdfs4_extent *dif_extents;
	int n_extents;
	int difference;
	int *leakage_type;
};

struct total_items_element {
	/** inum **/
	__u64 inode_number;
	/** Amount of files in the directory */
	__u64	total_items_count;
	/** Link's count for file */
	__u64	links_count;
	/** Total blocks count*/
	__u64	total_blocks_count;
};

/* TODO Refactor fsck simple array, change find logic */
struct total_items_arr {
	__u64 n_elements;
	struct total_items_element *tie;
};

struct fsck_simple_array {
	__u64 n_elements;
	__u32 elem_size;
	void *elements;
};

struct inum_extents_dependency {
	/** Object id **/
	__u64 inum;
	struct fsck_simple_array extents;
};

struct squash_fs_dependency {
	/** Object id **/
	__u64 image_inum;
	__u64 mount_pt_inum;
};

struct par_name_dependency {
	/** Object id **/
	__u64 obj_id;
	__u64 par_id;
	__u8 name_len;
	char name[VDFS4_FILE_NAME_LEN];
};

/**
 * @brief	The struct bitmap_info is used to keep info about bitmap.
 *		Struct contain pointer to bitmap, and length of bitmap in blocks
 *		and bytes.
 */

struct bitmap_info {
	char *bitmap;
	int length_in_bytes;
	int length_in_blocks;
};

struct command_line_info {
	int dump_node;
	char file_name_to_find[VDFS4_FILE_NAME_LEN];
	long long unsigned int block_to_find;
	int injection_seed;
	char restore_file_path[VDFS4_FILE_NAME_LEN];
	int trash_size;
	int trash_offset;
};

struct vdfs4_fsck_superblock_info {
	struct vdfs4_sb_info sbi;

	/*|0 - space bitmap, 1 - inode bitmap, 2 - sf bitmap| */
	struct bitmap_info
	sb_bitmaps[FSCK_NUM_OF_CHECKED_BMAPS + FSCK_NUM_OF_CHECKED_TREES];
	struct bitmap_info
	calc_bitmaps[FSCK_NUM_OF_CHECKED_BMAPS + FSCK_NUM_OF_CHECKED_TREES];
	struct bm_difference_result
	difference_result[FSCK_NUM_OF_CHECKED_BMAPS +
	FSCK_NUM_OF_CHECKED_TREES];

	struct total_items_arr calculated_tia;
	struct total_items_arr readed_tia;

	struct fsck_simple_array inum_fork_dep;

	struct command_line_info cmd_info;

	struct fsck_simple_array orphane_inodes;
	struct fsck_simple_array squash_mnt_dep;
	struct fsck_simple_array par_name_dep;
	/* CoW metadata tables */
	void *translation_tables;
};

typedef int (tree_handler)(struct vdfs4_btree_gen_record *,
		struct vdfs4_fsck_superblock_info *, void **callback);
typedef struct vdfs4_btree_gen_record *(common_get_first_record)
	(struct vdfs4_fsck_superblock_info *);


int print_record(struct vdfs4_bnode *bn, int rec_ctr, enum vdfs4_btree_type
		btree_type);

int print_bnode(struct vdfs4_btree *btree, __u32 node_id);

int print_superblock(struct vdfs4_fsck_superblock_info *fsck_info);

int is_fork_corrupted(struct vdfs4_fork *fk,
		struct vdfs4_fsck_superblock_info *fsck_info);

int is_extent_corrupted(struct vdfs4_extent *extnt,
	struct vdfs4_fsck_superblock_info *fsck_info);

int parse_cmd(int argc, char *argv[], struct vdfs4_fsck_superblock_info
		*fsck_info);

const char *print_metadata_name_by_inode(int inode_num);

int add_catrec_to_bmaps(struct vdfs4_btree_gen_record *rec,
		struct vdfs4_fsck_superblock_info *fsck_info, void **callback);

int add_extrec_to_bmap(struct vdfs4_btree_gen_record *rec,
		struct vdfs4_fsck_superblock_info *fsck_info, void **callback);
int check_orphan_inodes(struct vdfs4_fsck_superblock_info *fsck_info);
int create_bmap(int size_in_blocks, unsigned int block_size, char **bmap);

int read_bmap(int bitmap_ino, char *bmap,
		struct vdfs4_sb_info *sb_info, int *bmap_length);

int add_fork_to_bmap(struct vdfs4_fork *fork,
	struct vdfs4_fsck_superblock_info *fsck_info);

int add_extent_to_bmap(struct vdfs4_extent *ext,
	struct vdfs4_fsck_superblock_info *fsck_info);

void add_table_to_bmap(struct vdfs4_extended_super_block *esb,
		struct vdfs4_fsck_superblock_info *fsck_info);
void add_meta_to_bmap(struct vdfs4_extended_super_block *esb,
		struct vdfs4_fsck_superblock_info *fsck_info);

void print_fork(struct vdfs4_fork *fork);

int is_block_in_fork(struct vdfs4_fork *fork, long long unsigned int block);

int is_block_in_extent(struct vdfs4_extent *ext, __u64 block);

void print_extent(struct vdfs4_extent *ext);

int add_inode_to_bmap(__u64 inum, struct vdfs4_fsck_superblock_info *fsck_info);

int add_inodes_to_bmap(__u64 inum, struct vdfs4_fsck_superblock_info *fsck_info,
		__u32 inodes_num);

int check_all_trees_structure(struct vdfs4_fsck_superblock_info *fsck_info);

int test_bnode_in_bmap(int node_id, struct vdfs4_fsck_superblock_info *fsck_info,
		int tree_index);

int add_bnode_to_bmap(int node_id, struct vdfs4_fsck_superblock_info *fsck_info,
		int tree_index);

int check_total_items_and_links(struct vdfs4_fsck_superblock_info *fsck_info);

int is_extents_array_equal(struct vdfs4_extent *ext_arr1, struct vdfs4_extent
		*ext_arr2, __u32 n_elems);

int check_extents_intersection(struct vdfs4_fsck_superblock_info *fsck_info,
	int maximal_block);

int add_extents_to_buffer(char *buffer, struct vdfs4_extent *extnt,
	__u64 n_extents);

int restore_full_file_name(struct vdfs4_fsck_superblock_info *fsck_info,
	__u64 obj_id, char **result_path, int *path_len);

void *get_array_elem(struct fsck_simple_array *arr, __u32 index);

int build_squash_mnt_pt_config(struct vdfs4_fsck_superblock_info *fsck_info);

void print_bmap(struct bitmap_info *bmap);
#endif
