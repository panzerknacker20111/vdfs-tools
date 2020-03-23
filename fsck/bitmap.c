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

#include <stdlib.h>
#include "../include/vdfs_tools.h"
#include "../include/vdfs4_layout.h"
#include "fsck.h"
#include <limits.h>

int create_bmap(int size_in_blocks, unsigned int block_size, char **bmap)
{
	*bmap = malloc(size_in_blocks * block_size);
	if (!*bmap)
		return -ENOMEM;
	memset(*bmap, 0, size_in_blocks * block_size);
	return EXIT_SUCCESS;
}

/* Used only for the debugging */
void print_bmap(struct bitmap_info *bmap)
{
	int i;
	int row_bmap_size = 80;

	for (i = 0; i < 4096; i++) {
		if (!(i % row_bmap_size) && i)
			printf("\n");
		printf("%x ", bmap->bitmap[i]);
	}
}

int read_bmap(int bitmap_ino, char *bmap,
		struct vdfs4_sb_info *sb_info, int *bmap_length)
{
	int ret = 0, i;
	struct vdfs4_base_table *base_table = sb_info->snapshot.base_table;
	struct vdfs4_base_table_record *table = VDFS4_GET_TABLE(base_table,
					bitmap_ino);
	int last_iblock = VDFS4_GET_LAST_IBLOCK(base_table, bitmap_ino);

	for (i = 0; i < last_iblock + 1; i++) {
		int block_num =  metablock_to_iblock(sb_info,
				table[i].meta_iblock);
		ret = vdfs4_read_blocks(sb_info, block_num, bmap +
				i * sb_info->block_size, 1);
	}
	*bmap_length = (last_iblock  + 1);
	return ret;
}

void add_meta_to_bmap(struct vdfs4_extended_super_block *esb,
		struct vdfs4_fsck_superblock_info *fsck_info)
{
	unsigned int i, tbc = 0;

	for (i = 0; i < VDFS4_META_BTREE_EXTENTS; i++) {

		struct vdfs4_extent *extnt;
		if (tbc <= esb->meta_tbc) {
			extnt = &esb->meta[i];
			add_extent_to_bmap(extnt, fsck_info);
			tbc += extnt->length;
		} else
			return;
	}
}

void add_table_to_bmap(struct vdfs4_extended_super_block *esb,
		struct vdfs4_fsck_superblock_info *fsck_info)
{
	add_extent_to_bmap(&esb->tables, fsck_info);
}

int add_fork_to_bmap(struct vdfs4_fork *fork,
	struct vdfs4_fsck_superblock_info *fsck_info)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < VDFS4_EXTENTS_COUNT_IN_FORK; i++) {

		struct vdfs4_extent *extnt;

		extnt = &fork->extents[i].extent;
		ret = add_extent_to_bmap(extnt, fsck_info);
		if (ret < 0)
			return ret;
	}
	return ret;
}

int is_extents_equal(struct vdfs4_extent *extent1, struct vdfs4_extent *extent2)
{
	if (extent1->begin == extent2->begin &&
		extent1->length == extent2->length)
		return true;
	else
		return false;

}

int is_extents_array_equal(struct vdfs4_extent *ext_arr1, struct vdfs4_extent
		*ext_arr2, __u32 n_elems)
{
	unsigned int i;

	for (i = 0; i < n_elems; i++)
		if (!is_extents_equal(&ext_arr1[i], &ext_arr2[i]))
			return false;

	return true;
}

int add_extents_to_buffer(char *buffer, struct vdfs4_extent *extnt,
	__u64 n_extents)
{
	unsigned int i = 0, j;
	int ret = 0;
	for (; i < n_extents; i++) {
		for (j = 0; j < extnt[i].length; j++) {
			if (util_test_bit(buffer, extnt[i].begin + j)) {
				log_error("Block %llu belongs to multiple "
					"files\n", extnt[i].begin + j);
				ret |= FSCK_INTERSECTED_EXTENTS;
			}
		}

		util_set_bits((char *) buffer, (__u64)
			extnt[i].begin, extnt[i].length);
	}
	return ret;
}

int add_extent_to_bmap(struct vdfs4_extent *ext,
	struct vdfs4_fsck_superblock_info *fsck_info)
{
	return util_sign_set_bits((char *) fsck_info->calc_bitmaps
		[SPACE_BM_INDEX].bitmap, fsck_info->sb_bitmaps
		[SPACE_BM_INDEX].length_in_bytes, (long long unsigned)
		ext->begin, ext->length, fsck_info->sbi.block_size,
		FSM_BMP_MAGIC_LEN, CRC32_SIZE);
}

int add_inode_to_bmap(__u64 inum, struct vdfs4_fsck_superblock_info *fsck_info)
{
	return util_sign_set_bits((char *) fsck_info->calc_bitmaps
		[INODE_BM_INDEX].bitmap, fsck_info->sb_bitmaps
		[INODE_BM_INDEX].length_in_bytes, inum, 1, fsck_info->
		sbi.block_size, INODE_BITMAP_MAGIC_LEN, CRC32_SIZE);
}

int add_inodes_to_bmap(__u64 inum, struct vdfs4_fsck_superblock_info *fsck_info,
		__u32 inodes_num)
{
	return util_sign_set_bits((char *) fsck_info->calc_bitmaps
		[INODE_BM_INDEX].bitmap, fsck_info->sb_bitmaps
		[INODE_BM_INDEX].length_in_bytes, inum, inodes_num + 1, fsck_info->
		sbi.block_size, INODE_BITMAP_MAGIC_LEN, CRC32_SIZE);
}

int add_bnode_to_bmap(int node_id, struct vdfs4_fsck_superblock_info *fsck_info,
		int tree_index)
{
	return util_sign_set_bits((char *) fsck_info->calc_bitmaps
		[tree_index].bitmap, fsck_info->sb_bitmaps
		[tree_index].length_in_bytes, node_id, 1, fsck_info->
		sbi.block_size, 0, 0);
}

int test_bnode_in_bmap(int node_id, struct vdfs4_fsck_superblock_info *fsck_info,
		int tree_index)
{
	return util_sign_test_bit((char *) fsck_info->calc_bitmaps
		[tree_index].bitmap, fsck_info->sb_bitmaps
		[tree_index].length_in_bytes, node_id, fsck_info->
		sbi.block_size, 0, 0);
}

void print_extent(struct vdfs4_extent *ext)
{
	printf("st: %8llu, ln: %8lld\n", ext->begin, ext->length);
}

void print_fork(struct vdfs4_fork *fork)
{
	unsigned int i;

	for (i = 0; i < VDFS4_EXTENTS_COUNT_IN_FORK; i++) {
		printf("Ext %1d ", i);
		print_extent(&fork->extents[i].extent);
	}
}

int is_block_in_fork(struct vdfs4_fork *fork, __u64 block)
{
	unsigned int i;

	for (i = 0; i < VDFS4_EXTENTS_COUNT_IN_FORK; i++) {
		if (is_block_in_extent(&fork->extents[i].extent, block))
			return true;
	}

	return false;
}

int is_block_in_extent(struct vdfs4_extent *ext, __u64 block)
{
	if (block >= ext->begin && (block < ext->begin + ext->length))
		return true;
	else
		return false;
}
