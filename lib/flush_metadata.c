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

#include <vdfs_tools.h>
#include <vdfs4_layout.h>
#include <vdfs4.h>
#include <time.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
/**
 * @brief Function flushes subsystem on volume
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */


int flush_debug_area(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	char *buf = malloc(sbi->block_size * sbi->debug_area.block_count);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, sbi->block_size * sbi->debug_area.block_count);
	ret = vdfs4_write_blocks(sbi, sbi->debug_area.first_block,
				buf, sbi->debug_area.block_count);
	free(buf);
	if (ret)
		log_error("Can't put debug area on disk");
	return ret;
}
#define VDFS4_GET_IBLOCK(mblock, first_mblock)	(mblock + first_mblock)
int flush_subsystem(struct vdfs4_sb_info *sbi,
		struct vdfs4_subsystem_data *subsystem)
{
	int ret = 0;
	__u32 i;
	__u64 start_block;
	struct vdfs4_base_table_record *table;
	__le64 last_iblock;
	__u32 blocks_count;
	struct vdfs4_base_table *base_table;
	if (!sbi->vdfs4_volume)
		goto usual_flash;

	if (subsystem->sub_system_id > 0 &&
			subsystem->sub_system_id <= VDFS4_LSFILE) {
		base_table = (struct vdfs4_base_table *)
				sbi->snapshot.snapshot_subsystem.buffer;
		table = (struct vdfs4_base_table_record *)(VDFS4_GET_TABLE(
				base_table, subsystem->sub_system_id));
		last_iblock = le64_to_cpu(VDFS4_GET_LAST_IBLOCK(base_table,
				subsystem->sub_system_id));

		blocks_count = (last_iblock + 1) * get_iblock_size(sbi,
				subsystem->sub_system_id);
		for (i = 0; i < blocks_count; i++) {
			start_block = metablock_to_iblock_for_conversion(sbi,
					table[i].meta_iblock)
					+ sbi->vdfs4_start_block;
			ret = vdfs4_write_blocks(sbi, start_block,
					subsystem->buffer + i * sbi->block_size,
					1);
			if (ret) {
				log_error("Can't copy %s to disk",
						subsystem->subsystem_name);
				break;
			}
		}
		return ret;
	} else {
		struct vdfs4_extent_info *extent;
		u_int32_t used_extents = 0;
		if (subsystem->sub_system_id == 0) {
			extent = &sbi->snapshot.tables_extent;
			used_extents = sbi->snapshot.tables_extent_used;
		} else if (subsystem->sub_system_id >  VDFS4_LSFILE) {
			extent = subsystem->fork.extents;
			used_extents = subsystem->fork.used_extents;
		}
		for (i = 0; i <= used_extents; i++) {
			ret = vdfs4_write_blocks(sbi,
				(u_int64_t)extent[i].first_block +
				sbi->vdfs4_start_block,
				subsystem->buffer, extent[i].block_count);
			if (ret)
				return ret;
		}

		return ret;
	}


usual_flash:
	if (subsystem->sub_system_id == 0) {
		start_block = sbi->snapshot.tables_extent.first_block;
		blocks_count = sbi->snapshot.tables_extent.block_count;
		goto write;
	} else if (subsystem->sub_system_id > VDFS4_LSFILE) {
		start_block = subsystem->fork.extents[0].first_block;
		blocks_count = subsystem->fork.extents[0].block_count;
		goto write;
	}



	base_table = (struct vdfs4_base_table *)
			sbi->snapshot.snapshot_subsystem.buffer;
	table = (struct vdfs4_base_table_record *)(VDFS4_GET_TABLE(base_table,
			subsystem->sub_system_id));
	last_iblock = le64_to_cpu(VDFS4_GET_LAST_IBLOCK(base_table,
			subsystem->sub_system_id));

	blocks_count = (last_iblock + 1) * get_iblock_size(sbi,
			subsystem->sub_system_id);
	start_block = le64_to_cpu(VDFS4_GET_IBLOCK(table->meta_iblock,
			sbi->snapshot.metadata_extent[0].first_block));
	assert(start_block != 0);
write:

	ret = vdfs4_write_blocks(sbi, (u_int64_t)start_block,
			subsystem->buffer, blocks_count);
	if (ret)
		log_error("Can't copy % to disk", subsystem->subsystem_name);
	else
		log_activity("Copy %s", subsystem->subsystem_name);
	return ret;
}
/**
 * @brief Function flushes subsystem tree on volume
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int flush_subsystem_tree(struct vdfs4_sb_info *sbi,
		struct vdfs_tools_btree_info *tree)
{
	int ret = 0;
	u64 i;
	__u64 version = VERSION;
	__u64 bnodes_count = get_bnodes_count(tree);
	struct vdfs4_base_table *base_table = (struct vdfs4_base_table *)
			sbi->snapshot.snapshot_subsystem.buffer;
	/** FIXME check subsystem fragmentation */
	struct vdfs4_base_table_record *table = (VDFS4_GET_TABLE(
			base_table, tree->tree.sub_system_id));
	u64 start = 0;
	for (i = 0; i < bnodes_count; i++) {
		if (sbi->vdfs4_volume)
			start = metablock_to_iblock_for_conversion(sbi,
					table[i].meta_iblock) +
					sbi->vdfs4_start_block;
		else
			start = VDFS4_GET_IBLOCK(table[i].meta_iblock,
				sbi->snapshot.metadata_extent[0].first_block)
				+ sbi->vdfs4_start_block;
		memcpy(tree->bnode_array[i]->data + 4, &version, VERSION_SIZE);
		util_update_crc(tree->bnode_array[i]->data,
				get_bnode_size(sbi), NULL, 0);
		ret = vdfs4_write_blocks(sbi, start, tree->bnode_array[i]->data,
					byte_to_block(get_bnode_size(sbi),
							sbi->block_size));
		if (ret) {
			log_error("Can't copy %s to disk",
					tree->tree.subsystem_name);
			break;
		}
	}
	if (!ret)
		log_activity("Copy %s", tree->tree.subsystem_name);
	return ret;
}
/******************************************************************************/
int fill_superblock(struct vdfs4_sb_info *sbi)
{
	int real_sb_size;
	int ret = 0;
	assert(sizeof(struct vdfs4_super_block) == 512);

	memset(&sbi->sb, 0, sizeof(struct vdfs4_super_block));
	set_magic(sbi->sb.signature, VDFS4_SB_SIGNATURE);
	memcpy(sbi->sb.layout_version, VDFS4_LAYOUT_VERSION,
		strlen(VDFS4_LAYOUT_VERSION));

	sbi->sb.log_block_size = log2_32(sbi->block_size);
	sbi->sb.log_super_page_size = log2_32(sbi->super_page_size);
	sbi->sb.log_erase_block_size = log2_32(sbi->erase_block_size);

	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		sbi->image_size = get_image_size(sbi);
		sbi->min_image_size = sbi->image_size;
		sbi->sb.read_only = 1;
		sbi->sb.image_crc32_present =
				IS_FLAG_SET(sbi->service_flags, IMAGE_CRC32) ?
						1 : 0;
	}

	sbi->sb.maximum_blocks_count =
		cpu_to_le64(sbi->image_size / sbi->block_size);

	memcpy(&sbi->sb.creation_timestamp, &sbi->timestamp,
				sizeof(sbi->sb.creation_timestamp));

	memcpy(sbi->sb.volume_uuid, sbi->volume_uuid,
			sizeof(sbi->sb.volume_uuid) /
			sizeof(sbi->sb.volume_uuid[0]));

	memcpy(sbi->sb.volume_name, sbi->volume_name,
			sizeof(sbi->volume_name));

#ifdef GIT_BRANCH
	if (sizeof(GIT_BRANCH) != 0)
		set_magic(sbi->sb.mkfs_git_branch, GIT_BRANCH);
#endif

#ifdef GIT_HASH
	if (sizeof(GIT_HASH) != 0)
		set_magic(sbi->sb.mkfs_git_hash, GIT_HASH);
#endif

	sbi->sb.case_insensitive =
			IS_FLAG_SET(sbi->service_flags, CASE_INSENSITIVE);

	/* +2 = +1 - root, +1 - last_allocated */
	sbi->sb.image_inode_count =
			cpu_to_le64(sbi->last_allocated_inode_number + 2);
	/*SB signing*/
	if (sbi->rsa_key) {
		log_activity("Superblock signing");
		if (sbi->hash_alg == SHA256)
			sbi->sb.hash_type = VDFS4_HASH_SHA256;
		else if (sbi->hash_alg == SHA1)
			sbi->sb.hash_type = VDFS4_HASH_SHA1;
		else if (sbi->hash_alg == MD5)
			sbi->sb.hash_type = VDFS4_HASH_MD5;
		real_sb_size = sizeof(sbi->sb) - sizeof(sbi->sb.sb_hash) -
			sizeof(sbi->sb.checksum);
		ret = sign_rsa((unsigned char *)&sbi->sb, real_sb_size,
			sbi->sb.sb_hash, sbi->rsa_key, sbi->hash_alg,
			sbi->hash_len);
		if (ret)
			log_error("RSA signing error");
	}
	sbi->sb.checksum = cpu_to_le32(vdfs4_crc32(&(sbi->sb), sizeof(sbi->sb)
			- sizeof(sbi->sb.checksum)));

	return ret;

}

/******************************************************************************/
void fill_layout_fork(struct vdfs4_fork *fork, struct vdfs4_fork_info *fork_info,
		u_int32_t block_size)
{
	unsigned int count;

	memset((void *)fork, 0, sizeof(*fork));

	fork->total_blocks_count = cpu_to_le32(fork_info->total_block_count);
	fork->size_in_bytes = cpu_to_le64
			(block_to_byte(fork_info->total_block_count,
					block_size));

	for (count = 0; count < fork_info->used_extents; count++)
		init_iextent(&fork->extents[count],
				fork_info->extents[count].first_block,
				fork_info->extents[count].block_count,
				fork_info->extents[count].iblock);
}

void fill_ext_superblock(struct vdfs4_sb_info *sbi)
{
	struct snapshot_info *snapshot = &sbi->snapshot;
	__u32 i;
	assert(sizeof(sbi->esb) <= VDFS4_EXSB_LEN);
	assert(sizeof(struct vdfs4_extended_super_block) == 512 * 5);


	memset(&sbi->esb, 0, sizeof(struct vdfs4_extended_super_block));
	/* Copy-on-Write metadata updating algorithm */
	/* fill extended superblock */

	for (i = 0; i < sbi->snapshot.snapshot_subsystem.fork.used_extents + 1;
			i++) {
		sbi->esb.meta[i].begin =
			cpu_to_le64(snapshot->metadata_extent[i].first_block);
		sbi->esb.meta[i].length =
			cpu_to_le32(snapshot->metadata_extent[i].block_count);
		sbi->esb.meta_tbc +=
			cpu_to_le32(snapshot->metadata_extent[i].block_count);
	}

	sbi->esb.tables.begin =
		cpu_to_le64(snapshot->tables_extent.first_block);
	sbi->esb.tables.length =
		cpu_to_le32(snapshot->tables_extent.block_count);

	/*sbi->esb.tables[0].begin =
		cpu_to_le64(snapshot->tables_extent.first_block);
	sbi->esb.tables[0].length =
		cpu_to_le32(snapshot->tables_extent.block_count);
	sbi->esb.tables_tbc =
		cpu_to_le32(snapshot->tables_extent.block_count);*/
	sbi->esb.volume_body.length = cpu_to_le32(get_volume_body_length(sbi));

	sbi->esb.volume_blocks_count =
		cpu_to_le64(sbi->min_image_size / sbi->block_size);

	sbi->esb.files_count = cpu_to_le64(sbi->files_count);
	sbi->esb.folders_count = cpu_to_le64(sbi->folders_count);
	sbi->esb.crc = CRC_ENABLED;

	/* fill debug area extent: fixed place 1,2,3,4 blocks */
	sbi->esb.debug_area.begin = cpu_to_le64(sbi->debug_area.first_block);
	sbi->esb.debug_area.length = cpu_to_le32(sbi->debug_area.block_count);

	sbi->esb.sync_counter = cpu_to_le32(1);
	sbi->esb.checksum = cpu_to_le32(vdfs4_crc32(&sbi->esb, sizeof(sbi->esb) -
			sizeof(sbi->esb.checksum)));
}

int prepare_superblocks(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	ret = fill_superblock(sbi);
	if (ret)
		return ret;
	fill_ext_superblock(sbi);
	return ret;
}

int clean_superblocks_area(struct vdfs4_sb_info *sbi)
{
	int write_size = (VDFS4_RESERVED_AREA_LENGTH + SB_SIZE +
			VDFS4_EXSB_LEN) * 2;
	u8 write_buffer[write_size];
	int ret = 0;

	memset(write_buffer, 0, write_size);

	ret = vdfs4_write_blocks(sbi, 0 + sbi->vdfs4_start_block, write_buffer,
		byte_to_block(write_size, sbi->block_size));

	sync();

	return ret;
}


static void copy_cmd_line(int argc, char *argv[], char *buffer)
{
	size_t length;
	struct vdfs4_volume_begins *cmd_block =
			(struct vdfs4_volume_begins *)buffer;
	if (argc > 2)
		length = (size_t)((argv[argc - 2] - argv[0]) +
			strnlen(argv[argc - 2], IMAGE_CMD_LENGTH - 1));
	else
		length = (size_t)((argv[argc - 1] - argv[0]) +
				strnlen(argv[argc - 1], IMAGE_CMD_LENGTH - 1));

	memcpy(cmd_block->command_line, *argv, length);

	set_magic(cmd_block->signature, VDFS4_SB_SIGNATURE);
	memcpy(cmd_block->layout_version, VDFS4_LAYOUT_VERSION,
		strlen(VDFS4_LAYOUT_VERSION));

	cmd_block->checksum = cpu_to_le32(vdfs4_crc32(cmd_block,
			sizeof(*cmd_block) - 4));
}

int flush_superblocks(struct vdfs4_sb_info *sbi, int argc, char *argv[])
{
	int write_size = VDFS4_RESERVED_AREA_LENGTH + SB_SIZE +
			VDFS4_EXSB_LEN;
	u8 write_buffer[write_size];
	unsigned long long range[2];
	int ret = 0;
	int i;

	memset(write_buffer, 0, write_size);

	/* the first 512 bytes of the vdfs4 volume contains mkfs cmd line */
	copy_cmd_line(argc, argv, (char *)write_buffer);

	/* filling vdfs4 reserved area of first sb with one copy of
	 * superblock, then writing superblock on it's normal place
	 * (1024 bytes shift) */
	for (i = 1; i < 3; i++)
		memcpy(write_buffer + sizeof(sbi->sb) * i, &sbi->sb,
				sizeof(sbi->sb));

	memcpy(write_buffer + 3 * SB_SIZE, &sbi->esb, sizeof(sbi->esb));

#ifdef BLKDISCARD
	/*Trim from 0 to debug_area*/
	if (!sbi->vdfs4_volume) {
		range[0] = 0;
		range[1] = sbi->debug_area.first_block * sbi->block_size
				- range[0];
		ret = ioctl(sbi->disk_op_image.file_id, BLKDISCARD, &range);
		if (ret < 0)
			log_info("Trim: %s", strerror(errno));

		/* Trim from end of debug_area to end of volume */
		range[0] = (sbi->debug_area.first_block +
			sbi->debug_area.block_count) * sbi->block_size;
		range[1] = sbi->image_size - range[0];
		ret = ioctl(sbi->disk_op_image.file_id, BLKDISCARD, &range);
	}
#endif
	if (sbi->vdfs4_volume) {
		char *superblock_copy_buf = malloc(sbi->block_size);
		memset(superblock_copy_buf, 0, sbi->block_size);
		ret = vdfs4_write_blocks(sbi, (byte_to_block(sbi->image_size,
				sbi->block_size) - sbi->vdfs4_start_block),
				superblock_copy_buf, 1);
		free(superblock_copy_buf);
		if (ret)
			return ret;

	}
	log_activity("Copy superblocks");
	ret = vdfs4_write_blocks(sbi, 0 + sbi->vdfs4_start_block, write_buffer,
		byte_to_block(write_size, sbi->block_size));
	if (ret)
		return ret;
	ret = vdfs4_write_blocks(sbi, 1 + sbi->vdfs4_start_block, write_buffer,
		byte_to_block(write_size, sbi->block_size));
	if (ret)
		return ret;
	if ((IS_FLAG_SET(sbi->service_flags, IMAGE)) &&
			(!IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) &&
			(IS_FLAG_SET(sbi->service_flags, NO_STRIP_IMAGE)))
		ret = ftruncate(sbi->disk_op_image.file_id, sbi->image_size);
	return ret;
}



int allocate_fixed_areas(struct vdfs4_sb_info *sbi)
{
	int ret = 0;

	/* begin of a volume :						*/
	/* 0    1    2    3      8    9    10   11    16             32 */
	/* | SB | SB | SB | EXSB | SB | SB | SB | EXSB |  DEBUG AREA |  */

	/*
	 * first 4k - superblocks (superblock and extended superblock)
	 * second 4k - superblocks copy
	 * 8-16K Debug area
	 * */

	/* Mark unaligned areas at the begin and end of partition
	 * as used and change space manager data accordingly. */
	ret = allocate_space(sbi, 0, 1, NULL);
	if (ret) {/* First superblock */
		log_error("Can not get free space for first superblock");
		return ret;
	} else
		log_activity("First superblock allocated at block %lu",
			NULL);
	ret = allocate_space(sbi, 1, 1, NULL);
	if (ret) {
		log_error("Can not get free space for second"
				" superblock");
		return ret;	/* ... second */
	} else
		log_activity("Second superblock allocated at block %lu", 1);
	/*allocate space for debug area*/
	ret = allocate_space(sbi, sbi->debug_area.first_block,
			sbi->debug_area.block_count, NULL);

	return ret;
}

void generate_uuid(u_int8_t *uuid_array, u_int32_t uuid_length)
{
	u_int32_t i;
	unsigned int rand_32;
	u_int8_t rand_char;

	for (i = 0; i < uuid_length; i++) {
		do {
			rand_32 = rand();
			/* small digits of rand() is not truly random,     */
			/* so get big one                                    */
			rand_char = (u_int8_t)(rand_32 >> 24);
		} while (!isalpha(rand_char));

		uuid_array[i] = rand_char;
	}
}
