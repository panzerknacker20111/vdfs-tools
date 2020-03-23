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

#include "fsck.h"

unsigned int vdfs4_debug_mask = 0
		/*+ VDFS4_DBG_INO*/
		/*+ VDFS4_DBG_FSM*/
		/*+ VDFS4_DBG_SNAPSHOT*/
		/*+ VDFS4_DBG_TRANSACTION*/
		+ VDFS4_DBG_BTREE
		+ VDFS4_DBG_TMP
		;
const unsigned int vdfs_tools_mode = 0
		/*+ VDFS4_TOOLS_MULTITHREAD*/
		+ VDFS4_TOOLS_GET_BNODE_FROM_VOL
		;

char *fsck_checked_magics[FSCK_CHECKED_METADATA_ELS] = {
	FSM_BMP_MAGIC,
	INODE_BITMAP_MAGIC,
	"",
	"",
	""};

int fsck_checked_magics_len[FSCK_CHECKED_METADATA_ELS] = {
	FSM_BMP_MAGIC_LEN,
	INODE_BITMAP_MAGIC_LEN,
	0,
	0,
	0};

int fsck_checked_crc_size[FSCK_CHECKED_METADATA_ELS] = {
	4, 4, 0, 0, 0};

int fsck_checked_inos[FSCK_CHECKED_METADATA_ELS] = {
	VDFS4_SPACE_BITMAP_INO,
	VDFS4_FREE_INODE_BITMAP_INO,
	VDFS4_CAT_TREE_INO,
	VDFS4_EXTENTS_TREE_INO,
	VDFS4_XATTR_TREE_INO
};

int parse_debug_area(struct vdfs4_fsck_superblock_info *fsck_info)
{
	struct vdfs4_debug_record *debug_area_curr_rec_addr;
	int is_oops_area_present, ret = 0;
	void *debug_area_raw = malloc(DEBUG_AREA_DEFAULT_SIZE *
			fsck_info->sbi.block_size);

	if (!debug_area_raw)
		return -ENOMEM;

	struct vdfs4_debug_descriptor *debug_descriptor =
			(struct vdfs4_debug_descriptor *)debug_area_raw;

	ret = vdfs4_read_blocks(&fsck_info->sbi, DEBUG_AREA_DEFAULT_START,
			debug_area_raw, DEBUG_AREA_DEFAULT_SIZE);

	if (ret) {
		free(debug_area_raw);
		log_error("Can't read debug area\n");
		return -ERDFAIL;
	}

	is_oops_area_present = !(strncmp((char *) debug_descriptor->signature,
			VDFS4_OOPS_MAGIC, sizeof(VDFS4_OOPS_MAGIC) - 1));

	if (!is_oops_area_present) {
		free(debug_area_raw);
		log_info("There is no debug area on this volume\n");
		return EXIT_SUCCESS;
	}

	debug_area_curr_rec_addr = (struct vdfs4_debug_record *)
		((char *)debug_descriptor + sizeof(*debug_descriptor));

	printf("%10s%10s%10s%10s%10s%10s%3s%20.20s%6s\n", "UUID",
					"Fail num",
					"Err code",
					"Fail time", "Mnt ctr",
					"Sync ctr", "   ", "Func name",
					"Line");

	while ((u32)((char *)debug_area_curr_rec_addr - (char *)debug_area_raw)
		<= (u32)(DEBUG_AREA_DEFAULT_SIZE *
				(fsck_info->sbi.block_size))) {

		printf("%10llu%10hd%10d%10d%10d%10d%3s%20.20s%6s\n",
				debug_area_curr_rec_addr->uuid,
				debug_area_curr_rec_addr->fail_number,
				debug_area_curr_rec_addr->error_code,
				debug_area_curr_rec_addr->fail_time,
				debug_area_curr_rec_addr->mount_count,
				debug_area_curr_rec_addr->sync_count, "   ",
				debug_area_curr_rec_addr->function,
				debug_area_curr_rec_addr->line);

		debug_area_curr_rec_addr++;
	}

	free(debug_area_raw);
	return EXIT_SUCCESS;
}

/* TODO Refactor */
int find_file(struct vdfs4_fsck_superblock_info *fsck_info,
		char *name, long long unsigned int block)
{
	int found = 0;
	int ret = 0;
	struct vdfs4_sb_info *vdfs4_sbi = &fsck_info->sbi;
	struct vdfs4_cattree_record *cat_rec =
		vdfs4_cattree_get_first_child(vdfs4_sbi->catalog_tree,
					VDFS4_ROOT_INO);
	struct vdfs4_cattree_record *hl_rec = NULL;
	__u64 found_ino = -1;
	if (!IS_ERR(cat_rec)) {

		do {
			__u64 ino_n = -1;
			char *cur_file_name = cat_rec->key->name;

			struct vdfs4_catalog_file_record *file_rec;
			struct vdfs4_fork fk;
			if (le16_to_cpu(cat_rec->key->record_type) ==
					VDFS4_CATALOG_FILE_RECORD) {
				file_rec =
					(struct vdfs4_catalog_file_record *)
						cat_rec->val;
				ino_n = cat_rec->key->object_id;
			} else if (le16_to_cpu(cat_rec->key->record_type) ==
				VDFS4_CATALOG_HLINK_RECORD) {
				ino_n = cat_rec->key->object_id;
				hl_rec = vdfs4_cattree_find(
					vdfs4_sbi->catalog_tree,
					ino_n, NULL, 0, VDFS4_BNODE_MODE_RO);
				if (IS_ERR(hl_rec)) {
					ret = vdfs4_cattree_get_next_record(
						cat_rec);
					continue;
				}

				file_rec = hl_rec->val;
			} else {
				ret = vdfs4_cattree_get_next_record(cat_rec);
				continue;
			}

			fk = file_rec->data_fork;

			if (!strcmp(name, cur_file_name)) {
				found = 1;
				found_ino = ino_n;
				printf("Total blc: %lld\n",
					fk.total_blocks_count);
				printf("File %s, inum: %llu record type %d\n",
					cur_file_name,
					ino_n, cat_rec->key->record_type);
				print_fork(&fk);
				printf("\n");
			}

			if (is_block_in_fork(&fk, block)) {
				printf("File with block %llu have\n\t"
					"name '%s' and inum %llu,"
					" record type %d\n",
					block, cur_file_name,
					ino_n, cat_rec->key->
						record_type);
				found = 1;
			}


			if (hl_rec) {
				vdfs4_release_record(
				(struct vdfs4_btree_gen_record *)hl_rec);
				hl_rec = NULL;
			}
			ret = vdfs4_cattree_get_next_record(cat_rec);
			if (ret && (ret != -ENOENT)) {
				log_error("Cattree parsing error");
				return ret;
			}
		} while ((int)(intptr_t)ret != -ENOENT);
	}

	struct vdfs4_exttree_record *ext_rec =
			vdfs4_exttree_find_first_record(vdfs4_sbi, 0,
				VDFS4_BNODE_MODE_RW);

	if (!IS_ERR(ext_rec)) {
		do {
			if (is_block_in_extent(ext_rec->lextent, block)) {
				printf("Block found in exttree,\n"
					" owner is file with inum = %llu\n",
					ext_rec->key->object_id);
				found = 1;
			}
			if (ext_rec->key->object_id == found_ino)
				print_extent(ext_rec->lextent);

			ret = vdfs4_exttree_get_next_record(ext_rec);

		} while (ret != -ENOENT);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) ext_rec);
	} else if ((int)(intptr_t)ext_rec == -ENOENT) {
		log_info("Empty exttree\n");
	} else {
		log_error("Corrupted root bnode or record in exttree\n");
		return -ERDFAIL;
	}

	if (found) {
		if (hl_rec)
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
				hl_rec);
		return EXIT_SUCCESS;
	} else {
		log_error("Not found");
		return -EINVAL;
	}
}

struct vdfs4_btree_gen_record *exttree_get_first_record(
		struct	vdfs4_fsck_superblock_info *fsck_info)
{
	return (struct vdfs4_btree_gen_record *)vdfs4_exttree_find_first_record(
		&fsck_info->sbi, 0, VDFS4_BNODE_MODE_RW);
}

struct vdfs4_btree_gen_record *cattree_get_first_record(
	struct vdfs4_fsck_superblock_info *fsck_info)
{
	return (struct vdfs4_btree_gen_record *)vdfs4_cattree_get_first_child(
		fsck_info->sbi.catalog_tree, VDFS4_ROOT_INO);
}

int general_tree_parser(struct vdfs4_fsck_superblock_info *fsck_info,
	tree_handler handler, common_get_first_record get_first_rec,
	void **callback)
{
	int ret = 0;
	int corruption_errors = 0;
	struct vdfs4_btree_gen_record *rec = get_first_rec(fsck_info);

	if (!IS_ERR(rec)) {
		do {
			ret = handler(rec, fsck_info, callback);
			if (ret < 0)
				corruption_errors = 1;

			ret = vdfs4_get_next_btree_record((void *)rec);
			if (ret && (ret != -ENOENT)) {
				log_error("Tree parsing error, "
					"probably tree structure is damaged\n");
				return ret;
			}
		} while ((int)(intptr_t)ret != -ENOENT);
		vdfs4_release_record((struct vdfs4_btree_gen_record *)rec);
	} else if ((int)(intptr_t)rec == -ENOENT) {
		log_info("Empty tree\n");
	} else {
		log_error("Corrupted root bnode or record in tree\n");
		return -ERDFAIL;
	}

	if (!corruption_errors)
		return EXIT_SUCCESS;
	else
		return FSCK_CORRUPTED_RECORD;
}

int check_metadata_alignment(struct vdfs4_fsck_superblock_info *fsck_info)
{
	int ret = 0;
	struct vdfs4_sb_info *sbi = &fsck_info->sbi;
	int super_page_size = (1 << (sbi->sb.log_super_page_size -
			sbi->sb.log_block_size));
	int tables_count = 0;
	struct vdfs4_base_table *base_table = sbi->snapshot.base_table;
	int trees_array[FSCK_NUM_OF_CHECKED_TREES] = {VDFS4_CAT_TREE_INO,
		VDFS4_EXTENTS_TREE_INO, VDFS4_XATTR_TREE_INO};

	for (; tables_count < FSCK_NUM_OF_CHECKED_TREES; tables_count++) {
		struct vdfs4_base_table_record *table;
		int count;
		int tree_ino = trees_array[tables_count];

		int iblock_count = le64_to_cpu(base_table->last_page_index
			[VDFS4_SF_INDEX(tree_ino)]) + 1;

		table = (struct vdfs4_base_table_record *)
				(VDFS4_GET_TABLE(base_table, tree_ino));
		for (count = 0; count < iblock_count; count++) {
			if (table->meta_iblock % super_page_size) {
				log_error("Alignment violation %s block %llu",
					print_metadata_name_by_inode(tree_ino),
					*table);
				ret |= FSCK_UNALIGNED_METADATA;
			}
			table++;
		}
	}

	return ret;
}

int check_volume(struct vdfs4_sb_info *sbi)
{
	int ret = 0, ctr = 0;

	/* superblocks contains {first_sb, second_sb, third_sb, sb_copy} */
	struct vdfs4_super_block *superblocks[NUM_OF_SB_ON_VOLUME];
	memset(superblocks, 0, NUM_OF_SB_ON_VOLUME *
		sizeof(struct vdfs4_super_block *));

	sbi->block_size = SECTOR_SIZE;
	int sb_initial_block_pos[NUM_OF_SB_ON_VOLUME] = {0, 1, 2,
		8, 9, 10};

	/* read super block and extended super block from volume */
	/*  0    1    2    3      8    9   10   11     15   */
	/*  | SB | SB | SB |ESB   | SB | SB | SB |ESB   |   */
	/*  |    superblocks      |   superblocks_copy  |   */

	for (; ctr < NUM_OF_SB_ON_VOLUME; ctr++) {
		superblocks[ctr] = malloc(SB_SIZE);
		if (!superblocks[ctr]) {
			log_error("Out of memory\n");
			ret = -ENOMEM;
			goto exit;
		}

	ret |= vdfs4_read_blocks(sbi, sb_initial_block_pos[ctr],
			superblocks[ctr], 1);

	if (ret) {
			log_error("Can't read SB# %d\n", ctr);
			ret = -ERDFAIL;
			goto exit;
		}

	if (memcmp(superblocks[ctr]->signature,
			VDFS4_SB_SIGNATURE, strlen(VDFS4_SB_SIGNATURE))) {
			log_error("Signature is incorrect SB# %d\n", ctr);
			ret = -EINVAL;
			goto exit;
		}

	if (memcmp(superblocks[ctr]->layout_version,
			VDFS4_LAYOUT_VERSION, strlen(VDFS4_LAYOUT_VERSION))) {
			VDFS4_ERR("Invalid mkfs layout version: %.4s,\n"
			"fsck uses %.4s version\n", sbi->sb.layout_version,
			VDFS4_LAYOUT_VERSION);
			return -EINVAL;
		}

	if (!(superblocks[ctr]->checksum == vdfs4_crc32(superblocks[ctr],
			SB_SIZE - sizeof(superblocks[ctr]->checksum)))) {
			log_error("CRC is incorrect SB# %d\n", ctr);
			ret = -EINVAL;
			goto exit;
		}
	}
exit:
	/* free */
	for (ctr = 0; ctr < NUM_OF_SB_ON_VOLUME; ctr++)
		free(superblocks[ctr]);

	return ret;
}

int calculate_difference(char *calc_bitmap, char *sb_bitmap,
		int bitmap_length, struct bm_difference_result *diff_ret, int
		block_size, int magic_len, int crc_size)
{
	int btm_ctr = 0, ext_length = 0;
	int start_ext = -1;
	int test_bit = 0;
	int extent_size = sizeof(struct vdfs4_extent);
	int n_sign_bytes = CRC_BYTES_TO_SIGNIFICANT_BYTES(bitmap_length);
	diff_ret->n_extents = 0;
	diff_ret->difference = 0;
	diff_ret->dif_extents = (struct vdfs4_extent *)
			malloc(n_sign_bytes * extent_size);
	if (!diff_ret->dif_extents) {
		log_error("Out of memory\n");
		return -ENOMEM;
	}

	diff_ret->leakage_type = (int *)malloc(sizeof(int) *
			n_sign_bytes);

	if (!diff_ret->leakage_type) {
		free(diff_ret->dif_extents);
		log_error("Out of memory\n");
		return -ENOMEM;
	}

	for (; btm_ctr < n_sign_bytes; btm_ctr++) {

		long long unsigned bts_ctr = 0;
		for (; bts_ctr < CHAR_BIT; bts_ctr++) {

			long long unsigned cur_bit = btm_ctr * CHAR_BIT +
					bts_ctr;
			int re_bit = util_sign_test_bit(calc_bitmap,
				bitmap_length, cur_bit, block_size, magic_len,
				crc_size);

			int sb_bit = util_sign_test_bit(sb_bitmap,
				bitmap_length, cur_bit, block_size, magic_len,
				crc_size);

			if (re_bit < 0 || sb_bit < 0) {
				log_error("While accessing bits in signed "
						"bitmap error occured\n");
				return -EINVAL;
			}

			if (re_bit != sb_bit) {
				if (!ext_length)
					start_ext = CHAR_BIT *
						btm_ctr + bts_ctr;
				if (!test_bit)
					test_bit = re_bit;
				ext_length++;
				diff_ret->difference++;
			} else {

				if (ext_length) {
					diff_ret->
					leakage_type[diff_ret->n_extents] =
							(int)(test_bit > 0);
					diff_ret->n_extents++;

					diff_ret->
					dif_extents[diff_ret->n_extents - 1].
					begin =	start_ext;

					diff_ret->
					dif_extents[diff_ret->n_extents - 1].
					length = ext_length;
					test_bit = 0;
				}

				ext_length = 0;
				start_ext = -1;
			}
		}
	}

	if (ext_length) {

		diff_ret->n_extents++;
		diff_ret->dif_extents[diff_ret->n_extents - 1].begin =
				start_ext;
		diff_ret->dif_extents[diff_ret->n_extents - 1].length =
				ext_length;
	}

	if (!diff_ret->difference)
		return EXIT_SUCCESS;
	else
		return FSCK_DIFFERENCE_ERROR;
}

int add_metadata_to_calculated_inode_bmap(struct vdfs4_fsck_superblock_info
		*fsck_info)
{
	int ret = 0;
	char *calc_bitmap = fsck_info->calc_bitmaps[INODE_BM_INDEX].bitmap;
	unsigned int bit_ctr;
	for (bit_ctr = 0; bit_ctr < VDFS4_1ST_FILE_INO; bit_ctr++) {
		ret = util_sign_set_bits((char *) calc_bitmap, fsck_info->
			sb_bitmaps[INODE_BM_INDEX].length_in_bytes, bit_ctr, 1,
			fsck_info->sbi.block_size, INODE_BITMAP_MAGIC_LEN,
			CRC32_SIZE);
		if (ret < 0) {
			log_error("Can't add metadata to inode bm\n");
			return ret;
		}
	}
	return EXIT_SUCCESS;
}

int determine_end_bit_of_space_bitmap(struct vdfs4_fsck_superblock_info
		*fsck_info, int *end_bit)
{
	*end_bit = fsck_info->sbi.image_size / fsck_info->sbi.block_size;
	return EXIT_SUCCESS;
}

int add_metadata_to_calculated_space_bmap(struct vdfs4_fsck_superblock_info
		*fsck_info)
{
	int ret = 0;
	struct vdfs4_extended_super_block *esb = &fsck_info->sbi.esb;
	char *calc_block_bitmap = fsck_info->
		calc_bitmaps[SPACE_BM_INDEX].bitmap;

	/* 2 blocks : superblocks and 4 blocks debug area, 6 in total
	 * always*/
	ret |= util_sign_set_bits((char *) calc_block_bitmap, fsck_info->
		sb_bitmaps[SPACE_BM_INDEX].length_in_bytes, 0, 6,
		fsck_info->sbi.block_size, FSM_BMP_MAGIC_LEN, CRC32_SIZE);

	if (ret < 0) {
		log_error("Can't add metadata to block bitmap\n");
		return ret;
	}
	add_meta_to_bmap(esb, fsck_info);
	add_table_to_bmap(esb, fsck_info);

	return ret;
}

int check_snapshot_desc(struct vdfs4_snapshot_descriptor *desc, size_t size, const char *magic)
{
	int saved_crc, real_crc;

	if (memcmp(desc->signature, magic, 4))
		return 0;

	if (desc->checksum_offset + CRC32_SIZE > size)
		return 0;

	saved_crc = *(int*)((void *)desc + desc->checksum_offset);
	real_crc = vdfs4_crc32(desc, desc->checksum_offset);

	if (saved_crc != real_crc) {
		log_error("Table crc mismatch: %#08x vs %#08x", saved_crc, real_crc);
		log_data(desc, desc->checksum_offset + 4);
		return 0;
	}

	return 1;
}

int initialize_meta_tables(struct vdfs4_fsck_superblock_info *fsck_info)
{
	struct vdfs4_sb_info *sbi = &fsck_info->sbi;
	struct vdfs4_extended_table *ext_t;
	struct vdfs4_base_table *base_t, *base_t_second;
	struct vdfs4_extended_record *record;
	struct vdfs4_base_table_record *table;
	__le64 last_table_index;
	int ret = 0;
	u32 ext_count, rec_num;
	u32 records_count = 0;
	u64 base_ver = 0, ext_ver = 0, base_sec_ver, offset = 0;
	char *buf = malloc(le64_to_cpu(sbi->esb.tables.length) *
			sbi->block_size);
	int max_base_size;
	int base_valid, base_sec_valid;
	if (!buf)
		return -ENOMEM;

	ret = vdfs4_read_blocks(sbi, le64_to_cpu(
				sbi->esb.tables.begin), buf + offset *
				sbi->block_size,
				le64_to_cpu(sbi->esb.tables.length));
	if (ret) {
		log_error("Can't read meta tables");
		free(buf);
		return ret;
	}

	sbi->snapshot.snapshot_subsystem.buffer = buf;
	sbi->snapshot.snapshot_subsystem.buffer_size = le64_to_cpu(sbi->esb.
			tables.length) * sbi->block_size;
	base_t = (struct vdfs4_base_table *)
			sbi->snapshot.snapshot_subsystem.buffer;
	base_t_second = (struct vdfs4_base_table *)
				(sbi->snapshot.snapshot_subsystem.buffer +
				(sbi->snapshot.snapshot_subsystem.buffer_size
						>> 1));

	max_base_size = sbi->esb.tables.length / 2 * sbi->block_size -
		VDFS4_SNAPSHOT_EXT_TABLES * VDFS4_SNAPSHOT_EXT_SIZE;

	base_valid = check_snapshot_desc(&base_t->descriptor,
			max_base_size, VDFS4_SNAPSHOT_BASE_TABLE);

	base_sec_valid = check_snapshot_desc(&base_t_second->descriptor,
			max_base_size, VDFS4_SNAPSHOT_BASE_TABLE);

	if (!base_valid && !base_sec_valid) {
		log_error("Can't find base table, both copies are corrupted");
		free(buf);
		return ret;
	}

	base_ver = ((u64)le32_to_cpu(base_t->descriptor.mount_count) << 32) |
			le32_to_cpu(base_t->descriptor.sync_count);

	base_sec_ver = ((u64)le32_to_cpu(base_t_second->descriptor.
				mount_count) << 32) | le32_to_cpu(
				base_t_second->descriptor.sync_count);

	if (!base_valid || (base_sec_valid && base_sec_ver > base_ver)) {
		base_t = base_t_second;
		base_ver = base_sec_ver;
	}

	sbi->snapshot.base_table = base_t;
	ext_t = (struct vdfs4_extended_table *)(
			(char *)base_t + (char)DIV_ROUND_UP(le32_to_cpu(
			base_t->descriptor.checksum_offset + CRC32_SIZE),
			VDFS4_SNAPSHOT_EXT_SIZE) * VDFS4_SNAPSHOT_EXT_SIZE);
	for (ext_count = 0; ext_count < VDFS4_SNAPSHOT_EXT_TABLES; ext_count++) {
		if (!check_snapshot_desc(&ext_t->descriptor,
					VDFS4_SNAPSHOT_EXT_SIZE,
					VDFS4_SNAPSHOT_EXTENDED_TABLE))
				break;

		ext_ver = ((u64)le32_to_cpu(ext_t->descriptor.mount_count)
				<< 32) | le32_to_cpu(
						ext_t->descriptor.sync_count);

		if ((long long int)(ext_ver - base_ver) > 1LL) {
			log_error("Extended tables have inconsistent versions\n"
				"previous ext_tb:\n mnt_ctr: %d sync_ctr: %d\n"
				"next ext_tb:\n mnt_ctr: %d sync_ctr: %d\n",
				base_t->descriptor.mount_count,
				base_t->descriptor.sync_count,
				ext_t->descriptor.mount_count,
				ext_t->descriptor.sync_count);
			break;
		}
		if (ext_ver > base_ver) {
			records_count = le32_to_cpu(ext_t->records_count);
			for (rec_num = 0; rec_num < records_count; rec_num++) {
				record = (struct vdfs4_extended_record *)
				((void *)ext_t +
				sizeof(struct vdfs4_extended_table) +
				sizeof(struct vdfs4_extended_record) * rec_num);
				table = (struct vdfs4_base_table_record *)
						(VDFS4_GET_TABLE(base_t,
						record->object_id));
				last_table_index = VDFS4_GET_LAST_IBLOCK(base_t,
						record->object_id);

				assert(le64_to_cpu(record->table_index) <=
				last_table_index);
				table[le64_to_cpu(record->table_index)].
				meta_iblock = le64_to_cpu(record->meta_iblock);
				table[le64_to_cpu(record->table_index)].
				mount_count = (__le32)le64_to_cpu(
						ext_t->descriptor.mount_count);
				table[le64_to_cpu(record->table_index)].
				sync_count = (__le32)le64_to_cpu(
						ext_t->descriptor.sync_count);
			}
			base_t->descriptor.mount_count = le32_to_cpu(
					ext_t->descriptor.mount_count);
			base_t->descriptor.sync_count = le32_to_cpu(
					ext_t->descriptor.sync_count);
			base_ver = ext_ver;
		} else
			break;
		ext_t = (struct vdfs4_extended_table *)(
				(char *)ext_t + (char)DIV_ROUND_UP(le32_to_cpu(
				ext_t->descriptor.checksum_offset + CRC32_SIZE),
				VDFS4_SNAPSHOT_EXT_SIZE) * VDFS4_SNAPSHOT_EXT_SIZE);
	}

	return ret;
}


int initialize_tree(struct vdfs4_fsck_superblock_info *fsck_info,
	struct vdfs4_btree **tree, vdfs4_btree_key_cmp cmpfn,
		enum vdfs4_btree_type tree_type)
{
	static int tree_ctr;
	VDFS4_BUG_ON(tree_ctr > FSCK_NUM_OF_CHECKED_TREES);

	struct vdfs4_bnode *bnode;
	struct vdfs4_sb_info *sbi = &fsck_info->sbi;
	*tree = malloc(sizeof(struct vdfs4_btree));
	if (!*tree) {
		log_error("Out of memory\n");
		return -ENOMEM;
	}

	(*tree)->sbi = sbi;
	(*tree)->btree_type = tree_type;
	(*tree)->node_size_bytes = 1 << sbi->sb.log_super_page_size;
	(*tree)->sbi->block_size = sbi->block_size;

	bnode =	__vdfs4_get_bnode(*tree, 0, VDFS4_BNODE_MODE_RO);
	if (IS_ERR(bnode)) {
		free(*tree);
		return -ERDFAIL;
	}

	(*tree)->head_bnode = bnode;
	(*tree)->comp_fn = cmpfn;
	fsck_checked_trees[tree_ctr] = *tree;
	tree_ctr++;
	return EXIT_SUCCESS;
}

int initialize_sb_info(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	struct vdfs4_super_block sb;
	struct vdfs4_extended_super_block esb;

	#ifdef GIT_BRANCH
		log_info("git branch: %s", GIT_BRANCH);
	#endif
	#ifdef GIT_HASH
		log_info("git hash: %s", GIT_HASH);
	#endif

	sbi->block_size = SECTOR_SIZE;

	ret |= vdfs4_read_blocks(sbi, VDFS4_RESERVED_AREA_LENGTH / SECTOR_SIZE,
			&sb, sizeof(sb) / SECTOR_SIZE);
	ret |= vdfs4_read_blocks(sbi, VDFS4_RESERVED_AREA_LENGTH / SECTOR_SIZE +
			SB_SIZE_IN_SECTOR, &esb, sizeof(esb) / SECTOR_SIZE);

	if (ret) {
		log_error("Reading error in initialization_sb_info\n");
		return ret;
	}
	sbi->super_page_size = 1 << sb.log_super_page_size;
	sbi->block_size = 1 << sb.log_block_size;
	sbi->image_size = esb.volume_blocks_count << sb.log_block_size;

	if (sb.read_only) {
		log_info("Read only image\n");
		log_info("Image inodes count %lu\n",
			le64_to_cpu(sb.image_inode_count));
		SET_FLAG(sbi->service_flags, READ_ONLY_IMAGE);
	} else
		log_info("Volume created with size %llu Kb\n",
				(__u64) sbi->image_size >> 10);
	sbi->esb = esb;
	sbi->sb = sb;
	return EXIT_SUCCESS;
}

static int check_bitmap_pages(struct bitmap_info *bitmaps, int bitmap_n,
	struct vdfs4_fsck_superblock_info *fsck_info)
{
	int pages_num, page_size, inode_n;
	void *bitmap;
	char *magic;
	int page_n = 0,  ret = 0;
	int magic_len;

	bitmap = bitmaps[bitmap_n].bitmap;
	pages_num = bitmaps[bitmap_n].length_in_blocks;
	magic = fsck_checked_magics[bitmap_n];
	magic_len = strlen(magic);
	inode_n = fsck_checked_inos[bitmap_n];
	page_size =  fsck_info->sbi.block_size;

	for (page_n = 0; page_n < pages_num; page_n++) {
		void *cur_buff;
		int ret1 = 0, ret2 = 0;

		cur_buff = bitmap + page_size * page_n;

		if (memcmp(cur_buff, magic, magic_len)) {
			ret1 = 1;
			log_error("Invalid magic in %s page #%d\n",
				print_metadata_name_by_inode(
					inode_n), page_n);
		}
		if (!IS_FLAG_SET(fsck_info->sbi.service_flags, UPDATE_CRC)) {
			ret2 = util_validate_crc(cur_buff, PAGE_SIZE,
					FSM_BMP_MAGIC_LEN);
			if (ret2)
				log_error("Invalid crc in %s page #%d\n",
					print_metadata_name_by_inode(inode_n),
					page_n);
		}

		ret |= ret1 | ret2;

	}

	return ret;
}


int initialize_bitmaps(struct vdfs4_fsck_superblock_info *fsck_info,
	struct bitmap_info *bitmaps, int read_flag)
{
	int ret = 0, ctr = 0, signature_ret = 0;
	struct vdfs4_sb_info *sbi = &fsck_info->sbi;
	/* Initializing bitmaps */

	if (IS_FLAG_SET(fsck_info->sbi.service_flags, READ_ONLY_IMAGE))
		return 0;

	for (; ctr < FSCK_NUM_OF_CHECKED_BMAPS; ctr++) {
		/* Create sb bitmap */
		int bitmap_id = fsck_checked_inos[ctr];
		struct vdfs4_base_table *base_table = sbi->snapshot.base_table;
		u64 len = VDFS4_GET_LAST_IBLOCK(base_table, bitmap_id) + 1;
		ret = create_bmap(len, sbi->block_size,
			&bitmaps[ctr].bitmap);
		if (ret) {
			log_error("Failed to create SB block bitmap");
			return ret;
		}

		/* Read sb bitmap */
		if (read_flag) {
			ret = read_bmap(fsck_checked_inos[ctr],
					bitmaps[ctr].bitmap, sbi,
					&bitmaps[ctr].length_in_blocks);

			if (ret) {
				log_error("Failed to read bitmap\n");
				for (; ctr < FSCK_NUM_OF_CHECKED_BMAPS; ctr++)
					free(bitmaps[ctr].bitmap);

				return ret;
			}
			if (!(IS_FLAG_SET(fsck_info->sbi.service_flags,
					READ_ONLY_IMAGE) &&
					ctr < FSCK_FIRST_TREE_INDEX))
				signature_ret =
					check_bitmap_pages(bitmaps, ctr,
							fsck_info);

			bitmaps[ctr].length_in_bytes = bitmaps[ctr].
					length_in_blocks * sbi->block_size;
		}

	}
	if (signature_ret)
		return -EINVAL;

	return ret;
}

void print_fsck_result(struct vdfs4_fsck_superblock_info *info, int i_meta,
	int leakage_type)
{
	int ext_ctr, flag = 0;
	for (ext_ctr = 0; ext_ctr < info->difference_result[i_meta].n_extents;
		ext_ctr++)
		if (info->difference_result[i_meta].leakage_type
			[ext_ctr] == leakage_type)
				flag++;
	if (!flag)
		return;

	printf("Difference in %s\n",
		print_metadata_name_by_inode(fsck_checked_inos[i_meta]));

	for (ext_ctr = 0; ext_ctr < info->
		difference_result[i_meta].n_extents; ext_ctr++) {
		if (info->difference_result[i_meta].leakage_type
			[ext_ctr] != leakage_type)
			continue;

		printf("%4.4s %d", " ", (unsigned int)
		info->difference_result[i_meta].dif_extents[ext_ctr].begin);
		if (info->difference_result[i_meta].dif_extents[ext_ctr].length
			> 1)
			printf(" - %lld\n",
				(unsigned int)info->difference_result
				[i_meta].dif_extents[ext_ctr].begin +
				info->difference_result[i_meta].
				dif_extents[ext_ctr].length - 1);
		else
			printf("\n");
	}
}

int print_fsck_results(struct vdfs4_fsck_superblock_info *vdfs4_fsck_info,
	int leakage_type)
{
	int i_meta = 0;
	printf("\n");

	for (; i_meta < FSCK_CHECKED_METADATA_ELS; i_meta++)
		print_fsck_result(vdfs4_fsck_info, i_meta, leakage_type);

	printf("\n");
	return EXIT_SUCCESS;
}


static void print_translation_tables(struct vdfs4_fsck_superblock_info
		*fsck_info) {
	int tables_count;
	struct vdfs4_base_table *base_table = fsck_info->sbi.snapshot.base_table;
	printf("mount count %lu, sync count %d\n",
		(unsigned long)le64_to_cpu(base_table->descriptor.mount_count),
		(unsigned int)le32_to_cpu(base_table->descriptor.sync_count));
	for (tables_count = VDFS4_FSFILE; tables_count <= VDFS4_LSFILE;
			tables_count++) {
		struct vdfs4_base_table_record *table;
		int count;

		if (IS_FLAG_SET(fsck_info->sbi.service_flags,
			READ_ONLY_IMAGE) &&
			(tables_count == VDFS4_SPACE_BITMAP_INO ||
			tables_count == VDFS4_FREE_INODE_BITMAP_INO))
			continue;

		int iblock_count = le64_to_cpu(base_table->
				last_page_index[VDFS4_SF_INDEX(tables_count)])
				+ 1;

		table = (struct vdfs4_base_table_record *)(VDFS4_GET_TABLE(
				base_table, tables_count));

		printf("\n%s\n",
			print_metadata_name_by_inode(tables_count));

		printf("iblock count : %d\n", iblock_count);

		for (count = 0; count < iblock_count; count++) {
			if (!(count % 6) && count)
				printf("\n");
			printf("\t%4d : %" PRIu64 "-v%" PRIu32 ".%" PRIu32,
			count, (uint64_t)
			le64_to_cpu(table->meta_iblock),
			le32_to_cpu(table->mount_count),
			le32_to_cpu(table->sync_count));
			table++;
		}
	}

	printf("\n");
}

int inject_trash(struct vdfs4_fsck_superblock_info *fsck_info)
{
	FILE *restore_data = NULL;
	__u64 initial_trash_index = 0, trash_size = 0, initial_trash_pos = 0,
		initial_trash_offset = 0;
	char *trash_buffer = NULL;
	int ret = 0; unsigned int ctr = 0;
	char *restore_buffer = NULL;
	__u64 random_block;
	int random_metadata_ino = 0;

	int default_max_trash_size = fsck_info->cmd_info.trash_size;
	__u64 *table = NULL;
	int iblock_count = 0;
	int block_size = fsck_info->sbi.block_size;

	struct vdfs4_base_table *base_table = fsck_info->
		sbi.snapshot.base_table;
	__u8 volume_uid[VOLUME_UID_SIZE];
	memcpy(volume_uid, fsck_info->sbi.sb.volume_uuid, VOLUME_UID_SIZE);

	random_metadata_ino = VDFS4_FSFILE + rand() %
		(VDFS4_LSFILE - VDFS4_FSFILE + 1);

	log_info("Injecting trash into %s",
		print_metadata_name_by_inode(random_metadata_ino));

	iblock_count = le64_to_cpu(base_table->
		last_page_index[VDFS4_SF_INDEX(random_metadata_ino)]) + 1;

	restore_data = fopen(fsck_info->cmd_info.restore_file_path, "w");
	if (restore_data == NULL) {
		log_error("Can't open file\n");
		return -EINVAL;
	}

	restore_buffer = malloc(block_size);

	if (!restore_buffer) {
		fclose(restore_data);
		return -ENOMEM;
	}

	table = (__le64 *)(VDFS4_GET_TABLE(base_table, random_metadata_ino));

	trash_size = rand() % default_max_trash_size + 1;

	initial_trash_index = rand() % iblock_count;

	if (fsck_info->cmd_info.trash_offset)
		initial_trash_offset = rand() %
			(fsck_info->cmd_info.trash_offset);
	else
		initial_trash_offset = 0;

	random_block = metablock_to_iblock(&fsck_info->sbi,
		table[initial_trash_index]);

	initial_trash_pos = random_block * (block_size) +
		initial_trash_offset;

	trash_buffer = malloc(trash_size);

	if (!trash_buffer) {
		ret = -EINVAL;
		goto free_restore;
	}

	for (; ctr < trash_size; ctr++)
		trash_buffer[ctr] = rand() % CHAR_MAX;

	/* Creating restoring copy */

	ret =  vdfs4_read_blocks(&fsck_info->sbi, random_block,
		restore_buffer, 1);

	if (ret) {
		log_error("Can't read restore block\n");
		goto exit;
	}

	ret = fwrite(restore_buffer, block_size, 1,
		restore_data);

	if (ret != 1) {
		log_error("Error when writing to file\n");
		ret = -EWRFAIL;
		goto exit;
	}

	fseek(restore_data, 0, SEEK_END);
	ret = fwrite((char *)&random_block, sizeof(__u64), 1, restore_data);

	if (ret != 1) {
		log_error("Error when writing to file\n");
		ret = -EWRFAIL;
		goto exit;
	}

	fseek(restore_data, 0, SEEK_END);
	ret = fwrite((char *)volume_uid, VOLUME_UID_SIZE, 1, restore_data);

	if (ret != 1) {
		log_error("Error when writing to file\n");
		ret = -EWRFAIL;
		goto exit;
	}

	ret = vdfs4_write_bytes(&fsck_info->sbi, initial_trash_pos, trash_buffer,
		trash_size);

	if (ret)
		log_error("Can't write trash\n");

	log_info("Trash index: %llu", initial_trash_index);
	log_info("Trash start_block: %llu ", random_block);
	log_info("Trash bytes offset in block: %llu", initial_trash_offset);
	log_info("Trash len: %llu (in bytes) ", trash_size);

exit:
	free(trash_buffer);
free_restore:
	free(restore_buffer);
	fclose(restore_data);

	return ret;
}

int restore_before_injection_state(struct vdfs4_fsck_superblock_info *fsck_info,
	char *restore_file_path)
{
	int ret = 0;
	char *restore_buffer = NULL;
	FILE *restore_fid = NULL;
	__u64 restore_block = 0;
	int block_size = fsck_info->sbi.block_size;
	__u8 volume_uid[VOLUME_UID_SIZE];
	__u8 readed_uid[VOLUME_UID_SIZE];
	memcpy(volume_uid, fsck_info->sbi.sb.volume_uuid, VOLUME_UID_SIZE);

	restore_fid = fopen(restore_file_path, "r");
	if (restore_fid == NULL) {
		log_error("Can't open file\n");
		return -EINVAL;
	}

	restore_buffer = malloc(block_size);

	if (!restore_buffer) {
		fclose(restore_fid);
		return -ENOMEM;
	}

	ret = fread(restore_buffer, block_size, 1, restore_fid);
	if (ret != 1) {
		log_error("Error when reading file\n");
		fclose(restore_fid);
		free(restore_buffer);
		return -ERDFAIL;
	}

	fseek(restore_fid, -(sizeof(__u64) + VOLUME_UID_SIZE), SEEK_END);
	ret = fread((char *)&restore_block, sizeof(__u64), 1, restore_fid);

	if (ret != 1) {
		log_error("Error when reading file\n");
		fclose(restore_fid);
		free(restore_buffer);
		return -ERDFAIL;
	}

	fseek(restore_fid, -VOLUME_UID_SIZE, SEEK_END);
	ret = fread((char *)readed_uid, VOLUME_UID_SIZE, 1, restore_fid);

	if (ret != 1) {
		log_error("Error when reading file\n");
		fclose(restore_fid);
		free(restore_buffer);
		return -ERDFAIL;
	}

	if (!memcmp(readed_uid, volume_uid, VOLUME_UID_SIZE))
		ret = vdfs4_write_blocks(&fsck_info->sbi, restore_block,
				restore_buffer, 1);
	else
		log_info("-r option used only with -i option and must be used\n"
			" with same file_name as -i");

	if (ret)
		log_error("Can't write restore block\n");

	fclose(restore_fid);
	free(restore_buffer);
	return ret;
}

void init_fsck_info(struct vdfs4_fsck_superblock_info *fsck_info)
{
	memset(fsck_info, 0, sizeof(*fsck_info));
	fsck_info->cmd_info.block_to_find = -1;
	fsck_info->cmd_info.injection_seed = -1;
	fsck_info->inum_fork_dep.elem_size =
		sizeof(struct inum_extents_dependency);
	fsck_info->cmd_info.trash_size = 100;
	fsck_info->cmd_info.trash_offset = 1;
	fsck_info->orphane_inodes.elem_size = sizeof(__u64);
	fsck_info->squash_mnt_dep.elem_size =
		sizeof(struct squash_fs_dependency);
	fsck_info->par_name_dep.elem_size = sizeof(struct par_name_dependency);
}

int update_volume_crc(struct vdfs4_fsck_superblock_info *fsck_info)
{
	u32 i;
	int ret = 0;
	int crc = 0;
	int block = 0;
	u32 bnode_size = get_bnode_size(&fsck_info->sbi);
	struct vdfs4_bnode *bnode = NULL;
	fsck_info->sbi.esb.crc = CRC_ENABLED;
	crc = vdfs4_crc32(&fsck_info->sbi.esb, sizeof(fsck_info->sbi.esb) -
			sizeof(fsck_info->sbi.esb.checksum));
	if ((__le32)crc != le32_to_cpu(fsck_info->sbi.esb.checksum)) {
		fsck_info->sbi.esb.checksum = crc;
		ret = vdfs4_write_bytes(&fsck_info->sbi, 3 * SB_SIZE,
				(char *)&fsck_info->sbi.esb,
				sizeof(fsck_info->sbi.esb));
		if (ret)
			goto exit;
		ret = vdfs4_write_bytes(&fsck_info->sbi,
				fsck_info->sbi.block_size + 3 * SB_SIZE,
				(char *)&fsck_info->sbi.esb,
				sizeof(fsck_info->sbi.esb));
		if (ret)
			goto exit;
	}
	struct vdfs4_base_table *base_t = fsck_info->sbi.snapshot.base_table;
	struct vdfs4_base_table_record *table_record =
			(struct vdfs4_base_table_record *)(
			(char *)base_t + base_t->translation_table_offsets
			[VDFS4_SF_INDEX(VDFS4_CAT_TREE_INO)]);
	for (i = 0; i <= base_t->last_page_index[VDFS4_SF_INDEX(
			VDFS4_CAT_TREE_INO)]; i++) {
		block = metablock_to_iblock(&fsck_info->sbi,
				table_record[i].meta_iblock);
		if (block < 4) {
			ret = -EINVAL;
			goto exit;
		}
		bnode = __vdfs4_get_bnode(fsck_info->sbi.catalog_tree,
				i, VDFS4_BNODE_MODE_RW);
		if (IS_ERR(bnode))
			goto exit;
		crc = vdfs4_crc32((unsigned char *)bnode->data,
				bnode_size - CRC32_SIZE);
		if (crc != *(int *)(bnode->data + bnode_size - CRC32_SIZE))
			ret = vdfs4_write_bytes(&fsck_info->sbi,
					block_to_byte(block,
				fsck_info->sbi.block_size) +
				bnode_size - CRC32_SIZE, (char *)&crc,
				CRC32_SIZE);
		free(bnode->data);
		free(bnode);
		if (ret)
			goto exit;
	}

	table_record = (struct vdfs4_base_table_record *)((char *)
			base_t + base_t->translation_table_offsets
			[VDFS4_SF_INDEX(VDFS4_EXTENTS_TREE_INO)]);

	for (i = 0; i <= base_t->last_page_index[VDFS4_SF_INDEX(
			VDFS4_EXTENTS_TREE_INO)]; i++) {
		block = metablock_to_iblock(&fsck_info->sbi,
				table_record[i].meta_iblock);
		bnode = __vdfs4_get_bnode(fsck_info->sbi.extents_tree,
				i, VDFS4_BNODE_MODE_RW);
		if (IS_ERR(bnode))
			goto exit;
		crc = vdfs4_crc32((unsigned char *)bnode->data,
				bnode_size - CRC32_SIZE);
		if (crc != *(int *)(bnode->data + bnode_size - CRC32_SIZE))
			ret = vdfs4_write_bytes(&fsck_info->sbi, block_to_byte(
					block,
				fsck_info->sbi.block_size) +
				bnode_size - CRC32_SIZE, (char *)&crc,
				CRC32_SIZE);
		free(bnode->data);
		free(bnode);
		if (ret)
			goto exit;
	}

	table_record = (struct vdfs4_base_table_record *)((char *)
			base_t + base_t->translation_table_offsets
			[VDFS4_SF_INDEX(VDFS4_XATTR_TREE_INO)]);

	for (i = 0; i <= base_t->last_page_index[VDFS4_SF_INDEX(
			VDFS4_XATTR_TREE_INO)]; i++) {
		block = metablock_to_iblock(&fsck_info->sbi,
				table_record[i].meta_iblock);
		bnode = __vdfs4_get_bnode(fsck_info->sbi.xattr_tree,
				i, VDFS4_BNODE_MODE_RW);
		if (IS_ERR(bnode))
			goto exit;
		crc = vdfs4_crc32((unsigned char *)bnode->data,
				bnode_size - CRC32_SIZE);
		if (crc != *(int *)(bnode->data + bnode_size - CRC32_SIZE))
			ret = vdfs4_write_bytes(&fsck_info->sbi
				, block_to_byte(block,
				fsck_info->sbi.block_size) +
				bnode_size - CRC32_SIZE, (char *)&crc,
				CRC32_SIZE);
		free(bnode->data);
		free(bnode);
		if (ret)
			goto exit;
	}
	table_record = (struct vdfs4_base_table_record *)((char *)
			base_t + base_t->translation_table_offsets
			[VDFS4_SF_INDEX(VDFS4_SPACE_BITMAP_INO)]);
	for (i = 0; i <= base_t->last_page_index[VDFS4_SF_INDEX(
			VDFS4_SPACE_BITMAP_INO)]; i++) {
		block = metablock_to_iblock(&fsck_info->sbi,
				table_record[i].meta_iblock);

		crc = vdfs4_crc32(fsck_info->sb_bitmaps[0].bitmap +
			i * fsck_info->sbi.block_size + FSM_BMP_MAGIC_LEN,
			fsck_info->sbi.block_size - CRC32_SIZE
			- FSM_BMP_MAGIC_LEN);
		if (crc != *(int *)(fsck_info->sb_bitmaps[0].bitmap +
				i * fsck_info->sbi.block_size - CRC32_SIZE))
			ret = vdfs4_write_bytes(&fsck_info->sbi,
				block_to_byte(block,
				fsck_info->sbi.block_size) +
				fsck_info->sbi.block_size - CRC32_SIZE,
				(char *)&crc,
				CRC32_SIZE);
		if (ret)
			goto exit;
	}
	table_record = (struct vdfs4_base_table_record *)((char  *)
			base_t + base_t->translation_table_offsets
			[VDFS4_SF_INDEX(VDFS4_FREE_INODE_BITMAP_INO)]);
	for (i = 0; i <= base_t->last_page_index[VDFS4_SF_INDEX(
			VDFS4_FREE_INODE_BITMAP_INO)]; i++) {
		block = metablock_to_iblock(&fsck_info->sbi,
				table_record[i].meta_iblock);
		crc = vdfs4_crc32(fsck_info->sb_bitmaps[1].bitmap +
			i * fsck_info->sbi.block_size + INODE_BITMAP_MAGIC_LEN,
			fsck_info->sbi.block_size - CRC32_SIZE
			- INODE_BITMAP_MAGIC_LEN);
		if (crc != *(int *)(fsck_info->sb_bitmaps[1].bitmap +
					i * fsck_info->sbi.block_size
					- CRC32_SIZE))
			ret = vdfs4_write_bytes(&fsck_info->sbi,
				block_to_byte(block,
				fsck_info->sbi.block_size) +
				fsck_info->sbi.block_size - CRC32_SIZE,
				(char *)&crc,
				CRC32_SIZE);
		if (ret)
			goto exit;
	}
	sync();
exit:
	if (ret)
		log_error("Error when update crc");
	return ret;
}
int print_difference(struct vdfs4_fsck_superblock_info *fsck_info)
{
	int ret = 0, ctr = 0;
	printf("\n");
	printf("parent less allocated blocks (space leakage):\n");
	printf("%60.60s\n", "------------------------------------------"
	"-----------------------------------------------------------------");

	print_fsck_results(fsck_info, LEAKAGE_TYPE_1);
	printf("extents holding blocks marked as free in block bitmap:\n");
	printf("%60.60s\n", "------------------------------------------"
	"-----------------------------------------------------------------");
	print_fsck_results(fsck_info, LEAKAGE_TYPE_2);

	printf("Total:\n");
	printf("%60.60s\n", "------------------------------------------"
	"-----------------------------------------------------------------");
	for (ctr = 0; ctr < FSCK_CHECKED_METADATA_ELS; ctr++) {
		printf("Difference ( %s ): %d\n",
			print_metadata_name_by_inode(fsck_checked_inos[ctr]),
			fsck_info->difference_result[ctr].difference);
	}
	printf("\n");

	for (ctr = 0; ctr < (int)fsck_info->inum_fork_dep.n_elements; ctr++) {
		struct inum_extents_dependency *ptr =
			fsck_info->inum_fork_dep.elements
			+ ctr * fsck_info->inum_fork_dep.elem_size;
		free(ptr->extents.elements);
	}
	return ret;
}

/* For readonly images*/
void compensate_bitmaps(struct vdfs4_fsck_superblock_info *fsck_info)
{
	int ctr = 0;
	for (; ctr < FSCK_FIRST_TREE_INDEX; ctr++)
		fsck_info->calc_bitmaps[ctr].bitmap =
				fsck_info->sb_bitmaps[ctr].bitmap;
}

int main(int argc, char *argv[])
{
	int ret = 0, fsck_ret = 0, ctr = 0;
	struct vdfs4_fsck_superblock_info vdfs4_fsck_info;
	int blck_bitmap_end_bit = 0;
	init_fsck_info(&vdfs4_fsck_info);

	print_version();

	/* Parsing comand line arguments */
	ret = parse_cmd(argc, argv, &vdfs4_fsck_info);

	if (ret)
		goto err_cmd_parse;

	ret = open_disk(&vdfs4_fsck_info.sbi);
	if (ret) {
		log_error("Can't open volume\n");
		goto err_disk_op;
	}

	ret = check_volume(&vdfs4_fsck_info.sbi);
	if (ret) {
		log_error("Checking volume failed\n");
		goto err_check_vol;
	};
	ret = initialize_sb_info(&vdfs4_fsck_info.sbi);
	if (ret) {
		log_error("Sb_info initialization failed\n");
		goto err_init_sb;
	};

	ret = initialize_meta_tables(&vdfs4_fsck_info);
	if (ret) {
		log_error("Table initialization failed\n");
		goto err_init_tb;
	};

	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, PERFORM_INJECTION)) {

		if (vdfs4_fsck_info.cmd_info.injection_seed == -1) {
			struct timeval time;
			gettimeofday(&time, NULL);
			vdfs4_fsck_info.cmd_info.injection_seed =
				(time.tv_sec * 1000) + (time.tv_usec / 1000);
		}

		log_info("Injection seed: %d",
				vdfs4_fsck_info.cmd_info.injection_seed);
		srand(vdfs4_fsck_info.cmd_info.injection_seed);
		ret = inject_trash(&vdfs4_fsck_info);

		if (ret)
			log_error("Error while performing injection\n");

		goto exit_injection;
	}

	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, RESTORE)) {
		ret = restore_before_injection_state(&vdfs4_fsck_info,
			vdfs4_fsck_info.cmd_info.restore_file_path);

		if (ret != 0)
			log_error("Error occured, ret code: %d\n", ret);

		goto exit_injection;
	}

	/* If verbose print superblock here */
	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, VERBOSE)) {
		ret = print_superblock(&vdfs4_fsck_info);

		if (ret)
			goto exit_print;

		print_translation_tables(&vdfs4_fsck_info);
	}

	fsck_ret |= check_metadata_alignment(&vdfs4_fsck_info);

	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, PARSE_DEBUG_AREA)) {
		ret = parse_debug_area(&vdfs4_fsck_info);

		if (ret)
			log_error("Can't parse debug area\n");

		goto err_debug_area;
	}
	vdfs4_init_btree_caches();
	ret = initialize_tree(&vdfs4_fsck_info, &vdfs4_fsck_info.sbi.catalog_tree,
			vdfs4_cattree_cmpfn, VDFS4_BTREE_CATALOG);
	if (ret) {
		log_error("Failed to initialize cattree\n");
		goto err_cat_init;
	};
	ret = initialize_tree(&vdfs4_fsck_info, &vdfs4_fsck_info.sbi.extents_tree,
			vdfs4_exttree_cmpfn, VDFS4_BTREE_EXTENTS);
	if (ret) {
		log_error("Failed to initialize exttree\n");
		goto err_ext_init;
	};
	ret = initialize_tree(&vdfs4_fsck_info, &vdfs4_fsck_info.sbi.xattr_tree,
			vdfs4_xattrtree_cmpfn, VDFS4_BTREE_XATTRS);
	if (ret) {
		log_error("Failed to initialize xattrtree\n");
		goto err_xattr_init;
	};


	/* Print bnode from cattree if appropriate flag specified*/
	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, CATTREE_BNODE_DUMP)) {
		ret = print_bnode(vdfs4_fsck_info.sbi.catalog_tree,
			vdfs4_fsck_info.cmd_info.dump_node);
		goto bnode_dump_cattree_exit;
	}
	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, FIND_BY_NAME)) {
		ret = find_file(&vdfs4_fsck_info, vdfs4_fsck_info.cmd_info.
			file_name_to_find, vdfs4_fsck_info.cmd_info.
				block_to_find);
		goto find_by_name_exit;
	}
	ret = initialize_bitmaps(&vdfs4_fsck_info, vdfs4_fsck_info.sb_bitmaps, 1);

	if (ret)
		goto err_get_sb_bmaps;

	/* Print bnode from exttree if appropriate flag specified*/
	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, EXTTREE_BNODE_DUMP)) {
		ret = print_bnode(vdfs4_fsck_info.sbi.extents_tree,
			vdfs4_fsck_info.cmd_info.dump_node);
		goto bnode_dump_exttree_exit;
	}

	ret = initialize_bitmaps(&vdfs4_fsck_info,
		vdfs4_fsck_info.calc_bitmaps, 0);

	if (ret) {
		log_error("Failed to get calc bitmaps\n");
		goto err_get_cl_bmaps;
	};

	/* We must find the end bit of bitmap here, because for volumes
	 * which size don't match n^2 end bit will be inside bitmap extent (not
	 * in the end.*/
	ret = determine_end_bit_of_space_bitmap(&vdfs4_fsck_info,
			&blck_bitmap_end_bit);
	if (ret) {
		log_error("Unable to determine end bit of bitmap\n");
		goto err_end_bit;
	};
	/* We must mark blocks for metadata in space bitmap*/
	if (!IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = add_metadata_to_calculated_space_bmap(&vdfs4_fsck_info);

		if (ret) {
			log_error("Unable to add metadata to block bitmap\n");
			goto err_add_meta_to_space;
		}
	}
	/* We must mark inodes for metadata in inodes bitmap*/
	if (!IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = add_metadata_to_calculated_inode_bmap(&vdfs4_fsck_info);
		if (ret) {
			log_error("Unable to to add inode bitmap metadata\n");
			goto err_add_meta_to_inode;
		}
	}
	fsck_ret |= check_all_trees_structure(&vdfs4_fsck_info);

	if (fsck_ret == -EINVAL)
		goto err_check_struct;

	ret = general_tree_parser(&vdfs4_fsck_info, add_catrec_to_bmaps,
		cattree_get_first_record, NULL);
	if (ret) {
		fsck_ret |= ret;
		log_error("Errors occured while parsing cattree, err=%d\n", ret);
	}
	if (!IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = check_orphan_inodes(&vdfs4_fsck_info);
		if (ret) {
			fsck_ret |= ret;
			log_error("Errors occured while parsing orphan inodes,"
					" err=%d\n", ret);
		}
	}
	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags,
			SQUASH_CONF_RESTORE)) {
		ret = build_squash_mnt_pt_config(&vdfs4_fsck_info);
		if (ret) {
			log_error("Errors occured while restoring\n"
				"squashfs config\n");
			return -EINVAL;
		}
		goto fsck_info_free;
	}

	ret = general_tree_parser(&vdfs4_fsck_info, add_extrec_to_bmap,
		exttree_get_first_record, NULL);

	fsck_ret |= check_total_items_and_links(&vdfs4_fsck_info);

	if (ret)
		log_error("Errors occured while parsing exttree\n");

	if (!IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, READ_ONLY_IMAGE))
		fsck_ret |= check_extents_intersection(&vdfs4_fsck_info,
				blck_bitmap_end_bit);
	else
		compensate_bitmaps(&vdfs4_fsck_info);

	vdfs4_fsck_info.calc_bitmaps[0].length_in_bytes =
			vdfs4_fsck_info.sb_bitmaps[0].length_in_bytes;

	for (ctr = 0; ctr < FSCK_CHECKED_METADATA_ELS; ctr++) {
		fsck_ret |= calculate_difference(vdfs4_fsck_info.
			calc_bitmaps[ctr].bitmap,
			vdfs4_fsck_info.sb_bitmaps[ctr].bitmap,
			vdfs4_fsck_info.sb_bitmaps[ctr].length_in_bytes,
			&vdfs4_fsck_info.difference_result[ctr],
			vdfs4_fsck_info.sbi.block_size,
			fsck_checked_magics_len[ctr],
			fsck_checked_crc_size[ctr]);
	}

	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, VERBOSE))
		print_difference(&vdfs4_fsck_info);
	if (IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, UPDATE_CRC)) {
		if (ret == 0) {
			ret = update_volume_crc(&vdfs4_fsck_info);
		} else {
			log_error("Fsck can't update crc.Volume is invalid.");
			ret = -EINVAL;
		}
	}
fsck_info_free:
	free(vdfs4_fsck_info.inum_fork_dep.elements);
	free(vdfs4_fsck_info.calculated_tia.tie);
	free(vdfs4_fsck_info.readed_tia.tie);
	free(vdfs4_fsck_info.difference_result[SPACE_BM_INDEX].leakage_type);
	free(vdfs4_fsck_info.difference_result[SPACE_BM_INDEX].dif_extents);
	free(vdfs4_fsck_info.difference_result[INODE_BM_INDEX].leakage_type);
	free(vdfs4_fsck_info.difference_result[INODE_BM_INDEX].dif_extents);
err_check_struct:
err_add_meta_to_inode:
err_add_meta_to_space:
err_end_bit:
	if (!IS_FLAG_SET(vdfs4_fsck_info.sbi.service_flags, READ_ONLY_IMAGE)) {
		free(vdfs4_fsck_info.calc_bitmaps[SPACE_BM_INDEX].bitmap);
		free(vdfs4_fsck_info.calc_bitmaps[INODE_BM_INDEX].bitmap);
	}
err_get_cl_bmaps:
bnode_dump_exttree_exit:
find_by_name_exit:
bnode_dump_cattree_exit:
	free(vdfs4_fsck_info.sb_bitmaps[SPACE_BM_INDEX].bitmap);
	free(vdfs4_fsck_info.sb_bitmaps[INODE_BM_INDEX].bitmap);
err_get_sb_bmaps:
	vdfs4_put_bnode(vdfs4_fsck_info.sbi.xattr_tree->head_bnode);
	free(vdfs4_fsck_info.sbi.xattr_tree);
err_xattr_init:
	vdfs4_put_bnode(vdfs4_fsck_info.sbi.extents_tree->head_bnode);
	free(vdfs4_fsck_info.sbi.extents_tree);
err_ext_init:
	vdfs4_put_bnode(vdfs4_fsck_info.sbi.catalog_tree->head_bnode);
	free(vdfs4_fsck_info.sbi.catalog_tree);
err_cat_init:
err_debug_area:
exit_print:
exit_injection:
err_init_tb:
err_init_sb:
err_check_vol:
err_disk_op:
	close_disk(&vdfs4_fsck_info.sbi);
	free(vdfs4_fsck_info.sbi.snapshot.snapshot_subsystem.buffer);
	if (ret == 0 && fsck_ret == 0)
		log_info("Finished successfully");
err_cmd_parse:

	if (!ret)
		return fsck_ret > 255 ? -22 : -fsck_ret;
	else
		return ret;

}
