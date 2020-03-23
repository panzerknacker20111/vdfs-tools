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

#define MAX_RECS_IN_BNODE(bnode) ((cpu_to_le32(bnode->host->node_size_bytes - \
		sizeof(struct vdfs4_gen_node_descr) - \
		sizeof(vdfs4_bt_off_t) - VDFS4_BNODE_FIRST_OFFSET)) / \
		(sizeof(struct vdfs4_generic_key) + sizeof(int)))

#include "fsck.h"

int ino_to_index(int ino)
{
	int i = 0;
	for (; i < FSCK_CHECKED_METADATA_ELS; i++)
		if (ino == fsck_checked_inos[i])
			return i;
	return -EINVAL;
}

int compare(const void *a, const void *b)
{
	return *(int *)a - *(int *)b;
}

void *realloc_zero(void *buffer, size_t old_size, size_t new_size)
{
	void *pnew = realloc(buffer, new_size);
	if (new_size > old_size && pnew) {
		size_t diff = new_size - old_size;
		void *start = ((char *)pnew) + old_size;
		memset(start, 0, diff);
	}
	return pnew;
}

void *get_array_elem(struct fsck_simple_array *arr, __u32 index)
{
	return arr->elements + arr->elem_size * index;
}

void *find_in_arr(struct fsck_simple_array *arr, __u64 key)
{
	unsigned int i = 0;
	__u64 n_elems = arr->n_elements;
	__u32 elem_size = arr->elem_size;
	char *elements = (char *)arr->elements;
	for (; i < n_elems; i++) {
		__u64 *found_key = (__u64 *)(elements + i * elem_size);
		if (*found_key == key)
			return found_key;
	}
	return ERR_PTR(-EINVAL);
}

int push_back(struct fsck_simple_array *arr, void *element)
{
	__u64 n_elems = arr->n_elements;
	__u32 elem_size = arr->elem_size;
	char *elements = (char *)arr->elements;
	char *more_elements = realloc_zero(elements, n_elems * elem_size,
		(n_elems + 1) * elem_size);
	if (more_elements != NULL)
		memcpy(more_elements + n_elems * elem_size, element,
			elem_size);
	else {
		printf("Out of memory\n");
		return -ENOMEM;
	}
	arr->n_elements++;
	arr->elements = more_elements;
	return EXIT_SUCCESS;
}

/* TODO use determine end bit to handle blocks validity */
int is_valid_offset_for_bitmap(struct vdfs4_fsck_superblock_info *fsck_info,
	int bm_index, int block_size, __u64 inum)
{
	return util_sign_test_bit((char *) fsck_info->calc_bitmaps
		[bm_index].bitmap, fsck_info->sb_bitmaps
		[bm_index].length_in_bytes, inum, block_size, 12, CRC32_SIZE);
}


int fork_total_block_count(struct vdfs4_fork *fk)
{
	int ctr = 0, sum = 0;

	for (ctr = 0; ctr < VDFS4_EXTENTS_COUNT_IN_FORK; ctr++) {
			struct vdfs4_extent *extnt;
			extnt = &fk->extents[ctr].extent;
			sum += extnt->length;
	}
	return sum;
}

int is_fork_corrupted(struct vdfs4_fork *fk,
		struct vdfs4_fsck_superblock_info *fsck_info) {

	int ctr = 0, ret = 0;

	for (ctr = 0; ctr < VDFS4_EXTENTS_COUNT_IN_FORK; ctr++) {
			struct vdfs4_extent *extnt;
			extnt = &fk->extents[ctr].extent;
			ret = is_extent_corrupted(extnt, fsck_info);
			if (ret < 0)
				return ret;
	}
	return ret;
}

int is_extent_corrupted(struct vdfs4_extent *extnt,
	struct vdfs4_fsck_superblock_info *fsck_info)
{
	__u32 end_bit = fsck_info->sbi.image_size /
		fsck_info->sbi.block_size;
	if (extnt->begin + extnt->length > end_bit)
		return -EINVAL;
	else
		return EXIT_SUCCESS;
}

int check_gen_key(struct vdfs4_generic_key *gen_key, __u32 bnode_size)
{
	__u32 max_key_length = VDFS4_CAT_KEY_MAX_LEN;
	__u32 max_rec_length = VDFS4_CAT_KEY_MAX_LEN +
		sizeof(struct vdfs4_catalog_file_record);

	/* FIXME check against tree->max_record_len */

	if (gen_key->key_len > max_key_length || gen_key->record_len >
		max_rec_length) {
		if (gen_key->key_len > bnode_size ||
			gen_key->record_len > bnode_size)
			return FSCK_CORRUPTED_BTREE_STRUCTURE;
		else
			return FSCK_INVALID_GEN_KEY;
	} else
		return EXIT_SUCCESS;
}

struct vdfs4_catalog_file_record *get_rec_info(struct vdfs4_cattree_record
	*cat_rec, struct vdfs4_fsck_superblock_info *fsck_info, __u64 *inum)
{
	struct vdfs4_catalog_file_record *file_rec = NULL;
	struct vdfs4_cattree_record *hl_rec;
	int rec_type = le16_to_cpu(cat_rec->key->record_type);

	*inum = le64_to_cpu(cat_rec->key->object_id);
	if (rec_type == VDFS4_CATALOG_FOLDER_RECORD) {
		file_rec = (struct vdfs4_catalog_file_record *)cat_rec->val;
		return file_rec;
	} else if (rec_type == VDFS4_CATALOG_FILE_RECORD) {
		file_rec = (struct vdfs4_catalog_file_record *)cat_rec->val;
	} else if (rec_type == VDFS4_CATALOG_HLINK_RECORD) {
		int ret = 0;

		hl_rec = vdfs4_cattree_find(fsck_info->sbi.catalog_tree,
				*inum, NULL, 0, VDFS4_BNODE_MODE_RO);

		if (IS_ERR(hl_rec)) {
			log_error("Can't find inum %d in hltree for record %d:%.*s, error %d\n",
			*inum, cat_rec->key->parent_id, cat_rec->key->name_len,
			cat_rec->key->name, PTR_ERR(hl_rec));
			return (struct vdfs4_catalog_file_record *)hl_rec;
		}

		ret = check_gen_key(&hl_rec->key->gen_key,
			get_bnode_size(&fsck_info->sbi));
		if (ret) {
			log_error("Corrupted gen key, key_len: "
			"%d rec_len: %d\n", hl_rec->key->gen_key.key_len,
			hl_rec->key->gen_key.record_len);
			return ERR_PTR(-EINVAL);
		}

		file_rec = hl_rec->val;
	} else if (rec_type != VDFS4_CATALOG_ILINK_RECORD) {
			log_error("Unknow record type\n");
			return ERR_PTR(-EINVAL);
	}
	return file_rec;
}

int is_this_file_have_data_part(struct vdfs4_catalog_file_record *value)
{
	return S_ISLNK(value->common.file_mode) ||
			S_ISREG(value->common.file_mode);
}

/*
int is_tiny_file(struct vdfs4_catalog_file_record *value)
{
	return value->common.flags & (1 << TINY_FILE);
}
*/

int build_total_items_and_links_array(struct vdfs4_fsck_superblock_info
	*fsck_info, struct vdfs4_catalog_file_record *file, __u64 par_inum,
	__u8 rec_type, __u64 inum)
{
	struct total_items_element *readed_tie = NULL;
	struct total_items_element *calc_tie = NULL;
	int n_read_els = ++fsck_info->readed_tia.n_elements;

	readed_tie = realloc_zero(fsck_info->readed_tia.tie, (n_read_els - 1) *
		sizeof(struct total_items_element), n_read_els *
		sizeof(struct total_items_element));

	if (readed_tie == NULL)
		goto exit;

	fsck_info->readed_tia.tie = readed_tie;

	if (!(fsck_info->calculated_tia.n_elements > max(inum, par_inum))) {
		calc_tie = realloc_zero(fsck_info->calculated_tia.tie,
			(fsck_info->calculated_tia.n_elements) *
			sizeof(struct total_items_element), (max(inum, par_inum)
			+ 1) * sizeof(struct total_items_element));
		fsck_info->calculated_tia.n_elements = max(inum, par_inum) + 1;
		if (calc_tie == NULL)
			goto exit;

		fsck_info->calculated_tia.tie = calc_tie;
	}
	fsck_info->readed_tia.tie[n_read_els - 1].links_count =
		file->common.links_count;

	if (rec_type == VDFS4_CATALOG_FILE_RECORD ||
	    rec_type == VDFS4_CATALOG_HLINK_RECORD ||
	    (rec_type == VDFS4_CATALOG_FOLDER_RECORD &&
	     (S_ISCHR(file->common.file_mode) ||
	      S_ISBLK(file->common.file_mode))))
		fsck_info->readed_tia.tie[n_read_els - 1].total_items_count = 0;
	else
		fsck_info->readed_tia.tie[n_read_els - 1].total_items_count =
				file->common.total_items_count;

	fsck_info->readed_tia.tie[n_read_els - 1].inode_number = inum;

	fsck_info->calculated_tia.tie[inum].links_count++;
	fsck_info->calculated_tia.tie[par_inum].total_items_count++;

	if (is_this_file_have_data_part(file)) {
		int fk_total_count = 0;
		fsck_info->readed_tia.tie[n_read_els - 1].total_blocks_count =
			file->data_fork.total_blocks_count;
		fk_total_count = fork_total_block_count(&file->data_fork);
		if (fk_total_count < 0)
			goto exit;

		fsck_info->calculated_tia.tie[inum].total_blocks_count =
			fk_total_count;
	}
	return EXIT_SUCCESS;
exit:
	free(readed_tie);
	free(calc_tie);
	return -ENOMEM;
}

/* TODO Refactor using simple array interface */
int check_total_items_and_links(struct vdfs4_fsck_superblock_info *fsck_info)
{
	unsigned int ctr = 0;
	int ret = 0;
	for (; ctr < fsck_info->readed_tia.n_elements; ctr++) {
		__u64 inum = fsck_info->readed_tia.tie[ctr].inode_number;
		__u64 read_links_count =
			fsck_info->readed_tia.tie[ctr].links_count;
		__u64 calc_links_count =
			fsck_info->calculated_tia.tie[inum].links_count;
		__u64 read_ti_count =
			fsck_info->readed_tia.tie[ctr].total_items_count;
		__u64 calc_ti_count =
			fsck_info->calculated_tia.tie[inum].total_items_count;
		__u64 read_tb_count =
			fsck_info->readed_tia.tie[ctr].total_blocks_count;
		__u64 calc_tb_count =
			fsck_info->calculated_tia.tie[inum].total_blocks_count;
		if (read_links_count != calc_links_count) {
			log_error("Invalid links count inode %llu,\n "
				"calculated: %llu, readed: %llu\n", inum,
				calc_links_count, read_links_count);
			ret |= FSCK_INVALID_LINKS_COUNT;
		}

		if (read_ti_count != calc_ti_count) {
			log_error("Invalid total items count inode %llu,\n "
				"calculated: %llu, readed: %llu\n", inum,
				calc_ti_count, read_ti_count);
			ret |= FSCK_INVALID_TOTAL_ITEMS_COUNT;
		}

		if (read_tb_count != calc_tb_count) {
			log_error("Invalid total blocks count inode %llu,\n "
				"calculated: %llu, readed: %llu\n", inum,
				calc_tb_count, read_tb_count);
			ret |= FSCK_INVALID_TOTAL_BLOCKS_COUNT;
		}
	}
	return ret;
}

int build_inum_fork_dependency(struct vdfs4_fsck_superblock_info *fsck_info,
	__u64 inum, struct vdfs4_fork *fork)
{
	void *ret = NULL;
	unsigned int i = 0;
	struct inum_extents_dependency curr_el;

	ret = find_in_arr(&fsck_info->inum_fork_dep, inum);

	curr_el.inum = inum;
	curr_el.extents.elements = malloc(VDFS4_EXTENTS_COUNT_IN_FORK *
			sizeof(struct vdfs4_extent));
	curr_el.extents.elem_size = sizeof(struct vdfs4_extent);
	curr_el.extents.n_elements = 0;
	for (; i < VDFS4_EXTENTS_COUNT_IN_FORK; i++)
		if (fork->extents[i].extent.length)
			push_back(&curr_el.extents, &fork->extents[i].extent);

	if (IS_ERR(ret))
		push_back(&fsck_info->inum_fork_dep, &curr_el);
	else {
		struct inum_extents_dependency *found_el = ret;
		if (!is_extents_array_equal(curr_el.extents.elements,
			found_el->extents.elements,
			found_el->extents.n_elements)) {
			log_error("Different forks for one inum %llu\n ", inum);
			return -EINVAL;
		}
	}
	return EXIT_SUCCESS;
}

int check_extents_intersection(struct vdfs4_fsck_superblock_info *fsck_info,
	int maximal_block)
{
	unsigned int i = 0;
	int ret = 0;
	char *extents_intersection_bmap = calloc(maximal_block / CHAR_BIT, 1);
	for (; i < fsck_info->inum_fork_dep.n_elements; i++) {

		struct inum_extents_dependency *cur_element =
			fsck_info->inum_fork_dep.elements + i *
			sizeof(struct inum_extents_dependency);
		ret |= add_extents_to_buffer(extents_intersection_bmap,
			cur_element->extents.elements, cur_element->extents.
			n_elements);
	}

	free(extents_intersection_bmap);
	if (ret)
		log_info("Hint: Use fsck.vdfs4 -n option\n"
			"to find corrupted files\n");
	return ret;
}

int build_squash_mnt_pt_config(struct vdfs4_fsck_superblock_info *fsck_info)
{
	int ret = 0;
	int image_path_len;
	char *image_path = NULL, *mnt_pt_path = NULL;

	__u32 ctr = 0;
	__u64 image_inum, mnt_pt_inum;
	for (; ctr < fsck_info->squash_mnt_dep.n_elements; ctr++) {
		void *el = get_array_elem(&fsck_info->squash_mnt_dep, ctr);
		image_path_len = 0;
		if (IS_ERR(el))
			goto exit;
		image_inum = ((struct squash_fs_dependency *)el)->
			image_inum;
		mnt_pt_inum = ((struct squash_fs_dependency *)el)->
			mount_pt_inum;
		ret = restore_full_file_name(fsck_info, image_inum, &image_path,
				&image_path_len);
		if (ret)
			goto exit;

		image_path_len = 0;
		ret = restore_full_file_name(fsck_info, mnt_pt_inum,
			&mnt_pt_path, &image_path_len);
		if (ret)
			goto exit;

		printf("INSTALL %s %s\n", image_path, mnt_pt_path);
	}
exit:
	free(image_path);
	free(mnt_pt_path);
	return ret;
}

int add_extrec_to_bmap(struct vdfs4_btree_gen_record *rec,
		struct vdfs4_fsck_superblock_info *fsck_info,
		__attribute__((unused)) void **callback)
{
	int ret = 0;
	int display_bnode = 0;
	__u64 inum = 0;
	struct vdfs4_exttree_record *ext_rec = (struct vdfs4_exttree_record *)rec;
	inum = ext_rec->key->object_id;
	ret = check_gen_key(&ext_rec->key->gen_key,
		get_bnode_size(&fsck_info->sbi));

	if (ret) {
		log_error("Corrupted gen key, rec_len: %d key_len: %d\n",
			ext_rec->key->gen_key.key_len, ext_rec->key->gen_key.
				record_len);
		display_bnode = 1;
		goto print_exit;
	}
	if (!IS_FLAG_SET(fsck_info->sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = is_valid_offset_for_bitmap(fsck_info, INODE_BM_INDEX,
				fsck_info->sbi.block_size, inum);

		if (ret < 0) {
			log_error("Invalid object id number, %llu\n", inum);
			display_bnode = 1;
			ret = -EINVAL;
		}
	}
	if (!inum)
		goto print_exit;

	if (is_extent_corrupted(ext_rec->lextent, fsck_info) < 0) {
		log_error("Bad overflow tree extent\n");
		print_extent(ext_rec->lextent);
		display_bnode = 1;
	} else {
		void *ext_ret = NULL;
		add_extent_to_bmap(ext_rec->lextent, fsck_info);
		ext_ret = find_in_arr(&fsck_info->inum_fork_dep, inum);

		if (IS_ERR(ext_ret)) {
			if (inum < VDFS4_1ST_FILE_INO)
				return ret;
			log_error("Extent with obj_id %llu found in "
			"exttree but there is no file in cattree with "
			"such inum\n", inum);
			ret = -EINVAL;
		} else {
			struct inum_extents_dependency *found_el = ext_ret;
			if (found_el->extents.n_elements <
				VDFS4_EXTENTS_COUNT_IN_FORK) {
				log_error("Extent of file inum: %llu found in\n"
				" exttree, but it can't be there because\n"
				" number of extents = %llu", inum, found_el->
				extents.n_elements);
				ret = -EINVAL;
			}
			push_back(&found_el->extents, ext_rec->lextent);
			fsck_info->calculated_tia.tie[inum].
				total_blocks_count += ext_rec->lextent->length;
		}
	}
print_exit:
	if (display_bnode) {
		printf("Exttree\n");
		printf("Bnode id: %d\n", VDFS4_BTREE_REC_I((struct
			vdfs4_btree_gen_record*)ext_rec)->rec_pos.
				bnode->node_id);
		printf("Record pos: %d\n", VDFS4_BTREE_REC_I((struct
				vdfs4_btree_gen_record*)ext_rec)->rec_pos.pos);
		printf("\n");
	}
	return ret;
}

struct vdfs4_cattree_record *find_record_from_ino_n(struct vdfs4_sb_info *sbi,
		__le64 ino)
{
	void *ret = NULL;
	struct vdfs4_btree *tree = sbi->catalog_tree;
	struct vdfs4_cattree_record *record =
			vdfs4_cattree_get_first_child(sbi->catalog_tree, ino);

	if (IS_ERR(record))
		return record;

again:
	if (record->key->parent_id != ino) {
		ret = ERR_PTR(-ENOENT);
		vdfs4_release_record((struct vdfs4_btree_gen_record *)record);
		return ret;
	}

	if (record->key->record_type == VDFS4_CATALOG_ILINK_RECORD) {
		struct vdfs4_cattree_record *ilink = record;
		record = vdfs4_cattree_find_inode(tree,
				ino, ilink->key->object_id,
				ilink->key->name, ilink->key->name_len,
				VDFS4_BNODE_MODE_RO);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) ilink);
	} else if (le64_to_cpu(record->key->object_id) == ino) {
		/* hard-link body */
	} else {
		/* it could be: first child not ilink */
		int ret_val = vdfs4_get_next_btree_record(
				(struct vdfs4_btree_gen_record *) record);
		if (ret_val) {
			ret = ERR_PTR(ret_val);
			return ret;
		}
		goto again;
	}
	return record;
}

int check_orphan_inodes(struct vdfs4_fsck_superblock_info *fsck_info)
{
	int ret = 0;
	struct vdfs4_cattree_record *rec = vdfs4_cattree_find(
			fsck_info->sbi.catalog_tree, VDFS4_ROOTDIR_OBJ_ID,
			"root", 4, VDFS4_BNODE_MODE_RO);
	if (IS_ERR(rec)) {
		ret = PTR_ERR(rec);
		return ret;
	}
	struct vdfs4_catalog_file_record *value = rec->val;
	__le64 next_orphan_id = value->common.next_orphan_id;

	while (next_orphan_id) {
		vdfs4_release_record((struct vdfs4_btree_gen_record *)rec);
		rec = find_record_from_ino_n(&fsck_info->sbi, next_orphan_id);
		if (IS_ERR(rec)) {
			ret = PTR_ERR(rec);
			return ret;
		}
		value = rec->val;
		ret = add_inode_to_bmap(next_orphan_id, fsck_info);
		if (ret)
			goto exit;
		/*Checking data (for ordinary files)*/
		if (is_this_file_have_data_part(value)) {
			ret = is_fork_corrupted(&value->data_fork,
				fsck_info);
			if (ret == -EINVAL) {
				log_error("Bad file fork extent\n");
				print_fork(&value->data_fork);
				ret = -EINVAL;
			} else {
				ret = build_inum_fork_dependency(fsck_info,
					next_orphan_id, &value->data_fork);
				ret = add_fork_to_bmap(&value->data_fork,
						fsck_info);
				if (ret)
					goto exit;
			}
		}
		next_orphan_id = value->common.next_orphan_id;
	}
exit:
	vdfs4_release_record((struct vdfs4_btree_gen_record *)rec);
	return ret;
}
int add_catrec_to_bmaps(struct vdfs4_btree_gen_record *rec,
		struct vdfs4_fsck_superblock_info *fsck_info,
		__attribute__((unused)) void **callback)
{
	int ret = 0;
	__u64 inum = 1;
	int display_bnode = 0;
	int par_id_incorrect = 0;
	struct par_name_dependency par_name_dep;
	struct vdfs4_cattree_record *cat_rec = (struct vdfs4_cattree_record *)rec;
	int is_hlink = (le16_to_cpu(cat_rec->key->record_type) ==
		VDFS4_CATALOG_HLINK_RECORD);
	struct vdfs4_catalog_file_record *value = NULL;

	ret = check_gen_key(&cat_rec->key->gen_key,
			get_bnode_size(&fsck_info->sbi));

	if (ret) {
		log_error("Corrupted gen key, key_len: %d rec_len: %d\n",
			cat_rec->key->gen_key.key_len, cat_rec->key->gen_key.
				record_len);
		display_bnode = 1;
		goto print_exit;
	}

	/*/Checking key/*/
	/* Checking parent id */
	if (!IS_FLAG_SET(fsck_info->sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = is_valid_offset_for_bitmap(fsck_info, INODE_BM_INDEX,
				fsck_info->sbi.block_size,
				cat_rec->key->parent_id);

		if (ret < 0) {
			log_error("Invalid parent id number, %llu\n",
				cat_rec->key->parent_id);
			display_bnode = 1;
			par_id_incorrect = 1;
			ret = -EINVAL;
		}
	}
	/* Checking record type */
	value = get_rec_info(cat_rec, fsck_info, &inum);

	/* Hard-link body */
	if (le64_to_cpu(cat_rec->key->parent_id) == inum &&
			cat_rec->key->name_len == 0)
		return 0;

	if (cat_rec->key->record_type == VDFS4_CATALOG_ILINK_RECORD)
		return 0;

	if (IS_ERR(value)) {
		display_bnode = 1;
		ret = -EINVAL;
		/* Can't proceed checking */
		goto print_exit;
	}

	if (value->common.flags & (1 << ORPHAN_INODE))
		return ret;

	/* Checking value  */
	/* Checking common */
	/* Checking object id */
	if (!IS_FLAG_SET(fsck_info->sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = is_valid_offset_for_bitmap(fsck_info, INODE_BM_INDEX,
				fsck_info->sbi.block_size, inum);

		if ((ret > 0) && !is_hlink)
			log_info("Duplicate inode number %llu\n", inum);

		if (ret < 0) {
			log_error("Invalid object id number, %llu\n", inum);
			display_bnode = 1;
			ret = -EINVAL;
		} else {
			/* Set inode in bitmap if its ok */
			ret = add_inode_to_bmap(inum, fsck_info);
			if (!par_id_incorrect)
				ret = build_total_items_and_links_array(
					fsck_info, value,
					cat_rec->key->parent_id, cat_rec->key->
					record_type, inum);
		}
	}
	/*Checking data (for ordinary files)*/
	if (is_this_file_have_data_part(value)) {
		int ret = is_fork_corrupted(&value->data_fork,
			fsck_info);
		if (ret == -EINVAL) {
			log_error("Bad file fork extent\n");
			print_fork(&value->data_fork);
			display_bnode = 1;
			ret = -EINVAL;
		} else {
			ret = build_inum_fork_dependency(fsck_info,
				inum, &value->data_fork);
			add_fork_to_bmap(&value->data_fork, fsck_info);
		}
	}
	par_name_dep.name_len = cat_rec->key->name_len;
	memcpy(par_name_dep.name, cat_rec->key->name, par_name_dep.name_len);
	par_name_dep.obj_id = inum;
	par_name_dep.par_id = cat_rec->key->parent_id;
	push_back(&fsck_info->par_name_dep, &par_name_dep);

print_exit:
	if (display_bnode) {
		printf("Cattree\n");
		printf("Bnode id: %d\n", VDFS4_BTREE_REC_I((struct
			vdfs4_btree_gen_record*)cat_rec)->rec_pos.
				bnode->node_id);
		printf("Record pos: %d\n", VDFS4_BTREE_REC_I((struct
				vdfs4_btree_gen_record*)cat_rec)->rec_pos.pos);
		printf("\n");
	}
	return ret;
}

/* find by objid works, now expand to restore full name */
int restore_full_file_name(struct vdfs4_fsck_superblock_info *fsck_info,
	__u64 obj_id, char **result_path, int *path_len)
{
	int ret = 0;
	struct par_name_dependency *raw_par_dep = NULL;

	raw_par_dep = find_in_arr(&fsck_info->par_name_dep, obj_id);

	if (IS_ERR(raw_par_dep)) {
		log_error("Can't find obj_id %llu\n", obj_id);
		ret = -EINVAL;
		return ret;
	}

	if (raw_par_dep->par_id == VDFS4_ROOT_INO) {
		*result_path = realloc_zero(*result_path, *path_len,
			*path_len + raw_par_dep->name_len + 2);
		*path_len += raw_par_dep->name_len + 1;
		if (!*result_path)
			return -ENOMEM;
		strncat(*result_path, "/", 1);
		strncat(*result_path, (char *)raw_par_dep->name,
				raw_par_dep->name_len);
		return ret;
	}
	ret = restore_full_file_name(fsck_info, raw_par_dep->par_id,
		result_path, path_len);
	*result_path = realloc_zero(*result_path, *path_len,
		*path_len + raw_par_dep->name_len + 2);
	*path_len += raw_par_dep->name_len + 1;
	if (!*result_path)
		return -ENOMEM;
	strncat(*result_path, "/", 1);
	strncat(*result_path, (char *)raw_par_dep->name,
			raw_par_dep->name_len);
	return ret;
}

int check_head_bnode(struct vdfs4_bnode *bnode, __u32 max_bnode_id)
{
	int ret = 0;
	struct vdfs4_raw_btree_head *head_bn =
		(struct vdfs4_raw_btree_head *)bnode->data;

	if (memcmp(head_bn->magic, VDFS4_BTREE_HEAD_NODE_MAGIC,
			strlen(VDFS4_BTREE_HEAD_NODE_MAGIC))) {
		ret |= FSCK_CORRUPTED_BNODE_MAGIC;
		log_error("Invalid head bnode magic\n");
	}

	if (head_bn->root_bnode_id > max_bnode_id) {
		ret |= FSCK_CORRUPTED_BTREE_STRUCTURE;
		log_error("Invalid root_bnode id: %d\n",
			head_bn->root_bnode_id);
	}

	if (head_bn->btree_height >= 5) {
		ret |= FSCK_INVALID_BTREE_HEIGHT;
		log_error("Invalid btree height\n");
	}

	return ret;
}


static void *get_offset_addr(struct vdfs4_bnode *bnode, unsigned int index)
{
	void *ret;
	ret = (char *)bnode->data + bnode->host->node_size_bytes -
		VDFS4_BNODE_FIRST_OFFSET -
		sizeof(vdfs4_bt_off_t) * (index + 1);

	if (((unsigned)((char *)ret - (char *)bnode->data))
			>= bnode->host->node_size_bytes) {
		if (!is_sbi_flag_set(bnode->host->sbi, IS_MOUNT_FINISHED))
			return ERR_PTR(-EFAULT);
		else
			VDFS4_BUG();
	}
	return ret;
}


/**
 * @brief		Get offset for record with specified index
 *			inside bnode.
 * @param [in]	bnode	The bnode containing necessary record
 * @param [in]	index	Index of offset to get
 * @return		Returns offset starting from bnode start address
 */
static vdfs4_bt_off_t get_offset(struct vdfs4_bnode *bnode,
		unsigned int index)
{
	vdfs4_bt_off_t *p_ret;
	p_ret = get_offset_addr(bnode, index);
	if (IS_ERR(p_ret))
		return VDFS4_BT_INVALID_OFFSET;

	return *p_ret;
}


int check_bnode_records(struct vdfs4_bnode *bnode)
{
	int ret = 0, ctr = 0, offset_error = 0;
	int free_space = VDFS4_BNODE_DSCR(bnode)->free_space, calc_free_space;
	__u32 node_id = VDFS4_BNODE_DSCR(bnode)->node_id;
	__le16 recs_cnt = VDFS4_BNODE_DSCR(bnode)->recs_count;

	__u32 *offsets = malloc((recs_cnt + 1) * sizeof(int));
	memset(offsets, 0, recs_cnt * sizeof(int));

	for (; ctr <= recs_cnt; ctr++)
		offsets[ctr] = get_offset(bnode, ctr);

	calc_free_space = (intptr_t)get_offset_addr(bnode, recs_cnt) -
		(intptr_t)bnode->data - offsets[recs_cnt];

	if (free_space != calc_free_space) {
		log_error("Bnode free space doesn't match next to last record offset, "
			  "bnode %d, free_space: %d, calculated: %d\n",
			  node_id, free_space, calc_free_space);
		ret |= FSCK_RECORDS_OFFSETS_DOSENT_MATCH;
	}

	for (ctr = 0; ctr < recs_cnt + 1; ctr++) {
		if (offsets[ctr] >= bnode->host->node_size_bytes) {
			log_error("Invalid offset: %d bnode_id %d, offset # %d",
				offsets[ctr], node_id, ctr);
			offset_error = 1;
		}
	}
	if (offset_error) {
		free(offsets);
		return FSCK_CORRUPTED_OFFSET;
	}

	qsort(offsets, recs_cnt, sizeof(int), compare);
	for (ctr = 0; ctr < recs_cnt; ctr++) {
		int cur_offset = offsets[ctr];
		struct vdfs4_generic_key *rec =
			(void *)bnode->data + cur_offset;
		__u32 computed_len = offsets[ctr + 1] - offsets[ctr];

		if (computed_len != rec->record_len) {
			log_error("Offsets doesn't match records lens, "
			"bnode %d, calc_len: %d, readed_len: %d\n",
			node_id, computed_len, rec->record_len);
			ret |= FSCK_RECORDS_OFFSETS_DOSENT_MATCH;
		}

	}

	free(offsets);
	return ret;
}

static int check_left_and_right_bode_link(struct vdfs4_bnode *bnode,
	__u32 prev_node_id, __u32 node_id, __u32 next_node_id,
		int prev_node_id_correct, int next_node_id_correct)
{
	int ret = 0;

	if (prev_node_id && prev_node_id_correct) {
		struct vdfs4_bnode *prev_bnode = __vdfs4_get_bnode(bnode->host,
			prev_node_id, VDFS4_BNODE_MODE_RO);

		if (IS_ERR(prev_bnode)) {
			log_error("Can't get bnode\n");
			return -EINVAL;
		}

		__u32 prev_node_next_node_id = VDFS4_BNODE_DSCR(prev_bnode)->
			next_node_id;
		if (prev_node_next_node_id != node_id) {
			log_error("Link damaged between bnode %d and "
				"bnode %d\n", node_id, prev_node_id);
			ret |= FSCK_CORRUPTED_BNODE_ID;
		}
		put_bnode(prev_bnode);
	}

	if (next_node_id && next_node_id_correct) {
		struct vdfs4_bnode *next_bnode = __vdfs4_get_bnode(bnode->host,
			next_node_id, VDFS4_BNODE_MODE_RO);

		if (IS_ERR(next_bnode)) {
			log_error("Can't get bnode\n");
			return -EINVAL;
		}

		__u32 next_node_prev_node_id = VDFS4_BNODE_DSCR(next_bnode)->
			prev_node_id;
		if (next_node_prev_node_id != node_id) {
			log_error("Link damaged between bnode %d and "
				"bnode %d\n", node_id, next_node_id);
			ret |= FSCK_CORRUPTED_BTREE_STRUCTURE;
		}
		put_bnode(next_bnode);
	}
	return ret;
}

static void dump_bnode_info(struct vdfs4_bnode *bnode, char *msg)
{
	struct vdfs4_btree *btree = bnode->host;
	const char *btree_type;

	if (btree->btree_type == VDFS4_BTREE_EXTENTS)
		btree_type = "extents tree";
	else if (btree->btree_type == VDFS4_BTREE_CATALOG)
		btree_type = "catalog tree";
	else if (btree->btree_type == VDFS4_BTREE_XATTRS)
		btree_type = "xattr tree";
	else
		btree_type = "unknown tree";
	log_error("%s:\n\t%s, bnode %d\n\tprev bnode: %d\n\tnext bnode: %d\n",
			msg, btree_type,
			VDFS4_BNODE_DSCR(bnode)->node_id,
			VDFS4_BNODE_DSCR(bnode)->prev_node_id,
			VDFS4_BNODE_DSCR(bnode)->next_node_id);
}

int check_bnode(struct vdfs4_bnode *bnode, __u32 max_bnode_id, int flags)
{
	int ret = 0;
	__u32 node_id = VDFS4_BNODE_DSCR(bnode)->node_id;
	__u32 prev_node_id = VDFS4_BNODE_DSCR(bnode)->prev_node_id;
	__u32 next_node_id = VDFS4_BNODE_DSCR(bnode)->next_node_id;
	__u16 recs_cnt = VDFS4_BNODE_DSCR(bnode)->recs_count;
	int node_id_correct = node_id <= max_bnode_id;
	int prev_node_id_correct = prev_node_id <= max_bnode_id;
	int next_node_id_correct = next_node_id <= max_bnode_id;
	int is_recs_ok = recs_cnt <= MAX_RECS_IN_BNODE(bnode);

	if (!is_recs_ok) {
		dump_bnode_info(bnode, "Invalid recs_cnt in bnode");
		ret |= FSCK_INVALID_RECS_CNT;
	}

	if (memcmp(VDFS4_BNODE_DSCR(bnode)->magic, "Nd", strlen("Nd"))) {
		dump_bnode_info(bnode, "Invalid bnode magic");
		ret |= FSCK_CORRUPTED_BNODE_MAGIC;
	}

	if (!IS_FLAG_SET(flags, UPDATE_CRC))
		if (util_validate_crc(bnode->data,
				bnode->host->node_size_bytes, 0)) {
			dump_bnode_info(bnode, "Invalid bnode crc");
			ret |= FSCK_BNODE_CRC_MISMATCH;
	}

	if (!node_id_correct) {
		ret |= FSCK_CORRUPTED_BNODE_ID;
		dump_bnode_info(bnode, "Invalid bnode id: %d\n");
	}

	if (!prev_node_id_correct) {
		ret |= FSCK_CORRUPTED_BNODE_ID;
		dump_bnode_info(bnode, "Invalid prev bnode id");
	}

	if (!next_node_id_correct) {
		ret |= FSCK_CORRUPTED_BNODE_ID;
		ret |= FSCK_CORRUPTED_BTREE_STRUCTURE;
		dump_bnode_info(bnode, "Invalid next bnode id");
	}

	ret |= check_left_and_right_bode_link(bnode, prev_node_id, node_id,
		next_node_id, prev_node_id_correct, next_node_id_correct);

	if (ret == -EINVAL)
		return ret;

	if (is_recs_ok)
		ret |= check_bnode_records(bnode);
	return ret;
}

int mark_bnode_visited(__u32 node_id, struct vdfs4_fsck_superblock_info
	*fsck_info, int tree_ino)
{
	int tree_index = ino_to_index(tree_ino);

	if (tree_index == -EINVAL) {
		log_error("Invalid tree index\n");
		return -EINVAL;
	}

	int ret = test_bnode_in_bmap(node_id, fsck_info,
		tree_index);
	if (ret > 0)
		log_error("Bnode %d visited twice\n", node_id);
	if (ret < 0) {
		log_error("Can't test bit in bmap %d\n", node_id);
		return ret;
	}

	return add_bnode_to_bmap(node_id, fsck_info, tree_index);
}

int get_first_not_visited_child(struct vdfs4_bnode *bnode,
	struct vdfs4_fsck_superblock_info *fsck_info, __u32 max_bnode,
	int tree_ino, __u32 *next_node_id)
{
	int ctr = 0, glob_ret = 0;
	__u32 node_id = VDFS4_BNODE_DSCR(bnode)->node_id;

	for (; ctr < VDFS4_BNODE_DSCR(bnode)->recs_count; ctr++) {
		int ret = 0;
		void *rec = vdfs4_get_btree_record(bnode, ctr);
		if (IS_ERR(rec)) {
			log_error("Getting corrupted record, bnode %d\n",
				node_id);
			glob_ret |= FSCK_CORRUPTED_RECORD;
			continue;
		}
		struct vdfs4_generic_key *gen_key =
			((struct vdfs4_generic_key *)rec);

		ret = check_gen_key(gen_key, bnode->host->node_size_bytes);

		if (ret) {
			log_error("Invalid generic key, in "
				"index bnode %d, record %d", node_id, ctr);
			glob_ret |= FSCK_CORRUPTED_BTREE_STRUCTURE;
			continue;
		}

		struct generic_index_value *val = (struct generic_index_value *)
			((char *)rec + (gen_key->key_len));

		if (val->node_id <= max_bnode) {
			if (!test_bnode_in_bmap(val->node_id, fsck_info,
				ino_to_index(tree_ino))) {
				*next_node_id = val->node_id;
				return glob_ret;
			}
		} else {
			log_error("Invalid node_id in record, in "
				"index bnode %d", node_id);
		}
	}

	*next_node_id = -ENOENT;
	return glob_ret;
}

int dfs_bnode(__u32 node_id, struct vdfs4_fsck_superblock_info *fsck_info,
	__u32 max_bnode_id, struct vdfs4_btree *btree, int tree_ino)
{
	int ret = 0;
	__u32 next_node_id = 0;
	struct vdfs4_bnode *bnode = __vdfs4_get_bnode(btree, node_id,
		VDFS4_BNODE_MODE_RO);

	if (bnode->node_id != node_id)
		log_error("Retrieved bnode via index %d have node id %d\n",
			node_id, bnode->node_id);

	if (IS_ERR(bnode)) {
		mark_bnode_visited(node_id, fsck_info, tree_ino);
		log_error("Can't get bnode %d\n", node_id);
		return -EINVAL;
	}
	ret = check_bnode(bnode, max_bnode_id,
			fsck_info->sbi.service_flags);
	if (mark_bnode_visited(node_id, fsck_info, tree_ino) < 0)
		return -EINVAL;

	if (VDFS4_BNODE_DSCR(bnode)->type == VDFS4_NODE_INDEX) {
		do {
			if (util_test_bit((char *)&ret,
				(long long unsigned)log2_32(
					FSCK_INVALID_RECS_CNT))) {

				util_clear_bits((char *)&ret,
				(long long unsigned)log2_32(
					FSCK_INVALID_RECS_CNT), 1);
				return ret;
			}
			ret |= get_first_not_visited_child(bnode,
				fsck_info, max_bnode_id, tree_ino,
				&next_node_id);

			if ((int)next_node_id > 0)
				ret |= dfs_bnode(next_node_id, fsck_info,
					max_bnode_id, btree, tree_ino);

		} while ((int)next_node_id != -ENOENT);

	} else if (VDFS4_BNODE_DSCR(bnode)->type == VDFS4_NODE_LEAF) {
		/* Process leaf */
	} else
		log_error("Invalid bnode type, bnode id %d\n", node_id);

	put_bnode(bnode);
	return ret;
}

int initialize_tree_bitmap(struct bitmap_info *bitmap, struct vdfs4_bnode
	*bnode, int read_flag)
{
	bitmap->length_in_bytes = btree_get_bitmap_size(bnode->host->sbi);
	if (read_flag) {
		struct vdfs4_raw_btree_head *head_bnode_desc =
			bnode->data;
		bitmap->bitmap = (char *) &head_bnode_desc->bitmap;
	} else {
		bitmap->bitmap = calloc(bitmap->length_in_bytes, 1);
		if (!bitmap->bitmap) {
			log_error("Failed to create tree bmap");
			return -ENOMEM;
		}
	}
	return EXIT_SUCCESS;
}

int tree_structure_check(struct vdfs4_btree *btree,
	struct vdfs4_fsck_superblock_info *fsck_info, int tree_ino)
{
	int ret = 0, tree_index = 0;
	__u32 max_bnode_id = 0;
	struct vdfs4_bnode *head_bnode = NULL;
	int *visited_bnodes = NULL;
	struct vdfs4_base_table *base_table = fsck_info->sbi.snapshot.base_table;
	max_bnode_id = le64_to_cpu(base_table->
		last_page_index[VDFS4_SF_INDEX(tree_ino)]);

	head_bnode = __vdfs4_get_bnode(btree, HEAD_BNODE_ID,
			VDFS4_BNODE_MODE_RO);

	if (IS_ERR(head_bnode)) {
		log_error("Can't get head bnode\n");
		return -EINVAL;
	}

	ret |= check_head_bnode(head_bnode, max_bnode_id);

	if (util_test_bit((char *)&ret,
		(long long unsigned)log2_32(FSCK_CORRUPTED_BTREE_STRUCTURE))) {
		return ret;
	}
	tree_index = ino_to_index(tree_ino);

	if (tree_index == -EINVAL) {
		log_error("Invalid tree index\n");
		return -EINVAL;
	}

	ret = add_bnode_to_bmap(head_bnode->node_id, fsck_info, tree_index);
	if (ret < 0)
		return ret;

	ret |= dfs_bnode(VDFS4_BTREE_HEAD(btree)->root_bnode_id,
		fsck_info, max_bnode_id, btree, tree_ino);

	if (!util_test_bit((char *)&ret,
		(long long unsigned)log2_32(FSCK_CORRUPTED_BTREE_STRUCTURE))) {

		int dang_num = 0;
		ret |= vdfs4_check_btree_links(btree, &dang_num);
		if (ret < 0) {
			ret |= FSCK_CORRUPTED_BTREE_STRUCTURE;
			log_error("Btree links in index records dosen't match "
			"appropriate bnodes ids, dang num &d\n", dang_num);
			return ret;
		}

		ret |= vdfs4_check_btree_records_order(btree);
		if (ret < 0) {
			ret |= FSCK_CORRUPTED_BTREE_STRUCTURE;
			return ret;
		}
	}

	put_bnode(head_bnode);
	free(visited_bnodes);
	return ret;
}

int is_tree_structure_damaged_critically(int ret_code)
{
	if (util_test_bit((char *)&ret_code,
		(long long unsigned)log2_32(FSCK_CORRUPTED_BTREE_STRUCTURE)))
		return true;
	else
		return false;
}

int check_all_trees_structure(struct vdfs4_fsck_superblock_info *fsck_info)
{
	int ret[FSCK_NUM_OF_CHECKED_TREES];
	int ctr = 0;

	memset(ret, 0, FSCK_NUM_OF_CHECKED_TREES * sizeof(int));
	for (; ctr < FSCK_NUM_OF_CHECKED_TREES; ctr++) {
		int init_ret = 0;
		int tree_index = ctr + CATTREE_BM_INDEX;
		if (IS_FLAG_SET(fsck_info->sbi.service_flags, VERBOSE))
			printf("\nChecking %s  structure\n"
				"--------------------------------\n",
				print_metadata_name_by_inode(fsck_checked_inos
				[FSCK_FIRST_TREE_INDEX + ctr]));

		init_ret = initialize_tree_bitmap(&fsck_info->
			sb_bitmaps[tree_index], fsck_checked_trees
			[ctr]->head_bnode, 1);
		if (init_ret)
			return init_ret;

		init_ret = initialize_tree_bitmap(&fsck_info->calc_bitmaps
			[tree_index], fsck_checked_trees[ctr]->
			head_bnode, 0);
		if (init_ret)
			return init_ret;


		ret[ctr] = tree_structure_check(fsck_checked_trees[ctr],
			fsck_info, fsck_checked_inos
			[FSCK_FIRST_TREE_INDEX + ctr]);
		if (!ret[ctr]) {
			if (IS_FLAG_SET(fsck_info->sbi.service_flags, VERBOSE))
				printf("It's OK\n");

		}
		if (IS_FLAG_SET(fsck_info->sbi.service_flags, VERBOSE))
			printf("--------------------------------\n");
	}
	for (ctr = 0; ctr < FSCK_NUM_OF_CHECKED_TREES; ctr++) {
		if (is_tree_structure_damaged_critically(ret[ctr])) {
			log_error("%s structure damaged critically",
				print_metadata_name_by_inode(
				fsck_checked_inos[FSCK_FIRST_TREE_INDEX +
					ctr]));
			return -EINVAL;
		}
	}

	return EXIT_SUCCESS;
}
