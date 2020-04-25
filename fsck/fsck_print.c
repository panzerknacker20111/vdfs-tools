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

const char *print_metadata_name_by_inode(int inode_num)
{
	switch (inode_num) {
	case VDFS4_ROOT_INO:
		return "root inode";
	case VDFS4_SPACE_BITMAP_INO:
		return "space bitmap";
	case VDFS4_FREE_INODE_BITMAP_INO:
		return "free inode bitmap";
	case VDFS4_CAT_TREE_INO:
		return "catalog btree";
	case VDFS4_EXTENTS_TREE_INO:
		return "extents btree";
	case VDFS4_XATTR_TREE_INO:
		return "xattrs btree";
	default:
		return "";
	}
}

int print_cattree_leaf(struct vdfs4_cattree_key *key_ptr, struct vdfs4_bnode
		*bn, int rec_ctr)
{
	int ret = 0;
	__u64 inum;
	struct vdfs4_cattree_record *hl_rec;
	struct vdfs4_catalog_folder_record *val =
		(struct vdfs4_catalog_folder_record *)((char *)key_ptr +
				key_ptr->gen_key.key_len);

	__u32 offset = ((char *)key_ptr - (char *)bn->data);
	char *type;

	switch (key_ptr->record_type) {

	case VDFS4_CATALOG_FILE_RECORD:

		if (S_ISREG(val->file_mode)) {
			type = "File";
			break;
		}

		if (S_ISLNK(val->file_mode)) {
			type = "Symlink";
			break;
		}

		if (S_ISFIFO(val->file_mode)) {
			type = "FIFO";
			break;
		}

		if (S_ISSOCK(val->file_mode)) {
			type = "Socket";
			break;
		}

		if (S_ISCHR(val->file_mode)) {
			type = "Chardev";
			break;
		}

		if (S_ISBLK(val->file_mode)) {
			type = "Blkdev";
			break;
		}
	case VDFS4_CATALOG_HLINK_RECORD:
		type = "Hlink";
		inum = key_ptr->object_id;
		hl_rec = vdfs4_cattree_find(bn->host->sbi->catalog_tree,
				inum, NULL, 0, VDFS4_BNODE_MODE_RO);
		if (IS_ERR(hl_rec)) {
			log_error("Can't find inum %d in hltree, error %d\n",
					inum, PTR_ERR(hl_rec));

			printf(" name length %d name %s obj_id %lu par_id %lu"
					" record_type %d\n ",
					key_ptr->name_len,
					key_ptr->name,
					(long unsigned int)key_ptr->object_id,
					(long unsigned int)key_ptr->parent_id,
					key_ptr->record_type);

			return PTR_ERR((struct vdfs4_catalog_file_record *)
				hl_rec);
		}
		val = hl_rec->val;
		break;
	case VDFS4_CATALOG_FOLDER_RECORD:
		type = "Folder";
		break;
	case VDFS4_CATALOG_ILINK_RECORD:
		type = "Ilink";
		break;
	case VDFS4_CATALOG_DLINK_RECORD:
		type = "Dlink";
		break;
	default:
		log_error("Unrecognized file type: %x", key_ptr->record_type);
		type = "Error";
		ret = -EINVAL;
	};

	printf("%5d%10llu%10llu%3s%30.*s%10s%10d\n", rec_ctr,
			key_ptr->parent_id, key_ptr->object_id, "   ",
			key_ptr->name_len, key_ptr->name, type, offset);

	return ret;
}

void print_exttree_leaf(struct vdfs4_exttree_lrecord *rec_ptr,
		struct vdfs4_bnode *bn, int rec_ctr)
{
	__u32 offset = ((char *)rec_ptr - (char *)bn->data);

	printf("%5d%10llu%3s%7llu%10llu%10lld%10d\n", rec_ctr, rec_ptr->
			key.object_id, "   ", rec_ptr->key.iblock,
			rec_ptr->lextent.begin, rec_ptr->lextent.length,
			offset);
}

void print_cattree_index(struct vdfs4_cattree_key *key_ptr, struct vdfs4_bnode
		*bn, int rec_ctr)
{
	int offset = ((char *)key_ptr - (char *)bn->data);
	struct generic_index_value *val = (void *)key_ptr +
			key_ptr->gen_key.key_len;
	printf("%5d%10llu%3s%30.*s%10d%10d\n", rec_ctr, key_ptr->
			parent_id, "   ", key_ptr->name_len, key_ptr->name,
			val->node_id, offset);
}

void print_exttree_index(struct vdfs4_exttree_key *key_ptr,
		struct vdfs4_bnode *bn, int rec_ctr)
{
	int offset = ((char *)key_ptr - (char *)bn->data);
		struct generic_index_value *val = (void *)key_ptr +
				key_ptr->gen_key.key_len;
		printf("%5d%10llu%10llu%3s%10d%10d\n",
				rec_ctr, key_ptr->object_id,
				key_ptr->iblock, "   ", val->node_id, offset);
}

int print_record(struct vdfs4_bnode *bn, int rec_ctr, enum vdfs4_btree_type
		btree_type)
{
	int ret = 0;
	void *rec = vdfs4_get_btree_record(bn, rec_ctr);
	if (IS_ERR(rec)) {
		log_error("Getting corrupted record, can't parse\n");
		return -ERDFAIL;
	}

	if (btree_type == VDFS4_BTREE_CATALOG) {
		struct vdfs4_cattree_key *key_ptr = rec;

		if (VDFS4_BNODE_DSCR(bn)->type == VDFS4_NODE_LEAF)
			ret = print_cattree_leaf(key_ptr, bn, rec_ctr);
		else if (VDFS4_BNODE_DSCR(bn)->type == VDFS4_NODE_INDEX)
			print_cattree_index((struct vdfs4_cattree_key *)
					key_ptr, bn, rec_ctr);

	} else if (btree_type == VDFS4_BTREE_EXTENTS) {
		struct vdfs4_exttree_lrecord *key_ptr = rec;
		if (VDFS4_BNODE_DSCR(bn)->type == VDFS4_NODE_LEAF)
			print_exttree_leaf(key_ptr, bn, rec_ctr);
		else if (VDFS4_BNODE_DSCR(bn)->type == VDFS4_NODE_INDEX)
			print_exttree_index((struct vdfs4_exttree_key *)
					key_ptr, bn, rec_ctr);
	}
	return ret;
}

int print_bnode(struct vdfs4_btree *btree, __u32 node_id)
{
	int ret = 0;
	struct vdfs4_bnode *bnode = __vdfs4_get_bnode(btree, node_id,
			VDFS4_BNODE_MODE_RO);
	if (IS_ERR(bnode)) {
		log_error("Can't find such bnode with node_id %d\n", node_id);
		ret = -ERDFAIL;
		return ret;
	}

	if (!memcmp(VDFS4_BNODE_DSCR(bnode)->magic, "eH", strlen("eH"))) {

		short int height = VDFS4_BTREE_HEAD(btree)->btree_height;
		printf("Head bnode\n");
		printf("Btree height: %hd\n", height);
		printf("Root bnode id: %d\n", VDFS4_BTREE_HEAD(btree)->
				root_bnode_id);

	} else if (!memcmp(VDFS4_BNODE_DSCR(bnode)->magic, "Nd",
			strlen("Nd"))) {
		int rec_ctr;

		printf("Bnode type: ");
		if (VDFS4_BNODE_DSCR(bnode)->type == VDFS4_NODE_INDEX)
			printf("VDFS4_NODE_INDEX\n");
		else if (VDFS4_BNODE_DSCR(bnode)->type == VDFS4_NODE_LEAF)
			printf("VDFS4_NODE_LEAF\n");
		else {
			printf("Unknown bnode type %x, can't parse\n",
					VDFS4_BNODE_DSCR(bnode)->type);
			return -ERDFAIL;
		}
		printf("Node id: %d\n", VDFS4_BNODE_DSCR(bnode)->node_id);
		printf("Num of records: %hd\n", VDFS4_BNODE_DSCR(bnode)->
			recs_count);

		printf("Prev node id: %d\n", VDFS4_BNODE_DSCR(bnode)->
				prev_node_id);
		printf("Next node id: %d\n", VDFS4_BNODE_DSCR(bnode)->
				next_node_id);

		if (VDFS4_BNODE_DSCR(bnode)->type == VDFS4_NODE_LEAF) {
			if (btree->btree_type == VDFS4_BTREE_CATALOG)
				printf("%5s%10s%10s%3s%30.30s%10s%10s\n", "Num",
						"Par id", "Obj id", "   ",
						"Record contain", "Type",
						"Offset");
			else if (btree->btree_type == VDFS4_BTREE_EXTENTS)
				printf("%5s%10s%3s%7s%10s%10s%10s\n", "Num",
						"Obj id", "   ",
						"iblock", "begin",
						"length", "Offset");
			else {
				log_error("Wrong tree type, can't parse\n");
				return -ERDFAIL;
			}

		} else if (VDFS4_BNODE_DSCR(bnode)->type ==
				VDFS4_NODE_INDEX){
			if (btree->btree_type == VDFS4_BTREE_CATALOG)
				printf("%5s%10s%3s%30.30s%10s%10s\n", "Num",
						"Par id", "   ", "Name",
						"Node id", "Offset");
			else if (btree->btree_type == VDFS4_BTREE_EXTENTS)
				printf("%5s%10s%10s%3s%10s%10s\n", "Num",
						"Obj id", "iblock",  "   ",
						"Node id", "Offset");
			else {
				log_error("Unknown tree type, can't parse\n");
				return -ERDFAIL;
			}
		}

		for (rec_ctr = 0; rec_ctr < VDFS4_BNODE_DSCR(bnode)->
			recs_count; rec_ctr++) {
			ret = print_record(bnode, rec_ctr, btree->btree_type);
		}
	} else {
		log_info("Incorrect bnode magic, can't parse\n");
		ret = -ERDFAIL;
		return ret;
	}

	return ret;
}

int print_superblock(struct vdfs4_fsck_superblock_info *fsck_info)
{
	struct vdfs4_extended_super_block *esb = &fsck_info->sbi.esb;
	int ret = 0;
	int *total = malloc(NUM_OF_METADATA_FORKS_IN_ESB * sizeof(int));
	char *color_red = malloc(30);
	char *color_white = malloc(30);
	char *color_black = malloc(30);
	char *color = malloc(30);
	int count;
	uint32_t meta_tbc = le32_to_cpu(esb->meta_tbc);
	uint64_t table_tbc = le64_to_cpu(esb->tables.length);


	if (!color_red || !color_white || !color_black || !color || !total) {
		log_error("Out of memory\n");
		ret = -ENOMEM;
		goto exit;
	}

	printf("META tbc:%5u\n", meta_tbc);

	count = 0;
	while (meta_tbc) {
		printf("\tstart\t: %llu\n\tend\t: %llu\n",
			le64_to_cpu(esb->meta[count].begin),
			le64_to_cpu(esb->meta[count].length) +
			le64_to_cpu(esb->meta[count].begin) - 1);

		meta_tbc -=
			le32_to_cpu(esb->meta[count].length);
		count++;
	}
	printf("TABLE tbc:%5llu\n", (unsigned long long)table_tbc);
	printf("\tstart\t: %llu\n\tend\t: %llu\n",
		le64_to_cpu(esb->tables.begin),
		le64_to_cpu(esb->tables.length) +
		le64_to_cpu(esb->tables.begin) - 1);

exit:
	free(total);
	free(color_red);
	free(color_white);
	free(color_black);
	free(color);

	return ret;
}
