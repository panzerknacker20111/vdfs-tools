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

#include <assert.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <dirent.h>
#include "unpack.h"
#include <compress.h>

static int create_symlink(struct vdfs4_sb_info *sbi, char *name,
		struct vdfs4_catalog_file_record *file_rec);

unsigned int vdfs4_debug_mask = 0
		/*+ VDFS4_DBG_INO*/
		/*+ VDFS4_DBG_FSM*/
		/*+ VDFS4_DBG_SNAPSHOT*/
		/*+ VDFS4_DBG_TRANSACTION*/
		+ VDFS4_DBG_BTREE
		+ VDFS4_DBG_TMP
		;

const unsigned int vdfs_tools_mode = 0
		+ VDFS4_TOOLS_GET_BNODE_FROM_VOLUME_PUT
		/*+ VDFS4_TOOLS_MULTITHREAD*/
		;

#define MAX_SYMLINK_SIZE 1024
#define ROOT_OBJECT_ID 1
/** default path where to unpack files */
#define DEFAULT_ROOT_PATH "./vdfs4_root"
/** size of buffer to allocate to get files contents */
#define BLOCKS_IN_BUFFER 64

extern int futimesat(int __fd, __const char *__file, __const struct timeval
	__tvp[2]) __THROW;
/**
 * @brief	Init new item of list with data
 * @param[out]	item	Pointer to a structure to init
 * @param[in]	object_id Value to set to object_id field
 * @param[in]	name	String with full path to the object to set
 */
int list_item_init(struct dir_list_item *item, __le64 object_id,
		__le64 parent_id, char *name, int name_len)
{
	int ret = 0;
	memset(item, 0, sizeof(struct dir_list_item));
	item->object_id = object_id;
	item->name = name;
	item->parent_id = parent_id;
	item->name_len = name_len;
	return ret;
}

/**
 * @brief	Free all items in linked list
 * @param[in]	list	Pointer to a first structure in list
 */
void list_free(struct dir_list_item *list)
{
	while (list != NULL) {
		struct dir_list_item *temp = list;
		list = list->next;
		free(temp->name);
		free(temp);
	}
}

/**
 * @brief	Add new item to list
 * @param[in]	head	Pointer to the list head
 * @param[in]	new	Pointer to the new item to add
 */
void list_insert(struct dir_list_item *head, struct dir_list_item *new)
{
	struct dir_list_item *list = head;

	while (list != NULL) {
		if (list->next == NULL) {
			list->next = new;
			break;
		}
		if (list->next->object_id > new->object_id) {
			new->next = list->next;
			list->next = new;
			break;
		}
		list = list->next;
	}
}

/**
 * @brief	Get item from list by object_id
 * @param[in]	head	Pointer to the list head
 * @param[in]	object_id	Value to find in list structures
 * @return	Pointer to the list item with requested object_id
 */
struct dir_list_item *list_get(struct dir_list_item *head, __le64 object_id)
{
	struct dir_list_item *list = head;

	while (list != NULL) {
		if (list->object_id == object_id)
			break;
		list = list->next;
	}

	return list;
}


int make_folder_list(struct dir_list_item *dir_list,
		struct vdfs4_cattree_record *cat_rec)
{
	/* make folders list */
	char *name = NULL;
	int ret = 0, ret_records = 0;
	u8 rec_type;
	struct dir_list_item *new = NULL;
	do {
		rec_type = cat_rec->key->record_type;
		if (rec_type == VDFS4_CATALOG_FOLDER_RECORD) {
			name = malloc(cat_rec->key->name_len);
			if (!name) {
				ret = -ENOMEM;
				goto exit;
			}
			memcpy(name, cat_rec->key->name,
					cat_rec->key->name_len);
			new = malloc(sizeof(struct dir_list_item));
			if (!new) {
				free(name);
				ret = -ENOMEM;
				goto exit;
			}
			list_item_init(new,
					cat_rec->key->object_id,
					cat_rec->key->parent_id, name,
					cat_rec->key->name_len);

			list_insert(dir_list, new);
		}
		ret_records = vdfs4_cattree_get_next_record(cat_rec);
		if (ret_records == -ERDFAIL) {
			log_error("Catalog record read failed");
			list_free(dir_list);
			return ret_records;
		}
	} while (ret_records == 0);

	if (ret_records == -ENOENT)
		ret_records = 0;
	else {
		ret = ret_records;
		goto exit;
	}
exit:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) cat_rec);
	return ret;
}

int64_t get_file_block_num_in_image(struct vdfs4_sb_info *sbi, u64 object_id,
		struct vdfs4_catalog_file_record *rec, u_int64_t iblock)
{
	int i = 0, ret = 0;
	struct vdfs4_iextent *ext = NULL;
	struct vdfs4_exttree_record *ext_rec;
	if (iblock > rec->data_fork.total_blocks_count)
		return -EINVAL;
	for (i = 0; i < VDFS4_EXTENTS_COUNT_IN_FORK; i++) {
		ext = &rec->data_fork.extents[i];
		if (ext->iblock + ext->extent.length > iblock)
			return ext->extent.begin + iblock - ext->iblock;
	}
	ext_rec = vdfs4_exttree_find_first_record(sbi, object_id,
			VDFS4_BNODE_MODE_RO);
	if (IS_ERR(ext_rec))
		return PTR_ERR(ext_rec);
	while (!(IS_ERR(ext_rec)) &&
			(ext_rec->key->object_id == object_id)) {
		if (ext_rec->key->iblock + ext_rec->lextent->length > iblock) {
			ret = ext_rec->lextent->begin + iblock
					- ext_rec->key->iblock;
			break;
		}
		ret = vdfs4_exttree_get_next_record(ext_rec);
		if (ret)
			break;
	}
	vdfs4_release_record((struct vdfs4_btree_gen_record *)ext_rec);
	return ret;
}

/**
 * @brief	Init superblock runtime structures
 * @param[out]	sbi	Pointer to the superblock runtime structure
 * @return	0 on success, error code otherwise
 */
int init_sb_info(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	void *first_block = malloc(BLOCK_SIZE_DEFAULT);
	struct vdfs4_super_block *sb;
	__le32 checksum;
#ifdef GIT_BRANCH
	log_info("git branch: %s", GIT_BRANCH);
#endif
#ifdef GIT_HASH
	log_info("git hash: %s", GIT_HASH);
#endif
	if (!first_block)
		return -ENOMEM;

	log_info("Reading superblocks");

	sbi->block_size = BLOCK_SIZE_DEFAULT;
	ret = vdfs4_read_blocks(sbi, 0, first_block, 1);
	if (ret < 0) {
		log_error("Can't read block with first superblock");
		free(first_block);
		return ret;
	}

	if (sbi->root_path == NULL)
		sbi->root_path = DEFAULT_ROOT_PATH;

	sb = (struct vdfs4_super_block *)
		(first_block + 2 * sizeof(struct vdfs4_super_block));

	/* check magic number */
	if (memcmp(sb->signature, VDFS4_SB_SIGNATURE,
			strlen(VDFS4_SB_SIGNATURE))) {
		log_error("Wrong superblock magic");
		free(first_block);
		return -EINVAL;
	}

	if (memcmp(sb->layout_version, VDFS4_LAYOUT_VERSION,
			strlen(VDFS4_LAYOUT_VERSION))) {
		if (atoi((const char *)sb->layout_version) > 0)
			VDFS4_ERR("Invalid mkfs layout version: %.4s\n"
			"git branch - %s\ngit hash - %s\n"
			"unpack uses %.4s version\n",
			sb->layout_version,
			sb->mkfs_git_branch, sb->mkfs_git_hash,
			VDFS4_LAYOUT_VERSION);
		else
			VDFS4_ERR("Old mkfs layout\n"
				"git branch - %s\ngit hash - %s\n"
				"unpack uses %.4s version\n",
				((struct old_vdfs4_super_block *)
						sb)->mkfs_git_branch,
				((struct old_vdfs4_super_block *)
						sb)->mkfs_git_hash,
				VDFS4_LAYOUT_VERSION);
		free(first_block);
		return -EINVAL;
	}
	/* check crc32 */
	checksum = vdfs4_crc32(sb, sizeof(*sb) - sizeof(sb->checksum));
	if (sb->checksum != checksum) {
		log_error("Wrong superblock checksum");
		free(first_block);
		return -EINVAL;
	}
	if (sb->read_only && (IS_FLAG_SET(sbi->service_flags, NO_DECODE))) {
		log_error("Can't unpack read-only image without decoding."
				" Don't use --no-decode");
		ret = -EINVAL;
		goto exit;
	}
	struct vdfs4_extended_super_block *esb =
		(struct vdfs4_extended_super_block *)
		(first_block + 3 * sizeof(struct vdfs4_super_block));

	memcpy(&sbi->sb, sb, sizeof(struct vdfs4_super_block));
	memcpy(&sbi->esb, esb, sizeof(struct vdfs4_extended_super_block));
	sbi->block_size = 1 << sb->log_block_size;
	sbi->log_blocks_in_leb = sbi->sb.log_super_page_size
			- sbi->sb.log_block_size;
exit:
	free(first_block);
	return ret;
}

/**
 * @brief	Fill universal btree structure fields
 * @param[in]	sbi	Pointer to the superblock runtime structure
 * @param[out]	btree	Pointer to the btree structure to fill
 * @param[in]	esb_fork	Pointer to the fork structure of extended
 *			superblock on disk
 * @param[out]	btree_fork	Pointer to the fork structure of runtime
 *			btree to fill with data from esb_fork
 * @return	0 on success, error code otherwise
 */
int fill_btree(struct vdfs4_sb_info *sbi, struct vdfs4_btree *btree)
{
	int ret = 0;
	struct vdfs4_raw_btree_head *raw_btree_head;
	btree->sbi = sbi;
	btree->node_size_bytes = (1 << sbi->log_blocks_in_leb) *
		sbi->block_size;
	btree->head_bnode = __vdfs4_get_bnode(btree, 0, VDFS4_BNODE_MODE_RO);

	if (IS_ERR(btree->head_bnode)) {
		log_error("Can't get head bnode");
		return -EINVAL;
	}

	raw_btree_head = btree->head_bnode->data;
	if (memcmp(raw_btree_head->magic, VDFS4_BTREE_HEAD_NODE_MAGIC,
		sizeof(VDFS4_BTREE_HEAD_NODE_MAGIC) - 1)) {
		log_error("Wrong head bnode magic %s",
			raw_btree_head->magic);
		return -EINVAL;
	}

	return ret;
}

void free_btree(struct vdfs4_btree *btree)
{
	free(btree->head_bnode->data);
	free(btree->head_bnode);
}

/**
 * @brief	Fill catalog tree runtime structure
 * @param[in]	sbi	Pointer to the superblock runtime structure
 * @param[out]	cat_tree	Pointer to the catalog tree runtime structure
 * @return	0 on success, error code otherwise
 */
int fill_cat_tree(struct vdfs4_sb_info *sbi, struct vdfs4_btree *cat_tree)
{
	int ret = 0;

	log_info("Filling catalog tree");

	cat_tree->btree_type = VDFS4_BTREE_CATALOG;
	cat_tree->max_record_len = VDFS4_CAT_KEY_MAX_LEN +
		sizeof(struct vdfs4_catalog_file_record);

	ret = fill_btree(sbi, cat_tree);

	cat_tree->comp_fn = vdfs4_cattree_cmpfn;
	sbi->catalog_tree = cat_tree;
	return ret;
}

/**
 * @brief	Fill extents tree runtime structure
 * @param[in]	sbi	Pointer to the superblock runtime structure
 * @param[out]	ext_tree	Pointer to the extents tree runtime structure
 * @return	0 on success, error code otherwise
 */
int fill_ext_tree(struct vdfs4_sb_info *sbi, struct vdfs4_btree *ext_tree)
{
	int ret = 0;

	log_info("Filling extents tree");

	ext_tree->btree_type = VDFS4_BTREE_EXTENTS;
	ext_tree->max_record_len = sizeof(struct vdfs4_exttree_key) +
		sizeof(struct vdfs4_exttree_record);

	ret = fill_btree(sbi, ext_tree);

	ext_tree->comp_fn = vdfs4_exttree_cmpfn;
	sbi->extents_tree = ext_tree;
	return ret;
}

/**
 * @brief	Fill xattrs tree runtime structure
 * @param[in]	sbi	Pointer to the superblock runtime structure
 * @param[out]	xattr_tree	Pointer to the xattr tree runtime structure
 * @return	0 on success, error code otherwise
 */
int fill_xattr_tree(struct vdfs4_sb_info *sbi, struct vdfs4_btree *xattr_tree)
{
	int ret = 0;

	log_info("Filling extended attributes tree");

	xattr_tree->btree_type = VDFS4_BTREE_XATTRS;
	xattr_tree->max_record_len = VDFS4_XATTR_KEY_MAX_LEN +
		VDFS4_XATTR_VAL_MAX_LEN;

	ret = fill_btree(sbi, xattr_tree);

	xattr_tree->comp_fn = vdfs4_xattrtree_cmpfn;
	sbi->xattr_tree = xattr_tree;
	return ret;
}
/**
 * @brief	Set object attributes
 * @param[in]	name	String with full path to object
 * @param[in]	permissions Pointer to the structure with permissions of
			original object
 * @return	0 on success, error code otherwise
 */
int set_attributes(char *name, struct vdfs4_catalog_folder_record *cat_rec)
{
	int ret = 0;
	struct timeval times[2];
	int fd;
	struct stat stat_info;
	ret = lstat(name, &stat_info);
	if (ret) {
		log_error("Can't get stat info for %s because of %s", name,
				strerror(errno));
		return ret;
	}
	/* prepare file last access and modification time */
	times[0].tv_sec = cat_rec->creation_time.seconds;
	times[0].tv_usec = cat_rec->creation_time.nanoseconds / 1000;
	times[1].tv_sec = cat_rec->modification_time.seconds;
	times[1].tv_usec = cat_rec->modification_time.nanoseconds / 1000;
	if (S_ISLNK(stat_info.st_mode))
		goto set_permissions;
	/*Can not open not existing devices so don't open special files*/
	else if (S_ISCHR(stat_info.st_mode) || S_ISBLK(stat_info.st_mode) ||
			S_ISFIFO(stat_info.st_mode) ||
			S_ISSOCK(stat_info.st_mode))
		goto set_permissions;
	else if (S_ISDIR(stat_info.st_mode)) {
		DIR *dir =  opendir(name);
		if (dir == NULL) {
			ret = errno;
			log_info("%s %s", "Can't open dir", name);
			return ret;
		}
		fd = dirfd (dir);
		if (fd < 0) {
			ret = errno;
			closedir(dir);
			log_error("failed to get dir fd");
			return ret;
		}
		ret = futimes(fd, times);
		closedir(dir);

	} else {
		fd = open(name, O_RDWR, (mode_t)0666);
		if (fd < 0) {
			log_error("Failed to open %s because of %s",
						name, strerror(errno));
			return errno;
		}
		ret = futimes(fd, times);
		close(fd);
	}

	if (ret < 0) {
		ret = errno;
		log_error("Failed to set time on %s because of %s",
			name, strerror(errno));
		return ret;
	}

set_permissions:
	if (geteuid() == 0) {
		ret = lchown(name, cat_rec->uid, cat_rec->gid);
		if (ret)
			log_error("Failed to change uid and gid on %s because"
					" of %s", name, strerror(errno));
		if (!S_ISLNK(stat_info.st_mode)) {
			ret = chmod(name, cat_rec->file_mode);
			if (ret)
				log_error("Failed to change file mode for %s"
					" because of %s", name,
					strerror(errno));
		}
	}

	return ret;
}
/**
 * @brief	Recursive mkdir
 * @param[in]	dir	full path to dir to create
 * @param[in]	file_mode folder mode
 * @return	0 on success, error code otherwise
 */
static int _mkdir(const char *dir, mode_t file_mode)
{
	char *tmp = malloc(strlen(dir) + 1);
	char *p = NULL;
	size_t len;
	len = strlen(dir);
	snprintf(tmp, len, "%s", dir);

	if (tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for (p = tmp + 1; *p; p++)
		if (*p == '/') {
			*p = 0;
			mkdir(tmp, file_mode);
			*p = '/';
		}
	free(tmp);
	return mkdir(dir, file_mode);
}
/**
 * @brief	Creates a folder at requested path
 * @param[in]	name	A string with folder path
 * @param[in]	cat_rec	A pointer to the catalog record of folder to get
 *			folder mode
 * @return	0 on success, error code otherwise
 */
int create_folder(char *name, struct vdfs4_cattree_record *cat_rec)
{
	log_activity("Create directory: %s", name);
	return _mkdir(name, (mode_t) ((struct vdfs4_catalog_folder_record *)
			(cat_rec->val))->file_mode);
}

int get_data_from_file(struct vdfs4_sb_info *sbi, u64 obj_id,
		struct vdfs4_catalog_file_record *file_rec, char *buf,
		int offset, int bytes_count)
{
	int curr_offset = 0, img_block, read_size = 0;
	int ret = 0;
	while (curr_offset < bytes_count) {
		img_block = get_file_block_num_in_image(sbi, obj_id, file_rec,
				offset / sbi->block_size);
		if (img_block < 0) {
			log_error("Can't find iblock %d",
					offset / sbi->block_size);
			return img_block;
		}
		lseek(sbi->disk_op_image.file_id, (offset % sbi->block_size)
				+ img_block * sbi->block_size, SEEK_SET);
		read_size = sbi->block_size - (offset % sbi->block_size);
		if (curr_offset + read_size > bytes_count)
			read_size = bytes_count - curr_offset;
		ret = read(sbi->disk_op_image.file_id, buf + curr_offset,
				read_size);
		if (ret != read_size) {
			log_error("Read file error - %s", strerror(errno));
			return errno;
		}
		ret = 0;
		curr_offset += read_size;
		offset += read_size;
	}
	return ret;
}

int read_compression_info_from_image(struct vdfs4_sb_info *sbi, u64 obj_id,
		struct vdfs4_comp_file_descr *descr,
		struct vdfs4_comp_extent **ext, int *compress_type,
		struct vdfs4_catalog_file_record *file_rec) {
	int ret = 0;

	loff_t ext_pos;
	int ext_n;
	ret = get_data_from_file(sbi, obj_id, file_rec, (char *)descr,
			file_rec->data_fork.size_in_bytes
			- sizeof(struct vdfs4_comp_file_descr),
			sizeof(struct vdfs4_comp_file_descr));
	if (ret)
		return ret;

	if (!memcmp(descr->magic, VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC,
			sizeof(descr->magic)))
		*compress_type = VDFS4_COMPR_ZLIB;
	else if (!memcmp(descr->magic, VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC,
			sizeof(descr->magic)))
		*compress_type = VDFS4_COMPR_GZIP;
	else if (!memcmp(descr->magic, VDFS4_COMPR_LZO_FILE_DESCR_MAGIC,
			sizeof(descr->magic)))
		*compress_type = VDFS4_COMPR_LZO;
	else{
		log_error("Invalid magic for compressed file %s", descr->magic);
		return -EINVAL;
	}

	ext_n = descr->extents_num;
	ext_pos = file_rec->data_fork.size_in_bytes - sizeof(*descr) -
		ext_n * sizeof(struct vdfs4_comp_extent);
	*ext = realloc(*ext, ext_n * sizeof(struct vdfs4_comp_extent));
	if (!*ext)
		return -ENOMEM;
	ret = get_data_from_file(sbi, obj_id, file_rec, (char *)*ext, ext_pos,
			ext_n * sizeof(struct vdfs4_comp_extent));
	if (ret)
		log_error("Error when read data from file");
	return ret;
}

/**
 * @brief	Creates a file at requested path
 * @param[in]	sbi	Pointer to the superblock runtime structure
 * @param[in]	name	A string with file path
 * @param[in]	cat_rec A pointer to the catalog record of file
 * @return	0 on success, error code otherwise
 */
int create_file(struct vdfs4_sb_info *sbi, u64 object_id, char *name,
		struct vdfs4_catalog_file_record *file_rec)
{
	char *block_buffer;
	int64_t offset = 0;
	u_int64_t iblock = 0;
	u_int64_t write_size;
	u_int64_t size_in_bytes;
	int fd;
	ssize_t ret_write = 0;
	int ret = 0;

	log_activity("Create file: %s", name);

	fd = creat(name, (mode_t) file_rec->common.file_mode);
	if (fd == -1) {
		log_error("Can't create file %s - %s", name, strerror(errno));
		return -ENFILE;
	}

	block_buffer = malloc(sbi->block_size);
	if (block_buffer == NULL) {
		log_error("Can't allocate buffer to read file");
		close(fd);
		return -ENOMEM;
	}

	size_in_bytes = file_rec->data_fork.size_in_bytes;
	/* check every extent for file until we write last part */
	while (size_in_bytes != 0) {
		offset = get_file_block_num_in_image(sbi, object_id, file_rec,
				iblock);
		if (offset < 0) {
			ret = offset;
			goto exit;
		}
		write_size = 1;
		ret = vdfs4_read_blocks(sbi, offset, block_buffer, 1);
		if (ret < 0) {
			log_error("Failed to read");
			goto exit;
		}

		/* convert write size from blocks to bytes.
		* if write block is last, use exact size in bytes */
		write_size *= sbi->block_size;
		if (write_size > size_in_bytes)
			write_size = size_in_bytes;

		ret_write = write(fd, block_buffer, write_size);
		if (ret_write == -1) {
			log_error("Write failed");
			ret = -EWRFAIL;
			goto exit;
		}

		size_in_bytes -= write_size;
		iblock++;
	}
exit:
	free(block_buffer);
	close(fd);
	return ret;
}

int create_decompress_file(struct vdfs4_sb_info *sbi, char *name,
		u64 obj_id, struct vdfs4_catalog_file_record *file_rec)
{
	char gathered_name[VDFS4_FILE_NAME_LEN];
	int tmp_fd, dst_fd;
	int ret, flags = 0;
	pid_t pid = getpid();
	if (IS_FLAG_SET(sbi->service_flags, NO_DECODE)) {
		ret = create_file(sbi, obj_id, name, file_rec);
		if (ret)
			log_error("can not create file");
		return ret;
	}
	memset(gathered_name, 0, VDFS4_FILE_NAME_LEN);
	snprintf(gathered_name, VDFS4_FILE_NAME_LEN, "/tmp/compr_%lu",
			(long unsigned)pid);
	ret = create_file(sbi, obj_id, gathered_name, file_rec);
	if (ret) {
		log_error("can not create file");
		goto unlink_tmp;
	}

	tmp_fd = open(gathered_name, O_RDONLY);
	if (tmp_fd == -1) {
		ret = errno;
		perror("can not open file");
		goto unlink_tmp;
	}

	dst_fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (dst_fd == -1) {
		ret = errno;
		perror("cannot open file");
		goto close_tmp;
	}

	ret = decode_file(gathered_name, dst_fd,
			file_rec->common.flags & (1 << VDFS4_COMPRESSED_FILE),
			&flags);
	file_rec->common.flags |= flags;

	close(dst_fd);
close_tmp:
	close(tmp_fd);
unlink_tmp:
	unlink(gathered_name);
	return ret;
}

/*
int create_tiny_file(char *name, struct vdfs4_catalog_file_record *file_rec)
{
	char *block_buffer;
	u_int64_t size_in_bytes;
	int fd;
	ssize_t ret = 0;
	log_activity("Create tiny file: %s", name);
	size_in_bytes = file_rec->tiny.len;
	block_buffer = malloc(size_in_bytes + 1);
	if (block_buffer == NULL) {
		log_error("Can't allocate buffer to read file");
		ret = -ENOMEM;
		return ret;
	}
	memset(block_buffer, 0, size_in_bytes + 1);
	memcpy(block_buffer, file_rec->tiny.data, size_in_bytes);
	if (S_ISLNK(file_rec->common.file_mode)) {
		ret = symlink(block_buffer, name);
		block_buffer[size_in_bytes] = '\0';
		if (ret)
			log_error("Can't create symlink\n");
		free(block_buffer);
		return ret;
	} else {
		fd = creat(name,
				(mode_t)file_rec->common.file_mode);
		if (fd == -1) {
			log_error("Can't create tiny file %s - %s", name,
					strerror(errno));
			free(block_buffer);
			return -ENFILE;
		}

		ret = write(fd, block_buffer, size_in_bytes);
	}
	if (ret == -1) {
		log_error("Write failed; name -%s; error - %s", name,
				strerror(errno));
		ret = -EWRFAIL;
		goto exit;
	} else
		ret = 0;
exit:
	free(block_buffer);
	close(fd);
	return ret;
}
*/

static int process_dlink_unpack(struct vdfs4_sb_info *sbi,
		struct vdfs4_catalog_dlink_record *dlink_value,
		const char *name);

/**
 * @brief	Creates hardlink at requested path
 * @param[in]	name	String with full path
 * @param[in]	cat_rec	Pointer to the catalog record structure
 * @return	0 on success, error code otherwise
 */
int create_hlink(struct vdfs4_sb_info *sbi, char *name, __u64 obj_id)
{
	int ret = 0;
	struct vdfs4_catalog_file_record *file_rec;
	struct vdfs4_cattree_record *record;
	record = vdfs4_cattree_find(&sbi->cattree.vdfs4_btree,
			obj_id, NULL, 0, VDFS4_BNODE_MODE_RW);
	if (IS_ERR(record))
		return ret;
	log_activity("Create hlink: %s", name);
	file_rec = record->val;
	if (record->key->record_type == VDFS4_CATALOG_DLINK_RECORD) {
		if (sbi->squash_list_file)
			fprintf(sbi->squash_list_file, "dlink_hlink"
				"\t%s\n", name);
		ret = process_dlink_unpack(sbi, record->val, name);
	} else if (file_rec->common.flags & (1 << VDFS4_COMPRESSED_FILE)) {
		if (sbi->squash_list_file) {
			if (file_rec->common.flags &
				(1 << VDFS4_COMPRESSED_FILE))
				fprintf(sbi->squash_list_file,
					"compressed_hlink\t%s\n", name);
			else
				return -EINVAL;
		}
		ret = create_decompress_file(sbi,
				name, obj_id, file_rec);
		goto exit;
	} /* else if (file_rec->common.flags & (1 << TINY_FILE)) {
		ret = create_tiny_file(name, file_rec);
		goto exit;
	} */ else if (S_ISLNK(file_rec->common.file_mode)) {
		if (sbi->squash_list_file)
			fprintf(sbi->squash_list_file, "symlink_hlink"
				"\t%s\n", name);
		ret = create_symlink(sbi, name, file_rec);
		goto exit;
	} else {
		if (sbi->squash_list_file)
			fprintf(sbi->squash_list_file, "hlink"
				"\t%s\n", name);
		ret = create_file(sbi, obj_id, name, file_rec);
		goto exit;
	}
exit:
	if (ret)
		return ret;
	ret = set_attributes(name,
			(struct vdfs4_catalog_folder_record *)file_rec);
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	return ret;
}

/**
 * @brief	Creates simlink at requested path
 * @param[in]	sbi	Pointer to the superblock runtime structure
 * @param[in]	name	String with full path
 * @param[in]	cat_rec	Pointer to the catalog record structure
 * @return	0 on success, error code otherwise
 */
int create_symlink(struct vdfs4_sb_info *sbi, char *name,
		struct vdfs4_catalog_file_record *file_rec)
{
	struct vdfs4_iextent *iextent;
	u_int64_t length;
	u_int64_t offset;
	char *block_buffer;
	int ret = 0;

	log_activity("Create symlink: %s", name);
	iextent = &file_rec->data_fork.extents[0];
	length = iextent->extent.length;
	offset = iextent->extent.begin;

	block_buffer = malloc(length * sbi->block_size);
	if (block_buffer == NULL) {
		log_error("Can't allocate buffer to read symlink");
		return -ENOMEM;
	}

	ret = vdfs4_read_blocks(sbi, offset, block_buffer, length);
	if (ret < 0) {
		log_error("Failed to read symlink %s - %s", name,
				strerror(errno));
		free(block_buffer);
		return ret;
	}

	/* add null symbol at the end of symlink target path string */
	block_buffer[file_rec->data_fork.size_in_bytes] = '\0';

	ret = symlink(block_buffer, name);
	if (ret) {
		log_error("Failed to create symlink %s - %s", name,
				strerror(errno));
		ret = -EINVAL;
	}
	free(block_buffer);

	return ret;
}

/**
 * @brief	Creates special file at requested path
 * @param[in]	name	String with full path
 * @param[in]	cat_rec	Pointer to the catalog record structure
 * @return	0 on success, error code otherwise
 */
int create_spec_file(char *name, struct vdfs4_cattree_record *cat_rec)
{
	__le64 dev_kernel = VDFS4_CATTREE_FOLDVAL(cat_rec)->total_items_count;

	int minor = dev_kernel & 0xfffff;
	int major = dev_kernel >> 20;
	dev_t dev = makedev(major, minor);
	if (geteuid() != 0) {
		log_warning("You must be root to create special file %s", name);
		return -EPERM;
	}
	/*TODO: set major/minor numbers to dev */
	log_info("Create spec file: %s", name);
	return mknod(name, (mode_t) ((struct vdfs4_catalog_folder_record *)
			(cat_rec->val))->file_mode, dev);
}



int unpack_hlinks(struct vdfs4_sb_info *sbi)
{
	struct hlink_list_item *list = sbi->hlinks_list.next;
	u64 obj_id = 0;
	char *name = NULL;
	int ret = 0;

	while (list != NULL) {
		if (list->ino_n < VDFS4_1ST_FILE_INO) {
			log_error("Invalid obj id\n");
			goto exit;
		}
		if (list->ino_n != obj_id) {
			ret = create_hlink(sbi, list->name, list->ino_n);
			name = list->name;
			obj_id = list->ino_n;
			ret = unpack_xattr(&sbi->xattrtree.vdfs4_btree,
					list->name, list->ino_n);
		} else {
			log_activity("Create link %s to %s", list->name, name);
			ret = link(name, list->name);
			if (sbi->squash_list_file)
				fprintf(sbi->squash_list_file,
						"hlink\t%s\tto\t%s\n",
						list->name,
						name);
		}
		if (ret)
			goto exit;
		if (list->next == NULL) {
			ret = 0;
			goto exit;
		}
		list = list->next;
	}
exit:
	if (ret)
		log_error("Failed to create hlink %s", list->name);
	return ret;
}

static int unpack_dlink_file(struct vdfs4_sb_info *sbi, u64 par_inode,
		struct vdfs4_dlink_info *dl_inf, int *resulting_fd)
{
	int fd;
	struct vdfs4_cattree_record *cat_rec;
	struct vdfs4_catalog_file_record *file_rec;
	int ret = 0;
	int compressed = 0;
	char *dlink_name = NULL;

	cat_rec = vdfs4_cattree_get_first_child(&sbi->cattree.vdfs4_btree,
					par_inode);
	if (IS_ERR(cat_rec))
		return PTR_ERR(cat_rec);

	file_rec = (struct vdfs4_catalog_file_record *)cat_rec->val;
	compressed = file_rec->common.flags & (1 << VDFS4_COMPRESSED_FILE);

	if (compressed) {
		if (par_inode == dl_inf->dlink_inode_comp) {
			*resulting_fd = dl_inf->dlink_file_comp_fd;
		} else if (par_inode == dl_inf->dlink_inode_auth) {
			*resulting_fd = dl_inf->dlink_file_auth;
		} else if (par_inode == dl_inf->dlink_inode_ro_auth) {
			*resulting_fd = dl_inf->dlink_file_ro_auth;
		} else if (par_inode == dl_inf->dlink_signed) {
			*resulting_fd = dl_inf->dlink_file_signed;
		} else {
			pid_t pid = getpid();
			dlink_name = malloc(VDFS4_FILE_NAME_LEN);
			if (!dlink_name){
				ret = -ENOMEM;
				goto rel_file_rec;
			}
			memset(dlink_name, 0, VDFS4_FILE_NAME_LEN);
			snprintf(dlink_name,
					VDFS4_FILE_NAME_LEN,
					"/tmp/dl_%d_%lu", dl_inf->dlink_count,
					(long unsigned)pid);
			dl_inf->dlink_count++;
			ret = create_decompress_file(sbi,
					dlink_name, par_inode, file_rec);

			if (ret) {
				free(dlink_name);
				goto rel_file_rec;
			}
			fd = open(dlink_name, O_RDONLY);
			if (fd == -1) {
				free(dlink_name);
				return errno;
			}
			if (file_rec->common.flags &
					(1 << SIGNED_DLINK)) {
				dl_inf->dlink_signed = par_inode;
				dl_inf->dlink_file_signed = fd;
				dl_inf->dl_name_signed = dlink_name;
			} else if (file_rec->common.flags &
					(1 << VDFS4_READ_ONLY_AUTH)) {
				dl_inf->dlink_inode_ro_auth = par_inode;
				dl_inf->dlink_file_ro_auth = fd;
				dl_inf->dl_name_ro_auth = dlink_name;
			} else if (file_rec->common.flags &
					(1 << VDFS4_AUTH_FILE)) {
				dl_inf->dlink_inode_auth = par_inode;
				dl_inf->dlink_file_auth = fd;
				dl_inf->dl_name_auth = dlink_name;
			} else {
				dl_inf->dlink_inode_comp = par_inode;
				dl_inf->dlink_file_comp_fd = fd;
				dl_inf->dl_name_comp = dlink_name;
			}
			*resulting_fd = fd;
		}
	} else {
		if (dl_inf->dlink_file_fd == -1) {
			pid_t pid = getpid();
			dlink_name = malloc(VDFS4_FILE_NAME_LEN);
			if (!dlink_name){
				ret = -ENOMEM;
				goto rel_file_rec;
			}
			memset(dlink_name, 0, VDFS4_FILE_NAME_LEN);
			snprintf(dlink_name,
					VDFS4_FILE_NAME_LEN,
					"/tmp/dl_%d_%lu", dl_inf->dlink_count,
					(long unsigned)pid);
			dl_inf->dlink_count++;
			dl_inf->dl_name = dlink_name;

			ret = create_file(sbi, par_inode, dlink_name, file_rec);
			if (ret)
				goto rel_file_rec;

			fd = open(dlink_name, O_RDONLY);
			if (fd == -1)
				return errno;
			dl_inf->dlink_file_fd = fd;

		}
		*resulting_fd = dl_inf->dlink_file_fd;
	}

rel_file_rec:
	vdfs4_release_record((struct vdfs4_btree_gen_record *)cat_rec);
	return ret;
}

static int process_dlink_unpack(struct vdfs4_sb_info *sbi,
		struct vdfs4_catalog_dlink_record *dlink_value,
		const char *name)
{
	int ret = 0;
	int actual_fd, out_fd;
	u64 par_inode = dlink_value->data_inode;
	off_t dl_offset = le64_to_cpu(dlink_value->data_offset);
	struct vdfs4_dlink_info *dl_inf = &sbi->dl_inf;
	ssize_t sz, dl_size = le64_to_cpu(dlink_value->data_length);
	char *data;

	ret = unpack_dlink_file(sbi, par_inode, dl_inf, &actual_fd);
	if (ret) {
		if (ret < 0)
			ret = -ret;
		log_error("Can't unpack file %s:%s", name, strerror(ret));
	}

	data = malloc(dl_size + 1);
	lseek(actual_fd, dl_offset, SEEK_SET);
	sz = read(actual_fd, data, dl_size);
	if (sz != dl_size) {
		if (sz < 0)
			ret = errno;
		else
			ret = ENODATA;
		log_error("Unpack:Can't read from temp file:%s",
				strerror(ret));
		goto exit;
	}

	if (S_ISLNK(le16_to_cpu(dlink_value->common.file_mode))) {
		data[dl_size] = 0;
		ret = symlink(data, name);
		if (ret) {
			ret = errno;
			log_error("Failed to create symlink %s - %s", name,
					strerror(ret));
			goto exit;
		}
	} else {
		out_fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (out_fd == -1) {
			log_error("Unpack:Can't open target file %s:%s",
					name, strerror(errno));
			ret = -ENOENT;
			goto exit;
		}
		sz = write(out_fd, data, sz);
		if (sz != dl_size) {
			if (sz < 0)
				ret = errno;
			else
				ret = ENODATA;
			log_error("Unpack:Error in filling target file %s:s",
					name, strerror(ret));
			close(out_fd);
			goto exit;
		}
		fchmod(out_fd, dlink_value->common.file_mode);
		close(out_fd);
	}

exit:
	if (ret)
		close(actual_fd);
	free(data);
	return ret;
}

int make_path_from_dir_list(struct dir_list_item *head, __le64 obj_id,
		char **path, int name_len)
{
	struct dir_list_item *list = head;
	struct dir_list_item *cur_obj;
	int cur_len = name_len + 1;
	__le64 cur_obj_id = obj_id;
	while (cur_obj_id != 0) {
		cur_obj = list_get(list, cur_obj_id);
		if (!cur_obj)
			return -ENOENT;
		*path = realloc(*path, cur_obj->name_len + cur_len + 1);
		if (!*path)
			return -ENOMEM;
		memmove((*path + cur_obj->name_len + 1), *path, cur_len);
		memcpy(*path, cur_obj->name, cur_obj->name_len);
		memcpy(*path + cur_obj->name_len, "/", 1);
		cur_len += cur_obj->name_len + 1;
		cur_obj_id = cur_obj->parent_id;
	}
	memset(*path + cur_len - 1, 0, 1);
	return 0;
}

int create_all_folders(struct dir_list_item *dir_list,
		struct vdfs4_cattree_record *cat_rec,
		struct vdfs4_btree *xattr_tree)
{
	/* make folders list */
	char *path = NULL;
	int ret = 0, ret_records = 0;
	u8 rec_type;
	do {
		rec_type = cat_rec->key->record_type;
		if (rec_type == VDFS4_CATALOG_FOLDER_RECORD) {
			path = malloc(cat_rec->key->name_len);
			if (!path) {
				ret = -ENOMEM;
				goto exit;
			}

			memcpy(path, cat_rec->key->name,
					cat_rec->key->name_len);
			ret = make_path_from_dir_list(dir_list,
					cat_rec->key->parent_id, &path,
					cat_rec->key->name_len);
			if (ret) {
				log_error("Can't build path to object %s - %s",
						cat_rec->key->name,
						strerror(-ret));
				free(path);
				goto exit;
			}
			ret = create_folder(path, cat_rec);
			if (ret && errno != EEXIST) {
				log_error("Failed to create folder %s,"
						" because of %s", path,
						strerror(errno));
				free(path);
				goto exit;
			}
			ret = 0;
			ret = set_attributes(path,
					VDFS4_CATTREE_FOLDVAL(cat_rec));
			if ((!ret) && (!(S_ISLNK(VDFS4_CATTREE_FOLDVAL(cat_rec)->
					file_mode))))
				ret = unpack_xattr(xattr_tree, path,
					cat_rec->key->object_id);
			free(path);
		}
		ret_records = vdfs4_cattree_get_next_record(cat_rec);
		if (ret_records == -ERDFAIL) {
			log_error("Catalog record read failed");
			list_free(dir_list);
			return ret_records;
		}
	} while (ret_records == 0);
	if (ret_records == -ENOENT)
		ret_records = 0;
	else {
		ret = ret_records;
		goto exit;
	}
exit:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) cat_rec);
	return ret;
}

/**
 * @brief	Unpack files from disk or image to folder
 * @param[in]	sbi	Pointer to the superblock runtime structure
 * @param[in]	cat_tree	Pointer to the catalog tree runtime structure
 * @param[in]	ext_tree	Pointer to the extents tree runtime structure
 * @return	0 on success, error code otherwise
 */
int unpack_files(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_cattree_record *cat_rec;
	struct dir_list_item *dir_list;
	struct packtree_point_value_array ptree_val_info;
	struct stat s;
	int ret = 0;
	int ret_records;
	int rec_type;
	struct hlink_list_item *hl_list = &sbi->hlinks_list;
	struct hlink_list_item *list_item;
	char *name = NULL;
	memset(&ptree_val_info, 0,
			sizeof(struct packtree_point_value_array));
	cat_rec = vdfs4_cattree_get_first_child(&sbi->cattree.vdfs4_btree,
			VDFS4_ROOT_INO);

	sbi->dl_inf.dl_name = NULL;
	sbi->dl_inf.dl_name_comp = NULL;

	sbi->dl_inf.dlink_file_comp_fd = -1;
	sbi->dl_inf.dlink_file_fd = -1;

	if (IS_ERR(cat_rec)) {
		log_error("Empty volume, nothing to unpack");
		return -ENOENT;
	}

	dir_list = malloc(sizeof(struct dir_list_item));

	if (!dir_list)
		return -ENOMEM;
	/* plus 2 because of '/' and '\0' chars at the end */
	name = calloc(1, strlen(sbi->root_path) + 2);
	if (!name) {
		ret = -ENOMEM;
		goto exit;
	}
	strcpy(name, sbi->root_path);
	if (name[strlen(name) - 1] != '/')
		strncat(name, "/", 1);
	ret = list_item_init(dir_list, ROOT_OBJECT_ID, 0, name,
			strlen(sbi->root_path));
	if (ret)
		goto exit;
	name = NULL;
	/* check if root directory already exist, then delete it */
	log_activity("Create root directory %s", dir_list->name);
	ret = stat(dir_list->name, &s);
	if (!ret)
		if (S_ISDIR(s.st_mode)) {
			char temp[VDFS4_FULL_PATH_LEN + 1];
			temp[VDFS4_FULL_PATH_LEN] = 0;
			log_info("Root directory exists, deleting");
			snprintf(temp, VDFS4_FULL_PATH_LEN,
					"rm -rf %s", dir_list->name);
			ret = system(temp);
			if (ret) {
				log_error("Failed to clear root directory");
				goto exit;
			}
		}

	mkdir(dir_list->name, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	ret = make_folder_list(dir_list, cat_rec);
	if (ret)
		goto exit;

	cat_rec = vdfs4_cattree_get_first_child(&sbi->cattree.vdfs4_btree,
			VDFS4_ROOT_INO);

	ret = create_all_folders(dir_list, cat_rec, &sbi->xattrtree.vdfs4_btree);
	if (ret)
		goto exit;

	cat_rec = vdfs4_cattree_get_first_child(&sbi->cattree.vdfs4_btree,
			VDFS4_ROOT_INO);

	/* parse catalog tree */
	do {
		rec_type = le16_to_cpu(cat_rec->key->record_type);
		if ((rec_type == VDFS4_CATALOG_FOLDER_RECORD) ||
				(rec_type == VDFS4_CATALOG_ILINK_RECORD) ||
				(cat_rec->key->parent_id
						== cat_rec->key->object_id))
			goto next;
		name = malloc(cat_rec->key->name_len);
		if (!name) {
			ret = -ENOMEM;
			goto exit;
		}
		memcpy(name, cat_rec->key->name, cat_rec->key->name_len);
		ret = make_path_from_dir_list(dir_list, cat_rec->key->parent_id,
						&name,
						cat_rec->key->name_len);
		if (ret) {
			log_error("Can't build path to object %s - %s",
					name,
					strerror(-ret));
			goto exit;
		}

		switch (rec_type) {
		case VDFS4_CATALOG_HLINK_RECORD:
			list_item = malloc(sizeof(struct hlink_list_item));
			memset(list_item, 0, sizeof(struct hlink_list_item));
			hl_list_item_init(list_item, cat_rec->key->object_id,
					name, cat_rec->key->object_id);
			hl_list_insert(hl_list, list_item);
			ret = 1;
			break;
		case VDFS4_CATALOG_FILE_RECORD:
			if ((S_ISBLK(VDFS4_CATTREE_FOLDVAL(cat_rec)->
					file_mode)) ||
			(S_ISCHR(VDFS4_CATTREE_FOLDVAL(cat_rec)->
					file_mode)) ||
			(S_ISFIFO(VDFS4_CATTREE_FOLDVAL(cat_rec)->
					file_mode)) ||
			(S_ISSOCK(VDFS4_CATTREE_FOLDVAL(cat_rec)->
					file_mode))) {
				if (sbi->squash_list_file)
					fprintf(sbi->squash_list_file,
							"special\t%s\n", name);
				ret = create_spec_file(name, cat_rec);
				if (ret) {
					log_error("Failed to create special "
							"file %s", name);
					goto exit;
				}
			} else if (VDFS4_CATTREE_FOLDVAL(cat_rec)->flags &
					(1 << VDFS4_COMPRESSED_FILE)) {
				if (sbi->squash_list_file) {
					if (VDFS4_CATTREE_FOLDVAL(cat_rec)
						->flags &
						(1 << VDFS4_COMPRESSED_FILE))
						fprintf(sbi->squash_list_file,
							"compressed\t%s\n",
							name);
					else {
						ret = -EINVAL;
						goto exit;
					}
				}
				if (!IS_FLAG_SET(sbi->service_flags, NO_DECODE))
					ret = create_decompress_file(sbi,
							name,
						cat_rec->key->object_id,
						VDFS4_CATTREE_FILEVAL(cat_rec));
				else
					ret = create_file(sbi,
						cat_rec->key->object_id, name,
						VDFS4_CATTREE_FILEVAL(cat_rec));
			}
			/*else if (VDFS4_CATTREE_FOLDVAL(cat_rec)->flags &
					(1 << TINY_FILE))
				ret = create_tiny_file(name,
					(struct vdfs4_catalog_file_record *)
					(cat_rec->val)); */
			else if (S_ISLNK(VDFS4_CATTREE_FOLDVAL(cat_rec)->
					file_mode)) {
				if (sbi->squash_list_file)
					fprintf(sbi->squash_list_file,
							"symlink\t%s\n", name);
				ret = create_symlink(sbi, name,
						VDFS4_CATTREE_FILEVAL(cat_rec));
			} else {
				ret = create_file(sbi, cat_rec->key->object_id,
					name, VDFS4_CATTREE_FILEVAL(cat_rec));
				if (sbi->squash_list_file)
					fprintf(sbi->squash_list_file,
							"ordinary\t%s\n", name);
			}
			if (ret) {
				log_error("Failed to create file %s", name);
				goto exit;
			}
			break;
		case VDFS4_CATALOG_DLINK_RECORD:
			log_info("Unpack dlink %s", name);
			if (sbi->squash_list_file)
				fprintf(sbi->squash_list_file,
						"dlink\t%s\n", name);
			ret = process_dlink_unpack(sbi, cat_rec->val, name);
			break;
		};
		if (!ret)
			ret = set_attributes(name,
					VDFS4_CATTREE_FOLDVAL(cat_rec));
		if ((!ret) && (!(S_ISLNK(VDFS4_CATTREE_FOLDVAL(cat_rec)->
				file_mode))))
			ret = unpack_xattr(&sbi->xattrtree.vdfs4_btree, name,
					cat_rec->key->object_id);

		free(name);
		name = NULL;
next:
		ret_records = vdfs4_cattree_get_next_record(cat_rec);

		if (ret_records == -ERDFAIL) {
			log_error("Catalog record read failed");
			goto exit;
		}
	} while (ret_records != -ENOENT);

	ret = unpack_hlinks(sbi);
	hl_list_free(hl_list->next);
	if (ret)
		goto exit;
exit:
	if (sbi->dl_inf.dl_name_ro_auth) {
		close(sbi->dl_inf.dlink_file_ro_auth);
		unlink(sbi->dl_inf.dl_name_ro_auth);
		free(sbi->dl_inf.dl_name_ro_auth);
	}
	if (sbi->dl_inf.dl_name_auth) {
		close(sbi->dl_inf.dlink_file_auth);
		unlink(sbi->dl_inf.dl_name_auth);
		free(sbi->dl_inf.dl_name_auth);
	}
	if (sbi->dl_inf.dl_name) {
		close(sbi->dl_inf.dlink_file_fd);
		unlink(sbi->dl_inf.dl_name);
		free(sbi->dl_inf.dl_name);
	}
	if (sbi->dl_inf.dl_name_comp) {
		close(sbi->dl_inf.dlink_file_comp_fd);
		unlink(sbi->dl_inf.dl_name_comp);
		free(sbi->dl_inf.dl_name_comp);
	}
	list_free(dir_list);
	vdfs4_release_record((struct vdfs4_btree_gen_record *) cat_rec);
	free(name);
	free(ptree_val_info.val);
	return ret;
}

int fill_tables(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_extended_table *ext_t;
	struct vdfs4_base_table *base_t, *base_t_second;
	struct vdfs4_extended_record *record;
	u64 last_table_index;
	struct vdfs4_base_table_record *table;
	int ret = 0;
	u32 ext_count, rec_num;
	u32 records_count = 0;
	u64 base_ver = 0, ext_ver = 0, base_sec_ver, offset = 0;
	char *buf = malloc(le32_to_cpu(sbi->esb.tables.length) *
			sbi->block_size);
	int saved_crc, real_crc;
	if (!buf)
		return -ENOMEM;

	ret = vdfs4_read_blocks(sbi, le64_to_cpu(
			sbi->esb.tables.begin), buf + offset *
			sbi->block_size, le64_to_cpu(sbi->esb.tables.length));
	if (ret) {
		free(buf);
		return ret;
	}

	sbi->snapshot.snapshot_subsystem.buffer = buf;
	sbi->snapshot.snapshot_subsystem.buffer_size = sbi->esb.
			tables.length * sbi->block_size;
	base_t = (struct vdfs4_base_table *)
			sbi->snapshot.snapshot_subsystem.buffer;
	if (memcmp(base_t->descriptor.signature, VDFS4_SNAPSHOT_BASE_TABLE, 4)) {
		log_error("Can't find base table");
		free(buf);
		return ret;
	}
	saved_crc = *(int *)((void *)base_t +
			base_t->descriptor.checksum_offset);
	real_crc = vdfs4_crc32(base_t, base_t->descriptor.checksum_offset);
	if (saved_crc != real_crc) {
		log_error("Table crc mismatch");
		free(buf);
		return ret;
	}

	base_ver = ((u64)le32_to_cpu(base_t->descriptor.mount_count) << 32) |
			le32_to_cpu(base_t->descriptor.sync_count);
	base_t_second = (struct vdfs4_base_table *)
				(sbi->snapshot.snapshot_subsystem.buffer +
				(sbi->snapshot.snapshot_subsystem.buffer_size
						>> 1));
	if (!memcmp(base_t_second->descriptor.signature,
			VDFS4_SNAPSHOT_BASE_TABLE, 4)) {
		base_sec_ver = ((u64)le32_to_cpu(base_t_second->descriptor.
				mount_count) << 32) | le32_to_cpu(
				base_t_second->descriptor.sync_count);
		if (base_sec_ver > base_ver) {
			base_t = base_t_second;
			base_ver = base_sec_ver;
		}
	}
	sbi->snapshot.base_table = base_t;
	ext_t = (struct vdfs4_extended_table *)(
			(char *)base_t + (char)DIV_ROUND_UP(le32_to_cpu(
			base_t->descriptor.checksum_offset + CRC32_SIZE),
			512) * 512);
	for (ext_count = 0; ext_count < VDFS4_SNAPSHOT_EXT_TABLES; ext_count++) {
		if (memcmp(ext_t->descriptor.signature,
				VDFS4_SNAPSHOT_EXTENDED_TABLE, 4))
			break;
		ext_ver = ((u64)le32_to_cpu(ext_t->descriptor.mount_count)
				<< 32) | le32_to_cpu(
						ext_t->descriptor.sync_count);
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
				meta_iblock = record->meta_iblock;
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
				512) * 512);
	}

	return ret;
}
/**
 * @brief	Unpack main function
 * @param[in]	argc	Arguments count
 * @param[in]	argv	Array with arguments value strings
 * @return	0 on success, error code otherwise
 */
int main(int argc, char *argv[])
{
	int ret = 0;
	struct vdfs4_sb_info sbi;

	print_version();

	memset(&sbi, 0, sizeof(sbi));

	ret = parse_cmd(argc, argv, &sbi);
	if (ret)
		goto err_exit;

	ret = open_disk(&sbi);
	if (ret)
		goto err_exit;

	ret = init_sb_info(&sbi);
	if (ret)
		goto err_cache;
	ret = vdfs4_init_btree_caches();
	if (ret) {
		log_error("error btree caches init - ENOMEM");
		goto err_cache;
	}
	ret = fill_tables(&sbi);
	if (ret)
		goto err_tables;
	ret = fill_cat_tree(&sbi, &sbi.cattree.vdfs4_btree);
	if (ret)
		goto err_unpack;
	ret = fill_ext_tree(&sbi, &sbi.exttree.vdfs4_btree);
	if (ret)
		goto free_cattree;
	ret = fill_xattr_tree(&sbi, &sbi.xattrtree.vdfs4_btree);
	if (ret)
		goto free_exttree;
	ret = unpack_files(&sbi);
	if (ret)
		goto free_xattrtree;

	if (ret == 0)
		log_info("Unpacked successfully");
	if (sbi.squash_list_file)
		fclose(sbi.squash_list_file);
free_xattrtree:
	vdfs4_put_bnode(sbi.xattrtree.vdfs4_btree.head_bnode);
free_exttree:
	vdfs4_put_bnode(sbi.exttree.vdfs4_btree.head_bnode);
free_cattree:
	vdfs4_put_bnode(sbi.cattree.vdfs4_btree.head_bnode);

err_unpack:
	free(sbi.snapshot.snapshot_subsystem.buffer);
err_tables:
	vdfs4_destroy_btree_caches();
err_cache:
	close_disk(&sbi);
err_exit:
	if (sbi.dump_file)
		fclose(sbi.dump_file);

	return ret;
}
