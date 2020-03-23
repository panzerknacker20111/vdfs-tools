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

#include "mkfs.h"
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
		+ VDFS4_TOOLS_GET_BNODE_FROM_MEM
		;
int copy_file_to_dlink(struct vdfs4_sb_info *sbi,
		struct vdfs4_catalog_dlink_record *dl_rec, char *path)
{
	int ret = 0;
	int dl_fd = 0;
	int src_file = 0;
	char *data = NULL;
	off_t dl_offset, src_file_size;
	int need_to_read = 0, read_real = 0;
	int buf_size = 0;
	__u64 begin, dl_inode;

	struct list_head *data_ranges_list = NULL;
	if (dl_rec->common.flags & (1 << SIGNED_DLINK)) {
		if (!sbi->dl_inf.dlink_signed) {
			pid_t pid = getpid();
			int path_len = strlen(sbi->tmpfs_dir)
						+ VDFS4_FILE_NAME_LEN;
			sbi->dl_inf.dl_name_signed = malloc(path_len);
			if (!sbi->dl_inf.dl_name_signed)
				return -ENOMEM;
			memset(sbi->dl_inf.dl_name_signed, 0,
					path_len);
			snprintf(sbi->dl_inf.dl_name_signed, path_len,
					"%s/dl_signed_%lu", sbi->tmpfs_dir,
					(long unsigned)pid);
			sbi->dl_inf.dlink_file_signed =
					open(sbi->dl_inf.dl_name_signed,
					O_CREAT | O_EXCL | O_RDWR | O_TRUNC,
					S_IRUSR | S_IWUSR);
			if (sbi->dl_inf.dlink_file_signed < 0) {
				ret = -errno;
				log_error("Can't create file dlink_signed:"
						" %s", strerror(errno));
				return ret;
			}
			sbi->dl_inf.dlink_signed =
					get_free_inode_n(sbi, 1);
			INIT_LIST_HEAD(&sbi->dl_signed_data_ranges);
		}
		data_ranges_list = &sbi->dl_signed_data_ranges;
		dl_fd = sbi->dl_inf.dlink_file_signed;
		dl_inode = sbi->dl_inf.dlink_signed;
		dl_rec->common.flags &= ~((1 << VDFS4_COMPRESSED_FILE) |
				(1 << VDFS4_AUTH_FILE) |
				(1 << SIGNED_DLINK));
	} else if (dl_rec->common.flags & (1 << VDFS4_READ_ONLY_AUTH)) {
		if (!sbi->dl_inf.dlink_file_ro_auth) {
			pid_t pid = getpid();
			int path_len = strlen(sbi->tmpfs_dir)
						+ VDFS4_FILE_NAME_LEN;
			sbi->dl_inf.dl_name_ro_auth = malloc(path_len);
			if (!sbi->dl_inf.dl_name_ro_auth)
				return -ENOMEM;
			memset(sbi->dl_inf.dl_name_ro_auth, 0,
					path_len);
			snprintf(sbi->dl_inf.dl_name_ro_auth, path_len,
					"%s/dl_roauth_%lu", sbi->tmpfs_dir,
					(long unsigned)pid);
			sbi->dl_inf.dlink_file_ro_auth =
					open(sbi->dl_inf.dl_name_ro_auth,
					O_CREAT | O_EXCL | O_RDWR | O_TRUNC,
					S_IRUSR | S_IWUSR);
			if (sbi->dl_inf.dlink_file_ro_auth < 0) {
				ret = -errno;
				log_error("Can't create file dlink_comp_enc:"
						" %s", strerror(errno));
				return ret;
			}
			sbi->dl_inf.dlink_inode_ro_auth =
					get_free_inode_n(sbi, 1);
			INIT_LIST_HEAD(&sbi->dl_ro_auth_data_ranges);
		}
		data_ranges_list = &sbi->dl_ro_auth_data_ranges;
		dl_fd = sbi->dl_inf.dlink_file_ro_auth;
		dl_inode = sbi->dl_inf.dlink_inode_ro_auth;
		dl_rec->common.flags &= ~((1 << VDFS4_COMPRESSED_FILE) |
				(1 << VDFS4_AUTH_FILE) |
				(1 << VDFS4_READ_ONLY_AUTH));
	} else if (dl_rec->common.flags & (1 << VDFS4_AUTH_FILE)) {
		if (!sbi->dl_inf.dlink_file_auth) {
			pid_t pid = getpid();
			int path_len = strlen(sbi->tmpfs_dir)
							+ VDFS4_FILE_NAME_LEN;
			sbi->dl_inf.dl_name_auth = malloc(path_len);
			if (!sbi->dl_inf.dl_name_auth)
				return -ENOMEM;
			memset(sbi->dl_inf.dl_name_auth, 0,
							path_len);
			snprintf(sbi->dl_inf.dl_name_auth, path_len,
					"%s/dl_auth_%lu", sbi->tmpfs_dir,
					(long unsigned)pid);
			sbi->dl_inf.dlink_file_auth =
					open(sbi->dl_inf.dl_name_auth,
					O_CREAT | O_EXCL | O_RDWR | O_TRUNC,
					S_IRUSR | S_IWUSR);
			if (sbi->dl_inf.dlink_file_auth < 0) {
				ret = -errno;
				log_error("Can't create file dlink_comp_enc:"
						" %s", strerror(errno));
				return ret;
			}
			sbi->dl_inf.dlink_inode_auth =
					get_free_inode_n(sbi, 1);
			INIT_LIST_HEAD(&sbi->dl_auth_data_ranges);
		}
		data_ranges_list = &sbi->dl_auth_data_ranges;
		dl_fd = sbi->dl_inf.dlink_file_auth;
		dl_inode = sbi->dl_inf.dlink_inode_auth;
		dl_rec->common.flags &= ~((1 << VDFS4_COMPRESSED_FILE) |
				(1 << VDFS4_AUTH_FILE));
	} else if (dl_rec->common.flags & (1 << VDFS4_COMPRESSED_FILE)) {
		if (!sbi->dl_inf.dlink_file_comp_fd) {
			pid_t pid = getpid();
			int path_len = strlen(sbi->tmpfs_dir)
							+ VDFS4_FILE_NAME_LEN;
			sbi->dl_inf.dl_name_comp = malloc(path_len);
			if (!sbi->dl_inf.dl_name_comp)
				return -ENOMEM;
			memset(sbi->dl_inf.dl_name_comp, 0, path_len);
			snprintf(sbi->dl_inf.dl_name_comp, path_len,
					"%s/dl_comp_%lu", sbi->tmpfs_dir,
					(long unsigned)pid);
			sbi->dl_inf.dlink_file_comp_fd = open(
					sbi->dl_inf.dl_name_comp,
					O_CREAT | O_EXCL | O_RDWR | O_TRUNC,
					S_IRUSR | S_IWUSR);
			if (sbi->dl_inf.dlink_file_comp_fd < 0) {
				ret = -errno;
				log_error("Can't create file dlink_comp:"
						" %s", strerror(errno));
				return ret;
			}
			sbi->dl_inf.dlink_inode_comp = get_free_inode_n(sbi, 1);
			INIT_LIST_HEAD(&sbi->dl_comp_data_ranges);
		}
		data_ranges_list = &sbi->dl_comp_data_ranges;
		dl_fd = sbi->dl_inf.dlink_file_comp_fd;
		dl_inode = sbi->dl_inf.dlink_inode_comp;
		dl_rec->common.flags &= ~(1 << VDFS4_COMPRESSED_FILE);
	} else {
		if (!sbi->dl_inf.dlink_file_fd) {
			pid_t pid = getpid();
			int path_len = strlen(sbi->tmpfs_dir)
							+ VDFS4_FILE_NAME_LEN;
			sbi->dl_inf.dl_name = malloc(path_len);
			if (!sbi->dl_inf.dl_name)
				return -ENOMEM;
			memset(sbi->dl_inf.dl_name, 0, path_len);
			snprintf(sbi->dl_inf.dl_name, path_len,
					"%s/dl_%lu", sbi->tmpfs_dir,
					(long unsigned)pid);
			sbi->dl_inf.dlink_file_fd = open(sbi->dl_inf.dl_name,
					O_CREAT | O_EXCL | O_RDWR | O_TRUNC,
					S_IRUSR | S_IWUSR);
			if (sbi->dl_inf.dlink_file_fd < 0) {
				ret = -errno;
				log_error("Can't create file dlink:"
						" %s", strerror(errno));
				return ret;
			}
			sbi->dl_inf.dlink_inode = get_free_inode_n(sbi, 1);
			INIT_LIST_HEAD(&sbi->dl_data_ranges);
		}
		data_ranges_list = &sbi->dl_data_ranges;
		dl_fd = sbi->dl_inf.dlink_file_fd;
		dl_inode = sbi->dl_inf.dlink_inode;
	}
	buf_size = sbi->block_size;
	data = malloc(buf_size);
	if (!data) {
		log_info("Mkfs can't allocate enough memory");
		return -ENOMEM;
	}
	memset(data, 0, buf_size);
	ret = get_file_size(dl_fd, &dl_offset);
	if (ret)
		goto exit;

	dl_rec->data_offset = dl_offset;
	dl_rec->data_inode = dl_inode;
	lseek(dl_fd, dl_offset, SEEK_SET);
	/*If symlink*/
	if (S_ISLNK(dl_rec->common.file_mode)) {
		int r = readlink(path, data, buf_size);
		if (r < 0) {
			log_error("Can't read link %s - %s", path,
					strerror(errno));
			free(data);
			return -errno;
		}
		if (write(dl_fd, data, r) != r) {
			log_error("%s %s %s", "Can't copy symlink - ", path,
					strerror(errno));
			ret = -errno;
		}
		dl_rec->data_length = r;
		free(data);
		return ret;
	}

	/*Regular file*/
	src_file = open(path, O_RDONLY);
	if (src_file < 0) {
		ret = -errno;
		log_error("%s %s %s", "Can't open file - ",
				path, strerror(errno));
		free(data);
		return ret;
	}

	ret = get_file_size(src_file, &src_file_size);
	if (ret)
		goto exit;

	dl_rec->data_length = src_file_size;

	while (src_file_size) {
		need_to_read = (src_file_size > buf_size) ? buf_size :
				src_file_size;
		memset(data, 0, buf_size);
		read_real = read(src_file, data, need_to_read);
		if (read_real == -1) {
			ret = -errno;
			log_error("%s %s %s", "Can't read file - ", path,
					strerror(errno));
			goto exit;
		}
		if (write(dl_fd, data, read_real) != read_real) {
			ret = -errno;
			log_error("%s %s %s", "Can't copy file - ", path,
					strerror(errno));
			goto exit;
		}
		src_file_size -= read_real;
	}

	begin = 0;
	begin = find_data_duplicate(data_ranges_list,
			dl_fd, dl_fd, dl_rec->data_offset,
			dl_rec->data_length);
	if (begin) {
		dl_rec->data_offset = begin;
		ftruncate(dl_fd, dl_offset);
	} else
		add_data_range(sbi, data_ranges_list, dl_rec->data_offset,
				dl_rec->data_length);
exit:
	free(data);
	close(src_file);
	return ret;
}

void clear_data_range_list(struct list_head *data_range_list)
{
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, data_range_list) {
		struct data_range *dr =
			list_entry(pos, struct data_range, list);
		list_del(pos);
		free(dr);
	}
}





__u64 find_file_duplicate(struct vdfs4_sb_info *sbi, char *path)
{
	int fd;
	__u64 ret;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("cannot open %s", path);
		return 0;
	}
	if (fstat(fd, &st)) {
		log_error("cannot stat %s", path);
		close(fd);
		return 0;
	}
	ret = find_data_duplicate(&sbi->data_ranges,
			fd, sbi->disk_op_image.file_id, 0, st.st_size);
	close(fd);
	return ret;
}

/*
int copy_tiny_file(struct vdfs4_sb_info *sb_info UNUSED,
		const char *src_filename,
		struct vdfs4_catalog_file_record *rec)
{
	char *buf;
	int file, read_real, ret = 0;
	struct stat stat_info;
	memset(&stat_info, 0, sizeof(stat_info));
	ret = lstat(src_filename, &stat_info);
	if (ret < 0) {
		ret = errno;
		log_error("%s %s", "Can't get stat info of ", src_filename);
		return ret;
	}
	assert(stat_info.st_size <= (__off_t)(TINY_DATA_SIZE));
	buf = malloc(TINY_DATA_SIZE);
	if (!buf) {
		log_info("Mkfs can't allocate enough memory");
		return errno;
	}

	memset(buf, 0, TINY_DATA_SIZE);
	file = open(src_filename, O_RDONLY);
	if (file < 0)
		goto exit;
	read_real = read(file, buf, stat_info.st_size);
	close(file);
	if (read_real == -1) {
		log_warning("%s %s", "Can't read file", src_filename);
		ret = errno;
		goto exit;
	}
	memcpy(rec->tiny.data, buf, TINY_DATA_SIZE);
exit:
	free(buf);
	return ret;
}
*/
int insert_hlinks_data(struct vdfs4_sb_info *sbi, u64 *file_offset_abs)
{
	struct hlink_list_item *list;
	int ret = 0;
	u64 begin = 0, length = 0;
	struct vdfs4_cattree_record *record = NULL;
	struct vdfs4_catalog_file_record *file_rec;
	u64 file_offset_abs_new = *file_offset_abs;
	list = sbi->hlinks_list.next;
	if (list != 0)
		log_info("Copy hardlinks");
	while (list != NULL) {
		record = vdfs4_cattree_find(&sbi->cattree.vdfs4_btree,
				list->new_ino_n, NULL, 0, VDFS4_BNODE_MODE_RW);
		if (IS_ERR(record))
			return -ENOMEM;
		file_rec = record->val;
		if (record->key->record_type == VDFS4_CATALOG_DLINK_RECORD) {
			ret = copy_file_to_dlink(sbi,
					(struct vdfs4_catalog_dlink_record *)
					file_rec, list->name);
			if (ret)
				goto errors;
			goto next;
		}
		if (IS_FLAG_SET(file_rec->common.flags,
				VDFS4_COMPRESSED_FILE))
			goto next;

		if (S_ISREG(le16_to_cpu(file_rec->common.file_mode)) &&
		    file_rec->data_fork.size_in_bytes &&
		    IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
			length = le64_to_cpu(file_rec->data_fork.size_in_bytes);
			begin = find_file_duplicate(sbi, list->name);
			if (begin) {
				fork_init(&file_rec->data_fork, begin,
						length, sbi->block_size);
				goto next;
			}
		}

/*		if (file_rec->common.flags & (1 << TINY_FILE)) {
			ret = copy_tiny_file(sbi, list->name, file_rec);
			if (ret)
				goto errors;
			goto next;
		}
*/

		if (file_offset_abs_new % sbi->block_size)
			file_offset_abs_new = block_to_byte
			(byte_to_block(file_offset_abs_new,
				sbi->block_size), sbi->block_size);
		*file_offset_abs = file_offset_abs_new;
		begin = file_offset_abs_new;

		ret = copy_file_to_image(sbi, list->name, &file_offset_abs_new);
		if (ret)
			goto errors;
		length = file_offset_abs_new - *file_offset_abs;

		fork_init(&file_rec->data_fork, begin, length, sbi->block_size);
		add_data_range(sbi, &sbi->data_ranges, begin, length);
		*file_offset_abs = file_offset_abs_new;
next:
		list = list->next;
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	}
	hl_list_free(sbi->hlinks_list.next);
	sbi->hlinks_list.next = NULL;
	return ret;
errors:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	return ret;
}

int insert_hlinks_metadata(struct vdfs4_sb_info *sbi)
{
	int ret = 0;

	struct hlink_list_item *list;
	struct stat stat_info;
	__u64 obj_count = 0;


	list = sbi->hlinks_list.next;
	if (list != 0)
		log_info("Copy hardlinks");
	while (list != NULL) {
		ret = lstat(list->name, &stat_info);
		if (ret < 0) {
			log_error("%s %s", "Can't take stat info of",
					list->name);
			ret = errno;
			return ret;
		}

		stat_info.st_nlink = list->links;
		ret = insert_record(sbi, list->name, NULL, &stat_info,
				list->new_ino_n, list->new_ino_n,
				&obj_count, 0);
		if (ret)
			break;

		list = list->next;
	}

	return ret;
}


/**
 * @brief Function fill image metadata for VDFS4 subsystem
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int fill_image_metadata(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	char *root_rec_name = "root";
	int root_parent_id = 0;
	struct vdfs4_cattree_record *record;
	__u64 object_count = 0;

	if (sbi->root_path != NULL) {
		log_activity("Fill catalog tree from %s", sbi->root_path);
		ret = insert_metadata(sbi, sbi->root_path, VDFS4_ROOT_INO,
				&object_count, 0);
		if (ret)
			return ret;

		record = vdfs4_cattree_find(&sbi->cattree.vdfs4_btree,
				root_parent_id,
				root_rec_name, strlen(root_rec_name),
				VDFS4_BNODE_MODE_RW);
		if (IS_ERR(record))
			return -ENOMEM;
		VDFS4_CATTREE_FOLDVAL(record)->total_items_count =
				cpu_to_le64(object_count);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		ret = insert_hlinks_metadata(sbi);
		if (ret)
			return ret;
	}
	return ret;
};
/**
* @brief Function fill image data  for VDFS4 subsystem copy files from
* root_path to image file
* @param [in] sbi Superblock runtime structure
* @return 0 on success, error code otherwise
*/
int fill_image_data(struct vdfs4_sb_info *sbi)
{
	u64 file_offset = 0;
	int ret = 0;

	file_offset = get_metadata_size(sbi);
	if (sbi->metadata_size) {
		if (sbi->snapshot.metadata_size
				> sbi->metadata_size) {
			log_error("Metadata size is more than %lu",
				sbi->metadata_size);
			ret = -ENOSPC;
			return ret;
		} else {
			sbi->snapshot.preallocation_len +=
					sbi->metadata_size -
					sbi->snapshot.metadata_size;
			sbi->snapshot.metadata_size =
					sbi->metadata_size;
		}
	}

	if (sbi->root_path != NULL) {
		log_activity("Copy files data from %s", sbi->root_path);
		ret = insert_data(sbi, sbi->root_path, VDFS4_ROOT_INO,
				&file_offset);
		if (ret) {
			log_error("Error when insert data - %s",
					strerror(-ret));
			return ret;
		}
		ret = insert_hlinks_data(sbi, &file_offset);
		if (ret) {
			log_error("Error when insert hlinks data - %s",
					strerror(-ret));
			return ret;
		}
		ret = copy_dlink_files(sbi);
		if (ret) {
			log_error("Error when insert datalinks data - %s",
					strerror(-ret));
			return ret;
		}
	}

	if ((!IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) &&
		(file_offset + block_to_byte(sbi->snapshot.metadata_size,
			sbi->block_size)) > sbi->min_image_size) {
		ret = -ENOSPC;
		log_error("Size of root dir is more than image size");
		return ret;
	}

	return ret;
}
/**
 * @brief Function insert_data  for VDFS4 subsystem copy files from
 * root_path to image file
 * @param [in] sbi Superblock runtime structure
 * @param [in] dir_path Path to root_directory to insert from
 * @param [in] parent_id ID of directory to insert data from it
 * @param [in] file_offset_abs	offset of data
 * @return 0 on success, error code otherwise
 */
int insert_data(struct vdfs4_sb_info *sbi, char *dir_path,
		__u64 parent_id, u64 *file_offset_abs)
{
	DIR *dir;
	u64 parent_id_new, file_offset_abs_new;
	u_int64_t begin, length;
	u8 record_type;
	int ret = 0;
	char *path = NULL;
	struct dirent *data;
	struct vdfs4_cattree_record *record = NULL;
	struct vdfs4_catalog_file_record *file_rec;
	if (!sbi->root_path) {
		ret = 0;
		return ret;
	}
	dir = opendir(dir_path);

	if (dir == NULL) {
		log_info("%s %s", "Can't open dir", dir_path);
		return errno;
	}
	file_offset_abs_new = *file_offset_abs;

	while ((data = readdir(dir)) != NULL) {
		if ((strcmp(data->d_name, ".") == 0) ||
				(strcmp(data->d_name, "..") == 0))
			continue;

		path = calloc(1, strlen(dir_path) + strlen(data->d_name) + 2);
		if (!path) {
			ret = -ENOMEM;
			goto exit;
		}

		strncat(path, dir_path, strlen(dir_path));
		strncat(path, "/", 1);
		strncat(path, data->d_name, strlen(data->d_name));

		record = vdfs4_cattree_find(&sbi->cattree.vdfs4_btree,
				parent_id, data->d_name, strlen(data->d_name),
				VDFS4_BNODE_MODE_RW);

		if (IS_ERR(record)) {
			log_error("Can't find record about object %s in"
					"catalog tree", path);
			ret = PTR_ERR(record);
			goto exit;
		}
		record_type = record->key->record_type;

		if (record_type == VDFS4_CATALOG_FOLDER_RECORD) {
			/* Device/Socket/Fifo */
			if (!S_ISDIR(le16_to_cpu(VDFS4_CATTREE_FOLDVAL(record)
							->file_mode)))
				goto loop_end;
			/*Folder*/
			parent_id_new = record->key->object_id;
			ret = insert_data(sbi, path, parent_id_new,
					&file_offset_abs_new);
			if (ret)
				goto errors;
			*file_offset_abs = file_offset_abs_new;
		} else if (record_type == VDFS4_CATALOG_FILE_RECORD) {
			/*File */

			file_rec = (struct vdfs4_catalog_file_record *)
					record->val;
			if (IS_FLAG_SET(file_rec->common.flags,
					VDFS4_COMPRESSED_FILE))
				/*Nothing to do if file is
				 *  compressed
				 * (file data was already copied)*/
				goto loop_end;

			if (S_ISREG(le16_to_cpu(file_rec->common.file_mode)) &&
			    file_rec->data_fork.size_in_bytes &&
			    IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
				length = le64_to_cpu(file_rec->data_fork.size_in_bytes);
				begin = find_file_duplicate(sbi, path);
				if (begin) {
					fork_init(&file_rec->data_fork, begin,
						  length, sbi->block_size);
					goto loop_end;
				}
			}

/*			if (file_rec->common.flags & (1 << TINY_FILE)) {
				ret = copy_tiny_file(sbi, path,
					file_rec);
				if (ret)
					goto errors;
				goto loop_end;
			}
*/


			if (file_offset_abs_new % sbi->block_size)
				file_offset_abs_new = block_to_byte
					(byte_to_block(file_offset_abs_new,
					sbi->block_size), sbi->block_size);
			*file_offset_abs = file_offset_abs_new;
			begin = file_offset_abs_new;
			ret = copy_file_to_image(sbi, path,
					&file_offset_abs_new);
			if (ret)
				goto errors;
			length = file_offset_abs_new - *file_offset_abs;

			fork_init(&file_rec->data_fork, begin, length,
					sbi->block_size);
			add_data_range(sbi, &sbi->data_ranges, begin, length);
			*file_offset_abs = file_offset_abs_new;
		} else if (record_type == VDFS4_CATALOG_DLINK_RECORD) {
			struct vdfs4_catalog_dlink_record *dl_rec =
					(struct vdfs4_catalog_dlink_record *)
							(record->val);
			ret = copy_file_to_dlink(sbi, dl_rec, path);
			if (ret)
				goto errors;

		} else if (record_type != VDFS4_CATALOG_HLINK_RECORD){
			ret = -EINVAL;
			goto errors;
		}
loop_end:
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		record = NULL;
		free(path);
		path = NULL;
	}

	goto exit;
errors:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
exit:
	free(path);
	closedir(dir);
	return ret;
}


static int is_dlink(struct vdfs4_dlink_info *dl_inf, __u64 obj_id)
{
	return (obj_id == dl_inf->dlink_inode
		|| obj_id == dl_inf->dlink_inode_comp
		|| obj_id == dl_inf->dlink_inode_auth
		|| obj_id == dl_inf->dlink_inode_ro_auth);

}

static int is_compress_to_dlink(struct vdfs4_sb_info *sbi, const char *path)
{
	struct list_head *pos, *q;
	if (!list_empty(&sbi->compress_list))
		return 0;


	list_for_each_safe(pos, q, &sbi->compress_list) {
		struct install_task *ptr =
			list_entry(pos, struct install_task, list);
		if ((strlen(ptr->src_full_path) == strlen(path))
				&& !strncmp(ptr->src_full_path, path,
				strlen(path))) {
			list_del(&ptr->list);
			free(ptr);
			return 1;
		}
	}
	return 0;
}

/*****************************************************************************/
/**
 * @brief Function insert_record to cattree for VDFS4 subsystem
 * @param [in] sbi		Superblock runtime structure
 * @param [in] path		Full path to file or folder
 * @param [in] name		name of file
 * @param [in] record_type	Type of object to add in tree
 * @param [in] uuid		Id of current object
 * @param [in] parent_id	Id of parent directory
 * @return 0 on success, error code otherwise
 */
int insert_record(struct vdfs4_sb_info *sbi, char *path, char *name,
		struct stat *stat_info, int obj_id, int parent_id,
		__u64 *obj_count, int compress_to_dlink)
{

	int ret = 0;
	__u64 start = 0, length = 0;
	__u64 items = 0, links = 0;
	struct vdfs4_posix_permissions	permissions;
	struct vdfs4_timespec creation_time;
	struct vdfs4_timespec modification_time;
	struct vdfs4_timespec access_time;
	struct vdfs4_cattree_record *new_record;
	unsigned int record_type = VDFS4_CATALOG_FILE_RECORD;
	int chunk_size = 1 << sbi->log_chunk_size;

	if ((S_ISREG(stat_info->st_mode) || S_ISLNK(stat_info->st_mode)) &&
			(((IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) &&
				(stat_info->st_size > 0 &&
						stat_info->st_size < chunk_size))
						|| compress_to_dlink)
				&& (!is_dlink(&sbi->dl_inf, (__u64)obj_id))) {
			record_type = VDFS4_CATALOG_DLINK_RECORD;
	}


	permissions.file_mode = cpu_to_le16(stat_info->st_mode);
	if (IS_FLAG_SET(sbi->service_flags, ALL_ROOT)) {
		permissions.gid = 0;
		permissions.uid = 0;
	} else {
		permissions.gid = cpu_to_le32(stat_info->st_gid);
		permissions.uid = cpu_to_le32(stat_info->st_uid);
	}
	creation_time = vdfs4_encode_time(stat_info->st_ctim);
	modification_time = vdfs4_encode_time(stat_info->st_mtim);
	access_time = vdfs4_encode_time(stat_info->st_atim);
	if (S_ISDIR(stat_info->st_mode)) {
		start = 0;
		length = 0;
		items = *obj_count;
		links = 1;
		record_type = VDFS4_CATALOG_FOLDER_RECORD;
	} else {
		start = 0;
		length = stat_info->st_size;
		links = stat_info->st_nlink;

		if (S_ISCHR(stat_info->st_mode) || S_ISBLK(stat_info->st_mode))
			items = (major(stat_info->st_rdev) << 20)
				| minor(stat_info->st_rdev);

		if (name && links > 1) {
			struct hlink_list_item *list_item;
			record_type = VDFS4_CATALOG_HLINK_RECORD;
			list_item = hl_list_item_find(&sbi->hlinks_list,
					stat_info->st_ino);
			if (list_item) {
				list_item->links++;
				test_and_clear_inode_n(sbi, obj_id);
				obj_id = list_item->new_ino_n;
			} else {
				list_item = malloc(sizeof
						(struct hlink_list_item));
				memset(list_item, 0, sizeof
						(struct hlink_list_item));
				hl_list_item_init(list_item,
					stat_info->st_ino, path, obj_id);
				hl_list_insert(&sbi->hlinks_list, list_item);
			}
		}
	}

	if (!S_ISLNK(stat_info->st_mode) &&
	    record_type != VDFS4_CATALOG_HLINK_RECORD) {

		if (!is_dlink(&sbi->dl_inf, (__u64)obj_id))
			ret = get_set_xattrs(sbi, path, obj_id);
		if (ret)
			return ret;
	}
	new_record = vdfs4_cattree_place_record(&sbi->cattree.vdfs4_btree,
			obj_id, parent_id, name,
			name ? strlen(name) : 0, record_type);

	if (IS_ERR(new_record)) {
		ret = PTR_ERR(new_record);
		return ret;
	}
	vdfs4_fill_cattree_record_value(new_record, items, links,
		&permissions, creation_time, modification_time,
		access_time, start, length, sbi->block_size, compress_to_dlink);

	if ((record_type == VDFS4_CATALOG_FILE_RECORD) &&
			(S_ISREG(stat_info->st_mode))) {
		/* if (length <= TINY_DATA_SIZE) {
			VDFS4_CATTREE_FOLDVAL(new_record)->flags |=
					(1 << TINY_FILE);
			sbi->tiny_files_count++;
		}*/
	}

	vdfs4_release_record((struct vdfs4_btree_gen_record *) new_record);
	return ret;
}


/**
 * @brief Function insert_metadata
 * (read directory and add metadata about its objects to cattree)
 * for VDFS4 subsystem
 * @param [in] sbi		Superblock runtime structure
 * @param [in] dir_path		path to direcroty to read
 * @param [in] parent_id	ID of directory to insert metadata from it
  * @return 0 on success, or error code
 */
/******************************************************************************/
int insert_metadata(struct vdfs4_sb_info *sbi, char *dir_path, int parent_id,
		__u64 *object_count, int compress_to_dlink)
{
	DIR *dir;
	int ret;
	char *path = NULL;
	struct dirent *data;
	struct stat info;
	int obj_id;
	int compress_to_dlink_current = compress_to_dlink;
	__u64 obj_count = 0;
	ret = 0;

	dir = opendir(dir_path);

	if (dir == NULL) {
		log_error("Can't open dir %s - %s", dir_path, strerror(errno));
		return errno;
	}

	while ((data = readdir(dir)) != NULL) {
		if ((strcmp(data->d_name, ".") == 0) ||
				(strcmp(data->d_name, "..") == 0))
			continue;

		path = calloc(1, strlen(dir_path) + strlen(data->d_name) + 2);
		if (!path) {
			ret = -ENOMEM;
			goto exit;
		}
		strncat(path, dir_path, strlen(dir_path));
		strncat(path, "/", 1);
		strncat(path, data->d_name, strlen(data->d_name));
		ret = lstat(path, &info);
		if (ret) {
			log_error("Can't get stat information for %s - %s",
					path, strerror(errno));
			goto exit;
		}

		obj_id = get_free_inode_n(sbi, 1);
		compress_to_dlink_current = compress_to_dlink?
				compress_to_dlink :
				is_compress_to_dlink(sbi, path);
		if (S_ISDIR(info.st_mode)) {
			/*Found folder*/
			obj_count = 0;
			char *xattr_buf = malloc(XATTR_VAL_SIZE);
			memset(xattr_buf, 0, XATTR_VAL_SIZE);
			free(xattr_buf);
			ret = insert_metadata(sbi, path, obj_id, &obj_count,
					compress_to_dlink_current);

			if (ret)
				goto exit;
			ret = insert_record(sbi, path, data->d_name, &info,
					obj_id, parent_id, &obj_count,
					compress_to_dlink_current);
		} else {
			sbi->files_count++;


			ret = insert_record(sbi, path, data->d_name, &info,
				obj_id, parent_id, &obj_count,
				compress_to_dlink_current);

			if (ret)
				goto exit;
		}
		(*object_count)++;
		free(path);
		path = NULL;
	}


exit:
	free(path);
	closedir(dir);
	return ret;
}
/******************************************************************************/




int init_sb_info(struct vdfs4_sb_info *sbi)
{
	struct timespec cur_time;

	/*sbi->xattrtree.tree.name = subsystem_names[6];
	sbi->small_area_bitmap.name = subsystem_names[7];
	sbi->small_area.name = subsystem_names[8];*/
#ifdef GIT_BRANCH
	log_info("git branch: %s", GIT_BRANCH);
#endif
#ifdef GIT_HASH
	log_info("git hash: %s", GIT_HASH);
#endif
	if (sbi->image_size && sbi->image_size < MIN_VOLUME_SIZE) {
		log_error("Can't make file less then %d",
				MIN_VOLUME_SIZE);
		return -EINVAL;
	}
	if (!sbi->tmpfs_dir)
		sbi->tmpfs_dir = "/tmp";


	/* in case of image creation without size set in arguments */
	if (sbi->image_size == 0) {
		log_info("Image size is not specified,"
				" read-only image will be created");
		SET_FLAG(sbi->service_flags, READ_ONLY_IMAGE);
		sbi->image_size = -1;
		sbi->min_image_size = sbi->image_size;
	} else
		log_info("Image size is %llu", sbi->image_size);
	if (IS_FLAG_SET(sbi->service_flags, SIMULATE))
		log_info("Disk operations are in SIMULATE mode");

	sbi->block_size = BLOCK_SIZE_DEFAULT;

	if (sbi->super_page_size == 0)
		sbi->super_page_size = SUPER_PAGE_SIZE_DEFAULT;

	if (sbi->erase_block_size == 0)
		sbi->erase_block_size = ERASE_BLOCK_SIZE_DEFAULT;
	sbi->volume_size_in_erase_blocks =
		sbi->image_size / sbi->erase_block_size;
	log_info("Block size = %lu, erase block = %lu, super page = %lu",
		sbi->block_size, sbi->erase_block_size,
		sbi->super_page_size);
	log_info("Disk size in blocks %llu", byte_to_block(sbi->image_size,
		sbi->block_size));

	clock_gettime(CLOCK_REALTIME, &cur_time);
	sbi->timestamp = vdfs4_encode_time(cur_time);

	generate_uuid(sbi->volume_uuid, sizeof(sbi->volume_uuid));

	memcpy(sbi->volume_name, VOLUME_NAME_DEFAULT,
			sizeof(VOLUME_NAME_DEFAULT));

	sbi->log_blocks_in_leb = log2_32(sbi->super_page_size);
	sbi->log_sectors_per_block = log2_32(sbi->block_size / SECTOR_SIZE);
	sbi->log_erase_block_size = log2_32(sbi->erase_block_size);
	sbi->log_super_page_size = log2_32(sbi->super_page_size);
	sbi->log_block_size = log2_32(sbi->block_size);
	sbi->total_super_pages_count = sbi->image_size
		>> sbi->log_super_page_size;

	sbi->files_count = 0;
	sbi->folders_count = 1; /* root directory */

	sbi->debug_area.first_block = DEBUG_AREA_DEFAULT_START;
	sbi->debug_area.block_count = DEBUG_AREA_DEFAULT_SIZE;

	INIT_LIST_HEAD(&sbi->data_ranges);

	return 0;
}


int copy_dlink_file_to_image(struct vdfs4_sb_info *sbi,
		char *file_name, __u64 obj_id, unsigned cmd, int *count,
		int *ret_thread)
{
	int ret = 0;
	struct stat stat_info;
	__u64 obj_count = 0, file_start = 0;
	u64 file_offset = 0;
	struct install_task ptr;
	ret = lstat(file_name, &stat_info);
	if (ret)
		return ret;
	ret = insert_record(sbi, file_name, NULL, &stat_info,
			obj_id, obj_id, &obj_count, 0);
	if (ret)
		return ret;
	if (cmd & CMD_COMPRESS) {
		memset(&ptr, 0, sizeof(struct install_task));
		ptr.compress_type = sbi->dl_inf.compression_type;
		ptr.cmd = cmd;
		strncat(ptr.src_full_path, file_name, VDFS4_FULL_PATH_LEN);

		ptr.src_fname = file_name;
		memcpy(ptr.dst_parent_dir, "/", strlen("/"));
		int tnum = get_free_file_thread();
		pthread_mutex_lock(&thread_file[tnum].compr_file_mutex);
		memcpy(thread_file[tnum].ptr, &ptr,
				sizeof(struct install_task));
		thread_file[tnum].parent_id = obj_id;
		thread_file[tnum].sbi = sbi;
		thread_file[tnum].has_data = 1;
		thread_file[tnum].error = ret_thread;
		pthread_mutex_lock(&files_count_mutex);
		(*count)++;
		thread_file[tnum].count = count;
		pthread_mutex_unlock(&files_count_mutex);
		pthread_cond_signal(&thread_file[tnum].compr_file_cond);
		pthread_mutex_unlock(&thread_file[tnum].compr_file_mutex);
	} else {
		pthread_mutex_lock(&write_file_mutex);
		file_start = get_metadata_size(sbi);
		file_offset = 0;
		ret = copy_file_to_image(sbi, file_name, &file_offset);
		if (ret) {
			pthread_mutex_unlock(&write_file_mutex);
			return ret;
		}
		struct vdfs4_cattree_record *rec = vdfs4_cattree_find(
				&sbi->cattree.vdfs4_btree, obj_id, NULL, 0,
				VDFS4_BNODE_MODE_RW);
		if (IS_ERR(rec)) {
			pthread_mutex_unlock(&write_file_mutex);
			return PTR_ERR(rec);
		}
		fork_init(&((struct vdfs4_catalog_file_record *)
				(rec->val))->data_fork, file_start,
				stat_info.st_size, sbi->block_size);
		vdfs4_release_record((struct vdfs4_btree_gen_record *)rec);
		pthread_mutex_unlock(&write_file_mutex);
	}
	return ret;
}

int copy_dlink_files(struct vdfs4_sb_info *sbi)
{
	int ret = 0, ret_thread = 0;
	int count = 0;
	if (sbi->dl_inf.dlink_signed) {
		ret = copy_dlink_file_to_image(sbi,
				sbi->dl_inf.dl_name_signed,
				sbi->dl_inf.dlink_signed,
				CMD_AUTH | CMD_COMPRESS | CMD_DLINK,
				&count, &ret_thread);
		if (ret)
			goto exit;
		wait_finish(&count);
	}
	if (sbi->dl_inf.dlink_inode_ro_auth) {
		ret = copy_dlink_file_to_image(sbi,
				sbi->dl_inf.dl_name_ro_auth,
				sbi->dl_inf.dlink_inode_ro_auth,
				CMD_AUTH | CMD_COMPRESS, &count, &ret_thread);
		if (ret)
			goto exit;
		wait_finish(&count);
	}
	if (sbi->dl_inf.dlink_inode_auth) {
		ret = copy_dlink_file_to_image(sbi,
				sbi->dl_inf.dl_name_auth,
				sbi->dl_inf.dlink_inode_auth,
				CMD_AUTH | CMD_COMPRESS, &count, &ret_thread);
		if (ret)
			goto exit;
		wait_finish(&count);
	}
	if (sbi->dl_inf.dlink_inode_comp) {
		ret = copy_dlink_file_to_image(sbi, sbi->dl_inf.dl_name_comp,
				sbi->dl_inf.dlink_inode_comp, CMD_COMPRESS,
				&count, &ret_thread);
		if (ret)
			goto exit;
		wait_finish(&count);
	}
	if (sbi->dl_inf.dlink_inode) {
		ret = copy_dlink_file_to_image(sbi, sbi->dl_inf.dl_name,
				sbi->dl_inf.dlink_inode, 0, NULL, NULL);
		if (ret)
			goto exit;
		wait_finish(&count);
	}

	ret = ret_thread;
exit:
	if (sbi->dl_inf.dlink_inode_ro_auth)
		close(sbi->dl_inf.dlink_file_ro_auth);
	if (sbi->dl_inf.dlink_inode_auth)
		close(sbi->dl_inf.dlink_file_auth);
	if (sbi->dl_inf.dlink_inode_comp)
		close(sbi->dl_inf.dlink_file_comp_fd);
	if (sbi->dl_inf.dlink_inode)
		close(sbi->dl_inf.dlink_file_fd);
	if (sbi->dl_inf.dlink_signed)
		close(sbi->dl_inf.dlink_file_signed);
	return ret;
}

void remove_dlink_files(struct vdfs4_sb_info *sbi)
{
	if (sbi->dl_inf.dl_name_comp) {
		unlink(sbi->dl_inf.dl_name_comp);
		free(sbi->dl_inf.dl_name_comp);
		clear_data_range_list(&sbi->dl_comp_data_ranges);
	}
	if (sbi->dl_inf.dl_name) {
		unlink(sbi->dl_inf.dl_name);
		free(sbi->dl_inf.dl_name);
		clear_data_range_list(&sbi->dl_data_ranges);
	}
	if (sbi->dl_inf.dl_name_auth) {
		unlink(sbi->dl_inf.dl_name_auth);
		free(sbi->dl_inf.dl_name_auth);
		clear_data_range_list(&sbi->dl_auth_data_ranges);
	}
	if (sbi->dl_inf.dl_name_ro_auth) {
		unlink(sbi->dl_inf.dl_name_ro_auth);
		free(sbi->dl_inf.dl_name_ro_auth);
		clear_data_range_list(&sbi->dl_ro_auth_data_ranges);
	}
	if (sbi->dl_inf.dl_name_signed) {
		unlink(sbi->dl_inf.dl_name_signed);
		free(sbi->dl_inf.dl_name_signed);
		clear_data_range_list(&sbi->dl_signed_data_ranges);
	}
}

int calc_and_add_crc(int file_id)
{
	char buf[BLOCK_SIZE_DEFAULT];
	int error;
	unsigned int crc = calculate_file_crc(file_id, 1, &error);
	if (error)
		return error;

	*((unsigned int *)buf) = crc;
	if (write(file_id, buf, BLOCK_SIZE_DEFAULT) != BLOCK_SIZE_DEFAULT)
		return errno;
	return 0;
}

void init_threads(struct vdfs4_sb_info *sbi)
{
	int tnum;
	int ret = 0;
	int path_len = 0;
	processors = sysconf(_SC_NPROCESSORS_ONLN);

	thread = malloc(processors * sizeof(struct thread_info));
	thread_file = malloc(processors * sizeof(struct thread_file_info));
	pthread_mutex_init(&file_finished_mutex, NULL);
	pthread_mutex_init(&write_file_mutex, NULL);
	pthread_mutex_init(&files_count_mutex, NULL);
	pthread_mutex_init(&find_record_mutex, NULL);
	pthread_mutex_init(&thread_free_mutex, NULL);
	pthread_mutex_init(&thread_file_free_mutex, NULL);
	pthread_cond_init(&thread_free_cond, NULL);
	pthread_cond_init(&thread_file_free_cond, NULL);
	pthread_cond_init(&file_finished, NULL);
	for (tnum = 0; tnum < processors; tnum++) {
		memset(&thread[tnum], 0, sizeof(struct thread_info));
		thread[tnum].thread_num = tnum + 1;
		thread[tnum].is_free = 1;
		thread[tnum].in = malloc(1 << sbi->log_chunk_size);
		thread[tnum].out = malloc((1 << sbi->log_chunk_size) +
				(1 << sbi->log_chunk_size) / 16 + 64 + 3);
		pthread_mutex_init(&thread[tnum].compress_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].write_uncompr_mutex,
				NULL);
		pthread_mutex_init(&thread_file[tnum].write_compr_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].compress_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].write_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].compr_file_mutex, NULL);
		pthread_cond_init(&thread_file[tnum].compr_file_cond, NULL);
		pthread_cond_init(&thread_file[tnum].finished, NULL);
		pthread_cond_init(&thread[tnum].compress_cond, NULL);

		ret = pthread_create(&thread[tnum].thread_id, NULL,
				(void *)&compress_chunk_thread,
				(void *)&thread[tnum]);
		if (ret != 0)
			exit(EXIT_FAILURE);
		memset(&thread_file[tnum], 0, sizeof(struct thread_file_info));
		thread_file[tnum].thread_num = tnum + 1;
		thread_file[tnum].is_free = 1;
		thread_file[tnum].ptr = malloc(sizeof(struct install_task));
		if (sbi->rsa_key) {
			thread_file[tnum].rsa_copy  = malloc(sizeof(RSA));
			memcpy(thread_file[tnum].rsa_copy, sbi->rsa_key,
					sizeof(RSA));
			thread[tnum].hash_alg = sbi->hash_alg;
			thread[tnum].hash_len = sbi->hash_len;
		}
		ret = pthread_create(&thread_file[tnum].thread_id, NULL,
				(void *)&compress_file_thread,
				(void *)&thread_file[tnum]);
		if (ret != 0)
			exit(EXIT_FAILURE);



		path_len = strlen(sbi->tmpfs_dir)
				+ 1 + strlen("comp_") + 32;
		thread_file[tnum].compr_temp = malloc(path_len);
		memset(thread_file[tnum].compr_temp, 0, path_len);
		snprintf(thread_file[tnum].compr_temp, path_len,
				"%s/comp_%lu", sbi->tmpfs_dir,
				(long unsigned)thread_file[tnum].thread_id);
		path_len = strlen(sbi->tmpfs_dir) + 1 + strlen("uncom_") + 32;
		thread_file[tnum].uncompr_temp = malloc(path_len);
		memset(thread_file[tnum].uncompr_temp, 0, path_len);
		snprintf(thread_file[tnum].uncompr_temp, path_len,
				"%s/uncom_%lu", sbi->tmpfs_dir,
				(long unsigned)thread_file[tnum].thread_id);


	}

}

void destroy_threads(void)
{
	int i;
	for (i = 0; i < processors; i++) {
		if (thread[i].thread_id) {
			pthread_mutex_lock(&thread[i].compress_mutex);
			thread[i].exit = 1;
			pthread_cond_signal(&thread[i].compress_cond);
			pthread_mutex_unlock(&thread[i].compress_mutex);
			pthread_join(thread[i].thread_id, NULL);
			free(thread[i].in);
			free(thread[i].out);
			pthread_cond_destroy(&thread[i].compress_cond);
			pthread_mutex_destroy(&thread[i].compress_mutex);

		}
	}
	free(thread);
	for (i = 0; i < processors; i++) {
		if (thread_file[i].thread_id) {
			pthread_mutex_lock(&thread_file[i].compr_file_mutex);
			thread_file[i].exit = 1;
			pthread_cond_signal(&thread_file[i].compr_file_cond);
			pthread_mutex_unlock(&thread_file[i].compr_file_mutex);
			pthread_join(thread_file[i].thread_id, NULL);
			free(thread_file[i].ptr);
			free(thread_file[i].rsa_copy);
			free(thread_file[i].compr_temp);
			free(thread_file[i].uncompr_temp);
			pthread_cond_destroy(&thread_file[i].compr_file_cond);
			pthread_mutex_destroy(&thread_file[i].compr_file_mutex);
			pthread_mutex_destroy(
					&thread_file[i].write_compr_mutex);
			pthread_mutex_destroy(
					&thread_file[i].write_uncompr_mutex);
			pthread_mutex_destroy(&thread_file[i].write_mutex);
			pthread_mutex_destroy(&thread_file[i].compress_mutex);
			pthread_cond_destroy(&thread_file[i].finished);
		}
	}
	pthread_mutex_destroy(&thread_free_mutex);
	pthread_mutex_destroy(&thread_file_free_mutex);
	pthread_cond_destroy(&thread_file_free_cond);
	pthread_cond_destroy(&thread_free_cond);
	pthread_mutex_destroy(&files_count_mutex);
	pthread_mutex_destroy(&find_record_mutex);
	pthread_mutex_destroy(&file_finished_mutex);
	pthread_mutex_destroy(&write_file_mutex);
	pthread_cond_destroy(&file_finished);
	free(thread_file);

}

int main(int argc, char *argv[])
{
	int ret = 0;
	struct vdfs4_sb_info sbi;
	struct list_head install_task_list;

	INIT_LIST_HEAD(&install_task_list);
	INIT_LIST_HEAD(&sbi.data_ranges);
	memset(&sbi, 0, sizeof(sbi));
		print_version();
	INIT_LIST_HEAD(&sbi.compress_list);
	ret = parse_cmd(argc, argv, &sbi);
	if (ret)
		goto err_before_open;
	if (!IS_FLAG_SET(sbi.service_flags, IMAGE))
		ret = open_disk(&sbi);

	else
		ret = vdfs4_create_image(sbi.file_name, &sbi);

	if (ret)
		goto err_before_open;
	ret = init_sb_info(&sbi);
	if (ret)
		goto err_exit;

	ret = vdfs4_init_btree_caches();
	if (ret) {
		log_error("error btree caches init - ENOMEM");
		goto err_exit;
	}

	ret = init_snapshot(&sbi);
	if (ret)
		goto err_space_manager;

	ret = init_space_manager(&sbi);
	if (ret)
		goto err_space_manager;

	ret = clean_superblocks_area(&sbi);
	if (ret)
		goto err_space_manager;

	ret = init_inode_id_alloc(&sbi);
	if (ret)
		goto err_inode_id_alloc;

	ret = init_cattree(&sbi);
	if (ret)
		goto err_cat_tree;
	ret = init_exttree(&sbi);
	if (ret)
		goto err_ext_tree;
	ret = init_xattrtree(&sbi);
	if (ret)
		goto err_xattr_tree;

	if (sbi.squash_list_file) {
		ret = preprocess_sq_tasklist(&sbi, &install_task_list);
		if (ret)
			goto err_squashfs;
	}

	init_threads(&sbi);
	ret = fill_image_metadata(&sbi);
	if (ret)
		goto err_destroy_all;

	util_add_btree_size(&sbi, &sbi.cattree);
	util_add_btree_size(&sbi, &sbi.xattrtree);
	util_add_btree_size(&sbi, &sbi.exttree);

	ret = allocate_fixed_areas(&sbi);
	if (ret)
		goto err_destroy_all;

	ret = fill_inode_bitmap(&sbi);
	if (ret)
		goto err_destroy_all;
	ret = calculate_and_place_on_volume_snapshot(&sbi);
	if (ret)
		goto err_destroy_all;
	if (!list_empty(&install_task_list)) {
		ret = tune_files(&sbi, &install_task_list);
		if (ret)
			goto  err_destroy_all;
	}
	ret = fill_image_data(&sbi);
	if (ret)
		goto err_destroy_all;

	if (!IS_FLAG_SET(sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = place_on_volume_subsystem(&sbi,
				&sbi.space_manager_info.subsystem);
		if (ret)
			goto err_destroy_all;
		ret = place_on_volume_subsystem(&sbi, &sbi.inode_bitmap);
		if (ret)
			goto err_destroy_all;
	} else {
		SET_FLAG(sbi.service_flags, IMAGE_CRC32);
	}

	ret = place_on_volume_subsystem(&sbi, &sbi.cattree.tree);
	if (ret)
		goto err_destroy_all;
	ret = place_on_volume_subsystem(&sbi, &sbi.exttree.tree);
	if (ret)
		goto err_destroy_all;
	ret = place_on_volume_subsystem(&sbi, &sbi.xattrtree.tree);
	if (ret)
		goto err_destroy_all;
	ret = place_on_volume_preallocation(&sbi);
	if (ret)
		goto err_destroy_all;

	sign_sm_buffer(&sbi);
	if (!IS_FLAG_SET(sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = flush_subsystem(&sbi, &sbi.inode_bitmap);
		if (ret)
			goto err_destroy_all;
	}
	ret = flush_subsystem_tree(&sbi, &sbi.cattree);
	if (ret)
		goto err_destroy_all;
	ret = flush_subsystem_tree(&sbi, &sbi.exttree);
	if (ret)
		goto err_destroy_all;
	ret = flush_subsystem_tree(&sbi, &sbi.xattrtree);
	if (ret)
		goto err_destroy_all;

	ret = flush_debug_area(&sbi);
	if (ret)
		goto err_destroy_all;
	ret = flush_snapshot(&sbi);
	if (ret)
		goto err_destroy_all;
	if (!IS_FLAG_SET(sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = flush_subsystem(&sbi, &sbi.space_manager_info.subsystem);
		if (ret)
			goto err_destroy_all;
	}
	ret = prepare_superblocks(&sbi);
	if (ret)
		goto err_destroy_all;
	ret = flush_superblocks(&sbi, argc, argv);
	if (ret)
		goto err_destroy_all;

	if (IS_FLAG_SET(sbi.service_flags, IMAGE_CRC32)) {
		ret = calc_and_add_crc(sbi.disk_op_image.file_id);
		if (ret)
			goto err_destroy_all;
	}

err_destroy_all:
	if (ret)
		hl_list_free(sbi.hlinks_list.next);
	destroy_threads();
	if (!list_empty(&sbi.data_ranges))
		clear_data_range_list(&sbi.data_ranges);
	remove_dlink_files(&sbi);
err_squashfs:
	if (!list_empty(&install_task_list))
		clear_install_task_list(&install_task_list);
	if (!list_empty(&sbi.compress_list))
		clear_install_task_list(&sbi.compress_list);
err_xattr_tree:
	btree_destroy_tree(&sbi.xattrtree);
err_ext_tree:
	btree_destroy_tree(&sbi.exttree);
err_cat_tree:
	btree_destroy_tree(&sbi.cattree);
err_inode_id_alloc:
	destroy_inode_id_alloc(&sbi);
err_space_manager:
	destroy_snapshot(&sbi);
	destroy_space_manager(&sbi);
	if (sbi.dump_file)
		fclose(sbi.dump_file);
	close_disk(&sbi);
	vdfs4_destroy_btree_caches();
err_exit:
	if (ret == 0)
		log_info("Finished successfully");
	else {
		remove_image_file(&sbi);
		log_info("Finished unsuccessfully");
	}
err_before_open:
	if (sbi.squash_list_file)
		fclose(sbi.squash_list_file);
	if (sbi.rsa_key) {
		RSA_free(sbi.rsa_key);
		CRYPTO_cleanup_all_ex_data();
	}
	return ret;
}
