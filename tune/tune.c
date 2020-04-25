/**
 * @file	vdfs4-tools/install/install.c
 * @brief	squashfs image installation for vdfs4.
 * @author	Igor Skalkin, i.skalkin@samsung.com
 * @date	13.03.2013
 *
 * eMMCFS -- Samsung eMMC chip oriented File System, Version 1.
 *
 * @see         TODO: documents
 *
 * Copyright 2011 by Samsung Electronics, Inc.,
 *
 * This software is the confidential and proprietary information
 * of Samsung Electronics, Inc. ("Confidential Information").  You
 * shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement
 * you entered into with Samsung.
 */
#define _GNU_SOURCE
#include "compress.h"
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "zlib.h"
#include "vdfs_tools.h"
#include <ftw.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

struct vdfs_image_info {
	int fd;
	__u64 squashfs_file_size;
	__u64 *id_table;
	__u64 *xattr_id_table;
	__u64 xattr_offset;
	__u64 xattr_offset_tmp;
	__u64 *inode_lookup_table;
	__u64 *fragment_index;
	__u32 nfs_info_size_in_bytes;
	struct vdfs4_pack_nfs_item *nfs_info;
	int (*decompressor)(unsigned char *, int, unsigned char *, int*);
	bool metadata_gzip_padding;

	struct vdfs_tools_btree_info tree;
	char *filename;/* squashfs image to expand/install/revert */
	char *dirname;  /* directory name to install/unlink */
	char *src_filename; /*input and output files for  */
	char *dst_filename; /* compress/decompress*/
	char *src_dirname;
	char *dst_dirname;
	int compress_type;
	char toggle_decode;
	int src_fd;
	int dst_fd;
	int cmdline;
	char is_expanded;
	char is_installed;

	__u32 chunk_cnt;	/* count of chunks in image */
	__u32 chunk_table_size;	/* chunk table size (in items) */
	struct chunk_table_item *chunk_tab; /* chunk table */

	__u32 tiny_count;
	__u32 fragment_count;
	__u32 chunks_count;

	__u64 old_root_obj_id;

	/* Seems that it's somewhere already defined */
	RSA *rsa_key;
	char *rsa_private_file;
	char *rsa_pub_file;
	vdfs4_hash_algorithm_func *hash_alg;
	int hash_len;
	struct hlink_list_item hlinks_list;
	int log_chunk_size;
};


struct vdfs_image_info img_info;


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


/**
 * @brief	Print install.vdfs4 usage options.
 *		Shown in case of wrong parameters.
 * @return	void
 */
void print_usage(void)
{
	printf("Usage: tune.vdfs4 <command>[v [verbose_lvl default LOG_ALL]]"
		" [file] < -o [output file] >\n"
	"where <command> is\n"
	"--compress [zlib/lzo/gzip/zhw/default] src_file -o dst_file"
			" - compress src_file with\n"
			" current compression type to dst_file. "
			"In case of default option zlib will be used.\n"

	"--decompress src_file -o dst_file - decompress src_file to dst_file.\n"
	"Additional options is:\n"
	"-o dst_file - output file for compress/decompress.\n"
			"\t(Use only with"
			" options compress/decompress).\n"
	"-b block_size --block_size block_size chunk block size\n\n"
	"-t [ON/OFF] [file] - set decode (decompression) status"
			" for file.\n"
	"-H [rsa private key file] - sign file by rsa(use only with compress)\n"
	"-H [rsa private_exp key file] -P [rsa pub_modulus key file] -\n"
	"\t sign file by rsa(use only with compress)\n"
	"only file name without options - print file information. File can be:\n"
			"\t-vdfs4 image\n"
			"\t-squashfs image\n"
			"\t-compressed file\n"
			"\t-ordinary file.\n"
	"--sha256 - select SHA256 algorithm for hash calculation\n(has sense only"
		"when -H option is specified); default algorithm is MD5\n"
	"--sha1 - select MD5 algorithm for hash calculation\n(has sense only"
		"when -H option is specified); default algorithm is MD5\n"


	"Examples:\n"
	"tune.vdfs --compress zlib src_file -o dst_file - compress src_file"
			" data to dst_file with type zlib.\n"
	"tune.vdfs --decompress src_file -o dst_file - decompress src_file"
			" data to dst_file.\n"
	"tune.vdfs -t ON file - switch on decompression of"
		" file.\n"
	"tune.vdfs -t OFF file - switch off decompression of"
		" file.\n"
	"tune.vdfs -H rsa_private.pem -o -c zlib file -o out_file-"
			"\ncompress file to out_file and sign out_file by"
			"rsa private key.\n"
	"tune.vdfs -H rsa_private.exp -P rsa_pub.mod -o -c zlib file -o"
	" out_file-"
			"\ncompress file to out_file and sign out_file by"
			"rsa from two files in special formats:"
			"rsa_private exponent and rsa_public modulus.\n"
	"tune.vdfs4 file - print information about file.\n");
}

static int missing_one_of_cmd(int cmd_word, int first_cmd, int sec_cmd)
{
	return (!((cmd_word & first_cmd) && ((cmd_word & sec_cmd))));
}

static int toggle_decode(struct vdfs_image_info *inf, char *cmd)
{
	int ret = 0;
	inf->cmdline |= CMD_ON_OFF_DECODE;
	if (!strcmp(cmd, "ON"))
		inf->toggle_decode = CMD_ENABLE;
	else if (!strcmp(cmd, "OFF"))
		inf->toggle_decode = CMD_DISABLE;
	else if (!strcmp(cmd, "GET"))
		inf->toggle_decode = CMD_GET_STATUS;
	else {
		log_error("Invalid option %s. Can be:"
				" ON OFF GET", cmd);
		ret = -EWRONGOPTS;
	}
	return ret;

}

/**
 * @brief	Parse parameters from command line.
 * @param [in]	argc	Number of command line parameters.
 * @param [in]	argv[]	An array with command line parameters strings.
 * @param [in]	sbi	A pointer to the image information structure.
 * @return	0 if parsed successfully, or error.
 */
int parse_cmd(int argc, char *argv[], struct vdfs_image_info *inf,
		enum logger_level *log_level)
{
	const char *short_options = "erfv::c:do:t:H:P:b:";
	const struct option long_options[] = {
		{"verbose",	optional_argument,	NULL, 'v'},
		{"compress",	required_argument,	NULL, 'c'},
		{"decompress",	no_argument,	NULL, 'd'},
		{"output_file",	required_argument,	NULL, 'o'},
		{"decompression",	required_argument,	NULL, '1'},
		{"toggle-decode",	required_argument,	NULL, 't'},
		{"hash-rsa-key",	required_argument,	NULL, 'H'},
		{"pub-rsa-key",	required_argument,	NULL, 'P'},
		{"block_size", required_argument,	NULL, 'b'},
		{"sha256",	no_argument,		NULL, '3'},
		{"sha1",	no_argument,		NULL, '4'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0;
	int long_index = 0;
	int ret_code = 0;
	int block_size;

	optind = 0;
	/* default action - prepare if its needed and install */
	inf->cmdline = 0;

	while ((opt = getopt_long(argc, argv,
		short_options, long_options, &long_index)) != EOF) {

		if (opt == ':' || opt == ('?')) {
			ret_code = -EWRONGOPTS;
			goto print_usage;
		}

		switch (opt) {
		case 'c':
			inf->cmdline |= CMD_COMPRESS;
			if (!optarg) {
				log_error("No compression type chosen");
				ret_code = -EINVAL;
				goto print_usage;
			}
			inf->compress_type = get_compression_type(optarg);
			if (inf->compress_type < 0)  {
				log_error("Incorrect compression type %s",
						optarg);
				ret_code = -EINVAL;
				goto print_usage;
			}
			break;

		case 'd':
			inf->cmdline |= CMD_DECOMPRESS;
			break;
		case 'H':
			inf->rsa_private_file = optarg;
			break;
		case 'P':
			inf->rsa_pub_file = optarg;
			break;
		case 'o':
			inf->cmdline |= CMD_OUTPUT;
			inf->dst_filename = optarg;
			break;
		case 'v':
			if (optarg) {
				*log_level = atoi(optarg);
				if (*log_level > LOG_ALL)
					*log_level = LOG_ALL;
			} else
				*log_level = LOG_ALL;
			break;
		case 't':
			if (!optarg) {
				log_error("No toggle decode value set");
				ret_code = -EINVAL;
				goto print_usage;
			}
			ret_code = toggle_decode(inf, optarg);
			if (ret_code)
				goto print_usage;
			break;
		case 'b':
			if (!optarg) {
				log_error("Block size is not set");
				ret_code = EINVAL;
				goto print_usage;
			}

			block_size = atoi(optarg);
			inf->log_chunk_size = slog(block_size);
			break;
		case '3':
			inf->hash_alg = SHA256;
			inf->hash_len = VDFS4_SHA256_HASH_LEN;
			break;
		case '4':
			inf->hash_alg = SHA1;
			inf->hash_len = VDFS4_SHA1_HASH_LEN;
			break;
		}
	}

	if (inf->log_chunk_size == 0)
		inf->log_chunk_size = 17;

	if (inf->cmdline == 0)
		inf->cmdline = CMD_SHOW_FILE_INFO;

	if ((inf->cmdline & (CMD_OUTPUT | CMD_COMPRESS | CMD_DECOMPRESS)) &&
		(missing_one_of_cmd(inf->cmdline, CMD_OUTPUT, CMD_COMPRESS
			| CMD_DECOMPRESS))) {
			log_error("Option -o must be used with options "
					" --compress, --decompress");
			ret_code= -EWRONGOPTS;
			goto print_usage;
	}

	/* At list one filename or directory name must presence */
	if ((argc - 1) < optind) {
		log_error("No image name / directory name given");
		ret_code = -EWRONGOPTS;
		goto print_usage;
	}
	/* Check short commands
		install.vdfs4 -e image      - Expand squashfs image
		install.vdfs4 -u dir        - Uninstall image from directory
		install.vdfs4 -r image      - Revert image*/
	if (inf->rsa_private_file) {
		inf->rsa_key = create_rsa(inf->rsa_private_file,
				inf->rsa_pub_file, NULL, NULL);
		if (!inf->rsa_key) {
			log_error("Wrong rsa key file");
			return -EWRONGOPTS;
		}
	}
	if ((inf->cmdline & (CMD_COMPRESS | CMD_DECOMPRESS)) ||
			(inf->cmdline == CMD_ON_OFF_DECODE) ||
			(inf->cmdline == CMD_SHOW_FILE_INFO)) {
		if (!inf->hash_alg) {
			inf->hash_alg = MD5;
			inf->hash_len = VDFS4_MD5_HASH_LEN;
		}
		inf->src_filename = argv[optind];
	} else{
		/* Check long commands */
		if ((argc-2) < optind) {
			log_error("No directory name given");
			ret_code = -EWRONGOPTS;
			goto print_usage;
		}

		if ((argc - 2) > optind) {
			log_error("Too many options");
			ret_code = -EWRONGOPTS;
			goto print_usage;
		}
		inf->filename = argv[optind];
		inf->dirname = argv[optind + 1];
	}

print_usage:
	if (ret_code)
		print_usage();

	return ret_code;
}

char * compress_type[] = {
		"zlib",
		"lzo"
};

static int check_and_create_dst(struct vdfs_image_info *img_info)
{
	int ret = 0;
	mode_t src_mode;

	if (!img_info || !img_info->src_filename || !img_info->dst_filename)
		return -EINVAL;

	ret = check_file_before_compress(img_info->src_filename,
			img_info->cmdline & CMD_COMPRESS, &src_mode);
	if (ret) {
		if (ret == -ENOTCOMPR)
			log_error("File %s size is too small. Can't compress",
					img_info->src_filename);
		return ret;
	}
	img_info->dst_fd = creat(img_info->dst_filename, 0644);
	if (img_info->dst_fd < 0) {
		log_error("Can't create destination file %s because of %s",
				img_info->dst_filename, strerror(errno));
		ret = errno;
	}

	return ret;
}

static int compress_file(struct vdfs_image_info *img_info)
{
	int ret = 0;
	off_t file_size = 0;
	int dst_fd;
	ret = check_and_create_dst(img_info);
	if (ret)
		return ret;

	dst_fd = open(img_info->dst_filename, O_TRUNC | O_RDWR);
	if (dst_fd != -1) {


		ret = encode_file(NULL, img_info->src_filename, dst_fd,
			img_info->cmdline & CMD_COMPRESS,
			img_info->compress_type,
			&file_size, img_info->rsa_key, 0,
			img_info->log_chunk_size, "/tmp", NULL, -1,
			img_info->hash_alg, img_info->hash_len);
		close(dst_fd);
		if (ret) {
			if (ret == -ENOTCOMPR)
				log_error("File can not be compressed");
			else
				unlink(img_info->dst_filename);
		}
	} else {
		ret = errno;
		log_error("error %s while opening file %s for write",
				strerror(errno), img_info->dst_filename);
	}
	return ret;
}

static int decompress_file(struct vdfs_image_info *img_info)
{
	int ret = 0;
	int dst_fd;
	int flags = 0;
	ret = check_and_create_dst(img_info);
	if (ret)
		return ret;

	dst_fd = open(img_info->dst_filename, O_WRONLY | O_TRUNC);
	if (dst_fd == -1) {
		ret = errno;
		perror("can not open destanation file");
		return ret;
	}

	ret = decode_file(img_info->src_filename, dst_fd,
			img_info->cmdline & CMD_DECOMPRESS,
			&flags);

	close(dst_fd);
	return ret;
}

int get_set_decode_ioctl(struct vdfs_image_info *img_info, int *status)
{
	int ret = 0;
	char *status_string = NULL;
	int fd = open(img_info->src_filename, O_RDONLY);
	if (fd < 0) {
		printf("Can not open file %s: %s\n", img_info->src_filename,
				strerror(errno));
		return errno;
	}
	switch (img_info->toggle_decode) {
	case CMD_ENABLE:
	case CMD_DISABLE:
		ret = ioctl(fd, VDFS4_IOC_SET_DECODE_STATUS,
				&img_info->toggle_decode);
		if (ret) {
			log_error ("Set status failed ret=%d: %s\n", ret,
				strerror(errno));
			ret = errno;
			goto exit;
		}
		break;
	case CMD_GET_STATUS: {
		ret = ioctl(fd, VDFS4_IOC_GET_DECODE_STATUS, status);
		if (img_info->cmdline == CMD_SHOW_FILE_INFO) {
			if (ret) {
				ret = -errno;
				*status = UNKNOWN;
			}
			goto exit;
		}

		if (ret) {
			ret = errno;
			*status = UNKNOWN;
			log_error("Getting status failed ret=%d: %s\n",
					ret, strerror(errno));
			goto exit;
		}
		switch (*status) {
		case CMD_ENABLE:
			status_string = "ON";
			break;
		case CMD_DISABLE:
			status_string = "OFF";
			break;
		default:
			ret = -EINVAL;
			goto exit;
		}
			printf("DECODE FILE STATUS is %s\n", status_string);
		break;
	}
	}
exit:
	close(fd);
	return ret;
}

static int get_file_info(struct vdfs_image_info *info)
{
	int ret = 0;
	int fd = open(info->src_filename, O_RDONLY);
	char *type = NULL;
	char *status_string = NULL;
	int compress_type = 0, chunks_num = 0, decoding = 0;
	off_t src_file_size = 0, data_area_size = 0;
	int is_authenticated = 0;
	struct vdfs4_comp_extent *extents = NULL;
	int log_chunk_size = 0;

	if (fd < 0)
		return -errno;
	ret = analyse_existing_file(fd, &compress_type,
			&chunks_num, &src_file_size, &data_area_size, &extents,
			&is_authenticated, &log_chunk_size);

	if (ret)
		goto exit;
	printf("%s INFORMATION:\n", info->src_filename);
	/*get decoding_status from file system*/
	info->toggle_decode = CMD_GET_STATUS;
	ret = get_set_decode_ioctl(info, &decoding);
	if (ret && ret != -ENOTTY)
		goto exit;
	ret = 0;

	if (decoding == CMD_ENABLE) {
		int flags = 0;
		ret = ioctl(fd, VDFS4_IOC_GET_COMPR_TYPE,
				&compress_type);
		if (ret) {
			log_error("Get compression type ioctl error");
			goto exit;
		}
		ret = ioctl(fd, VDFS4_IOC_IS_AUTHENTICATED,
				&flags);
		if (ret) {
			log_error("Get authentification status ioctl error");
			goto exit;
		}
		is_authenticated = flags & (1 << VDFS4_AUTH_FILE);
	}


	if (is_authenticated)
		printf("\tTYPE:\t\tAuthenticated file\n");

	switch (compress_type) {
	case VDFS4_COMPR_ZLIB:
		type = "ZLIB";
		break;
	case VDFS4_COMPR_LZO:
		type = "LZO";
		break;
	case VDFS4_COMPR_GZIP:
		type = "GZIP";
		break;
	}

	if (type)
		printf("\tTYPE:\t\tCompressed file.\n\tCOMPR TYPE:\t%s\n",
				type);



	switch (decoding) {
	case CMD_ENABLE:
		status_string = "ON";
		break;
	case CMD_DISABLE:
		status_string = "OFF";
		break;
	}
	if ((compress_type == VDFS4_COMPR_NONE) &&
			(decoding == CMD_DISABLE || decoding == UNKNOWN))
		printf("\tTYPE:\t\tOrdinary file\n");
	if (status_string)
		printf("\tDECODE FILE STATUS:\t\t%s\n", status_string);

	info->filename = info->src_filename;
exit:
	if (fd >= 0)
		close(fd);
	free(extents);
	return ret;
}


static int process_file(struct vdfs_image_info *img_info)
{
	int rc = 0;
	if (img_info->cmdline == CMD_SHOW_FILE_INFO) {
		rc = get_file_info(img_info);
	} else if (img_info->cmdline & CMD_COMPRESS) {
		rc = compress_file(img_info);
	} else if (img_info->cmdline & CMD_DECOMPRESS) {
		rc = decompress_file(img_info);
	} else if (img_info->cmdline == CMD_ON_OFF_DECODE) {
		int status;
		rc = get_set_decode_ioctl(img_info, &status);
	} else {
		rc = -EINVAL;
	}
	if (!rc && img_info->dst_filename) {
		struct stat info;
		rc = stat(img_info->src_filename, &info);
		if (rc < 0) {
			rc = -errno;
			log_error("Can't get stat info of %s - %s",
					img_info->src_filename,
					strerror(-rc));
			return rc;
		}
		rc = chmod(img_info->dst_filename, info.st_mode);
		if (rc < 0) {
			rc = -errno;
			log_error("Can't change mod of %s - %s",
					img_info->dst_filename, strerror(-rc));
		}
	}
	return rc;
}

int walk_dir(const char *name, const struct stat *st, int type, struct FTW *f)
{
	(void)f;
	int ret = 0;
	/*Make new pathes*/
	img_info.src_filename = (char *)name;
	if (img_info.dst_filename) {
		int new_dst_path_len = strlen(img_info.dst_dirname)
				+ strlen(img_info.src_filename)
				- strlen(img_info.src_dirname) + 1;
		img_info.dst_filename = realloc(img_info.dst_filename,
				new_dst_path_len);
		if (!img_info.dst_filename)
			return -ENOMEM;
		memset(img_info.dst_filename, 0, new_dst_path_len);
		strncat(img_info.dst_filename, img_info.dst_dirname,
				strlen(img_info.dst_dirname));
		strncat(img_info.dst_filename, img_info.src_filename
				+ strlen(img_info.src_dirname),
				strlen(img_info.src_filename) -
				strlen(img_info.src_dirname));
	}
	switch (type) {
	case FTW_SL:
		if (img_info.dst_filename) {
			char *buf = malloc(VDFS4_FULL_PATH_LEN);
			if (!buf)
				return -ENOMEM;
			memset(buf, 0, VDFS4_FULL_PATH_LEN);
			ret = readlink(img_info.src_filename, buf,
					VDFS4_FULL_PATH_LEN);
			if (ret < 0) {
				ret = -errno;
				log_error("Can't read link %s - %s",
						img_info.src_filename,
						strerror(-ret));
				free(buf);
					return -errno;
				return ret;
			}
			ret = symlink(buf, img_info.dst_filename);
			if (ret < 0) {
				ret = -errno;
				log_error("Can't create symlink %s - %s",
						img_info.dst_filename,
						strerror(-ret));
			}
			free(buf);
		}
		break;
	case FTW_F:
		if ((S_ISSOCK(st->st_mode) || S_ISBLK(st->st_mode) ||
			S_ISCHR(st->st_mode) || S_ISFIFO(st->st_mode)) &&
			img_info.dst_filename) {
			if (geteuid() != 0) {
				log_warning("You must be root"
					" to create special file %s",
				img_info.dst_filename);
				return -EPERM;
			}
			ret = mknod(img_info.dst_filename,
					st->st_mode, st->st_dev);
			if (ret) {
				ret = -errno;
				log_error("Can't create special file"
					"%s - %s",
					img_info.dst_filename,
					strerror(-ret));
			}
		} else if (S_ISREG(st->st_mode)) {
			/*Check is hardlink*/
			if (img_info.dst_filename && st->st_nlink > 1) {
				struct hlink_list_item *list_item;
				list_item = hl_list_item_find(
						&img_info.hlinks_list,
						st->st_ino);
				if (list_item) {
					list_item->links++;
					ret = link(list_item->name,
							img_info.dst_filename);
					if (ret) {
						ret = -errno;
						log_error("Can't create link"
							"%s - %s",
							img_info.dst_filename,
							strerror(-ret));
					}
					break;
				} else {
					list_item = malloc(sizeof
						(struct hlink_list_item));
					if (!list_item)
						return -ENOMEM;
					memset(list_item, 0, sizeof
						(struct hlink_list_item));
					hl_list_item_init(list_item, st->st_ino,
						img_info.dst_filename, 0);
					hl_list_insert(&img_info.hlinks_list,
							list_item);
				}
			}
			ret = process_file(&img_info);
		}
		break;
	case FTW_D:
		if (img_info.dst_filename) {
			ret = mkdir(img_info.dst_filename, st->st_mode);
			if (ret) {
				ret = -errno;
				log_error("Can't create directory %s - %s",
						img_info.dst_filename,
						strerror(-ret));
			}
		}
		break;
	case FTW_DNR:
		log_error("Cannot read dir: %s\n", name);
		break;
	}
	return ret;
}

static int rm_files(const char *name, const struct stat *st UNUSED,
		int type, struct FTW *f)
{
	(void)f;
	int ret = 0;
	switch (type) {
	case FTW_DNR:
		fprintf(stderr, "cannot read dir: %s\n", name);
		break;
	case FTW_F:
	case FTW_SL:
	case FTW_D:
	default:
		ret = remove(name);
		break;
	}
	return ret;
}
static int process_dir_or_file()
{
	int rc = 0;
	struct stat stat_info;
	rc = stat(img_info.src_filename, &stat_info);
	if (rc < 0) {
		log_error("Can't get stat info of %s - %s",
				img_info.src_filename, strerror(errno));
		return -errno;
	}
	if (S_ISDIR(stat_info.st_mode)) {
		/*Save src dirpath and dst dirpath*/
		img_info.src_dirname = img_info.src_filename;
		img_info.dst_dirname = img_info.dst_filename;
		if (img_info.dst_filename) {
			img_info.dst_filename = malloc(VDFS4_FILE_NAME_LEN);
			if (!img_info.dst_filename)
				return -ENOMEM;
		}
		rc = nftw(img_info.src_filename, walk_dir, 64,
				FTW_MOUNT | FTW_PHYS);

		free(img_info.dst_filename);
		if (rc && rc != -EEXIST && img_info.dst_dirname)
			nftw(img_info.dst_dirname, rm_files, 64,
					FTW_DEPTH | FTW_PHYS);

		hl_list_free(img_info.hlinks_list.next);
	} else
		rc = process_file(&img_info);
	return rc;

}

int main(int argc, char *argv[])
{
	int rc;
	struct vdfs4_sb_info sbi;
	enum logger_level log_level = LOG_ERRORS;

	print_version();

	memset(&sbi, 0, sizeof(sbi));
	sbi.block_size = PAGE_SIZE; /* todo */
	sbi.super_page_size = sbi.block_size << 2; /* todo */
	memset(&img_info, 0, sizeof(img_info));
	img_info.compress_type = VDFS4_COMPR_NONE;

	rc = parse_cmd(argc, argv, &img_info, &log_level);
	if (rc)
		return rc;

	set_logger_verbosity(log_level);

	rc = vdfs4_init_btree_caches();
	if (rc) {
		log_error("error btree caches init - ENOMEM");
		return rc;
	}

	rc = process_dir_or_file();

	vdfs4_destroy_btree_caches();
	return rc;
}
