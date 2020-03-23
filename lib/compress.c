/* zpipe.c: example of proper use of zlib's inflate() and deflate()
   Not copyrighted -- provided to the public domain
   Version 1.4	11 December 2005  Mark Adler */

/* Version history:
   1.0	30 Oct 2004  First version
   1.1	 8 Nov 2004  Add void casting for unused return values
					 Use switch statement for inflate() return values
   1.2	 9 Nov 2004  Add assertions to document zlib guarantees
   1.3	 6 Apr 2005  Remove incorrect assertion in inf()
   1.4	11 Dec 2005  Add hack to avoid MSDOS end-of-line conversions
					 Avoid some compiler warnings for input and output buffers
 */

/* Origina source and explanation is here:
 * http://www.zlib.net/zlib_how.html */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>
#include <lzoconf.h>
#include <lzo1x.h>
#include <vdfs_tools.h>
#include <compress.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

int processors = 1;
char *compressor_names[VDFS4_COMPR_NR] = {
	[VDFS4_COMPR_UNDEF] = NULL,
	[VDFS4_COMPR_ZLIB] = "zlib",
	[VDFS4_COMPR_LZO] = "lzo",
	[VDFS4_COMPR_XZ] = "xz",
	[VDFS4_COMPR_LZMA] = "lzma",
	[VDFS4_COMPR_GZIP] = "gzip",
	[VDFS4_COMPR_ZHW] = "zhw",
	[VDFS4_COMPR_NONE] = NULL,
};

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */
enum compr_type get_compression_type(char *type_string)
{
	int comp_type;
	for (comp_type = 0; comp_type < VDFS4_COMPR_NR; comp_type++)
		if (!strcmp(type_string, "default"))
			return VDFS4_COMPR_ZLIB;
		else if (compressor_names[comp_type] &&
		    !strcmp(type_string, compressor_names[comp_type]))
			return comp_type;
	return -1;
}


int add_compression_info(int dst_fd, int chunks_num, int file_size,
		const struct vdfs4_comp_extent *ext,
		int compress_type, unsigned char **hash,
		RSA *rsa_key, off_t *c_size, int log_chunk_size,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len)
{
	int ret = 0;
	struct vdfs4_comp_file_descr _descr, *descr = &_descr;
	char *magic = NULL;
	ssize_t written, aligned_size;
	u_int32_t crc;
	size_t h_size = (chunks_num + 1) * hash_len +
				VDFS4_CRYPTED_HASH_LEN;
	struct stat f_stat;
	char buffer[VDFS4_BLOCK_SIZE];
	memset(descr, 0x0, sizeof(*descr));
	memset(buffer, 0x0, VDFS4_BLOCK_SIZE);

	if (chunks_num == 0)
		return 0;
	/* align the dst_fd to block size */
	ret = fstat(dst_fd, &f_stat);
	if (ret == -1)
		return ret;

	aligned_size = ALIGN(*c_size, sizeof(struct vdfs4_comp_extent))
			- *c_size;
	/*ret = ftruncate(dst_fd, aligned_size);
	if (ret == -1)
		return ret;*/

	lseek(dst_fd, f_stat.st_size + aligned_size, SEEK_SET);
	*c_size += aligned_size;
	switch (compress_type) {
	case VDFS4_COMPR_ZLIB:
		magic = VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_GZIP:
		magic = VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_LZO:
		magic = VDFS4_COMPR_LZO_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_ZHW:
		magic = VDFS4_COMPR_ZHW_FILE_DESCR_MAGIC;
		break;
	default:
		log_error("Incorrect compress type %d", compress_type);
		ret = -EINVAL;
		goto exit;
	}

	if (*hash) {
		if (hash_alg == MD5)
			descr->magic[0] = VDFS4_MD5_AUTH;
		else if (hash_alg == SHA256)
			descr->magic[0] = VDFS4_SHA256_AUTH;
		else if (hash_alg == SHA1)
			descr->magic[0] = VDFS4_SHA1_AUTH;
	} else
		descr->magic[0] = VDFS4_COMPR_DESCR_START;

	memcpy(descr->magic + 1, magic, sizeof(descr->magic) - 1);
	descr->extents_num = chunks_num;
	descr->unpacked_size = file_size;
	descr->layout_version = VDFS4_COMPR_LAYOUT_VER;
	descr->log_chunk_size = log_chunk_size;

	if (rsa_key) {
		unsigned char *extended_hash_table = NULL;

		extended_hash_table = realloc(*hash, h_size);
		if (extended_hash_table)
			*hash = extended_hash_table;
		else {
			errno = ENOMEM;
			return -1;
		}
		/*Sign tuned file*/
		assert(hash);

		hash_alg((const unsigned char *)descr,
			(char *)&descr->crc - (char *)descr,
			*hash + hash_len * chunks_num);

		ret = sign_rsa(*hash, hash_len *
				(chunks_num + 1), *hash + hash_len *
				(chunks_num + 1), rsa_key, hash_alg, hash_len);
		if (ret) {
			log_error("Error when signing hash");
			return ret;
		}
	}
	crc = crc32_body(0, (const __u8 *)ext, chunks_num * sizeof(*ext));
	if (*hash)
		crc = crc32_body(crc, *hash, h_size);
	descr->crc = crc32_body(crc, (const __u8 *)descr, sizeof(*descr));

	/* write chunk table */
	written = write(dst_fd, ext, chunks_num * sizeof(*ext));
	if (written != (ssize_t)(sizeof(*ext) * chunks_num)) {
		errno = (written == -1) ? errno : ENOSPC;
		goto exit;
	} else
		*c_size += written;

	/* write hash table */
	if (*hash) {
		written = write(dst_fd, *hash, h_size);
		if (written != (ssize_t)h_size) {
			errno = (written == -1) ? errno : ENOSPC;
			goto exit;
		} else
			*c_size += written;
	}


	/* write descriptor */
	written = write(dst_fd, descr, sizeof(*descr));
	if (written != sizeof(*descr)) {
		errno = (written == -1) ? errno : ENOSPC;
		goto exit;
	} else {
		*c_size += written;
	}
exit:
	return ret;
}
#define LZO_OUT_LEN	()

static int compress_chunk(unsigned char *in, unsigned char *out,
		int chunk_size, int compress_type,
		struct vdfs4_comp_extent *c_ext, int *c_size,
		int volume_chunk_size)
{
	int ret = 0;
#ifdef COMPRESS_RATIO
	int have_compress_ratio = 0;
	int compress_ratio = atoi(COMPRESS_RATIO);

	if (compress_ratio < 0 || compress_ratio > 100)
		compress_ratio = 75;
#endif
	*c_size = chunk_size;
	ret = compressor[compress_type](in, chunk_size, out, c_size);
	if (ret)
		return ret;
#ifdef COMPRESS_RATIO
	have_compress_ratio = ((chunk_size - *c_size) * 100) / chunk_size;
	if ((chunk_size == *c_size) ||
		(have_compress_ratio > compress_ratio)) {
		/* the chunk is uncompressed */
#else
		if (chunk_size <= *c_size) {
#endif
			c_ext->len_bytes = chunk_size;
			/* Fill vdfs4 extent */
			c_ext->flags |= VDFS4_CHUNK_FLAG_UNCOMPR;
	} else {
		c_ext->len_bytes = chunk_size - *c_size;
		/* the chunk is compressed */
		/* gzip chunks has to be aligned to 8 bytes for HW */
		if ((compress_type == VDFS4_COMPR_GZIP) && (volume_chunk_size ==
				(VDFS4_HW_COMPR_PAGE_PER_CHUNK << PAGE_SHIFT))) {
			c_ext->len_bytes = ALIGN(c_ext->len_bytes, 8);
			*c_size = chunk_size - c_ext->len_bytes;
		} else if ((compress_type == VDFS4_COMPR_ZHW)&&
				(volume_chunk_size ==
				(VDFS4_HW_COMPR_PAGE_PER_CHUNK << PAGE_SHIFT))) {
			c_ext->len_bytes = ALIGN(c_ext->len_bytes, 16);
			*c_size = chunk_size - c_ext->len_bytes;
		}
	}

	return 0;
}



void compress_chunk_thread(void *arg)
{
	struct thread_info *tinfo = (struct thread_info *)arg;
	struct vdfs4_comp_extent *cur_ext = NULL;
	int compressed_size;
	int ret = 0, written;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	while (!tinfo->exit) {

		pthread_mutex_lock(&tinfo->compress_mutex);

		while (!(tinfo->has_data)) {
			pthread_cond_wait(&tinfo->compress_cond,
					&tinfo->compress_mutex);
			if (tinfo->exit) {
				pthread_mutex_unlock(&tinfo->compress_mutex);
				return;
			}
		}
		tinfo->has_data = 0;
		ret = 0;
		if (*tinfo->error) {
			ret = *tinfo->error;
			pthread_mutex_unlock(&tinfo->compress_mutex);
			goto err_exit;
		}
		pthread_mutex_unlock(&tinfo->compress_mutex);

		cur_ext = &tinfo->ext_table[tinfo->count - 1];
		memset(cur_ext, 0x0, sizeof(struct vdfs4_comp_extent));
		memset(tinfo->out, 0, tinfo->chunk_size);
		memcpy(cur_ext->magic, VDFS4_COMPR_EXT_MAGIC,
				sizeof(cur_ext->magic));

		if (tinfo->src_file_size < (VDFS4_BLOCK_SIZE << 1)) {
			cur_ext->len_bytes = tinfo->in_size;
			/* Fill vdfs4 extent */
			cur_ext->flags |= VDFS4_CHUNK_FLAG_UNCOMPR;
		} else {
			ret = compress_chunk(tinfo->in, tinfo->out,
					tinfo->in_size, tinfo->compress_type,
					cur_ext, &compressed_size,
					tinfo->chunk_size);
			if (ret) {
				ret = -errno;
				goto err_exit;
			}
		}
		if (cur_ext->flags & VDFS4_CHUNK_FLAG_UNCOMPR) {
			/*UNCOMPRESSED CHUNK*/
			if (tinfo->compress_type == VDFS4_COMPR_GZIP &&
				tinfo->chunk_size ==
				(VDFS4_HW_COMPR_PAGE_PER_CHUNK
						<< PAGE_SHIFT)
						&& tinfo->in_size % 8 ) {
				memset(tinfo->in + tinfo->in_size, 0,
						ALIGN(tinfo->in_size, 8) -
						tinfo->in_size);
				tinfo->in_size = ALIGN(tinfo->in_size, 8);
			} else if (tinfo->compress_type == VDFS4_COMPR_ZHW &&
				tinfo->chunk_size ==
					(VDFS4_HW_COMPR_PAGE_PER_CHUNK
						<< PAGE_SHIFT)
					&& (tinfo->in_size % 16)) {
				memset(tinfo->in + tinfo->in_size, 0, 16 -
						(tinfo->in_size % 16));
				tinfo->in_size = ALIGN(tinfo->in_size, 16);
			}
			pthread_mutex_lock(&thread_file[tinfo->parent_thread].
					write_uncompr_mutex);
			written = write(tinfo->tmp_uncompr_fd, tinfo->in,
					tinfo->in_size);
			cur_ext->start = *tinfo->unpacked_offset;
			*tinfo->unpacked_offset += written;
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_uncompr_mutex);
			if (written != tinfo->in_size) {
				ret = (written == -1) ? -errno : -ENOSPC;
				goto err_exit;
			}

		} else {
			/*COMPRESSED CHUNK*/
			pthread_mutex_lock(&thread_file[tinfo->parent_thread].
					write_compr_mutex);
			compressed_size = tinfo->in_size - compressed_size;
			written = write(tinfo->tmp_compr_fd, tinfo->out,
					compressed_size);
			cur_ext->start = *tinfo->packed_offset;
			*tinfo->packed_offset += written;
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_compr_mutex);
			if (written != compressed_size) {
				ret = (written == -1) ? -errno : -ENOSPC;
				goto err_exit;
			}


		}

		if (tinfo->hash_table) {
			/*CALCULATE HASH FOR CHUNK*/
			unsigned char *data = (cur_ext->flags &
					VDFS4_CHUNK_FLAG_UNCOMPR) ? tinfo->in :
							tinfo->out;
			ssize_t data_size = cur_ext->len_bytes;
			tinfo->hash_alg((const unsigned char *)data, data_size,
					tinfo->hash_table
					+ tinfo->hash_len * (tinfo->count - 1));
		}
err_exit:
		pthread_mutex_lock(
				&thread_file[tinfo->parent_thread].write_mutex);
		if (ret)
			*tinfo->error = ret;
		*tinfo->new_file_size += written;
		if (!--*tinfo->chunks) {
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_mutex);

			pthread_cond_signal(&thread_file[tinfo->parent_thread].
					finished);
		} else
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_mutex);
		pthread_mutex_lock(&tinfo->compress_mutex);
		tinfo->is_free = 1;
		pthread_mutex_unlock(&tinfo->compress_mutex);
		pthread_cond_broadcast(&thread_free_cond);

	}
}



int get_free_thread()
{
	int i;
	struct timespec timewait;
	timewait.tv_sec = 0;
	timewait.tv_nsec = 1000000;
	while (1) {
		for (i = 0; i < processors; i++) {
			pthread_mutex_lock(&thread[i].compress_mutex);
				if (thread[i].is_free) {
					thread[i].is_free = 0;
					pthread_mutex_unlock(&thread[i].
							compress_mutex);
					return i;
				}
				pthread_mutex_unlock(&thread[i].compress_mutex);
		}
		pthread_mutex_lock(&thread_free_mutex);
		pthread_cond_timedwait(&thread_free_cond, &thread_free_mutex,
				&timewait);
		pthread_mutex_unlock(&thread_free_mutex);
	}

}
static int prepare_file_descr(struct vdfs4_comp_file_descr *descr,
		int compress_type, int chunks, int src_file_size,
		int log_chunk_size, int hash,
		vdfs4_hash_algorithm_func *hash_alg)
{
	char *magic;
	int ret = 0;
	memset(descr, 0x0, sizeof(*descr));
	switch (compress_type) {
	case VDFS4_COMPR_ZLIB:
		magic = VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_GZIP:
		magic = VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_LZO:
		magic = VDFS4_COMPR_LZO_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_ZHW:
		magic = VDFS4_COMPR_ZHW_FILE_DESCR_MAGIC;
		break;
	default:
		log_error("Incorrect compress type %d", compress_type);
		ret = -EINVAL;
		goto err_exit;
	}
	if (hash) {
		if (hash_alg == MD5)
			descr->magic[0] = VDFS4_MD5_AUTH;
		else if (hash_alg == SHA256)
			descr->magic[0] = VDFS4_SHA256_AUTH;
		else if (hash_alg == SHA1)
			descr->magic[0] = VDFS4_SHA1_AUTH;
	} else
		descr->magic[0] = VDFS4_COMPR_DESCR_START;

	memcpy(descr->magic + 1, magic, sizeof(descr->magic) - 1);
	descr->extents_num = chunks;
	descr->unpacked_size = src_file_size;
	descr->layout_version = VDFS4_COMPR_LAYOUT_VER;
	descr->log_chunk_size = log_chunk_size;
err_exit:
	return ret;
}

/* the compress_file returns chunks count */
static int compress_file_tune(int src_fd, int dst_fd,
		int tmp_fd, int compress_type, struct vdfs4_comp_extent **ext,
		unsigned char **hash, off_t *new_file_size, int log_chunk_size,
		off_t src_file_size, vdfs4_hash_algorithm_func *hash_alg,
		int hash_len)
{
	int ret = 0;
	size_t packed_offset = 0, unpacked_offset = 0;
	ssize_t written = 0, avail_in = 0;
	int count = 0;
	struct vdfs4_comp_extent *ext_table = NULL, *extended_ext_table = NULL;
	unsigned char *hash_table = NULL, *extended_hash_table = NULL;
	int chunk_size = 1 << log_chunk_size;
	unsigned char *in = malloc(chunk_size);
	unsigned char *out = malloc(chunk_size + chunk_size / 16 + 64 + 3);

	if (!in || !out) {
		ret = ENOMEM;
		goto err_exit;
	}

	if (compress_type < 0 || compress_type >= VDFS4_COMPR_NR) {
		ret = -1;
		errno = EINVAL;
		goto err_exit;
	}
	memset(in, 0x0, chunk_size);

	avail_in = read(src_fd, in, chunk_size);
	for (count = 1; avail_in; count++, avail_in = read(src_fd, in,
				chunk_size)) {
		struct vdfs4_comp_extent *cur_ext = NULL;
		int compressed_size;


		if (avail_in == -1) {
			ret = -1;
			goto err_exit;
		}
		extended_ext_table = realloc(ext_table,
				count * sizeof(*ext_table));
		if (extended_ext_table == NULL) {
			errno = ENOMEM;
			ret = -1;
			goto err_exit;
		}
		ext_table = extended_ext_table;
		cur_ext = &ext_table[count - 1];
		memset(cur_ext, 0x0, sizeof(*ext_table));
		memset(out, 0, chunk_size);
		memcpy(cur_ext->magic, VDFS4_COMPR_EXT_MAGIC,
				sizeof(cur_ext->magic));

		if (src_file_size < (VDFS4_BLOCK_SIZE << 1)) {
			cur_ext->len_bytes = avail_in;
			/* Fill vdfs4 extent */
			cur_ext->flags |= VDFS4_CHUNK_FLAG_UNCOMPR;
		} else {

			ret = compress_chunk(in, out, avail_in,
					compress_type, cur_ext,
					&compressed_size, chunk_size);
			if (ret) {
				errno = ret;
				ret = -1;
				goto err_exit;
			}
		}
		if (cur_ext->flags & VDFS4_CHUNK_FLAG_UNCOMPR) {
			/* chunk is uncompressed */
			if (compress_type == VDFS4_COMPR_GZIP
					&& ALIGN(avail_in, 8) != avail_in) {

				memset(in + avail_in, 0, ALIGN(avail_in, 8)
						- avail_in);
				avail_in = ALIGN(avail_in, 8);
			} else if (compress_type == VDFS4_COMPR_ZHW &&
				(avail_in % 16)) {
				memset(in + avail_in, 0, 16 - (avail_in % 16));
				avail_in = ALIGN(avail_in, 16);
			}
			written = write(dst_fd, in, avail_in);
			if (written != avail_in) {
				errno = (written == -1) ? errno : ENOSPC;
				ret = -1;
				goto err_exit;
			}
			cur_ext->start = unpacked_offset;
			unpacked_offset += written;
		} else {
			/* chunk is compressed */
			compressed_size = avail_in - compressed_size;
			written = write(tmp_fd, out, compressed_size);
			if (written != compressed_size) {
				errno = (written == -1) ? errno : ENOSPC;
				ret = -1;
				goto err_exit;
			}
			cur_ext->start = packed_offset;
			packed_offset += written;
		}

		if (hash) {
			unsigned char *data = (cur_ext->flags &
					VDFS4_CHUNK_FLAG_UNCOMPR) ? in : out;
			ssize_t data_size = cur_ext->len_bytes;

			extended_hash_table = realloc(hash_table, count *
					hash_len);
			if (extended_hash_table == NULL) {
				errno = ENOMEM;
				ret = -1;
				goto err_exit;
			}
			hash_table = extended_hash_table;
			hash_alg((const unsigned char *)data, data_size, hash_table
					+ hash_len * (count - 1));
		}

		*new_file_size += written;
	}
	count--;

	/* copy  chunks */
	ret = lseek(tmp_fd, 0, SEEK_SET);
	if (ret == -1)
		goto err_exit;

	while ((avail_in = read(tmp_fd, in, chunk_size)) > 0)
		write(dst_fd, in, avail_in);

	if (avail_in == -1)
		goto err_exit;

	if (hash)
		*hash = hash_table;
	*ext = ext_table;

	/* update compressed chunks offsets */
	for (ret = 0; ret < count; ret++) {
		if (!(ext_table[ret].flags & VDFS4_CHUNK_FLAG_UNCOMPR))
			ext_table[ret].start += unpacked_offset;
	}

	free(in);
	free(out);

	return count;

err_exit:
	if (ext)
		*ext = ext_table;
	if (hash)
		*hash = hash_table;
	free(in);
	free(out);
	return ret;
}


void wait_file_finish(int *count, int parent_thread)
{

	int a = 0;
	struct timespec timewait;
	timewait.tv_sec = 1;
	timewait.tv_nsec = 0;
	while (1) {
		pthread_mutex_lock(&thread_file[parent_thread].
							write_mutex);

		a = *count;


		if (a) {
			pthread_mutex_unlock(&thread_file[parent_thread].write_mutex);
			pthread_mutex_lock(&thread_file[parent_thread].compress_mutex);
			pthread_cond_timedwait(&thread_file[parent_thread].finished,
					&thread_file[parent_thread].compress_mutex,
					&timewait);
			pthread_mutex_unlock(&thread_file[parent_thread].compress_mutex);
		} else {
			pthread_mutex_unlock(&thread_file[parent_thread].write_mutex);
			return;
		}
	}
}

/* the compress_file returns chunks count */
static int compress_file(struct vdfs4_sb_info *sbi, int src_fd,
		int tmp_uncompr_fd, int dst_fd, int tmp_fd, int compress_type,
		struct vdfs4_comp_extent **ext,
		unsigned char **hash, off_t *new_file_size, int log_chunk_size,
		off_t src_file_size, RSA *rsa_key, u_int64_t *block,
		int parent_thread)
{
	int ret = 0;
	size_t packed_offset = 0, unpacked_offset = 0;
	ssize_t  avail_in = 0;
	int count = 0, ret_thread = 0;
	struct vdfs4_comp_file_descr __descr, *descr = &__descr;
	struct vdfs4_comp_extent *ext_table = NULL;
	struct vdfs4_comp_extent *extended_ext_table = NULL;
	unsigned char *hash_table = NULL;
	unsigned char *extended_hash_table = NULL;
	int chunk_size = 1 << log_chunk_size;
	unsigned char *in = malloc(chunk_size);
	int hash_len = sbi->hash_len;
	if (compress_type < 0 || compress_type >= VDFS4_COMPR_NR) {
		ret = -1;
		errno = EINVAL;
		goto err_exit;
	}
	int chunks = ALIGN(src_file_size, chunk_size) / chunk_size;
	thread_file[parent_thread].chunks_count = chunks;
	extended_ext_table = realloc(ext_table,
			chunks * sizeof(struct vdfs4_comp_extent));
	if (extended_ext_table == NULL) {
		errno = ENOMEM;
		ret = -1;
		goto err_exit;
	}
	ext_table = extended_ext_table;
	if (hash) {
		extended_hash_table = realloc(hash_table, chunks *
				hash_len);
		if (extended_hash_table == NULL) {
			errno = ENOMEM;
			ret = -1;
			goto err_exit;
		}
		hash_table = extended_hash_table;
	}
	for (count = 1; count <= chunks; count++) {
		avail_in = read(src_fd, in, chunk_size);
		if (avail_in == -1) {
			ret = -1;
			goto err_exit;
		}
		int thread_num = get_free_thread();

		thread[thread_num].chunks =
				&thread_file[parent_thread].chunks_count;
		thread[thread_num].src_fd = src_fd;
		thread[thread_num].chunk_size = chunk_size;
		thread[thread_num].compress_type = compress_type;
		thread[thread_num].count = count;
		thread[thread_num].tmp_uncompr_fd = tmp_uncompr_fd;
		memcpy(thread[thread_num].in, in, chunk_size);
		thread[thread_num].in_size = avail_in;
		thread[thread_num].tmp_compr_fd = tmp_fd;
		thread[thread_num].ext_table = ext_table;
		thread[thread_num].hash_table = hash_table;
		pthread_mutex_lock(&thread[thread_num].compress_mutex);
		thread[thread_num].has_data = 1;
		thread[thread_num].error = &ret_thread;
		thread[thread_num].new_file_size = new_file_size;
		thread[thread_num].unpacked_offset = &unpacked_offset;
		thread[thread_num].packed_offset = &packed_offset;
		thread[thread_num].src_file_size = src_file_size;
		thread[thread_num].parent_thread = parent_thread;

		ret = pthread_cond_signal(&thread[thread_num].compress_cond);
		pthread_mutex_unlock(&thread[thread_num].compress_mutex);
		if (ret != 0)
			goto err_exit;

	}

	wait_file_finish(&thread_file[parent_thread].chunks_count, parent_thread);

	*ext = ext_table;
	if (hash)
		*hash = hash_table;

	if (ret_thread) {
		ret = ret_thread;
		goto err_exit;
	}
	count--;

	/* update compressed chunks offsets */
	for (ret = 0; ret < count; ret++) {
		if (!(ext_table[ret].flags & VDFS4_CHUNK_FLAG_UNCOMPR))
			ext_table[ret].start += unpacked_offset;
	}

	ret = prepare_file_descr(descr, compress_type, chunks, src_file_size,
			log_chunk_size, hash_table ? 1 : 0, sbi->hash_alg);
	if (ret)
		goto err_exit;

	if (rsa_key) {
		unsigned char *extended_hash_table = NULL;

		extended_hash_table = realloc(hash_table, (chunks + 1) *
				hash_len + VDFS4_CRYPTED_HASH_LEN);
		if (extended_hash_table)
			hash_table = extended_hash_table;
		else {
			ret = -ENOMEM;
			goto err_exit;
		}
		*hash = hash_table;
		/*Sign tuned file*/
		assert(hash_table);
		sbi->hash_alg((const unsigned char *)descr,
			(char *)&descr->crc - (char *)descr,
			hash_table + hash_len * chunks);

		ret = sign_rsa(hash_table, hash_len *
				(chunks + 1), hash_table + hash_len *
				(chunks + 1),
				rsa_key, sbi->hash_alg, sbi->hash_len);
		if (ret) {
			log_error("Error when signing hash");
			goto err_exit;
		}
	}



	int aligned_size = ALIGN(*new_file_size,
			sizeof(struct vdfs4_comp_extent)) - *new_file_size;
	size_t h_size = (chunks + 1) * hash_len +
				VDFS4_CRYPTED_HASH_LEN;
	pthread_mutex_lock(&write_file_mutex);

	if (!IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE) &&
			!sbi->space_manager_info.space_manager_list) {
		ret = -ENOSPC;
		goto err_write_exit;
	}

	int dst_offset = get_metadata_size(sbi);
	lseek(dst_fd, dst_offset, SEEK_SET);
	unpacked_offset = 0;
	for (ret = 0; ret < count; ret++) {
		if ((ext_table[ret].flags & VDFS4_CHUNK_FLAG_UNCOMPR)) {
			int align = 0;
			if (compress_type == VDFS4_COMPR_GZIP && chunk_size ==
					(VDFS4_HW_COMPR_PAGE_PER_CHUNK
							<< PAGE_SHIFT))
				align = ALIGN(ext_table[ret].len_bytes, 8)
				- ext_table[ret].len_bytes;
			else if (compress_type == VDFS4_COMPR_ZHW && chunk_size ==
					(VDFS4_HW_COMPR_PAGE_PER_CHUNK
							<< PAGE_SHIFT))
				align =  ALIGN(ext_table[ret].len_bytes, 16)
				- ext_table[ret].len_bytes;

			lseek(tmp_uncompr_fd, ext_table[ret].start, SEEK_SET);
			avail_in = read(tmp_uncompr_fd, in,
					ext_table[ret].len_bytes + align);
			if (avail_in != (ssize_t)(ext_table[ret].len_bytes
					+ align)) {
				ret = -1;
				goto err_write_exit;
			}
			ext_table[ret].start = unpacked_offset;

			unpacked_offset += ext_table[ret].len_bytes + align;
			write(dst_fd, in, avail_in);
		}
	}
	__u32 crc = crc32_body(0, (const __u8 *)ext_table,
			chunks * sizeof(*ext_table));
	if (hash_table)
		crc = crc32_body(crc, hash_table, (chunks + 1) * hash_len +
				VDFS4_CRYPTED_HASH_LEN);
	descr->crc = crc32_body(crc, (const __u8 *)descr, sizeof(*descr));
	ret = lseek(tmp_fd, 0, SEEK_SET);
	if (ret == -1)
		goto err_write_exit;

	while ((avail_in = read(tmp_fd, in, chunk_size)) > 0)
		write(dst_fd, in, avail_in);

	/* write chunk table */
	struct stat f_stat;
	ret = fstat(dst_fd, &f_stat);
	if (ret == -1)
		goto err_write_exit;

	lseek(dst_fd, f_stat.st_size + aligned_size, SEEK_SET);
	*new_file_size += aligned_size;
	int written = write(dst_fd, ext_table, chunks * sizeof(*ext_table));
	if (written != (ssize_t)(sizeof(*ext_table) * chunks)) {
		ret = (written == -1) ? -errno : -ENOSPC;
		goto err_write_exit;
	} else
		*new_file_size += written;

	/* write hash table */
	if (hash_table) {
		written = write(dst_fd, hash_table, h_size);
		if (written != (ssize_t)h_size) {
			ret = (written == -1) ? -errno : -ENOSPC;
			goto err_write_exit;
		} else
			*new_file_size += written;
	}


	/* write descriptor */
	written = write(dst_fd, descr, sizeof(*descr));
	if (written != sizeof(*descr)) {
		ret = (written == -1) ? -errno : -ENOSPC;
		goto err_write_exit;
	} else {
		*new_file_size += written;
	}
	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		__u64 begin = find_data_duplicate(&sbi->data_ranges,
				sbi->disk_op_image.file_id,
				sbi->disk_op_image.file_id,
				dst_offset, *new_file_size);
		if (begin) {
			*block = ALIGN(begin, sbi->block_size) / sbi->block_size;;
			ftruncate(sbi->disk_op_image.file_id, dst_offset);
			ret = 0;
			goto exit;
		}
	}
	u_int64_t begin = ALIGN(dst_offset, sbi->block_size) / sbi->block_size;
	uint32_t count_blocks = (u_int32_t)(ALIGN(*new_file_size,
			sbi->block_size) / sbi->block_size);
	ret = allocate_space(sbi,  begin, count_blocks, block);
	if (ret) {
		log_error("Can't allocate space - %s", strerror(-ret));
		goto err_write_exit;
	}

	if (IS_FLAG_SET(thread_file[parent_thread].sbi->service_flags,
			READ_ONLY_IMAGE))
		add_data_range(sbi, &sbi->data_ranges, (*block << PAGE_SHIFT),
				*new_file_size);
exit:
	pthread_mutex_unlock(&write_file_mutex);
	free(in);
	return count;
err_write_exit:
	pthread_mutex_unlock(&write_file_mutex);
err_exit:
	if (ext)
		*ext = ext_table;
	if (hash)
		*hash = hash_table;
	free(in);
	return ret;
}


#if 0
static inline int is_magic_set(struct vdfs4_comp_file_descr *descr,
		const char *magic)
{
	return !memncmp(descr->magic + 1, magic, strlen(magic));
}
#else
#define is_magic_set(descr, magic_str) !memcmp((descr)->magic + 1, (magic_str),\
		sizeof((magic_str)) - 1)
#endif

int analyse_existing_file(int rd_fd,
		int *compress_type, int *chunks_num, off_t *src_file_size,
		off_t *data_area_size, struct vdfs4_comp_extent **extents,
		int *is_authenticated, int *log_chunk_size)
{
	struct vdfs4_comp_file_descr descr;
	int ret = 0;
	off_t file_size;

	ret = get_file_size(rd_fd, &file_size);
	if (ret)
		return ret;

	if (file_size < (off_t)sizeof(struct vdfs4_comp_file_descr)) {
		*compress_type = VDFS4_COMPR_NONE;
		*chunks_num = 0;
		*extents = NULL;
		return 0;
	}

	ret = read_descriptor_info(rd_fd, &descr, data_area_size, extents,
			compress_type, file_size, log_chunk_size);
	if (ret == -EINVAL) {
		*compress_type = VDFS4_COMPR_NONE;
	} else if (ret == 0) {
		*chunks_num = le16_to_cpu(descr.extents_num);
		*src_file_size = le64_to_cpu(descr.unpacked_size);

		if (descr.magic[0] == VDFS4_MD5_AUTH ||
			descr.magic[0] == VDFS4_SHA1_AUTH ||
			descr.magic[0] == VDFS4_SHA256_AUTH) {
			*is_authenticated = 1;
		} else if (descr.magic[0] != VDFS4_COMPR_DESCR_START) {
			*compress_type = VDFS4_COMPR_NONE;
			*chunks_num = 0;
			*extents = NULL;
		}
		if (descr.layout_version != VDFS4_COMPR_LAYOUT_VER) {
			log_error("Wrong VDFS4 COMPRESSED FILE LAYOUT VERSION -"
					" %d, current version - %d",
					descr.layout_version,
					VDFS4_COMPR_LAYOUT_VER);
			return -EINVAL;
		}
	}
	return 0;
}

int check_file_before_compress(const char *filename, int need_compress,
		mode_t *src_mode)
{
	int ret = 0;
	struct stat stat_info;
	memset(&stat_info, 0, sizeof(struct stat));
	ret = stat(filename, &stat_info);
	if (ret < 0) {
		int err = errno;
		log_error("Can't get stat info of %s because of %s",
				filename, strerror(err));
		return err;
	}
	*src_mode = stat_info.st_mode;
	if (!S_ISREG(*src_mode)) {
		log_error("Source file %s is not regular file", filename);
		return -EINVAL;
	}
	if (need_compress && stat_info.st_size < MIN_COMPRESSED_FILE_SIZE)
		return -ENOTCOMPR;
	return ret;
}


int encode_file(struct vdfs4_sb_info *sbi, char *src_filename, int dst_fd,
		int need_compress, int compress_type, off_t *rsl_filesize,
		RSA *rsa_key, int sign_dlink, int log_chunk_size,
		const char *tmp_dir, u_int64_t *block, int thread_num,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len)
{
	int src_fd;
	int tmp_dst_fd = -1, tmp_uncompr_fd = -1;

	char *compr_name = NULL;
	char *uncompr_name = NULL;
	if (thread_num >= 0) {
		compr_name =thread_file[thread_num].compr_temp;
		uncompr_name = thread_file[thread_num].uncompr_temp;
	} else {
		compr_name =tempnam(tmp_dir, "comprXXXXXX");
	}

	off_t src_file_size;
	int ret;
	RSA *__rsa_key = rsa_key;
	int is_authenticated = 0;
	/* If the file was really compressed. Not already! Actual only if
	 * compression requested. Unused if compression is not requested, even
	 * if the source file is already compressed by tune utility.
	 * There's no guarantee that file can be actually compressed, because
	 * uncompressed contents. So even if compression requested we need to
	 * treat this file as common, though return -ENOTCOMPR.
	 */
	struct vdfs4_comp_extent *extents = NULL;
	unsigned char *hash_table = NULL;
	int chunks_num = 0, infile_compression;
	off_t data_area_size;
	int _log_chunk_size = 0;


	*rsl_filesize = 0;

	src_fd = open(src_filename, O_RDONLY);
	if (src_fd == -1) {
		ret = errno;
		log_error("error %s while opening file %s for read",
				strerror(errno), src_filename);
		goto rel_src_fd;
	}
	ret = get_file_size(src_fd, &src_file_size);
	if (ret)
		goto rel_src_fd;

	/* check: is file encoded? */
	ret = analyse_existing_file(src_fd, &infile_compression,
			&chunks_num, &src_file_size, &data_area_size, &extents,
			&is_authenticated, &_log_chunk_size);
	if (ret) {
		log_error("cannot analyse the input file");
		goto rel_src_fd;
	}

	if (infile_compression != VDFS4_COMPR_NONE) {
		log_error("Input file is compressed");

		ret = -EINVAL;
		goto rel_extents;
	}
	if (sbi && IS_FLAG_SET(sbi->service_flags, SIGN_ALL)) {
		__rsa_key = rsa_key;
	} else {
		if (!sign_dlink)
			__rsa_key = (is_need_sign(src_fd) > 0) ?
					rsa_key : NULL;
		else if (!(IS_FLAG_SET(sign_dlink, VDFS4_AUTH_FILE)))
			__rsa_key = NULL;
	}
	tmp_dst_fd = open(compr_name, O_RDWR | O_CREAT | O_TRUNC);
	if (tmp_dst_fd == -1) {
		ret = errno;
		log_error("%s temporary file %s", strerror(ret),
				compr_name);
		goto rel_src_fd;
	}
	unlink(compr_name);
	if (thread_num >= 0) {
		tmp_uncompr_fd = open(uncompr_name, O_RDWR | O_CREAT | O_TRUNC);
		if (tmp_uncompr_fd == -1) {
			ret = errno;
			log_error("%s temporary file %s", strerror(ret),
					uncompr_name);
			close(tmp_dst_fd);
			goto rel_src_fd;
		}
		unlink(uncompr_name);
	}
	if (need_compress) {
		infile_compression = compress_type;
		if (thread_num >= 0)
			chunks_num = compress_file(sbi, src_fd, tmp_uncompr_fd,
					dst_fd, tmp_dst_fd, compress_type,
					&extents, (__rsa_key) ?
					&hash_table : NULL,  rsl_filesize,
					log_chunk_size, src_file_size,
					__rsa_key, block, thread_num);
		else
			chunks_num = compress_file_tune(src_fd, dst_fd,
					tmp_dst_fd, compress_type, &extents,
					(__rsa_key) ? &hash_table : NULL,
					rsl_filesize, log_chunk_size,
					src_file_size, hash_alg, hash_len);
		if (chunks_num < 0) {
			ret = chunks_num;
			if (ret == -ENOTCOMPR) {
				compress_type = VDFS4_COMPR_NONE;
				/* For Gzip compression */
				*rsl_filesize =  src_file_size;
			} else {
				goto rel_extents;
			}
		}
	}

rel_extents:
	if (tmp_dst_fd >= 0)
		close(tmp_dst_fd);
	if (tmp_uncompr_fd >= 0)
		close(tmp_uncompr_fd);
	if ((thread_num < 0) && !ret)
		ret = add_compression_info(dst_fd, chunks_num,
				src_file_size, extents, infile_compression,
				&hash_table, __rsa_key, rsl_filesize,
				log_chunk_size, hash_alg, hash_len);
	free(extents);
	free(hash_table);

rel_src_fd:
	if (thread_num < 0)
		free(compr_name);
	if (src_fd != -1)
		close(src_fd);

	return ret;
}

static int __compress_zlib_gzip_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen, int is_gzip)
{
	int ret = 0;

	/* GZIP parameters for hw2 decompressor */
	int window_size = is_gzip ? 12+16 : 15;
	int level = is_gzip ? Z_DEFAULT_COMPRESSION : Z_BEST_COMPRESSION;

	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	ret = deflateInit2(&strm, level, Z_DEFLATED, window_size,
			8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		return ret;
	strm.avail_in = ilen;
	strm.next_in = ibuff;
	strm.avail_out = *olen;
	strm.next_out = obuff;
	ret = deflate(&strm, Z_FINISH);
	if (ret == Z_OK || strm.avail_out >= (unsigned int) ilen) {
		/* Incompressible chunk */
		*olen = ilen;
		memcpy(obuff, ibuff, ilen);
	} else {
		assert(ret == Z_STREAM_END);
		*olen = strm.avail_out;
	}

	(void)deflateEnd(&strm);
	if (ret != Z_STREAM_END)
		return ret;
	return 0;
}

int compress_zlib_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	return __compress_zlib_gzip_chunk(ibuff, ilen, obuff, olen, 0);
}

int compress_gzip_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	return __compress_zlib_gzip_chunk(ibuff, ilen, obuff, olen, 1);
}

int compress_lzo_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	int ret = 0;
	int new_olen = *olen;
	lzo_voidp wrkmem[LZO1X_999_MEM_COMPRESS];
	ret = lzo_init();
	if (ret != LZO_E_OK) {
		log_error("internal error - lzo_init() failed !!!\n");
		goto exit;
	}
	ret = lzo1x_999_compress(ibuff, ilen, obuff, (lzo_uintp)&new_olen,
			wrkmem);
	if (ret != LZO_E_OK) {
		log_error("%d: lzo compress error\n", ret);
		goto exit;
	}
	if (new_olen >= ilen) {
		*olen = ilen;
		memcpy(obuff, ibuff, ilen);
	} else
		*olen -= new_olen;
exit:
	return ret;
}

int not_supported_compressor(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	/* Silent gcc warnings */
	(void) ibuff;
	(void) ilen;
	(void) obuff;
	(void) olen;

	log_error("Compressor is not supported");
	return -ENOTSUP;
}

/* report a zlib or i/o error */
void zerr(int ret)
{
	fputs("zlib: ", stderr);
	switch (ret) {
	case Z_ERRNO:
		if (ferror(stdin))
			fputs("error reading stdin\n", stderr);
		if (ferror(stdout))
			fputs("error writing stdout\n", stderr);
		break;
	case Z_STREAM_ERROR:
		fputs("invalid compression level\n", stderr);
		break;
	case Z_DATA_ERROR:
		fputs("invalid or incomplete deflate data\n", stderr);
		break;
	case Z_MEM_ERROR:
		fputs("out of memory\n", stderr);
		break;
	case Z_VERSION_ERROR:
		fputs("zlib version mismatch!\n", stderr);
	}
}

/* Should correspond to enum compr_type*/
int (*compressor[VDFS4_COMPR_NR])(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen) = {
	[VDFS4_COMPR_ZLIB]	= compress_zlib_chunk,
	[VDFS4_COMPR_LZO]	= compress_lzo_chunk,
	[VDFS4_COMPR_XZ]		= not_supported_compressor,
	[VDFS4_COMPR_LZMA]	= not_supported_compressor,
	[VDFS4_COMPR_GZIP]	= compress_gzip_chunk,
	[VDFS4_COMPR_ZHW]	= compress_zlib_chunk,
};

int parse_list_cmd(struct install_task *sqt, char *cmd_str)
{
	char *cmd = cmd_str;
	char *next_cmd = NULL;
	char *type = NULL;
	int ret = 0;
	while (cmd) {
		next_cmd = strpbrk(cmd, ",");
		if (next_cmd)
			memcpy(next_cmd, "\0", 1);
		if (!strncmp(cmd, "COMPRESS", strlen("COMPRESS"))) {
			sqt->cmd |= CMD_COMPRESS;
			type = cmd;
			if (type[strlen("COMPRESS")] == '=')
				strsep(&type, "=");
			if (type)
				sqt->compress_type = get_compression_type(type);
			if (sqt->compress_type < 0 || !type) {
				ret = -EINVAL;
				goto exit;
			}
		} else if (!strncmp(cmd, "DLINK", strlen("DLINK"))) {
			if ((sqt->cmd & CMD_COMPRESS) ||
					(sqt->cmd & CMD_DLINK)) {
				log_error("Duplicate command: COMPRESS");
				return -EINVAL;
			}
			sqt->cmd |= CMD_COMPRESS | CMD_DLINK;
			type = cmd;
			if (type[strlen("DLINK")] == '=')
				strsep(&type, "=");
			if (type)
				sqt->compress_type = get_compression_type(type);
			if (sqt->compress_type < 0 || !type) {
				ret = -EINVAL;
				goto exit;
			}
		} else {
			ret = -ENOTCMD;
			return ret;
		}


		if (next_cmd)
			cmd = ++next_cmd;
		else
			break;

	}

exit:
	if (ret)
		log_error("Incorrect format of config file");
	return ret;
}

int get_wsp_separated_payload(char **src, char *whitespace, char *payload)
{
	const char *orig_start = *src, *payl_start;
	int whsp_len, payl_len;
	while (**src && isspace(**src))
		++(*src);
	if (whitespace != NULL) {
		whsp_len = *src - orig_start;
		strncpy(whitespace, orig_start, whsp_len);
		whitespace[whsp_len] = 0;
	}

	payl_start = *src;
	while (**src && !isspace(**src))
		++(*src);
	payl_len = *src - payl_start;
	strncpy(payload, payl_start, payl_len);
	payload[payl_len] = 0;
	return payl_len;
}

/**
 * @brief	todo
 * @param [in]	sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int preprocess_sq_tasklist(struct vdfs4_sb_info *sbi,
		struct list_head *install_task_list)
{
	struct install_task *sqt;
	int ret = 0;
	char cmd[VDFS4_FULL_PATH_LEN];
	if (strlen(sbi->root_path) > VDFS4_FULL_PATH_LEN) {
		log_error("Can't work with files list because of length of root"
				" path is more than %d", VDFS4_FULL_PATH_LEN);
		return -EINVAL;
	}

	for (;;) {
		char wsp[VDFS4_FULL_PATH_LEN], payl[VDFS4_FULL_PATH_LEN];
		char *cur = cmd;
		char *dst;
		int i;

		if (!fgets(cmd, VDFS4_FULL_PATH_LEN - 1,
				sbi->squash_list_file))
			break;

		get_wsp_separated_payload(&cur, NULL, payl);
		if (strlen(payl) == 0)
			continue;

		sqt = malloc(sizeof(struct install_task));
				if (!sqt) {
					log_error("not enough memory");
					return -ENOMEM;
				}

		memset(sqt, 0, sizeof(*sqt));
		strncpy(sqt->src_full_path, sbi->root_path,
				VDFS4_FULL_PATH_LEN);
		sqt->compress_type = VDFS4_COMPR_NONE;



		ret = parse_list_cmd(sqt, payl);
		if (ret) {
			goto err;
		} else {
			get_wsp_separated_payload(&cur, NULL, payl);
			strncat(sqt->src_full_path, payl, VDFS4_FULL_PATH_LEN);
		}
		if ((sqt->cmd & CMD_DLINK) &&
			!IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
			log_error("Can use DLINK command only for read-only "
					"images (without -z option)");
			ret = -EINVAL;
			goto err;
		}
		dst = sqt->src_full_path;
		while (get_wsp_separated_payload(&cur, wsp, payl)) {
			if (payl[0] == '/')
				dst = sqt->dst_parent_dir;
			else
				strncat(dst, wsp, VDFS4_FULL_PATH_LEN);

			strncat(dst, payl, VDFS4_FULL_PATH_LEN);
		}

		if ((sqt->cmd & CMD_COMPRESS) && !sbi->dl_inf.compression_type)
			sbi->dl_inf.compression_type = sqt->compress_type;

		if (sqt->src_full_path[strlen(sbi->root_path)] != '/') {
			log_error("Incorrect source path - %s. Must be"
				" - /%s",
				&sqt->src_full_path[strlen(sbi->root_path)],
				&sqt->src_full_path[strlen(sbi->root_path)]);
			ret = -EINVAL;
			goto err;
		}

		for (i = strlen(sqt->src_full_path) - 1; i >= 0; i--)
			if (sqt->src_full_path[i] == '/') {
				sqt->src_fname = &sqt->src_full_path[++i];
					break;
			}
		if (sqt->cmd & CMD_DLINK) {
			if (!sbi->rsa_key) {
				log_error("Wrong config file:"
					"Command DLINK can be used only "
					"with authentication options"
					"(-H rsa key)");
				ret = -EINVAL;
				goto err;
			}
			struct install_task *sqt_dlink = malloc(sizeof(
					struct install_task));
			if (!sqt_dlink) {
				log_error("not enough memory");
				return -ENOMEM;
			}
			memcpy(sqt_dlink, sqt, sizeof(struct install_task));
			list_add(&sqt_dlink->list, &sbi->compress_list);
		}
		list_add(&sqt->list, install_task_list);
	}
	return 0;
err:
	config_file_format();
	free(sqt);
	return ret;
}

static __u64 __find_parent_id(struct vdfs4_sb_info *sbi, __u64 parent_id,
		char *name)
{
	struct vdfs4_cattree_record *record = vdfs4_cattree_find(
		&sbi->cattree.vdfs4_btree, parent_id, name, strlen(name),
		VDFS4_BNODE_MODE_RW);
	if (IS_ERR(record))
		return PTR_ERR(record);

	parent_id = le64_to_cpu(record->key->object_id);

	vdfs4_release_record((struct vdfs4_btree_gen_record *)record);
	return parent_id;
}

struct vdfs4_cattree_record *find_record(struct vdfs4_sb_info *sbi,
		char *path)
{
	int i, len = strlen(path);
	char *name = "root";
	__u64 parent_id = 0;

	for (i = 0; i < len; i++) {
		if (path[i] == '/') {
			path[i] = 0;
			parent_id = __find_parent_id(sbi, parent_id, name);
			path[i] = '/';
			if (IS_ERR_VALUE(parent_id)) {
				log_error("%s - %s", path,
						strerror(-parent_id));
				return ERR_PTR(parent_id);
			}
			name = &path[i + 1];
			if (name[0] == '/')
				name++;
		}
	}
	return vdfs4_cattree_find(&sbi->cattree.vdfs4_btree, parent_id, name,
			strlen(name), VDFS4_BNODE_MODE_RW);
}

int get_free_file_thread(void)
{
	int i;
	struct timespec timewait;
	timewait.tv_sec = 0;
	timewait.tv_nsec = 1000000;
	while (1) {
		for (i = 0; i < processors; i++) {
			pthread_mutex_lock(&thread_file[i].compr_file_mutex);
			if (thread_file[i].is_free) {
				thread_file[i].is_free = 0;
				pthread_mutex_unlock(&thread_file[i].
						compr_file_mutex);
				return i;
			}
			pthread_mutex_unlock(&thread_file[i].compr_file_mutex);
		}
		pthread_mutex_lock(&thread_file_free_mutex);
		pthread_cond_timedwait(&thread_file_free_cond,
				&thread_file_free_mutex, &timewait);
		pthread_mutex_unlock(&thread_file_free_mutex);
	}


}


void compress_file_thread(void *arg)
{
	struct thread_file_info *tinfo = (struct thread_file_info *)arg;
	int ret = 0;
	off_t new_file_size = 0;
	u_int64_t  begin, block = 0;
	int sign_dlink = 0;
	struct vdfs4_catalog_file_record *f_rec = NULL;
	struct vdfs4_cattree_record *record = NULL;
	__mode_t src_mode;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	/*Do not repeat copy data for hlinks*/
	while (!tinfo->exit) {
		sign_dlink = 0;
		pthread_mutex_lock(&tinfo->compr_file_mutex);
		while (!(tinfo->has_data)) {
			pthread_cond_wait(&tinfo->compr_file_cond,
					&tinfo->compr_file_mutex);
			if (tinfo->exit) {
				pthread_mutex_unlock(&tinfo->compr_file_mutex);
				return;
			}
		}
		tinfo->has_data = 0;
		record = NULL;
		ret = 0;
		pthread_mutex_unlock(&tinfo->compr_file_mutex);
		/*parent_id != 0 only for dlink records*/
		pthread_mutex_lock(&files_count_mutex);
		if (*tinfo->error) {
			ret = *tinfo->error;
			pthread_mutex_unlock(&files_count_mutex);
			goto exit;
		}
		pthread_mutex_unlock(&files_count_mutex);
		if (!tinfo->parent_id) {

			record = find_record(tinfo->sbi,
					&tinfo->ptr->src_full_path[strlen(
						tinfo->sbi->root_path)]);

		} else {
			record = vdfs4_cattree_find(
					&tinfo->sbi->cattree.vdfs4_btree,
					tinfo->parent_id,
					NULL, 0, VDFS4_BNODE_MODE_RW);

			sign_dlink |= (1 << VDFS4_COMPRESSED_FILE);
			if (tinfo->ptr->cmd & CMD_AUTH)
				sign_dlink |= (1 << VDFS4_AUTH_FILE);
		}
		if (IS_ERR(record)) {
			ret = PTR_ERR(record);
			goto err_exit;
		}

		if (record->key->record_type == VDFS4_CATALOG_HLINK_RECORD) {
			pthread_mutex_lock(&find_record_mutex);
			__u64 obj_id = record->key->object_id;
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
			record = vdfs4_cattree_find(
					&tinfo->sbi->cattree.vdfs4_btree,
					obj_id, NULL, 0, VDFS4_BNODE_MODE_RW);
			f_rec = (struct vdfs4_catalog_file_record *)
					(record->val);
			if (IS_FLAG_SET(f_rec->common.flags,
					VDFS4_COMPRESSED_FILE)) {
				log_info("File %s has been copied already",
						tinfo->ptr->src_full_path);
				pthread_mutex_unlock(&find_record_mutex);
				goto exit;
			} else {
				if (tinfo->ptr->cmd & CMD_COMPRESS)
					f_rec->common.flags |=
						(1 << VDFS4_COMPRESSED_FILE);
				if (tinfo->ptr->cmd & CMD_DLINK)
					f_rec->common.flags |=
							(1 << SIGNED_DLINK);
			}
			pthread_mutex_unlock(&find_record_mutex);
		} else {
			f_rec = (struct vdfs4_catalog_file_record *)
					(record->val);
			if (IS_FLAG_SET(f_rec->common.flags,
					VDFS4_COMPRESSED_FILE)) {
				log_info("File %s has been copied already",
						tinfo->ptr->src_full_path);
				goto exit;
			}
		}
		if (IS_FLAG_SET(f_rec->common.flags, VDFS4_IMMUTABLE)) {
			log_info("File %s has been installed. Mkfs"
					" will not compress installed file",
					tinfo->ptr->src_full_path);
			goto exit;
		}

		if (record->key->record_type == VDFS4_CATALOG_DLINK_RECORD) {
			pthread_mutex_lock(&find_record_mutex);
			if (tinfo->ptr->cmd & CMD_COMPRESS) {
				f_rec->common.flags |=
						(1 << VDFS4_COMPRESSED_FILE);
				if (tinfo->sbi->rsa_key &&
					(!S_ISLNK(f_rec->common.file_mode))) {
					int fd = open(tinfo->ptr->src_full_path,
							O_RDONLY);
					if (fd < 0) {
						ret = errno;
						perror("can not open file"
								" for reading");
						if (ret == EACCES)
							printf("Don't"
							" you forget sudo?\n");
						pthread_mutex_unlock(
							&find_record_mutex);
						goto err_exit;
					}
					if (IS_FLAG_SET(tinfo->sbi->service_flags,
							SIGN_ALL) ||
							is_need_sign(fd)) {
						f_rec->common.flags |=
							(1 << VDFS4_AUTH_FILE);
					}
					close(fd);
				}
			}
			pthread_mutex_unlock(&find_record_mutex);
			goto exit;
		}

		ret = check_file_before_compress(tinfo->ptr->src_full_path,
				tinfo->ptr->cmd & CMD_COMPRESS, &src_mode);
		if (ret) {
			if (ret == -ENOTCOMPR) {
				log_info("File %s was not compressed because "
						"of too small size",
						tinfo->ptr->src_full_path);
				ret = 0;
			}
			goto err_exit;
		}

		if (tinfo->ptr->cmd & CMD_COMPRESS)
			log_info("Compress file %s", tinfo->ptr->src_full_path);

		ret = encode_file(tinfo->sbi, tinfo->ptr->src_full_path,
				tinfo->sbi->disk_op_image.file_id,
				tinfo->ptr->cmd & CMD_COMPRESS,
				tinfo->ptr->compress_type, &new_file_size,
				tinfo->rsa_copy, sign_dlink,
				tinfo->sbi->log_chunk_size,
				tinfo->sbi->tmpfs_dir, &block,
				(tinfo->thread_num - 1), tinfo->sbi->hash_alg,
				tinfo->sbi->hash_len);

		if (!new_file_size)
			goto exit;

		if (ret) {
			if (ret == -ENOTCOMPR) {
				ret = 0;
			} else {
				log_error("Compression error - %d,"
						" file - %s", ret,
						tinfo->ptr->src_full_path);
				goto err_exit;
			}
		} else {
			pthread_mutex_lock(&find_record_mutex);
			if (tinfo->ptr->cmd & CMD_COMPRESS)
				f_rec->common.flags |=
						(1 << VDFS4_COMPRESSED_FILE);
			if (tinfo->ptr->cmd & CMD_DLINK)
				f_rec->common.flags |=
						(1 << SIGNED_DLINK);
			pthread_mutex_unlock(&find_record_mutex);
		}

		begin = block_to_byte(block, tinfo->sbi->block_size);
		fork_init(&f_rec->data_fork, begin, new_file_size,
				tinfo->sbi->block_size);


err_exit:
exit:
		pthread_mutex_lock(&files_count_mutex);
		if (ret)
			*tinfo->error = ret;
		if (!IS_ERR(record) && record)
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
		if (!--*tinfo->count) {
			pthread_mutex_unlock(&files_count_mutex);
			pthread_cond_broadcast(&file_finished);
		} else
			pthread_mutex_unlock(&files_count_mutex);
		pthread_mutex_lock(&tinfo->compr_file_mutex);
		tinfo->is_free = 1;
		pthread_mutex_unlock(&tinfo->compr_file_mutex);
		pthread_cond_broadcast(&thread_file_free_cond);

	}

}


void wait_finish(int *count)
{
	int a = 0;
	struct timespec timewait;
	timewait.tv_sec = 1;
	timewait.tv_nsec = 0;
	while (1) {

		pthread_mutex_lock(&files_count_mutex);

		a = *count;


		if (a) {
			pthread_mutex_unlock(&files_count_mutex);
			pthread_mutex_lock(&file_finished_mutex);
			pthread_cond_timedwait(&file_finished,
					&file_finished_mutex,
					&timewait);
			pthread_mutex_unlock(&file_finished_mutex);

		} else {
			pthread_mutex_unlock(&files_count_mutex);
			return;
		}
	}
}

static int compress_dir(struct vdfs4_sb_info *sbi,
		struct install_task *ptr)
{
	int ret = 0, ret_thread = 0;
	DIR *dir;
	char *path = NULL;
	struct dirent *data;
	struct stat info;
	struct install_task obj_ptr;
	int count = 0;
	char *dirpath = ptr->src_full_path;
	if (ptr->cmd & CMD_COMPRESS)
		log_info("Recursive compress directory %s",
				dirpath);
	else if (ptr->cmd & CMD_COMPRESS)
		log_info("Recursive compress directory %s", dirpath);
	dir = opendir(dirpath);

	if (dir == NULL) {
		log_info("%s %s", "Can't open dir", dirpath);
		return errno;
	}
	obj_ptr.cmd = ptr->cmd;
	obj_ptr.compress_type = ptr->compress_type;
	while ((data = readdir(dir)) != NULL) {
		if ((strcmp(data->d_name, ".") == 0) ||
				(strcmp(data->d_name, "..") == 0))
			continue;
		path = calloc(1, strlen(dirpath) + strlen(data->d_name) + 2);
		if (!path) {
			ret = -ENOMEM;
			goto exit;
		}
		strncat(path, dirpath, strlen(dirpath));
		if (path[strlen(dirpath) - 1] != '/')
			strncat(path, "/", 1);
		strncat(path, data->d_name, strlen(data->d_name));
		memset(obj_ptr.src_full_path, 0, sizeof(obj_ptr.src_full_path));
		memcpy(obj_ptr.src_full_path, path, strlen(path));
		obj_ptr.src_fname = data->d_name;
		ret = lstat(path, &info);
		if (ret)
			goto exit;
		if (S_ISDIR(info.st_mode)) {
			memcpy(obj_ptr.src_full_path + strlen(path), "/", 1);
			ret = compress_dir(sbi, &obj_ptr);
			if (ret)
				goto exit;
		} else if (((S_ISREG(info.st_mode)) ||
			(IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)
			&& S_ISLNK(info.st_mode))) && (info.st_size)) {

			int tnum = get_free_file_thread();
			pthread_mutex_lock(&thread_file[tnum].compr_file_mutex);
			memcpy(thread_file[tnum].ptr, &obj_ptr,
					sizeof(struct install_task));
			thread_file[tnum].parent_id = 0;
			thread_file[tnum].sbi = sbi;
			thread_file[tnum].has_data = 1;
			thread_file[tnum].is_free = 0;
			thread_file[tnum].error = &ret_thread;
			pthread_mutex_lock(&files_count_mutex);
			count++;

			thread_file[tnum].count = &count;
			pthread_mutex_unlock(&files_count_mutex);
			pthread_cond_signal(&thread_file[tnum].compr_file_cond);
			pthread_mutex_unlock(
					&thread_file[tnum].compr_file_mutex);
		}

		free(path);
		path = NULL;
	}
	wait_finish(&count);
	ret = ret_thread;
exit:
	free(path);
	closedir(dir);
	return ret;
}

void clear_install_task_list(struct list_head *install_task_list)
{
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, install_task_list) {
		struct install_task *ptr =
			list_entry(pos, struct install_task, list);
		list_del(pos);
		free(ptr);
	}
}


int tune_files(struct vdfs4_sb_info *sbi,
		struct list_head *install_task_list) {
	int ret = 0, ret_thread = 0;
	struct list_head *pos;
	struct stat stat_info;
	int count = 0;
	for (pos = install_task_list->next; pos != install_task_list;
				pos = pos->next) {
		struct install_task *ptr =
			list_entry(pos, struct install_task, list);
		if ((ptr->cmd & CMD_COMPRESS)) {
			ret = lstat(ptr->src_full_path, &stat_info);
			if (ret) {
				log_error("Can't get stat info of %s",
						ptr->src_full_path);
				ret = errno;
				goto exit;
			}
			if (S_ISREG(stat_info.st_mode)) {
				/*ret = compress_file(sbi, ptr, 0);
				if (ret) {
					log_error("Can't process file %s",
							ptr->src_full_path);
					goto exit;
				}*/
				if (!stat_info.st_size)
					continue;
				int tnum = get_free_file_thread();
				pthread_mutex_lock(&thread_file[tnum].
						compr_file_mutex);
				memcpy(thread_file[tnum].ptr, ptr,
						sizeof(struct install_task));
				thread_file[tnum].parent_id = 0;
				thread_file[tnum].sbi = sbi;
				thread_file[tnum].has_data = 1;
				pthread_mutex_lock(&files_count_mutex);
				count++;
				thread_file[tnum].count = &count;
				thread_file[tnum].error = &ret_thread;
				pthread_mutex_unlock(&files_count_mutex);
				pthread_cond_signal(&thread_file[tnum].
						compr_file_cond);
				pthread_mutex_unlock(&thread_file[tnum].
						compr_file_mutex);
			} else if (S_ISDIR(stat_info.st_mode)) {
				ret = compress_dir(sbi, ptr);
				if (ret)
					goto exit;
			} else {
				log_error("Incorrect type of %s. "
					"Can be regular file or directory only",
					ptr->src_full_path);
				ret = -EINVAL;
				goto exit;
			}
		}
	}

	wait_finish(&count);
	ret = ret_thread;
exit:
	return ret;
}

