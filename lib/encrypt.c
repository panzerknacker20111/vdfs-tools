/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2014 by Samsung Electronics, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "vdfs_tools.h"
#include "compress.h"

int hextoint(char c)
{
	switch (c) {
	case 'a':
		c = 'A';
		break;
	case 'b':
		c = 'B';
		break;
	case 'c':
		c = 'C';
		break;
	case 'd':
		c = 'D';
		break;
	case 'e':
		c = 'E';
		break;
	case 'f':
		c = 'F';
		break;
	default:
		break;
	}
return c > '9' ? c - 'A' + 10 : c - '0';
}

int get_key_from_file(unsigned char *mkey, const char *filename, int m_keysize)
{
	int i, ret, realsize;
	FILE *file;
	unsigned char key[m_keysize];
	unsigned char tmp[m_keysize*2];

	realsize = m_keysize*2;

	file = fopen(filename, "r");
	if (file == NULL) {
		printf("[ERROR] %s does not exist.!!!!\n", filename);
		return -1;
	}
	ret = fread((void *)tmp, sizeof(unsigned char), realsize, file);
	/*if( ret != realsize ) {
		printf("[ERROR] real size and read size"
				" are different (real size:%d,"
				" read size : %d!!!!\n", realsize, ret);
		fclose(file);
		return -1;
	}*/
	for (i = 0; i < realsize; i = i+2) {
		ret = (hextoint((char)tmp[i]) << 4) + hextoint((char)tmp[i+1]);
		key[i/2] = ret;
	}
	memcpy(mkey, key, m_keysize);

	fclose(file);
	return 0;
}

RSA *create_rsa(char *private_key, char *pub_key, char *q_file, char *p_file)
{
	int ret = 0;
	RSA *rs = NULL;
	BN_CTX *ctx = NULL;
	ctx = BN_CTX_new();
	if (ctx == NULL)
		return ERR_PTR(-ENOMEM);
	BN_CTX_start(ctx);

	if (pub_key) {


		int expon = 0x10001;
		unsigned char *modulus = NULL, *private = NULL;
		modulus = malloc(RSA_KEY_SIZE);
		if (!modulus)
			goto err_exit;
		private = malloc(RSA_KEY_SIZE);
		if (!private)
			goto err_exit;
		ret = get_key_from_file(modulus, pub_key, RSA_KEY_SIZE);
		if (ret)
			goto err_exit;
		ret = get_key_from_file(private, private_key, RSA_KEY_SIZE);
		if (ret)
			goto err_exit;
		rs = RSA_new();
		if (!rs)
			goto err_exit;
		rs->ex_data.dummy = 0;
		rs->meth->init(rs);
		rs->n = BN_new();
		rs->d = BN_new();
		rs->e = BN_new();

		BN_bin2bn(modulus, RSA_KEY_SIZE, rs->n);
		BN_bin2bn(private, RSA_KEY_SIZE, rs->d);
		BN_bin2bn((const unsigned char *)&expon, 3, rs->e);
		/*Calculate*/
		if (q_file && p_file) {
			BIGNUM *r1 = NULL, *r2 = NULL;

			unsigned char *p = NULL, *q = NULL;


			r1 = BN_CTX_get(ctx);
			r2 = BN_CTX_get(ctx);
			if (r2 == NULL || r1 == NULL)
				goto err1_exit;
			rs->p = BN_new();
			rs->q = BN_new();
			rs->dmp1 = BN_new();
			rs->dmq1 = BN_new();
			rs->iqmp = BN_new();
			p = malloc(128);
			q = malloc(128);
			if (!p || !q)
				goto err1_exit;
			memset(p, 0, 128);
			memset(q, 0, 128);
			ret = get_key_from_file(p, p_file, 128);
			if (ret)
				goto err1_exit;
			ret = get_key_from_file(q, q_file, 128);
			if (ret)
				goto err1_exit;


			BN_bin2bn(q, 128, rs->q);
			BN_bin2bn(p, 128, rs->p);

			if (!BN_sub(r1, rs->p, BN_value_one()))
				goto err1_exit;	/* p-1 */
			if (!BN_sub(r2, rs->q, BN_value_one()))
				goto err1_exit;	/* q-1 */

			/* calculate d mod (p-1) */
			if (!BN_mod(rs->dmp1, rs->d, r1, ctx))
				goto err1_exit;

			/* calculate d mod (q-1) */
			if (!BN_mod(rs->dmq1, rs->d, r2, ctx))
				goto err1_exit;

			/* calculate inverse of q mod p */
			if (!BN_mod_inverse(rs->iqmp, rs->q, rs->p, ctx))
				goto err1_exit;

err1_exit:

			free(p);
			free(q);

		}
err_exit:
		free(modulus);
		free(private);
	} else {
		FILE *fp = fopen(private_key, "r");
		if (fp == NULL)
			return NULL;
		rs = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
	}
	if (rs && !(rs->flags & RSA_FLAG_NO_BLINDING))
		rs->blinding = RSA_setup_blinding(rs, ctx);
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return rs;

}

int sign_rsa(unsigned char *buf, unsigned long buf_len,
		unsigned char *rsa_hash, RSA *rsa_key,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len)
{
	int ret = 0;
	unsigned char hash[VDFS4_CRYPTED_HASH_LEN];
	memset(hash, 0, VDFS4_CRYPTED_HASH_LEN);
	hash_alg(buf, buf_len, hash + VDFS4_CRYPTED_HASH_LEN - hash_len);
	ret = RSA_private_encrypt(VDFS4_CRYPTED_HASH_LEN,
			(const unsigned char *)hash,
			rsa_hash, rsa_key, RSA_NO_PADDING);
	if (ret != VDFS4_CRYPTED_HASH_LEN)
		return -EINVAL;

	return 0;
}
