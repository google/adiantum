/*
 * Chaskey-LTS block cipher, based on the original paper
 * "Chaskey: An Efficient MAC Algorithm for 32-bit Microcontrollers" (2014),
 * https://eprint.iacr.org/2014/386.pdf
 *
 * and also the code at https://tinycrypt.wordpress.com/2017/02/20/asmcodes-chaskey-cipher/
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "util.h"

struct chaskey_lts_ctx {
	u32 k[4];
};

static void chaskey_lts_setkey(struct chaskey_lts_ctx *ctx, const u8 *key)
{
	memcpy(ctx->k, key, sizeof(ctx->k));
}

static void chaskey_lts_encrypt(const struct chaskey_lts_ctx *ctx,
				u8 *dst, const u8 *src)
{
	u32 v0, v1, v2, v3;
	int i;

	// pre-whiten
	v0 = get_unaligned_le32(src + 0) ^ ctx->k[0];
	v1 = get_unaligned_le32(src + 4) ^ ctx->k[1];
	v2 = get_unaligned_le32(src + 8) ^ ctx->k[2];
	v3 = get_unaligned_le32(src + 12) ^ ctx->k[3];

	// apply permutation function
	for (i = 0; i < 16; i++) {
		v0 += v1;
		v1 = rol32(v1, 5);
		v1 ^= v0;

		v0 = rol32(v0, 16);
		v2 += v3;
		v3 = rol32(v3, 8);
		v3 ^= v2;

		v0 += v3;
		v3 = rol32(v3, 13);
		v3 ^= v0;

		v2 += v1;
		v1 = rol32(v1, 7);
		v1 ^= v2;

		v2 = rol32(v2, 16);
	}

	// post-whiten
	put_unaligned_le32(v0 ^ ctx->k[0], dst + 0);
	put_unaligned_le32(v1 ^ ctx->k[1], dst + 4);
	put_unaligned_le32(v2 ^ ctx->k[2], dst + 8);
	put_unaligned_le32(v3 ^ ctx->k[3], dst + 12);
}

static void chaskey_lts_decrypt(const struct chaskey_lts_ctx *ctx,
				u8 *dst, const u8 *src)
{
	u32 v0, v1, v2, v3;
	int i;

	// pre-whiten
	v0 = get_unaligned_le32(src + 0) ^ ctx->k[0];
	v1 = get_unaligned_le32(src + 4) ^ ctx->k[1];
	v2 = get_unaligned_le32(src + 8) ^ ctx->k[2];
	v3 = get_unaligned_le32(src + 12) ^ ctx->k[3];

	// apply permutation function
	for (i = 0; i < 16; i++) {
		v2 = ror32(v2, 16);
		v1 ^= v2;
		v1 = ror32(v1, 7);
		v2 -= v1;
		v3 ^= v0;
		v3 = ror32(v3, 13);
		v0 -= v3;
		v3 ^= v2;
		v3 = ror32(v3, 8);
		v2 -= v3;
		v0 = ror32(v0, 16);
		v1 ^= v0;
		v1 = ror32(v1, 5);
		v0 -= v1;
	}

	// post-whiten
	put_unaligned_le32(v0 ^ ctx->k[0], dst + 0);
	put_unaligned_le32(v1 ^ ctx->k[1], dst + 4);
	put_unaligned_le32(v2 ^ ctx->k[2], dst + 8);
	put_unaligned_le32(v3 ^ ctx->k[3], dst + 12);
}

#ifdef __arm__
void chaskey_lts_xts_encrypt_neon(const struct chaskey_lts_ctx *key,
				  void *dst, const void *src,
				  unsigned int nbytes, void *tweak);

void chaskey_lts_xts_decrypt_neon(const struct chaskey_lts_ctx *key,
				  void *dst, const void *src,
				  unsigned int nbytes, void *tweak);
#endif

void test_chaskey_lts(void)
{
#define BLOCK_BYTES		16
#define KEY_BYTES		16
#define ENCRYPT			chaskey_lts_encrypt
#define DECRYPT			chaskey_lts_decrypt
#define	KEY			struct chaskey_lts_ctx
#define SETKEY			chaskey_lts_setkey
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	chaskey_lts_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	chaskey_lts_xts_decrypt_neon
#endif
#define ALGNAME			"Chaskey-LTS"
#include "xts_benchmark_template.h"
}
