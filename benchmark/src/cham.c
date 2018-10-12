/*
 * CHAM block cipher, based on the original paper:
 * "CHAM: A Family of Lightweight Block Ciphers for Resource-Constrained Devices" (2018),
 * https://link.springer.com/chapter/10.1007/978-3-319-78556-1_1
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "util.h"

#define CHAM128_128_NROUNDS	80
#define CHAM128_256_NROUNDS	96

struct cham128_ctx {
	u32 round_keys[16];
	int rk_mask;
	int nrounds;
};

static void cham128_setkey(struct cham128_ctx *ctx, const u8 *key,
			   int key_words)
{
	int i;

	for (i = 0; i < key_words; i++) {
		u32 k = get_unaligned_le32(key + 4*i);

		ctx->round_keys[i] = k ^ rol32(k, 1) ^ rol32(k, 8);
		ctx->round_keys[(i + key_words) ^ 1] =
			k ^ rol32(k, 1) ^ rol32(k, 11);
	}
	ctx->rk_mask = 2 * key_words - 1;
}


static void cham128_128_setkey(struct cham128_ctx *ctx, const u8 *key)
{
	cham128_setkey(ctx, key, 128 / 32);
	ctx->nrounds = CHAM128_128_NROUNDS;
}

static void cham128_256_setkey(struct cham128_ctx *ctx, const u8 *key)
{
	cham128_setkey(ctx, key, 256 / 32);
	ctx->nrounds = CHAM128_256_NROUNDS;
}

static void cham128_encrypt(const struct cham128_ctx *ctx,
			    u8 *dst, const u8 *src)
{
	u32 x0 = get_unaligned_le32(src + 0);
	u32 x1 = get_unaligned_le32(src + 4);
	u32 x2 = get_unaligned_le32(src + 8);
	u32 x3 = get_unaligned_le32(src + 12);
	u32 t1, t2;
	int rk_mask = ctx->rk_mask;
	int i;

	for (i = 0; i < ctx->nrounds; i += 2) {
		t1 = rol32((x0 ^ i) + (rol32(x1, 1) ^ ctx->round_keys[i & rk_mask]), 8);
		t2 = rol32((x1 ^ (i + 1)) + (rol32(x2, 8) ^ ctx->round_keys[(i + 1) & rk_mask]), 1);
		x0 = x2;
		x1 = x3;
		x2 = t1;
		x3 = t2;
	}

	put_unaligned_le32(x0, dst + 0);
	put_unaligned_le32(x1, dst + 4);
	put_unaligned_le32(x2, dst + 8);
	put_unaligned_le32(x3, dst + 12);
}

static void cham128_decrypt(const struct cham128_ctx *ctx,
			    u8 *dst, const u8 *src)
{
	u32 x0 = get_unaligned_le32(src + 0);
	u32 x1 = get_unaligned_le32(src + 4);
	u32 x2 = get_unaligned_le32(src + 8);
	u32 x3 = get_unaligned_le32(src + 12);
	u32 t1, t2;
	int rk_mask = ctx->rk_mask;
	int i;

	for (i = ctx->nrounds - 1; i >= 0; i -= 2) {
		t1 = i ^ (ror32(x3, 1) - (rol32(x0, 8) ^ ctx->round_keys[i & rk_mask]));
		t2 = (i - 1) ^ (ror32(x2, 8) - (rol32(t1, 1) ^ ctx->round_keys[(i - 1) & rk_mask]));
		x3 = x1;
		x2 = x0;
		x1 = t1;
		x0 = t2;
	}

	put_unaligned_le32(x0, dst + 0);
	put_unaligned_le32(x1, dst + 4);
	put_unaligned_le32(x2, dst + 8);
	put_unaligned_le32(x3, dst + 12);
}

#ifdef __arm__
void cham128_xts_encrypt_neon(const u32 *round_keys, int nrounds,
			      void *dst, const void *src,
			      unsigned int nbytes, void *tweak);

void cham128_xts_decrypt_neon(const u32 *round_keys, int nrounds,
			      void *dst, const void *src,
			      unsigned int nbytes, void *tweak);

static void cham128_128_xts_encrypt_neon(const struct cham128_ctx *ctx,
					 void *dst, const void *src,
					 unsigned int nbytes, void *tweak)
{
	cham128_xts_encrypt_neon(ctx->round_keys, ctx->nrounds,
				 dst, src, nbytes, tweak);
}

static void cham128_128_xts_decrypt_neon(const struct cham128_ctx *ctx,
					 void *dst, const void *src,
					 unsigned int nbytes, void *tweak)
{
	cham128_xts_decrypt_neon(ctx->round_keys, ctx->nrounds,
				 dst, src, nbytes, tweak);
}
#endif /* __arm__ */

void test_cham(void)
{
	/* Test vectors from the CHAM paper */
	static const u8 tv_key[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	};
	static const u8 tv_plaintext[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};
	static const u8 tv_ciphertext_128[16] = {
		0x34, 0x60, 0x74, 0xc3, 0xc5, 0x00, 0x57, 0xb5,
		0x32, 0xec, 0x64, 0x8d, 0xf7, 0x32, 0x93, 0x48,
	};
	static const u8 tv_ciphertext_256[16] = {
		0xa0, 0xc8, 0x99, 0xa8, 0x5c, 0xd5, 0x29, 0xc9,
		0x38, 0x0d, 0x67, 0xab, 0xc8, 0x7a, 0x4f, 0x0c,
	};
	struct cham128_ctx ctx;
	u8 block[16];

	cham128_128_setkey(&ctx, tv_key);

	cham128_encrypt(&ctx, block, tv_plaintext);
	ASSERT(!memcmp(block, tv_ciphertext_128, sizeof(block)));

	cham128_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv_plaintext, sizeof(block)));

	cham128_256_setkey(&ctx, tv_key);

	cham128_encrypt(&ctx, block, tv_plaintext);
	ASSERT(!memcmp(block, tv_ciphertext_256, sizeof(block)));

	cham128_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv_plaintext, sizeof(block)));

#define BLOCK_BYTES		16
#define ENCRYPT			cham128_encrypt
#define DECRYPT			cham128_decrypt
#define	KEY			struct cham128_ctx

#define KEY_BYTES		16
#define SETKEY			cham128_128_setkey
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	cham128_128_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	cham128_128_xts_decrypt_neon
#endif
#define ALGNAME			"CHAM128/128"
#include "xts_benchmark_template.h"

#define KEY_BYTES		32
#define SETKEY			cham128_256_setkey
#define ALGNAME			"CHAM128/256"
#include "xts_benchmark_template.h"
}
