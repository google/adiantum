/*
 * XTEA block cipher
 *
 * Reference: "Tea extensions" http://www.cix.co.uk/~klockstone/xtea.pdf
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "util.h"

#define DELTA		0x9e3779b9
#define NUM_ROUNDS	32

struct xtea_ctx {
	u32 k[4];
};

static void xtea_setkey(struct xtea_ctx *ctx, const u8 *key)
{
	ctx->k[0] = get_unaligned_le32(key + 0);
	ctx->k[1] = get_unaligned_le32(key + 4);
	ctx->k[2] = get_unaligned_le32(key + 8);
	ctx->k[3] = get_unaligned_le32(key + 12);
}

/*
 * Note: the reference code relies heavily on C operator precedence, making the
 * evaluation order unclear.  We have clarified it by adding extra parentheses.
 */

static void xtea_encrypt(const struct xtea_ctx *ctx, u8 *dst, const u8 *src)
{
	u32 y = get_unaligned_le32(src + 0);
	u32 z = get_unaligned_le32(src + 4);
	u32 limit = DELTA * NUM_ROUNDS;
	u32 sum = 0;

	while (sum != limit) {
		y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + ctx->k[sum & 3]);
		sum += DELTA;
		z += (((y << 4) ^ (y >> 5)) + y) ^
		     (sum + ctx->k[(sum >> 11) & 3]);
	}

	put_unaligned_le32(y, dst + 0);
	put_unaligned_le32(z, dst + 4);
}

static void xtea_decrypt(const struct xtea_ctx *ctx, u8 *dst, const u8 *src)
{
	u32 y = get_unaligned_le32(src + 0);
	u32 z = get_unaligned_le32(src + 4);
	u32 sum = DELTA * NUM_ROUNDS;

	while (sum) {
		z -= (((y << 4) ^ (y >> 5)) + y) ^
		     (sum + ctx->k[(sum >> 11) & 3]);
		sum -= DELTA;
		y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + ctx->k[sum & 3]);
	}

	put_unaligned_le32(y, dst + 0);
	put_unaligned_le32(z, dst + 4);
}

#ifdef __arm__
void xtea_xts_encrypt_neon(const struct xtea_ctx *ctx,
			   void *dst, const void *src,
			   unsigned int nbytes, void *tweak);

void xtea_xts_decrypt_neon(const struct xtea_ctx *ctx,
			   void *dst, const void *src,
			   unsigned int nbytes, void *tweak);
#endif

void test_xtea(void)
{
	/* XTEA test vector from Linux kernel crypto/testmgr.h */
	static const u8 tv_key[16] = "\x2b\x02\x05\x68\x06\x14\x49\x76"
				       "\x77\x5d\x0e\x26\x6c\x28\x78\x43";
	static const u8 tv_plaintext[8] = "\x74\x65\x73\x74\x20\x6d\x65\x2e";
	static const u8 tv_ciphertext[8] = "\x94\xeb\xc8\x96\x84\x6a\x49\xa8";
	struct xtea_ctx ctx;
	u8 block[8];

	xtea_setkey(&ctx, tv_key);

	xtea_encrypt(&ctx, block, tv_plaintext);
	ASSERT(!memcmp(block, tv_ciphertext, sizeof(block)));

	xtea_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv_plaintext, sizeof(block)));

#define BLOCK_BYTES		8
#define ENCRYPT			xtea_encrypt
#define DECRYPT			xtea_decrypt
#define	KEY			struct xtea_ctx
#define KEY_BYTES		16
#define SETKEY			xtea_setkey
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	xtea_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	xtea_xts_decrypt_neon
#endif
#define ALGNAME			"XTEA"
#include "xts_benchmark_template.h"
}
