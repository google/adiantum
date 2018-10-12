/*
 * RC5 block cipher, based on the original paper:
 * "The RC5 Encryption Algorithm" (1997),
 * https://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "util.h"

#define RC5_MAX_NROUNDS	20

static int g_nrounds = 12;

/***** RC5-64 ******/

struct rc5_64_ctx {
	u32 round_keys[2 * RC5_MAX_NROUNDS + 2];
	int nrounds;
};

static void rc5_64_setkey(struct rc5_64_ctx *ctx, const u8 *key)
{
	u32 *S = ctx->round_keys;
	u32 L[4];
	u32 A, B, i, j;
	int s;

	memcpy(L, key, sizeof(L));
	ctx->nrounds = g_nrounds;

	S[0] = 0xB7E15163;
	for (i = 1; i < 2 * ctx->nrounds + 2; i++)
		S[i] = S[i - 1] + 0x9E3779B9;

	A = B = i = j = 0;

	for (s = 0; s < 3 * (2 * ctx->nrounds + 2); s++) {
		A = S[i] = rol32(S[i] + A + B, 3);
		B = L[j] = rol32(L[j] + A + B, (A + B) & 31);
		i = (i + 1) % (2 * ctx->nrounds + 2);
		j = (j + 1) % ARRAY_SIZE(L);
	}
}

static void rc5_64_encrypt(const struct rc5_64_ctx *ctx, u8 *dst, const u8 *src)
{
	const u32 *S = ctx->round_keys;
	u32 A = get_unaligned_le32(src + 0);
	u32 B = get_unaligned_le32(src + 4);
	int i;

	A += *S++;
	B += *S++;

	for (i = 0; i < ctx->nrounds; i++) {
		A = rol32(A ^ B, B & 31) + *S++;
		B = rol32(B ^ A, A & 31) + *S++;
	}

	put_unaligned_le32(A, dst + 0);
	put_unaligned_le32(B, dst + 4);
}

static void rc5_64_decrypt(const struct rc5_64_ctx *ctx, u8 *dst, const u8 *src)
{
	const u32 *S = &ctx->round_keys[2 * ctx->nrounds + 1];
	u32 A = get_unaligned_le32(src + 0);
	u32 B = get_unaligned_le32(src + 4);
	int i;

	for (i = 0; i < ctx->nrounds; i++) {
		B = ror32(B - *S--, A & 31) ^ A;
		A = ror32(A - *S--, B & 31) ^ B;
	}

	B -= *S--;
	A -= *S--;

	put_unaligned_le32(A, dst + 0);
	put_unaligned_le32(B, dst + 4);
}

#ifdef __arm__
void rc5_64_xts_encrypt_neon(const u32 round_keys[], int nrounds,
			     void *dst, const void *src,
			     unsigned int nbytes, void *tweak);
void rc5_64_xts_decrypt_neon(const u32 round_keys[], int nrounds,
			     void *dst, const void *src,
			     unsigned int nbytes, void *tweak);

static void _rc5_64_xts_encrypt_neon(const struct rc5_64_ctx *ctx,
				     void *dst, const void *src,
				     unsigned int nbytes, void *tweak)
{
	rc5_64_xts_encrypt_neon(ctx->round_keys, ctx->nrounds,
				dst, src, nbytes, tweak);
}
static void _rc5_64_xts_decrypt_neon(const struct rc5_64_ctx *ctx,
				     void *dst, const void *src,
				     unsigned int nbytes, void *tweak)
{
	rc5_64_xts_decrypt_neon(ctx->round_keys, ctx->nrounds,
				dst, src, nbytes, tweak);
}
#endif /* __arm__ */

/***** RC5-128 ******/

struct rc5_128_ctx {
	u64 round_keys[2 * RC5_MAX_NROUNDS + 2];
	int nrounds;
};

static void rc5_128_setkey(struct rc5_128_ctx *ctx, const u8 *key)
{
	u64 *S = ctx->round_keys;
	u64 L[4];
	u64 A, B, i, j;
	int s;

	memcpy(L, key, sizeof(L));
	ctx->nrounds = g_nrounds;

	S[0] = 0xB7E151628AED2A6BULL;
	for (i = 1; i < 2 * ctx->nrounds + 2; i++)
		S[i] = S[i - 1] + 0x9E3779B97F4A7C15ULL;

	A = B = i = j = 0;

	for (s = 0; s < 3 * (2 * ctx->nrounds + 2); s++) {
		A = S[i] = rol64(S[i] + A + B, 3);
		B = L[j] = rol64(L[j] + A + B, (A + B) & 63);
		i = (i + 1) % (2 * ctx->nrounds + 2);
		j = (j + 1) % ARRAY_SIZE(L);
	}
}

static void rc5_128_encrypt(const struct rc5_128_ctx *ctx,
			    u8 *dst, const u8 *src)
{
	const u64 *S = ctx->round_keys;
	u64 A = get_unaligned_le64(src + 0);
	u64 B = get_unaligned_le64(src + 8);
	int i;

	A += *S++;
	B += *S++;

	for (i = 0; i < ctx->nrounds; i++) {
		A = rol64(A ^ B, B & 63) + *S++;
		B = rol64(B ^ A, A & 63) + *S++;
	}

	put_unaligned_le64(A, dst + 0);
	put_unaligned_le64(B, dst + 8);
}

static void rc5_128_decrypt(const struct rc5_128_ctx *ctx,
			    u8 *dst, const u8 *src)
{
	const u64 *S = &ctx->round_keys[2 * ctx->nrounds + 1];
	u64 A = get_unaligned_le64(src + 0);
	u64 B = get_unaligned_le64(src + 8);
	int i;

	for (i = 0; i < ctx->nrounds; i++) {
		B = ror64(B - *S--, A & 63) ^ A;
		A = ror64(A - *S--, B & 63) ^ B;
	}

	B -= *S--;
	A -= *S--;

	put_unaligned_le64(A, dst + 0);
	put_unaligned_le64(B, dst + 8);
}

#ifdef __arm__
void rc5_128_xts_encrypt_neon(const u64 round_keys[], int nrounds,
			      void *dst, const void *src,
			      unsigned int nbytes, void *tweak);
void rc5_128_xts_decrypt_neon(const u64 round_keys[], int nrounds,
			      void *dst, const void *src,
			      unsigned int nbytes, void *tweak);

static void _rc5_128_xts_encrypt_neon(const struct rc5_128_ctx *ctx,
				      void *dst, const void *src,
				      unsigned int nbytes, void *tweak)
{
	rc5_128_xts_encrypt_neon(ctx->round_keys, ctx->nrounds,
				 dst, src, nbytes, tweak);
}
static void _rc5_128_xts_decrypt_neon(const struct rc5_128_ctx *ctx,
				      void *dst, const void *src,
				      unsigned int nbytes, void *tweak)
{
	rc5_128_xts_decrypt_neon(ctx->round_keys, ctx->nrounds,
				 dst, src, nbytes, tweak);
}
#endif /* __arm__ */

static void test_rc5_rounds(int nrounds)
{
	char algname[64];

	g_nrounds = nrounds;
	sprintf(algname, "RC5-64/%d/128", nrounds);
#define BLOCK_BYTES		8
#define KEY_BYTES		16
#define ENCRYPT			rc5_64_encrypt
#define DECRYPT			rc5_64_decrypt
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	_rc5_64_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	_rc5_64_xts_decrypt_neon
#endif
#define	KEY			struct rc5_64_ctx
#define SETKEY			rc5_64_setkey
#define ALGNAME			algname
#include "xts_benchmark_template.h"

#undef BLOCK_BYTES
#undef ENCRYPT
#undef DECRYPT
#undef KEY
	sprintf(algname, "RC5-128/%d/256", nrounds);
#define BLOCK_BYTES		16
#define KEY_BYTES		32
#define ENCRYPT			rc5_128_encrypt
#define DECRYPT			rc5_128_decrypt
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	_rc5_128_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	_rc5_128_xts_decrypt_neon
#endif
#define	KEY			struct rc5_128_ctx
#define SETKEY			rc5_128_setkey
#define ALGNAME			algname
#include "xts_benchmark_template.h"
}

void test_rc5(void)
{
	/*
	 * Test vector taken from the Appendix of the RC5 paper.  This is only
	 * for the 64-bit block size with 12 rounds.
	 */
	static const u8 tv_64_plaintext[8] =
		"\x21\xa5\xdb\xee\x15\x4b\x8f\x6d";
	static const u8 tv_64_ciphertext[8] =
		"\xf7\xc0\x13\xac\x5b\x2b\x89\x52";
	static const u8 tv_64_key[16] =
		"\x91\x5f\x46\x19\xbe\x41\xb2\x51\x63\x55\xa5\x01\x10\xa9\xce\x91";
	u8 block[8];
	struct rc5_64_ctx ctx;

	g_nrounds = 12;
	rc5_64_setkey(&ctx, tv_64_key);
	rc5_64_encrypt(&ctx, block, tv_64_plaintext);
	ASSERT(!memcmp(block, tv_64_ciphertext, 8));
	rc5_64_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv_64_plaintext, 8));

	test_rc5_rounds(12);
	test_rc5_rounds(20);
}
