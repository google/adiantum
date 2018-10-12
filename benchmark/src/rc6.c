/*
 * RC6 block cipher, based on the original paper:
 * "The RC6(TM) Block Cipher" (1998), http://people.csail.mit.edu/rivest/Rc6.pdf
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "util.h"

#define RC6_NROUNDS	20

struct rc6_ctx {
	u32 round_keys[2 * RC6_NROUNDS + 4];
};

static void rc6_setkey(struct rc6_ctx *ctx, const u8 *key)
{
	u32 *S = ctx->round_keys;
	u32 L[4];
	u32 A, B, i, j;
	int s;

	memcpy(L, key, sizeof(L));

	S[0] = 0xB7E15163;
	for (i = 1; i < ARRAY_SIZE(ctx->round_keys); i++)
		S[i] = S[i - 1] + 0x9E3779B9;

	A = B = i = j = 0;

	for (s = 0; s < 3 * ARRAY_SIZE(ctx->round_keys); s++) {
		A = S[i] = rol32(S[i] + A + B, 3);
		B = L[j] = rol32(L[j] + A + B, (A + B) & 31);
		i = (i + 1) % ARRAY_SIZE(ctx->round_keys);
		j = (j + 1) % ARRAY_SIZE(L);
	}
}

static void rc6_encrypt(const struct rc6_ctx *ctx, u8 *dst, const u8 *src)
{
	const u32 *S = ctx->round_keys;
	u32 A = get_unaligned_le32(src + 0);
	u32 B = get_unaligned_le32(src + 4);
	u32 C = get_unaligned_le32(src + 8);
	u32 D = get_unaligned_le32(src + 12);
	int i;

	B += *S++;
	D += *S++;

	for (i = 1; i <= RC6_NROUNDS; i++) {
		u32 t, u;

		t = rol32(B * (2*B + 1), 5);
		u = rol32(D * (2*D + 1), 5);

		A = rol32(A ^ t, u & 31) + *S++;
		C = rol32(C ^ u, t & 31) + *S++;

		t = A;
		A = B;
		B = C;
		C = D;
		D = t;
	}

	A += *S++;
	C += *S++;

	put_unaligned_le32(A, dst + 0);
	put_unaligned_le32(B, dst + 4);
	put_unaligned_le32(C, dst + 8);
	put_unaligned_le32(D, dst + 12);
}

static void rc6_decrypt(const struct rc6_ctx *ctx, u8 *dst, const u8 *src)
{
	const u32 *S = &ctx->round_keys[2 * RC6_NROUNDS + 3];
	u32 A = get_unaligned_le32(src + 0);
	u32 B = get_unaligned_le32(src + 4);
	u32 C = get_unaligned_le32(src + 8);
	u32 D = get_unaligned_le32(src + 12);
	int i;

	C -= *S--;
	A -= *S--;

	for (i = RC6_NROUNDS; i >= 1; i--) {
		u32 t, u;

		t = D;
		D = C;
		C = B;
		B = A;
		A = t;

		t = rol32(B * (2*B + 1), 5);
		u = rol32(D * (2*D + 1), 5);

		C = ror32(C - *S--, t & 31) ^ u;
		A = ror32(A - *S--, u & 31) ^ t;
	}

	D -= *S--;
	B -= *S--;

	put_unaligned_le32(A, dst + 0);
	put_unaligned_le32(B, dst + 4);
	put_unaligned_le32(C, dst + 8);
	put_unaligned_le32(D, dst + 12);
}

#ifdef __arm__
void rc6_xts_encrypt_neon(const struct rc6_ctx *ctx,
			  void *dst, const void *src,
			  unsigned int nbytes, void *tweak);
void rc6_xts_decrypt_neon(const struct rc6_ctx *ctx,
			  void *dst, const void *src,
			  unsigned int nbytes, void *tweak);
#endif

void test_rc6(void)
{
	/* Test vector taken from the Appendix of the RC6 paper */
	static const u8 tv_plaintext[16] =
		"\x02\x13\x24\x35\x46\x57\x68\x79\x8a\x9b\xac\xbd\xce\xdf\xe0\xf1";
	static const u8 tv_ciphertext[16] =
		"\x52\x4e\x19\x2f\x47\x15\xc6\x23\x1f\x51\xf6\x36\x7e\xa4\x3f\x18";
	static const u8 tv_key[16] =
		"\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x12\x23\x34\x45\x56\x67\x78";
	u8 block[16];
	struct rc6_ctx ctx;

	rc6_setkey(&ctx, tv_key);
	rc6_encrypt(&ctx, block, tv_plaintext);
	ASSERT(!memcmp(block, tv_ciphertext, 16));
	rc6_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv_plaintext, 16));

#define BLOCK_BYTES		16
#define KEY_BYTES		16
#define ENCRYPT			rc6_encrypt
#define DECRYPT			rc6_decrypt
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	rc6_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	rc6_xts_decrypt_neon
#endif
#define	KEY			struct rc6_ctx
#define SETKEY			rc6_setkey
#define ALGNAME			"RC6"
#include "xts_benchmark_template.h"
}
