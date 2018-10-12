/*
 * NOEKEON block cipher, based on the original paper:
 * "Nessie Proposal: NOEKEON" (2000), http://gro.noekeon.org/Noekeon-spec.pdf
 * and also the reference code at http://gro.noekeon.org/Noekeon_ref.zip,
 * but heavily rewritten
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "noekeon.h"

static forceinline void Theta(const u32 k[4], u32 x[4])
{
	u32 tmp;

	tmp = x[0] ^ x[2];
	tmp ^= rol32(tmp, 8) ^ rol32(tmp, 24);
	x[1] ^= tmp;
	x[3] ^= tmp;

	x[0] ^= k[0];
	x[1] ^= k[1];
	x[2] ^= k[2];
	x[3] ^= k[3];

	tmp = x[1] ^ x[3];
	tmp ^= rol32(tmp, 8) ^ rol32(tmp, 24);
	x[0] ^= tmp;
	x[2] ^= tmp;
}

static forceinline void noekeon_round(u32 x[4], const u32 k[4], u8 rc1, u8 rc2)
{
	u32 tmp;

	x[0] ^= rc1;
	Theta(k, x);
	x[0] ^= rc2;

	/* Pi1 */
	x[1] = rol32(x[1], 1);
	x[2] = rol32(x[2], 5);
	x[3] = rol32(x[3], 2);

	/* Gamma */

	/* first non-linear step in gamma */
	x[1] ^= ~(x[3] | x[2]);
	x[0] ^= x[2] & x[1];

	/* linear step in gamma */
	tmp = x[3];
	x[3] = x[0];
	x[0] = tmp;
	x[2] ^= x[0] ^ x[1] ^ x[3];

	/* last non-linear step in gamma */
	x[1] ^= ~(x[3] | x[2]);
	x[0] ^= x[2] & x[1];

	/* Pi2 */
	x[1] = rol32(x[1], 31);
	x[2] = rol32(x[2], 27);
	x[3] = rol32(x[3], 30);
}

void noekeon_encrypt(const struct noekeon_ctx *ctx, u8 *dst, const u8 *src)
{
	u32 x[4];

	x[0] = get_unaligned_be32(src +  0);
	x[1] = get_unaligned_be32(src +  4);
	x[2] = get_unaligned_be32(src +  8);
	x[3] = get_unaligned_be32(src + 12);

	noekeon_round(x, ctx->enckey, 0x80, 0);
	noekeon_round(x, ctx->enckey, 0x1B, 0);
	noekeon_round(x, ctx->enckey, 0x36, 0);
	noekeon_round(x, ctx->enckey, 0x6C, 0);
	noekeon_round(x, ctx->enckey, 0xD8, 0);
	noekeon_round(x, ctx->enckey, 0xAB, 0);
	noekeon_round(x, ctx->enckey, 0x4D, 0);
	noekeon_round(x, ctx->enckey, 0x9A, 0);
	noekeon_round(x, ctx->enckey, 0x2F, 0);
	noekeon_round(x, ctx->enckey, 0x5E, 0);
	noekeon_round(x, ctx->enckey, 0xBC, 0);
	noekeon_round(x, ctx->enckey, 0x63, 0);
	noekeon_round(x, ctx->enckey, 0xC6, 0);
	noekeon_round(x, ctx->enckey, 0x97, 0);
	noekeon_round(x, ctx->enckey, 0x35, 0);
	noekeon_round(x, ctx->enckey, 0x6A, 0);
	x[0] ^= 0xD4;
	Theta(ctx->enckey, x);

	put_unaligned_be32(x[0], dst +  0);
	put_unaligned_be32(x[1], dst +  4);
	put_unaligned_be32(x[2], dst +  8);
	put_unaligned_be32(x[3], dst + 12);
}

void noekeon_decrypt(const struct noekeon_ctx *ctx, u8 *dst, const u8 *src)
{
	u32 x[4];

	x[0] = get_unaligned_be32(src +  0);
	x[1] = get_unaligned_be32(src +  4);
	x[2] = get_unaligned_be32(src +  8);
	x[3] = get_unaligned_be32(src + 12);

	noekeon_round(x, ctx->deckey, 0, 0xD4);
	noekeon_round(x, ctx->deckey, 0, 0x6A);
	noekeon_round(x, ctx->deckey, 0, 0x35);
	noekeon_round(x, ctx->deckey, 0, 0x97);
	noekeon_round(x, ctx->deckey, 0, 0xC6);
	noekeon_round(x, ctx->deckey, 0, 0x63);
	noekeon_round(x, ctx->deckey, 0, 0xBC);
	noekeon_round(x, ctx->deckey, 0, 0x5E);
	noekeon_round(x, ctx->deckey, 0, 0x2F);
	noekeon_round(x, ctx->deckey, 0, 0x9A);
	noekeon_round(x, ctx->deckey, 0, 0x4D);
	noekeon_round(x, ctx->deckey, 0, 0xAB);
	noekeon_round(x, ctx->deckey, 0, 0xD8);
	noekeon_round(x, ctx->deckey, 0, 0x6C);
	noekeon_round(x, ctx->deckey, 0, 0x36);
	noekeon_round(x, ctx->deckey, 0, 0x1B);
	Theta(ctx->deckey, x);
	x[0] ^= 0x80;

	put_unaligned_be32(x[0], dst +  0);
	put_unaligned_be32(x[1], dst +  4);
	put_unaligned_be32(x[2], dst +  8);
	put_unaligned_be32(x[3], dst + 12);
}

void noekeon_setkey(struct noekeon_ctx *ctx, const u8 *key)
{
	static const u32 zeroes[4] = {0, 0, 0, 0};

	ctx->enckey[0] = get_unaligned_be32(key +  0);
	ctx->enckey[1] = get_unaligned_be32(key +  4);
	ctx->enckey[2] = get_unaligned_be32(key +  8);
	ctx->enckey[3] = get_unaligned_be32(key + 12);

	memcpy(ctx->deckey, ctx->enckey, 16);
	Theta(zeroes, ctx->deckey);
}

#ifdef __arm__
void noekeon_xts_encrypt_neon(const u32 key[4], void *dst, const void *src,
			      unsigned int nbytes, void *tweak);
void noekeon_xts_decrypt_neon(const u32 key[4], void *dst, const void *src,
			      unsigned int nbytes, void *tweak);

static void _noekeon_xts_encrypt_neon(const struct noekeon_ctx *ctx,
				      void *dst, const void *src,
				      unsigned int nbytes, void *tweak)
{
	noekeon_xts_encrypt_neon(ctx->enckey, dst, src, nbytes, tweak);
}

static void _noekeon_xts_decrypt_neon(const struct noekeon_ctx *ctx,
				      void *dst, const void *src,
				      unsigned int nbytes, void *tweak)
{
	noekeon_xts_decrypt_neon(ctx->deckey, dst, src, nbytes, tweak);
}
#endif /* __arm__ */

void test_noekeon(void)
{
	/* from reference code: http://gro.noekeon.org/Noekeon_ref.zip */
	static const u8 tv_key[16] = "\xb1\x65\x68\x51\x69\x9e\x29\xfa"
				     "\x24\xb7\x01\x48\x50\x3d\x2d\xfc";
	static const u8 tv_plaintext[16] = "\x2a\x78\x42\x1b\x87\xc7\xd0\x92"
					   "\x4f\x26\x11\x3f\x1d\x13\x49\xb2";
	static const u8 tv_ciphertext[16] = "\xe2\xf6\x87\xe0\x7b\x75\x66\x0f"
					    "\xfc\x37\x22\x33\xbc\x47\x53\x2c";
	struct noekeon_ctx ctx;
	u8 block[16];

	noekeon_setkey(&ctx, tv_key);
	noekeon_encrypt(&ctx, block, tv_plaintext);
	ASSERT(!memcmp(block, tv_ciphertext, 16));
	noekeon_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv_plaintext, 16));

#define ALGNAME		"NOEKEON"
#define BLOCK_BYTES	16
#define KEY_BYTES	16
#define KEY		struct noekeon_ctx
#define SETKEY		noekeon_setkey
#define ENCRYPT		noekeon_encrypt
#define DECRYPT		noekeon_decrypt
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD _noekeon_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD _noekeon_xts_decrypt_neon
#endif
#include "xts_benchmark_template.h"
}
