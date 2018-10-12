/*
 * AES block cipher (glue code)
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"

#ifdef __arm__
void aesbs_convert_key(u8 out[], u32 const rk[], int rounds);
void aesbs_xts_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
		       int blocks, u8 iv[]);
void aesbs_xts_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
		       int blocks, u8 iv[]);
#endif

static void aes_setkey(struct aes_ctx *ctx, const u8 *key, int key_len)
{
	int err;

#ifdef __arm__
	err = aesti_expand_key(&ctx->aes_ti_ctx, key, key_len);
	ASSERT(err == 0);
	ctx->rounds = 6 + key_len / 4;
	aesbs_convert_key(ctx->rk, ctx->aes_ti_ctx.key_enc, ctx->rounds);
#endif

	err = aesti_set_key(&ctx->aes_ti_ctx, key, key_len);
	ASSERT(err == 0);
}

void aes128_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes_setkey(ctx, key, AES_KEYSIZE_128);
}

void aes256_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes_setkey(ctx, key, AES_KEYSIZE_256);
}

void aes_encrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
	aesti_encrypt(&ctx->aes_ti_ctx, out, in);
}

void aes_decrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
	aesti_decrypt(&ctx->aes_ti_ctx, out, in);
}

#ifdef __arm__
static void aes_xts_encrypt_neon(const struct aes_ctx *ctx,
				 u8 *out, const u8 *in,
				 unsigned int nbytes, void *tweak)
{
	aesbs_xts_encrypt(out, in, ctx->rk, ctx->rounds,
			  nbytes / AES_BLOCK_SIZE, tweak);
}

static void aes_xts_decrypt_neon(const struct aes_ctx *ctx,
				 u8 *out, const u8 *in,
				 unsigned int nbytes, void *tweak)
{
	aesbs_xts_decrypt(out, in, ctx->rk, ctx->rounds,
			  nbytes / AES_BLOCK_SIZE, tweak);
}
#endif /* __arm__ */

void test_aes(void)
{
	static const u8 tv128_key[16] =
		"\x00\x01\x02\x03\x04\x05\x06\x07"
		"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
	static const u8 tv128_plaintext[16] =
		"\x00\x11\x22\x33\x44\x55\x66\x77"
		"\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
	static const u8 tv128_ciphertext[16] =
		"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30"
		"\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a";

	static const u8 tv256_key[32] =
		"\x00\x01\x02\x03\x04\x05\x06\x07"
		"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		"\x10\x11\x12\x13\x14\x15\x16\x17"
		"\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
	static const u8 tv256_plaintext[16] =
		"\x00\x11\x22\x33\x44\x55\x66\x77"
		"\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
	static const u8 tv256_ciphertext[16] =
		"\x8e\xa2\xb7\xca\x51\x67\x45\xbf"
		"\xea\xfc\x49\x90\x4b\x49\x60\x89";
	struct aes_ctx ctx;
	u8 block[16];

	aes128_setkey(&ctx, tv128_key);
	aes_encrypt(&ctx, block, tv128_plaintext);
	ASSERT(!memcmp(block, tv128_ciphertext, 16));
	aes_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv128_plaintext, 16));

	aes256_setkey(&ctx, tv256_key);
	aes_encrypt(&ctx, block, tv256_plaintext);
	ASSERT(!memcmp(block, tv256_ciphertext, 16));
	aes_decrypt(&ctx, block, block);
	ASSERT(!memcmp(block, tv256_plaintext, 16));

#define ALGNAME		"AES-128"
#define BLOCK_BYTES	16
#define KEY_BYTES	16
#define KEY		struct aes_ctx
#define SETKEY		aes128_setkey
#define ENCRYPT		aes_encrypt
#define DECRYPT		aes_decrypt
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD aes_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD aes_xts_decrypt_neon
#endif
#include "xts_benchmark_template.h"

#define ALGNAME		"AES-256"
#define BLOCK_BYTES	16
#define KEY_BYTES	32
#define KEY		struct aes_ctx
#define SETKEY		aes256_setkey
#define ENCRYPT		aes_encrypt
#define DECRYPT		aes_decrypt
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD aes_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD aes_xts_decrypt_neon
#endif
#include "xts_benchmark_template.h"
}
