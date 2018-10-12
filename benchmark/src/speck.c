/*
 * Speck: a lightweight block cipher
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

/*
 * Speck has 10 variants, including 5 block sizes.  For now we only implement
 * the variants Speck128/128, Speck128/192, Speck128/256, Speck64/96, and
 * Speck64/128.   Speck${B}/${K} denotes the variant with a block size of B bits
 * and a key size of K bits.  The Speck128 variants are believed to be the most
 * secure variants, and they use the same block size and key sizes as AES.  The
 * Speck64 variants are less secure, but on 32-bit processors are usually
 * faster.  The remaining variants (Speck32, Speck48, and Speck96) are even less
 * secure and/or not as well suited for implementation on either 32-bit or
 * 64-bit processors, so are omitted.
 *
 * Reference: "The Simon and Speck Families of Lightweight Block Ciphers"
 * https://eprint.iacr.org/2013/404.pdf
 *
 * In a correspondence, the Speck designers have also clarified that the words
 * should be interpreted in little-endian format, and the words should be
 * ordered such that the first word of each block is 'y' rather than 'x', and
 * the first key word (rather than the last) becomes the first round key.
 */

#include "util.h"

#define SPECK128_128_NROUNDS	32
#define SPECK128_256_NROUNDS	34

struct speck128_ctx {
	u64 round_keys[SPECK128_256_NROUNDS];
	int nrounds;
};

static forceinline void speck128_round(u64 *x, u64 *y, u64 k)
{
	*x = ror64(*x, 8);
	*x += *y;
	*x ^= k;
	*y = rol64(*y, 3);
	*y ^= *x;
}

static forceinline void speck128_unround(u64 *x, u64 *y, u64 k)
{
	*y ^= *x;
	*y = ror64(*y, 3);
	*x ^= k;
	*x -= *y;
	*x = rol64(*x, 8);
}

static void speck128_encrypt(const struct speck128_ctx *ctx,
			     u8 *out, const u8 *in)
{
	u64 y = get_unaligned_le64(in);
	u64 x = get_unaligned_le64(in + 8);
	int i;

	for (i = 0; i < ctx->nrounds; i++)
		speck128_round(&x, &y, ctx->round_keys[i]);

	put_unaligned_le64(y, out);
	put_unaligned_le64(x, out + 8);
}

static void speck128_decrypt(const struct speck128_ctx *ctx,
			     u8 *out, const u8 *in)
{
	u64 y = get_unaligned_le64(in);
	u64 x = get_unaligned_le64(in + 8);
	int i;

	for (i = ctx->nrounds - 1; i >= 0; i--)
		speck128_unround(&x, &y, ctx->round_keys[i]);

	put_unaligned_le64(y, out);
	put_unaligned_le64(x, out + 8);
}

static void speck128_128_setkey(struct speck128_ctx *ctx, const u8 *key)
{
	u64 k = get_unaligned_le64(key);
	u64 l = get_unaligned_le64(key + 8);
	int i;

	ctx->nrounds = SPECK128_128_NROUNDS;
	for (i = 0; i < ctx->nrounds; i++) {
		ctx->round_keys[i] = k;
		speck128_round(&l, &k, i);
	}
}

static void speck128_256_setkey(struct speck128_ctx *ctx, const u8 *key)
{
	u64 l[3];
	u64 k;
	int i;

	k = get_unaligned_le64(key);
	l[0] = get_unaligned_le64(key + 8);
	l[1] = get_unaligned_le64(key + 16);
	l[2] = get_unaligned_le64(key + 24);
	ctx->nrounds = SPECK128_256_NROUNDS;
	for (i = 0; i < ctx->nrounds; i++) {
		ctx->round_keys[i] = k;
		speck128_round(&l[i % 3], &k, i);
	}
}

#define SPECK64_128_NROUNDS	27

struct speck64_ctx {
	u32 round_keys[SPECK64_128_NROUNDS];
	int nrounds;
};

static forceinline void speck64_round(u32 *x, u32 *y, u32 k)
{
	*x = ror32(*x, 8);
	*x += *y;
	*x ^= k;
	*y = rol32(*y, 3);
	*y ^= *x;
}

static forceinline void speck64_unround(u32 *x, u32 *y, u32 k)
{
	*y ^= *x;
	*y = ror32(*y, 3);
	*x ^= k;
	*x -= *y;
	*x = rol32(*x, 8);
}

static void speck64_encrypt(const struct speck64_ctx *ctx,
			    u8 *out, const u8 *in)
{
	u32 y = get_unaligned_le32(in);
	u32 x = get_unaligned_le32(in + 4);
	int i;

	for (i = 0; i < ctx->nrounds; i++)
		speck64_round(&x, &y, ctx->round_keys[i]);

	put_unaligned_le32(y, out);
	put_unaligned_le32(x, out + 4);
}

static void speck64_decrypt(const struct speck64_ctx *ctx,
			    u8 *out, const u8 *in)
{
	u32 y = get_unaligned_le32(in);
	u32 x = get_unaligned_le32(in + 4);
	int i;

	for (i = ctx->nrounds - 1; i >= 0; i--)
		speck64_unround(&x, &y, ctx->round_keys[i]);

	put_unaligned_le32(y, out);
	put_unaligned_le32(x, out + 4);
}

static void speck64_128_setkey(struct speck64_ctx *ctx, const u8 *key)
{
	u32 l[3];
	u32 k;
	int i;

	k = get_unaligned_le32(key);
	l[0] = get_unaligned_le32(key + 4);
	l[1] = get_unaligned_le32(key + 8);
	l[2] = get_unaligned_le32(key + 12);
	ctx->nrounds = SPECK64_128_NROUNDS;
	for (i = 0; i < ctx->nrounds; i++) {
		ctx->round_keys[i] = k;
		speck64_round(&l[i % 3], &k, i);
	}
}

#ifdef __arm__
void speck128_xts_encrypt_neon(const u64 *round_keys, int nrounds,
			       void *dst, const void *src,
			       unsigned int nbytes, void *tweak);

void speck128_xts_decrypt_neon(const u64 *round_keys, int nrounds,
			       void *dst, const void *src,
			       unsigned int nbytes, void *tweak);

void speck64_xts_encrypt_neon(const u32 *round_keys, int nrounds,
			      void *dst, const void *src,
			      unsigned int nbytes, void *tweak);

void speck64_xts_decrypt_neon(const u32 *round_keys, int nrounds,
			      void *dst, const void *src,
			      unsigned int nbytes, void *tweak);

static void _speck128_xts_encrypt_neon(const struct speck128_ctx *ctx,
				       void *dst, const void *src,
				       unsigned int nbytes, void *tweak)
{
	speck128_xts_encrypt_neon(ctx->round_keys, ctx->nrounds,
				  dst, src, nbytes, tweak);
}

static void _speck128_xts_decrypt_neon(const struct speck128_ctx *ctx,
				       void *dst, const void *src,
				       unsigned int nbytes, void *tweak)
{
	speck128_xts_decrypt_neon(ctx->round_keys, ctx->nrounds,
				  dst, src, nbytes, tweak);
}

static void _speck64_xts_encrypt_neon(const struct speck64_ctx *ctx,
				      void *dst, const void *src,
				      unsigned int nbytes, void *tweak)
{
	speck64_xts_encrypt_neon(ctx->round_keys, ctx->nrounds,
				 dst, src, nbytes, tweak);
}

static void _speck64_xts_decrypt_neon(const struct speck64_ctx *ctx,
				      void *dst, const void *src,
				      unsigned int nbytes, void *tweak)
{
	speck64_xts_decrypt_neon(ctx->round_keys, ctx->nrounds,
				 dst, src, nbytes, tweak);
}
#endif /* __arm__ */

void test_speck(void)
{
	/*
	 * Speck test vectors taken from the original paper:
	 * "The Simon and Speck Families of Lightweight Block Ciphers"
	 * https://eprint.iacr.org/2013/404.pdf
	 *
	 * Note that the paper does not make byte and word order clear.  But it
	 * was confirmed with the authors that the intended orders are little
	 * endian byte order and (y, x) word order.  Equivalently, the printed
	 * test vectors, when looking at only the bytes (ignoring the whitespace
	 * that divides them into words), are backwards: the left-most byte is
	 * actually the one with the highest memory address, while the
	 * right-most byte is actually the one with the lowest memory address.
	 */
	static const u8 tv128_128_key[16] =
		"\x00\x01\x02\x03\x04\x05\x06\x07"
		"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
	static const u8 tv128_128_plaintext[16] =
		"\x20\x6d\x61\x64\x65\x20\x69\x74"
		"\x20\x65\x71\x75\x69\x76\x61\x6c";
	static const u8 tv128_128_ciphertext[16] =
		"\x18\x0d\x57\x5c\xdf\xfe\x60\x78"
		"\x65\x32\x78\x79\x51\x98\x5d\xa6";
	static const u8 tv128_256_key[32] =
		"\x00\x01\x02\x03\x04\x05\x06\x07"
		"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		"\x10\x11\x12\x13\x14\x15\x16\x17"
		"\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
	static const u8 tv128_256_plaintext[16] =
		"\x70\x6f\x6f\x6e\x65\x72\x2e\x20"
		"\x49\x6e\x20\x74\x68\x6f\x73\x65";
	static const u8 tv128_256_ciphertext[16] =
		"\x43\x8f\x18\x9c\x8d\xb4\xee\x4e"
		"\x3e\xf5\xc0\x05\x04\x01\x09\x41";

	static const u8 tv64_128_key[16] =
		"\x00\x01\x02\x03\x08\x09\x0a\x0b"
		"\x10\x11\x12\x13\x18\x19\x1a\x1b";
	static const u8 tv64_128_plaintext[8] =
		"\x2d\x43\x75\x74\x74\x65\x72\x3b";
	static const u8 tv64_128_ciphertext[8] =
		"\x8b\x02\x4e\x45\x48\xa5\x6f\x8c";
	struct speck128_ctx ctx128;
	struct speck64_ctx ctx64;
	u8 block[16];

	speck128_128_setkey(&ctx128, tv128_128_key);
	speck128_encrypt(&ctx128, block, tv128_128_plaintext);
	ASSERT(!memcmp(block, tv128_128_ciphertext, 16));
	speck128_decrypt(&ctx128, block, block);
	ASSERT(!memcmp(block, tv128_128_plaintext, 16));

	speck128_256_setkey(&ctx128, tv128_256_key);
	speck128_encrypt(&ctx128, block, tv128_256_plaintext);
	ASSERT(!memcmp(block, tv128_256_ciphertext, 16));
	speck128_decrypt(&ctx128, block, block);
	ASSERT(!memcmp(block, tv128_256_plaintext, 16));

	speck64_128_setkey(&ctx64, tv64_128_key);
	speck64_encrypt(&ctx64, block, tv64_128_plaintext);
	ASSERT(!memcmp(block, tv64_128_ciphertext, 8));
	speck64_decrypt(&ctx64, block, block);
	ASSERT(!memcmp(block, tv64_128_plaintext, 8));

#define BLOCK_BYTES		16
#define ENCRYPT			speck128_encrypt
#define DECRYPT			speck128_decrypt
#define	KEY			struct speck128_ctx

#define KEY_BYTES		16
#define SETKEY			speck128_128_setkey
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	_speck128_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	_speck128_xts_decrypt_neon
#endif
#define ALGNAME			"Speck128/128"
#include "xts_benchmark_template.h"

#define KEY_BYTES		32
#define SETKEY			speck128_256_setkey
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	_speck128_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	_speck128_xts_decrypt_neon
#endif
#define ALGNAME			"Speck128/256"
#include "xts_benchmark_template.h"

#undef BLOCK_BYTES
#undef ENCRYPT
#undef DECRYPT
#undef KEY
#define BLOCK_BYTES		8
#define ENCRYPT			speck64_encrypt
#define DECRYPT			speck64_decrypt
#define	KEY			struct speck64_ctx

#define KEY_BYTES		16
#define SETKEY			speck64_128_setkey
#ifdef __arm__
#  define XTS_ENCRYPT_SIMD	_speck64_xts_encrypt_neon
#  define XTS_DECRYPT_SIMD	_speck64_xts_decrypt_neon
#endif
#define ALGNAME			"Speck64/128"
#include "xts_benchmark_template.h"
}
