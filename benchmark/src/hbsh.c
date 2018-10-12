/*
 * HBSH encryption mode, including Adiantum and HPolyC
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "cbconfig.h"

#include "aes.h"
#include "chacha.h"
#include "nh.h"
#include "noekeon.h"
#include "poly1305.h"
#include "testvec.h"
#include "util.h"

#define HBSH_KEYSIZE			CHACHA_KEY_SIZE

#define HPOLYC_DEFAULT_TWEAK_LEN	12
#define ADIANTUM_DEFAULT_TWEAK_LEN	32

/*
 * Size of right-hand block of input data, in bytes; also the size of the block
 * cipher's block size and the hash function's output.  HBSH doesn't prescribe a
 * specific value here (it's more general), but for now we only support 16 bytes
 * which is the size used in HPolyC and Adiantum.
 */
#define BLOCKCIPHER_BLOCK_SIZE		16

#define NHPOLY1305_KEY_SIZE	(POLY1305_BLOCK_SIZE + NH_KEY_BYTES)

/* Size of the hash key (H_K) in bytes */
#define HPOLYC_HASH_KEY_SIZE	POLY1305_BLOCK_SIZE
#define ADIANTUM_HASH_KEY_SIZE	(POLY1305_BLOCK_SIZE + NHPOLY1305_KEY_SIZE)

/* block cipher to use */
#if 1
#  define BLOCKCIPHER_NAME	"AES"
#  define BLOCKCIPHER_SETKEY	aes256_setkey
#  define BLOCKCIPHER_ENCRYPT	aes_encrypt
#  define BLOCKCIPHER_DECRYPT	aes_decrypt
#  define BLOCKCIPHER_CTX	struct aes_ctx
#  define BLOCKCIPHER_KEYSIZE	32
#else
#  define BLOCKCIPHER_NAME	"NOEKEON"
#  define BLOCKCIPHER_SETKEY	noekeon_setkey
#  define BLOCKCIPHER_ENCRYPT	noekeon_encrypt
#  define BLOCKCIPHER_DECRYPT	noekeon_decrypt
#  define BLOCKCIPHER_CTX	struct noekeon_ctx
#  define BLOCKCIPHER_KEYSIZE	16
#endif

#undef HAVE_HBSH_SIMD
#ifdef HAVE_CHACHA_SIMD
#  define HAVE_HBSH_SIMD 1
#endif

enum hbsh_hash_alg {
	HBSH_HASH_HPOLYC,
	HBSH_HASH_ADIANTUM,
};

union hbsh_hash_state {
	struct poly1305_state hpolyc;	/* unreduced hash state */
	le128 adiantum;			/* reduced hash state */
};

struct hbsh_ctx {
	struct chacha_ctx chacha;
	BLOCKCIPHER_CTX blkcipher;
	enum hbsh_hash_alg hash_alg;
	unsigned int default_tweak_len;
	union {
		struct poly1305_key hpolyc;
		struct adiantum_hash_key {
			struct poly1305_key polyt;
			struct poly1305_key poly;
			struct nh_ctx nh;
		} adiantum;
	} hash;
};

/*
 * Given the XChaCha stream key K_S, derive the block cipher key K_E and the
 * hash key K_H as follows:
 *
 *     K_E || K_H || ... = XChaCha(key=K_S, nonce=1||0^191)
 *
 * Note that this denotes using bits from the XChaCha keystream, which here we
 * get indirectly by encrypting a buffer containing all 0's.
 */
static void hbsh_setkey(struct hbsh_ctx *ctx, const u8 *key,
			int nrounds, enum hbsh_hash_alg hash_alg)
{
	static const u8 iv[XCHACHA_IV_SIZE] = { 1 };
	u8 keys[BLOCKCIPHER_KEYSIZE +
		max(HPOLYC_HASH_KEY_SIZE, ADIANTUM_HASH_KEY_SIZE)];
	u8 *keyp = keys;

	chacha_setkey(&ctx->chacha, key, nrounds);

	memset(keys, 0, sizeof(keys));
	xchacha(&ctx->chacha, keys, keys, sizeof(keys), iv, false);

	ctx->hash_alg = hash_alg;
	BLOCKCIPHER_SETKEY(&ctx->blkcipher, keyp);
	keyp += BLOCKCIPHER_KEYSIZE;

	switch (hash_alg) {
	case HBSH_HASH_HPOLYC:
		ctx->default_tweak_len = HPOLYC_DEFAULT_TWEAK_LEN;
		poly1305_setkey(&ctx->hash.hpolyc, keyp);
		break;
	case HBSH_HASH_ADIANTUM:
		ctx->default_tweak_len = ADIANTUM_DEFAULT_TWEAK_LEN;
		poly1305_setkey(&ctx->hash.adiantum.polyt, keyp);
		keyp += POLY1305_BLOCK_SIZE;
		poly1305_setkey(&ctx->hash.adiantum.poly, keyp);
		keyp += POLY1305_BLOCK_SIZE;
		nh_setkey(&ctx->hash.adiantum.nh, keyp);
		break;
	default:
		ASSERT(0);
	}
}

/* HPolyC: export state after hashing the tweak length and tweak */
static void hash_header_hpolyc(const struct poly1305_key *key, const u8 *tweak,
			       size_t tweak_len, size_t message_len, bool simd,
			       struct poly1305_state *out)
{
	size_t full_tweaklen = sizeof(__le32) + tweak_len;
	size_t tweakpad = -full_tweaklen % POLY1305_BLOCK_SIZE;
	u8 tweakbuf[full_tweaklen + tweakpad];

	ASSERT(tweak_len <= UINT32_MAX / 8);
	put_unaligned_le32(tweak_len * 8, tweakbuf);
	memcpy(&tweakbuf[sizeof(__le32)], tweak, tweak_len);
	memset(&tweakbuf[sizeof(__le32) + tweak_len], 0, tweakpad);

	poly1305_init(out);
	poly1305_blocks(key, out, tweakbuf,
			sizeof(tweakbuf) / POLY1305_BLOCK_SIZE, 1, simd);
}

/* HPolyC: hash the message, given the state after hashing the tweak */
static void hash_msg_hpolyc(const struct poly1305_key *key,
			    const struct poly1305_state *initial_state,
			    const u8 *src, size_t srclen, bool simd,
			    le128 *digest)
{
	struct poly1305_state state = *initial_state;

	poly1305_tail(key, &state, src, srclen, simd);
	poly1305_emit(&state, digest, simd);
}

/*
 * For Adiantum hashing: apply the Poly1305 εA∆U hash function to
 * (message length, tweak) and save the result to ->out.
 *
 * This value is reused in both the first and second hash steps.  Specifically,
 * it's added to the result of an independently keyed εA∆U hash function (for
 * equal length inputs only) taken over the message.  This gives the overall
 * Adiantum hash of the (tweak, message) pair.
 */
static void hash_header_adiantum(const struct adiantum_hash_key *ctx,
				 const u8 *tweak, size_t tweak_len,
				 size_t message_len, bool simd, le128 *out)
{
	struct {
		__le64 message_bits;
		__le64 pad;
	} header = {
		cpu_to_le64(message_len * 8),
	};
	struct poly1305_state state;

	BUILD_BUG_ON(sizeof(header) % POLY1305_BLOCK_SIZE != 0);
	poly1305_init(&state);
	poly1305_blocks(&ctx->polyt, &state, &header,
			sizeof(header) / POLY1305_BLOCK_SIZE, 1,
			!KERNELISH && simd);
	poly1305_tail(&ctx->polyt, &state, tweak, tweak_len, !KERNELISH && simd);
	poly1305_emit(&state, out, !KERNELISH && simd);
}

/*
 * For Adiantum hashing: hash the left-hand block (the "bulk") of the message
 * using NHPoly1305.
 */
static void hash_msg_adiantum(const struct adiantum_hash_key *ctx,
			      const u8 *src, size_t srclen, bool simd,
			      le128 *digest)
{
#define NH_HASHES_PER_POLY	16	/* helps with SIMD Poly1305 */
	struct poly1305_state state;
	union nh_hash nh_hashes[NH_HASHES_PER_POLY];
	size_t num_hashes = 0;

	BUILD_BUG_ON(sizeof(union nh_hash) % POLY1305_BLOCK_SIZE != 0);

	poly1305_init(&state);

	while (srclen >= NH_MESSAGE_BYTES) {
		nh(ctx->nh.key, src, NH_MESSAGE_BYTES,
		   nh_hashes[num_hashes++].bytes, simd);
		if (num_hashes == ARRAY_SIZE(nh_hashes)) {
			poly1305_blocks(&ctx->poly, &state, nh_hashes,
					sizeof(nh_hashes) / POLY1305_BLOCK_SIZE,
					1, !KERNELISH && simd);
			num_hashes = 0;
		}
		src += NH_MESSAGE_BYTES;
		srclen -= NH_MESSAGE_BYTES;
	}

	if (srclen) {
		unsigned int partial = srclen % NH_MESSAGE_UNIT;
		union nh_hash *hash = &nh_hashes[num_hashes++];

		if (srclen >= NH_MESSAGE_UNIT) {
			nh(ctx->nh.key, src, srclen - partial, hash->bytes,
			   simd);
			src += srclen - partial;
		}
		if (partial) {
			u8 unit[NH_MESSAGE_UNIT];
			union nh_hash tmp_hash;

			memcpy(unit, src, partial);
			memset(&unit[partial], 0, sizeof(unit) - partial);
			if (srclen >= NH_MESSAGE_UNIT) {
				nh(&ctx->nh.key[(srclen - partial) / 4],
				   unit, sizeof(unit), tmp_hash.bytes, simd);
				nh_combine(hash, hash, &tmp_hash);
			} else {
				nh(ctx->nh.key, unit, sizeof(unit),
				   hash->bytes, simd);
			}
		}
	}

	if (num_hashes) {
		poly1305_blocks(&ctx->poly, &state, nh_hashes,
				num_hashes * (NH_HASH_BYTES /
					      POLY1305_BLOCK_SIZE),
				1, !KERNELISH && simd);
	}
	poly1305_emit(&state, digest, !KERNELISH && simd);
}

static void hash_header(const struct hbsh_ctx *ctx, const u8 *tweak,
			size_t tweak_len, size_t message_len, bool simd,
			union hbsh_hash_state *out)
{
	switch (ctx->hash_alg) {
	case HBSH_HASH_HPOLYC:
		hash_header_hpolyc(&ctx->hash.hpolyc, tweak, tweak_len,
				   message_len, simd, &out->hpolyc);
		break;
	case HBSH_HASH_ADIANTUM:
		hash_header_adiantum(&ctx->hash.adiantum, tweak, tweak_len,
				     message_len, simd, &out->adiantum);
		break;
	default:
		ASSERT(0);
	}
}

static void hash_msg(const struct hbsh_ctx *ctx,
		     const union hbsh_hash_state *initial_state,
		     const u8 *src, size_t srclen, bool simd, le128 *digest)
{
	switch (ctx->hash_alg) {
	case HBSH_HASH_HPOLYC:
		hash_msg_hpolyc(&ctx->hash.hpolyc, &initial_state->hpolyc,
				src, srclen, simd, digest);
		break;
	case HBSH_HASH_ADIANTUM:
		hash_msg_adiantum(&ctx->hash.adiantum, src, srclen, simd,
				  digest);
		le128_add(digest, digest, &initial_state->adiantum);
		break;
	default:
		ASSERT(0);
	}
}

enum {
	ENCRYPT,
	DECRYPT,
};

static forceinline void
__hbsh_crypt(const struct hbsh_ctx *ctx, u8 *dst, const u8 *src, size_t nbytes,
	     const u8 *tweak, size_t tweak_len, int direction, bool simd)
{
	const size_t bulk_len = nbytes - BLOCKCIPHER_BLOCK_SIZE;
	union hbsh_hash_state header_hash;
	/*
	 * Buffer for right-hand block of data, i.e.
	 *
	 *    P_L => P_M => C_M => C_R when encrypting, or
	 *    C_R => C_M => P_M => P_L when decrypting.
	 *
	 * Also used to build the IV for the stream cipher.
	 */
	union {
		u8 bytes[XCHACHA_IV_SIZE];
		__le32 words[XCHACHA_IV_SIZE / sizeof(__le32)];
		le128 bignum;	/* interpret as element of Z/(2^{128}Z) */
	} rbuf;
	le128 digest;
	size_t stream_len;

	ASSERT(nbytes >= BLOCKCIPHER_BLOCK_SIZE);

	/*
	 * First hash step
	 *	enc: P_M = P_R + H_{K_H}(T, P_L)
	 *	dec: C_M = C_R + H_{K_H}(T, C_L)
	 */
	hash_header(ctx, tweak, tweak_len, bulk_len, simd, &header_hash);
	hash_msg(ctx, &header_hash, src, bulk_len, simd, &digest);
	memcpy(&rbuf.bignum, src + bulk_len, BLOCKCIPHER_BLOCK_SIZE);
	le128_add(&rbuf.bignum, &rbuf.bignum, &digest);

	/* Initialize the rest of the XChaCha IV (first part is C_M) */
	BUILD_BUG_ON(BLOCKCIPHER_BLOCK_SIZE != 16);
	BUILD_BUG_ON(XCHACHA_IV_SIZE != 32);	/* nonce || stream position */
	rbuf.words[4] = cpu_to_le32(1);
	rbuf.words[5] = 0;
	rbuf.words[6] = 0;
	rbuf.words[7] = 0;

	/*
	 * XChaCha needs to be done on all the data except the last 16 bytes;
	 * for disk encryption that usually means 4080 or 496 bytes.  But ChaCha
	 * implementations tend to be most efficient when passed a whole number
	 * of 64-byte ChaCha blocks, or sometimes even a multiple of 256 bytes.
	 * And here it doesn't matter whether the last 16 bytes are written to,
	 * as the second hash step will overwrite them.  Thus, round the XChaCha
	 * length up to the next 64-byte boundary if possible.
	 */
	stream_len = bulk_len;
	if (round_up(stream_len, CHACHA_BLOCK_SIZE) <= nbytes)
		stream_len = round_up(stream_len, CHACHA_BLOCK_SIZE);

	if (direction == ENCRYPT) {
		/* Encrypt P_M with the block cipher to get C_M */
		BLOCKCIPHER_ENCRYPT(&ctx->blkcipher, rbuf.bytes, rbuf.bytes);

		xchacha(&ctx->chacha, dst, src, stream_len, rbuf.bytes, simd);
	} else {
		xchacha(&ctx->chacha, dst, src, stream_len, rbuf.bytes, simd);

		/* Decrypt C_M with the block cipher to get P_M */
		BLOCKCIPHER_DECRYPT(&ctx->blkcipher, rbuf.bytes, rbuf.bytes);
	}

	/*
	 * Second hash step
	 *	enc: C_R = C_M - H_{K_H}(T, C_L)
	 *	dec: P_R = P_M - H_{K_H}(T, P_L)
	 */
	hash_msg(ctx, &header_hash, dst, bulk_len, simd, &digest);
	le128_sub(&rbuf.bignum, &rbuf.bignum, &digest);
	memcpy(dst + bulk_len, &rbuf.bignum, BLOCKCIPHER_BLOCK_SIZE);
}

static void hbsh_encrypt_generic(const struct hbsh_ctx *ctx, u8 *dst,
				 const u8 *src, unsigned int nbytes,
				 const u8 *iv)
{
	__hbsh_crypt(ctx, dst, src, nbytes, iv, ctx->default_tweak_len,
		     ENCRYPT, false);
}

static void hbsh_decrypt_generic(const struct hbsh_ctx *ctx, u8 *dst,
				 const u8 *src, unsigned int nbytes,
				 const u8 *iv)
{
	__hbsh_crypt(ctx, dst, src, nbytes, iv, ctx->default_tweak_len,
		     DECRYPT, false);
}

#ifdef HAVE_HBSH_SIMD
static void hbsh_encrypt_simd(const struct hbsh_ctx *ctx, u8 *dst,
			      const u8 *src, unsigned int nbytes, const u8 *iv)
{
	__hbsh_crypt(ctx, dst, src, nbytes, iv, ctx->default_tweak_len,
		     ENCRYPT, true);
}

static void hbsh_decrypt_simd(const struct hbsh_ctx *ctx, u8 *dst,
			      const u8 *src, unsigned int nbytes, const u8 *iv)
{
	__hbsh_crypt(ctx, dst, src, nbytes, iv, ctx->default_tweak_len,
		     DECRYPT, true);
}
#endif /* HAVE_HBSH_SIMD */

static void hbsh_crypt(const struct hbsh_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *tweak, size_t tweak_len,
		       int direction, bool simd)
{
	__hbsh_crypt(ctx, dst, src, nbytes, tweak, tweak_len, direction, simd);
}

struct hbsh_testvec {
	struct testvec_buffer key;
	struct testvec_buffer tweak;
	struct testvec_buffer plaintext;
	struct testvec_buffer ciphertext;
};

#include "adiantum_testvecs.h"
#include "hpolyc_testvecs.h"

static void do_test_hbsh_testvec(const struct hbsh_testvec *v,
				 struct hbsh_ctx *ctx, bool simd)
{
	size_t len = v->plaintext.len;
	u8 ptext[len];
	u8 tmp1[len];
	u8 tmp2[len];

	ASSERT(v->ciphertext.len == len);

	memcpy(ptext, v->plaintext.data, len);

	/* out-of place */
	hbsh_crypt(ctx, tmp1, ptext, len, v->tweak.data, v->tweak.len,
		   ENCRYPT, simd);
	ASSERT(!memcmp(tmp1, v->ciphertext.data, len));

	hbsh_crypt(ctx, tmp2, tmp1, len, v->tweak.data, v->tweak.len,
		   DECRYPT, simd);
	ASSERT(!memcmp(tmp2, v->plaintext.data, len));

	/* in-place */
	hbsh_crypt(ctx, tmp2, tmp2, len, v->tweak.data, v->tweak.len,
		   ENCRYPT, simd);
	ASSERT(!memcmp(tmp2, v->ciphertext.data, len));

	hbsh_crypt(ctx, tmp1, tmp1, len, v->tweak.data, v->tweak.len,
		   DECRYPT, simd);
	ASSERT(!memcmp(tmp1, v->plaintext.data, len));
}

static void test_hbsh_testvec(const struct hbsh_testvec *v, int nrounds,
			      enum hbsh_hash_alg hash_alg)
{
	struct hbsh_ctx ctx;

	ASSERT(v->key.len == HBSH_KEYSIZE);
	hbsh_setkey(&ctx, v->key.data, nrounds, hash_alg);

	do_test_hbsh_testvec(v, &ctx, false);
#ifdef HAVE_HBSH_SIMD
	do_test_hbsh_testvec(v, &ctx, true);
#endif
}

static int g_nrounds;

static void hpolyc_setkey(struct hbsh_ctx *ctx, const u8 *key)
{
	hbsh_setkey(ctx, key, g_nrounds, HBSH_HASH_HPOLYC);
}

static void adiantum_setkey(struct hbsh_ctx *ctx, const u8 *key)
{
	hbsh_setkey(ctx, key, g_nrounds, HBSH_HASH_ADIANTUM);
}

static void do_test_hpolyc(int nrounds)
{
	char algname[64];

	g_nrounds = nrounds;
	sprintf(algname, "HPolyC-XChaCha%d-%s", nrounds, BLOCKCIPHER_NAME);

	if (strcmp(BLOCKCIPHER_NAME, "AES") == 0) {
		const struct hbsh_testvec *testvecs;
		size_t num_testvecs;
		size_t i;

		switch (nrounds) {
		case 20:
			testvecs = hpolyc_xchacha20_aes256_tv;
			num_testvecs = ARRAY_SIZE(hpolyc_xchacha20_aes256_tv);
			break;
		case 12:
			testvecs = hpolyc_xchacha12_aes256_tv;
			num_testvecs = ARRAY_SIZE(hpolyc_xchacha12_aes256_tv);
			break;
		case 8:
			testvecs = hpolyc_xchacha8_aes256_tv;
			num_testvecs = ARRAY_SIZE(hpolyc_xchacha8_aes256_tv);
			break;
		default:
			ASSERT(0);
		}

		for (i = 0; i < num_testvecs; i++) {
			test_hbsh_testvec(&testvecs[i], nrounds,
					  HBSH_HASH_HPOLYC);
		}
	}

#define ENCRYPT		hbsh_encrypt_generic
#define DECRYPT		hbsh_decrypt_generic
#ifdef HAVE_HBSH_SIMD
#  define ENCRYPT_SIMD	hbsh_encrypt_simd
#  define DECRYPT_SIMD	hbsh_decrypt_simd
#endif
#define KEY		struct hbsh_ctx
#define SETKEY		hpolyc_setkey
#define KEY_BYTES	HBSH_KEYSIZE
#define IV_BYTES	HPOLYC_DEFAULT_TWEAK_LEN
#define ALGNAME		algname
#include "cipher_benchmark_template.h"
}

static void do_test_adiantum(int nrounds)
{
	char algname[64];

	g_nrounds = nrounds;
	sprintf(algname, "Adiantum-XChaCha%d-%s", nrounds, BLOCKCIPHER_NAME);

	if (strcmp(BLOCKCIPHER_NAME, "AES") == 0) {
		const struct hbsh_testvec *testvecs;
		size_t num_testvecs;
		size_t i;

		switch (nrounds) {
		case 20:
			testvecs = adiantum_xchacha20_aes256_tv;
			num_testvecs = ARRAY_SIZE(adiantum_xchacha20_aes256_tv);
			break;
		case 12:
			testvecs = adiantum_xchacha12_aes256_tv;
			num_testvecs = ARRAY_SIZE(adiantum_xchacha12_aes256_tv);
			break;
		case 8:
			testvecs = adiantum_xchacha8_aes256_tv;
			num_testvecs = ARRAY_SIZE(adiantum_xchacha8_aes256_tv);
			break;
		default:
			ASSERT(0);
		}

		for (i = 0; i < num_testvecs; i++) {
			test_hbsh_testvec(&testvecs[i], nrounds,
					  HBSH_HASH_ADIANTUM);
		}
	}

#define ENCRYPT		hbsh_encrypt_generic
#define DECRYPT		hbsh_decrypt_generic
#ifdef HAVE_HBSH_SIMD
#  define ENCRYPT_SIMD	hbsh_encrypt_simd
#  define DECRYPT_SIMD	hbsh_decrypt_simd
#endif
#define KEY		struct hbsh_ctx
#define SETKEY		adiantum_setkey
#define KEY_BYTES	HBSH_KEYSIZE
#define IV_BYTES	ADIANTUM_DEFAULT_TWEAK_LEN
#define ALGNAME		algname
#include "cipher_benchmark_template.h"
}

void test_hpolyc(void)
{
	do_test_hpolyc(20);
	do_test_hpolyc(12);
	do_test_hpolyc(8);
}

void test_adiantum(void)
{
	do_test_adiantum(20);
	do_test_adiantum(12);
	do_test_adiantum(8);
}
