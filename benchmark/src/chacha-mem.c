/*
 * ChaCha-MEM (Masked Even-Mansour)
 *
 * Reference: "Improved Masking for Tweakable Blockciphers with Applications
 * to Authenticated Encryption" (https://eprint.iacr.org/2015/999.pdf)
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "chacha.h"

#define COLUMN_HALFUNROUND(n1, n2) ({	\
	x[7]  = ror32(x[7], n2);	\
	x[6]  = ror32(x[6], n2);	\
	x[5]  = ror32(x[5], n2);	\
	x[4]  = ror32(x[4], n2);	\
	x[7]  ^= x[11];			\
	x[6]  ^= x[10];			\
	x[5]  ^= x[9];			\
	x[4]  ^= x[8];			\
	x[11] -= x[15];			\
	x[10] -= x[14];			\
	x[9]  -= x[13];			\
	x[8]  -= x[12];			\
					\
	x[15] = ror32(x[15], n1);	\
	x[14] = ror32(x[14], n1);	\
	x[13] = ror32(x[13], n1);	\
	x[12] = ror32(x[12], n1);	\
	x[15] ^= x[3];			\
	x[14] ^= x[2];			\
	x[13] ^= x[1];			\
	x[12] ^= x[0];			\
	x[3]  -= x[7];			\
	x[2]  -= x[6];			\
	x[1]  -= x[5];			\
	x[0]  -= x[4]; })

#define DIAGONAL_HALFUNROUND(n1, n2) ({	\
	x[6] = ror32(x[6], n2);		\
	x[5] = ror32(x[5], n2);		\
	x[4] = ror32(x[4], n2);		\
	x[7] = ror32(x[7], n2);		\
	x[6] ^= x[11];			\
	x[5] ^= x[10];			\
	x[4] ^= x[9];			\
	x[7] ^= x[8];			\
	x[11] -= x[12];			\
	x[10] -= x[15];			\
	x[9]  -= x[14];			\
	x[8]  -= x[13];			\
					\
	x[14] = ror32(x[14], n1);	\
	x[13] = ror32(x[13], n1);	\
	x[12] = ror32(x[12], n1);	\
	x[15] = ror32(x[15], n1);	\
	x[14] ^= x[3];			\
	x[13] ^= x[2];			\
	x[12] ^= x[1];			\
	x[15] ^= x[0];			\
	x[3]  -= x[4];			\
	x[2]  -= x[7];			\
	x[1]  -= x[6];			\
	x[0]  -= x[5]; })

static void chacha_invperm_generic(u32 x[16], int nrounds)
{
	do {
		DIAGONAL_HALFUNROUND(8, 7);
		DIAGONAL_HALFUNROUND(16, 12);
		COLUMN_HALFUNROUND(8, 7);
		COLUMN_HALFUNROUND(16, 12);
	} while ((nrounds -= 2) != 0);
}

static void mem_next_mask(u32 mask[16])
{
	u32 t = rol32(mask[0], 5) ^ (mask[3] >> 7);
	int i;

	for (i = 0; i < 15; i++)
		mask[i] = mask[i + 1];
	mask[15] = t;
}

static void chacha_mem_crypt(const struct chacha_ctx *ctx,
			     u8 *dst, const u8 *src, unsigned int nbytes,
			     const u8 *iv, bool enc)
{
	u32 mask[16];

	ASSERT(nbytes % CHACHA_BLOCK_SIZE == 0);

	chacha_init_state(mask, ctx, iv);

	chacha_perm_generic(mask, ctx->nrounds);

	while (nbytes) {
		xor(dst, src, mask, CHACHA_BLOCK_SIZE);
		if (enc)
			chacha_perm_generic((u32 *)dst, ctx->nrounds);
		else
			chacha_invperm_generic((u32 *)dst, ctx->nrounds);
		xor(dst, dst, mask, CHACHA_BLOCK_SIZE);
		mem_next_mask(mask);
		nbytes -= CHACHA_BLOCK_SIZE;
		src += CHACHA_BLOCK_SIZE;
		dst += CHACHA_BLOCK_SIZE;
	}
}

static void chacha_mem_encrypt(const struct chacha_ctx *ctx, u8 *dst,
			       const u8 *src, unsigned int nbytes, const u8 *iv)
{
	chacha_mem_crypt(ctx, dst, src, nbytes, iv, true);
}

static void chacha_mem_decrypt(const struct chacha_ctx *ctx, u8 *dst,
			       const u8 *src, unsigned int nbytes, const u8 *iv)
{
	chacha_mem_crypt(ctx, dst, src, nbytes, iv, false);
}

#ifdef __arm__
void chacha_mem_encrypt_4block_neon(u32 *mask, u8 *dst, const u8 *src,
				    int nrounds);
void chacha_mem_decrypt_4block_neon(u32 *mask, u8 *dst, const u8 *src,
				    int nrounds);

static void chacha_mem_crypt_neon(const struct chacha_ctx *ctx,
				  u8 *dst, const u8 *src, unsigned int nbytes,
				  const u8 *iv, bool enc)
{
	u32 mask[16];

	ASSERT(nbytes % CHACHA_BLOCK_SIZE == 0);

	chacha_init_state(mask, ctx, iv);

	chacha_perm_neon(mask, ctx->nrounds);

	while (nbytes >= 4 * CHACHA_BLOCK_SIZE) {
		if (enc) {
			chacha_mem_encrypt_4block_neon(mask, dst, src,
						       ctx->nrounds);
		} else {
			chacha_mem_decrypt_4block_neon(mask, dst, src,
						       ctx->nrounds);
		}
		nbytes -= 4 * CHACHA_BLOCK_SIZE;
		src += 4 * CHACHA_BLOCK_SIZE;
		dst += 4 * CHACHA_BLOCK_SIZE;
	}

	while (nbytes) {
		xor(dst, src, mask, CHACHA_BLOCK_SIZE);
		if (enc)
			chacha_perm_neon((u32 *)dst, ctx->nrounds);
		else
			chacha_invperm_generic((u32 *)dst, ctx->nrounds);
		xor(dst, dst, mask, CHACHA_BLOCK_SIZE);
		mem_next_mask(mask);
		nbytes -= CHACHA_BLOCK_SIZE;
		src += CHACHA_BLOCK_SIZE;
		dst += CHACHA_BLOCK_SIZE;
	}
}

static void chacha_mem_encrypt_neon(const struct chacha_ctx *ctx, u8 *dst,
				    const u8 *src, unsigned int nbytes,
				    const u8 *iv)
{
	chacha_mem_crypt_neon(ctx, dst, src, nbytes, iv, true);
}

static void chacha_mem_decrypt_neon(const struct chacha_ctx *ctx, u8 *dst,
				    const u8 *src, unsigned int nbytes,
				    const u8 *iv)
{
	chacha_mem_crypt_neon(ctx, dst, src, nbytes, iv, false);
}
#endif /* __arm__ */

static int g_nrounds;

static void chacha_mem_setkey(struct chacha_ctx *ctx, const u8 *key)
{
	chacha_setkey(ctx, key, g_nrounds);
}

static void do_test_chacha_mem(int nrounds)
{
	char algname[32];
	u8 orig_state[64];
	u32 state[16];

	rand_bytes(orig_state, 64);
	memcpy(state, orig_state, 64);
	chacha_perm_generic(state, nrounds);
	ASSERT(memcmp(state, orig_state, 64));
	chacha_invperm_generic(state, nrounds);
	ASSERT(!memcmp(state, orig_state, 64));

	sprintf(algname, "ChaCha%d-MEM", nrounds);
	g_nrounds = nrounds;
#define ENCRYPT		chacha_mem_encrypt
#define DECRYPT		chacha_mem_decrypt
#ifdef __arm__
#  define ENCRYPT_SIMD	chacha_mem_encrypt_neon
#  define DECRYPT_SIMD	chacha_mem_decrypt_neon
#endif
#define KEY		struct chacha_ctx
#define SETKEY		chacha_mem_setkey
#define KEY_BYTES	CHACHA_KEY_SIZE
#define IV_BYTES	CHACHA_IV_SIZE
#define ALGNAME		algname
#include "cipher_benchmark_template.h"
}


void test_chacha_mem(void)
{
	do_test_chacha_mem(20);
	do_test_chacha_mem(12);
	do_test_chacha_mem(8);
}
