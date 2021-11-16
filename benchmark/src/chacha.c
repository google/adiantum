/*
 * ChaCha and XChaCha stream ciphers
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "cbconfig.h"

#include "chacha.h"
#include "util.h"

/* Choose the ARM32 assembly implementation of ChaCha */
enum {
	CHACHA_ASM_IMPL_LINUX_NEON,	/* fastest on Cortex-A7 */
	CHACHA_ASM_IMPL_SCALAR,		/* nearly fastest on Cortex-A7 */
	CHACHA_ASM_IMPL_OPENSSL_NEON,	/* slow on Cortex-A7, fastest on other ARM CPUs */
	CHACHA_ASM_IMPL_OPENSSL_SCALAR, /* slower than other scalar impl */
};
#if KERNELISH
#define CHACHA_ASM_IMPL CHACHA_ASM_IMPL_SCALAR
#else
#define CHACHA_ASM_IMPL CHACHA_ASM_IMPL_LINUX_NEON
#endif

void chacha_setkey(struct chacha_ctx *ctx, const u8 *key, int nrounds)
{
	int i;

	for (i = 0; i < CHACHA_KEY_SIZE / sizeof(__le32); i++)
		ctx->key[i] = get_unaligned_le32(key + i * sizeof(__le32));
	ctx->nrounds = nrounds;
}

void chacha_init_state(u32 state[16], const struct chacha_ctx *ctx,
		       const u8 *iv)
{
	state[0]  = 0x61707865; /* "expa" */
	state[1]  = 0x3320646e; /* "nd 3" */
	state[2]  = 0x79622d32; /* "2-by" */
	state[3]  = 0x6b206574; /* "te k" */
	state[4]  = ctx->key[0];
	state[5]  = ctx->key[1];
	state[6]  = ctx->key[2];
	state[7]  = ctx->key[3];
	state[8]  = ctx->key[4];
	state[9]  = ctx->key[5];
	state[10] = ctx->key[6];
	state[11] = ctx->key[7];
	state[12] = get_unaligned_le32(iv +  0);
	state[13] = get_unaligned_le32(iv +  4);
	state[14] = get_unaligned_le32(iv +  8);
	state[15] = get_unaligned_le32(iv + 12);
}

#define COLUMN_HALFROUND(n1, n2) ({	\
	x[0]  += x[4];			\
	x[1]  += x[5];			\
	x[2]  += x[6];			\
	x[3]  += x[7];			\
	x[12] ^= x[0];			\
	x[13] ^= x[1];			\
	x[14] ^= x[2];			\
	x[15] ^= x[3];			\
	x[12] = rol32(x[12], n1);	\
	x[13] = rol32(x[13], n1);	\
	x[14] = rol32(x[14], n1);	\
	x[15] = rol32(x[15], n1);	\
					\
	x[8]  += x[12];			\
	x[9]  += x[13];			\
	x[10] += x[14];			\
	x[11] += x[15];			\
	x[4]  ^= x[8];			\
	x[5]  ^= x[9];			\
	x[6]  ^= x[10];			\
	x[7]  ^= x[11];			\
	x[4]  = rol32(x[4], n2);	\
	x[5]  = rol32(x[5], n2);	\
	x[6]  = rol32(x[6], n2);	\
	x[7]  = rol32(x[7], n2); })

#define DIAGONAL_HALFROUND(n1, n2) ({	\
	x[0]  += x[5];			\
	x[1]  += x[6];			\
	x[2]  += x[7];			\
	x[3]  += x[4];			\
	x[15] ^= x[0];			\
	x[12] ^= x[1];			\
	x[13] ^= x[2];			\
	x[14] ^= x[3];			\
	x[15] = rol32(x[15], n1);	\
	x[12] = rol32(x[12], n1);	\
	x[13] = rol32(x[13], n1);	\
	x[14] = rol32(x[14], n1);	\
					\
	x[8]  += x[13];			\
	x[9]  += x[14];			\
	x[10] += x[15];			\
	x[11] += x[12];			\
	x[7] ^= x[8];			\
	x[4] ^= x[9];			\
	x[5] ^= x[10];			\
	x[6] ^= x[11];			\
	x[7] = rol32(x[7], n2);		\
	x[4] = rol32(x[4], n2);		\
	x[5] = rol32(x[5], n2);		\
	x[6] = rol32(x[6], n2); })

void chacha_perm_generic(u32 x[16], int nrounds)
{
	do {
		COLUMN_HALFROUND(16, 12);
		COLUMN_HALFROUND(8, 7);
		DIAGONAL_HALFROUND(16, 12);
		DIAGONAL_HALFROUND(8, 7);
	} while ((nrounds -= 2) != 0);
}

static void chacha_block_generic(u32 state[16], __le32 stream[16], int nrounds)
{
	u32 x[16];
	int i;

	memcpy(x, state, sizeof(x));

	chacha_perm_generic(x, nrounds);

	for (i = 0; i < 16; i++)
		stream[i] = cpu_to_le32(x[i] + state[i]);

	state[12]++;
}

static void chacha_generic(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
			   unsigned int bytes, const u8 *iv)
{
	u32 state[16];
	__le32 stream[16];

	chacha_init_state(state, ctx, iv);

	while (bytes) {
		chacha_block_generic(state, stream, ctx->nrounds);
		if (bytes < CHACHA_BLOCK_SIZE) {
			xor(dst, src, stream, bytes);
			break;
		}
		xor(dst, src, stream, CHACHA_BLOCK_SIZE);
		bytes -= CHACHA_BLOCK_SIZE;
		dst += CHACHA_BLOCK_SIZE;
		src += CHACHA_BLOCK_SIZE;
	}
}

static inline void __maybe_unused
chacha_advance(u32 state[16], u8 **dst_p, const u8 **src_p,
	       unsigned int *bytes_p, unsigned int blocks)
{
	state[12] += blocks;
	*dst_p += blocks * CHACHA_BLOCK_SIZE;
	*src_p += blocks * CHACHA_BLOCK_SIZE;
	*bytes_p -= blocks * CHACHA_BLOCK_SIZE;
}

#ifdef __arm__

/* CHACHA_ASM_IMPL_LINUX_NEON */
void chacha_block_xor_neon(u32 state[16], u8 *dst, const u8 *src, int nrounds);
void chacha_4block_xor_neon(u32 state[16], u8 *dst, const u8 *src, int nrounds);
/* + chacha_perm_neon() */

/* CHACHA_ASM_IMPL_SCALAR */
void chacha_arm(u8 *out, const u8 *in, size_t len, const u32 key[8],
		const u32 iv[4], int nrounds);
void hchacha_arm(const u32 state[16], u32 out[8], int nrounds);

/* CHACHA_ASM_IMPL_OPENSSL_NEON */
void openssl_chacha20_neon(u8 *out, const u8 *in, size_t len, const u32 key[8],
			   const u32 counter[4]);

/* CHACHA_ASM_IMPL_OPENSSL_SCALAR */
void openssl_chacha20_arm(u8 *out, const u8 *in, size_t len, const u32 key[8],
			  const u32 counter[4]);

static void chacha_simd(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
			unsigned int bytes, const u8 *iv)
{
	u32 state[16];
	u8 buf[4 * CHACHA_BLOCK_SIZE] __attribute__((aligned(4)));

	if (CHACHA_ASM_IMPL == CHACHA_ASM_IMPL_OPENSSL_NEON &&
	    ctx->nrounds == 20) {
		u32 _iv[4];

		if (!bytes)	/* asm doesn't handle empty input */
			return;

		memcpy(_iv, iv, 16);
		openssl_chacha20_neon(dst, src, bytes, ctx->key, _iv);
		return;
	} else if (CHACHA_ASM_IMPL == CHACHA_ASM_IMPL_OPENSSL_SCALAR &&
		   ctx->nrounds == 20) {
		u32 _iv[4];

		memcpy(_iv, iv, 16);
		openssl_chacha20_arm(dst, src, bytes, ctx->key, _iv);
		return;
	} else if (CHACHA_ASM_IMPL == CHACHA_ASM_IMPL_SCALAR) {
		u32 _iv[4];

		memcpy(_iv, iv, 16);
		chacha_arm(dst, src, bytes, ctx->key, _iv, ctx->nrounds);
		return;
	}

	/* CHACHA_ASM_IMPL_LINUX_NEON */

	chacha_init_state(state, ctx, iv);

	while (bytes >= 4 * CHACHA_BLOCK_SIZE) {
		chacha_4block_xor_neon(state, dst, src, ctx->nrounds);
		chacha_advance(state, &dst, &src, &bytes, 4);
	}
	if (bytes > 2 * CHACHA_BLOCK_SIZE) {
		/* optimization: use _4block if more than 2 blocks remain */
		memcpy(buf, src, bytes);
		chacha_4block_xor_neon(state, buf, buf, ctx->nrounds);
		memcpy(dst, buf, bytes);
	} else {
		while (bytes >= CHACHA_BLOCK_SIZE) {
			chacha_block_xor_neon(state, dst, src, ctx->nrounds);
			chacha_advance(state, &dst, &src, &bytes, 1);
		}
		if (bytes) {
			memcpy(buf, src, bytes);
			chacha_block_xor_neon(state, buf, buf, ctx->nrounds);
			memcpy(dst, buf, bytes);
		}
	}
}

static void hchacha_simd(const u32 state[16], u32 out[8], int nrounds)
{
	/* faster than chacha_perm_neon() on most (or all?) CPUs */
	hchacha_arm(state, out, nrounds);
}

#elif defined(__aarch64__)

asmlinkage void chacha_block_xor_neon(u32 *state, u8 *dst, const u8 *src,
				      int nrounds);
asmlinkage void chacha_4block_xor_neon(u32 *state, u8 *dst, const u8 *src,
				       int nrounds, int bytes);
asmlinkage void hchacha_block_neon(const u32 *state, u32 *out, int nrounds);

static void chacha_simd(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
			unsigned int bytes, const u8 *iv)
{
	u32 state[16];
	u8 buf[CHACHA_BLOCK_SIZE];

	chacha_init_state(state, ctx, iv);

	while (bytes >= 5 * CHACHA_BLOCK_SIZE) {
		chacha_4block_xor_neon(state, dst, src, ctx->nrounds,
				       5 * CHACHA_BLOCK_SIZE);
		chacha_advance(state, &dst, &src, &bytes, 5);
	}

	if (bytes > CHACHA_BLOCK_SIZE) {
		chacha_4block_xor_neon(state, dst, src, ctx->nrounds, bytes);
	} else {
		memcpy(buf, src, bytes);
		chacha_block_xor_neon(state, buf, buf, ctx->nrounds);
		memcpy(dst, buf, bytes);
	}
}

static void hchacha_simd(const u32 state[16], u32 out[8], int nrounds)
{
	hchacha_block_neon(state, out, nrounds);
}

#elif defined(__x86_64__) && defined(__SSSE3__)

asmlinkage void chacha_block_xor_ssse3(u32 *state, u8 *dst, const u8 *src,
				       unsigned int len, int nrounds);
asmlinkage void chacha_4block_xor_ssse3(u32 *state, u8 *dst, const u8 *src,
					unsigned int len, int nrounds);
asmlinkage void hchacha_block_ssse3(const u32 *state, u32 *out, int nrounds);

asmlinkage void chacha_2block_xor_avx2(u32 *state, u8 *dst, const u8 *src,
				       unsigned int len, int nrounds);
asmlinkage void chacha_4block_xor_avx2(u32 *state, u8 *dst, const u8 *src,
				       unsigned int len, int nrounds);
asmlinkage void chacha_8block_xor_avx2(u32 *state, u8 *dst, const u8 *src,
				       unsigned int len, int nrounds);

asmlinkage void chacha_2block_xor_avx512vl(u32 *state, u8 *dst, const u8 *src,
					   unsigned int len, int nrounds);
asmlinkage void chacha_4block_xor_avx512vl(u32 *state, u8 *dst, const u8 *src,
					   unsigned int len, int nrounds);
asmlinkage void chacha_8block_xor_avx512vl(u32 *state, u8 *dst, const u8 *src,
					   unsigned int len, int nrounds);

static void chacha_simd(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
			unsigned int bytes, const u8 *iv)
{
	const int nrounds = ctx->nrounds;
	u32 state[16] __attribute__((aligned(16)));

	chacha_init_state(state, ctx, iv);

#ifdef __AVX512VL__
#define SIMD_IMPL_NAME "AVX-512VL"
	while (bytes >= 8 * CHACHA_BLOCK_SIZE) {
		chacha_8block_xor_avx512vl(state, dst, src, bytes, nrounds);
		chacha_advance(state, &dst, &src, &bytes, 8);
	}
	if (bytes > 4 * CHACHA_BLOCK_SIZE)
		chacha_8block_xor_avx512vl(state, dst, src, bytes, nrounds);
	else if (bytes > 2 * CHACHA_BLOCK_SIZE)
		chacha_4block_xor_avx512vl(state, dst, src, bytes, nrounds);
	else if (bytes)
		chacha_2block_xor_avx512vl(state, dst, src, bytes, nrounds);
#elif defined(__AVX2__)
#define SIMD_IMPL_NAME "AVX2"
	while (bytes >= 8 * CHACHA_BLOCK_SIZE) {
		chacha_8block_xor_avx2(state, dst, src, bytes, nrounds);
		chacha_advance(state, &dst, &src, &bytes, 8);
	}
	if (bytes > 4 * CHACHA_BLOCK_SIZE)
		chacha_8block_xor_avx2(state, dst, src, bytes, nrounds);
	else if (bytes > 2 * CHACHA_BLOCK_SIZE)
		chacha_4block_xor_avx2(state, dst, src, bytes, nrounds);
	else if (bytes > CHACHA_BLOCK_SIZE)
		chacha_2block_xor_avx2(state, dst, src, bytes, nrounds);
	else if (bytes)
		chacha_block_xor_ssse3(state, dst, src, bytes, nrounds);
#else
#define SIMD_IMPL_NAME "SSSE3"
	while (bytes >= 4 * CHACHA_BLOCK_SIZE) {
		chacha_4block_xor_ssse3(state, dst, src, bytes, nrounds);
		chacha_advance(state, &dst, &src, &bytes, 4);
	}
	if (bytes > CHACHA_BLOCK_SIZE)
		chacha_4block_xor_ssse3(state, dst, src, bytes, nrounds);
	else if (bytes)
		chacha_block_xor_ssse3(state, dst, src, bytes, nrounds);
#endif
}

static void hchacha_simd(const u32 state[16], u32 out[8], int nrounds)
{
	hchacha_block_ssse3(state, out, nrounds);
}
#endif /* __x86_64__ */

/* ChaCha stream cipher */
void chacha(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
	    unsigned int bytes, const u8 *iv, bool simd)
{
#ifdef HAVE_CHACHA_SIMD
	if (simd) {
		chacha_simd(ctx, dst, src, bytes, iv);
		return;
	}
#endif
	chacha_generic(ctx, dst, src, bytes, iv);
}

/* HChaCha, an intermediate step towards XChaCha */
static void hchacha(const u32 state[16], u32 out[8], int nrounds, bool simd)
{
	u32 x[16];

#ifdef HAVE_HCHACHA_SIMD
	if (simd) {
		hchacha_simd(state, out, nrounds);
		return;
	}
#endif
	memcpy(x, state, sizeof(x));
	chacha_perm_generic(x, nrounds);
	memcpy(&out[0], &x[0], 16);
	memcpy(&out[4], &x[12], 16);
}

/* XChaCha stream cipher */
void xchacha(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
	     unsigned int nbytes, const u8 *iv, bool simd)
{
	u32 state[16];
	struct chacha_ctx subctx;
	u8 real_iv[16];

	/* Compute the subkey given the original key and first 128 nonce bits */
	chacha_init_state(state, ctx, iv);
	hchacha(state, subctx.key, ctx->nrounds, simd);
	subctx.nrounds = ctx->nrounds;

	/* Build the real IV */
	memcpy(&real_iv[0], iv + 24, 8); /* stream position */
	memcpy(&real_iv[8], iv + 16, 8); /* remaining 64 nonce bits */

	/* Generate the stream and XOR it with the data */
	chacha(&subctx, dst, src, nbytes, real_iv, simd);
}

static void fuzz_chacha(int nrounds)
{
#ifdef HAVE_CHACHA_SIMD
	struct chacha_ctx ctx;
	u8 iv[CHACHA_IV_SIZE];
	u8 in[1024];
	u8 out_generic[sizeof(in)];
	u8 out_simd[sizeof(in)];
	int i;

	ctx.nrounds = nrounds;

	for (i = 0; i < 10000; i++) {
		int in_off = rand() % sizeof(in);
		int out_off = rand() % sizeof(in);
		int len = rand() % (1 + sizeof(in) -
				    max(in_off, out_off));

		rand_bytes(&in[in_off], len);
		rand_bytes(ctx.key, sizeof(ctx.key));
		rand_bytes(iv, sizeof(iv));

		chacha(&ctx, out_generic, &in[in_off], len, iv, false);
		chacha(&ctx, &out_simd[out_off], &in[in_off], len, iv, true);
		ASSERT(!memcmp(out_generic, &out_simd[out_off], len));
	}
#endif
}

static void fuzz_hchacha(int nrounds)
{
#ifdef HAVE_HCHACHA_SIMD
	int i;

	for (i = 0; i < 10; i++) {
		u32 state[16];
		u32 out_generic[8];
		u32 out_simd[8];

		rand_bytes(state, sizeof(state));
		hchacha(state, out_generic, nrounds, false);
		hchacha(state, out_simd, nrounds, true);
		ASSERT(!memcmp(out_generic, out_simd, sizeof(out_generic)));
	}
#endif
}

static int g_nrounds;

static void _chacha_setkey(struct chacha_ctx *ctx, const u8 *key)
{
	chacha_setkey(ctx, key, g_nrounds);
}

static void do_test_chacha(int nrounds)
{
	char algname[32];

	fuzz_chacha(nrounds);
	fuzz_hchacha(nrounds);

	sprintf(algname, "ChaCha%d", nrounds);
	g_nrounds = nrounds;
#define ENCRYPT		chacha_generic
#define DECRYPT		chacha_generic
#ifdef HAVE_CHACHA_SIMD
#  define ENCRYPT_SIMD	chacha_simd
#  define DECRYPT_SIMD	chacha_simd
#endif
#define KEY		struct chacha_ctx
#define SETKEY		_chacha_setkey
#define KEY_BYTES	CHACHA_KEY_SIZE
#define IV_BYTES	CHACHA_IV_SIZE
#define ALGNAME		algname
#include "cipher_benchmark_template.h"
}

void test_chacha(void)
{
	do_test_chacha(20);
	do_test_chacha(12);
	do_test_chacha(8);
}
