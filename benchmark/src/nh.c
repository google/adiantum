/*
 * NH hash algorithm, specifically the variant used by Adiantum hashing
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "nh.h"
#include "testvec.h"

#if 0 /* unoptimized generic version */
static u64 nhpass(const u32 *key, const u32 *message, size_t message_dwords)
{
	u64 sum = 0;
	int i, j;

	for (i = 0; i < message_dwords; i += NH_PAIR_STRIDE * 2) {
		for (j = i; j < i + NH_PAIR_STRIDE; j++) {
			u32 l = key[j] + message[j];
			u32 r = key[j + NH_PAIR_STRIDE] +
				message[j + NH_PAIR_STRIDE];

			sum += (u64)l * (u64)r;
		}
	}

	return sum;
}

void nh_generic(const u32 *key, const u8 *message, size_t message_len, u8 *hash)
{
	u32 message_vec[NH_MESSAGE_DWORDS];
	u64 hash_vec[NH_NUM_PASSES];
	size_t message_dwords = message_len / sizeof(__le32);
	int i;

	ASSERT(message_len % NH_MESSAGE_UNIT == 0);

	for (i = 0; i < message_dwords; i++)
		message_vec[i] =
			get_unaligned_le32(&message[i * sizeof(__le32)]);

	for (i = 0; i < NH_NUM_PASSES; i++)
		hash_vec[i] = nhpass(&key[i * NH_PAIR_STRIDE * 2],
				     message_vec, message_dwords);

	for (i = 0; i < ARRAY_SIZE(hash_vec); i++)
		put_unaligned_le64(hash_vec[i], &hash[i * sizeof(__le64)]);
}
#else /* optimized generic version */

#define NH_STRIDE(K0, K1, K2, K3)				\
({								\
	m_A = get_unaligned_le32(message); message += 4;	\
	m_B = get_unaligned_le32(message); message += 4;	\
	m_C = get_unaligned_le32(message); message += 4;	\
	m_D = get_unaligned_le32(message); message += 4;	\
	K3##_A = *key++;					\
	K3##_B = *key++;					\
	K3##_C = *key++;					\
	K3##_D = *key++;					\
	sum0 += (u64)(m_A + K0##_A) * (u64)(m_C + K0##_C);	\
	sum1 += (u64)(m_A + K1##_A) * (u64)(m_C + K1##_C);	\
	sum2 += (u64)(m_A + K2##_A) * (u64)(m_C + K2##_C);	\
	sum3 += (u64)(m_A + K3##_A) * (u64)(m_C + K3##_C);	\
	sum0 += (u64)(m_B + K0##_B) * (u64)(m_D + K0##_D);	\
	sum1 += (u64)(m_B + K1##_B) * (u64)(m_D + K1##_D);	\
	sum2 += (u64)(m_B + K2##_B) * (u64)(m_D + K2##_D);	\
	sum3 += (u64)(m_B + K3##_B) * (u64)(m_D + K3##_D);	\
})

void nh_generic(const u32 *key, const u8 *message, size_t message_len, u8 *hash)
{
	u64 sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
	u32 k0_A = *key++;
	u32 k0_B = *key++;
	u32 k0_C = *key++;
	u32 k0_D = *key++;
	u32 k1_A = *key++;
	u32 k1_B = *key++;
	u32 k1_C = *key++;
	u32 k1_D = *key++;
	u32 k2_A = *key++;
	u32 k2_B = *key++;
	u32 k2_C = *key++;
	u32 k2_D = *key++;
	u32 k3_A, k3_B, k3_C, k3_D;
	u32 m_A, m_B, m_C, m_D;
	size_t n = message_len / 16;

	BUILD_BUG_ON(NH_PAIR_STRIDE != 2);
	BUILD_BUG_ON(NH_NUM_PASSES != 4);

	while (n >= 4) {
		NH_STRIDE(k0, k1, k2, k3);
		NH_STRIDE(k1, k2, k3, k0);
		NH_STRIDE(k2, k3, k0, k1);
		NH_STRIDE(k3, k0, k1, k2);
		n -= 4;
	}
	if (n) {
		NH_STRIDE(k0, k1, k2, k3);
		if (--n) {
			NH_STRIDE(k1, k2, k3, k0);
			if (--n)
				NH_STRIDE(k2, k3, k0, k1);
		}
	}

	put_unaligned_le64(sum0, hash + 0);
	put_unaligned_le64(sum1, hash + 8);
	put_unaligned_le64(sum2, hash + 16);
	put_unaligned_le64(sum3, hash + 24);
}
#endif /* optimized generic version */

void nh_setkey(struct nh_ctx *ctx, const u8 *key)
{
	int i;

	for (i = 0; i < NH_KEY_DWORDS; i++)
		ctx->key[i] = get_unaligned_le32(key + i * sizeof(u32));
}

static __always_inline void
__nh_bulk(const struct nh_ctx *ctx, const void *data, unsigned int nbytes,
	  u8 *digest, bool simd)
{
	u8 tmp_hash[NH_HASH_BYTES];

	memset(digest, 0, NH_HASH_BYTES);
	while (nbytes >= NH_MESSAGE_BYTES) {
		nh(ctx->key, data, NH_MESSAGE_BYTES, tmp_hash, simd);
		/* bogus combining method, just for testing... */
		xor(digest, digest, tmp_hash, NH_HASH_BYTES);
		data += NH_MESSAGE_BYTES;
		nbytes -= NH_MESSAGE_BYTES;
	}
	if (nbytes > 0) {
		nh(ctx->key, data, nbytes, tmp_hash, simd);
		/* bogus combining method, just for testing... */
		xor(digest, digest, tmp_hash, NH_HASH_BYTES);
	}
}

static void nh_bulk_generic(const struct nh_ctx *ctx, const void *data,
			    unsigned int nbytes, u8 *digest)
{
	__nh_bulk(ctx, data, nbytes, digest, false);
}

#ifdef HAVE_NH_SIMD
static void nh_bulk_simd(const struct nh_ctx *ctx, const void *data,
			 unsigned int nbytes, u8 *digest)
{
	__nh_bulk(ctx, data, nbytes, digest, true);
}
#endif

struct nh_testvec {
	struct testvec_buffer key;
	struct testvec_buffer message;
	struct testvec_buffer hash;
};

static void test_nh_testvec(const struct nh_testvec *v, bool simd)
{
	u8 res[NH_HASH_BYTES];
	u32 key[NH_KEY_DWORDS];
	int i;

	ASSERT(v->key.len == NH_KEY_BYTES);
	ASSERT(v->message.len > 0);
	ASSERT(v->message.len % NH_MESSAGE_UNIT == 0);
	ASSERT(v->message.len <= NH_MESSAGE_BYTES);
	ASSERT(v->hash.len == NH_HASH_BYTES);

	for (i = 0; i < NH_KEY_DWORDS; i++)
		key[i] = get_unaligned_le32(&v->key.data[i * 4]);
	nh(key, v->message.data, v->message.len, res, simd);
	ASSERT(!memcmp(res, v->hash.data, sizeof(res)));
}

#include "nh_testvecs.h"

static void fuzz_nh(void)
{
#ifdef HAVE_NH_SIMD
	u32 key[NH_KEY_DWORDS];
	u8 message[NH_MESSAGE_BYTES];
	u8 hash_generic[NH_HASH_BYTES];
	u8 hash_simd[NH_HASH_BYTES];
	unsigned int len;

	for (len = 0; len <= NH_MESSAGE_BYTES; len += NH_MESSAGE_UNIT) {
		rand_bytes(key, NH_KEY_BYTES);
		rand_bytes(message, len);

		memset(hash_generic, 0, NH_HASH_BYTES);
		nh_generic(key, message, len, hash_generic);

		memset(hash_simd, 0, NH_HASH_BYTES);
		nh_simd(key, message, len, hash_simd);

		ASSERT(!memcmp(hash_generic, hash_simd, NH_HASH_BYTES));
	}
#endif
}

static void test_nh_testvecs(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nh_tv); i++) {
		test_nh_testvec(&nh_tv[i], false);
#ifdef HAVE_NH_SIMD
		test_nh_testvec(&nh_tv[i], true);
#endif
	}

	fuzz_nh();
}

void test_nh(void)
{
	test_nh_testvecs();

#define ALGNAME		"NH"
#define HASH		nh_bulk_generic
#ifdef HAVE_NH_SIMD
#  define HASH_SIMD	nh_bulk_simd
#endif
#define KEY		struct nh_ctx
#define SETKEY		nh_setkey
#define KEY_BYTES	NH_KEY_BYTES
#define DIGEST_SIZE	NH_HASH_BYTES
#include "hash_benchmark_template.h"
}
