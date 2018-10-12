/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#define NH_PAIR_STRIDE		2
#define NH_NUM_STRIDES		64
#define NH_NUM_PASSES		4

#define NH_MESSAGE_DWORDS	(NH_PAIR_STRIDE * 2 * NH_NUM_STRIDES)
#define NH_KEY_DWORDS		(NH_MESSAGE_DWORDS + \
				 NH_PAIR_STRIDE * 2 * (NH_NUM_PASSES - 1))
#define NH_MESSAGE_UNIT		(NH_PAIR_STRIDE * 8)
#define NH_MESSAGE_BYTES	(NH_MESSAGE_DWORDS * 4)
#define NH_KEY_BYTES		(NH_KEY_DWORDS * 4)
#define NH_HASH_BYTES		(NH_NUM_PASSES * 8)

#ifndef __ASSEMBLER__

#include "util.h"

void nh_generic(const u32 *key, const u8 *message, size_t message_len,
		u8 *hash);

#undef HAVE_NH_SIMD

#if defined(__arm__) || defined(__aarch64__)

#define HAVE_NH_SIMD 1

void nh_neon(const u32 *key, const u8 *message,
	     size_t message_len, u8 hash[NH_HASH_BYTES]);
#define nh_simd nh_neon

#elif defined(__x86_64__)

#define HAVE_NH_SIMD 1

void nh_sse2(const u32 *key, const u8 *message,
	     size_t message_len, u8 hash[NH_HASH_BYTES]);
void nh_avx2(const u32 *key, const u8 *message,
	     size_t message_len, u8 hash[NH_HASH_BYTES]);
#ifdef __AVX2__
#  define nh_simd nh_avx2
#  define SIMD_IMPL_NAME "AVX2"
#else
#  define nh_simd nh_sse2
#  define SIMD_IMPL_NAME "SSE2"
#endif

#endif

struct nh_ctx {
	u32 key[NH_KEY_DWORDS];
};

void nh_setkey(struct nh_ctx *ctx, const u8 *key);

static inline void nh(const u32 *key, const u8 *message,
		      size_t message_len, u8 *hash, bool simd)
{
#ifdef HAVE_NH_SIMD
	if (simd)
		nh_simd(key, message, message_len, hash);
	else
#endif
		nh_generic(key, message, message_len, hash);
}

union nh_hash {
	u8 bytes[NH_HASH_BYTES];
	__le64 sums[NH_NUM_PASSES];
};

static inline void nh_combine(union nh_hash *dst, const union nh_hash *src1,
			      const union nh_hash *src2)
{
	int i;

	BUILD_BUG_ON(sizeof(dst->bytes) != sizeof(dst->sums));

	for (i = 0; i < ARRAY_SIZE(dst->sums); i++) {
		dst->sums[i] = cpu_to_le64(le64_to_cpu(src1->sums[i]) +
					   le64_to_cpu(src2->sums[i]));
	}
}

#endif /* !__ASSEMBLER__ */
